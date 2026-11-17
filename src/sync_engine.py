#!/usr/bin/env python3
"""
Core Sync, Validation, Backup, and Rollback Engine for Cloudflare -> AWS Prefix Lists.
======================================================================================
- Zero external third-party dependencies beyond Python Standard Library + boto3.
- Fetches Cloudflare IPv4 & IPv6 CIDRs from `https://api.cloudflare.com/client/v4/ips`
  with automatic fallback to `https://www.cloudflare.com/ips-v4` and `/ips-v6`.
- Enforces anti-lockout guardrails:
    1. Rejects 0.0.0.0/0, ::/0, private, loopback, multicast, or link-local CIDRs.
    2. Enforces minimum prefix counts (default: >=10 IPv4, >=5 IPv6).
    3. Enforces maximum removal ratio circuit breaker (default: <=50% removal in one run).
- Creates immutable pre-update state backups (S3 and/or local disk) capturing:
    - Current Prefix List metadata, version, and exact CIDR entries.
    - Full `describe_security_groups` state of any referenced ALB Security Groups.
- Atomically updates Customer-Managed VPC Prefix Lists (`ModifyManagedPrefixList`),
  automatically resizing `MaxEntries` if Cloudflare expands its CIDR list.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cloudflare_prefix_sync")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


CLOUDFLARE_API_URL = "https://api.cloudflare.com/client/v4/ips"
CLOUDFLARE_FALLBACK_V4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_FALLBACK_V6_URL = "https://www.cloudflare.com/ips-v6"

DEFAULT_MIN_IPV4_CIDRS = 10
DEFAULT_MIN_IPV6_CIDRS = 5
DEFAULT_MAX_REMOVAL_RATIO = 0.50
DEFAULT_ENTRY_DESCRIPTION = "Cloudflare Edge CIDR (Managed by cf-prefix-sync)"


class CloudflareFetchError(RuntimeError):
    """Raised when Cloudflare IP endpoints cannot be reached or return invalid payloads."""


class ValidationGuardrailError(ValueError):
    """Raised when fetched CIDRs or computed diffs violate anti-lockout safety guardrails."""


class BackupFailureError(RuntimeError):
    """Raised when pre-update backup creation fails. Blocks any subsequent AWS mutation."""


@dataclass(frozen=True)
class CloudflareIpRanges:
    ipv4_cidrs: Tuple[str, ...]
    ipv6_cidrs: Tuple[str, ...]
    etag: str
    source: str
    fetched_at_utc: str


@dataclass
class PrefixListDiff:
    prefix_list_id: str
    address_family: str  # "IPv4" or "IPv6"
    current_version: int
    current_max_entries: int
    current_cidrs: Tuple[str, ...]
    desired_cidrs: Tuple[str, ...]
    to_add: Tuple[str, ...]
    to_remove: Tuple[str, ...]

    @property
    def has_changes(self) -> bool:
        return bool(self.to_add or self.to_remove)

    @property
    def removal_ratio(self) -> float:
        if not self.current_cidrs:
            return 0.0
        return len(self.to_remove) / float(len(self.current_cidrs))


@dataclass
class SyncConfig:
    ipv4_prefix_list_id: Optional[str] = None
    ipv6_prefix_list_id: Optional[str] = None
    alb_security_group_ids: List[str] = field(default_factory=list)
    backup_s3_bucket: Optional[str] = None
    backup_s3_prefix: str = "backups"
    backup_local_dir: Optional[str] = None
    sns_topic_arn: Optional[str] = None
    min_ipv4_cidrs: int = DEFAULT_MIN_IPV4_CIDRS
    min_ipv6_cidrs: int = DEFAULT_MIN_IPV6_CIDRS
    max_removal_ratio: float = DEFAULT_MAX_REMOVAL_RATIO
    force_update: bool = False
    dry_run: bool = True
    audit_enabled: bool = False
    audit_all_load_balancers: bool = False
    # Operating mode: discover | audit | sync | attach | enforce (see src/modes.py)
    mode: str = "sync"
    # Existing prefix lists to compare with Cloudflare, read-only (never modified)
    compare_prefix_list_ids: List[str] = field(default_factory=list)
    # Security groups that attach/enforce may change (in addition to tagged ones)
    managed_security_group_ids: List[str] = field(default_factory=list)
    managed_tag_key: str = "cloudflare-prefix-sync"  # empty string disables tag opt-in
    managed_tag_value: str = "managed"
    ingress_ports: List[int] = field(default_factory=lambda: [443])
    allowed_cidrs: List[str] = field(default_factory=list)
    allowed_prefix_list_ids: List[str] = field(default_factory=list)
    allowed_source_security_group_ids: List[str] = field(default_factory=list)
    revoke_private_cidrs: bool = False
    revoke_security_group_sources: bool = False
    max_revocations_per_run: int = 25
    # SNS report policy: never | alerts | drift | always; format: text | json
    notify_on: str = "alerts"
    notify_format: str = "text"
    entry_description: str = DEFAULT_ENTRY_DESCRIPTION
    cloudflare_api_url: str = CLOUDFLARE_API_URL
    cloudflare_v4_fallback_url: str = CLOUDFLARE_FALLBACK_V4_URL
    cloudflare_v6_fallback_url: str = CLOUDFLARE_FALLBACK_V6_URL


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_compact_timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def normalize_and_validate_cidrs(
    raw_cidrs: List[str],
    expected_version: int,
    min_count: int,
) -> Tuple[str, ...]:
    """
    Validates, normalizes, deduplicates, and sorts CIDR ranges.
    Rejects private, loopback, link-local, multicast, unspecified, or full-internet (0.0.0.0/0, ::/0) prefixes.
    """
    if expected_version not in (4, 6):
        raise ValueError(f"Unsupported IP version: {expected_version}")

    normalized: Set[str] = set()
    for item in raw_cidrs:
        cidr_str = (item or "").strip()
        if not cidr_str:
            continue
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError as exc:
            raise ValidationGuardrailError(
                f"Invalid CIDR returned by upstream source: '{cidr_str}' ({exc})"
            ) from exc

        if net.version != expected_version:
            raise ValidationGuardrailError(
                f"CIDR '{cidr_str}' has IP version {net.version}, expected IPv{expected_version}"
            )

        if net.prefixlen == 0:
            raise ValidationGuardrailError(
                f"Full-internet wildcard CIDR '{net.with_prefixlen}' is strictly forbidden by guardrail."
            )

        if (
            net.is_private
            or net.is_loopback
            or net.is_link_local
            or net.is_multicast
            or net.is_unspecified
            or net.is_reserved
        ):
            raise ValidationGuardrailError(
                f"Non-public or reserved CIDR '{net.with_prefixlen}' is forbidden in Cloudflare public edge ranges."
            )

        normalized.add(net.with_prefixlen)

    sorted_cidrs = tuple(
        sorted(normalized, key=lambda c: (int(ipaddress.ip_network(c).network_address), ipaddress.ip_network(c).prefixlen))
    )

    if len(sorted_cidrs) < min_count:
        raise ValidationGuardrailError(
            f"Safety threshold failed for IPv{expected_version}: received {len(sorted_cidrs)} CIDRs, "
            f"minimum required is {min_count}."
        )

    return sorted_cidrs


def _default_http_get(url: str, timeout: int = 10) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/plain;q=0.9",
            "User-Agent": "aws-cloudflare-prefix-sync/1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", 200)
        if status < 200 or status >= 300:
            raise CloudflareFetchError(f"HTTP {status} from {url}")
        return resp.read().decode("utf-8")


def fetch_cloudflare_ip_ranges(
    config: SyncConfig,
    http_get: Callable[[str, int], str] = _default_http_get,
    max_retries: int = 3,
    retry_delay_sec: float = 1.0,
) -> CloudflareIpRanges:
    """
    Fetches Cloudflare IPv4 and IPv6 ranges from the official v4 API endpoint,
    falling back to `/ips-v4` and `/ips-v6` plain-text endpoints if needed.
    """
    last_error: Optional[Exception] = None

    # 1. Try Primary JSON API
    for attempt in range(1, max_retries + 1):
        try:
            raw_body = http_get(config.cloudflare_api_url, 10)
            payload = json.loads(raw_body)
            if not payload.get("success", False) or "result" not in payload:
                raise CloudflareFetchError(
                    f"Cloudflare API returned success=false or missing result: {raw_body[:300]}"
                )
            result = payload["result"]
            raw_v4 = result.get("ipv4_cidrs", [])
            raw_v6 = result.get("ipv6_cidrs", [])
            v4_cidrs = normalize_and_validate_cidrs(raw_v4, expected_version=4, min_count=config.min_ipv4_cidrs)
            v6_cidrs = normalize_and_validate_cidrs(raw_v6, expected_version=6, min_count=config.min_ipv6_cidrs)
            etag = result.get("etag") or hashlib.sha256(
                json.dumps({"v4": v4_cidrs, "v6": v6_cidrs}).encode("utf-8")
            ).hexdigest()[:32]
            return CloudflareIpRanges(
                ipv4_cidrs=v4_cidrs,
                ipv6_cidrs=v6_cidrs,
                etag=etag,
                source=config.cloudflare_api_url,
                fetched_at_utc=utc_now_iso(),
            )
        except ValidationGuardrailError:
            raise
        except Exception as exc:
            last_error = exc
            logger.warning(
                "Primary Cloudflare API fetch attempt %d/%d failed: %s",
                attempt,
                max_retries,
                exc,
            )
            if attempt < max_retries and retry_delay_sec > 0:
                time.sleep(retry_delay_sec)

    # 2. Fallback to plain-text endpoints (/ips-v4 and /ips-v6)
    try:
        logger.info("Attempting fallback to Cloudflare plain-text endpoints...")
        v4_text = http_get(config.cloudflare_v4_fallback_url, 10)
        v6_text = http_get(config.cloudflare_v6_fallback_url, 10)
        raw_v4 = [line.strip() for line in v4_text.splitlines() if line.strip()]
        raw_v6 = [line.strip() for line in v6_text.splitlines() if line.strip()]
        v4_cidrs = normalize_and_validate_cidrs(raw_v4, expected_version=4, min_count=config.min_ipv4_cidrs)
        v6_cidrs = normalize_and_validate_cidrs(raw_v6, expected_version=6, min_count=config.min_ipv6_cidrs)
        etag = hashlib.sha256(
            json.dumps({"v4": v4_cidrs, "v6": v6_cidrs}).encode("utf-8")
        ).hexdigest()[:32]
        return CloudflareIpRanges(
            ipv4_cidrs=v4_cidrs,
            ipv6_cidrs=v6_cidrs,
            etag=etag,
            source=f"{config.cloudflare_v4_fallback_url}+{config.cloudflare_v6_fallback_url}",
            fetched_at_utc=utc_now_iso(),
        )
    except ValidationGuardrailError:
        raise
    except Exception as fallback_exc:
        raise CloudflareFetchError(
            f"Both primary and fallback Cloudflare IP endpoints failed. "
            f"Primary error: {last_error}; Fallback error: {fallback_exc}"
        ) from fallback_exc


def get_prefix_list_state(ec2_client: Any, prefix_list_id: str) -> Dict[str, Any]:
    """
    Retrieves metadata (Version, MaxEntries, AddressFamily, State) and all active CIDR entries
    for a Customer-Managed VPC Prefix List.
    """
    desc_resp = ec2_client.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])
    pl_list = desc_resp.get("PrefixLists", [])
    if not pl_list:
        raise ValueError(f"Managed Prefix List '{prefix_list_id}' not found.")
    pl_meta = pl_list[0]

    entries: List[Dict[str, str]] = []
    paginator_token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"PrefixListId": prefix_list_id, "MaxResults": 100}
        if paginator_token:
            kwargs["NextToken"] = paginator_token
        resp = ec2_client.get_managed_prefix_list_entries(**kwargs)
        for entry in resp.get("Entries", []):
            entries.append(
                {
                    "Cidr": entry["Cidr"],
                    "Description": entry.get("Description", ""),
                }
            )
        paginator_token = resp.get("NextToken")
        if not paginator_token:
            break

    cidrs = tuple(sorted({e["Cidr"] for e in entries}))
    return {
        "prefix_list_id": prefix_list_id,
        "prefix_list_name": pl_meta.get("PrefixListName", ""),
        "prefix_list_arn": pl_meta.get("PrefixListArn", ""),
        "address_family": pl_meta.get("AddressFamily", "IPv4"),
        "state": pl_meta.get("State", "unknown"),
        "version": int(pl_meta.get("Version", 1)),
        "max_entries": int(pl_meta.get("MaxEntries", 0)),
        "cidrs": list(cidrs),
        "raw_entries": entries,
    }


def compute_prefix_list_diff(
    pl_state: Dict[str, Any],
    desired_cidrs: Tuple[str, ...],
    max_removal_ratio: float = DEFAULT_MAX_REMOVAL_RATIO,
    force_update: bool = False,
) -> PrefixListDiff:
    """
    Computes exact additions and removals between a Prefix List's current CIDRs and desired CIDRs.
    Enforces the maximum removal ratio circuit breaker unless `force_update=True`.
    """
    current_set = set(pl_state["cidrs"])
    desired_set = set(desired_cidrs)

    to_add = tuple(sorted(desired_set - current_set))
    to_remove = tuple(sorted(current_set - desired_set))

    diff = PrefixListDiff(
        prefix_list_id=pl_state["prefix_list_id"],
        address_family=pl_state["address_family"],
        current_version=int(pl_state["version"]),
        current_max_entries=int(pl_state["max_entries"]),
        current_cidrs=tuple(sorted(current_set)),
        desired_cidrs=tuple(sorted(desired_set)),
        to_add=to_add,
        to_remove=to_remove,
    )

    if diff.has_changes and not force_update and len(current_set) > 0:
        if diff.removal_ratio > max_removal_ratio:
            raise ValidationGuardrailError(
                f"Circuit breaker tripped for {diff.prefix_list_id} ({diff.address_family}): "
                f"update would remove {len(to_remove)}/{len(current_set)} ({diff.removal_ratio:.1%}) "
                f"existing prefixes, exceeding max_removal_ratio={max_removal_ratio:.1%}. "
                f"Pass --force / force_update=True if intentional."
            )

    return diff


def discover_referencing_security_groups(
    ec2_client: Any,
    prefix_list_ids: List[str],
    explicit_sg_ids: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Captures the full configuration state of Security Groups that either:
      1. Are explicitly listed in `explicit_sg_ids`, OR
      2. Reference any of `prefix_list_ids` in their Ingress/Egress IpPermissions.
    """
    sg_map: Dict[str, Dict[str, Any]] = {}

    if explicit_sg_ids:
        clean_ids = [sg.strip() for sg in explicit_sg_ids if sg and sg.strip()]
        if clean_ids:
            resp = ec2_client.describe_security_groups(GroupIds=clean_ids)
            for sg in resp.get("SecurityGroups", []):
                sg_map[sg["GroupId"]] = sg

    if prefix_list_ids:
        try:
            resp = ec2_client.describe_security_groups(
                Filters=[{"Name": "ip-permission.prefix-list-id", "Values": prefix_list_ids}]
            )
            for sg in resp.get("SecurityGroups", []):
                sg_map[sg["GroupId"]] = sg
        except Exception as exc:
            logger.warning("Could not filter security groups by prefix-list-id: %s", exc)

    return [sg_map[k] for k in sorted(sg_map.keys())]


def create_pre_update_backup(
    config: SyncConfig,
    ec2_client: Any,
    s3_client: Optional[Any],
    prefix_list_states: Dict[str, Dict[str, Any]],
    diffs: Dict[str, PrefixListDiff],
    cf_ranges: CloudflareIpRanges,
    account_id: str = "unknown",
    region: str = "unknown",
) -> Dict[str, Any]:
    """
    Creates an immutable pre-update backup snapshot before any Prefix List is modified.
    Writes to S3 (if `backup_s3_bucket` is configured) and/or local disk (if `backup_local_dir` is set).
    Raises `BackupFailureError` if no backup destination succeeded when at least one is configured,
    or if neither S3 nor local backup is configured during a live execution.
    """
    if not config.backup_s3_bucket and not config.backup_local_dir:
        raise BackupFailureError(
            "Mandatory backup guardrail: At least one backup destination "
            "(backup_s3_bucket or backup_local_dir) must be configured before applying updates."
        )

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    # Millisecond precision so two runs in the same second never share a name; still sorts by time.
    backup_id = f"cf-prefix-backup-{now_dt.strftime('%Y%m%dT%H%M%S')}{now_dt.microsecond // 1000:03d}Z"
    if config.backup_local_dir:
        base, n = backup_id, 1
        while os.path.exists(os.path.join(config.backup_local_dir, f"{backup_id}.json")):
            n += 1
            backup_id = f"{base}-{n}"

    tracked_pl_ids = [st["prefix_list_id"] for st in prefix_list_states.values()]
    security_groups = discover_referencing_security_groups(
        ec2_client=ec2_client,
        prefix_list_ids=tracked_pl_ids,
        explicit_sg_ids=config.alb_security_group_ids,
    )

    snapshot_body: Dict[str, Any] = {
        "backup_id": backup_id,
        "timestamp_utc": utc_now_iso(),
        "account_id": account_id,
        "region": region,
        "cloudflare_upstream": {
            "source": cf_ranges.source,
            "etag": cf_ranges.etag,
            "fetched_at_utc": cf_ranges.fetched_at_utc,
            "desired_ipv4_count": len(cf_ranges.ipv4_cidrs),
            "desired_ipv6_count": len(cf_ranges.ipv6_cidrs),
        },
        "prefix_lists": prefix_list_states,
        "planned_changes": {
            key: {
                "prefix_list_id": d.prefix_list_id,
                "address_family": d.address_family,
                "previous_version": d.current_version,
                "to_add": list(d.to_add),
                "to_remove": list(d.to_remove),
            }
            for key, d in diffs.items()
        },
        "security_groups": security_groups,
    }

    serialized = json.dumps(snapshot_body, indent=2, sort_keys=True, default=str)
    sha256_hex = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    snapshot_body["sha256_checksum"] = sha256_hex
    serialized_with_checksum = json.dumps(snapshot_body, indent=2, sort_keys=True, default=str)

    locations: List[str] = []

    # 1. Write to S3 if configured
    if config.backup_s3_bucket:
        if s3_client is None:
            raise BackupFailureError("backup_s3_bucket is set, but s3_client is None.")
        prefix = (config.backup_s3_prefix or "backups").strip("/")
        s3_key = f"{prefix}/{now_dt.strftime('%Y/%m/%d')}/{backup_id}.json"
        try:
            s3_client.put_object(
                Bucket=config.backup_s3_bucket,
                Key=s3_key,
                Body=serialized_with_checksum.encode("utf-8"),
                ContentType="application/json",
                ServerSideEncryption="AES256",
                Metadata={
                    "backup-id": backup_id,
                    "sha256": sha256_hex,
                    "account-id": str(account_id),
                    "region": str(region),
                },
            )
            s3_uri = f"s3://{config.backup_s3_bucket}/{s3_key}"
            locations.append(s3_uri)
            logger.info("Pre-update backup saved to S3: %s (sha256=%s)", s3_uri, sha256_hex[:12])
        except Exception as exc:
            raise BackupFailureError(
                f"Failed to write pre-update backup to s3://{config.backup_s3_bucket}/{s3_key}: {exc}"
            ) from exc

    # 2. Write to local backup directory if configured
    if config.backup_local_dir:
        try:
            os.makedirs(config.backup_local_dir, exist_ok=True)
            local_path = os.path.join(config.backup_local_dir, f"{backup_id}.json")
            with open(local_path, "w", encoding="utf-8") as fh:
                fh.write(serialized_with_checksum)
            locations.append(local_path)
            logger.info("Pre-update backup saved locally: %s (sha256=%s)", local_path, sha256_hex[:12])
        except Exception as exc:
            raise BackupFailureError(
                f"Failed to write pre-update backup to local path '{config.backup_local_dir}': {exc}"
            ) from exc

    return {
        "backup_id": backup_id,
        "sha256_checksum": sha256_hex,
        "locations": locations,
        "security_groups_captured": len(security_groups),
        "snapshot": snapshot_body,
    }


def wait_for_prefix_list_ready(
    ec2_client: Any,
    prefix_list_id: str,
    max_wait_seconds: int = 60,
    poll_interval: float = 1.5,
) -> Dict[str, Any]:
    """
    Waits until a Managed Prefix List reaches a steady state (`create-complete`, `modify-complete`, `restore-complete`).
    """
    deadline = time.time() + max_wait_seconds
    last_state = "unknown"
    while time.time() <= deadline:
        resp = ec2_client.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])
        pls = resp.get("PrefixLists", [])
        if not pls:
            raise ValueError(f"Prefix list '{prefix_list_id}' disappeared while polling state.")
        pl = pls[0]
        last_state = pl.get("State", "")
        if last_state in ("create-complete", "modify-complete", "restore-complete"):
            return pl
        if "failed" in last_state:
            reason = pl.get("StateMessage", "no state message provided")
            raise RuntimeError(
                f"Prefix list '{prefix_list_id}' entered failure state '{last_state}': {reason}"
            )
        time.sleep(poll_interval)

    raise TimeoutError(
        f"Timed out waiting for Prefix List '{prefix_list_id}' to finish modifying (last state: {last_state})."
    )


def apply_prefix_list_diff(
    ec2_client: Any,
    diff: PrefixListDiff,
    entry_description: str = DEFAULT_ENTRY_DESCRIPTION,
    poll_interval: float = 1.0,
) -> Dict[str, Any]:
    """
    Atomically applies `diff` to a Customer-Managed VPC Prefix List.
    Note: AWS `ModifyManagedPrefixList` does not allow changing `MaxEntries` and `AddEntries`/`RemoveEntries`
    in the same API call. If `len(desired_cidrs) > current_max_entries`, this function first resizes
    `MaxEntries` with headroom, waits for `modify-complete`, and then applies the atomic CIDR diff.
    """
    if not diff.has_changes:
        return {
            "prefix_list_id": diff.prefix_list_id,
            "modified": False,
            "previous_version": diff.current_version,
            "new_version": diff.current_version,
            "added_count": 0,
            "removed_count": 0,
        }

    # Ensure Prefix List is in a modifiable state first
    pl_meta = wait_for_prefix_list_ready(
        ec2_client, diff.prefix_list_id, poll_interval=poll_interval
    )
    current_version = int(pl_meta.get("Version", diff.current_version))
    current_max = int(pl_meta.get("MaxEntries", diff.current_max_entries))

    desired_count = len(diff.desired_cidrs)
    resized_max_entries: Optional[int] = None
    if desired_count > current_max:
        new_max = max(desired_count + 10, int(desired_count * 1.25))
        logger.info(
            "Prefix List %s requires capacity expansion: desired=%d > MaxEntries=%d. Resizing to %d...",
            diff.prefix_list_id,
            desired_count,
            current_max,
            new_max,
        )
        ec2_client.modify_managed_prefix_list(
            PrefixListId=diff.prefix_list_id,
            MaxEntries=new_max,
        )
        pl_meta = wait_for_prefix_list_ready(
            ec2_client, diff.prefix_list_id, poll_interval=poll_interval
        )
        current_version = int(pl_meta.get("Version", current_version))
        resized_max_entries = new_max

    add_entries = [
        {"Cidr": cidr, "Description": entry_description} for cidr in diff.to_add
    ]
    remove_entries = [{"Cidr": cidr} for cidr in diff.to_remove]

    modify_kwargs: Dict[str, Any] = {
        "PrefixListId": diff.prefix_list_id,
        "CurrentVersion": current_version,
    }
    if add_entries:
        modify_kwargs["AddEntries"] = add_entries
    if remove_entries:
        modify_kwargs["RemoveEntries"] = remove_entries

    ec2_client.modify_managed_prefix_list(**modify_kwargs)
    updated_meta = wait_for_prefix_list_ready(
        ec2_client, diff.prefix_list_id, poll_interval=poll_interval
    )
    new_version = int(updated_meta.get("Version", current_version + 1))

    logger.info(
        "Successfully updated Prefix List %s (%s): Version %d -> %d (+%d added, -%d removed)",
        diff.prefix_list_id,
        diff.address_family,
        diff.current_version,
        new_version,
        len(diff.to_add),
        len(diff.to_remove),
    )

    return {
        "prefix_list_id": diff.prefix_list_id,
        "address_family": diff.address_family,
        "modified": True,
        "previous_version": diff.current_version,
        "new_version": new_version,
        "resized_max_entries": resized_max_entries,
        "added_count": len(diff.to_add),
        "removed_count": len(diff.to_remove),
        "added_cidrs": list(diff.to_add),
        "removed_cidrs": list(diff.to_remove),
    }


def send_sns_notification(
    sns_client: Optional[Any],
    topic_arn: Optional[str],
    subject: str,
    payload: Dict[str, Any],
) -> None:
    if not topic_arn or sns_client is None:
        return
    try:
        clean_subject = subject[:100]
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=clean_subject,
            Message=json.dumps(payload, indent=2, default=str),
        )
    except Exception as exc:
        logger.warning("Failed to publish SNS notification to %s: %s", topic_arn, exc)


def _split_ids(values: Optional[List[str]]) -> List[str]:
    return [v.strip() for v in (values or []) if v and v.strip()]


def _compare_reference_list(
    ec2_client: Any, prefix_list_id: str, cf_ranges: CloudflareIpRanges
) -> Dict[str, Any]:
    """Read-only comparison of an existing prefix list with Cloudflare's published ranges."""
    state = get_prefix_list_state(ec2_client, prefix_list_id)
    desired = cf_ranges.ipv6_cidrs if state["address_family"] == "IPv6" else cf_ranges.ipv4_cidrs
    diff = compute_prefix_list_diff(state, desired, force_update=True)
    return {
        "prefix_list_id": prefix_list_id,
        "name": state["prefix_list_name"],
        "address_family": state["address_family"],
        "have_count": len(state["cidrs"]),
        "want_count": len(desired),
        "to_add": list(diff.to_add),
        "to_remove": list(diff.to_remove),
        "in_sync": not diff.has_changes,
    }


def run_sync(
    config: SyncConfig,
    ec2_client: Any,
    s3_client: Optional[Any] = None,
    sns_client: Optional[Any] = None,
    sts_client: Optional[Any] = None,
    http_get: Callable[[str, int], str] = _default_http_get,
    poll_interval: float = 1.0,
    elbv2_client: Optional[Any] = None,
    cloudfront_client: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    End-to-end orchestrator. What it does depends on `config.mode` (see src/modes.py):

      discover  inventory entry points and how exposed they are; read-only
      audit     + compare prefix lists with Cloudflare + exposure audit; read-only
      sync      + update the managed prefix lists
      attach    + add missing Cloudflare rules to in-scope security groups
      enforce   + revoke non-Cloudflare ingress on in-scope security groups

    `config.dry_run` turns any mode into a preview. Writes are always preceded by a backup;
    if the backup fails nothing is modified. A have-vs-needs report is sent to SNS according to
    `config.notify_on`.
    """
    try:
        from src.audit import AllowList, run_exposure_audit
        from src.discovery import run_discovery
        from src.remediate import (
            RemediationGuardrailError,
            RemediationSettings,
            apply_plan,
            find_tagged_security_groups,
            plan_security_groups,
        )
        from src.report import (
            build_gap_report,
            normalize_notify_format,
            normalize_notify_policy,
            send_report,
            should_notify,
            summarize_security_group,
        )
    except ImportError:  # Lambda flat layout
        from audit import AllowList, run_exposure_audit  # type: ignore
        from discovery import run_discovery  # type: ignore
        from remediate import (  # type: ignore
            RemediationGuardrailError,
            RemediationSettings,
            apply_plan,
            find_tagged_security_groups,
            plan_security_groups,
        )
        from report import (  # type: ignore
            build_gap_report,
            normalize_notify_format,
            normalize_notify_policy,
            send_report,
            should_notify,
            summarize_security_group,
        )
    try:
        from src.modes import DISCOVER, capabilities_for, normalize_mode
    except ImportError:
        from modes import DISCOVER, capabilities_for, normalize_mode  # type: ignore

    mode = normalize_mode(config.mode)
    caps = capabilities_for(mode)
    notify_policy = normalize_notify_policy(config.notify_on)
    notify_format = normalize_notify_format(config.notify_format)

    managed_ids = _split_ids([config.ipv4_prefix_list_id or "", config.ipv6_prefix_list_id or ""])
    compare_ids = [p for p in _split_ids(config.compare_prefix_list_ids) if p not in managed_ids]
    if not managed_ids and not compare_ids and mode != DISCOVER:
        raise ValueError(
            "At least one of ipv4_prefix_list_id, ipv6_prefix_list_id or compare_prefix_list_ids "
            "must be provided."
        )
    if caps.write_prefix_lists and not managed_ids:
        raise ValueError(
            f"mode '{mode}' updates prefix lists, so ipv4_prefix_list_id and/or ipv6_prefix_list_id "
            "is required. Use mode 'audit' or 'discover' to only compare an existing list."
        )

    live = (not config.dry_run) and caps.writes
    account_id = "unknown"
    if sts_client is not None:
        try:
            account_id = sts_client.get_caller_identity().get("Account", "unknown")
        except Exception:
            pass
    region = getattr(getattr(ec2_client, "meta", None), "region_name", "unknown") or "unknown"

    try:
        # ---- 1. Cloudflare ranges and prefix list state (only when a list is involved)
        cf_ranges: Optional[CloudflareIpRanges] = None
        if managed_ids or compare_ids:
            cf_ranges = fetch_cloudflare_ip_ranges(config=config, http_get=http_get)

        prefix_list_states: Dict[str, Dict[str, Any]] = {}
        diffs: Dict[str, PrefixListDiff] = {}
        if cf_ranges is not None:
            for key, pl_id, desired in (
                ("ipv4", config.ipv4_prefix_list_id, cf_ranges.ipv4_cidrs),
                ("ipv6", config.ipv6_prefix_list_id, cf_ranges.ipv6_cidrs),
            ):
                if not pl_id:
                    continue
                state = get_prefix_list_state(ec2_client, pl_id)
                prefix_list_states[key] = state
                diffs[key] = compute_prefix_list_diff(
                    pl_state=state,
                    desired_cidrs=desired,
                    max_removal_ratio=config.max_removal_ratio,
                    force_update=config.force_update,
                )
        comparisons: List[Dict[str, Any]] = []
        if cf_ranges is not None:
            for pl_id in compare_ids:
                comparisons.append(_compare_reference_list(ec2_client, pl_id, cf_ranges))

        cloudflare_ids = managed_ids + compare_ids
        plan_list_ids = managed_ids or compare_ids
        pl_changes = any(d.has_changes for d in diffs.values())

        summary: Dict[str, Any] = {
            "status": "NO_CHANGES",
            "mode": mode,
            "timestamp_utc": utc_now_iso(),
            "account_id": account_id,
            "region": region,
            "dry_run": config.dry_run,
            "cloudflare": None if cf_ranges is None else {
                "source": cf_ranges.source,
                "etag": cf_ranges.etag,
                "ipv4_count": len(cf_ranges.ipv4_cidrs),
                "ipv6_count": len(cf_ranges.ipv6_cidrs),
            },
            "diffs": {
                k: {
                    "prefix_list_id": d.prefix_list_id,
                    "address_family": d.address_family,
                    "current_version": d.current_version,
                    "has_changes": d.has_changes,
                    "have_count": len(d.current_cidrs),
                    "want_count": len(d.desired_cidrs),
                    "to_add": list(d.to_add),
                    "to_remove": list(d.to_remove),
                }
                for k, d in diffs.items()
            },
            "comparisons": comparisons,
            "backup": None,
            "updates": {},
        }

        # ---- 2. Scope, discovery / audit (the "what you have" half)
        allow = AllowList.build(
            config.allowed_cidrs, config.allowed_prefix_list_ids,
            config.allowed_source_security_group_ids,
        )
        needs_sg_view = mode == DISCOVER or config.audit_enabled or caps.attach_rules
        tagged: Set[str] = set()
        tag_errors: List[str] = []
        if needs_sg_view and config.managed_tag_key:
            try:
                tagged = find_tagged_security_groups(
                    ec2_client, config.managed_tag_key, config.managed_tag_value)
            except Exception as exc:
                tag_errors.append(f"tag scope lookup failed: {exc}")
        mutable_ids = set(_split_ids(config.managed_security_group_ids)) | tagged
        audited_ids = set(_split_ids(config.alb_security_group_ids)) | mutable_ids

        groups: List[Dict[str, Any]] = []
        if mode == DISCOVER:
            discovery = run_discovery(
                ec2_client, elbv2_client, cloudfront_client,
                managed_prefix_list_ids=cloudflare_ids, tagged_sg_ids=tagged, allow=allow)
            groups = discovery.pop("_groups", [])
            discovery["errors"].extend(tag_errors)
            summary["discovery"] = discovery
            # Also show anything the user explicitly listed that discovery did not reach
            missing = audited_ids - {g["GroupId"] for g in groups}
            if missing:
                try:
                    groups += ec2_client.describe_security_groups(GroupIds=sorted(missing)).get(
                        "SecurityGroups", [])
                except Exception as exc:
                    discovery["errors"].append(f"listed security groups not readable: {exc}")
        elif needs_sg_view:
            audit = run_exposure_audit(
                ec2_client=ec2_client, elbv2_client=elbv2_client,
                managed_prefix_list_ids=cloudflare_ids, explicit_sg_ids=sorted(audited_ids),
                audit_all_load_balancers=config.audit_all_load_balancers, allow=allow)
            groups = audit.pop("_groups", [])
            audit["errors"].extend(tag_errors)
            summary["audit"] = audit

        settings = RemediationSettings(
            ports=tuple(config.ingress_ports or (443,)), allow=allow,
            revoke_private_cidrs=config.revoke_private_cidrs,
            revoke_security_group_sources=config.revoke_security_group_sources,
            max_revocations=config.max_revocations_per_run, force=config.force_update)
        plan = plan_security_groups(
            groups, plan_list_ids, settings, cloudflare_prefix_list_ids=cloudflare_ids
        ) if plan_list_ids else {}
        summary["security_group_plan"] = plan
        mutable_plan = {k: v for k, v in plan.items() if k in mutable_ids}
        mutable_groups = [g for g in groups if g["GroupId"] in mutable_ids]

        # In attach mode only authorizations are actionable; enforce also revokes.
        def _actionable(actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            return [a for a in actions if a["action"] == "authorize" or caps.revoke_rules]

        sg_changes = caps.attach_rules and any(_actionable(a) for a in mutable_plan.values())
        any_changes = pl_changes or bool(sg_changes)
        # Drift = anything that differs from "Cloudflare only", whether or not this mode may fix it
        drift = pl_changes or bool(plan) or any(not c["in_sync"] for c in comparisons)

        # ---- 3. Backup, then write
        # (a live write below overrides this with UPDATED)
        if any_changes and caps.writes and not live:
            summary["status"] = "DRY_RUN_CHANGES_DETECTED"
        elif drift:
            summary["status"] = "DRIFT_DETECTED"
        if any_changes and live:
            backup_cfg = replace(
                config,
                alb_security_group_ids=sorted(set(_split_ids(config.alb_security_group_ids)) | mutable_ids),
            )
            backup_info = create_pre_update_backup(
                config=backup_cfg, ec2_client=ec2_client, s3_client=s3_client,
                prefix_list_states=prefix_list_states, diffs=diffs, cf_ranges=cf_ranges,
                account_id=account_id, region=region,
            ) if cf_ranges is not None else None
            if backup_info is not None:
                summary["backup"] = {
                    "backup_id": backup_info["backup_id"],
                    "sha256_checksum": backup_info["sha256_checksum"],
                    "locations": backup_info["locations"],
                    "security_groups_captured": backup_info["security_groups_captured"],
                }
            for key, diff in diffs.items():
                if diff.has_changes:
                    summary["updates"][key] = apply_prefix_list_diff(
                        ec2_client=ec2_client, diff=diff,
                        entry_description=config.entry_description, poll_interval=poll_interval)
            summary["status"] = "UPDATED"

        if caps.attach_rules and mutable_plan:
            # Revocation safety comes from the managed lists (always present in attach/enforce).
            # Rules that reference a compare-only list are kept; that list's drift is reported.
            try:
                remediation = apply_plan(
                    ec2_client, mutable_groups, mutable_plan, plan_list_ids, settings,
                    allow_attach=True, allow_revoke=caps.revoke_rules, dry_run=not live)
            except RemediationGuardrailError as exc:
                remediation = {"dry_run": not live, "authorized": [], "revoked": [], "skipped": [],
                               "errors": [{"error": f"guardrail: {exc}"}]}
            summary["remediation"] = remediation
            if live and (remediation["authorized"] or remediation["revoked"]):
                summary["status"] = "UPDATED"
                if config.audit_enabled:
                    after = run_exposure_audit(
                        ec2_client=ec2_client, elbv2_client=elbv2_client,
                        managed_prefix_list_ids=cloudflare_ids, explicit_sg_ids=sorted(audited_ids),
                        audit_all_load_balancers=config.audit_all_load_balancers, allow=allow)
                    after.pop("_groups", None)
                    summary["audit_after"] = after

        if mode == DISCOVER:
            summary["status"] = "DISCOVERY"
        elif not any_changes:
            logger.info("Nothing to change (mode=%s).", mode)
        elif not live and not caps.writes:
            logger.info("Read-only mode '%s': drift detected, nothing modified.", mode)

        # ---- 4. Have-vs-needs report and notification
        cf_ids_for_view = cloudflare_ids
        sg_state = [summarize_security_group(g, cf_ids_for_view, allow) for g in groups]
        report = build_gap_report(summary, sg_state)
        summary["report"] = report
        if should_notify(notify_policy, report) and send_report(
            sns_client, config.sns_topic_arn, report, summary, notify_format
        ):
            summary["notified"] = True
        return summary

    except Exception as exc:
        error_payload = {
            "status": "ERROR",
            "timestamp_utc": utc_now_iso(),
            "account_id": account_id,
            "region": region,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }
        if notify_policy != "never":
            send_sns_notification(
                sns_client=sns_client,
                topic_arn=config.sns_topic_arn,
                subject=f"[CF-Prefix-Sync] ALERT: Sync Error in {region}",
                payload=error_payload,
            )
        raise


def restore_prefix_list_version(
    ec2_client: Any,
    prefix_list_id: str,
    target_version: Optional[int] = None,
    dry_run: bool = True,
    poll_interval: float = 1.0,
) -> Dict[str, Any]:
    """
    Rolls back a Customer-Managed VPC Prefix List using AWS's native `RestoreManagedPrefixListVersion` API.
    If `target_version` is None, defaults to `current_version - 1`.
    """
    pl_meta = wait_for_prefix_list_ready(ec2_client, prefix_list_id, poll_interval=poll_interval)
    current_version = int(pl_meta.get("Version", 1))
    if target_version is None:
        target_version = current_version - 1

    if target_version < 1 or target_version >= current_version:
        raise ValueError(
            f"Invalid target_version={target_version} for Prefix List '{prefix_list_id}' "
            f"(current_version={current_version}). Must be between 1 and {current_version - 1}."
        )

    if dry_run:
        return {
            "status": "DRY_RUN_ROLLBACK",
            "prefix_list_id": prefix_list_id,
            "current_version": current_version,
            "restore_to_version": target_version,
        }

    ec2_client.restore_managed_prefix_list_version(
        PrefixListId=prefix_list_id,
        PreviousVersion=target_version,
        CurrentVersion=current_version,
    )
    updated_meta = wait_for_prefix_list_ready(ec2_client, prefix_list_id, poll_interval=poll_interval)
    new_version = int(updated_meta.get("Version", current_version + 1))

    return {
        "status": "RESTORED_FROM_AWS_VERSION",
        "prefix_list_id": prefix_list_id,
        "previous_version": current_version,
        "restored_source_version": target_version,
        "new_version": new_version,
    }


def restore_from_backup_snapshot(
    ec2_client: Any,
    snapshot: Dict[str, Any],
    dry_run: bool = True,
    poll_interval: float = 1.0,
) -> Dict[str, Any]:
    """
    Restores all Prefix Lists recorded in a JSON backup snapshot (`snapshot["prefix_lists"]`)
    to their exact historical CIDR entries.
    """
    pl_backups = snapshot.get("prefix_lists", {})
    if not pl_backups:
        raise ValueError("Backup snapshot does not contain any 'prefix_lists' entries.")

    results: Dict[str, Any] = {}
    for key, backed_up_state in pl_backups.items():
        pl_id = backed_up_state["prefix_list_id"]
        desired_cidrs = tuple(sorted(backed_up_state.get("cidrs", [])))
        current_state = get_prefix_list_state(ec2_client, pl_id)
        diff = compute_prefix_list_diff(
            pl_state=current_state,
            desired_cidrs=desired_cidrs,
            force_update=True,
        )
        if dry_run:
            results[key] = {
                "prefix_list_id": pl_id,
                "status": "DRY_RUN_RESTORE" if diff.has_changes else "ALREADY_MATCHES_BACKUP",
                "to_add": list(diff.to_add),
                "to_remove": list(diff.to_remove),
            }
        else:
            if not diff.has_changes:
                results[key] = {
                    "prefix_list_id": pl_id,
                    "status": "ALREADY_MATCHES_BACKUP",
                    "modified": False,
                }
            else:
                res = apply_prefix_list_diff(
                    ec2_client=ec2_client,
                    diff=diff,
                    entry_description=f"Restored from backup {snapshot.get('backup_id', 'snapshot')}",
                    poll_interval=poll_interval,
                )
                results[key] = res

    return {
        "backup_id": snapshot.get("backup_id", "unknown"),
        "dry_run": dry_run,
        "results": results,
    }
