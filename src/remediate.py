#!/usr/bin/env python3
"""
Remediation: plan and (optionally) apply security group changes that make Cloudflare the only way in.
====================================================================================================
Planning is pure and always available, so every mode can show "what you have vs what needs to change".
Applying is only done by `mode=attach` (authorize only) and `mode=enforce` (authorize + revoke),
and only on security groups in the *mutation scope*:

  - security groups listed in `managed_security_group_ids`, plus
  - security groups carrying the opt-in tag (default `cloudflare-prefix-sync=managed`).

Security groups that are only listed for discovery/audit (`security_group_ids`) are never changed.

Guardrails
  1. Revocation needs managed Cloudflare prefix lists; without them nothing is revoked.
  2. A security group is only revoked from if it has, or has just been given, a Cloudflare rule
     for every managed prefix list on every configured port (no self-inflicted lockout).
  3. `max_revocations_per_run` (default 25) caps one run unless `force` is set.
  4. Allow-listed CIDRs, prefix lists and security groups are never revoked.
  5. Private CIDRs and security-group sources are kept unless explicitly opted in.
  6. The caller must write a backup of the scope's security groups first (see sync_engine).
  7. `restore_security_group_rules` re-adds revoked rules from a backup snapshot.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    from src.audit import AllowList, classify_ingress_sources
except ImportError:  # Lambda flat layout
    from audit import AllowList, classify_ingress_sources  # type: ignore

logger = logging.getLogger("cloudflare_prefix_sync.remediate")

DEFAULT_TAG_KEY = "cloudflare-prefix-sync"
DEFAULT_TAG_VALUE = "managed"
DEFAULT_MAX_REVOCATIONS = 25
RULE_DESCRIPTION = "Cloudflare (managed by cf-prefix-sync)"


class RemediationGuardrailError(ValueError):
    """Raised when a remediation plan violates a safety guardrail."""


@dataclass
class RemediationSettings:
    ports: Tuple[int, ...] = (443,)
    allow: AllowList = field(default_factory=AllowList)
    revoke_private_cidrs: bool = False
    revoke_security_group_sources: bool = False
    max_revocations: int = DEFAULT_MAX_REVOCATIONS
    force: bool = False


def _error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


# --------------------------------------------------------------------------- scope
def find_tagged_security_groups(
    ec2_client: Any, tag_key: str = DEFAULT_TAG_KEY, tag_value: str = DEFAULT_TAG_VALUE
) -> Set[str]:
    """Security group IDs that opted in to management through a tag."""
    if not tag_key:
        return set()
    found: Set[str] = set()
    token: Optional[str] = None
    while True:
        kwargs: Dict[str, Any] = {"Filters": [{"Name": f"tag:{tag_key}", "Values": [tag_value]}]}
        if token:
            kwargs["NextToken"] = token
        resp = ec2_client.describe_security_groups(**kwargs)
        found.update(sg["GroupId"] for sg in resp.get("SecurityGroups", []))
        token = resp.get("NextToken")
        if not token:
            return found


# --------------------------------------------------------------------------- helpers
def permission_covers_port(perm: Dict[str, Any], port: int) -> bool:
    proto = str(perm.get("IpProtocol", ""))
    if proto == "-1":
        return True
    if proto not in ("tcp", "6"):
        return False
    return int(perm.get("FromPort", 0)) <= port <= int(perm.get("ToPort", 65535))


def has_prefix_list_rule(sg: Dict[str, Any], prefix_list_id: str, port: int) -> bool:
    return any(
        permission_covers_port(perm, port)
        and any(p.get("PrefixListId") == prefix_list_id for p in perm.get("PrefixListIds", []))
        for perm in sg.get("IpPermissions", [])
    )


def _fragment(perm: Dict[str, Any], kind: str, source: str) -> Dict[str, Any]:
    """A single-source IpPermission, usable for authorize and revoke."""
    frag: Dict[str, Any] = {"IpProtocol": perm.get("IpProtocol", "tcp")}
    if "FromPort" in perm:
        frag["FromPort"] = perm["FromPort"]
    if "ToPort" in perm:
        frag["ToPort"] = perm["ToPort"]
    if kind == "cidr" and ":" in source:
        frag["Ipv6Ranges"] = [{"CidrIpv6": source}]
    elif kind == "cidr":
        frag["IpRanges"] = [{"CidrIp": source}]
    elif kind == "prefix_list":
        frag["PrefixListIds"] = [{"PrefixListId": source}]
    else:
        pair: Dict[str, str] = {"GroupId": source}
        for p in perm.get("UserIdGroupPairs", []):
            if p.get("GroupId") == source and p.get("UserId"):
                pair["UserId"] = p["UserId"]
        frag["UserIdGroupPairs"] = [pair]
    return frag


def _fragment_key(frag: Dict[str, Any]) -> Tuple[Any, ...]:
    src: Tuple[str, str] = ("", "")
    if frag.get("IpRanges"):
        src = ("cidr", frag["IpRanges"][0]["CidrIp"])
    elif frag.get("Ipv6Ranges"):
        src = ("cidr", frag["Ipv6Ranges"][0]["CidrIpv6"])
    elif frag.get("PrefixListIds"):
        src = ("prefix_list", frag["PrefixListIds"][0]["PrefixListId"])
    elif frag.get("UserIdGroupPairs"):
        src = ("security_group", frag["UserIdGroupPairs"][0]["GroupId"])
    return (str(frag.get("IpProtocol")), frag.get("FromPort"), frag.get("ToPort")) + src


def _all_fragments(sg: Dict[str, Any]) -> List[Dict[str, Any]]:
    frags: List[Dict[str, Any]] = []
    for perm in sg.get("IpPermissions", []):
        for r in perm.get("IpRanges", []):
            f = _fragment(perm, "cidr", r["CidrIp"])
            if r.get("Description"):
                f["IpRanges"][0]["Description"] = r["Description"]
            frags.append(f)
        for r in perm.get("Ipv6Ranges", []):
            f = _fragment(perm, "cidr", r["CidrIpv6"])
            if r.get("Description"):
                f["Ipv6Ranges"][0]["Description"] = r["Description"]
            frags.append(f)
        for p in perm.get("PrefixListIds", []):
            f = _fragment(perm, "prefix_list", p["PrefixListId"])
            if p.get("Description"):
                f["PrefixListIds"][0]["Description"] = p["Description"]
            frags.append(f)
        for p in perm.get("UserIdGroupPairs", []):
            f = _fragment(perm, "security_group", p["GroupId"])
            if p.get("UserId"):
                f["UserIdGroupPairs"][0]["UserId"] = p["UserId"]
            if p.get("Description"):
                f["UserIdGroupPairs"][0]["Description"] = p["Description"]
            frags.append(f)
    return frags


# --------------------------------------------------------------------------- planning
def plan_attach(
    sg: Dict[str, Any], prefix_list_ids: Iterable[str], ports: Iterable[int]
) -> List[Dict[str, Any]]:
    """Cloudflare prefix list rules this security group is missing."""
    actions: List[Dict[str, Any]] = []
    for pl_id in sorted({p for p in prefix_list_ids if p}):
        for port in ports:
            if not has_prefix_list_rule(sg, pl_id, port):
                actions.append({
                    "action": "authorize", "group_id": sg["GroupId"], "prefix_list_id": pl_id,
                    "port": port,
                    "detail": f"Allow tcp/{port} from Cloudflare prefix list {pl_id}",
                })
    return actions


def plan_revoke(
    sg: Dict[str, Any], managed_prefix_list_ids: Iterable[str], settings: RemediationSettings
) -> List[Dict[str, Any]]:
    """Ingress rules that let something other than Cloudflare reach the security group."""
    revocable = {"open_to_internet", "public_cidr", "other_prefix_list"}
    if settings.revoke_private_cidrs:
        revocable.add("private_cidr")
    if settings.revoke_security_group_sources:
        revocable.add("security_group")

    actions: List[Dict[str, Any]] = []
    for src in classify_ingress_sources(sg, managed_prefix_list_ids, settings.allow):
        if src["category"] not in revocable:
            continue
        actions.append({
            "action": "revoke", "group_id": sg["GroupId"], "kind": src["kind"],
            "source": src["source"], "port": src["port"], "category": src["category"],
            "permission": _fragment(src["permission"], src["kind"], src["source"]),
            "detail": f"Remove {src['port']} from {src['source']} ({src['category']})",
        })
    return actions


def plan_security_groups(
    security_groups: List[Dict[str, Any]],
    managed_prefix_list_ids: Iterable[str],
    settings: RemediationSettings,
    include_revokes: bool = True,
    cloudflare_prefix_list_ids: Optional[Iterable[str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Per-security-group list of recommended actions. Empty lists are omitted.
    Rules are attached for `managed_prefix_list_ids`. Sources in `cloudflare_prefix_list_ids`
    (managed plus compare-only lists; defaults to the managed lists) are never revoked.
    """
    managed = [p for p in managed_prefix_list_ids if p]
    cloudflare = sorted(set(managed) | {p for p in (cloudflare_prefix_list_ids or []) if p})
    plan: Dict[str, List[Dict[str, Any]]] = {}
    for sg in security_groups:
        actions: List[Dict[str, Any]] = []
        if managed:
            actions += plan_attach(sg, managed, settings.ports)
            if include_revokes:
                actions += plan_revoke(sg, cloudflare, settings)
        if actions:
            plan[sg["GroupId"]] = actions
    return plan


# --------------------------------------------------------------------------- execution
def _authorize(ec2_client: Any, group_id: str, perms: List[Dict[str, Any]]) -> None:
    try:
        ec2_client.authorize_security_group_ingress(GroupId=group_id, IpPermissions=perms)
    except Exception as exc:
        if _error_code(exc) != "InvalidPermission.Duplicate":
            raise


def apply_plan(
    ec2_client: Any,
    security_groups: List[Dict[str, Any]],
    plan: Dict[str, List[Dict[str, Any]]],
    managed_prefix_list_ids: Iterable[str],
    settings: RemediationSettings,
    allow_attach: bool,
    allow_revoke: bool,
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Applies `plan` (output of `plan_security_groups`) to the given security groups.
    Authorizations run first. Revocations on a group only run if every managed prefix list
    rule is present on every configured port, and never exceed the per-run cap.
    """
    managed = [p for p in managed_prefix_list_ids if p]
    by_id = {sg["GroupId"]: sg for sg in security_groups}
    result: Dict[str, Any] = {
        "dry_run": dry_run, "authorized": [], "revoked": [], "skipped": [], "errors": [],
    }

    total_revokes = sum(1 for acts in plan.values() for a in acts if a["action"] == "revoke")
    if allow_revoke and not managed and total_revokes:
        raise RemediationGuardrailError(
            "Refusing to revoke rules: no managed Cloudflare prefix list is configured, "
            "so Cloudflare access could not be guaranteed.")
    if allow_revoke and total_revokes > settings.max_revocations and not settings.force:
        raise RemediationGuardrailError(
            f"Circuit breaker: plan would revoke {total_revokes} rules, above "
            f"max_revocations_per_run={settings.max_revocations}. Review the plan and re-run with "
            "force_update / --force, or raise the limit.")

    for group_id, actions in sorted(plan.items()):
        sg = by_id.get(group_id)
        if sg is None:
            continue
        authorize_actions = [a for a in actions if a["action"] == "authorize"]
        revoke_actions = [a for a in actions if a["action"] == "revoke"]
        attach_ok = True

        for a in authorize_actions:
            if not allow_attach:
                result["skipped"].append({**a, "reason": "mode does not allow attaching rules"})
                attach_ok = False
                continue
            if dry_run:
                result["authorized"].append({**a, "applied": False})
                continue
            perm = {
                "IpProtocol": "tcp", "FromPort": a["port"], "ToPort": a["port"],
                "PrefixListIds": [{"PrefixListId": a["prefix_list_id"], "Description": RULE_DESCRIPTION}],
            }
            try:
                _authorize(ec2_client, group_id, [perm])
                result["authorized"].append({**a, "applied": True})
            except Exception as exc:
                attach_ok = False
                result["errors"].append({
                    "group_id": group_id, "action": "authorize", "detail": a["detail"],
                    "error": f"{_error_code(exc) or type(exc).__name__}: {exc}"})

        if not revoke_actions:
            continue
        if not allow_revoke:
            for a in revoke_actions:
                result["skipped"].append({**a, "reason": "mode does not allow revoking rules"})
            continue
        if not attach_ok:
            for a in revoke_actions:
                result["skipped"].append({
                    **a, "reason": "lockout guard: Cloudflare rules are not fully in place"})
            continue
        if dry_run:
            result["revoked"].extend({**a, "applied": False} for a in revoke_actions)
            continue
        try:
            ec2_client.revoke_security_group_ingress(
                GroupId=group_id, IpPermissions=[a["permission"] for a in revoke_actions])
            result["revoked"].extend({**a, "applied": True} for a in revoke_actions)
        except Exception as exc:
            result["errors"].append({
                "group_id": group_id, "action": "revoke",
                "detail": f"{len(revoke_actions)} rules",
                "error": f"{_error_code(exc) or type(exc).__name__}: {exc}"})
    return result


# --------------------------------------------------------------------------- rollback
def restore_security_group_rules(
    ec2_client: Any, snapshot: Dict[str, Any], dry_run: bool = True
) -> Dict[str, Any]:
    """
    Re-adds ingress rules recorded in a backup snapshot that are no longer present.
    It does not remove rules that were added after the backup.
    """
    results: Dict[str, Any] = {}
    for old_sg in snapshot.get("security_groups", []):
        group_id = old_sg["GroupId"]
        current = ec2_client.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
        have = {_fragment_key(f) for f in _all_fragments(current[0])} if current else set()
        missing = [f for f in _all_fragments(old_sg) if _fragment_key(f) not in have]
        entry: Dict[str, Any] = {"missing_rules": len(missing), "restored": 0, "errors": []}
        if missing and not dry_run:
            for frag in missing:
                try:
                    _authorize(ec2_client, group_id, [frag])
                    entry["restored"] += 1
                except Exception as exc:
                    entry["errors"].append(f"{_fragment_key(frag)}: {exc}")
        else:
            entry["rules"] = [list(_fragment_key(f)) for f in missing]
        results[group_id] = entry
    return {"backup_id": snapshot.get("backup_id", "unknown"), "dry_run": dry_run, "results": results}
