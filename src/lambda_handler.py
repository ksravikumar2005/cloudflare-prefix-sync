#!/usr/bin/env python3
"""
AWS Lambda entrypoint for cloudflare-prefix-sync.
=================================================
Configuration comes from environment variables. Any setting can be overridden per
invocation with the same name in lower case in the event, for example
`{"mode": "audit", "dry_run": true}`. List values are comma-separated strings or JSON lists.

Mode
  MODE                   discover | audit | sync (default) | attach | enforce   (see docs/MODES.md)
  DRY_RUN                "true" previews every write                            (default: false)

Prefix lists
  IPV4_PREFIX_LIST_ID    Managed IPv4 prefix list. Updated in sync/attach/enforce.
  IPV6_PREFIX_LIST_ID    Managed IPv6 prefix list.
  COMPARE_PREFIX_LIST_IDS  Existing prefix lists to compare with Cloudflare. Read-only.

Security groups
  SECURITY_GROUP_IDS     Existing security groups to discover/audit/back up. Read-only.
                         (ALB_SECURITY_GROUP_IDS is accepted as an alias.)
  MANAGED_SECURITY_GROUP_IDS  Security groups attach/enforce may change.
  MANAGED_TAG_KEY / MANAGED_TAG_VALUE  Opt-in tag for more groups (default cloudflare-prefix-sync=managed;
                         set MANAGED_TAG_KEY to an empty string to disable).
  INGRESS_PORTS          TCP ports that need a Cloudflare rule (default 443).
  ALLOWED_CIDRS / ALLOWED_PREFIX_LIST_IDS / ALLOWED_SOURCE_SECURITY_GROUP_IDS
                         Sources that are expected and must never be reported or revoked.
  REVOKE_PRIVATE_CIDRS / REVOKE_SECURITY_GROUP_SOURCES  "true" to also revoke these (enforce only).
  MAX_REVOCATIONS_PER_RUN  Circuit breaker for enforce (default 25).

Audit and notification
  AUDIT_ENABLED          "true" (default) runs the read-only exposure audit
  AUDIT_ALL_LOAD_BALANCERS  "true" audits every internet-facing ALB/NLB in the region
  SNS_TOPIC_ARN          Topic for the have-vs-needs report
  NOTIFY_ON              never | alerts (default) | drift | always
  NOTIFY_FORMAT          text (default) | json

Safety
  BACKUP_S3_BUCKET, BACKUP_S3_PREFIX, MIN_IPV4_CIDRS, MIN_IPV6_CIDRS, MAX_REMOVAL_RATIO
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

import boto3

try:
    from src.modes import DISCOVER, normalize_mode
    from src.sync_engine import SyncConfig, run_sync
except ImportError:
    from modes import DISCOVER, normalize_mode  # type: ignore
    from sync_engine import SyncConfig, run_sync  # type: ignore

logger = logging.getLogger("cloudflare_prefix_sync.lambda")
logger.setLevel(logging.INFO)


def _str_to_bool(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("1", "true", "yes", "y")


def _setting(event: Dict[str, Any], name: str, default: Any = None) -> Any:
    """Event value (lower-case key) wins over the environment variable."""
    key = name.lower()
    if key in event and event[key] is not None:
        return event[key]
    return os.environ.get(name, default)


def _as_list(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(s).strip() for s in raw if str(s).strip()]
    return [s.strip() for s in str(raw).split(",") if s.strip()]


def build_config_from_env(event: Dict[str, Any] | None = None) -> SyncConfig:
    event = event or {}
    audited = _as_list(_setting(event, "SECURITY_GROUP_IDS")) + \
        _as_list(_setting(event, "ALB_SECURITY_GROUP_IDS")) + \
        _as_list(event.get("alb_security_group_ids"))
    ports = [int(p) for p in _as_list(_setting(event, "INGRESS_PORTS", "443"))] or [443]

    return SyncConfig(
        mode=normalize_mode(_setting(event, "MODE", "sync")),
        ipv4_prefix_list_id=_setting(event, "IPV4_PREFIX_LIST_ID") or None,
        ipv6_prefix_list_id=_setting(event, "IPV6_PREFIX_LIST_ID") or None,
        compare_prefix_list_ids=_as_list(_setting(event, "COMPARE_PREFIX_LIST_IDS")),
        alb_security_group_ids=sorted(set(audited)),
        managed_security_group_ids=_as_list(_setting(event, "MANAGED_SECURITY_GROUP_IDS")),
        managed_tag_key=str(_setting(event, "MANAGED_TAG_KEY", "cloudflare-prefix-sync")),
        managed_tag_value=str(_setting(event, "MANAGED_TAG_VALUE", "managed")),
        ingress_ports=ports,
        allowed_cidrs=_as_list(_setting(event, "ALLOWED_CIDRS")),
        allowed_prefix_list_ids=_as_list(_setting(event, "ALLOWED_PREFIX_LIST_IDS")),
        allowed_source_security_group_ids=_as_list(_setting(event, "ALLOWED_SOURCE_SECURITY_GROUP_IDS")),
        revoke_private_cidrs=_str_to_bool(_setting(event, "REVOKE_PRIVATE_CIDRS")),
        revoke_security_group_sources=_str_to_bool(_setting(event, "REVOKE_SECURITY_GROUP_SOURCES")),
        max_revocations_per_run=int(_setting(event, "MAX_REVOCATIONS_PER_RUN", "25")),
        backup_s3_bucket=_setting(event, "BACKUP_S3_BUCKET") or None,
        backup_s3_prefix=_setting(event, "BACKUP_S3_PREFIX", "backups"),
        sns_topic_arn=_setting(event, "SNS_TOPIC_ARN") or None,
        notify_on=_setting(event, "NOTIFY_ON", "alerts"),
        notify_format=_setting(event, "NOTIFY_FORMAT", "text"),
        min_ipv4_cidrs=int(_setting(event, "MIN_IPV4_CIDRS", "10")),
        min_ipv6_cidrs=int(_setting(event, "MIN_IPV6_CIDRS", "5")),
        max_removal_ratio=float(_setting(event, "MAX_REMOVAL_RATIO", "0.50")),
        force_update=_str_to_bool(event.get("force_update", False)),
        dry_run=_str_to_bool(_setting(event, "DRY_RUN", "false")),
        audit_enabled=_str_to_bool(_setting(event, "AUDIT_ENABLED", "true"), default=True),
        audit_all_load_balancers=_str_to_bool(_setting(event, "AUDIT_ALL_LOAD_BALANCERS")),
    )


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    config = build_config_from_env(event)
    session = boto3.session.Session()
    ec2_client = session.client("ec2")
    s3_client = session.client("s3") if config.backup_s3_bucket else None
    sns_client = session.client("sns") if config.sns_topic_arn else None
    sts_client = session.client("sts")
    needs_elb = config.audit_enabled or config.mode == DISCOVER
    elbv2_client = session.client("elbv2") if needs_elb else None
    cloudfront_client = session.client("cloudfront") if config.mode == DISCOVER else None

    result = run_sync(
        config=config,
        ec2_client=ec2_client,
        s3_client=s3_client,
        sns_client=sns_client,
        sts_client=sts_client,
        elbv2_client=elbv2_client,
        cloudfront_client=cloudfront_client,
    )
    logger.info("Run completed: %s", json.dumps(
        {k: v for k, v in result.items() if k in ("status", "mode", "dry_run")}, default=str))
    return result
