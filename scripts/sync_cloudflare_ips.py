#!/usr/bin/env python3
"""
Standalone CLI for cloudflare-prefix-sync.
==========================================
Runs the same engine as the Lambda, from a workstation, CloudShell or a CI runner.

Modes (see docs/MODES.md), from read-only to fully autonomous:
  discover  inventory entry points and exposure
  audit     + compare prefix lists with Cloudflare and audit security groups
  sync      + update the managed prefix lists            (default)
  attach    + add missing Cloudflare rules to in-scope security groups
  enforce   + revoke non-Cloudflare ingress on in-scope security groups

Nothing is written unless you pass --execute. Without it every mode is a preview.

Examples
  # What is exposed in this account? (read-only, no setup needed)
  python scripts/sync_cloudflare_ips.py --mode discover --region us-east-1

  # How does my existing prefix list compare with Cloudflare, and who is told?
  python scripts/sync_cloudflare_ips.py --mode audit --compare-prefix-list-ids pl-0abc \\
      --security-group-ids sg-0123 --sns-topic-arn arn:aws:sns:us-east-1:111122223333:alerts \\
      --notify-on drift

  # Preview, then apply, full enforcement on two security groups
  python scripts/sync_cloudflare_ips.py --mode enforce --ipv4-prefix-list-id pl-1 \\
      --ipv6-prefix-list-id pl-2 --managed-security-group-ids sg-0123 sg-0456
  ... --execute
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import boto3

# Ensure repo root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.modes import ALL_MODES, DISCOVER  # noqa: E402
from src.report import NOTIFY_POLICIES, render_text  # noqa: E402
from src.sync_engine import SyncConfig, run_sync  # noqa: E402


def _csv_env(name: str) -> list:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Make Cloudflare the only way into your AWS entry points: discover, audit, sync, attach or enforce.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--mode", choices=ALL_MODES, default=os.environ.get("MODE", "sync"),
                   help="How much the tool may do (default: sync).")

    g = p.add_argument_group("prefix lists")
    g.add_argument("--ipv4-prefix-list-id", default=os.environ.get("IPV4_PREFIX_LIST_ID"),
                   help="Managed IPv4 prefix list. Updated in sync/attach/enforce.")
    g.add_argument("--ipv6-prefix-list-id", default=os.environ.get("IPV6_PREFIX_LIST_ID"),
                   help="Managed IPv6 prefix list.")
    g.add_argument("--compare-prefix-list-ids", nargs="*", default=_csv_env("COMPARE_PREFIX_LIST_IDS"),
                   help="Existing prefix lists to compare with Cloudflare. Read-only, never modified.")

    g = p.add_argument_group("security groups")
    g.add_argument("--security-group-ids", "--alb-security-group-ids", dest="security_group_ids", nargs="*",
                   default=_csv_env("SECURITY_GROUP_IDS") or _csv_env("ALB_SECURITY_GROUP_IDS"),
                   help="Existing security groups to discover, audit and back up. Read-only.")
    g.add_argument("--managed-security-group-ids", nargs="*", default=_csv_env("MANAGED_SECURITY_GROUP_IDS"),
                   help="Security groups attach/enforce may change.")
    g.add_argument("--managed-tag-key", default=os.environ.get("MANAGED_TAG_KEY", "cloudflare-prefix-sync"),
                   help="Security groups with this tag are also in the change scope ('' disables).")
    g.add_argument("--managed-tag-value", default=os.environ.get("MANAGED_TAG_VALUE", "managed"))
    g.add_argument("--ingress-ports", nargs="*", type=int, default=[443],
                   help="TCP ports that need a Cloudflare rule (default: 443).")
    g.add_argument("--allowed-cidrs", nargs="*", default=_csv_env("ALLOWED_CIDRS"),
                   help="Expected sources that are never reported or revoked (for example an admin CIDR).")
    g.add_argument("--allowed-prefix-list-ids", nargs="*", default=_csv_env("ALLOWED_PREFIX_LIST_IDS"))
    g.add_argument("--allowed-source-security-group-ids", nargs="*",
                   default=_csv_env("ALLOWED_SOURCE_SECURITY_GROUP_IDS"))
    g.add_argument("--revoke-private-cidrs", action="store_true", help="enforce: also revoke RFC1918 sources.")
    g.add_argument("--revoke-security-group-sources", action="store_true",
                   help="enforce: also revoke rules that reference other security groups.")
    g.add_argument("--max-revocations-per-run", type=int, default=25,
                   help="enforce: refuse to revoke more rules than this in one run (default: 25).")

    g = p.add_argument_group("audit and notification")
    g.add_argument("--audit", action="store_true", help="Run the exposure audit (implied by audit/attach/enforce).")
    g.add_argument("--audit-all-load-balancers", action="store_true",
                   help="Also audit every internet-facing ALB/NLB in the region.")
    g.add_argument("--sns-topic-arn", default=os.environ.get("SNS_TOPIC_ARN"),
                   help="SNS topic that receives the have-vs-needs report.")
    g.add_argument("--notify-on", choices=NOTIFY_POLICIES, default=os.environ.get("NOTIFY_ON", "alerts"),
                   help="never | alerts (default) | drift | always")
    g.add_argument("--notify-format", choices=("text", "json"), default=os.environ.get("NOTIFY_FORMAT", "text"))
    g.add_argument("--format", choices=("json", "text"), default="json", dest="output_format",
                   help="How to print the result locally (default: json).")

    g = p.add_argument_group("safety and backups")
    g.add_argument("--backup-s3-bucket", default=os.environ.get("BACKUP_S3_BUCKET"))
    g.add_argument("--backup-s3-prefix", default=os.environ.get("BACKUP_S3_PREFIX", "backups"))
    g.add_argument("--backup-dir", default=os.path.join(REPO_ROOT, "backups"),
                   help="Local directory for pre-update JSON backups (default: ./backups).")
    g.add_argument("--min-ipv4-cidrs", type=int, default=10)
    g.add_argument("--min-ipv6-cidrs", type=int, default=5)
    g.add_argument("--max-removal-ratio", type=float, default=0.50)
    g.add_argument("--force", action="store_true",
                   help="Bypass the prefix-list removal and revocation circuit breakers.")

    g = p.add_argument_group("aws")
    g.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))
    g.add_argument("--profile", default=None)
    p.add_argument("--execute", action="store_true", default=False,
                   help="Apply changes. Without this flag every mode is a read-only preview.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    config = SyncConfig(
        mode=args.mode,
        ipv4_prefix_list_id=args.ipv4_prefix_list_id,
        ipv6_prefix_list_id=args.ipv6_prefix_list_id,
        compare_prefix_list_ids=args.compare_prefix_list_ids,
        alb_security_group_ids=args.security_group_ids,
        managed_security_group_ids=args.managed_security_group_ids,
        managed_tag_key=args.managed_tag_key,
        managed_tag_value=args.managed_tag_value,
        ingress_ports=args.ingress_ports,
        allowed_cidrs=args.allowed_cidrs,
        allowed_prefix_list_ids=args.allowed_prefix_list_ids,
        allowed_source_security_group_ids=args.allowed_source_security_group_ids,
        revoke_private_cidrs=args.revoke_private_cidrs,
        revoke_security_group_sources=args.revoke_security_group_sources,
        max_revocations_per_run=args.max_revocations_per_run,
        backup_s3_bucket=args.backup_s3_bucket,
        backup_s3_prefix=args.backup_s3_prefix,
        backup_local_dir=args.backup_dir,
        sns_topic_arn=args.sns_topic_arn,
        notify_on=args.notify_on,
        notify_format=args.notify_format,
        min_ipv4_cidrs=args.min_ipv4_cidrs,
        min_ipv6_cidrs=args.min_ipv6_cidrs,
        max_removal_ratio=args.max_removal_ratio,
        force_update=args.force,
        dry_run=not args.execute,
        audit_enabled=args.audit or args.audit_all_load_balancers or args.mode != "sync",
        audit_all_load_balancers=args.audit_all_load_balancers or args.mode == DISCOVER,
    )

    session = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    ec2_client = session.client("ec2")
    s3_client = session.client("s3") if config.backup_s3_bucket else None
    sns_client = session.client("sns") if config.sns_topic_arn else None
    sts_client = session.client("sts")
    result = run_sync(
        config=config,
        ec2_client=ec2_client,
        s3_client=s3_client,
        sns_client=sns_client,
        sts_client=sts_client,
        elbv2_client=session.client("elbv2") if (config.audit_enabled or config.mode == DISCOVER) else None,
        cloudfront_client=session.client("cloudfront") if config.mode == DISCOVER else None,
    )
    if args.output_format == "text":
        print(render_text(result["report"], result))
    else:
        print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
