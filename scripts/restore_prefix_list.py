#!/usr/bin/env python3
"""
Instant Rollback CLI for Cloudflare Customer-Managed VPC Prefix Lists.
======================================================================
Supports two restoration methods:
  1. Native AWS Prefix List Version Rollback (`--prefix-list-id <id> --previous-version` or `--target-version <N>`)
     Uses `ec2:RestoreManagedPrefixListVersion` for a single-API-call atomic rollback.
  2. Full JSON Backup Snapshot Restore (`--from-backup-file <path>` or `--from-s3-uri s3://bucket/key`)
     Reads a pre-update JSON backup snapshot and restores all backed-up Prefix Lists to their exact CIDR entries.

Defaults to `--dry-run` mode unless `--execute` is explicitly provided.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Tuple

import boto3

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.remediate import restore_security_group_rules  # noqa: E402
from src.sync_engine import (  # noqa: E402
    restore_from_backup_snapshot,
    restore_prefix_list_version,
)


def parse_s3_uri(s3_uri: str) -> Tuple[str, str]:
    if not s3_uri.startswith("s3://"):
        raise ValueError(f"Invalid S3 URI '{s3_uri}'. Must start with 's3://'.")
    without_scheme = s3_uri[len("s3://") :]
    parts = without_scheme.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Invalid S3 URI '{s3_uri}'. Expected 's3://<bucket>/<key>'.")
    return parts[0], parts[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Roll back Customer-Managed Prefix Lists via native AWS version history or a JSON backup snapshot."
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--prefix-list-id",
        help="Prefix List ID to roll back using AWS native version history (e.g. pl-0123456789abcdef0).",
    )
    mode_group.add_argument(
        "--from-backup-file",
        help="Path to a local pre-update JSON backup snapshot file.",
    )
    mode_group.add_argument(
        "--from-s3-uri",
        help="S3 URI (s3://bucket/key.json) of a pre-update JSON backup snapshot.",
    )

    parser.add_argument(
        "--previous-version",
        action="store_true",
        default=False,
        help="When using --prefix-list-id, roll back to (CurrentVersion - 1).",
    )
    parser.add_argument(
        "--target-version",
        type=int,
        default=None,
        help="When using --prefix-list-id, roll back to a specific historical version number.",
    )
    parser.add_argument(
        "--restore-security-groups",
        action="store_true",
        default=False,
        help="With a backup snapshot: also re-add security group ingress rules that were revoked "
        "by enforce mode. Rules added after the backup are left in place.",
    )
    parser.add_argument(
        "--skip-prefix-lists",
        action="store_true",
        default=False,
        help="With a backup snapshot: do not restore prefix list entries (use with --restore-security-groups).",
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        help="AWS region name.",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Optional AWS CLI profile name.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Execute the rollback. Without this flag, runs in read-only dry-run mode.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dry_run = not args.execute

    session = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    ec2_client = session.client("ec2")

    if args.prefix_list_id:
        target_ver = args.target_version
        result = restore_prefix_list_version(
            ec2_client=ec2_client,
            prefix_list_id=args.prefix_list_id,
            target_version=target_ver,
            dry_run=dry_run,
        )
        print(json.dumps(result, indent=2, default=str))
        return 0

    snapshot: Dict[str, Any]
    if args.from_backup_file:
        with open(args.from_backup_file, "r", encoding="utf-8") as fh:
            snapshot = json.load(fh)
    elif args.from_s3_uri:
        bucket, key = parse_s3_uri(args.from_s3_uri)
        s3_client = session.client("s3")
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        snapshot = json.loads(obj["Body"].read().decode("utf-8"))
    else:
        raise RuntimeError("No rollback source specified.")

    output: Dict[str, Any] = {}
    if not args.skip_prefix_lists and snapshot.get("prefix_lists"):
        output["prefix_lists"] = restore_from_backup_snapshot(
            ec2_client=ec2_client,
            snapshot=snapshot,
            dry_run=dry_run,
        )
    if args.restore_security_groups:
        output["security_groups"] = restore_security_group_rules(
            ec2_client=ec2_client, snapshot=snapshot, dry_run=dry_run
        )
    if not output:
        raise SystemExit(
            "Nothing to restore: the snapshot has no prefix lists. "
            "Add --restore-security-groups to restore revoked security group rules."
        )
    print(json.dumps(output, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
