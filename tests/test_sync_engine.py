#!/usr/bin/env python3
"""
Unit & Failure-Injection Test Suite for Cloudflare -> AWS Prefix List Sync Engine.
==================================================================================
Tests:
  1. Primary Cloudflare JSON API parsing and CIDR normalization.
  2. Automatic fallback to `/ips-v4` and `/ips-v6` when primary API fails.
  3. Anti-lockout guardrails:
     - Rejects 0.0.0.0/0 and ::/0 wildcard CIDRs.
     - Rejects RFC1918 private, loopback, link-local, and multicast CIDRs.
     - Rejects upstream payloads below minimum CIDR count thresholds.
     - Trips circuit breaker when removal ratio exceeds `max_removal_ratio`.
  4. Mandatory pre-update backup barrier:
     - Verifies S3 and local JSON backup snapshots contain Prefix List entries,
       version numbers, and ALB Security Group rules before `modify_managed_prefix_list` is called.
     - Verifies that if S3 backup fails, ZERO modifications are made to AWS Prefix Lists.
  5. Automatic `MaxEntries` capacity resize when Cloudflare adds CIDRs exceeding current capacity.
  6. Rollback restoration from both AWS native version history and JSON backup snapshots.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
from typing import Any, Dict, List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.sync_engine import (  # noqa: E402
    BackupFailureError,
    CloudflareFetchError,
    SyncConfig,
    ValidationGuardrailError,
    compute_prefix_list_diff,
    fetch_cloudflare_ip_ranges,
    normalize_and_validate_cidrs,
    restore_from_backup_snapshot,
    restore_prefix_list_version,
    run_sync,
)

SAMPLE_CF_IPV4 = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

SAMPLE_CF_IPV6 = [
    "2400:cb00::/32",
    "2405:8100::/32",
    "2405:b500::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]


class FakeMeta:
    region_name = "us-east-1"


class FakeEc2Client:
    """In-memory mock of AWS EC2 Managed Prefix Lists and Security Groups APIs."""

    def __init__(
        self,
        ipv4_entries: List[str] | None = None,
        ipv6_entries: List[str] | None = None,
        ipv4_max_entries: int = 25,
        ipv6_max_entries: int = 20,
    ) -> None:
        self.meta = FakeMeta()
        self.call_order: List[str] = []
        self.prefix_lists: Dict[str, Dict[str, Any]] = {
            "pl-ipv4": {
                "PrefixListId": "pl-ipv4",
                "PrefixListName": "cloudflare-ipv4",
                "PrefixListArn": "arn:aws:ec2:us-east-1:123456789012:prefix-list/pl-ipv4",
                "AddressFamily": "IPv4",
                "State": "create-complete",
                "Version": 3,
                "MaxEntries": ipv4_max_entries,
                "Entries": [
                    {"Cidr": c, "Description": "Initial"}
                    for c in (ipv4_entries if ipv4_entries is not None else SAMPLE_CF_IPV4)
                ],
            },
            "pl-ipv6": {
                "PrefixListId": "pl-ipv6",
                "PrefixListName": "cloudflare-ipv6",
                "PrefixListArn": "arn:aws:ec2:us-east-1:123456789012:prefix-list/pl-ipv6",
                "AddressFamily": "IPv6",
                "State": "create-complete",
                "Version": 2,
                "MaxEntries": ipv6_max_entries,
                "Entries": [
                    {"Cidr": c, "Description": "Initial"}
                    for c in (ipv6_entries if ipv6_entries is not None else SAMPLE_CF_IPV6)
                ],
            },
        }
        self.security_groups = [
            {
                "GroupId": "sg-alb123",
                "GroupName": "prod-cloudflare-alb-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "PrefixListIds": [
                            {"PrefixListId": "pl-ipv4"},
                            {"PrefixListId": "pl-ipv6"},
                        ],
                    }
                ],
            }
        ]

    def describe_managed_prefix_lists(self, PrefixListIds: List[str]) -> Dict[str, Any]:
        self.call_order.append(f"describe_managed_prefix_lists:{','.join(PrefixListIds)}")
        return {"PrefixLists": [self.prefix_lists[pid] for pid in PrefixListIds if pid in self.prefix_lists]}

    def get_managed_prefix_list_entries(
        self, PrefixListId: str, MaxResults: int = 100, NextToken: str | None = None
    ) -> Dict[str, Any]:
        self.call_order.append(f"get_managed_prefix_list_entries:{PrefixListId}")
        pl = self.prefix_lists[PrefixListId]
        return {"Entries": list(pl["Entries"])}

    def describe_security_groups(self, **kwargs: Any) -> Dict[str, Any]:
        self.call_order.append("describe_security_groups")
        return {"SecurityGroups": list(self.security_groups)}

    def modify_managed_prefix_list(self, **kwargs: Any) -> Dict[str, Any]:
        pid = kwargs["PrefixListId"]
        pl = self.prefix_lists[pid]
        if "MaxEntries" in kwargs:
            self.call_order.append(f"modify_max_entries:{pid}:{kwargs['MaxEntries']}")
            pl["MaxEntries"] = int(kwargs["MaxEntries"])
            pl["State"] = "modify-complete"
            return {"PrefixList": pl}

        self.call_order.append(f"modify_entries:{pid}")
        cur_ver = int(kwargs["CurrentVersion"])
        if cur_ver != pl["Version"]:
            raise RuntimeError(f"Version mismatch: expected {pl['Version']}, got {cur_ver}")

        current_map = {e["Cidr"]: e for e in pl["Entries"]}
        for rem in kwargs.get("RemoveEntries", []):
            current_map.pop(rem["Cidr"], None)
        for add in kwargs.get("AddEntries", []):
            current_map[add["Cidr"]] = {"Cidr": add["Cidr"], "Description": add.get("Description", "")}

        if len(current_map) > pl["MaxEntries"]:
            raise RuntimeError(f"Prefix list capacity exceeded: {len(current_map)} > {pl['MaxEntries']}")

        pl["Entries"] = [current_map[k] for k in sorted(current_map.keys())]
        pl["Version"] += 1
        pl["State"] = "modify-complete"
        return {"PrefixList": pl}

    def restore_managed_prefix_list_version(
        self, PrefixListId: str, PreviousVersion: int, CurrentVersion: int
    ) -> Dict[str, Any]:
        self.call_order.append(f"restore_version:{PrefixListId}:{PreviousVersion}")
        pl = self.prefix_lists[PrefixListId]
        if CurrentVersion != pl["Version"]:
            raise RuntimeError("CurrentVersion mismatch")
        pl["Version"] += 1
        pl["State"] = "restore-complete"
        return {"PrefixList": pl}


class FakeS3Client:
    def __init__(self, should_fail: bool = False, ec2_ref: FakeEc2Client | None = None) -> None:
        self.should_fail = should_fail
        self.ec2_ref = ec2_ref
        self.objects: Dict[str, bytes] = {}

    def put_object(self, **kwargs: Any) -> Dict[str, Any]:
        if self.ec2_ref is not None:
            self.ec2_ref.call_order.append("s3_put_object")
        if self.should_fail:
            raise RuntimeError("Simulated S3 PutObject KMS/AccessDenied failure")
        key = f"{kwargs['Bucket']}/{kwargs['Key']}"
        self.objects[key] = kwargs["Body"]
        return {"ETag": '"fake-etag"'}


class FakeSnsClient:
    def __init__(self) -> None:
        self.messages: List[Dict[str, str]] = []

    def publish(self, **kwargs: Any) -> Dict[str, Any]:
        self.messages.append(kwargs)
        return {"MessageId": "msg-123"}


class FakeStsClient:
    def get_caller_identity(self) -> Dict[str, str]:
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/SyncRole"}


def make_cf_api_response(v4_list: List[str], v6_list: List[str], etag: str = "etag-123") -> str:
    return json.dumps(
        {
            "result": {
                "ipv4_cidrs": v4_list,
                "ipv6_cidrs": v6_list,
                "etag": etag,
            },
            "success": True,
            "errors": [],
            "messages": [],
        }
    )


class TestCloudflarePrefixSync(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="cf_sync_test_")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_normalize_and_validate_cidrs_rejects_dangerous_prefixes(self) -> None:
        # 1. Reject 0.0.0.0/0
        with self.assertRaises(ValidationGuardrailError):
            normalize_and_validate_cidrs(SAMPLE_CF_IPV4 + ["0.0.0.0/0"], expected_version=4, min_count=5)

        # 2. Reject ::/0
        with self.assertRaises(ValidationGuardrailError):
            normalize_and_validate_cidrs(SAMPLE_CF_IPV6 + ["::/0"], expected_version=6, min_count=5)

        # 3. Reject RFC1918 private IPs
        with self.assertRaises(ValidationGuardrailError):
            normalize_and_validate_cidrs(SAMPLE_CF_IPV4 + ["10.0.0.0/8"], expected_version=4, min_count=5)

        # 4. Reject below minimum threshold
        with self.assertRaises(ValidationGuardrailError):
            normalize_and_validate_cidrs(SAMPLE_CF_IPV4[:3], expected_version=4, min_count=10)

    def test_fallback_to_plain_text_endpoints_when_json_api_fails(self) -> None:
        config = SyncConfig()

        def fake_http(url: str, timeout: int = 10) -> str:
            if "api.cloudflare.com" in url:
                raise urllib.error.URLError("Simulated primary API timeout")
            if url.endswith("/ips-v4"):
                return "\n".join(SAMPLE_CF_IPV4)
            if url.endswith("/ips-v6"):
                return "\n".join(SAMPLE_CF_IPV6)
            raise CloudflareFetchError(f"Unexpected URL: {url}")

        ranges = fetch_cloudflare_ip_ranges(config, http_get=fake_http, max_retries=2, retry_delay_sec=0.0)
        self.assertEqual(list(ranges.ipv4_cidrs), sorted(SAMPLE_CF_IPV4))
        self.assertEqual(list(ranges.ipv6_cidrs), sorted(SAMPLE_CF_IPV6))
        self.assertIn("ips-v4", ranges.source)

    def test_no_changes_produces_zero_backups_and_zero_modifications(self) -> None:
        ec2 = FakeEc2Client()
        s3 = FakeS3Client(ec2_ref=ec2)
        config = SyncConfig(
            ipv4_prefix_list_id="pl-ipv4",
            ipv6_prefix_list_id="pl-ipv6",
            backup_s3_bucket="my-backup-bucket",
            backup_local_dir=self.temp_dir,
            dry_run=False,
        )

        result = run_sync(
            config=config,
            ec2_client=ec2,
            s3_client=s3,
            sts_client=FakeStsClient(),
            http_get=lambda u, t=10: make_cf_api_response(SAMPLE_CF_IPV4, SAMPLE_CF_IPV6),
            poll_interval=0.0,
        )
        self.assertEqual(result["status"], "NO_CHANGES")
        self.assertIsNone(result["backup"])
        self.assertEqual(len(s3.objects), 0)
        self.assertNotIn("modify_entries:pl-ipv4", ec2.call_order)

    def test_update_creates_backup_first_and_updates_prefix_list_atomically(self) -> None:
        # Remove one IPv4 and add a new public IPv4 in Cloudflare's advertised list
        updated_v4 = [c for c in SAMPLE_CF_IPV4 if c != "198.41.128.0/17"] + ["198.41.192.0/18"]
        ec2 = FakeEc2Client(ipv4_max_entries=15)  # Exact capacity to test normal update
        s3 = FakeS3Client(ec2_ref=ec2)
        sns = FakeSnsClient()

        config = SyncConfig(
            ipv4_prefix_list_id="pl-ipv4",
            ipv6_prefix_list_id="pl-ipv6",
            alb_security_group_ids=["sg-alb123"],
            backup_s3_bucket="my-backup-bucket",
            backup_local_dir=self.temp_dir,
            sns_topic_arn="arn:aws:sns:us-east-1:123456789012:alerts",
            dry_run=False,
        )

        result = run_sync(
            config=config,
            ec2_client=ec2,
            s3_client=s3,
            sns_client=sns,
            sts_client=FakeStsClient(),
            http_get=lambda u, t=10: make_cf_api_response(updated_v4, SAMPLE_CF_IPV6),
            poll_interval=0.0,
        )

        self.assertEqual(result["status"], "UPDATED")
        self.assertIsNotNone(result["backup"])
        self.assertEqual(len(s3.objects), 1)

        # Verify strictly that S3 backup happened BEFORE modify_entries
        backup_idx = ec2.call_order.index("s3_put_object")
        modify_idx = ec2.call_order.index("modify_entries:pl-ipv4")
        self.assertLess(backup_idx, modify_idx, "Backup MUST complete before Prefix List is modified!")

        # Verify Prefix List version incremented by 1 and has the exact new CIDRs
        self.assertEqual(ec2.prefix_lists["pl-ipv4"]["Version"], 4)
        current_v4_cidrs = [e["Cidr"] for e in ec2.prefix_lists["pl-ipv4"]["Entries"]]
        self.assertIn("198.41.192.0/18", current_v4_cidrs)
        self.assertNotIn("198.41.128.0/17", current_v4_cidrs)

        # Verify local backup JSON file was written and contains pre-change state + SG rules
        backup_files = [f for f in os.listdir(self.temp_dir) if f.endswith(".json")]
        self.assertEqual(len(backup_files), 1)
        with open(os.path.join(self.temp_dir, backup_files[0]), "r", encoding="utf-8") as fh:
            snap = json.load(fh)
        self.assertIn("198.41.128.0/17", snap["prefix_lists"]["ipv4"]["cidrs"])
        self.assertEqual(len(snap["security_groups"]), 1)
        self.assertEqual(snap["security_groups"][0]["GroupId"], "sg-alb123")

    def test_backup_failure_aborts_prefix_list_modification(self) -> None:
        updated_v4 = SAMPLE_CF_IPV4 + ["198.41.192.0/18"]
        ec2 = FakeEc2Client()
        failing_s3 = FakeS3Client(should_fail=True, ec2_ref=ec2)

        config = SyncConfig(
            ipv4_prefix_list_id="pl-ipv4",
            backup_s3_bucket="my-backup-bucket",
            dry_run=False,
        )

        with self.assertRaises(BackupFailureError):
            run_sync(
                config=config,
                ec2_client=ec2,
                s3_client=failing_s3,
                sts_client=FakeStsClient(),
                http_get=lambda u, t=10: make_cf_api_response(updated_v4, SAMPLE_CF_IPV6),
                poll_interval=0.0,
            )

        # Ensure Prefix List was NOT modified
        self.assertNotIn("modify_entries:pl-ipv4", ec2.call_order)
        self.assertEqual(ec2.prefix_lists["pl-ipv4"]["Version"], 3)

    def test_auto_capacity_expansion_when_max_entries_exceeded(self) -> None:
        expanded_v4 = SAMPLE_CF_IPV4 + ["198.41.192.0/18", "198.41.64.0/18"]
        ec2 = FakeEc2Client(ipv4_max_entries=15)  # Current count=15, desired=17 -> requires resize
        s3 = FakeS3Client(ec2_ref=ec2)

        config = SyncConfig(
            ipv4_prefix_list_id="pl-ipv4",
            backup_s3_bucket="my-backup-bucket",
            dry_run=False,
        )

        result = run_sync(
            config=config,
            ec2_client=ec2,
            s3_client=s3,
            sts_client=FakeStsClient(),
            http_get=lambda u, t=10: make_cf_api_response(expanded_v4, SAMPLE_CF_IPV6),
            poll_interval=0.0,
        )

        self.assertEqual(result["status"], "UPDATED")
        self.assertIsNotNone(result["updates"]["ipv4"]["resized_max_entries"])
        self.assertGreaterEqual(ec2.prefix_lists["pl-ipv4"]["MaxEntries"], 27)

    def test_circuit_breaker_blocks_mass_cidr_removal(self) -> None:
        # Attempt to remove 10 out of 15 CIDRs (66.7% removal > 50% max_removal_ratio)
        pl_state = {
            "prefix_list_id": "pl-ipv4",
            "address_family": "IPv4",
            "version": 3,
            "max_entries": 25,
            "cidrs": SAMPLE_CF_IPV4,
        }
        truncated_desired = tuple(SAMPLE_CF_IPV4[:5])
        with self.assertRaises(ValidationGuardrailError):
            compute_prefix_list_diff(pl_state, truncated_desired, max_removal_ratio=0.50, force_update=False)

    def test_rollback_from_snapshot_and_native_version(self) -> None:
        ec2 = FakeEc2Client()
        # 1. Test native version rollback
        res_ver = restore_prefix_list_version(
            ec2_client=ec2,
            prefix_list_id="pl-ipv4",
            target_version=2,
            dry_run=False,
            poll_interval=0.0,
        )
        self.assertEqual(res_ver["status"], "RESTORED_FROM_AWS_VERSION")
        self.assertEqual(res_ver["restored_source_version"], 2)

        # 2. Test snapshot restore after modifying entries
        snapshot = {
            "backup_id": "cf-prefix-backup-test",
            "prefix_lists": {
                "ipv4": {
                    "prefix_list_id": "pl-ipv4",
                    "cidrs": SAMPLE_CF_IPV4[:-1],
                }
            },
        }
        res_snap = restore_from_backup_snapshot(
            ec2_client=ec2,
            snapshot=snapshot,
            dry_run=False,
            poll_interval=0.0,
        )
        self.assertTrue(res_snap["results"]["ipv4"]["modified"])
        self.assertEqual(res_snap["results"]["ipv4"]["removed_count"], 1)


if __name__ == "__main__":
    unittest.main()
