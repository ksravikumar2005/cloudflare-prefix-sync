#!/usr/bin/env python3
"""
Tests for the operating modes (discover, audit, sync, attach, enforce), the have-vs-needs
report, notification policy, bring-your-own prefix lists/security groups, and rollback.
All AWS calls go to in-memory fakes; nothing touches the network.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.audit import AllowList, classify_security_group  # noqa: E402
from src.modes import capabilities_for, normalize_mode  # noqa: E402
from src.remediate import restore_security_group_rules  # noqa: E402
from src.report import should_notify  # noqa: E402
from src.sync_engine import SyncConfig, run_sync  # noqa: E402

CF_V4 = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13", "104.24.0.0/14",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]
CF_V6 = [
    "2400:cb00::/32", "2405:8100::/32", "2405:b500::/32", "2606:4700::/32",
    "2803:f800::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]


def cf_http_get(url: str, timeout: int = 10) -> str:
    return json.dumps({"success": True, "result": {
        "ipv4_cidrs": CF_V4, "ipv6_cidrs": CF_V6, "etag": "test-etag"}})


def no_network(url: str, timeout: int = 10) -> str:
    raise AssertionError("Cloudflare must not be contacted in this scenario")


class FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeEc2:
    class meta:  # noqa: N801
        region_name = "us-east-1"

    def __init__(self) -> None:
        self.prefix_lists: Dict[str, Dict[str, Any]] = {}
        self.sgs: Dict[str, Dict[str, Any]] = {}
        self.instances: List[Dict[str, Any]] = []
        self.calls: List[str] = []

    # ---- prefix lists
    def add_prefix_list(self, pl_id: str, family: str, entries: List[str], max_entries: int = 50) -> None:
        self.prefix_lists[pl_id] = {"family": family, "entries": set(entries), "version": 1, "max": max_entries}

    def describe_managed_prefix_lists(self, PrefixListIds: List[str]) -> Dict[str, Any]:
        pl = self.prefix_lists[PrefixListIds[0]]
        return {"PrefixLists": [{
            "PrefixListId": PrefixListIds[0], "PrefixListName": f"name-{PrefixListIds[0]}",
            "AddressFamily": pl["family"], "State": "modify-complete",
            "Version": pl["version"], "MaxEntries": pl["max"]}]}

    def get_managed_prefix_list_entries(self, PrefixListId: str, **_: Any) -> Dict[str, Any]:
        return {"Entries": [{"Cidr": c, "Description": ""} for c in sorted(self.prefix_lists[PrefixListId]["entries"])]}

    def modify_managed_prefix_list(self, PrefixListId: str, **kw: Any) -> Dict[str, Any]:
        self.calls.append("modify_managed_prefix_list")
        pl = self.prefix_lists[PrefixListId]
        for e in kw.get("AddEntries", []):
            pl["entries"].add(e["Cidr"])
        for e in kw.get("RemoveEntries", []):
            pl["entries"].discard(e["Cidr"])
        if "MaxEntries" in kw:
            pl["max"] = kw["MaxEntries"]
        pl["version"] += 1
        return {}

    # ---- security groups
    def add_sg(self, sg_id: str, perms: List[Dict[str, Any]], tags: Optional[Dict[str, str]] = None) -> None:
        self.sgs[sg_id] = {"GroupId": sg_id, "GroupName": f"name-{sg_id}", "IpPermissions": perms,
                           "Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()]}

    def describe_security_groups(self, GroupIds: Optional[List[str]] = None,
                                 Filters: Optional[List[Dict[str, Any]]] = None, **_: Any) -> Dict[str, Any]:
        groups = list(self.sgs.values())
        if GroupIds is not None:
            groups = [self.sgs[g] for g in GroupIds]
        for f in Filters or []:
            if f["Name"].startswith("tag:"):
                key = f["Name"][4:]
                groups = [g for g in groups if any(t["Key"] == key and t["Value"] in f["Values"] for t in g["Tags"])]
            elif f["Name"] == "ip-permission.prefix-list-id":
                groups = [g for g in groups if any(
                    p["PrefixListId"] in f["Values"] for perm in g["IpPermissions"] for p in perm.get("PrefixListIds", []))]
        return {"SecurityGroups": json.loads(json.dumps(groups))}

    def authorize_security_group_ingress(self, GroupId: str, IpPermissions: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.calls.append("authorize")
        for perm in IpPermissions:
            for existing in self.sgs[GroupId]["IpPermissions"]:
                same = existing.get("FromPort") == perm.get("FromPort") and existing.get("ToPort") == perm.get("ToPort")
                if same and any(
                    p["PrefixListId"] == q["PrefixListId"]
                    for p in existing.get("PrefixListIds", []) for q in perm.get("PrefixListIds", [])
                ) or same and any(
                    r["CidrIp"] == q["CidrIp"]
                    for r in existing.get("IpRanges", []) for q in perm.get("IpRanges", [])
                ):
                    raise FakeClientError("InvalidPermission.Duplicate")
            self.sgs[GroupId]["IpPermissions"].append(json.loads(json.dumps(perm)))
        return {}

    def revoke_security_group_ingress(self, GroupId: str, IpPermissions: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.calls.append("revoke")
        for perm in IpPermissions:
            for existing in self.sgs[GroupId]["IpPermissions"]:
                if existing.get("FromPort") != perm.get("FromPort") or existing.get("ToPort") != perm.get("ToPort"):
                    continue
                for field, key in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6"),
                                   ("PrefixListIds", "PrefixListId"), ("UserIdGroupPairs", "GroupId")):
                    drop = {x[key] for x in perm.get(field, [])}
                    existing[field] = [x for x in existing.get(field, []) if x[key] not in drop]
        self.sgs[GroupId]["IpPermissions"] = [
            p for p in self.sgs[GroupId]["IpPermissions"]
            if any(p.get(f) for f in ("IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs"))]
        return {}

    def describe_instances(self, **_: Any) -> Dict[str, Any]:
        return {"Reservations": [{"Instances": self.instances}]}


class FakeElbv2:
    def __init__(self, lbs: List[Dict[str, Any]], mtls: bool = False) -> None:
        self.lbs, self.mtls = lbs, mtls

    def describe_load_balancers(self, **_: Any) -> Dict[str, Any]:
        return {"LoadBalancers": self.lbs}

    def describe_listeners(self, **_: Any) -> Dict[str, Any]:
        l: Dict[str, Any] = {"ListenerArn": "arn:l", "Protocol": "HTTPS"}
        if self.mtls:
            l["MutualAuthentication"] = {"Mode": "verify"}
        return {"Listeners": [l]}

    def describe_rules(self, **_: Any) -> Dict[str, Any]:
        return {"Rules": []}


class FakeCloudFront:
    def list_distributions(self, **_: Any) -> Dict[str, Any]:
        return {"DistributionList": {"IsTruncated": False, "Items": [{
            "Id": "E123", "DomainName": "d1.cloudfront.net", "Enabled": True,
            "Aliases": {"Items": ["www.example.com"]}, "WebACLId": "",
            "Origins": {"Items": [{"DomainName": "origin.example.com"}]}}]}}


class FakeSns:
    def __init__(self) -> None:
        self.messages: List[Dict[str, str]] = []

    def publish(self, **kw: Any) -> Dict[str, Any]:
        self.messages.append(kw)
        return {}


def https_perm(**sources: Any) -> Dict[str, Any]:
    perm: Dict[str, Any] = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}
    perm.update(sources)
    return perm


class ModeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="cf_modes_")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ec2 = FakeEc2()
        self.sns = FakeSns()
        self.ec2.add_prefix_list("pl-v4", "IPv4", CF_V4)
        self.ec2.add_prefix_list("pl-v6", "IPv6", CF_V6)

    def cfg(self, **kw: Any) -> SyncConfig:
        base: Dict[str, Any] = dict(
            ipv4_prefix_list_id="pl-v4", ipv6_prefix_list_id="pl-v6", backup_local_dir=self.tmp,
            sns_topic_arn="arn:aws:sns:us-east-1:1:t", dry_run=False, audit_enabled=True, managed_tag_key="")
        base.update(kw)
        return SyncConfig(**base)

    def run_it(self, config: SyncConfig, elb: Optional[FakeElbv2] = None, http=cf_http_get, cf=None) -> Dict[str, Any]:
        return run_sync(config, self.ec2, sns_client=self.sns, elbv2_client=elb, cloudfront_client=cf, http_get=http)


class TestModes(unittest.TestCase):
    def test_capability_ladder(self) -> None:
        flags = {m: capabilities_for(m) for m in ("discover", "audit", "sync", "attach", "enforce")}
        self.assertFalse(flags["discover"].writes)
        self.assertFalse(flags["audit"].writes)
        self.assertTrue(flags["sync"].write_prefix_lists and not flags["sync"].attach_rules)
        self.assertTrue(flags["attach"].attach_rules and not flags["attach"].revoke_rules)
        self.assertTrue(flags["enforce"].revoke_rules)

    def test_unknown_mode_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalize_mode("yolo")


class TestDiscover(ModeTestCase):
    def test_discover_needs_no_prefix_lists_or_cloudflare(self) -> None:
        self.ec2.add_sg("sg-open", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}])])
        self.ec2.instances = [{"InstanceId": "i-1", "PublicIpAddress": "3.3.3.3",
                               "SecurityGroups": [{"GroupId": "sg-open"}], "Tags": []}]
        elb = FakeElbv2([{"LoadBalancerArn": "arn:lb", "LoadBalancerName": "web", "Scheme": "internet-facing",
                          "Type": "application", "SecurityGroups": ["sg-open"]}])
        cfg = SyncConfig(mode="discover", sns_topic_arn="arn:aws:sns:us-east-1:1:t", managed_tag_key="")
        res = self.run_it(cfg, elb, http=no_network, cf=FakeCloudFront())
        self.assertEqual(res["status"], "DISCOVERY")
        d = res["discovery"]["summary"]
        self.assertEqual((d["load_balancers"], d["cloudfront_distributions"], d["public_ec2_instances"]), (1, 1, 1))
        self.assertEqual(d["security_group_exposure"], {"open_to_internet": 1})
        codes = {f["code"] for f in res["discovery"]["findings"]}
        self.assertTrue({"OPEN_TO_INTERNET", "ORIGIN_AUTH_MISSING", "CLOUDFRONT_PUBLIC_ENTRY",
                         "PUBLIC_EC2_INSTANCE"} <= codes)
        self.assertEqual(self.ec2.calls, [])  # nothing written
        self.assertEqual(len(self.sns.messages), 1)  # actionable -> alert

    def test_discover_with_existing_prefix_list_compares_it(self) -> None:
        self.ec2.prefix_lists["pl-v4"]["entries"].discard(CF_V4[0])
        cfg = SyncConfig(mode="discover", compare_prefix_list_ids=["pl-v4"], managed_tag_key="")
        res = self.run_it(cfg, FakeElbv2([]))
        self.assertEqual(res["comparisons"][0]["to_add"], [CF_V4[0]])


class TestAuditAndReport(ModeTestCase):
    def test_audit_compares_existing_list_and_never_writes(self) -> None:
        self.ec2.prefix_lists["pl-v4"]["entries"].discard("104.16.0.0/13")
        self.ec2.prefix_lists["pl-v4"]["entries"].add("9.9.9.0/24")
        self.ec2.add_sg("sg-1", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}])])
        cfg = SyncConfig(mode="audit", compare_prefix_list_ids=["pl-v4"], alb_security_group_ids=["sg-1"],
                         sns_topic_arn="arn:aws:sns:us-east-1:1:t", audit_enabled=True, managed_tag_key="")
        res = self.run_it(cfg, FakeElbv2([]))
        self.assertEqual(res["status"], "DRIFT_DETECTED")
        pl = res["report"]["prefix_lists"][0]
        self.assertEqual((pl["role"], pl["to_add"], pl["to_remove"]), ("reference", ["104.16.0.0/13"], ["9.9.9.0/24"]))
        needs = res["report"]["security_groups"][0]["needs"]
        self.assertTrue(any(n["action"] == "revoke" for n in needs))
        self.assertTrue(any(n["action"] == "authorize" for n in needs))
        self.assertEqual(self.ec2.calls, [])
        self.assertEqual(self.ec2.prefix_lists["pl-v4"]["version"], 1)
        text = self.sns.messages[0]["Message"]
        self.assertIn("have", text)
        self.assertIn("needs", text)
        self.assertIn("ADD 1, REMOVE 1", text)
        self.assertIn("ACTION NEEDED", self.sns.messages[0]["Subject"])

    def test_audit_mode_requires_a_prefix_list(self) -> None:
        with self.assertRaises(ValueError):
            self.run_it(SyncConfig(mode="audit"))

    def test_sync_mode_rejects_reference_only(self) -> None:
        with self.assertRaises(ValueError):
            self.run_it(SyncConfig(mode="sync", compare_prefix_list_ids=["pl-v4"]))

    def test_allow_list_suppresses_findings(self) -> None:
        self.ec2.add_sg("sg-1", [https_perm(PrefixListIds=[{"PrefixListId": "pl-v4"}, {"PrefixListId": "pl-v6"}],
                                            IpRanges=[{"CidrIp": "198.51.100.7/32"}])])
        base = dict(mode="audit", alb_security_group_ids=["sg-1"], audit_enabled=True, managed_tag_key="")
        noisy = self.run_it(self.cfg(**base), FakeElbv2([]))
        self.assertFalse(noisy["audit"]["compliant"])
        quiet = self.run_it(self.cfg(allowed_cidrs=["198.51.100.7/32"], **base), FakeElbv2([]))
        self.assertTrue(quiet["audit"]["compliant"])
        self.assertEqual(quiet["report"]["security_groups"][0]["exposure"], "cloudflare_only")


class TestNotifyPolicy(ModeTestCase):
    def compliant_sg(self) -> None:
        self.ec2.add_sg("sg-1", [https_perm(PrefixListIds=[{"PrefixListId": "pl-v4"}, {"PrefixListId": "pl-v6"}])])

    def test_alerts_is_silent_when_compliant(self) -> None:
        self.compliant_sg()
        res = self.run_it(self.cfg(mode="audit", alb_security_group_ids=["sg-1"]), FakeElbv2([]))
        self.assertIn("COMPLIANT", res["report"]["headline"])
        self.assertEqual(self.sns.messages, [])

    def test_always_sends_when_compliant(self) -> None:
        self.compliant_sg()
        self.run_it(self.cfg(mode="audit", alb_security_group_ids=["sg-1"], notify_on="always"), FakeElbv2([]))
        self.assertEqual(len(self.sns.messages), 1)
        self.assertIn("OK", self.sns.messages[0]["Subject"])

    def test_never_sends_nothing(self) -> None:
        self.ec2.add_sg("sg-1", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}])])
        self.run_it(self.cfg(mode="audit", alb_security_group_ids=["sg-1"], notify_on="never"), FakeElbv2([]))
        self.assertEqual(self.sns.messages, [])

    def test_json_format(self) -> None:
        self.ec2.add_sg("sg-1", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}])])
        self.run_it(self.cfg(mode="audit", alb_security_group_ids=["sg-1"], notify_format="json"), FakeElbv2([]))
        self.assertIn("report", json.loads(self.sns.messages[0]["Message"]))

    def test_drift_policy_reports_low_items(self) -> None:
        report = {"actionable": False, "has_gaps": True, "changes_applied": False, "errors": []}
        self.assertFalse(should_notify("alerts", report))
        self.assertTrue(should_notify("drift", report))


class TestSyncMode(ModeTestCase):
    def test_sync_updates_prefix_lists_but_not_security_groups(self) -> None:
        self.ec2.prefix_lists["pl-v4"]["entries"].discard("104.16.0.0/13")
        self.ec2.add_sg("sg-1", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}])])
        res = self.run_it(self.cfg(mode="sync", alb_security_group_ids=["sg-1"]), FakeElbv2([]))
        self.assertEqual(res["status"], "UPDATED")
        self.assertIn("104.16.0.0/13", self.ec2.prefix_lists["pl-v4"]["entries"])
        self.assertNotIn("revoke", self.ec2.calls)
        self.assertNotIn("authorize", self.ec2.calls)
        self.assertEqual(len(self.sns.messages), 1)


class TestAttachAndEnforce(ModeTestCase):
    def open_sg(self) -> None:
        self.ec2.add_sg("sg-1", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}, {"CidrIp": "203.0.113.9/32"}])])

    def test_dry_run_changes_nothing(self) -> None:
        self.open_sg()
        res = self.run_it(self.cfg(mode="enforce", dry_run=True, managed_security_group_ids=["sg-1"]), FakeElbv2([]))
        self.assertEqual(res["status"], "DRY_RUN_CHANGES_DETECTED")
        self.assertEqual(self.ec2.calls, [])
        self.assertTrue(res["remediation"]["revoked"])
        self.assertFalse(res["remediation"]["revoked"][0]["applied"])

    def test_attach_adds_cloudflare_rules_and_never_revokes(self) -> None:
        self.open_sg()
        res = self.run_it(self.cfg(mode="attach", managed_security_group_ids=["sg-1"]), FakeElbv2([]))
        self.assertEqual(res["status"], "UPDATED")
        self.assertEqual(len(res["remediation"]["authorized"]), 2)
        self.assertEqual(res["remediation"]["revoked"], [])
        self.assertNotIn("revoke", self.ec2.calls)
        self.assertEqual(self.ec2.sgs["sg-1"]["IpPermissions"][0]["IpRanges"][0]["CidrIp"], "0.0.0.0/0")

    def test_enforce_revokes_everything_except_allow_list_after_backup(self) -> None:
        self.open_sg()
        res = self.run_it(self.cfg(mode="enforce", managed_security_group_ids=["sg-1"],
                                   allowed_cidrs=["203.0.113.9/32"]), FakeElbv2([]))
        self.assertEqual(res["status"], "UPDATED")
        self.assertLess(self.ec2.calls.index("authorize"), self.ec2.calls.index("revoke"))
        cidrs = [r["CidrIp"] for p in self.ec2.sgs["sg-1"]["IpPermissions"] for r in p.get("IpRanges", [])]
        self.assertEqual(cidrs, ["203.0.113.9/32"])
        self.assertEqual(classify_security_group(self.ec2.sgs["sg-1"], ["pl-v4", "pl-v6"],
                                                 AllowList.build(cidrs=["203.0.113.9/32"])), "cloudflare_only")
        self.assertTrue(res["audit_after"]["compliant"])
        backups = [f for f in os.listdir(self.tmp) if f.endswith(".json")]
        self.assertEqual(len(backups), 1)
        with open(os.path.join(self.tmp, backups[0]), encoding="utf-8") as fh:
            snap = json.load(fh)
        self.assertEqual([g["GroupId"] for g in snap["security_groups"]], ["sg-1"])

    def test_backup_failure_blocks_security_group_changes(self) -> None:
        self.open_sg()
        with self.assertRaises(Exception):
            self.run_it(self.cfg(mode="enforce", managed_security_group_ids=["sg-1"], backup_local_dir=None),
                        FakeElbv2([]))
        self.assertEqual(self.ec2.calls, [])

    def test_listed_but_unmanaged_security_group_is_never_changed(self) -> None:
        self.open_sg()
        self.ec2.add_sg("sg-managed", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}])])
        res = self.run_it(self.cfg(mode="enforce", alb_security_group_ids=["sg-1"],
                                   managed_security_group_ids=["sg-managed"]), FakeElbv2([]))
        self.assertEqual(len(self.ec2.sgs["sg-1"]["IpPermissions"][0]["IpRanges"]), 2)
        self.assertIn("sg-1", res["security_group_plan"])  # still reported as "needs"

    def test_tag_opt_in_extends_scope(self) -> None:
        self.ec2.add_sg("sg-tagged", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}])],
                        tags={"cloudflare-prefix-sync": "managed"})
        self.ec2.add_sg("sg-plain", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}])])
        self.run_it(self.cfg(mode="enforce", managed_tag_key="cloudflare-prefix-sync",
                             alb_security_group_ids=["sg-plain"]), FakeElbv2([]))
        self.assertFalse(any(p.get("IpRanges") for p in self.ec2.sgs["sg-tagged"]["IpPermissions"]))
        self.assertTrue(self.ec2.sgs["sg-plain"]["IpPermissions"][0]["IpRanges"])

    def test_revocation_circuit_breaker(self) -> None:
        self.ec2.add_sg("sg-1", [https_perm(IpRanges=[{"CidrIp": f"198.51.100.{i}/32"} for i in range(1, 6)])])
        res = self.run_it(self.cfg(mode="enforce", managed_security_group_ids=["sg-1"],
                                   max_revocations_per_run=3), FakeElbv2([]))
        self.assertNotIn("revoke", self.ec2.calls)
        self.assertIn("Circuit breaker", res["remediation"]["errors"][0]["error"])
        forced = self.run_it(self.cfg(mode="enforce", managed_security_group_ids=["sg-1"],
                                      max_revocations_per_run=3, force_update=True), FakeElbv2([]))
        self.assertEqual(len(forced["remediation"]["revoked"]), 5)

    def test_rules_using_a_reference_list_are_kept_and_its_drift_reported(self) -> None:
        self.ec2.add_prefix_list("pl-ref", "IPv4", CF_V4[:5])
        self.ec2.add_sg("sg-1", [https_perm(IpRanges=[{"CidrIp": "0.0.0.0/0"}],
                                            PrefixListIds=[{"PrefixListId": "pl-ref"}])])
        res = self.run_it(self.cfg(mode="enforce", managed_security_group_ids=["sg-1"],
                                   compare_prefix_list_ids=["pl-ref"]), FakeElbv2([]))
        perm = self.ec2.sgs["sg-1"]["IpPermissions"][0]
        self.assertEqual(perm.get("IpRanges"), [])
        self.assertEqual([p["PrefixListId"] for p in perm["PrefixListIds"]], ["pl-ref"])
        ref = [p for p in res["report"]["prefix_lists"] if p["role"] == "reference"][0]
        self.assertEqual(len(ref["to_add"]), len(CF_V4) - 5)

    def test_private_cidrs_and_sg_sources_kept_by_default(self) -> None:
        self.ec2.add_sg("sg-1", [https_perm(IpRanges=[{"CidrIp": "10.0.0.0/8"}, {"CidrIp": "0.0.0.0/0"}],
                                            UserIdGroupPairs=[{"GroupId": "sg-other"}])])
        self.run_it(self.cfg(mode="enforce", managed_security_group_ids=["sg-1"]), FakeElbv2([]))
        perm = self.ec2.sgs["sg-1"]["IpPermissions"][0]
        self.assertEqual([r["CidrIp"] for r in perm["IpRanges"]], ["10.0.0.0/8"])
        self.assertEqual(perm["UserIdGroupPairs"][0]["GroupId"], "sg-other")

    def test_restore_re_adds_revoked_rules(self) -> None:
        self.open_sg()
        before = json.loads(json.dumps(self.ec2.sgs["sg-1"]))
        self.run_it(self.cfg(mode="enforce", managed_security_group_ids=["sg-1"]), FakeElbv2([]))
        preview = restore_security_group_rules(self.ec2, {"security_groups": [before]}, dry_run=True)
        self.assertEqual(preview["results"]["sg-1"]["missing_rules"], 2)
        done = restore_security_group_rules(self.ec2, {"security_groups": [before]}, dry_run=False)
        self.assertEqual(done["results"]["sg-1"]["restored"], 2)
        cidrs = {r["CidrIp"] for p in self.ec2.sgs["sg-1"]["IpPermissions"] for r in p.get("IpRanges", [])}
        self.assertEqual(cidrs, {"0.0.0.0/0", "203.0.113.9/32"})


if __name__ == "__main__":
    unittest.main()
