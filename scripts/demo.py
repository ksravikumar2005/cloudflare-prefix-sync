#!/usr/bin/env python3
"""
Hands-on demo: break a Cloudflare prefix list on purpose and watch the automation repair it.
==========================================================================================
Creates (or adopts) a small, isolated set of resources, damages them in controlled ways,
then runs cloudflare-prefix-sync so you can see the backup it takes and the changes it makes.

Commands
  setup        Create a demo IPv4 + IPv6 prefix list (seeded from Cloudflare) and a demo
               security group that allows tcp/443 from them. Uses the default VPC unless
               --vpc-id is given.
  use-deployed Point the demo at a deployment created with demo_vpc_id (Terraform) or
               DemoVpcId (CloudFormation) instead of creating resources.
  status       Show each prefix list next to Cloudflare's list, and the security group's rules.
  break        Damage the demo: remove CIDRs from a prefix list (default 3 from IPv4), and
               optionally add a bogus CIDR, open the security group to 0.0.0.0/0, or remove
               one of its Cloudflare rules.
  run          Run the automation (default mode sync). Preview unless --execute. Runs locally
               with your credentials, or invokes the deployed Lambda with --via-lambda.
               Prints the have-vs-needs report and the backup it wrote.
  show-backup  Summarize the latest (or a given) backup file.
  walkthrough  setup -> status -> break -> audit -> sync preview -> sync -> backup -> enforce
               -> status, pausing between steps (--yes to run straight through).
  teardown     Delete resources created by `setup`. Never deletes adopted deployments.

Safety
  - Every resource the demo changes must carry the tag `cloudflare-prefix-sync-demo`.
    `break` refuses to touch anything else.
  - Local runs are scoped to the demo security group only (tag opt-in is disabled).
  - State is kept in .cfps-demo.json (git-ignored). Local backups go to backups/demo/.

Examples
  python scripts/demo.py walkthrough --region us-east-1
  python scripts/demo.py setup --region us-east-1
  python scripts/demo.py break --remove 3 --add-bogus --open-sg
  python scripts/demo.py run                     # preview
  python scripts/demo.py run --execute           # backup + repair
  python scripts/demo.py run --mode enforce --execute
  python scripts/demo.py teardown
"""

from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import random
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.audit import classify_ingress_sources  # noqa: E402
from src.report import render_text  # noqa: E402
from src.sync_engine import (  # noqa: E402
    SyncConfig,
    _default_http_get,
    fetch_cloudflare_ip_ranges,
    get_prefix_list_state,
    run_sync,
    wait_for_prefix_list_ready,
)

DEMO_TAG = "cloudflare-prefix-sync-demo"
DEFAULT_STATE_FILE = os.path.join(REPO_ROOT, ".cfps-demo.json")
DEFAULT_BACKUP_DIR = os.path.join(REPO_ROOT, "backups", "demo")
DEMO_PORT = 443
# Documentation ranges (RFC 5737 / RFC 3849): never routed on the internet, safe as "bogus" entries.
BOGUS_CIDRS = {"IPv4": "198.51.100.0/24", "IPv6": "2001:db8::/32"}

HttpGet = Callable[[str, int], str]


class DemoError(RuntimeError):
    """A demo command cannot continue; the message says why and what to do."""


# --------------------------------------------------------------------------- helpers
def _err_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def _tags_to_dict(tags: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tags or [])}


def _heading(text: str) -> None:
    print("\n" + "=" * 78 + f"\n {text}\n" + "=" * 78)


def load_state(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_state(path: str, state: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def require_state(path: str) -> Dict[str, Any]:
    state = load_state(path)
    if not state:
        raise DemoError(f"No demo state in {path}. Run `setup` or `use-deployed` first.")
    return state


def prefix_list_ids(state: Dict[str, Any]) -> List[Tuple[str, str]]:
    """[(family, prefix_list_id), ...] for the lists present in the state."""
    out = []
    if state.get("ipv4_prefix_list_id"):
        out.append(("IPv4", state["ipv4_prefix_list_id"]))
    if state.get("ipv6_prefix_list_id"):
        out.append(("IPv6", state["ipv6_prefix_list_id"]))
    return out


# --------------------------------------------------------------------------- safety
def assert_demo_resources(ec2: Any, state: Dict[str, Any]) -> None:
    """Refuse to modify anything that is not tagged as a demo resource."""
    problems = []
    for _, pl_id in prefix_list_ids(state):
        pl = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]
        if DEMO_TAG not in _tags_to_dict(pl.get("Tags")):
            problems.append(pl_id)
    sg_id = state.get("security_group_id")
    if sg_id:
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        if DEMO_TAG not in _tags_to_dict(sg.get("Tags")):
            problems.append(sg_id)
    if problems:
        raise DemoError(
            f"Refusing to modify {', '.join(problems)}: missing the '{DEMO_TAG}' tag. "
            "The demo only changes resources created for it (demo setup, or a deployment "
            "with demo_vpc_id / DemoVpcId).")


# --------------------------------------------------------------------------- setup
def find_default_vpc(ec2: Any) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", [])
    if not vpcs:
        raise DemoError("This region has no default VPC. Pass --vpc-id.")
    return vpcs[0]["VpcId"]


def setup_demo(
    ec2: Any, state: Dict[str, Any], vpc_id: Optional[str], name_prefix: str,
    http_get: HttpGet = _default_http_get,
) -> Dict[str, Any]:
    """
    Creates the demo resources. `state` is filled in as each resource is created, so the caller
    can save it even if a later step fails (and `teardown` can clean up).
    """
    vpc_id = vpc_id or find_default_vpc(ec2)
    cf = fetch_cloudflare_ip_ranges(SyncConfig(), http_get=http_get)
    demo_id = f"{name_prefix}-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')}"
    state.update({"demo_id": demo_id, "owned": True, "vpc_id": vpc_id,
                  "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})

    def tags(resource_type: str, name: str) -> List[Dict[str, Any]]:
        return [{"ResourceType": resource_type, "Tags": [
            {"Key": "Name", "Value": name},
            {"Key": DEMO_TAG, "Value": demo_id},
            {"Key": "ManagedBy", "Value": "cloudflare-prefix-sync demo"},
        ]}]

    for family, key, cidrs, max_entries in (
        ("IPv4", "ipv4_prefix_list_id", cf.ipv4_cidrs, 30),
        ("IPv6", "ipv6_prefix_list_id", cf.ipv6_cidrs, 20),
    ):
        resp = ec2.create_managed_prefix_list(
            PrefixListName=f"{demo_id}-cloudflare-{family.lower()}",
            AddressFamily=family,
            MaxEntries=max_entries,
            Entries=[{"Cidr": c, "Description": "Cloudflare (demo seed)"} for c in cidrs],
            TagSpecifications=tags("prefix-list", f"{demo_id}-cloudflare-{family.lower()}"),
        )
        state[key] = resp["PrefixList"]["PrefixListId"]
        wait_for_prefix_list_ready(ec2, state[key])
        print(f"  created {family} prefix list {state[key]} with {len(cidrs)} Cloudflare ranges")

    resp = ec2.create_security_group(
        GroupName=f"{demo_id}-sg",
        Description="cloudflare-prefix-sync demo security group (safe to delete)",
        VpcId=vpc_id,
        TagSpecifications=tags("security-group", f"{demo_id}-sg"),
    )
    state["security_group_id"] = resp["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=state["security_group_id"], IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": DEMO_PORT, "ToPort": DEMO_PORT,
        "PrefixListIds": [
            {"PrefixListId": state["ipv4_prefix_list_id"], "Description": "Cloudflare IPv4 (demo)"},
            {"PrefixListId": state["ipv6_prefix_list_id"], "Description": "Cloudflare IPv6 (demo)"},
        ],
    }])
    print(f"  created security group {state['security_group_id']} in {vpc_id}, "
          f"allowing tcp/{DEMO_PORT} from both prefix lists")
    return state


def use_deployed(
    state: Dict[str, Any], outputs: Dict[str, str], region: Optional[str]
) -> Dict[str, Any]:
    """Adopts a deployment's demo resources (never deleted by teardown)."""
    missing = [k for k in ("security_group_id",) if not outputs.get(k)]
    if missing:
        raise DemoError(
            "The deployment has no demo security group. Deploy with demo_vpc_id (Terraform) or "
            "DemoVpcId (CloudFormation), or use `setup` instead.")
    state.update({"owned": False, "region": region, **{k: v for k, v in outputs.items() if v}})
    return state


def outputs_from_stack(cfn: Any, stack_name: str) -> Dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    out = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {
        "ipv4_prefix_list_id": out.get("CloudflareIpv4PrefixListId", ""),
        "ipv6_prefix_list_id": out.get("CloudflareIpv6PrefixListId", ""),
        "security_group_id": out.get("DemoSecurityGroupId", ""),
        "function_name": out.get("SyncLambdaFunctionName", ""),
        "backup_bucket": out.get("BackupBucketName", ""),
    }


def outputs_from_terraform(tf_dir: str) -> Dict[str, str]:
    raw = subprocess.run(["terraform", f"-chdir={tf_dir}", "output", "-json"],
                         check=True, capture_output=True, text=True).stdout
    out = {k: (v.get("value") or "") for k, v in json.loads(raw).items()}
    return {
        "ipv4_prefix_list_id": out.get("cloudflare_ipv4_prefix_list_id", ""),
        "ipv6_prefix_list_id": out.get("cloudflare_ipv6_prefix_list_id", ""),
        "security_group_id": out.get("demo_security_group_id", ""),
        "function_name": out.get("sync_lambda_function_name", ""),
        "backup_bucket": out.get("backup_bucket_name", ""),
    }


# --------------------------------------------------------------------------- status
def demo_status(ec2: Any, state: Dict[str, Any], http_get: HttpGet = _default_http_get) -> Dict[str, Any]:
    cf = fetch_cloudflare_ip_ranges(SyncConfig(), http_get=http_get)
    want = {"IPv4": set(cf.ipv4_cidrs), "IPv6": set(cf.ipv6_cidrs)}
    result: Dict[str, Any] = {"prefix_lists": [], "security_group": None}

    print("\nPREFIX LISTS (have vs Cloudflare)")
    for family, pl_id in prefix_list_ids(state):
        st = get_prefix_list_state(ec2, pl_id)
        have = set(st["cidrs"])
        missing, extra = sorted(want[family] - have), sorted(have - want[family])
        result["prefix_lists"].append({"prefix_list_id": pl_id, "family": family, "version": st["version"],
                                       "have": len(have), "cloudflare": len(want[family]),
                                       "missing": missing, "extra": extra})
        verdict = "in sync" if not missing and not extra else f"{len(missing)} missing, {len(extra)} extra"
        print(f"  {pl_id} {family}  version {st['version']}  have {len(have)}, "
              f"Cloudflare {len(want[family])}  ->  {verdict}")
        for c in missing:
            print(f"      missing  {c}")
        for c in extra:
            print(f"      extra    {c}")

    sg_id = state.get("security_group_id")
    if sg_id:
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        cloudflare_ids = [pl for _, pl in prefix_list_ids(state)]
        sources = classify_ingress_sources(sg, cloudflare_ids)
        result["security_group"] = {"group_id": sg_id, "sources": [
            {"port": s["port"], "source": s["source"], "category": s["category"]} for s in sources]}
        print(f"\nSECURITY GROUP {sg_id} inbound rules")
        for s in sources or []:
            flag = "" if s["category"] == "cloudflare_prefix_list" else "   <- not Cloudflare"
            print(f"  {s['port']:<14} from {s['source']:<24} [{s['category']}]{flag}")
        if not sources:
            print("  (no inbound rules)")
        have_pls = {s["source"] for s in sources if s["category"] == "cloudflare_prefix_list"}
        for _, pl in prefix_list_ids(state):
            if pl not in have_pls:
                print(f"  missing rule  tcp/{DEMO_PORT} from {pl}   <- attach/enforce re-add this")
    return result


# --------------------------------------------------------------------------- break
def _modify_entries(ec2: Any, pl_id: str, add: List[str], remove: List[str]) -> None:
    if not add and not remove:
        return
    meta = wait_for_prefix_list_ready(ec2, pl_id)
    kwargs: Dict[str, Any] = {"PrefixListId": pl_id, "CurrentVersion": int(meta["Version"])}
    if add:
        kwargs["AddEntries"] = [{"Cidr": c, "Description": "demo: bogus entry"} for c in add]
    if remove:
        kwargs["RemoveEntries"] = [{"Cidr": c} for c in remove]
    ec2.modify_managed_prefix_list(**kwargs)
    wait_for_prefix_list_ready(ec2, pl_id)


def break_demo(
    ec2: Any, state: Dict[str, Any], remove: int = 3, remove_cidrs: Optional[List[str]] = None,
    family: str = "ipv4", add_bogus: bool = False, open_sg: bool = False,
    drop_sg_rule: bool = False, seed: Optional[int] = None,
) -> List[str]:
    """Damages the demo resources and returns a description of each change."""
    assert_demo_resources(ec2, state)
    rng = random.Random(seed)
    families = {"ipv4": ["IPv4"], "ipv6": ["IPv6"], "both": ["IPv4", "IPv6"]}[family]
    actions: List[str] = []

    for fam, pl_id in prefix_list_ids(state):
        st = get_prefix_list_state(ec2, pl_id)
        current = sorted(st["cidrs"])
        if remove_cidrs:
            to_remove = [c for c in remove_cidrs if c in current and (":" in c) == (fam == "IPv6")]
        elif fam in families:
            # Keep at least one entry so the list is never empty
            to_remove = sorted(rng.sample(current, min(remove, max(len(current) - 1, 0))))
        else:
            to_remove = []
        to_add = [BOGUS_CIDRS[fam]] if add_bogus and fam in families and BOGUS_CIDRS[fam] not in current else []
        _modify_entries(ec2, pl_id, to_add, to_remove)
        actions += [f"removed {c} from {pl_id}" for c in to_remove]
        actions += [f"added bogus {c} to {pl_id}" for c in to_add]

    sg_id = state.get("security_group_id")
    if sg_id and open_sg:
        try:
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": DEMO_PORT, "ToPort": DEMO_PORT,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "demo: bypasses Cloudflare"}]}])
            actions.append(f"opened {sg_id} tcp/{DEMO_PORT} to 0.0.0.0/0")
        except Exception as exc:
            if _err_code(exc) != "InvalidPermission.Duplicate":
                raise
            actions.append(f"{sg_id} was already open to 0.0.0.0/0")
    if sg_id and drop_sg_rule and state.get("ipv6_prefix_list_id"):
        try:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": DEMO_PORT, "ToPort": DEMO_PORT,
                "PrefixListIds": [{"PrefixListId": state["ipv6_prefix_list_id"]}]}])
            actions.append(f"removed the IPv6 Cloudflare rule from {sg_id}")
        except Exception as exc:
            if _err_code(exc) not in ("InvalidPermission.NotFound",):
                raise
            actions.append(f"{sg_id} had no IPv6 Cloudflare rule to remove")

    for a in actions:
        print(f"  {a}")
    if not actions:
        print("  nothing changed")
    return actions


# --------------------------------------------------------------------------- run
def build_local_config(state: Dict[str, Any], mode: str, execute: bool, backup_dir: str,
                       sns_topic_arn: Optional[str], notify_on: str) -> SyncConfig:
    sg = [state["security_group_id"]] if state.get("security_group_id") else []
    return SyncConfig(
        mode=mode,
        ipv4_prefix_list_id=state.get("ipv4_prefix_list_id"),
        ipv6_prefix_list_id=state.get("ipv6_prefix_list_id"),
        alb_security_group_ids=sg,
        managed_security_group_ids=sg,
        managed_tag_key="",          # never pick up other tagged groups in the account
        ingress_ports=[DEMO_PORT],
        backup_local_dir=backup_dir,
        sns_topic_arn=sns_topic_arn,
        notify_on=notify_on,
        dry_run=not execute,
        audit_enabled=True,
    )


def run_local(ec2: Any, state: Dict[str, Any], mode: str, execute: bool, backup_dir: str,
              http_get: HttpGet = _default_http_get, sns: Optional[Any] = None,
              sns_topic_arn: Optional[str] = None, notify_on: str = "never",
              sts: Optional[Any] = None) -> Dict[str, Any]:
    if execute:
        assert_demo_resources(ec2, state)
    config = build_local_config(state, mode, execute, backup_dir, sns_topic_arn, notify_on)
    result = run_sync(config, ec2, sns_client=sns, sts_client=sts, http_get=http_get)
    print(render_text(result["report"], result))
    for key, upd in (result.get("updates") or {}).items():
        print(f"  {key}: {upd['prefix_list_id']} version {upd['previous_version']} -> {upd['new_version']} "
              f"(+{upd['added_count']} -{upd['removed_count']})")
    if result.get("backup"):
        local = [p for p in result["backup"]["locations"] if not p.startswith("s3://")]
        if local:
            with open(local[0], encoding="utf-8") as fh:
                summarize_backup(json.load(fh), local[0])
    elif not execute:
        print("\n(preview: nothing was written and no backup was needed; re-run with --execute)")
    return result


def run_via_lambda(lambda_client: Any, s3_client: Optional[Any], state: Dict[str, Any],
                   mode: Optional[str], execute: bool) -> Dict[str, Any]:
    fn = state.get("function_name")
    if not fn:
        raise DemoError("No Lambda function in the demo state. Use `use-deployed` first.")
    payload: Dict[str, Any] = {"dry_run": not execute, "notify_on": "always"}
    if mode:
        payload["mode"] = mode
    print(f"  invoking {fn} with {json.dumps(payload)}")
    resp = lambda_client.invoke(FunctionName=fn, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise DemoError(f"Lambda failed: {body.get('errorType')}: {body.get('errorMessage')}")
    print(render_text(body["report"], body))
    s3_uris = [p for p in ((body.get("backup") or {}).get("locations") or []) if p.startswith("s3://")]
    if s3_uris and s3_client is not None:
        bucket, key = s3_uris[0][5:].split("/", 1)
        snapshot = json.loads(s3_client.get_object(Bucket=bucket, Key=key)["Body"].read())
        summarize_backup(snapshot, s3_uris[0])
    return body


# --------------------------------------------------------------------------- backups
def summarize_backup(snapshot: Dict[str, Any], location: str) -> None:
    _heading("BACKUP written before the change")
    print(f"  location : {location}")
    print(f"  id       : {snapshot.get('backup_id')}   taken {snapshot.get('timestamp_utc')}")
    print(f"  sha256   : {snapshot.get('sha256_checksum', '')[:16]}...")
    planned = snapshot.get("planned_changes", {})
    for key, pl in (snapshot.get("prefix_lists") or {}).items():
        plan = planned.get(key, {})
        print(f"  {pl['prefix_list_id']} ({pl['address_family']}) version {pl['version']}: "
              f"{len(pl['cidrs'])} entries saved")
        for c in plan.get("to_add", []):
            print(f"      will add     {c}")
        for c in plan.get("to_remove", []):
            print(f"      will remove  {c}")
    for sg in snapshot.get("security_groups", []):
        n = sum(len(p.get("IpRanges", [])) + len(p.get("Ipv6Ranges", [])) + len(p.get("PrefixListIds", []))
                + len(p.get("UserIdGroupPairs", [])) for p in sg.get("IpPermissions", []))
        print(f"  {sg['GroupId']}: {n} inbound rule source(s) saved")
    print("\n  Roll back with:")
    flag = "--from-s3-uri" if location.startswith("s3://") else "--from-backup-file"
    print(f"    python scripts/restore_prefix_list.py {flag} {location} --restore-security-groups --execute")


def latest_backup(backup_dir: str) -> Optional[str]:
    files = sorted(glob.glob(os.path.join(backup_dir, "cf-prefix-backup-*.json")))
    return files[-1] if files else None


# --------------------------------------------------------------------------- teardown
def teardown_demo(ec2: Any, state: Dict[str, Any]) -> List[str]:
    if not state.get("owned"):
        raise DemoError(
            "These resources belong to a deployment (adopted with use-deployed). Remove them by "
            "unsetting demo_vpc_id / DemoVpcId and redeploying.")
    done: List[str] = []
    sg_id = state.get("security_group_id")
    if sg_id:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            done.append(f"deleted security group {sg_id}")
        except Exception as exc:
            if _err_code(exc) != "InvalidGroup.NotFound":
                raise DemoError(f"Could not delete {sg_id}: {exc}. Detach it from any resource and retry.")
    for _, pl_id in prefix_list_ids(state):
        try:
            ec2.delete_managed_prefix_list(PrefixListId=pl_id)
            done.append(f"deleted prefix list {pl_id}")
        except Exception as exc:
            if _err_code(exc) not in ("InvalidPrefixListID.NotFound", "InvalidPrefixListId.NotFound"):
                raise DemoError(f"Could not delete {pl_id}: {exc}")
    for d in done:
        print(f"  {d}")
    return done


# --------------------------------------------------------------------------- walkthrough
def walkthrough(clients: Dict[str, Any], state_file: str, vpc_id: Optional[str], name_prefix: str,
                backup_dir: str, yes: bool, teardown_after: bool,
                http_get: HttpGet = _default_http_get, pause: Callable[[str], Any] = input) -> None:
    ec2 = clients["ec2"]

    def step(title: str) -> None:
        _heading(title)
        if not yes:
            pause("  press Enter to continue (Ctrl+C to stop) ")

    state = load_state(state_file)
    if not state:
        step("1. SETUP  create a demo prefix list pair and security group")
        state = {"region": clients.get("region")}
        try:
            setup_demo(ec2, state, vpc_id, name_prefix, http_get)
        finally:
            save_state(state_file, state)
    else:
        _heading("1. SETUP  reusing existing demo resources from " + state_file)

    step("2. STATUS  everything starts in sync with Cloudflare")
    demo_status(ec2, state, http_get)

    step("3. BREAK  remove 3 Cloudflare ranges, add a bogus range, open the SG to the internet")
    break_demo(ec2, state, remove=3, add_bogus=True, open_sg=True)

    step("4. STATUS  the damage, as AWS sees it now")
    demo_status(ec2, state, http_get)

    step("5. AUDIT  read-only: what the automation reports (nothing is changed)")
    run_local(ec2, state, "audit", False, backup_dir, http_get)

    step("6. SYNC PREVIEW  what sync would change (dry run)")
    run_local(ec2, state, "sync", False, backup_dir, http_get)

    step("7. SYNC  back up first, then add the missing ranges and remove the bogus one")
    run_local(ec2, state, "sync", True, backup_dir, http_get, sts=clients.get("sts"))

    step("8. ENFORCE  back up, then remove the 0.0.0.0/0 rule (Cloudflare rules stay)")
    run_local(ec2, state, "enforce", True, backup_dir, http_get, sts=clients.get("sts"))

    step("9. STATUS  repaired")
    demo_status(ec2, state, http_get)

    print("\nBackups from this walkthrough are in " + backup_dir)
    if teardown_after:
        step("10. TEARDOWN")
        teardown_demo(ec2, state)
        os.remove(state_file)
    else:
        print("Run `python scripts/demo.py teardown` when you are done.")


# --------------------------------------------------------------------------- CLI
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="cloudflare-prefix-sync hands-on demo.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))
    p.add_argument("--profile", default=None)
    p.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    p.add_argument("--backup-dir", default=DEFAULT_BACKUP_DIR)
    # The same flags are accepted after the subcommand (SUPPRESS keeps the top-level defaults).
    common = argparse.ArgumentParser(add_help=False)
    for flag in ("--region", "--profile", "--state-file", "--backup-dir"):
        common.add_argument(flag, default=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    _add = sub.add_parser

    def add_parser(name: str, **kw: Any) -> argparse.ArgumentParser:
        return _add(name, parents=[common], **kw)

    sub.add_parser = add_parser  # type: ignore[method-assign]

    s = sub.add_parser("setup", help="Create demo prefix lists and a demo security group.")
    s.add_argument("--vpc-id", help="VPC for the security group (default: the default VPC).")
    s.add_argument("--name-prefix", default="cfps-demo")

    s = sub.add_parser("use-deployed", help="Use the demo resources of a Terraform or CloudFormation deployment.")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--stack-name", help="CloudFormation stack deployed with DemoVpcId.")
    g.add_argument("--terraform-dir", help="Terraform directory applied with demo_vpc_id.")

    sub.add_parser("status", help="Compare the demo prefix lists with Cloudflare and list the SG rules.")

    s = sub.add_parser("break", help="Damage the demo resources on purpose.")
    s.add_argument("--remove", type=int, default=3, help="Random CIDRs to remove per list (default 3).")
    s.add_argument("--remove-cidrs", nargs="*", default=None, help="Remove these exact CIDRs instead.")
    s.add_argument("--family", choices=["ipv4", "ipv6", "both"], default="ipv4")
    s.add_argument("--add-bogus", action="store_true", help="Add a documentation-range CIDR the sync should remove.")
    s.add_argument("--open-sg", action="store_true", help="Add tcp/443 from 0.0.0.0/0 (enforce removes it).")
    s.add_argument("--drop-sg-rule", action="store_true", help="Remove the IPv6 Cloudflare rule (attach re-adds it).")
    s.add_argument("--seed", type=int, default=None, help="Make the random choice repeatable.")

    s = sub.add_parser("run", help="Run the automation against the demo resources.")
    s.add_argument("--mode", choices=["audit", "sync", "attach", "enforce"], default=None,
                   help="Default: sync locally, the deployed mode with --via-lambda.")
    s.add_argument("--execute", action="store_true", help="Apply changes. Without it this is a preview.")
    s.add_argument("--via-lambda", action="store_true", help="Invoke the deployed Lambda instead of running locally.")
    s.add_argument("--sns-topic-arn", default=None, help="Local runs: also send the report to this topic.")

    s = sub.add_parser("show-backup", help="Summarize a backup file.")
    s.add_argument("path", nargs="?", help="Backup JSON file (default: latest in --backup-dir).")

    s = sub.add_parser("walkthrough", help="Run every step in order.")
    s.add_argument("--vpc-id")
    s.add_argument("--name-prefix", default="cfps-demo")
    s.add_argument("--yes", action="store_true", help="Do not pause between steps.")
    s.add_argument("--teardown", action="store_true", help="Delete the demo resources at the end.")

    sub.add_parser("teardown", help="Delete resources created by setup.")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "show-backup":
        path = args.path or latest_backup(args.backup_dir)
        if not path:
            raise DemoError(f"No backups in {args.backup_dir}.")
        with open(path, encoding="utf-8") as fh:
            summarize_backup(json.load(fh), path)
        return 0

    import boto3

    state = load_state(args.state_file)
    region = args.region or (state or {}).get("region")
    session = boto3.session.Session(profile_name=args.profile, region_name=region)
    if not session.region_name:
        raise DemoError("No region. Pass --region or set AWS_REGION.")
    ec2 = session.client("ec2")

    if args.command == "setup":
        if state:
            raise DemoError(f"Demo state already exists in {args.state_file}. Run `teardown` first.")
        state = {"region": session.region_name}
        try:
            setup_demo(ec2, state, args.vpc_id, args.name_prefix)
        finally:
            save_state(args.state_file, state)
        print(f"\nState saved to {args.state_file}. Next: `python scripts/demo.py status`.")
    elif args.command == "use-deployed":
        outputs = (outputs_from_stack(session.client("cloudformation"), args.stack_name)
                   if args.stack_name else outputs_from_terraform(args.terraform_dir))
        state = use_deployed({}, outputs, session.region_name)
        save_state(args.state_file, state)
        print(json.dumps(state, indent=2))
    elif args.command == "status":
        demo_status(ec2, require_state(args.state_file))
    elif args.command == "break":
        break_demo(ec2, require_state(args.state_file), args.remove, args.remove_cidrs, args.family,
                   args.add_bogus, args.open_sg, args.drop_sg_rule, args.seed)
        print("\nNext: `python scripts/demo.py status`, then `python scripts/demo.py run`.")
    elif args.command == "run":
        state = require_state(args.state_file)
        if args.via_lambda:
            run_via_lambda(session.client("lambda"), session.client("s3"), state, args.mode, args.execute)
        else:
            sns = session.client("sns") if args.sns_topic_arn else None
            run_local(ec2, state, args.mode or "sync", args.execute, args.backup_dir,
                      sns=sns, sns_topic_arn=args.sns_topic_arn,
                      notify_on="always" if args.sns_topic_arn else "never", sts=session.client("sts"))
    elif args.command == "walkthrough":
        walkthrough({"ec2": ec2, "sts": session.client("sts"), "region": session.region_name},
                    args.state_file, args.vpc_id, args.name_prefix, args.backup_dir, args.yes, args.teardown)
    elif args.command == "teardown":
        state = require_state(args.state_file)
        if state.get("owned"):
            teardown_demo(ec2, state)  # raises (and keeps the state) if something cannot be deleted
        else:
            print("  adopted deployment: nothing deleted in AWS. Remove the demo security group by "
                  "unsetting demo_vpc_id / DemoVpcId and redeploying.")
        os.remove(args.state_file)
        print(f"Removed {args.state_file}.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DemoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nStopped. Demo state is kept; run `teardown` to clean up.", file=sys.stderr)
        sys.exit(130)
