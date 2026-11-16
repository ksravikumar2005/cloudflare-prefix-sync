#!/usr/bin/env python3
"""
CloudFormation stack / StackSet deployer for cloudflare-prefix-sync.
====================================================================
  --target stack     one account and region (create or update)
  --target stackset  AWS Organizations SERVICE_MANAGED StackSet, deployed to OUs and regions

Steps: package src/ (scripts/package_lambda.py), upload the zip, create/update the stack or
StackSet. Without --execute it prints the plan and changes nothing.

Lambda code location
  stack:    --artifact-bucket must be an existing bucket in --region.
  stackset: Lambda needs the code in each target region. Create <artifact-bucket>-<region>
            buckets readable by the member accounts (bucket policy with aws:PrincipalOrgID),
            and this script uploads to each and sets CodeBucketHasRegionSuffix=true.

Examples
  python scripts/deploy_stackset.py --target stack --artifact-bucket my-artifacts-us-east-1 \\
      --mode audit --param SecurityGroupIds=sg-0123 --param NotificationEmail=sec@example.com

  python scripts/deploy_stackset.py --target stackset --artifact-bucket org-cfps-artifacts \\
      --mode audit --ou-ids ou-abcd-11111111 --regions us-east-1 eu-west-1 --execute
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TEMPLATE = os.path.join(REPO_ROOT, "templates", "cloudflare-prefix-sync-template.yaml")
MODES = ("discover", "audit", "sync", "attach", "enforce")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Deploy cloudflare-prefix-sync as a stack or Organizations StackSet.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--target", choices=["stack", "stackset"], default="stack")
    p.add_argument("--stack-name", default="cloudflare-prefix-sync", help="Stack or StackSet name.")
    p.add_argument("--template-path", default=DEFAULT_TEMPLATE)
    p.add_argument("--artifact-bucket", required=True, help="Existing bucket for the Lambda zip (see above).")
    p.add_argument("--mode", choices=MODES, default="audit")
    p.add_argument("--lambda-dry-run", action="store_true", help="Deploy with DryRun=true.")
    p.add_argument("--param", action="append", default=[], metavar="Key=Value",
                   help="Any other template parameter, for example SecurityGroupIds=sg-1,sg-2. Repeatable.")
    p.add_argument("--tag", action="append", default=[], metavar="Key=Value",
                   help="Stack tag, propagated to all resources. Repeatable.")
    p.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1",
                   help="Stack region, or the StackSet administration region.")
    p.add_argument("--regions", nargs="*", default=[], help="stackset: target regions (default: --region).")
    p.add_argument("--ou-ids", nargs="*", default=[], help="stackset: target organizational unit IDs.")
    p.add_argument("--profile", default=None)
    p.add_argument("--execute", action="store_true", help="Make changes. Without it the plan is printed only.")
    return p.parse_args()


def kv_list(items: List[str], what: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"{what} '{item}' must be Key=Value")
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def package(bucket: str, region: str, regions: List[str], profile: str | None, upload: bool) -> Dict[str, Any]:
    cmd = [sys.executable, os.path.join(REPO_ROOT, "scripts", "package_lambda.py")]
    if upload:
        cmd += ["--bucket", bucket]
        cmd += ["--regions", *regions] if regions else ["--region", region]
        if profile:
            cmd += ["--profile", profile]
    return json.loads(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)


def main() -> int:
    args = parse_args()
    if args.target == "stackset" and not args.ou_ids:
        raise SystemExit("--target stackset needs --ou-ids")
    regions = (args.regions or [args.region]) if args.target == "stackset" else []

    with open(args.template_path, "r", encoding="utf-8") as fh:
        template_body = fh.read()

    pkg = package(args.artifact_bucket, args.region, regions, args.profile, upload=args.execute)
    params = {"Mode": args.mode, "DryRun": "true" if args.lambda_dry_run else "false",
              "CodeS3Bucket": args.artifact_bucket, "CodeS3Key": pkg["key"]}
    if args.target == "stackset":
        params["CodeBucketHasRegionSuffix"] = "true"
    params.update(kv_list(args.param, "--param"))
    tags = {"Project": "cloudflare-prefix-sync", **kv_list(args.tag, "--tag")}

    cfn_params = [{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()]
    cfn_tags = [{"Key": k, "Value": v} for k, v in tags.items()]
    plan: Dict[str, Any] = {
        "target": args.target, "name": args.stack_name, "region": args.region, "execute": args.execute,
        "code": pkg.get("uploaded") or [f"(not uploaded) {pkg['key']}"], "parameters": params, "tags": tags,
    }
    if args.target == "stackset":
        plan.update({"regions": regions, "ou_ids": args.ou_ids})

    if not args.execute:
        print(json.dumps(plan, indent=2))
        print("Preview only. Re-run with --execute to deploy.", file=sys.stderr)
        return 0

    import boto3

    session = boto3.session.Session(profile_name=args.profile, region_name=args.region)
    cfn = session.client("cloudformation")
    common = dict(TemplateBody=template_body, Parameters=cfn_params,
                  Capabilities=["CAPABILITY_NAMED_IAM"], Tags=cfn_tags)

    if args.target == "stack":
        try:
            cfn.describe_stacks(StackName=args.stack_name)
            exists = True
        except cfn.exceptions.ClientError:
            exists = False
        if exists:
            try:
                plan["stack_id"] = cfn.update_stack(StackName=args.stack_name, **common)["StackId"]
                plan["action"] = "UPDATE_STACK"
            except cfn.exceptions.ClientError as exc:
                if "No updates are to be performed" not in str(exc):
                    raise
                plan["action"] = "NO_CHANGES"
        else:
            plan["stack_id"] = cfn.create_stack(StackName=args.stack_name, **common)["StackId"]
            plan["action"] = "CREATE_STACK"
    else:
        try:
            cfn.describe_stack_set(StackSetName=args.stack_name, CallAs="SELF")
            cfn.update_stack_set(StackSetName=args.stack_name, PermissionModel="SERVICE_MANAGED",
                                 AutoDeployment={"Enabled": True, "RetainStacksOnAccountRemoval": False}, **common)
            plan["action"] = "UPDATE_STACK_SET"
        except cfn.exceptions.StackSetNotFoundException:
            cfn.create_stack_set(StackSetName=args.stack_name, PermissionModel="SERVICE_MANAGED",
                                 Description="cloudflare-prefix-sync",
                                 AutoDeployment={"Enabled": True, "RetainStacksOnAccountRemoval": False}, **common)
            op = cfn.create_stack_instances(
                StackSetName=args.stack_name, DeploymentTargets={"OrganizationalUnitIds": args.ou_ids},
                Regions=regions, OperationPreferences={"FailureToleranceCount": 0, "MaxConcurrentCount": 1})
            plan["action"] = "CREATE_STACK_SET"
            plan["operation_id"] = op["OperationId"]

    print(json.dumps(plan, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
