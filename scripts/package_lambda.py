#!/usr/bin/env python3
"""
Build (and optionally upload) the Lambda deployment package.
============================================================
The CloudFormation template loads the function code from S3. This script zips `src/`
(the same code Terraform deploys) into a reproducible archive whose name contains a
content hash, so a code change always produces a new S3 key and CloudFormation updates
the function.

  python scripts/package_lambda.py
      -> dist/cloudflare-prefix-sync-<hash>.zip

  python scripts/package_lambda.py --bucket my-artifacts --region us-east-1
      -> uploads to s3://my-artifacts/cloudflare-prefix-sync/cloudflare-prefix-sync-<hash>.zip
         and prints {"bucket": ..., "key": ...}

  python scripts/package_lambda.py --bucket my-artifacts --regions us-east-1 eu-west-1
      -> uploads to my-artifacts-us-east-1 and my-artifacts-eu-west-1 (for StackSets,
         with CodeBucketHasRegionSuffix=true)

The script never creates buckets. The bucket must already exist, in the same region as the stack.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import zipfile
from typing import List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(REPO_ROOT, "src")
DIST_DIR = os.path.join(REPO_ROOT, "dist")
KEY_PREFIX = "cloudflare-prefix-sync"
FIXED_DATE = (2020, 1, 1, 0, 0, 0)  # reproducible zip timestamps


def build_zip_bytes() -> bytes:
    files: List[str] = sorted(
        name for name in os.listdir(SRC_DIR)
        if name.endswith(".py") and os.path.isfile(os.path.join(SRC_DIR, name))
    )
    if "lambda_handler.py" not in files:
        raise SystemExit(f"lambda_handler.py not found in {SRC_DIR}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in files:
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(SRC_DIR, name), "rb") as fh:
                zf.writestr(info, fh.read())
    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description="Package src/ for Lambda and optionally upload it to S3.")
    parser.add_argument("--bucket", help="Existing S3 bucket to upload to (base name when --regions is used).")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))
    parser.add_argument("--regions", nargs="*", default=[],
                        help="Upload to <bucket>-<region> for each region (StackSets).")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--key-prefix", default=KEY_PREFIX)
    args = parser.parse_args()

    data = build_zip_bytes()
    digest = hashlib.sha256(data).hexdigest()[:16]
    filename = f"cloudflare-prefix-sync-{digest}.zip"
    os.makedirs(DIST_DIR, exist_ok=True)
    local_path = os.path.join(DIST_DIR, filename)
    with open(local_path, "wb") as fh:
        fh.write(data)

    result = {"local_path": local_path, "sha256_prefix": digest, "key": f"{args.key_prefix}/{filename}"}

    if args.bucket:
        import boto3

        targets = [(f"{args.bucket}-{r}", r) for r in args.regions] if args.regions else [(args.bucket, args.region)]
        uploaded = []
        for bucket, region in targets:
            session = boto3.session.Session(profile_name=args.profile, region_name=region)
            session.client("s3").put_object(
                Bucket=bucket, Key=result["key"], Body=data, ContentType="application/zip",
                ServerSideEncryption="AES256",
            )
            uploaded.append(f"s3://{bucket}/{result['key']}")
        result["bucket"] = args.bucket
        result["uploaded"] = uploaded

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
