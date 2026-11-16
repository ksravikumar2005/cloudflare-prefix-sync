#!/usr/bin/env bash
# ==============================================================================
# cloudflare-prefix-sync - CloudFormation deployer for AWS CloudShell / Linux / macOS
# ==============================================================================
# Needs: AWS CLI v2 and python3 (both preinstalled in CloudShell).
# Without --execute it only packages the code and validates the template.
#
# Usage:
#   ./scripts/deploy_cli_cloudshell.sh --artifact-bucket <bucket> [options] [--execute]
#
# Options:
#   --artifact-bucket <name>        Existing S3 bucket (same region) for the Lambda zip. Required.
#   --stack-name <name>             Stack name (default: cloudflare-prefix-sync)
#   --region <region>               AWS region (default: $AWS_REGION or us-east-1)
#   --mode <mode>                   discover | audit | sync | attach | enforce (default: audit)
#   --lambda-dry-run                Deploy with DryRun=true (preview writes in attach/enforce)
#   --security-group-ids <ids>      Comma-separated SGs to audit/report on (never changed)
#   --managed-security-group-ids <ids>  Comma-separated SGs attach/enforce may change
#   --compare-prefix-list-ids <ids> Comma-separated existing prefix lists to compare (never changed)
#   --existing-prefix-lists <v4>,<v6>   Manage existing prefix lists instead of creating new ones
#   --email <address>               Subscribe an email to the report topic
#   --notify-on <policy>            never | alerts | drift | always (default: alerts)
#   --tags "K=V K2=V2"              Stack tags (propagate to all resources)
#   --param Key=Value               Any other template parameter (repeatable)
#   --execute                       Deploy and run the function once
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE_FILE="${REPO_ROOT}/templates/cloudflare-prefix-sync-template.yaml"

STACK_NAME="cloudflare-prefix-sync"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
ARTIFACT_BUCKET=""
EXECUTE="false"
TAGS="Project=cloudflare-prefix-sync"
MODE="audit"
DRY_RUN="false"
PARAMS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-bucket) ARTIFACT_BUCKET="$2"; shift 2 ;;
    --stack-name) STACK_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --lambda-dry-run) DRY_RUN="true"; shift ;;
    --security-group-ids) PARAMS+=("SecurityGroupIds=$2"); shift 2 ;;
    --managed-security-group-ids) PARAMS+=("ManagedSecurityGroupIds=$2"); shift 2 ;;
    --compare-prefix-list-ids) PARAMS+=("ComparePrefixListIds=$2"); shift 2 ;;
    --existing-prefix-lists)
      PARAMS+=("CreatePrefixLists=false" "ExistingIpv4PrefixListId=${2%%,*}" "ExistingIpv6PrefixListId=${2#*,}")
      shift 2 ;;
    --email) PARAMS+=("NotificationEmail=$2"); shift 2 ;;
    --notify-on) PARAMS+=("NotifyOn=$2"); shift 2 ;;
    --tags) TAGS="$TAGS $2"; shift 2 ;;
    --param) PARAMS+=("$2"); shift 2 ;;
    --execute) EXECUTE="true"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown argument '$1' (see --help)" >&2; exit 1 ;;
  esac
done

if [[ -z "${ARTIFACT_BUCKET}" ]]; then
  echo "ERROR: --artifact-bucket is required (an existing bucket in ${REGION})." >&2
  exit 1
fi

echo "[1/4] Packaging Lambda code..."
PKG_JSON="$(python3 "${REPO_ROOT}/scripts/package_lambda.py")"
LOCAL_ZIP="$(echo "${PKG_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["local_path"])')"
CODE_KEY="$(echo "${PKG_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')"
# ${arr[@]+...} keeps `set -u` happy on bash 3.2 (macOS) when no extra parameters were given
PARAMS=("Mode=${MODE}" "DryRun=${DRY_RUN}" "CodeS3Bucket=${ARTIFACT_BUCKET}" "CodeS3Key=${CODE_KEY}" ${PARAMS[@]+"${PARAMS[@]}"})

echo "[2/4] Validating template..."
aws cloudformation validate-template --region "${REGION}" \
  --template-body "file://${TEMPLATE_FILE}" > /dev/null

echo "  stack:      ${STACK_NAME} (${REGION})"
echo "  code:       s3://${ARTIFACT_BUCKET}/${CODE_KEY}"
echo "  parameters: ${PARAMS[*]}"
echo "  tags:       ${TAGS}"

if [[ "${EXECUTE}" != "true" ]]; then
  echo "Preview only. Re-run with --execute to upload and deploy."
  exit 0
fi

echo "[3/4] Uploading code and deploying stack..."
aws s3 cp --region "${REGION}" "${LOCAL_ZIP}" "s3://${ARTIFACT_BUCKET}/${CODE_KEY}" --sse AES256
# shellcheck disable=SC2086
aws cloudformation deploy --region "${REGION}" \
  --template-file "${TEMPLATE_FILE}" \
  --stack-name "${STACK_NAME}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides "${PARAMS[@]}" \
  --tags ${TAGS}

FUNCTION_NAME="$(aws cloudformation describe-stacks --region "${REGION}" --stack-name "${STACK_NAME}" \
  --query "Stacks[0].Outputs[?OutputKey=='SyncLambdaFunctionName'].OutputValue" --output text)"

echo "[4/4] Running ${FUNCTION_NAME} once..."
aws lambda invoke --region "${REGION}" --function-name "${FUNCTION_NAME}" \
  --cli-binary-format raw-in-base64-out --payload '{}' /tmp/cf-prefix-sync-result.json > /dev/null
python3 - <<'EOF'
import json
r = json.load(open("/tmp/cf-prefix-sync-result.json"))
if "errorMessage" in r:
    print("Lambda error:", r["errorMessage"])
else:
    print(r.get("report", {}).get("headline", r.get("status")))
EOF
