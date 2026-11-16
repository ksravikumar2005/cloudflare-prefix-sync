# Installation

Choose one way to run the tool:

| Option | Best for |
| :--- | :--- |
| [CLI](#cli-no-deployment) | A one-off discover or audit, or trying settings before deploying |
| [Terraform](#terraform) | Teams that manage AWS with Terraform |
| [CloudFormation](#cloudformation) | Console, AWS CLI or CloudShell users |
| [CloudFormation StackSets](#stacksets-aws-organizations) | Many accounts and regions in AWS Organizations |
| [GitHub Actions](#github-actions) | Running from CI with OIDC instead of a Lambda |

Prefix lists and security groups are regional. Every option runs in one region per deployment.

## Prerequisites

- An AWS account and credentials. For a deployment you need permission to create IAM roles, Lambda, S3, SNS, KMS, EventBridge, CloudWatch and EC2 prefix lists.
- Python 3.10 or later and `boto3` for the CLI and Python deployers.
- AWS CLI v2 for the shell and PowerShell deployers.
- Terraform 1.5+ and AWS provider 6.x for the Terraform module.

## CLI (no deployment)

```bash
git clone https://github.com/OWNER/cloudflare-prefix-sync.git
cd cloudflare-prefix-sync
pip install boto3

python scripts/sync_cloudflare_ips.py --mode discover --region us-east-1 --format text
```

The CLI is a preview unless you pass `--execute`. Read-only modes (`discover`, `audit`) need only describe permissions. Backups from `--execute` runs go to `./backups` unless you set `--backup-dir` or `--backup-s3-bucket`.

All flags: `python scripts/sync_cloudflare_ips.py --help` and [CONFIGURATION.md](CONFIGURATION.md).

## Terraform

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`. A first deployment usually looks like this:

```hcl
aws_region         = "us-east-1"
mode               = "audit"
security_group_ids = ["sg-0123456789abcdef0"]
notification_email = "security@example.com"
notify_on          = "drift"
tags               = { Owner = "security@example.com" }
```

Then:

```bash
terraform init
terraform plan
terraform apply
```

Confirm the SNS subscription email. Run once without waiting for the schedule:

```bash
aws lambda invoke --function-name "$(terraform output -raw sync_lambda_function_name)" \
  --cli-binary-format raw-in-base64-out --payload '{}' result.json && cat result.json
```

What Terraform creates: two managed prefix lists (unless `create_prefix_lists = false`), an S3 backup bucket, a KMS key and SNS topic, the Lambda with a log group and error alarm, an EventBridge schedule, and an IAM role whose permissions follow `mode`.

The prefix lists use `lifecycle { ignore_changes = [entry, max_entries] }`, so later applies do not undo the Lambda's updates.

To use as a module from another configuration, reference the `terraform/` directory with `source` and remove or override the `provider "aws"` block in `versions.tf`.

## CloudFormation

The template loads the Lambda code from S3, because the code is larger than CloudFormation's 4 KB inline limit. You need an existing S3 bucket in the target region for the zip.

### With the deploy script (CloudShell, Linux, macOS)

```bash
./scripts/deploy_cli_cloudshell.sh \
  --artifact-bucket my-artifacts-us-east-1 \
  --region us-east-1 \
  --mode audit \
  --security-group-ids sg-0123456789abcdef0 \
  --email security@example.com \
  --tags "Owner=security@example.com Environment=prod"
```

That previews. Add `--execute` to upload the code, deploy the stack and run the function once. Other parameters: `--param Key=Value` (repeatable), for example `--param NotifyOn=always`.

### With PowerShell

```powershell
.\scripts\deploy_cli.ps1 -ArtifactBucket my-artifacts-us-east-1 -Region us-east-1 `
  -Mode audit -SecurityGroupIds "sg-0123456789abcdef0" -NotificationEmail security@example.com `
  -Tags @{ Owner = "security@example.com" } -Parameters @{ NotifyOn = "drift" } -Execute
```

### By hand

```bash
python scripts/package_lambda.py --bucket my-artifacts-us-east-1 --region us-east-1
# prints {"key": "cloudflare-prefix-sync/cloudflare-prefix-sync-<hash>.zip", ...}

aws cloudformation deploy --region us-east-1 \
  --template-file templates/cloudflare-prefix-sync-template.yaml \
  --stack-name cloudflare-prefix-sync \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides Mode=audit CodeS3Bucket=my-artifacts-us-east-1 \
      CodeS3Key=cloudflare-prefix-sync/cloudflare-prefix-sync-<hash>.zip \
      SecurityGroupIds=sg-0123456789abcdef0 NotificationEmail=security@example.com \
  --tags Owner=security@example.com
```

Stack tags propagate to every resource. The template no longer has tag parameters.

In the console, upload the zip to S3 first, then create the stack from `templates/cloudflare-prefix-sync-template.yaml` and fill in `CodeS3Bucket` and `CodeS3Key`.

## StackSets (AWS Organizations)

Lambda must load its code from a bucket in its own region. Create one bucket per target region named `<base>-<region>` (for example `org-cfps-artifacts-us-east-1`) with a bucket policy that lets member accounts read the code:

```json
{
  "Sid": "OrgRead",
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::org-cfps-artifacts-us-east-1/cloudflare-prefix-sync/*",
  "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xxxxxxxxxx"}}
}
```

Then, from the management or delegated administrator account:

```bash
python scripts/deploy_stackset.py --target stackset \
  --artifact-bucket org-cfps-artifacts \
  --regions us-east-1 eu-west-1 \
  --ou-ids ou-abcd-11111111 \
  --mode audit \
  --param NotifyOn=drift \
  --tag Owner=security@example.com \
  --execute
```

This uploads the zip to each regional bucket, sets `CodeBucketHasRegionSuffix=true`, and creates the StackSet with automatic deployment to new accounts in the OUs. Re-running it updates an existing StackSet; adding regions or OUs to an existing StackSet is done with `aws cloudformation create-stack-instances`.

Account-specific values such as security group IDs usually differ per account. Use the tag opt-in (`cloudflare-prefix-sync=managed`) for the change scope and `AuditAllLoadBalancers=true` for the audit scope, instead of listing IDs.

## GitHub Actions

`.github/workflows/scheduled-sync.yml` runs the CLI every 6 hours with OIDC. Set repository variables:

| Variable | Example |
| :--- | :--- |
| `AWS_ROLE_ARN` (required) | `arn:aws:iam::111122223333:role/cfps-github` |
| `AWS_REGION` | `us-east-1` |
| `CFPS_MODE` | `audit` |
| `CFPS_EXECUTE` | `true` to apply changes on schedule |
| `IPV4_PREFIX_LIST_ID`, `IPV6_PREFIX_LIST_ID`, `COMPARE_PREFIX_LIST_IDS` | |
| `SECURITY_GROUP_IDS`, `MANAGED_SECURITY_GROUP_IDS` | comma-separated |
| `BACKUP_S3_BUCKET`, `SNS_TOPIC_ARN`, `NOTIFY_ON` | |

The role needs the same permissions as the Lambda for the chosen mode (see [MODES.md](MODES.md#iam-per-mode)) and a trust policy for `token.actions.githubusercontent.com` limited to your repository.

## Upgrading from v1

v2 keeps the v1 resources and their logical IDs / addresses, so an upgrade updates in place.

- **Mode.** v1 behaved like `sync`. The CloudFormation and Terraform default is still `sync`; the deploy scripts default to `audit`, so pass `--mode sync` / `-Mode sync` to keep v1 behavior.
- **CloudFormation code.** The template now needs `CodeS3Bucket` and `CodeS3Key`. Package and upload the code first (the deploy scripts do this).
- **Tags.** The 12 tag parameters and variables are gone. Use stack tags (CloudFormation) or the `tags` map (Terraform). On update, CloudFormation and Terraform remove tags that are no longer specified.
- **Terraform state.** `moved` blocks move the prefix lists to `[0]` addresses (they now have `count`). The v1 variables `target_alb_security_group_id`, `auto_attach_to_alb_security_group` and `alb_ingress_port` still work and keep their rule addresses. `additional_security_group_ids` was never released and is replaced by `terraform_attach_security_group_ids`.
- **Terraform provider.** AWS provider 6.x is required (`data.aws_region.region`).
- **Environment.** `ALB_SECURITY_GROUP_IDS` still works as an alias for `SECURITY_GROUP_IDS`.
- **SNS.** The topic moves from the `aws/sns` key to a customer managed key so the error alarm can publish. Existing subscriptions are kept.
- **Notifications.** v1 sent an email after every change. v2's default `NOTIFY_ON=alerts` also sends when something needs action; use `NOTIFY_ON=drift` or `always` for more, or `never`.

Run `terraform plan` or create a CloudFormation change set and review it before applying.

## Uninstall

- Terraform: `terraform destroy`. The backup bucket must be empty first (it is versioned).
- CloudFormation: delete the stack. The backup bucket is retained (`DeletionPolicy: Retain`); delete it yourself when you no longer need the backups.

Deleting a managed prefix list fails while security group rules still reference it. Remove those rules first, or keep the lists by removing them from state (`terraform state rm`) or by setting `DeletionPolicy: Retain` in a fork.
