# cloudflare-prefix-sync

[![CI](https://github.com/OWNER/cloudflare-prefix-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/cloudflare-prefix-sync/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Make Cloudflare the only way into your AWS origins.

`cloudflare-prefix-sync` keeps AWS managed prefix lists in step with [Cloudflare's published IP ranges](https://www.cloudflare.com/ips/), checks which security groups and entry points can still be reached without going through Cloudflare, and, if you allow it, fixes them. It runs as a scheduled Lambda (CloudFormation or Terraform), from the CLI, or from GitHub Actions.

You choose how much it may do, from a read-only inventory up to full enforcement, and you get an SNS report that shows what you have next to what needs to change.

---

## Modes

Each mode includes everything in the modes above it.

| Mode | What it does | Writes to AWS |
| :--- | :--- | :--- |
| `discover` | Inventories internet-facing ALBs, NLBs, CloudFront distributions and public EC2 instances, and classifies every security group they use. Needs no prefix list. | Nothing |
| `audit` | Compares your prefix lists with Cloudflare and audits your security groups for non-Cloudflare ingress and missing origin authentication. | Nothing |
| `sync` | Keeps the managed Cloudflare prefix lists current. | Managed prefix lists |
| `attach` | Adds missing Cloudflare ingress rules to in-scope security groups. Never removes anything. | + `AuthorizeSecurityGroupIngress` |
| `enforce` | Removes ingress that does not come from Cloudflare (or your allow-list) on in-scope security groups. | + `RevokeSecurityGroupIngress` |

Every mode can run as a dry run, which reports the planned writes and makes none. IAM permissions are granted for the deployed mode only, so a `sync` deployment cannot change security groups even if someone invokes it with `{"mode": "enforce"}`.

The recommended path is `discover` → `audit` → `sync` → `attach` → `enforce` with `dry_run` → `enforce`. See [docs/MODES.md](docs/MODES.md).

## Bring your own prefix lists and security groups

You do not need to adopt anything to get value from the tool.

| You have | Setting | Effect |
| :--- | :--- | :--- |
| A prefix list you maintain by hand | `compare_prefix_list_ids` | Compared with Cloudflare and reported on. Never modified. |
| A prefix list you want kept current | `existing_ipv4_prefix_list_id` / `existing_ipv6_prefix_list_id` with `create_prefix_lists = false` | Updated in `sync` and above. |
| Security groups you want checked | `security_group_ids` | Audited, reported on and backed up. Never modified. |
| Security groups you want fixed | `managed_security_group_ids`, or tag them `cloudflare-prefix-sync=managed` | Changed in `attach` / `enforce`. |
| Sources that are meant to be there | `allowed_cidrs`, `allowed_prefix_list_ids`, `allowed_source_security_group_ids` | Never reported or revoked. |

## The report

Each run builds a have-vs-needs report and sends it to SNS according to `notify_on` (`never`, `alerts` (default), `drift`, `always`). Text format, as it arrives by email:

```text
[CF-Prefix-Sync] ACTION NEEDED (us-east-1)

Cloudflare Prefix Sync report
  mode=audit  dry_run=False  account=111122223333  region=us-east-1  time=2026-11-16T17:53:49Z

ACTION NEEDED: 1 prefix list(s) out of date, 1 security group(s) to change, 1 high / 1 medium finding(s)

PREFIX LISTS  (have vs what Cloudflare publishes)
  pl-0aaa1111bbbb2222c [reference, IPv4]  have 15, Cloudflare 15  ->  ADD 1, REMOVE 1
      + 104.16.0.0/13
      - 9.9.9.0/24

SECURITY GROUPS  (what can reach them vs what must change)
  sg-0123456789abcdef0 web-alb  [open_to_internet]  status: needs_change
    have:
      tcp/443-443 from 0.0.0.0/0 [open_to_internet]
      tcp/443-443 from pl-0aaa1111bbbb2222c [cloudflare_prefix_list]
    needs:
      Remove tcp/443-443 from 0.0.0.0/0 (open_to_internet)

HIGH FINDINGS (1)
  OPEN_TO_INTERNET  sg-0123456789abcdef0: Allows tcp/443-443 from 0.0.0.0/0, bypassing Cloudflare.

MEDIUM FINDINGS (1)
  ORIGIN_AUTH_MISSING  web-alb: No mTLS (verify mode) and no http-header listener rule. ...
```

`notify_format = "json"` sends the same data as JSON for automation. See [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md).

## Quick start

### 1. Look before you deploy (CLI, read-only)

Needs Python 3.10+, `boto3` and credentials with read access.

```bash
git clone https://github.com/OWNER/cloudflare-prefix-sync.git
cd cloudflare-prefix-sync
pip install boto3

# What can reach this account from the internet?
python scripts/sync_cloudflare_ips.py --mode discover --region us-east-1 --format text

# How does my existing prefix list and security group compare with Cloudflare?
python scripts/sync_cloudflare_ips.py --mode audit --region us-east-1 --format text \
  --compare-prefix-list-ids pl-0aaa1111bbbb2222c \
  --security-group-ids sg-0123456789abcdef0
```

Nothing is written without `--execute`.

### 2. Deploy with Terraform

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # set mode, security groups, email
terraform init
terraform apply
```

### 3. Deploy with CloudFormation

The template loads the Lambda code from S3, so you need an existing bucket in the target region.

```bash
./scripts/deploy_cli_cloudshell.sh --artifact-bucket my-artifacts-us-east-1 \
  --mode audit --security-group-ids sg-0123456789abcdef0 \
  --email security@example.com --execute
```

PowerShell: `scripts/deploy_cli.ps1`. Organizations StackSets: `scripts/deploy_stackset.py --target stackset`. See [docs/INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md).

## What this does not cover

Read this before relying on the tool for your security boundary.

- **Cloudflare IPs are shared.** Every Cloudflare customer's traffic comes from the same ranges, so an IP allow-list proves the request came through Cloudflare, not through *your* Cloudflare zone. Pair it with [Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/) (mTLS on the ALB) or a secret header checked by a listener rule. The audit reports ALBs that have neither (`ORIGIN_AUTH_MISSING`); it does not configure them.
- **CloudFront and WAF are reported, not changed.** Security groups cannot be attached to CloudFront. Discovery lists distributions as separate public entry points.
- **Regional.** Prefix lists and security groups are regional. Deploy once per region, or use the StackSet deployer.
- **Not covered at all:** API Gateway, Lambda function URLs, App Runner, S3 website endpoints, Elastic IPs on resources other than EC2, and network ACLs.

## Safety

- Cloudflare data is validated before use: `/0`, private and reserved ranges are rejected, and too few ranges stops the run (`MIN_IPV4_CIDRS`, `MIN_IPV6_CIDRS`).
- A prefix list update that would remove more than `MAX_REMOVAL_RATIO` (50%) of entries is refused.
- `enforce` refuses to revoke more than `max_revocations_per_run` (25) rules per run, and never revokes from a security group until its Cloudflare rules are in place.
- Private CIDRs and security-group sources are kept unless you opt in to revoking them.
- Every write is preceded by a backup of the prefix lists and in-scope security groups to S3 (or a local folder for the CLI). If the backup fails, nothing is changed.
- `scripts/restore_prefix_list.py` restores prefix lists from AWS version history or a backup, and re-adds revoked security group rules (`--restore-security-groups`).

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Cost

About $1 per month per region, almost all of it the KMS key that encrypts the SNS topic (CloudWatch alarms cannot publish to topics encrypted with the AWS managed `aws/sns` key). Lambda, EventBridge, SNS and S3 usage normally stay within the free tier at the default 6-hour schedule.

## Documentation

| Document | Contents |
| :--- | :--- |
| [docs/MODES.md](docs/MODES.md) | Each mode in detail, IAM per mode, rollout plan |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every setting, with its Lambda variable, CLI flag, Terraform variable and CloudFormation parameter |
| [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md) | Report contents, notification policies, formats, subscribing |
| [docs/INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md) | Terraform, CloudFormation, StackSets, CLI, GitHub Actions; upgrading from v1 |
| [docs/USAGE_GUIDE.md](docs/USAGE_GUIDE.md) | Day-to-day operation, rollback, troubleshooting |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Flow, guardrails, IAM, quotas, threat model |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and pull requests |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Repository layout

```text
src/                     Engine (packaged as the Lambda)
  sync_engine.py         Orchestration, Cloudflare fetch/validation, prefix list sync, backups
  modes.py               Mode ladder and capabilities
  discovery.py           Read-only inventory of entry points
  audit.py               Exposure audit and ingress classification
  remediate.py           Attach / enforce planning, execution and security group restore
  report.py              Have-vs-needs report and SNS delivery
  lambda_handler.py      Lambda entry point (environment and event configuration)
scripts/                 CLI, packaging, deployers, restore
templates/               CloudFormation template
terraform/               Terraform root module
tests/                   Offline unit tests (no AWS or network access)
docs/                    Documentation
```

## License

[MIT](LICENSE)
