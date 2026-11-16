# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.0] - 2026-11-16

### Added

- Operating modes `discover`, `audit`, `sync`, `attach` and `enforce`, each with dry-run support. Terraform and CloudFormation grant IAM permissions for the deployed mode only.
- Discovery of internet-facing ALBs and NLBs, CloudFront distributions and public EC2 instances, with a classification of every security group they use.
- Exposure audit: non-Cloudflare ingress, missing Cloudflare rules, NLBs without security groups, and ALBs without origin authentication (mTLS or a header rule).
- Have-vs-needs report for prefix lists and security groups, sent to SNS according to `NOTIFY_ON` (`never`, `alerts`, `drift`, `always`) in `text` or `json`.
- Bring-your-own resources: compare-only prefix lists (`COMPARE_PREFIX_LIST_IDS`), managing existing prefix lists, audit-only security groups (`SECURITY_GROUP_IDS`), and a change scope by ID or by tag (`cloudflare-prefix-sync=managed`).
- Allow-lists for expected CIDRs, prefix lists and source security groups.
- `enforce` guardrails: lockout guard, revocation cap (`MAX_REVOCATIONS_PER_RUN`), private and security-group sources kept by default.
- Security group restore from backups (`restore_prefix_list.py --restore-security-groups`).
- `scripts/package_lambda.py` for reproducible Lambda packages.
- CloudWatch alarm on Lambda errors, CloudWatch Logs retention, KMS key for the SNS topic.
- StackSet deployment to Organizations OUs across regions.
- Documentation: modes, configuration reference, notifications, architecture and threat model.
- CI for Python 3.10, 3.12 and 3.13, cfn-lint, Terraform validate and ShellCheck.

### Changed

- The CloudFormation template loads the Lambda from S3 (`CodeS3Bucket`, `CodeS3Key`) and runs the same `src/` code as Terraform. The previous inline function exceeded CloudFormation's 4 KB inline code limit and differed from `src/`.
- Tagging uses stack tags (CloudFormation) and a `tags` map (Terraform) instead of 12 fixed tag parameters with organization-specific defaults.
- Terraform requires AWS provider 6.x.
- The SNS topic uses a customer managed KMS key, because CloudWatch alarms cannot publish to topics encrypted with `aws/sns`.
- Lambda memory 128 → 256 MB and timeout 60 → 180 s, for discovery and enforcement in larger accounts.
- `is_private_cidr` uses an explicit list of internal ranges; Python's `is_private` also matched documentation ranges.
- The deploy scripts default to `audit` mode.

### Deprecated

- `TargetAlbSecurityGroupId` / `AutoAttachToAlbSecurityGroup` / `AlbIngressPort` and their Terraform equivalents. Use `SecurityGroupIds`, `ManagedSecurityGroupIds` or `terraform_attach_security_group_ids`.
- `ALB_SECURITY_GROUP_IDS`, now an alias for `SECURITY_GROUP_IDS`.

### Removed

- The 12 enterprise tag parameters and variables.

See [docs/INSTALLATION_GUIDE.md](docs/INSTALLATION_GUIDE.md#upgrading-from-v1) for upgrade steps.

## [1.0.0] - 2026-11-13

### Added

- Scheduled sync of Cloudflare IPv4 and IPv6 ranges into customer managed prefix lists, with validation, minimum counts, removal-ratio circuit breaker, pre-update backups and rollback.
- CloudFormation, Terraform, CLI and GitHub Actions deployment options.

[Unreleased]: https://github.com/ksravikumar2005/cloudflare-prefix-sync/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/ksravikumar2005/cloudflare-prefix-sync/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/ksravikumar2005/cloudflare-prefix-sync/releases/tag/v1.0.0
