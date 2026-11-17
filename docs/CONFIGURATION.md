# Configuration reference

Every setting can be given four ways. The Lambda reads environment variables, and any of them can be overridden for one invocation by putting the lower-case name in the event, for example `{"mode": "audit", "dry_run": true}`.

List values are comma-separated in environment variables and CloudFormation, space-separated after a CLI flag, and lists in Terraform.

## Mode

| Lambda env / event | CLI | Terraform | CloudFormation | Default | Meaning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `MODE` | `--mode` | `mode` | `Mode` | `sync` | `discover`, `audit`, `sync`, `attach`, `enforce`. See [MODES.md](MODES.md). |
| `DRY_RUN` | omit `--execute` | `dry_run` | `DryRun` | `false` (CLI: preview unless `--execute`) | Report planned writes, make none. |
| event `force_update` | `--force` | | | `false` | Bypass the prefix-list removal and revocation circuit breakers for one run. |
| | | `schedule_expression` | `ScheduleExpression` | `rate(6 hours)` | EventBridge schedule. |

## Prefix lists

| Lambda env / event | CLI | Terraform | CloudFormation | Default | Meaning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| | | `create_prefix_lists` | `CreatePrefixLists` | `true` | Create the managed IPv4/IPv6 lists. |
| `IPV4_PREFIX_LIST_ID` | `--ipv4-prefix-list-id` | `existing_ipv4_prefix_list_id` (with `create_prefix_lists = false`) | `ExistingIpv4PrefixListId` | created list | Managed IPv4 list, kept equal to Cloudflare in `sync`+. |
| `IPV6_PREFIX_LIST_ID` | `--ipv6-prefix-list-id` | `existing_ipv6_prefix_list_id` | `ExistingIpv6PrefixListId` | created list | Managed IPv6 list. |
| `COMPARE_PREFIX_LIST_IDS` | `--compare-prefix-list-ids` | `compare_prefix_list_ids` | `ComparePrefixListIds` | none | Existing lists to compare and report on. Never modified, never used for revocation. |
| | | `initial_ipv4_max_entries` | `InitialIpv4MaxEntries` | `30` | Capacity of a created IPv4 list. |
| | | `initial_ipv6_max_entries` | `InitialIpv6MaxEntries` | `20` | Capacity of a created IPv6 list. |

A compare-only list's address family is read from the list, so it is compared with the matching Cloudflare ranges.

## Security groups

| Lambda env / event | CLI | Terraform | CloudFormation | Default | Meaning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SECURITY_GROUP_IDS` (alias `ALB_SECURITY_GROUP_IDS`) | `--security-group-ids` | `security_group_ids` | `SecurityGroupIds` | none | Groups to audit, report on and back up. Never modified. |
| `MANAGED_SECURITY_GROUP_IDS` | `--managed-security-group-ids` | `managed_security_group_ids` | `ManagedSecurityGroupIds` | none | Groups `attach`/`enforce` may change. Also audited. |
| `MANAGED_TAG_KEY` | `--managed-tag-key` | `managed_tag_key` | fixed `cloudflare-prefix-sync`; `EnableTagScope` turns it on/off | `cloudflare-prefix-sync` | Groups with this tag are in the change scope. Empty disables. |
| `MANAGED_TAG_VALUE` | `--managed-tag-value` | `managed_tag_value` | `ManagedTagValue` | `managed` | Tag value that opts a group in. |
| `INGRESS_PORTS` | `--ingress-ports` | `ingress_ports` | `IngressPorts` | `443` | TCP ports that must allow Cloudflare. |
| `ALLOWED_CIDRS` | `--allowed-cidrs` | `allowed_cidrs` | `AllowedCidrs` | none | Expected sources: never reported, never revoked. Exact match. |
| `ALLOWED_PREFIX_LIST_IDS` | `--allowed-prefix-list-ids` | `allowed_prefix_list_ids` | `AllowedPrefixListIds` | none | Expected prefix list sources. |
| `ALLOWED_SOURCE_SECURITY_GROUP_IDS` | `--allowed-source-security-group-ids` | `allowed_source_security_group_ids` | `AllowedSourceSecurityGroupIds` | none | Expected security group sources. |
| `REVOKE_PRIVATE_CIDRS` | `--revoke-private-cidrs` | `revoke_private_cidrs` | `RevokePrivateCidrs` | `false` | `enforce`: also revoke private ranges. |
| `REVOKE_SECURITY_GROUP_SOURCES` | `--revoke-security-group-sources` | `revoke_security_group_sources` | `RevokeSecurityGroupSources` | `false` | `enforce`: also revoke security group sources. |
| `MAX_REVOCATIONS_PER_RUN` | `--max-revocations-per-run` | `max_revocations_per_run` | `MaxRevocationsPerRun` | `25` | `enforce` circuit breaker. |
| | | `terraform_attach_security_group_ids` | | none | Terraform creates static Cloudflare rules on these groups, independent of mode. Do not also list them as managed. |

## Audit and notifications

| Lambda env / event | CLI | Terraform | CloudFormation | Default | Meaning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `AUDIT_ENABLED` | `--audit` | `audit_enabled` | `AuditEnabled` | `true` (CLI: on except in `sync`) | Run the exposure audit. |
| `AUDIT_ALL_LOAD_BALANCERS` | `--audit-all-load-balancers` | `audit_all_load_balancers` | `AuditAllLoadBalancers` | `false` | Also audit every internet-facing ALB/NLB in the region. |
| `SNS_TOPIC_ARN` | `--sns-topic-arn` | created | created | none | Topic for the report. |
| | | `notification_email` | `NotificationEmail` | none | Email subscribed to the created topic. |
| `NOTIFY_ON` | `--notify-on` | `notify_on` | `NotifyOn` | `alerts` | `never`, `alerts`, `drift`, `always`. See [NOTIFICATIONS.md](NOTIFICATIONS.md). |
| `NOTIFY_FORMAT` | `--notify-format` | `notify_format` | `NotifyFormat` | `text` | `text` or `json`. |
| | `--format` | | | `json` | How the CLI prints the result (`json` or `text`). |

## Safety and retention

| Lambda env / event | CLI | Terraform | CloudFormation | Default | Meaning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `MIN_IPV4_CIDRS` | `--min-ipv4-cidrs` | `min_ipv4_cidrs` | `MinIpv4Cidrs` | `10` | Refuse to run if Cloudflare returns fewer IPv4 ranges. |
| `MIN_IPV6_CIDRS` | `--min-ipv6-cidrs` | `min_ipv6_cidrs` | `MinIpv6Cidrs` | `5` | Same for IPv6. |
| `MAX_REMOVAL_RATIO` | `--max-removal-ratio` | `max_removal_ratio` | `MaxRemovalRatio` | `0.50` | Refuse to remove more than this fraction of a prefix list in one run. |
| `BACKUP_S3_BUCKET` | `--backup-s3-bucket` | created | created | none | Backup bucket. |
| `BACKUP_S3_PREFIX` | `--backup-s3-prefix` | | | `backups` | Key prefix. |
| | `--backup-dir` | | | `./backups` | CLI local backup folder. |
| | | `backup_retention_days` | `BackupRetentionDays` | `365` | S3 lifecycle expiry. |
| | | `log_retention_days` | `LogRetentionDays` | `90` | CloudWatch Logs retention. |

## Deployment-only settings

| Terraform | CloudFormation | Meaning |
| :--- | :--- | :--- |
| `aws_region` | (stack region) | Region. |
| `name_prefix` | (stack name) | Resource name prefix. |
| `tags` | stack tags (`--tags`) | Tags on every resource. |
| | `CodeS3Bucket`, `CodeS3Key` | Lambda zip location, from `scripts/package_lambda.py`. |
| | `CodeBucketHasRegionSuffix` | Use `<CodeS3Bucket>-<region>` (StackSets). |
| `demo_vpc_id` | `DemoVpcId` | Demo only: create a demo security group in this VPC and tag the managed prefix lists so `scripts/demo.py` may break them. See [DEMO.md](DEMO.md). |
| `target_alb_security_group_id`, `auto_attach_to_alb_security_group`, `alb_ingress_port` | `TargetAlbSecurityGroupId`, `AutoAttachToAlbSecurityGroup`, `AlbIngressPort` | Deprecated v1 settings, kept so existing rules are not recreated. |

## Lambda event examples

```json
{"mode": "discover"}
{"mode": "audit", "notify_on": "always"}
{"dry_run": true}
{"compare_prefix_list_ids": ["pl-0aaa1111bbbb2222c"], "notify_on": "drift"}
{"force_update": true}
```

An event cannot exceed the IAM permissions of the deployed mode: invoking a `sync` deployment with `{"mode": "enforce"}` plans revocations but AWS denies them, and the errors appear in the report.
