# Operating guide

## Running on demand

Lambda (any setting can be overridden in the event, see [CONFIGURATION.md](CONFIGURATION.md#lambda-event-examples)):

```bash
aws lambda invoke --function-name cloudflare-prefix-sync-sync \
  --cli-binary-format raw-in-base64-out --payload '{"dry_run": true, "notify_on": "always"}' result.json
python -c "import json; print(json.load(open('result.json'))['report']['headline'])"
```

CLI:

```bash
python scripts/sync_cloudflare_ips.py --mode enforce \
  --ipv4-prefix-list-id pl-0123456789abcdef0 --ipv6-prefix-list-id pl-0fedcba9876543210 \
  --managed-security-group-ids sg-0123456789abcdef0 --format text          # preview
python scripts/sync_cloudflare_ips.py ... --execute                         # apply
```

## Reading the result

The Lambda returns, and the CLI prints with `--format json`, a summary with these keys:

| Key | Contents |
| :--- | :--- |
| `status` | `NO_CHANGES`, `DRIFT_DETECTED`, `DRY_RUN_CHANGES_DETECTED`, `UPDATED`, `DISCOVERY` |
| `mode`, `dry_run`, `account_id`, `region`, `timestamp_utc` | Run context |
| `cloudflare` | Source, etag and counts of the ranges used |
| `diffs` | Managed prefix lists: current version, entries to add and remove |
| `comparisons` | Compare-only prefix lists: entries to add and remove |
| `audit` / `discovery` | Findings, audited groups and load balancers, errors |
| `security_group_plan` | Per security group, the authorize/revoke actions that would make it Cloudflare-only |
| `remediation` | What `attach`/`enforce` authorized, revoked, skipped (with reason) and any errors |
| `audit_after` | Audit repeated after live security group changes |
| `backup` | Backup ID, checksum and locations |
| `updates` | Prefix list version changes |
| `report` | The have-vs-needs report (see [NOTIFICATIONS.md](NOTIFICATIONS.md)) |

## Putting security groups in scope

Listed: add the IDs to `managed_security_group_ids` / `ManagedSecurityGroupIds` and redeploy.

Tagged (no redeploy):

```bash
aws ec2 create-tags --resources sg-0123456789abcdef0 --tags Key=cloudflare-prefix-sync,Value=managed
```

Remove the tag to take a group out of scope. Changes already made stay.

## Handling findings you expect

Add expected sources to the allow-lists instead of ignoring the report. For example, a monitoring service that checks the origin directly:

```hcl
allowed_cidrs = ["198.51.100.10/32"]
```

Allow-list matching is exact: `198.51.100.0/24` does not cover a rule for `198.51.100.10/32`.

## Backups

A backup is written before every live change, to `s3://<bucket>/backups/YYYY/MM/DD/cf-prefix-backup-<timestamp>.json` (and/or `--backup-dir` for the CLI). It contains:

- each managed prefix list's ID, version, `MaxEntries` and entries;
- the planned prefix list changes;
- the full `describe_security_groups` output for every audited, managed and referencing security group;
- the Cloudflare source and etag;
- a SHA-256 checksum.

```bash
aws s3 ls s3://cf-prefix-sync-backups-111122223333-us-east-1/backups/ --recursive | tail
```

## Rolling back

### Prefix lists, from AWS version history (fastest)

```bash
python scripts/restore_prefix_list.py --prefix-list-id pl-0123456789abcdef0 --previous-version            # preview
python scripts/restore_prefix_list.py --prefix-list-id pl-0123456789abcdef0 --previous-version --execute
python scripts/restore_prefix_list.py --prefix-list-id pl-0123456789abcdef0 --target-version 4 --execute
```

### Prefix lists, from a backup

```bash
python scripts/restore_prefix_list.py --from-s3-uri s3://<bucket>/backups/2026/11/16/cf-prefix-backup-20261116T120000Z.json --execute
```

### Security group rules revoked by enforce

```bash
python scripts/restore_prefix_list.py \
  --from-s3-uri s3://<bucket>/backups/2026/11/16/cf-prefix-backup-20261116T120000Z.json \
  --restore-security-groups --skip-prefix-lists            # preview: lists the missing rules
... --execute
```

This re-adds rules that are in the backup but missing now. It does not remove rules added later, such as the Cloudflare rules from `attach`.

Before rolling back a revocation, lower the mode (to `attach` or below) or the next scheduled run will revoke the rules again.

## Pausing

- Change to a read-only mode (`audit`), or
- disable the schedule: `aws events disable-rule --name cloudflare-prefix-sync-schedule` (Terraform) / `<stack>-schedule` (CloudFormation).

## Troubleshooting

### `RulesPerSecurityGroupLimitExceeded` when adding Cloudflare rules

A rule that references a prefix list counts as the list's `MaxEntries` rules. With the defaults (30 + 20) and one port, the Cloudflare rules use 50 of the default 60 inbound rules per group, and each extra port adds another 50. Options:

1. Use a dedicated security group for the Cloudflare rules and attach it alongside the existing one (an ALB accepts up to 5 security groups).
2. Lower `initial_ipv4_max_entries` / `initial_ipv6_max_entries` (Cloudflare publishes about 15 IPv4 and 7 IPv6 ranges).
3. Request a higher "Inbound or outbound rules per security group" quota (`L-0EA8095F`).

The failure is reported under `remediation.errors`, and that group's revocations are skipped.

### `Circuit breaker: plan would revoke N rules`

`enforce` found more rules to revoke than `MAX_REVOCATIONS_PER_RUN`. Review `security_group_plan`, then run once with `{"force_update": true}` or raise the limit.

### `Circuit breaker tripped for pl-...`

Cloudflare's list would remove more than half of a prefix list's entries in one run. Check https://www.cloudflare.com/ips/ by hand. If the change is real, run once with `{"force_update": true}`.

### `Safety threshold failed for IPv4: received N CIDRs`

Cloudflare returned fewer ranges than `MIN_IPV4_CIDRS` / `MIN_IPV6_CIDRS`. The run stops before any change. It is usually a transient upstream problem; the next run normally succeeds.

### A hand-maintained prefix list is still allowed after enforce

Rules that reference a list in `COMPARE_PREFIX_LIST_IDS` are treated as Cloudflare and kept. The report shows how that list differs from Cloudflare. Once the managed lists are attached, remove the list from `COMPARE_PREFIX_LIST_IDS` and the next `enforce` run revokes its rules as `other_prefix_list`.

### `UnauthorizedOperation` on authorize or revoke

The security group is not in the IAM scope of the deployed mode: not listed in `managed_security_group_ids`, not tagged, or the event asked for a higher mode than was deployed.

### No email arrives

- Confirm the subscription (check spam for "AWS Notification - Subscription Confirmation").
- `NOTIFY_ON=alerts` sends nothing when everything is compliant. Invoke with `{"notify_on": "always"}` to test.
- The function logs `Failed to publish report` when SNS rejects the message.

### `ORIGIN_AUTH_MISSING` on an ALB that does use a secret header

The check needs a non-default listener rule with an `http-header` condition on an HTTPS listener. If the header is checked by the application or a WAF rule instead, add the ALB's security group to the allow-list or accept the finding.
