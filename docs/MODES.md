# Modes

The mode decides how much the tool may change. Modes form a ladder: each one does everything the previous one does, plus one more kind of write.

```text
discover ─► audit ─► sync ─► attach ─► enforce
read-only   read-only  prefix   + add       + remove
                       lists    Cloudflare  non-Cloudflare
                                rules       rules
```

| | discover | audit | sync | attach | enforce |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Inventory of ALBs, NLBs, CloudFront, public EC2 | ✓ | | | | |
| Compare prefix lists with Cloudflare | if configured | ✓ | ✓ | ✓ | ✓ |
| Exposure audit of security groups and ALBs | ✓ | ✓ | ✓ | ✓ | ✓ |
| Have-vs-needs report to SNS | ✓ | ✓ | ✓ | ✓ | ✓ |
| Update managed prefix lists | | | ✓ | ✓ | ✓ |
| Add Cloudflare rules to in-scope security groups | | | | ✓ | ✓ |
| Revoke non-Cloudflare rules on in-scope security groups | | | | | ✓ |

`sync` runs the audit only when `AUDIT_ENABLED` is true (the Lambda default). The CLI enables the audit automatically in every mode except `sync`, where you add `--audit`.

## Dry run

`DRY_RUN=true` (Lambda), `dry_run = true` (Terraform), `DryRun=true` (CloudFormation), or omitting `--execute` (CLI) turns any mode into a preview. The plan and report show exactly what would be written, marked as not applied, and nothing changes in AWS. Run status is `DRY_RUN_CHANGES_DETECTED`.

## discover

Use it to answer "what in this region can be reached from the internet, and how?" before you configure anything.

It lists:

- internet-facing **ALBs and NLBs**, their security groups, and whether each ALB has origin authentication (mTLS in verify mode, or an `http-header` listener rule);
- **CloudFront distributions**, with aliases, origins and whether a WAF web ACL is attached;
- running **EC2 instances with a public IPv4 or IPv6 address**;
- every **security group** attached to those, classified as `cloudflare_only`, `open_to_internet`, `other_sources` or `no_ingress`, and whether it is opted in by tag.

It does not need prefix lists and does not contact Cloudflare. If you set `COMPARE_PREFIX_LIST_IDS` (or the managed prefix list IDs), it also compares those lists with Cloudflare.

Findings it can raise: `OPEN_TO_INTERNET`, `NON_CLOUDFLARE_CIDR`, `OTHER_PREFIX_LIST`, `PRIVATE_CIDR`, `NON_CLOUDFLARE_SECURITY_GROUP`, `MISSING_CLOUDFLARE_PREFIX_LIST`, `NLB_WITHOUT_SECURITY_GROUP`, `ORIGIN_AUTH_MISSING`, `CLOUDFRONT_PUBLIC_ENTRY`, `PUBLIC_EC2_INSTANCE`. See [NOTIFICATIONS.md](NOTIFICATIONS.md#findings).

Status: `DISCOVERY`.

## audit

Use it to watch an environment you do not want this tool to change, or to compare a prefix list you maintain yourself.

- Fetches and validates Cloudflare's ranges.
- Diffs the managed prefix lists and any `COMPARE_PREFIX_LIST_IDS` lists against them.
- Audits `SECURITY_GROUP_IDS`, `MANAGED_SECURITY_GROUP_IDS` and tag-opted-in groups. With `AUDIT_ALL_LOAD_BALANCERS=true` it also audits every internet-facing ALB/NLB and its groups.
- Builds the plan of rule changes that would make each group Cloudflare-only, and reports it as "needs".

Status: `DRIFT_DETECTED` when anything differs, otherwise `NO_CHANGES`.

At least one prefix list (managed or compare-only) is required.

## sync

Keeps the managed IPv4 and IPv6 prefix lists equal to Cloudflare's ranges. Security groups that reference the lists pick up changes automatically, so this is all most deployments need once the rules are in place.

- Additions and removals are applied in one `ModifyManagedPrefixList` call per list (one version bump).
- If Cloudflare publishes more ranges than the list's `MaxEntries`, the list is resized first.
- Compare-only lists are never written.

Requires `IPV4_PREFIX_LIST_ID` and/or `IPV6_PREFIX_LIST_ID`.

## attach

Adds an ingress rule `tcp/<port> from <managed prefix list>` to every in-scope security group that lacks one, for each port in `INGRESS_PORTS` and each managed list. It never removes anything, so it is safe to run on groups that still have other rules.

In scope means listed in `MANAGED_SECURITY_GROUP_IDS`, or tagged `cloudflare-prefix-sync=managed` (tag key and value are configurable; set the key to empty to disable). Groups listed only in `SECURITY_GROUP_IDS` are audited but never changed.

Each referenced prefix list counts as its `MaxEntries` toward the security group rule quota. See [ARCHITECTURE.md](ARCHITECTURE.md#security-group-quota).

## enforce

Everything `attach` does, then revokes ingress on in-scope security groups that does not come from Cloudflare:

| Source | Revoked by default |
| :--- | :--- |
| `0.0.0.0/0`, `::/0` | Yes |
| Other public CIDRs | Yes |
| Prefix lists other than the managed ones | Yes |
| Private CIDRs (RFC1918, CGNAT, ULA, link-local, loopback) | Only with `REVOKE_PRIVATE_CIDRS=true` |
| Other security groups | Only with `REVOKE_SECURITY_GROUP_SOURCES=true` |
| Anything in the allow-lists | Never |

Safeguards:

1. Revocation needs managed prefix lists; it never relies on a compare-only list. Rules that reference a compare-only list are treated as Cloudflare and kept, and that list's drift is reported under PREFIX LISTS so you can fix or replace it.
2. A group is only revoked from after it has a Cloudflare rule for every managed list on every configured port. If adding those rules failed, its revocations are skipped (lockout guard).
3. A run that would revoke more than `MAX_REVOCATIONS_PER_RUN` (default 25) rules revokes nothing and reports a circuit-breaker error, unless forced (`force_update` in the event, `--force` in the CLI).
4. All in-scope groups are backed up to S3 before any change. If the backup fails, nothing changes.
5. Revoked rules can be put back with `scripts/restore_prefix_list.py --from-s3-uri <backup> --restore-security-groups --skip-prefix-lists --execute`.

Note: `enforce` works on rules, not ports. A rule allowing `tcp/22` from a public CIDR is revoked like any other non-Cloudflare rule. Put administrative access in the allow-lists, or better, use Systems Manager Session Manager.

## IAM per mode

Terraform and CloudFormation grant only what the deployed mode needs.

| Permission | discover / audit | sync | attach | enforce |
| :--- | :---: | :---: | :---: | :---: |
| Describe prefix lists, security groups, instances, load balancers; list CloudFront | ✓ | ✓ | ✓ | ✓ |
| Write backups to the stack's bucket, publish to the stack's topic | ✓ | ✓ | ✓ | ✓ |
| `ec2:ModifyManagedPrefixList`, `RestoreManagedPrefixListVersion` on the managed lists only | | ✓ | ✓ | ✓ |
| `ec2:AuthorizeSecurityGroupIngress` on listed or tagged groups | | | ✓ | ✓ |
| `ec2:RevokeSecurityGroupIngress` on listed or tagged groups | | | | ✓ |

The tag-scoped statements use `aws:ResourceTag/<key>`, so anyone who can tag security groups can put them in scope. Restrict `ec2:CreateTags` on that key (for example with an SCP) if that matters in your organization.

## Rollout plan

1. **discover** once from the CLI. Read the report and decide which groups should be Cloudflare-only.
2. Deploy **audit** with those groups in `SECURITY_GROUP_IDS` and `NOTIFY_ON=drift`. Add expected sources to the allow-lists until the only remaining findings are real.
3. Switch to **sync** to create and maintain the managed prefix lists.
4. Move the groups to `MANAGED_SECURITY_GROUP_IDS` (or tag them) and switch to **attach**. Check that traffic through Cloudflare still works.
5. Deploy **enforce** with `DRY_RUN=true`. Review the "needs" list in one or two reports.
6. Set `DRY_RUN=false`. Keep `NOTIFY_ON=alerts`, so you hear about changes and new drift.

You can go back down the ladder at any time by changing the mode; lowering the mode also removes the corresponding IAM permissions.
