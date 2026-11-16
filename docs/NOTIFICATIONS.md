# Notifications and the have-vs-needs report

Every run builds a report that puts what you have next to what needs to change. The Lambda returns it under `report`, the CLI prints it (`--format text`), and it is published to SNS according to the notification policy.

## When a report is sent

| `NOTIFY_ON` | Sends when |
| :--- | :--- |
| `never` | Never. Run errors are not sent either. |
| `alerts` (default) | Changes were applied, something needs action (out-of-date prefix list, security group to change, HIGH or MEDIUM finding), or there was an error. |
| `drift` | As `alerts`, plus low-severity items (private CIDR sources, security-group sources, CloudFront with a WAF). |
| `always` | After every run, including "COMPLIANT". Useful as a heartbeat. |

With `alerts`, an unchanged problem is reported on every scheduled run until it is fixed or allow-listed. That is intentional; if it is too noisy, lengthen the schedule or allow-list the expected source.

Independently of the policy, the CloudWatch alarm created by Terraform and CloudFormation sends a message to the same topic when the Lambda fails (for example a timeout).

## Subject line

```text
[CF-Prefix-Sync] ACTION NEEDED (us-east-1)
[CF-Prefix-Sync] UPDATED (us-east-1)
[CF-Prefix-Sync] REVIEW (us-east-1)
[CF-Prefix-Sync] OK (us-east-1)
[CF-Prefix-Sync] ALERT: Sync Error in us-east-1
```

Subscriptions can use SNS [message filtering](https://docs.aws.amazon.com/sns/latest/dg/sns-message-filtering.html) on the message body only for JSON format; use separate topics if you need to route by severity with text.

## Report sections (text format)

1. **Header**: mode, dry run, account, region, time.
2. **Headline**: `ACTION NEEDED`, `UPDATED`, `REVIEW` or `COMPLIANT`, with counts.
3. **PREFIX LISTS**: for each managed (`managed`) or compare-only (`reference`) list, the number of entries it has, the number Cloudflare publishes, and the `+` additions and `-` removals needed. Managed lists show `UPDATED` when the run applied the change.
4. **SECURITY GROUPS**: for each audited group,
   - `exposure`: `cloudflare_only`, `open_to_internet`, `other_sources` or `no_ingress`;
   - `have`: every inbound source with port and category;
   - `needs`: the rule changes that would make it Cloudflare-only, prefixed `DONE` when this run applied them;
   - `status`: `compliant`, `needs_change` or `remediated`.
5. **HIGH / MEDIUM / LOW FINDINGS**.
6. **ENTRY POINTS DISCOVERED** (discover mode).
7. **ERRORS**, **NOT APPLIED** (planned changes the mode or a guardrail did not allow, with the reason), and the **Backup** location.

Long lists are cut at 25 lines per section with "... and N more". The JSON format and the Lambda return value always contain everything.

"needs" is computed for every audited group, whether or not the tool may change it, so you get the same comparison for groups you manage yourself.

## Categories

| Category | Meaning |
| :--- | :--- |
| `cloudflare_prefix_list` | A managed or compare-only Cloudflare list. |
| `open_to_internet` | `0.0.0.0/0` or `::/0`. |
| `public_cidr` | Any other internet-routable CIDR. |
| `private_cidr` | RFC1918, 100.64.0.0/10, fc00::/7, link-local or loopback. |
| `other_prefix_list` | A prefix list this tool does not know as Cloudflare. |
| `security_group` | Another security group (self-references are ignored). |
| `allowed` | Matches an allow-list entry. |

## Findings

| Code | Severity | Raised when |
| :--- | :--- | :--- |
| `OPEN_TO_INTERNET` | HIGH | A rule allows `0.0.0.0/0` or `::/0`. |
| `NLB_WITHOUT_SECURITY_GROUP` | HIGH | An internet-facing NLB has no security group, so it cannot be limited to Cloudflare. (Security groups can only be added to an NLB when it is created.) |
| `NON_CLOUDFLARE_CIDR` | MEDIUM | A rule allows another public CIDR. |
| `OTHER_PREFIX_LIST` | MEDIUM | A rule allows a prefix list that is not a Cloudflare list. |
| `MISSING_CLOUDFLARE_PREFIX_LIST` | MEDIUM | The group has no rule using one of the Cloudflare lists. |
| `ORIGIN_AUTH_MISSING` | MEDIUM | An internet-facing ALB has no HTTPS listener in mTLS verify mode and no `http-header` listener rule. |
| `PUBLIC_EC2_INSTANCE` | MEDIUM | A running instance has a public address (discover). |
| `CLOUDFRONT_PUBLIC_ENTRY` | MEDIUM, LOW if a WAF web ACL is attached | A CloudFront distribution is a separate public entry point (discover). |
| `PRIVATE_CIDR` | LOW | A rule allows a private range. |
| `NON_CLOUDFLARE_SECURITY_GROUP` | LOW | A rule allows another security group. |

`ORIGIN_AUTH_MISSING` only checks that a mechanism exists; it cannot tell whether the header rule checks a secret or whether the mTLS trust store contains Cloudflare's origin-pull CA.

## JSON format

`NOTIFY_FORMAT=json` publishes `{"report": {...}, "summary": {...}}`, where `summary` is the full run result (diffs, comparisons, audit, plan, remediation, backup). Top-level report fields:

```json
{
  "headline": "ACTION NEEDED: ...",
  "actionable": true,
  "has_gaps": true,
  "changes_applied": false,
  "prefix_lists": [{"prefix_list_id": "pl-...", "role": "reference", "address_family": "IPv4",
                    "have": 15, "cloudflare": 15, "to_add": ["104.16.0.0/13"],
                    "to_remove": ["9.9.9.0/24"], "in_sync": false, "applied": false}],
  "security_groups": [{"group_id": "sg-...", "name": "web-alb", "exposure": "open_to_internet",
                       "have": ["tcp/443-443 from 0.0.0.0/0 [open_to_internet]"],
                       "needs": [{"action": "revoke", "detail": "Remove tcp/443-443 from 0.0.0.0/0 (open_to_internet)",
                                  "applied": false}],
                       "status": "needs_change"}],
  "findings": {"HIGH": [], "MEDIUM": [], "LOW": []},
  "errors": []
}
```

Messages larger than 200 KB are truncated to stay under the SNS 256 KB limit.

## Subscribing

- **Email**: set `notification_email` / `NotificationEmail`, then confirm the subscription email AWS sends.
- **Slack or Microsoft Teams**: subscribe [AWS Chatbot (Amazon Q Developer in chat applications)](https://docs.aws.amazon.com/chatbot/latest/adminguide/what-is.html) to the topic. Chatbot formats only certain AWS event types; plain text reports may appear as raw messages.
- **Ticketing or automation**: subscribe an HTTPS endpoint, SQS queue or Lambda, and use `NOTIFY_FORMAT=json`.
- **Your own topic**: with the CLI or a custom deployment, pass `--sns-topic-arn` / `SNS_TOPIC_ARN`. The function's role needs `sns:Publish` on it, and `kms:GenerateDataKey*` / `kms:Decrypt` if it is encrypted with a customer managed key.
