# Demo: break it on purpose, watch it repair

`scripts/demo.py` sets up a small, isolated environment, damages it in ways you choose, and runs the automation against it. You see:

- the drift, as AWS sees it;
- the have-vs-needs report;
- the backup taken **before** anything changes, and what it will change;
- the prefix list and security group after the repair.

Demo resources cost nothing: AWS does not charge for customer managed prefix lists or security groups.

## Two ways to run it

| | Standalone | With a deployment |
| :--- | :--- | :--- |
| Creates | 2 prefix lists and 1 security group, with your credentials | Nothing extra; Terraform or CloudFormation creates the demo security group |
| Runs the automation | Locally, same engine as the Lambda | Locally, or by invoking the deployed Lambda (`--via-lambda`) |
| Backups | `backups/demo/*.json` | Local: `backups/demo/`. Lambda: the deployment's S3 bucket |
| Clean up | `demo.py teardown` | Unset `demo_vpc_id` / `DemoVpcId` and redeploy |

## Standalone in one command

Needs Python 3.10+, `boto3`, credentials with the [permissions below](#permissions), and a VPC (the default VPC is used unless you pass `--vpc-id`).

```bash
pip install boto3
python scripts/demo.py --region us-east-1 walkthrough
```

It pauses before each step. Add `--yes` to run straight through and `--teardown` to delete everything at the end.

The steps:

| Step | What happens | Writes to AWS |
| :--- | :--- | :--- |
| 1. setup | Creates IPv4 and IPv6 prefix lists seeded with Cloudflare's current ranges, and a security group allowing tcp/443 from both. All tagged `cloudflare-prefix-sync-demo`. | Yes (demo resources) |
| 2. status | Shows both lists in sync with Cloudflare | No |
| 3. break | Removes 3 random Cloudflare ranges from the IPv4 list, adds `198.51.100.0/24`, opens the security group to `0.0.0.0/0` | Yes (demo resources) |
| 4. status | Shows the damage | No |
| 5. audit | The report in read-only mode | No |
| 6. sync preview | What sync would change | No |
| 7. sync | Writes a backup, then adds the 3 missing ranges and removes the bogus one in one prefix list update | Yes |
| 8. enforce | Writes a backup, then revokes `0.0.0.0/0`; the Cloudflare rules stay | Yes |
| 9. status | Everything repaired | No |

## Step by step

```bash
python scripts/demo.py --region us-east-1 setup
python scripts/demo.py status
python scripts/demo.py break --remove 3 --add-bogus --open-sg
python scripts/demo.py status
python scripts/demo.py run                         # preview (sync)
python scripts/demo.py run --execute               # backup, then repair the prefix list
python scripts/demo.py run --mode enforce --execute
python scripts/demo.py show-backup                 # latest backup
python scripts/demo.py teardown
```

The region is saved in `.cfps-demo.json` after `setup`, so later commands do not need `--region`.

### Ways to break it

| `break` option | Effect | Repaired by |
| :--- | :--- | :--- |
| `--remove N` (default 3) | Removes N random Cloudflare ranges from the IPv4 list | `sync` and above |
| `--remove-cidrs 104.16.0.0/13 2400:cb00::/32` | Removes exactly these | `sync` and above |
| `--family ipv6` / `both` | Applies `--remove` and `--add-bogus` to the IPv6 list, or both | `sync` and above |
| `--add-bogus` | Adds `198.51.100.0/24` (IPv6: `2001:db8::/32`), documentation ranges that are never routed | `sync` and above (removed) |
| `--open-sg` | Adds tcp/443 from `0.0.0.0/0` | `enforce` (revoked) |
| `--drop-sg-rule` | Removes the IPv6 Cloudflare rule from the security group | `attach` and above (re-added) |
| `--seed 42` | Makes the random choice repeatable | |

Combine them freely. Removing more than half of a list is fine: the circuit breaker limits removals *by* the automation, not additions.

## What you will see

After `break --remove 3 --add-bogus --open-sg`, `status` shows:

```text
PREFIX LISTS (have vs Cloudflare)
  pl-0a1b2c3d4e5f60718 IPv4  version 2  have 13, Cloudflare 15  ->  3 missing, 1 extra
      missing  103.31.4.0/22
      missing  173.245.48.0/20
      missing  188.114.96.0/20
      extra    198.51.100.0/24
  pl-0f1e2d3c4b5a69788 IPv6  version 1  have 7, Cloudflare 7  ->  in sync

SECURITY GROUP sg-0123456789abcdef0 inbound rules
  tcp/443-443    from pl-0a1b2c3d4e5f60718     [cloudflare_prefix_list]
  tcp/443-443    from pl-0f1e2d3c4b5a69788     [cloudflare_prefix_list]
  tcp/443-443    from 0.0.0.0/0                [open_to_internet]   <- not Cloudflare
```

`run --execute` (sync) prints the report, the prefix list version change, and the backup it wrote first:

```text
PREFIX LISTS  (have vs what Cloudflare publishes)
  pl-0a1b2c3d4e5f60718 [managed, IPv4]  have 13, Cloudflare 15  ->  UPDATED
      + 103.31.4.0/22
      + 173.245.48.0/20
      + 188.114.96.0/20
      - 198.51.100.0/24
  ...
  ipv4: pl-0a1b2c3d4e5f60718 version 2 -> 3 (+3 -1)

==============================================================================
 BACKUP written before the change
==============================================================================
  location : backups/demo/cf-prefix-backup-20261117T211806678Z.json
  id       : cf-prefix-backup-20261117T211806678Z   taken 2026-11-17T21:18:06Z
  sha256   : 37b52b7fb216170a...
  pl-0a1b2c3d4e5f60718 (IPv4) version 2: 13 entries saved
      will add     103.31.4.0/22
      will add     173.245.48.0/20
      will add     188.114.96.0/20
      will remove  198.51.100.0/24
  pl-0f1e2d3c4b5a69788 (IPv6) version 1: 7 entries saved
  sg-0123456789abcdef0: 3 inbound rule source(s) saved

  Roll back with:
    python scripts/restore_prefix_list.py --from-backup-file backups/demo/cf-prefix-backup-20261117T211806678Z.json --restore-security-groups --execute
```

The backup holds the **broken** state (13 entries, version 2), because it is taken before the change. Sync alone leaves the `0.0.0.0/0` rule in place and keeps reporting it as a HIGH finding; `run --mode enforce --execute` removes it, after another backup.

The prefix list also keeps every version natively, so you can compare:

```bash
aws ec2 get-managed-prefix-list-entries --prefix-list-id pl-0a1b2c3d4e5f60718 --target-version 2
aws ec2 get-managed-prefix-list-entries --prefix-list-id pl-0a1b2c3d4e5f60718
```

### Try the rollback too

Restoring a backup puts the demo back into its broken state, which proves the backup is complete:

```bash
python scripts/restore_prefix_list.py --from-backup-file backups/demo/<file>.json --restore-security-groups --execute
python scripts/demo.py status        # broken again
python scripts/demo.py run --mode enforce --execute
```

## With a deployment

### Terraform

```hcl
# terraform.tfvars
mode        = "sync"          # or "enforce" to let the Lambda remove 0.0.0.0/0 as well
demo_vpc_id = "vpc-0123456789abcdef0"
```

### CloudFormation

```bash
./scripts/deploy_cli_cloudshell.sh --artifact-bucket my-artifacts-us-east-1 \
  --mode sync --param DemoVpcId=vpc-0123456789abcdef0 --execute
```

Either way you get a security group named `<prefix>-demo` that allows the first ingress port from the managed prefix lists. The managed prefix lists and that group are tagged `cloudflare-prefix-sync-demo`, which is what allows `demo.py break` to touch them, and the group is added to the managed and audited security groups.

Then:

```bash
python scripts/demo.py --region us-east-1 use-deployed --terraform-dir terraform
#   or: use-deployed --stack-name cloudflare-prefix-sync

python scripts/demo.py break --remove 3 --add-bogus
python scripts/demo.py run --via-lambda                # preview through the Lambda
python scripts/demo.py run --via-lambda --execute      # Lambda backs up to S3, then repairs
```

`--via-lambda` invokes the function with `{"dry_run": ..., "notify_on": "always"}`, so the report is also emailed if you subscribed. It downloads and summarizes the S3 backup. You can also just wait for the next scheduled run.

The Lambda can only do what its deployed mode allows. With `mode = "sync"`, `--mode enforce --via-lambda` plans the revocation but AWS denies it; run enforce locally instead (`run --mode enforce --execute`, using your credentials) or deploy with `mode = "enforce"`.

Do not use `demo_vpc_id` / `DemoVpcId` in a real deployment: it tags the production prefix lists as demo resources, which lets `demo.py` remove entries from them.

When you change the demo group with `--drop-sg-rule` and `attach` re-adds the rule, Terraform sees the rule as changed on the next plan. That only affects the demo group.

## Safety

- `break` refuses any prefix list or security group without the `cloudflare-prefix-sync-demo` tag.
- Local runs use only the demo security group: tag opt-in is turned off, so other tagged groups in the account are not touched.
- `teardown` deletes only what `setup` created. For an adopted deployment it only removes the local state file.
- State is in `.cfps-demo.json` and local backups are in `backups/demo/`; both are git-ignored.

## Permissions

Standalone demo, for the credentials you run it with:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeVpcs",
      "ec2:CreateManagedPrefixList", "ec2:DescribeManagedPrefixLists", "ec2:GetManagedPrefixListEntries",
      "ec2:ModifyManagedPrefixList", "ec2:DeleteManagedPrefixList",
      "ec2:CreateSecurityGroup", "ec2:DescribeSecurityGroups", "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
      "ec2:CreateTags",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

With a deployment, add `cloudformation:DescribeStacks` (for `use-deployed --stack-name`), `lambda:InvokeFunction` on the function and `s3:GetObject` on the backup bucket (for `--via-lambda`).

## Troubleshooting

| Message | Fix |
| :--- | :--- |
| `This region has no default VPC` | Pass `--vpc-id vpc-...` to `setup` or `walkthrough`. |
| `Demo state already exists` | Run `teardown`, or use another `--state-file`. |
| `Refusing to modify ...: missing the 'cloudflare-prefix-sync-demo' tag` | The resource is not a demo resource. Use `setup`, or deploy with `demo_vpc_id` / `DemoVpcId`. |
| `Could not delete sg-...` | The group is attached to something (for example an instance you added). Detach it and rerun `teardown`. |
| `The deployment has no demo security group` | Redeploy with `demo_vpc_id` / `DemoVpcId`. |
