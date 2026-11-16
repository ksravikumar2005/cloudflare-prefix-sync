# Security policy

## Supported versions

| Version | Supported |
| :--- | :--- |
| 2.x | Yes |
| 1.x | No. Upgrade to 2.x ([guide](docs/INSTALLATION_GUIDE.md#upgrading-from-v1)). |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository ([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)). Do not open a public issue.

Include:

- what an attacker can do and under which configuration (mode, scope settings);
- steps or a test case that shows it;
- the version or commit.

We aim to acknowledge reports within 5 working days and to agree on a disclosure date with you once a fix is available.

## In scope

- The engine (`src/`), scripts, CloudFormation template and Terraform module in this repository.
- Examples: a way to make the tool open a security group to non-Cloudflare sources, to change resources outside the configured scope, to exceed the IAM permissions of the deployed mode, to bypass a guardrail, or to leak backup or report contents.

## Out of scope

- Limits described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#threat-model), such as other Cloudflare customers sharing the same IP ranges.
- Vulnerabilities in AWS, Cloudflare, Python or boto3 themselves. Report those to the vendor.
- Misconfiguration in your own deployment, such as broad tag permissions that let others put security groups in scope.

## Hardening recommendations

- Start in `audit` mode and move up the ladder as described in [docs/MODES.md](docs/MODES.md#rollout-plan).
- Restrict who can set the `cloudflare-prefix-sync` tag on security groups if you use tag opt-in with `attach` or `enforce`.
- Use Authenticated Origin Pulls or a secret header in addition to IP allow-listing.
- Review `UPDATED` reports.
