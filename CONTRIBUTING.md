# Contributing

Thanks for helping. Bug reports, documentation fixes and pull requests are all welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Security problems: do not open a public issue. See [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone https://github.com/OWNER/cloudflare-prefix-sync.git
cd cloudflare-prefix-sync
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install boto3 cfn-lint
```

The engine has no dependencies besides `boto3`, which the Lambda runtime provides. Keep it that way: the Lambda package is `src/` zipped as is.

## Checks

Run these before opening a pull request. CI runs the same.

```bash
python -m unittest discover -s tests -v
python scripts/package_lambda.py
cfn-lint templates/cloudflare-prefix-sync-template.yaml
cd terraform && terraform fmt -check -recursive && terraform init -backend=false && terraform validate
shellcheck scripts/*.sh
```

Tests run offline against in-memory fakes (`tests/test_modes.py`, `tests/test_sync_engine.py`). Never call AWS or Cloudflare from a test.

## Guidelines

- **Safety first.** Any change that can write to AWS needs a test that proves it does nothing in dry run and in the modes that must not write, and that a failed backup blocks it.
- **Feature parity.** A new setting usually needs to appear in `SyncConfig`, `lambda_handler.py`, the CLI, Terraform (`variables.tf`, `main.tf`), the CloudFormation template, and [docs/CONFIGURATION.md](docs/CONFIGURATION.md).
- **IAM.** If code calls a new AWS API, add the permission to both Terraform and CloudFormation, scoped to the modes that need it, and update [docs/MODES.md](docs/MODES.md#iam-per-mode).
- **Imports.** Modules in `src/` import each other with `try: from src.x import ...` / `except ImportError: from x import ...` so they work both in the repository and in the flat Lambda zip.
- **Style.** Python 3.10+, type hints, standard library only. Keep functions that decide what to change pure (planning) and separate from functions that call AWS (applying).
- **Changelog.** Add a line under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).

## Pull requests

- One topic per pull request.
- Describe what changes for a user, how you tested it, and whether it changes IAM permissions or default behavior.
- Fill in the pull request template checklist.

## Releasing (maintainers)

1. Move `[Unreleased]` entries to a new version section in `CHANGELOG.md` and update `version` in `pyproject.toml`.
2. Tag `vX.Y.Z` and create a GitHub release with the changelog section.
3. Attach `dist/cloudflare-prefix-sync-<hash>.zip` from `python scripts/package_lambda.py`.

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE) and that you will follow the [Code of Conduct](CODE_OF_CONDUCT.md).
