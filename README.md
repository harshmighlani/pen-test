# apiguard

API security/performance probing toolkit (Python + `httpx`, async checks).

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development (includes tests):

```bash
pip install -e ".[dev]"
```

## Quick start

```bash
# Copy and edit config
cp config.example.yaml config.yaml

# See available checks
apiguard list-checks

# Run scan (console + json by default from config)
apiguard scan config.yaml

# JSON only
apiguard scan config.yaml --format json --output ./reports/apiguard-report

# Fail CI on high/critical findings
apiguard scan config.yaml --fail-on high
```

## How the project is designed to work

1. Load YAML config (`target`, auth tokens, endpoints, enabled checks).
2. Build an authenticated `APIClient`.
3. Instantiate enabled checks from a global registry (`ALL_CHECKS`).
4. Run checks concurrently with bounded concurrency.
5. Collect findings (severity, evidence, remediation) into a final scan report.
6. Exit with code policy in CLI/CI depending on severity threshold.

## Project structure

```text
apiguard/
├── apiguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── auth.py
│   │   ├── injection.py
│   │   ├── rate_limit.py
│   │   ├── data_exposure.py
│   │   ├── cors_headers.py
│   │   └── business_logic.py
│   ├── core/
│   │   ├── config.py
│   │   ├── client.py
│   │   ├── engine.py
│   │   └── models.py
│   └── reports/
│       └── reporters.py
├── config.example.yaml
└── pyproject.toml
```

## Minimal verification checklist

- `apiguard list-checks` shows all check IDs.
- `apiguard scan config.yaml` completes without import/runtime errors.
- JSON report file is created.
- `--fail-on high` returns non-zero when high/critical findings exist.

## Config reference

- `target`: base API URL
- `auth.token`: bearer token for authenticated checks
- `auth.other_user_token`: optional second-user token for BOLA checks
- `endpoints[]`: endpoint objects (`path`, `method`, optional `params`/`body`, `auth_required`)
- `scan.timeout`: request timeout (seconds)
- `scan.concurrency`: max parallel check tasks
- `scan.verify_ssl`: set `false` for local/self-signed environments
- `checks.<id>.enabled`: enable/disable each check
- `report.formats`: output formats (`console`, `json`)
- `report.output`: base path for report files

## Notes

- Existing top-level `*.py` files are currently kept for compatibility while the package is being stabilized.
- New work should target the packaged modules under `apiguard/`.

## Run tests

```bash
pytest -q
```
