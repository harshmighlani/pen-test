# apiguard
 
API penetration testing suite for development — built with Python + httpx.
 
## Install
 
```bash
cd apiguard
pip install -e ".[dev]"
```
 
## Quick start
 
```bash
# Copy and edit the example config
cp config.example.yaml config.yaml
# edit config.yaml — set target, token, endpoints
 
# Run a full scan
apiguard scan config.yaml
 
# List available checks
apiguard list-checks
 
# Output JSON only (good for CI)
apiguard scan config.yaml --format json --output ./reports/scan
 
# Fail CI pipeline if any HIGH/CRITICAL found (exit code 1)
apiguard scan config.yaml --fail-on high
```
 
## Project structure
 
```
apiguard/
├── cli.py                    # Typer entry point
├── config.example.yaml       # Annotated config template
├── core/
│   ├── client.py             # httpx async client wrapper
│   ├── config.py             # YAML config loader + defaults
│   ├── engine.py             # Orchestrates checks concurrently
│   └── models.py             # Finding, Severity, ScanResult
├── checks/
│   ├── base.py               # BaseCheck (all checks inherit this)
│   ├── auth.py               # JWT alg=none, BOLA/IDOR, missing auth
│   ├── injection.py          # SQLi, command injection
│   ├── rate_limit.py         # Flood detection
│   ├── data_exposure.py      # Verbose errors, sensitive fields
│   ├── cors_headers.py       # CORS misconfig, security headers
│   └── business_logic.py     # Negative amounts, race conditions, mass assignment
└── reports/
    └── reporters.py          # Rich console + JSON output
```
 
## Adding a new check
 
1. Create `apiguard/checks/my_check.py`:
```python
from apiguard.checks.base import BaseCheck
from apiguard.core.models import Severity
 
class MyCheck(BaseCheck):
    id   = "my_check"
    name = "My Custom Check"
 
    async def run(self) -> None:
        resp, _ = await self.client.get("/some-path")
        if resp.status_code == 200 and "secret" in resp.text:
            self.add_finding(
                Severity.HIGH,
                "Secret exposed",
                "The /some-path endpoint leaks a secret.",
                endpoint="/some-path",
                remediation="Remove the secret from the response.",
            )
```
 
2. Register it in `apiguard/checks/__init__.py`:
```python
from apiguard.checks.my_check import MyCheck
ALL_CHECKS["my_check"] = MyCheck
```
 
3. Add an entry under `checks:` in your YAML config.
## CI integration
 
```yaml
# .github/workflows/security.yml
- name: API security scan
  run: |
    pip install -e ./apiguard
    apiguard scan config.yaml --fail-on high --format json --output security-report
- uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: security-report.json
```
 
## Config reference
 
| Key | Default | Description |
|-----|---------|-------------|
| `target` | — | Base URL of your API |
| `auth.token` | `""` | Bearer token for your test user |
| `auth.other_user_token` | `""` | Second user token for BOLA checks |
| `scan.timeout` | `10` | Request timeout (seconds) |
| `scan.concurrency` | `5` | Max parallel checks |
| `scan.verify_ssl` | `true` | Set false for self-signed certs |
| `checks.<id>.enabled` | `true` | Toggle individual checks |
| `report.formats` | `[console, json]` | Output formats |
| `report.output` | `./apiguard-report` | Base path for file reports |
 
