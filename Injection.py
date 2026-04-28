"""Injection checks: SQL injection, command injection, NoSQL injection."""
from __future__ import annotations

import httpx

from apiguard.checks.base import BaseCheck
from apiguard.core.models import Severity

# ------------------------------------------------------------------ #
# Payload libraries                                                    #
# ------------------------------------------------------------------ #

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "1' AND SLEEP(3)--",          # time-based blind
    "1' AND 1=CONVERT(int,@@version)--",
    "'; WAITFOR DELAY '0:0:3'--",  # MSSQL time-based
    "1 UNION SELECT NULL--",
    "' OR 1=1#",
    "admin'--",
]

CMD_PAYLOADS = [
    "; ls",
    "| ls",
    "& ls",
    "`ls`",
    "$(ls)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; sleep 3",
    "| sleep 3",
    "& ping -c 1 127.0.0.1",
]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
]

# Strings that indicate injection landed
SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "unclosed quotation",
    "odbc driver",
    "ora-",
    "pg_query",
    "syntax error",
    "sqlstate",
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed string",
]

CMD_SUCCESS_SIGNATURES = [
    "root:x:",             # /etc/passwd
    "/bin/bash",
    "uid=",
    "total 0",
    "drwxr",
]


def _body_contains(body: str, signatures: list[str]) -> str | None:
    lower = body.lower()
    for sig in signatures:
        if sig.lower() in lower:
            return sig
    return None


class InjectionCheck(BaseCheck):
    id          = "injection"
    name        = "Injection"
    description = "SQL, command, and NoSQL injection probes"
    tags        = ["owasp-api8", "owasp-a03"]

    async def run(self) -> None:
        endpoints = self.config.endpoints
        if not endpoints:
            self.add_finding(
                Severity.INFO,
                "No endpoints configured for injection testing",
                "Add endpoints with parameters to your config to enable injection probes.",
            )
            return

        for ep in endpoints:
            path   = ep.get("path", "/")
            method = ep.get("method", "GET")
            params = ep.get("params", {})
            body   = ep.get("body", {})

            if params:
                await self._probe_params(method, path, params)
            if body:
                await self._probe_body(method, path, body)

    # ------------------------------------------------------------------ #

    async def _probe_params(
        self, method: str, path: str, params: dict
    ) -> None:
        for param_name in params:
            for payload in SQL_PAYLOADS[:5]:
                mutated = {**params, param_name: payload}
                try:
                    resp, elapsed = await self.client.request(
                        method, path, params=mutated
                    )
                    body = resp.text
                    hit = _body_contains(body, SQL_ERROR_SIGNATURES)
                    if hit:
                        self.add_finding(
                            Severity.CRITICAL,
                            f"SQL injection — query param '{param_name}'",
                            (
                                f"Payload `{payload}` triggered SQL error signature "
                                f"'{hit}' in response body."
                            ),
                            endpoint=path,
                            request=self.client.fmt_request(resp),
                            response=self.client.fmt_response(resp),
                            remediation=(
                                "Use parameterised queries / prepared statements. "
                                "Never interpolate user input into SQL strings."
                            ),
                        )
                        break  # one finding per param is enough
                    if elapsed >= 2.8:
                        self.add_finding(
                            Severity.HIGH,
                            f"Possible time-based SQL injection — param '{param_name}'",
                            f"Response took {elapsed:.1f}s with payload `{payload}`.",
                            endpoint=path,
                            remediation="Use parameterised queries.",
                        )
                        break
                except httpx.RequestError as exc:
                    self.add_error(f"SQLi probe error on {path}?{param_name}: {exc}")

            for payload in CMD_PAYLOADS[:3]:
                mutated = {**params, param_name: payload}
                try:
                    resp, elapsed = await self.client.request(
                        method, path, params=mutated
                    )
                    hit = _body_contains(resp.text, CMD_SUCCESS_SIGNATURES)
                    if hit:
                        self.add_finding(
                            Severity.CRITICAL,
                            f"Command injection — query param '{param_name}'",
                            f"Payload `{payload}` matched command output signature '{hit}'.",
                            endpoint=path,
                            request=self.client.fmt_request(resp),
                            response=self.client.fmt_response(resp),
                            remediation=(
                                "Never pass user input to shell commands. "
                                "Use subprocess with a list, never shell=True."
                            ),
                        )
                        break
                    if elapsed >= 2.8:
                        self.add_finding(
                            Severity.HIGH,
                            f"Possible time-based command injection — param '{param_name}'",
                            f"Response took {elapsed:.1f}s with payload `{payload}`.",
                            endpoint=path,
                            remediation="Avoid shell execution with user-supplied input.",
                        )
                        break
                except httpx.RequestError as exc:
                    self.add_error(f"CMDi probe error on {path}: {exc}")

    async def _probe_body(self, method: str, path: str, body: dict) -> None:
        for field_name in body:
            for payload in SQL_PAYLOADS[:5]:
                mutated = {**body, field_name: payload}
                try:
                    resp, elapsed = await self.client.request(
                        method, path, json=mutated
                    )
                    hit = _body_contains(resp.text, SQL_ERROR_SIGNATURES)
                    if hit:
                        self.add_finding(
                            Severity.CRITICAL,
                            f"SQL injection — body field '{field_name}'",
                            f"Payload `{payload}` triggered '{hit}' in response.",
                            endpoint=path,
                            request=self.client.fmt_request(resp),
                            response=self.client.fmt_response(resp),
                            remediation="Use parameterised queries / prepared statements.",
                        )
                        break
                    if elapsed >= 2.8:
                        self.add_finding(
                            Severity.HIGH,
                            f"Possible time-based SQL injection — body field '{field_name}'",
                            f"Response took {elapsed:.1f}s with payload `{payload}`.",
                            endpoint=path,
                            remediation="Use parameterised queries.",
                        )
                        break
                except httpx.RequestError as exc:
                    self.add_error(f"SQLi body probe error on {path}.{field_name}: {exc}")
