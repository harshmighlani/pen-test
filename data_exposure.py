"""Data exposure checks: verbose errors, stack traces, sensitive field leakage."""
from __future__ import annotations

import re

import httpx

from apiguard.checks.base import BaseCheck
from apiguard.core.models import Severity

# ------------------------------------------------------------------ #
# Signatures                                                           #
# ------------------------------------------------------------------ #

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*\(",   # Java/JS
    r"File \"[^\"]+\", line \d+",                                    # Python
    r"System\.Web\.",                                                 # ASP.NET
    r"Microsoft\.AspNetCore",
    r"org\.springframework",
    r"ActiveRecord::.*Error",
    r"PG::.*Error",
    r"SQLSTATE\[",
]

SENSITIVE_FIELD_PATTERNS = [
    (r'"password"\s*:', "password field in response"),
    (r'"passwd"\s*:', "passwd field in response"),
    (r'"secret"\s*:', "secret field in response"),
    (r'"api_key"\s*:', "api_key field in response"),
    (r'"token"\s*:\s*"[A-Za-z0-9_\-\.]{20,}"', "token in response body"),
    (r'"private_key"\s*:', "private_key in response"),
    (r'"ssn"\s*:', "SSN field in response"),
    (r'"credit_card"\s*:', "credit card field in response"),
    (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', "possible credit card number"),
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b', "email address"),
]

BAD_ERROR_ENDPOINTS = [
    "/undefined",
    "/null",
    "/%00",
    "/____nonexistent____",
    "/../etc/passwd",
]

VERBOSE_ERROR_PATTERNS = [
    r"Internal Server Error",
    r"unhandled exception",
    r"NullPointerException",
    r"undefined method",
    r"NoMethodError",
    r"AttributeError",
    r"KeyError",
    r"IndexError",
]


class DataExposureCheck(BaseCheck):
    id          = "data_exposure"
    name        = "Data Exposure"
    description = "Verbose errors, stack traces, sensitive fields in responses"
    tags        = ["owasp-api3", "owasp-a02"]

    async def run(self) -> None:
        await self._probe_error_endpoints()
        await self._check_existing_endpoints()

    async def _probe_error_endpoints(self) -> None:
        """Hit known-bad paths to trigger verbose errors."""
        for path in BAD_ERROR_ENDPOINTS:
            try:
                resp, _ = await self.client.get(path)
                self._analyse_response(resp, path)
            except httpx.RequestError as exc:
                self.add_error(f"Error probe failed for {path}: {exc}")

    async def _check_existing_endpoints(self) -> None:
        """Scan normal endpoint responses for sensitive leakage."""
        token = self.config.auth.get("token", "")
        auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

        for ep in self.config.endpoints[:10]:
            path   = ep.get("path", "/")
            method = ep.get("method", "GET")
            try:
                resp, _ = await self.client.request(
                    method, path, headers=auth_headers
                )
                self._analyse_response(resp, path)
                self._check_sensitive_fields(resp, path)
            except httpx.RequestError as exc:
                self.add_error(f"Data exposure scan error on {path}: {exc}")

    # ------------------------------------------------------------------ #

    def _analyse_response(self, resp: httpx.Response, path: str) -> None:
        body = resp.text

        # Stack traces
        for pattern in STACK_TRACE_PATTERNS:
            if re.search(pattern, body):
                self.add_finding(
                    Severity.HIGH,
                    "Stack trace / debug info in response",
                    f"Pattern `{pattern}` matched in response body for {path}.",
                    endpoint=path,
                    request=self.client.fmt_request(resp),
                    response=self.client.fmt_response(resp),
                    remediation=(
                        "Disable debug mode in production. "
                        "Return generic error messages to clients; log details server-side."
                    ),
                )
                return  # one finding per endpoint is enough

        # Verbose error messages (lower severity)
        for pattern in VERBOSE_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                self.add_finding(
                    Severity.MEDIUM,
                    "Verbose error message exposed",
                    f"Error signature `{pattern}` found in response for {path}.",
                    endpoint=path,
                    response=self.client.fmt_response(resp),
                    remediation=(
                        "Return a generic error message (e.g. 'An error occurred'). "
                        "Log verbose details internally."
                    ),
                )
                return

    def _check_sensitive_fields(self, resp: httpx.Response, path: str) -> None:
        body = resp.text
        found: list[str] = []
        for pattern, label in SENSITIVE_FIELD_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                found.append(label)

        if found:
            self.add_finding(
                Severity.HIGH,
                "Sensitive data in response body",
                f"Detected: {', '.join(found)} in response from {path}.",
                endpoint=path,
                response=self.client.fmt_response(resp),
                remediation=(
                    "Apply field-level filtering before serialising responses. "
                    "Never return password hashes, raw tokens, or PII unless explicitly required."
                ),
            )
