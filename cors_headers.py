"""CORS misconfiguration and security headers checks."""
from __future__ import annotations

import httpx

from apiguard.checks.base import BaseCheck
from apiguard.core.models import Severity

REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "Missing HSTS header",
        "Strict-Transport-Security is not set. Browsers may allow HTTP downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Missing X-Content-Type-Options header",
        "Without nosniff, browsers may MIME-sniff responses into executable types.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Missing X-Frame-Options header",
        "API responses could be embedded in iframes (clickjacking).",
        "Add: X-Frame-Options: DENY",
    ),
    "content-security-policy": (
        Severity.LOW,
        "Missing Content-Security-Policy header",
        "No CSP header found — XSS mitigation is weaker.",
        "Add an appropriate CSP policy.",
    ),
}

PERMISSIVE_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.io",
    "null",
]


class CorsHeadersCheck(BaseCheck):
    id          = "cors"
    name        = "CORS & Security Headers"
    description = "CORS wildcard/misconfiguration, missing security headers"
    tags        = ["owasp-api7", "owasp-a05"]

    async def run(self) -> None:
        await self._check_security_headers()
        await self._check_cors()

    async def _check_security_headers(self) -> None:
        try:
            resp, _ = await self.client.get("/")
        except httpx.RequestError as exc:
            self.add_error(f"Could not fetch / for header check: {exc}")
            return

        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, (severity, title, detail, remediation) in REQUIRED_SECURITY_HEADERS.items():
            if header not in resp_headers_lower:
                self.add_finding(
                    severity, title, detail,
                    endpoint="/",
                    response=self.client.fmt_response(resp),
                    remediation=remediation,
                )
            else:
                self.add_pass(f"{header} is present")

        # Check for server banner disclosure
        server = resp_headers_lower.get("server", "")
        x_powered = resp_headers_lower.get("x-powered-by", "")
        if server and any(kw in server.lower() for kw in ("apache", "nginx", "iis", "gunicorn", "uvicorn")):
            self.add_finding(
                Severity.LOW,
                "Server version disclosed in 'Server' header",
                f"Server: {server}",
                endpoint="/",
                remediation="Remove or genericise the Server header to avoid fingerprinting.",
            )
        if x_powered:
            self.add_finding(
                Severity.LOW,
                "Technology stack disclosed via 'X-Powered-By'",
                f"X-Powered-By: {x_powered}",
                endpoint="/",
                remediation="Remove the X-Powered-By header.",
            )

    async def _check_cors(self) -> None:
        """Test whether the API echoes back arbitrary or null origins."""
        endpoints = self.config.endpoints[:3] or [{"method": "GET", "path": "/"}]

        for ep in endpoints:
            path = ep.get("path", "/")
            method = ep.get("method", "GET")

            # 1. Wildcard ACAO
            try:
                resp, _ = await self.client.request(method, path)
                acao = resp.headers.get("access-control-allow-origin", "")
                if acao == "*":
                    self.add_finding(
                        Severity.MEDIUM,
                        "CORS wildcard (*) on credentialed endpoint",
                        f"{method} {path} returns Access-Control-Allow-Origin: *. "
                        "This allows any origin to read the response.",
                        endpoint=path,
                        response=self.client.fmt_response(resp),
                        remediation=(
                            "Restrict ACAO to a specific allowlist of trusted origins. "
                            "Never combine wildcard with credentials=true."
                        ),
                    )
            except httpx.RequestError as exc:
                self.add_error(f"CORS wildcard probe failed for {path}: {exc}")

            # 2. Origin reflection
            for evil_origin in PERMISSIVE_ORIGINS:
                try:
                    resp, _ = await self.client.request(
                        method, path,
                        headers={"Origin": evil_origin},
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")
                    if acao == evil_origin:
                        severity = (
                            Severity.CRITICAL
                            if acac.lower() == "true"
                            else Severity.HIGH
                        )
                        self.add_finding(
                            severity,
                            "CORS origin reflection" + (" with credentials" if acac.lower() == "true" else ""),
                            (
                                f"Server reflected origin '{evil_origin}' in ACAO header on {path}. "
                                + ("Credentials are allowed — attackers can read authenticated responses." if acac.lower() == "true" else "")
                            ),
                            endpoint=path,
                            request=self.client.fmt_request(resp),
                            response=self.client.fmt_response(resp),
                            remediation=(
                                "Validate Origin against a strict allowlist. "
                                "Never reflect arbitrary origins. "
                                "Do not combine Allow-Credentials: true with dynamic origins."
                            ),
                        )
                    elif acao == "null":
                        self.add_finding(
                            Severity.HIGH,
                            "CORS null origin accepted",
                            f"Server returned ACAO: null on {path}. Sandboxed iframes can exploit this.",
                            endpoint=path,
                            remediation="Do not allow null origins in your CORS policy.",
                        )
                except httpx.RequestError as exc:
                    self.add_error(f"CORS origin probe failed for {path}: {exc}")
