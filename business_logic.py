"""Business logic checks: negative amounts, race conditions, sequence skipping."""
from __future__ import annotations

import asyncio

import httpx

from apiguard.checks.base import BaseCheck
from apiguard.core.models import Severity


class BusinessLogicCheck(BaseCheck):
    id          = "business_logic"
    name        = "Business Logic"
    description = "Negative values, race conditions, mass assignment, sequence tampering"
    tags        = ["owasp-api6"]

    async def run(self) -> None:
        endpoints = self.config.endpoints
        if not endpoints:
            self.add_finding(
                Severity.INFO,
                "No endpoints configured for business logic testing",
                "Add endpoints with body schemas to enable these checks.",
            )
            return

        await self._check_negative_amounts(endpoints)
        await self._check_mass_assignment(endpoints)
        await self._check_race_conditions(endpoints)
        await self._check_http_methods(endpoints)

    # ------------------------------------------------------------------ #

    async def _check_negative_amounts(self, endpoints: list[dict]) -> None:
        """Submit negative / zero numeric values to financial-looking fields."""
        numeric_fields = ("amount", "quantity", "price", "balance", "count", "total", "credits")
        candidates = [
            e for e in endpoints
            if e.get("body") and any(
                k.lower() in numeric_fields
                for k in e["body"].keys()
            )
        ]
        for ep in candidates:
            path   = ep["path"]
            method = ep.get("method", "POST")
            body   = dict(ep["body"])

            for field in list(body.keys()):
                if field.lower() not in numeric_fields:
                    continue
                for evil_val in (-1, -9999, 0):
                    mutated = {**body, field: evil_val}
                    try:
                        resp, _ = await self.client.request(
                            method, path, json=mutated
                        )
                        if resp.status_code < 400:
                            self.add_finding(
                                Severity.HIGH,
                                f"Negative/zero value accepted for '{field}'",
                                (
                                    f"{method} {path} accepted {field}={evil_val} "
                                    f"with HTTP {resp.status_code}. "
                                    "This may allow free or reversed transactions."
                                ),
                                endpoint=path,
                                request=self.client.fmt_request(resp),
                                response=self.client.fmt_response(resp),
                                remediation=(
                                    f"Validate that '{field}' is > 0 (or >= minimum threshold) "
                                    "before processing. Reject invalid values with HTTP 422."
                                ),
                            )
                            break
                    except httpx.RequestError as exc:
                        self.add_error(f"Negative amount probe error on {path}: {exc}")

    async def _check_mass_assignment(self, endpoints: list[dict]) -> None:
        """Inject extra privileged fields into POST/PUT bodies."""
        extra_fields = {
            "is_admin": True,
            "role": "admin",
            "verified": True,
            "balance": 99999,
            "credits": 99999,
            "subscription": "premium",
        }
        writable_eps = [
            e for e in endpoints
            if e.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
            and e.get("body")
        ]
        for ep in writable_eps[:3]:
            path   = ep["path"]
            method = ep["method"].upper()
            body   = {**ep["body"], **extra_fields}
            try:
                resp, _ = await self.client.request(method, path, json=body)
                resp_body = resp.text.lower()
                if resp.status_code < 400 and any(
                    str(v).lower() in resp_body
                    for v in extra_fields.values()
                    if isinstance(v, str)
                ):
                    self.add_finding(
                        Severity.HIGH,
                        "Possible mass assignment vulnerability",
                        (
                            f"{method} {path} accepted extra privileged fields and "
                            "their values appear in the response."
                        ),
                        endpoint=path,
                        request=self.client.fmt_request(resp),
                        response=self.client.fmt_response(resp),
                        remediation=(
                            "Use an explicit allowlist of permitted fields when binding "
                            "request bodies to models. Never bind raw request dicts to DB models."
                        ),
                    )
                elif resp.status_code < 400:
                    self.add_finding(
                        Severity.MEDIUM,
                        "Extra fields not rejected — possible mass assignment",
                        (
                            f"{method} {path} returned {resp.status_code} "
                            "when extra privileged fields were submitted. "
                            "Manually verify whether they were silently accepted."
                        ),
                        endpoint=path,
                        remediation=(
                            "Reject unknown fields with HTTP 400, or use an explicit field allowlist."
                        ),
                    )
            except httpx.RequestError as exc:
                self.add_error(f"Mass assignment probe error on {path}: {exc}")

    async def _check_race_conditions(self, endpoints: list[dict]) -> None:
        """Fire concurrent requests to idempotency-sensitive endpoints."""
        cfg            = self.config.check_cfg("business_logic")
        concurrency    = int(cfg.get("concurrency", 10))
        race_candidates = [
            e for e in endpoints
            if any(
                kw in e.get("path", "").lower()
                for kw in ("redeem", "purchase", "coupon", "transfer", "withdraw", "apply", "claim")
            )
        ]
        for ep in race_candidates[:2]:
            path   = ep["path"]
            method = ep.get("method", "POST")
            body   = ep.get("body")

            status_codes: list[int] = []

            async def _one() -> None:
                try:
                    resp, _ = await self.client.request(
                        method, path,
                        json=body if body else None,
                    )
                    status_codes.append(resp.status_code)
                except httpx.RequestError:
                    status_codes.append(0)

            await asyncio.gather(*[_one() for _ in range(concurrency)])
            success_count = sum(1 for s in status_codes if 200 <= s < 300)

            if success_count > 1:
                self.add_finding(
                    Severity.HIGH,
                    f"Potential race condition on {method} {path}",
                    (
                        f"{success_count}/{concurrency} concurrent requests succeeded. "
                        "This endpoint may be vulnerable to double-spending or double-redemption."
                    ),
                    endpoint=path,
                    remediation=(
                        "Use database-level locking, idempotency keys, or optimistic concurrency "
                        "to prevent duplicate processing of the same operation."
                    ),
                )
            else:
                self.add_pass(
                    f"Race condition not detected on {method} {path}",
                    f"Only {success_count}/{concurrency} concurrent requests succeeded.",
                )

    async def _check_http_methods(self, endpoints: list[dict]) -> None:
        """Check whether DELETE/PUT/PATCH are unintentionally exposed."""
        dangerous_methods = ["DELETE", "PUT", "PATCH", "TRACE", "OPTIONS"]
        for ep in self.config.endpoints[:5]:
            path = ep.get("path", "/")
            expected_method = ep.get("method", "GET").upper()

            for method in dangerous_methods:
                if method == expected_method:
                    continue
                try:
                    resp, _ = await self.client.request(method, path)
                    if resp.status_code not in (405, 404, 403, 501):
                        if method == "TRACE":
                            self.add_finding(
                                Severity.LOW,
                                f"HTTP TRACE enabled on {path}",
                                "TRACE can be used in cross-site tracing (XST) attacks.",
                                endpoint=path,
                                remediation="Disable TRACE method on your web server.",
                            )
                        else:
                            self.add_finding(
                                Severity.MEDIUM,
                                f"Unexpected HTTP method {method} accepted on {path}",
                                f"Server returned {resp.status_code} instead of 405.",
                                endpoint=path,
                                remediation=f"Explicitly reject {method} on {path} with 405.",
                            )
                except httpx.RequestError:
                    pass
