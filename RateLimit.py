"""Rate limiting checks — flood endpoints and detect missing throttling."""
from __future__ import annotations

import asyncio
import time

import httpx

from apiguard.checks.base import BaseCheck
from apiguard.core.models import Severity


class RateLimitCheck(BaseCheck):
    id          = "rate_limit"
    name        = "Rate Limiting"
    description = "Detects missing or bypassable rate limiting on sensitive endpoints"
    tags        = ["owasp-api4"]

    async def run(self) -> None:
        cfg         = self.config.check_cfg("rate_limit")
        num_req     = int(cfg.get("requests", 20))
        window_s    = float(cfg.get("window_s", 5))
        endpoints   = self.config.endpoints or [{"method": "GET", "path": "/"}]

        # Focus on sensitive-looking endpoints
        sensitive = [
            e for e in endpoints
            if any(
                kw in e.get("path", "").lower()
                for kw in ("login", "auth", "token", "password", "reset", "otp", "verify", "register")
            )
        ] or endpoints[:3]

        for ep in sensitive:
            await self._flood(ep, num_req, window_s)

    async def _flood(self, ep: dict, num_req: int, window_s: float) -> None:
        path   = ep.get("path", "/")
        method = ep.get("method", "GET")
        body   = ep.get("body")
        params = ep.get("params")

        statuses: list[int] = []
        rate_limited = False
        t0 = time.perf_counter()

        async def _one() -> None:
            nonlocal rate_limited
            try:
                resp, _ = await self.client.request(
                    method, path,
                    json=body if body else None,
                    params=params,
                )
                statuses.append(resp.status_code)
                if resp.status_code in (429, 503):
                    rate_limited = True
            except httpx.RequestError:
                statuses.append(0)

        tasks = [_one() for _ in range(num_req)]
        await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - t0

        total      = len(statuses)
        ok_count   = sum(1 for s in statuses if 200 <= s < 300)
        rate_count = sum(1 for s in statuses if s in (429, 503))

        if rate_limited or rate_count > 0:
            self.add_pass(
                f"Rate limiting active on {method} {path}",
                f"{rate_count}/{total} requests were throttled (429/503) in {elapsed:.1f}s.",
            )
        elif ok_count == total:
            self.add_finding(
                Severity.HIGH,
                f"No rate limiting detected on {method} {path}",
                (
                    f"Sent {num_req} concurrent requests in {elapsed:.1f}s — "
                    f"all {ok_count} returned 2xx. "
                    "This endpoint is vulnerable to brute-force and enumeration attacks."
                ),
                endpoint=path,
                remediation=(
                    "Implement rate limiting (e.g. token bucket / sliding window). "
                    "Return HTTP 429 with Retry-After. "
                    "Apply stricter limits to auth/sensitive endpoints."
                ),
                tags=["brute-force"],
            )
        else:
            self.add_finding(
                Severity.MEDIUM,
                f"Inconsistent responses under load on {method} {path}",
                (
                    f"{ok_count} OK, {rate_count} rate-limited, "
                    f"{total - ok_count - rate_count} errors in {elapsed:.1f}s."
                ),
                endpoint=path,
                remediation="Verify rate limiting is consistently applied.",
            )
