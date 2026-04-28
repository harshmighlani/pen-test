"""Scan engine: loads checks, runs them concurrently, collects results."""

from __future__ import annotations

import asyncio
import time
from typing import Callable

from apiguard.checks import ALL_CHECKS
from apiguard.core.client import APIClient
from apiguard.core.config import Config
from apiguard.core.models import ScanResult


class Engine:
    def __init__(
        self,
        config: Config,
        *,
        progress_cb: Callable[[str, str], None] | None = None,
    ) -> None:
        self.config = config
        self.progress_cb = progress_cb or (lambda *_: None)

    async def run(self) -> ScanResult:
        cfg = self.config.scan
        result = ScanResult(
            target=self.config.target,
            config_file="",
        )
        t0 = time.perf_counter()

        auth_headers: dict[str, str] = {}
        token = self.config.auth.get("token", "")
        if token:
            auth_headers["Authorization"] = f"Bearer {token}"

        async with APIClient(
            self.config.target,
            timeout=float(cfg.get("timeout", 10)),
            verify_ssl=bool(cfg.get("verify_ssl", True)),
            follow_redirects=bool(cfg.get("follow_redirects", False)),
            headers=auth_headers,
            user_agent=str(cfg.get("user_agent", "apiguard/0.1")),
        ) as client:
            checks_to_run = [
                cls(client, self.config)
                for check_id, cls in ALL_CHECKS.items()
                if self.config.check_enabled(check_id)
            ]
            sem = asyncio.Semaphore(int(cfg.get("concurrency", 5)))

            async def run_one(check):
                self.progress_cb("start", check.name)
                async with sem:
                    cr = await check.execute()
                self.progress_cb("done", check.name)
                return cr

            check_results = await asyncio.gather(*(run_one(c) for c in checks_to_run))

        for cr in check_results:
            result.check_results.append(cr)
            result.findings.extend(cr.findings)
            if cr.errors:
                result.meta.setdefault("errors", []).extend(cr.errors)

        result.duration_s = time.perf_counter() - t0
        return result
