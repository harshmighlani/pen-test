"""Base class for all checks."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from apiguard.core.client import APIClient
from apiguard.core.config import Config
from apiguard.core.models import CheckResult, Finding, Severity


class BaseCheck(ABC):
    id = "base"
    name = "Base Check"
    description = ""
    tags: list[str] = []

    def __init__(self, client: APIClient, config: Config) -> None:
        self.client = client
        self.config = config
        self._findings: list[Finding] = []
        self._passes: list[dict[str, str]] = []
        self._errors: list[str] = []

    @abstractmethod
    async def run(self) -> None:
        """Implement check logic."""

    async def execute(self) -> CheckResult:
        start = time.perf_counter()
        try:
            await self.run()
        except Exception as exc:  # pragma: no cover
            self.add_error(f"Unhandled error in check '{self.id}': {exc}")
        duration = time.perf_counter() - start
        return CheckResult(
            check_id=self.id,
            check_name=self.name,
            findings=self._findings,
            passes=self._passes,
            errors=self._errors,
            duration_s=duration,
        )

    def add_finding(
        self,
        severity: Severity,
        title: str,
        detail: str,
        *,
        endpoint: str | None = None,
        request: str | None = None,
        response: str | None = None,
        remediation: str | None = None,
        tags: list[str] | None = None,
    ) -> None:
        finding = Finding(
            severity=severity,
            title=title,
            detail=detail,
            endpoint=endpoint,
            request=request,
            response=response,
            remediation=remediation,
            tags=tags or [],
        )
        self._findings.append(finding)

    def add_pass(self, title: str, detail: str = "") -> None:
        self._passes.append({"title": title, "detail": detail})

    def add_error(self, error: str) -> None:
        self._errors.append(error)
