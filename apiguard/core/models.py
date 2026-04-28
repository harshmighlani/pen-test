"""Core data models for scan execution and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    endpoint: str | None = None
    request: str | None = None
    response: str | None = None
    remediation: str | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class CheckResult:
    check_id: str
    check_name: str
    findings: list[Finding] = field(default_factory=list)
    passes: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "findings": [f.to_dict() for f in self.findings],
            "passes": self.passes,
            "errors": self.errors,
            "duration_s": self.duration_s,
        }


@dataclass
class ScanResult:
    target: str
    config_file: str
    check_results: list[CheckResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    duration_s: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "config_file": self.config_file,
            "duration_s": self.duration_s,
            "meta": self.meta,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": {
                    s.value: sum(1 for f in self.findings if f.severity == s)
                    for s in Severity
                },
            },
            "check_results": [cr.to_dict() for cr in self.check_results],
            "findings": [f.to_dict() for f in self.findings],
        }
