"""Configuration loader for apiguard YAML files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Config:
    target: str
    auth: dict[str, Any]
    endpoints: list[dict[str, Any]]
    scan: dict[str, Any]
    checks: dict[str, dict[str, Any]]
    report: dict[str, Any]

    @classmethod
    def load(cls, path: str) -> "Config":
        cfg_path = Path(path)
        if not cfg_path.exists():
            raise FileNotFoundError(f"Config file not found: {cfg_path}")

        raw = yaml.safe_load(cfg_path.read_text()) or {}
        target = str(raw.get("target", "")).rstrip("/")
        if not target:
            raise ValueError("Config must include a non-empty 'target' URL.")

        return cls(
            target=target,
            auth=raw.get("auth", {}) or {},
            endpoints=raw.get("endpoints", []) or [],
            scan=raw.get("scan", {}) or {},
            checks=raw.get("checks", {}) or {},
            report=raw.get("report", {}) or {},
        )

    def check_enabled(self, check_id: str) -> bool:
        return bool((self.checks.get(check_id, {}) or {}).get("enabled", True))

    def check_cfg(self, check_id: str) -> dict[str, Any]:
        return self.checks.get(check_id, {}) or {}
