"""CLI entrypoint for apiguard."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from apiguard import __version__
from apiguard.checks import ALL_CHECKS
from apiguard.core.config import Config
from apiguard.core.engine import Engine
from apiguard.core.models import Severity
from apiguard.reports.reporters import print_console, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="apiguard")
    parser.add_argument("--version", action="version", version=f"apiguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    list_checks = sub.add_parser("list-checks", help="List available checks")
    list_checks.set_defaults(_cmd=cmd_list_checks)

    scan = sub.add_parser("scan", help="Run a scan")
    scan.add_argument("config", help="Path to YAML config file")
    scan.add_argument(
        "--format",
        default="",
        help="Comma-separated formats: console,json (default from config)",
    )
    scan.add_argument(
        "--output",
        default="",
        help="Base output path for report files (default from config)",
    )
    scan.add_argument(
        "--fail-on",
        default="",
        choices=[s.value for s in Severity],
        help="Exit non-zero if any finding >= this severity",
    )
    scan.set_defaults(_cmd=cmd_scan)
    return parser.parse_args()


def cmd_list_checks(_: argparse.Namespace) -> int:
    for check_id, check_cls in ALL_CHECKS.items():
        print(f"{check_id:16} {check_cls.name}")
    return 0


def severity_rank(severity: Severity) -> int:
    return {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }[severity]


async def run_scan(args: argparse.Namespace) -> int:
    cfg = Config.load(args.config)
    engine = Engine(cfg)
    result = await engine.run()
    result.config_file = str(Path(args.config).resolve())

    configured_formats = cfg.report.get("formats", ["console", "json"])
    formats = (
        [f.strip() for f in args.format.split(",") if f.strip()]
        if args.format
        else configured_formats
    )
    output = args.output or cfg.report.get("output", "./apiguard-report")
    fail_on = args.fail_on or cfg.report.get("fail_on", "")

    if "console" in formats:
        print_console(result)
    if "json" in formats:
        json_path = write_json(result, output)
        print(f"\nJSON report written: {json_path}")

    if fail_on:
        threshold = Severity(fail_on)
        threshold_rank = severity_rank(threshold)
        has_failure = any(
            severity_rank(finding.severity) >= threshold_rank for finding in result.findings
        )
        if has_failure:
            return 1
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    return asyncio.run(run_scan(args))


def main() -> int:
    args = parse_args()
    return args._cmd(args)


if __name__ == "__main__":
    raise SystemExit(main())
