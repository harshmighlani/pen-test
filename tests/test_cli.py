from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from apiguard import cli
from apiguard.core.models import Finding, ScanResult, Severity


def _write_min_config(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                'target: "http://localhost:8000"',
                "report:",
                "  formats: [json]",
                "  output: ./report-out",
            ]
        )
    )


def test_run_scan_writes_json(monkeypatch, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_min_config(config_path)

    async def fake_run(self):  # noqa: ANN001
        return ScanResult(target="http://localhost:8000", config_file="")

    monkeypatch.setattr(cli.Engine, "run", fake_run)

    args = argparse.Namespace(
        config=str(config_path),
        format="json",
        output=str(tmp_path / "scan-report"),
        fail_on="",
    )
    rc = asyncio.run(cli.run_scan(args))
    assert rc == 0
    assert (tmp_path / "scan-report.json").exists()


def test_run_scan_fail_on_threshold(monkeypatch, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    _write_min_config(config_path)

    async def fake_run(self):  # noqa: ANN001
        return ScanResult(
            target="http://localhost:8000",
            config_file="",
            findings=[
                Finding(
                    severity=Severity.HIGH,
                    title="High issue",
                    detail="Example finding",
                )
            ],
        )

    monkeypatch.setattr(cli.Engine, "run", fake_run)

    args = argparse.Namespace(
        config=str(config_path),
        format="json",
        output=str(tmp_path / "scan-report"),
        fail_on="high",
    )
    rc = asyncio.run(cli.run_scan(args))
    assert rc == 1


def test_list_checks_command(capsys) -> None:
    rc = cli.cmd_list_checks(argparse.Namespace())
    out = capsys.readouterr().out
    assert rc == 0
    assert "auth" in out
    assert "injection" in out
