from __future__ import annotations

from pathlib import Path

import pytest

from apiguard.core.config import Config


def test_load_config_success(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                'target: "http://localhost:8000/"',
                "auth:",
                '  token: "abc"',
                "checks:",
                "  auth:",
                "    enabled: false",
            ]
        )
    )

    cfg = Config.load(str(config_file))

    assert cfg.target == "http://localhost:8000"
    assert cfg.auth["token"] == "abc"
    assert cfg.check_enabled("auth") is False
    assert cfg.check_enabled("injection") is True


def test_load_config_requires_target(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("auth: {}\n")

    with pytest.raises(ValueError):
        Config.load(str(config_file))
