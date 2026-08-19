"""Конфигурация оболочки.

Отдельные модули читают свои собственные ``.env`` — здесь только то, что
относится к самой оболочке: куда писать сводные отчёты и как логировать.
Это осознанное решение: заставлять модули читать чужой конфиг означало бы
сломать их автономность, а она нужна, чтобы каждый инструмент оставался
пригодным к самостоятельному использованию.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(RuntimeError):
    """Некорректная конфигурация оболочки."""


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} должен быть целым числом: {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    log_level: str = "INFO"
    log_file: Path = field(default_factory=lambda: Path("logs/soc_toolkit.log"))
    log_max_bytes: int = 1_048_576
    log_backup_count: int = 3
    escalate_cross_tool: bool = True

    def validate(self) -> None:
        if self.log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigError(f"Неизвестный LOG_LEVEL: {self.log_level}")


def load_settings(env_file: str | os.PathLike[str] | None = None) -> Settings:
    if env_file is not None:
        load_dotenv(env_file, override=False)
    else:
        load_dotenv(override=False)

    escalate = _get_str("ESCALATE_CROSS_TOOL", "true").lower()
    settings = Settings(
        output_dir=Path(_get_str("TOOLKIT_OUTPUT_DIR", "reports")),
        log_level=_get_str("LOG_LEVEL", "INFO").upper() or "INFO",
        log_file=Path(_get_str("TOOLKIT_LOG_FILE", "logs/soc_toolkit.log")),
        log_max_bytes=_get_int("LOG_MAX_BYTES", 1_048_576),
        log_backup_count=_get_int("LOG_BACKUP_COUNT", 3),
        escalate_cross_tool=escalate in {"1", "true", "yes", "on", "y"},
    )
    settings.validate()
    return settings
