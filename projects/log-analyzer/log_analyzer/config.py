"""Конфигурация SOC Log Analyzer.

Все пороги детектирования вынесены сюда и читаются из ``.env``. Это не
формальность: «сколько неудачных входов считать атакой» — вопрос не к
разработчику, а к команде, которая эксплуатирует систему. На рабочей станции
разработчика 5 неудач подряд — обычное дело, на сервере в DMZ — инцидент.
Правило, в котором порог зашит константой, придётся править и пересобирать
при каждом изменении политики.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dotenv import load_dotenv


class ConfigError(RuntimeError):
    """Некорректная конфигурация."""


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} должен быть целым числом, получено: {raw!r}") from exc


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


@dataclass(frozen=True)
class Settings:
    """Пороги детектирования и параметры запуска."""

    # Разбор
    timezone: str = "UTC"
    default_year: int | None = None

    # T1110.001 — brute force
    bruteforce_threshold: int = 5
    bruteforce_window: int = 300

    # T1110.003 — password spraying
    spraying_min_users: int = 5
    spraying_max_attempts_per_user: int = 3
    spraying_window: int = 1800

    # T1078 — успешный вход после серии неудач
    success_after_failures_min: int = 3
    success_after_failures_window: int = 600

    # T1087 — перебор имён учётных записей
    enumeration_min_invalid_users: int = 5
    enumeration_window: int = 600

    # Распределённая атака на одну учётную запись
    distributed_min_sources: int = 3
    distributed_window: int = 1800

    # Аномалии по времени
    business_hours_start: int = 8
    business_hours_end: int = 20
    flag_weekend_logins: bool = True

    # T1548.003 — sudo
    sudo_failure_threshold: int = 3
    sudo_failure_window: int = 600

    # Вывод
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    log_level: str = "INFO"
    log_file: Path = field(default_factory=lambda: Path("logs/log_analyzer.log"))
    log_max_bytes: int = 1_048_576
    log_backup_count: int = 3

    @property
    def tzinfo(self) -> ZoneInfo:
        try:
            return ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ConfigError(f"Неизвестный часовой пояс: {self.timezone!r}") from exc

    def validate(self) -> None:
        positive = {
            "BRUTEFORCE_THRESHOLD": self.bruteforce_threshold,
            "BRUTEFORCE_WINDOW": self.bruteforce_window,
            "SPRAYING_MIN_USERS": self.spraying_min_users,
            "SPRAYING_WINDOW": self.spraying_window,
            "SUCCESS_AFTER_FAILURES_MIN": self.success_after_failures_min,
            "ENUMERATION_MIN_INVALID_USERS": self.enumeration_min_invalid_users,
            "DISTRIBUTED_MIN_SOURCES": self.distributed_min_sources,
            "SUDO_FAILURE_THRESHOLD": self.sudo_failure_threshold,
        }
        for name, value in positive.items():
            if value < 1:
                raise ConfigError(f"{name} должен быть >= 1, получено {value}")

        if not 0 <= self.business_hours_start <= 23:
            raise ConfigError("BUSINESS_HOURS_START должен быть в диапазоне 0..23")
        if not 0 <= self.business_hours_end <= 23:
            raise ConfigError("BUSINESS_HOURS_END должен быть в диапазоне 0..23")
        if self.business_hours_start >= self.business_hours_end:
            raise ConfigError("BUSINESS_HOURS_START должен быть меньше BUSINESS_HOURS_END")
        if self.log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigError(f"Неизвестный LOG_LEVEL: {self.log_level}")
        self.tzinfo  # проверяем, что пояс существует


def load_settings(env_file: str | os.PathLike[str] | None = None) -> Settings:
    """Прочитать .env и собрать настройки."""
    if env_file is not None:
        load_dotenv(env_file, override=False)
    else:
        load_dotenv(override=False)

    year_raw = _get_str("LOG_DEFAULT_YEAR")
    settings = Settings(
        timezone=_get_str("LOG_TIMEZONE", "UTC") or "UTC",
        default_year=int(year_raw) if year_raw.isdigit() else None,
        bruteforce_threshold=_get_int("BRUTEFORCE_THRESHOLD", 5),
        bruteforce_window=_get_int("BRUTEFORCE_WINDOW", 300),
        spraying_min_users=_get_int("SPRAYING_MIN_USERS", 5),
        spraying_max_attempts_per_user=_get_int("SPRAYING_MAX_ATTEMPTS_PER_USER", 3),
        spraying_window=_get_int("SPRAYING_WINDOW", 1800),
        success_after_failures_min=_get_int("SUCCESS_AFTER_FAILURES_MIN", 3),
        success_after_failures_window=_get_int("SUCCESS_AFTER_FAILURES_WINDOW", 600),
        enumeration_min_invalid_users=_get_int("ENUMERATION_MIN_INVALID_USERS", 5),
        enumeration_window=_get_int("ENUMERATION_WINDOW", 600),
        distributed_min_sources=_get_int("DISTRIBUTED_MIN_SOURCES", 3),
        distributed_window=_get_int("DISTRIBUTED_WINDOW", 1800),
        business_hours_start=_get_int("BUSINESS_HOURS_START", 8),
        business_hours_end=_get_int("BUSINESS_HOURS_END", 20),
        flag_weekend_logins=_get_bool("FLAG_WEEKEND_LOGINS", True),
        sudo_failure_threshold=_get_int("SUDO_FAILURE_THRESHOLD", 3),
        sudo_failure_window=_get_int("SUDO_FAILURE_WINDOW", 600),
        output_dir=Path(_get_str("OUTPUT_DIR", "reports")),
        log_level=_get_str("LOG_LEVEL", "INFO").upper() or "INFO",
        log_file=Path(_get_str("LOG_FILE", "logs/log_analyzer.log")),
        log_max_bytes=_get_int("LOG_MAX_BYTES", 1_048_576),
        log_backup_count=_get_int("LOG_BACKUP_COUNT", 3),
    )
    settings.validate()
    return settings
