"""Общие фикстуры и удобный конструктор событий.

Правила тестируются списками :class:`AuthEvent`, а не файлами на диске.
Это следствие архитектуры: правило не знает о форматах логов, поэтому и
проверять его надо в отрыве от них — тест получается быстрым, читаемым и
не ломается при изменении регулярных выражений в парсере.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from log_analyzer.config import Settings
from log_analyzer.models import AuthEvent, EventOutcome, Platform

BASE_TIME = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def settings(tmp_path) -> Settings:
    """Пороги по умолчанию, вывод — во временный каталог."""
    return Settings(
        timezone="UTC",
        default_year=2026,
        bruteforce_threshold=5,
        bruteforce_window=300,
        spraying_min_users=5,
        spraying_max_attempts_per_user=3,
        spraying_window=1800,
        success_after_failures_min=3,
        success_after_failures_window=600,
        enumeration_min_invalid_users=5,
        enumeration_window=600,
        distributed_min_sources=3,
        distributed_window=1800,
        sudo_failure_threshold=3,
        sudo_failure_window=600,
        output_dir=tmp_path / "reports",
        log_file=tmp_path / "logs" / "test.log",
    )
