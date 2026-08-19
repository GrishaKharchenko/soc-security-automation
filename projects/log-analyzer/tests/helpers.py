"""Конструкторы событий для тестов.

Вынесены из conftest.py: файл conftest не предназначен для прямого
импорта, pytest подгружает его сам только ради фикстур.
"""

from __future__ import annotations

from datetime import timedelta

from log_analyzer.models import AuthEvent, EventOutcome, Platform

from .conftest import BASE_TIME

def event(
    seconds: int = 0,
    outcome: EventOutcome | str = EventOutcome.FAILURE,
    username: str | None = "alice",
    source_ip: str | None = "192.0.2.10",
    event_type: str = "ssh_login",
    invalid_user: bool = False,
    service: str = "sshd",
    logon_type: str | None = None,
    hostname: str = "web01",
) -> AuthEvent:
    """Собрать событие со смещением ``seconds`` от базового времени."""
    if isinstance(outcome, str):
        outcome = EventOutcome(outcome)
    return AuthEvent(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        outcome=outcome,
        platform=Platform.LINUX,
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        invalid_user=invalid_user,
        service=service,
        logon_type=logon_type,
        hostname=hostname,
        raw="synthetic",
    )


def failures(count: int, step: int = 10, start: int = 0, **kwargs) -> list[AuthEvent]:
    """Серия неудачных попыток с шагом ``step`` секунд."""
    kwargs.setdefault("outcome", EventOutcome.FAILURE)
    return [event(seconds=start + index * step, **kwargs) for index in range(count)]
