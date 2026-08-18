"""Настройка логирования.

Два независимых канала:
* консоль — короткий человекочитаемый формат для аналитика;
* файл с ротацией — подробный формат с модулем и строкой для разбора инцидентов.

Плюс фильтр-редактор, который вырезает API-ключ из любых сообщений: логи
попадают в тикеты и чаты, утечка ключа оттуда — реальный инцидент.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_CONSOLE_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
_FILE_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class SecretRedactingFilter(logging.Filter):
    """Заменяет секреты на ``***REDACTED***`` в сообщении и аргументах записи."""

    def __init__(self, secrets: list[str]) -> None:
        super().__init__()
        # Совсем короткие значения не маскируем: риск испортить весь текст.
        self._secrets = [s for s in secrets if s and len(s) >= 8]

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._secrets:
            return True
        if isinstance(record.msg, str):
            for secret in self._secrets:
                record.msg = record.msg.replace(secret, "***REDACTED***")
        if record.args:
            record.args = tuple(self._redact(arg) for arg in _as_tuple(record.args))
        return True

    def _redact(self, value: object) -> object:
        if isinstance(value, str):
            for secret in self._secrets:
                value = value.replace(secret, "***REDACTED***")
        return value


def _as_tuple(args: object) -> tuple:
    return args if isinstance(args, tuple) else (args,)


def setup_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    max_bytes: int = 1_048_576,
    backup_count: int = 3,
    secrets: list[str] | None = None,
    quiet: bool = False,
) -> logging.Logger:
    """Сконфигурировать корневой логгер приложения и вернуть его.

    Функция идемпотентна: повторный вызов (например, в тестах) не плодит
    дублирующиеся обработчики.
    """
    logger = logging.getLogger("ioc_analyzer")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    redactor = SecretRedactingFilter(secrets or [])

    if not quiet:
        console = logging.StreamHandler()
        console.setLevel(logger.level)
        console.setFormatter(logging.Formatter(_CONSOLE_FORMAT, _DATE_FORMAT))
        console.addFilter(redactor)
        logger.addHandler(console)

    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        # В файл всегда пишем DEBUG: разбор инцидента задним числом важнее места.
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(_FILE_FORMAT, _DATE_FORMAT))
        file_handler.addFilter(redactor)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Дочерний логгер модуля: ``ioc_analyzer.enrichment.virustotal``."""
    return logging.getLogger(f"ioc_analyzer.{name}")
