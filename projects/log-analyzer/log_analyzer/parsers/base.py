"""Контракт парсера логов.

Каждый формат логов знает только о себе и обязан отдать наружу поток
:class:`~log_analyzer.models.AuthEvent`. Ни одно правило детектирования не
содержит регулярных выражений под конкретный формат — вся специфика заперта
здесь. Добавить Cisco ASA, VPN или Okta = написать ещё один класс, не трогая
ни детекты, ни отчёты.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ..models import AuthEvent


class ParseError(RuntimeError):
    """Файл нельзя разобрать: не существует, пустой, неизвестный формат."""


@dataclass
class ParseStats:
    """Статистика разбора — попадает в отчёт и в лог.

    Число нераспознанных строк — важная метрика качества: если парсер понимает
    5% файла, детекты будут построены на 5% данных, и молчание системы будет
    означать не «атак нет», а «мы ничего не увидели».
    """

    total_lines: int = 0
    parsed: int = 0
    skipped_irrelevant: int = 0     # строки не про аутентификацию
    unparsed: int = 0               # похоже на событие, но разобрать не вышло
    unparsed_samples: list[str] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        """Доля разобранных строк среди значимых."""
        meaningful = self.parsed + self.unparsed
        return round(self.parsed / meaningful * 100, 1) if meaningful else 100.0

    def note_unparsed(self, line: str) -> None:
        self.unparsed += 1
        if len(self.unparsed_samples) < 10:
            self.unparsed_samples.append(line.strip()[:200])

    def to_dict(self) -> dict[str, object]:
        return {
            "total_lines": self.total_lines,
            "parsed_events": self.parsed,
            "skipped_irrelevant": self.skipped_irrelevant,
            "unparsed": self.unparsed,
            "coverage_percent": self.coverage,
            "unparsed_samples": self.unparsed_samples,
        }


class LogParser(ABC):
    """Базовый класс парсера."""

    name: str = "base"
    description: str = ""

    def __init__(self) -> None:
        self.stats = ParseStats()

    @classmethod
    @abstractmethod
    def sniff(cls, sample: str, path: Path) -> bool:
        """Похож ли файл на этот формат? Используется автоопределением."""

    @abstractmethod
    def parse(self, path: Path) -> Iterator[AuthEvent]:
        """Разобрать файл и выдать поток нормализованных событий."""


_ENCODINGS = ("utf-8-sig", "utf-8", "cp1251", "latin-1")


def read_text(path: Path) -> str:
    """Прочитать файл, подобрав кодировку.

    Логи приезжают откуда угодно: выгрузка из Windows в UTF-16, старый сервер
    в cp1251, экспорт из Excel с BOM. Падать на этом нельзя.
    """
    if not path.exists():
        raise ParseError(f"Файл не найден: {path}")
    if not path.is_file():
        raise ParseError(f"Это не файл: {path}")

    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")

    last_error: Exception | None = None
    for encoding in _ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError as exc:
            last_error = exc
    raise ParseError(f"Не удалось определить кодировку файла {path}: {last_error}")
