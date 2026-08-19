"""Автоопределение формата лога и запуск подходящего парсера.

Аналитик не обязан помнить, какой ключ соответствует какому формату: он
указывает файл, а инструмент разбирается сам. Определение идёт по первым
килобайтам содержимого, а не по расширению — файл вполне может называться
``export.txt`` и быть выгрузкой Windows в CSV.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Sequence

from ..config import Settings
from ..logging_setup import get_logger
from ..models import AuthEvent
from .base import LogParser, ParseError, ParseStats, read_text
from .linux_auth import LinuxAuthParser
from .windows_evtx_export import WindowsEventLogParser

logger = get_logger("parsers.registry")

PARSER_NAMES = ("auto", "linux", "windows")


def build_parser(name: str, settings: Settings) -> LogParser:
    if name == "linux":
        return LinuxAuthParser(tz=settings.timezone, default_year=settings.default_year)
    if name == "windows":
        return WindowsEventLogParser(tz=settings.timezone)
    raise ParseError(f"Неизвестный парсер: {name}")


def detect_parser(path: Path, settings: Settings) -> LogParser:
    """Подобрать парсер по содержимому файла."""
    sample = read_text(path)[:8192]
    if not sample.strip():
        raise ParseError(f"Файл пуст: {path}")

    for parser_class, key in ((WindowsEventLogParser, "windows"),
                              (LinuxAuthParser, "linux")):
        if parser_class.sniff(sample, path):
            logger.info("Формат %s определён как: %s", path.name, parser_class.description)
            return build_parser(key, settings)

    raise ParseError(
        f"Не удалось определить формат файла {path}. Поддерживаются: "
        "Linux auth.log/secure и выгрузка Windows Security Log в CSV/JSON. "
        "Формат можно задать явно флагом --format."
    )


def load_events(
    paths: Sequence[str | Path],
    settings: Settings,
    parser_name: str = "auto",
) -> tuple[list[AuthEvent], ParseStats]:
    """Прочитать один или несколько файлов и вернуть события с общей статистикой.

    Несколько файлов — не прихоть: реальный разбор инцидента почти всегда идёт
    по нескольким источникам сразу (auth.log с веб-сервера плюс выгрузка с
    контроллера домена). События из разных файлов складываются в общий поток и
    сортируются по времени — только так корреляция увидит связь между ними.
    """
    events: list[AuthEvent] = []
    total = ParseStats()

    for raw_path in paths:
        path = Path(raw_path)
        parser = (detect_parser(path, settings) if parser_name == "auto"
                  else build_parser(parser_name, settings))

        before = len(events)
        events.extend(parser.parse(path))

        total.total_lines += parser.stats.total_lines
        total.parsed += parser.stats.parsed
        total.skipped_irrelevant += parser.stats.skipped_irrelevant
        total.unparsed += parser.stats.unparsed
        for sample in parser.stats.unparsed_samples:
            if len(total.unparsed_samples) < 10:
                total.unparsed_samples.append(sample)

        logger.info("%s: событий %d, строк %d, покрытие %.1f%%",
                    path.name, len(events) - before,
                    parser.stats.total_lines, parser.stats.coverage)

    # Единый хронологический порядок — обязательное условие для правил,
    # работающих со скользящим временным окном.
    events.sort(key=lambda e: e.timestamp)

    if total.unparsed:
        logger.warning("Не разобрано строк: %d (покрытие %.1f%%). Примеры: %s",
                       total.unparsed, total.coverage, total.unparsed_samples[:3])
    return events, total
