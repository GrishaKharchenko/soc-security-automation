"""Чтение входных файлов с индикаторами (TXT и CSV).

Задача модуля — превратить файл произвольного качества в список
нормализованных :class:`IOC` и честную статистику разбора. Реальные фиды
грязные: BOM, комментарии, пустые строки, кавычки, точка с запятой вместо
запятой, кириллица в UTF-8 или cp1251. Всё это обрабатывается здесь, чтобы
остальной конвейер работал с чистыми данными.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from ..logging_setup import get_logger
from ..models import IOC
from ..ioc.normalizer import deduplicate, normalize

logger = get_logger("parsers.reader")

COMMENT_PREFIXES = ("#", "//", ";")

# Названия колонок, в которых обычно лежит сам индикатор.
IOC_COLUMN_CANDIDATES = (
    "ioc", "indicator", "value", "artifact", "observable",
    "ip", "ip_address", "domain", "hostname", "url", "hash",
    "md5", "sha1", "sha256", "индикатор", "значение",
)

_ENCODINGS = ("utf-8-sig", "utf-8", "cp1251", "latin-1")


class InputError(RuntimeError):
    """Файл нельзя прочитать: не существует, не тот формат, пустой."""


@dataclass
class ParseStats:
    """Статистика разбора — попадает в отчёт и в лог."""

    total_lines: int = 0
    parsed: int = 0
    skipped_empty: int = 0
    skipped_comments: int = 0
    invalid: int = 0
    duplicates: int = 0
    invalid_samples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "total_lines": self.total_lines,
            "parsed": self.parsed,
            "skipped_empty": self.skipped_empty,
            "skipped_comments": self.skipped_comments,
            "invalid": self.invalid,
            "duplicates_removed": self.duplicates,
            "invalid_samples": self.invalid_samples[:10],
        }


def _read_text(path: Path) -> str:
    """Прочитать файл, подобрав кодировку.

    ``utf-8-sig`` идёт первой: она снимает BOM, который Excel добавляет в
    экспортированные CSV и который иначе приклеивается к первому индикатору.
    """
    last_error: Exception | None = None
    for encoding in _ENCODINGS:
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError as exc:
            last_error = exc
            continue
    raise InputError(f"Не удалось определить кодировку файла {path}: {last_error}")


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_PREFIXES)


def _iter_txt_tokens(text: str) -> Iterator[tuple[int, str]]:
    """TXT: одна строка — один индикатор (запятые/точки с запятой тоже режем)."""
    for line_number, line in enumerate(text.splitlines(), start=1):
        yield line_number, line


def _pick_ioc_columns(header: list[str]) -> list[int]:
    """Выбрать колонки CSV, где лежат индикаторы.

    Стратегия: сначала ищем колонку с «говорящим» именем. Если заголовок
    нестандартный — берём все колонки и полагаемся на детектор типов; лучше
    просканировать лишнее, чем потерять индикатор.
    """
    normalized = [h.strip().lower().lstrip("﻿") for h in header]
    matched = [i for i, name in enumerate(normalized) if name in IOC_COLUMN_CANDIDATES]
    if matched:
        logger.debug("CSV: колонки с индикаторами %s", [header[i] for i in matched])
        return matched
    logger.debug("CSV: знакомых колонок нет, сканируем все %d", len(header))
    return list(range(len(header)))


def _looks_like_header(row: list[str]) -> bool:
    """Первая строка — заголовок, если ни одна ячейка не распознана как IOC."""
    return not any(normalize(cell) for cell in row if cell.strip())


def _iter_csv_tokens(text: str) -> Iterator[tuple[int, str]]:
    """CSV: разделитель определяем автоматически (``,`` ``;`` ``\\t`` ``|``)."""
    sample = "\n".join(text.splitlines()[:20])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ","
        logger.debug("CSV: разделитель не определён, используем запятую")

    rows = list(csv.reader(text.splitlines(), delimiter=delimiter))
    if not rows:
        return

    first, *rest = rows
    if _looks_like_header(first):
        columns = _pick_ioc_columns(first)
        data_rows = rest
        offset = 2
    else:
        columns = list(range(len(first)))
        data_rows = rows
        offset = 1

    for row_index, row in enumerate(data_rows, start=offset):
        for column_index in columns:
            if column_index < len(row):
                yield row_index, row[column_index]


def _split_inline(token: str) -> Iterable[str]:
    """Разбить строку вида ``1.1.1.1, 2.2.2.2`` на отдельные кандидаты."""
    if _is_comment(token):
        return []
    # Отсекаем inline-комментарий после индикатора. Только '#': '//' живёт
    # внутри URL, а ';' в середине строки — это разделитель индикаторов
    # ("1.1.1.1; 2.2.2.2"), комментарием он считается лишь в начале строки.
    token = token.split("#", 1)[0]
    parts = [p for chunk in token.split(",") for p in chunk.split(";")]
    return [p.strip() for p in parts if p.strip()]


def read_iocs(path: str | Path, dedupe: bool = True) -> tuple[list[IOC], ParseStats]:
    """Прочитать файл и вернуть ``(список IOC, статистика разбора)``.

    Формат выбирается по расширению; всё, что не ``.csv``/``.tsv``,
    обрабатывается как TXT — это безопасный дефолт для фидов без расширения.
    """
    path = Path(path)
    if not path.exists():
        raise InputError(f"Файл не найден: {path}")
    if not path.is_file():
        raise InputError(f"Это не файл: {path}")

    text = _read_text(path)
    if not text.strip():
        raise InputError(f"Файл пуст: {path}")

    is_csv = path.suffix.lower() in {".csv", ".tsv"}
    logger.info("Читаю %s (формат: %s, размер: %d байт)",
                path, "CSV" if is_csv else "TXT", path.stat().st_size)

    tokens = _iter_csv_tokens(text) if is_csv else _iter_txt_tokens(text)

    stats = ParseStats()
    iocs: list[IOC] = []
    seen_lines: set[int] = set()

    for line_number, token in tokens:
        seen_lines.add(line_number)
        if not token.strip():
            stats.skipped_empty += 1
            continue
        if _is_comment(token):
            stats.skipped_comments += 1
            continue

        for candidate in _split_inline(token):
            ioc = normalize(candidate, line_number)
            if ioc is None:
                stats.invalid += 1
                if len(stats.invalid_samples) < 10:
                    stats.invalid_samples.append(candidate[:120])
                continue
            iocs.append(ioc)
            stats.parsed += 1

    stats.total_lines = len(seen_lines)

    if dedupe:
        before = len(iocs)
        iocs = deduplicate(iocs)
        stats.duplicates = before - len(iocs)

    logger.info(
        "Разобрано: %d уникальных IOC (всего найдено %d, дубликатов %d, "
        "нераспознано %d, комментариев %d)",
        len(iocs), stats.parsed, stats.duplicates, stats.invalid, stats.skipped_comments,
    )
    if stats.invalid:
        logger.warning("Нераспознанные строки (первые %d): %s",
                       len(stats.invalid_samples), stats.invalid_samples)
    return iocs, stats
