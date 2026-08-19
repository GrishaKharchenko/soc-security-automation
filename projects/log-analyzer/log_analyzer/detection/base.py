"""Контракт правила детектирования.

Правило получает **отсортированный по времени** список нормализованных событий
и возвращает список срабатываний. Оно ничего не знает ни о форматах логов, ни
о том, как результат будет сохранён.

Это даёт три вещи: правило тестируется списком событий без файлов на диске;
новое правило добавляется одним классом; порядок правил не влияет на результат,
потому что они не изменяют общее состояние.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import timedelta
from typing import Callable, Iterable, Iterator, Sequence, TypeVar

from ..config import Settings
from ..models import AuthEvent, Detection

K = TypeVar("K")


class DetectionRule(ABC):
    """Базовый класс правила."""

    rule_id: str = "base"
    title: str = ""
    description: str = ""
    # Основные техники ATT&CK правила. Объявлены на уровне класса, чтобы
    # справка и документация строились из кода и не расходились с ним.
    primary_techniques: tuple[str, ...] = ()

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @abstractmethod
    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        """Проанализировать поток событий и вернуть срабатывания."""


# --------------------------------------------------------------- утилиты

def group_by(
    events: Iterable[AuthEvent], key: Callable[[AuthEvent], K | None]
) -> dict[K, list[AuthEvent]]:
    """Сгруппировать события по ключу, пропуская события без ключа."""
    grouped: dict[K, list[AuthEvent]] = defaultdict(list)
    for event in events:
        value = key(event)
        if value is not None:
            grouped[value].append(event)
    return dict(grouped)


def sliding_windows(
    events: Sequence[AuthEvent], window_seconds: int, min_size: int
) -> Iterator[list[AuthEvent]]:
    """Выдать максимальные «всплески» событий, укладывающиеся во временное окно.

    Это ядро всех пороговых детектов. Две ошибки, которых оно избегает:

    **Фиксированные отрезки.** Если считать события по календарным пятиминуткам,
    атака, попавшая на границу отрезков, разделится пополам и не превысит порог
    ни в одной из половин. Скользящее окно проверяет любой промежуток нужной
    длины, а не только выровненный по часам.

    **Дробление одной атаки на десятки срабатываний.** Наивное скользящее окно
    для 50 попыток подряд выдаст 45 почти одинаковых групп, и аналитик получит
    45 алертов вместо одного. Здесь найденный всплеск поглощается целиком:
    группа расширяется вперёд, пока разрыв между соседними событиями не
    превышает окно, после чего поиск продолжается уже за её границей.

    Сложность — O(n) по отсортированному списку.
    """
    if min_size <= 0 or not events:
        return

    window = timedelta(seconds=window_seconds)
    total = len(events)
    index = 0

    while index < total:
        # Правая граница окна, начинающегося в events[index].
        edge = index
        while edge + 1 < total and \
                events[edge + 1].timestamp - events[index].timestamp <= window:
            edge += 1

        if edge - index + 1 >= min_size:
            # Порог превышен — поглощаем весь непрерывный всплеск.
            last = edge
            while last + 1 < total and \
                    events[last + 1].timestamp - events[last].timestamp <= window:
                last += 1
            yield list(events[index:last + 1])
            index = last + 1
        else:
            index += 1


def time_bounds(events: Sequence[AuthEvent]) -> tuple[object, object]:
    return (events[0].timestamp, events[-1].timestamp) if events else (None, None)
