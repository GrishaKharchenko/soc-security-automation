"""Контракт адаптера инструмента.

Адаптер — единственное место, где живёт знание о том, как устроен конкретный
инструмент. Он запускает его и переводит результат в общую модель
:class:`~soc_toolkit.models.Finding`.

Благодаря этому оболочка не зависит ни от одного инструмента напрямую:
добавить четвёртый (например, анализатор фишинговых писем) означает написать
один адаптер, не трогая ни CLI, ни отчёты, ни корреляцию.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Sequence

from ..models import Finding


class AdapterError(RuntimeError):
    """Инструмент не удалось запустить или его результат не разобрать."""


class ToolAdapter(ABC):
    """Базовый адаптер."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def run(self, **kwargs: Any) -> Sequence[Finding]:
        """Запустить инструмент и вернуть находки в общем формате."""

    @staticmethod
    def is_available() -> bool:
        """Доступен ли инструмент в текущем окружении."""
        return True
