"""Файловый кеш ответов провайдера обогащения.

Мотивация чисто практическая: у публичного ключа VT 500 запросов в сутки.
Повторный прогон того же фида (а он бывает ежедневным) не должен сжигать
квоту заново. Кеш — простой JSON-файл с TTL: прозрачно, легко посмотреть
глазами, не требует внешних зависимостей вроде Redis.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger

logger = get_logger("enrichment.cache")


class ResponseCache:
    """Кеш ``ключ -> (время записи, полезная нагрузка)`` с TTL."""

    def __init__(self, path: str | Path, ttl: int = 86_400, enabled: bool = True) -> None:
        self.path = Path(path)
        self.ttl = ttl
        self.enabled = enabled
        self._data: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self.hits = 0
        self.misses = 0
        if self.enabled:
            self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._data = raw
                logger.debug("Кеш загружен: %d записей из %s", len(raw), self.path)
        except (json.JSONDecodeError, OSError) as exc:
            # Битый кеш — не повод падать: просто начинаем с пустого.
            logger.warning("Не удалось прочитать кеш %s (%s), начинаю с пустого",
                           self.path, exc)
            self._data = {}

    def get(self, key: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        entry = self._data.get(key)
        if entry is None:
            self.misses += 1
            return None
        age = time.time() - entry.get("cached_at", 0)
        if age > self.ttl:
            logger.debug("Запись кеша устарела (%.0f с > TTL %d): %s", age, self.ttl, key)
            self._data.pop(key, None)
            self._dirty = True
            self.misses += 1
            return None
        self.hits += 1
        logger.debug("Кеш HIT: %s", key)
        return entry.get("payload")

    def set(self, key: str, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        self._data[key] = {"cached_at": time.time(), "payload": payload}
        self._dirty = True

    def save(self) -> None:
        """Записать кеш на диск атомарно (через временный файл + rename)."""
        if not self.enabled or not self._dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._data, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)  # атомарно: не оставим полуфайл при падении
            self._dirty = False
            logger.debug("Кеш сохранён: %d записей в %s", len(self._data), self.path)
        except OSError as exc:
            logger.warning("Не удалось сохранить кеш %s: %s", self.path, exc)

    @property
    def stats(self) -> dict[str, int]:
        return {"hits": self.hits, "misses": self.misses, "entries": len(self._data)}
