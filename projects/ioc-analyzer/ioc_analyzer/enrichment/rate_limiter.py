"""Ограничитель частоты запросов (token bucket со скользящим окном).

Публичный ключ VirusTotal — 4 запроса в минуту. Превысил — получил 429 и,
при систематическом нарушении, бан ключа. Поэтому лимит соблюдается
**проактивно** (ждём сами), а не реактивно (ловим 429 и ретраим).

Реализация — скользящее окно на ``collections.deque``: храним метки времени
последних N запросов и, если окно заполнено, спим ровно до момента, когда
самый старый запрос выпадет из окна. Это точнее, чем ``sleep(60/rpm)`` после
каждого запроса: не тормозит, когда запросов мало, и не даёт всплесков.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from ..logging_setup import get_logger

logger = get_logger("enrichment.rate_limiter")


class RateLimiter:
    """Не более ``max_calls`` вызовов за ``period`` секунд."""

    def __init__(self, max_calls: int, period: float = 60.0) -> None:
        if max_calls < 1:
            raise ValueError("max_calls должен быть >= 1")
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()  # безопасно, если появится многопоточность
        self.total_waited = 0.0

    def acquire(self) -> float:
        """Занять слот, при необходимости подождав. Вернуть время ожидания."""
        with self._lock:
            now = time.monotonic()
            self._evict(now)

            if len(self._calls) < self.max_calls:
                self._calls.append(now)
                return 0.0

            # Окно заполнено: ждём, пока самый старый вызов покинет период.
            sleep_for = self._calls[0] + self.period - now
            if sleep_for > 0:
                logger.info("Rate limit %d/%.0fс достигнут — пауза %.1f с",
                            self.max_calls, self.period, sleep_for)
                time.sleep(sleep_for)
                self.total_waited += sleep_for

            now = time.monotonic()
            self._evict(now)
            self._calls.append(now)
            return max(sleep_for, 0.0)

    def _evict(self, now: float) -> None:
        """Выбросить из окна вызовы старше ``period``."""
        while self._calls and now - self._calls[0] >= self.period:
            self._calls.popleft()

    def __enter__(self) -> "RateLimiter":
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None
