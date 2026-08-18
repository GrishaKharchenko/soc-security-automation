"""Контракт провайдера обогащения.

Абстракция нужна не «для красоты»: VirusTotal — не единственный источник.
Завтра появятся AbuseIPDB, AlienVault OTX, внутренний MISP. Всё, что от них
требуется, — реализовать :meth:`EnrichmentProvider.enrich` и вернуть
:class:`~ioc_analyzer.models.EnrichmentResult`. Скоринг и отчёты при этом
не меняются вообще: они зависят от нашей внутренней модели, а не от формата
конкретного вендора (принцип инверсии зависимостей).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import IOC, EnrichmentResult, EnrichmentStatus


class EnrichmentProvider(ABC):
    """Базовый класс источника данных об индикаторе."""

    name: str = "base"

    @abstractmethod
    def enrich(self, ioc: IOC) -> EnrichmentResult:
        """Вернуть данные об индикаторе. Не должен выбрасывать исключения:
        любая ошибка становится ``EnrichmentResult`` со статусом ошибки —
        один сбойный индикатор не имеет права уронить весь прогон."""

    def unsupported(self, reason: str = "тип IOC не поддерживается провайдером") -> EnrichmentResult:
        return EnrichmentResult(
            provider=self.name, status=EnrichmentStatus.UNSUPPORTED, error=reason
        )

    def close(self) -> None:
        """Освободить ресурсы (HTTP-сессию, кеш). По умолчанию — ничего."""
