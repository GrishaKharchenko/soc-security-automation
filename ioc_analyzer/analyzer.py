"""Оркестратор конвейера анализа.

Связывает этапы: чтение -> нормализация/дедуп -> обогащение -> скоринг.
Вынесен в отдельный класс, а не размазан по CLI, по двум причинам:

* CLI остаётся тонким слоем разбора аргументов (его легко заменить на HTTP-API
  или на вызов из Airflow/SOAR — логика анализа не переписывается);
* конвейер можно протестировать целиком, не эмулируя argparse.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from .config import Settings
from .enrichment.base import EnrichmentProvider
from .logging_setup import get_logger
from .models import IOC, AnalysisResult, IOCType, Verdict
from .parsers.reader import ParseStats, read_iocs
from .scoring.verdict import calculate_verdict

logger = get_logger("analyzer")

ProgressCallback = Callable[[int, int, IOC], None]


@dataclass
class AnalysisRun:
    """Результат прогона: сами находки + метаданные для отчёта."""

    results: list[AnalysisResult] = field(default_factory=list)
    parse_stats: ParseStats | None = None
    source_file: str = ""
    duration_seconds: float = 0.0
    api_calls: int = 0
    cache_stats: dict[str, int] = field(default_factory=dict)
    enrichment_enabled: bool = True

    def metadata(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "duration_seconds": round(self.duration_seconds, 2),
            "enrichment_enabled": self.enrichment_enabled,
            "api_calls": self.api_calls,
            "cache": self.cache_stats,
            "parsing": self.parse_stats.to_dict() if self.parse_stats else {},
        }


class IOCAnalyzer:
    """Конвейер анализа индикаторов."""

    def __init__(self, settings: Settings, provider: EnrichmentProvider | None = None) -> None:
        self.settings = settings
        # provider=None — легитимный режим (--offline): читаем, нормализуем,
        # классифицируем, но в сеть не ходим. Полезно для проверки фида и демо.
        self.provider = provider

    def analyze_file(
        self,
        path: str | Path,
        limit: int | None = None,
        only_types: Sequence[IOCType] | None = None,
        dedupe: bool = True,
        progress: ProgressCallback | None = None,
    ) -> AnalysisRun:
        """Полный цикл: файл -> список ``AnalysisResult``."""
        started = time.monotonic()
        iocs, parse_stats = read_iocs(path, dedupe=dedupe)

        if only_types:
            wanted = set(only_types)
            before = len(iocs)
            iocs = [ioc for ioc in iocs if ioc.type in wanted]
            logger.info("Фильтр по типам %s: осталось %d из %d",
                        [t.value for t in wanted], len(iocs), before)

        if limit is not None and limit > 0 and len(iocs) > limit:
            logger.info("Ограничение --limit: беру первые %d из %d индикаторов",
                        limit, len(iocs))
            iocs = iocs[:limit]

        results = self.analyze_iocs(iocs, progress=progress)

        run = AnalysisRun(
            results=results,
            parse_stats=parse_stats,
            source_file=str(path),
            duration_seconds=time.monotonic() - started,
            enrichment_enabled=self.provider is not None,
        )
        run.api_calls = getattr(self.provider, "api_calls", 0) if self.provider else 0
        cache = getattr(self.provider, "cache", None)
        run.cache_stats = dict(cache.stats) if cache is not None else {}

        logger.info("Анализ завершён за %.1f с: %d индикаторов, %d запросов к API",
                    run.duration_seconds, len(results), run.api_calls)
        return run

    def analyze_iocs(
        self,
        iocs: list[IOC],
        progress: ProgressCallback | None = None,
    ) -> list[AnalysisResult]:
        """Обогатить и оценить список индикаторов.

        Ошибка на одном индикаторе не прерывает прогон: провайдер по контракту
        не выбрасывает исключений, но на случай чужой некорректной реализации
        стоит перехват — устойчивость важнее, чем «красивый» стектрейс.
        """
        total = len(iocs)
        results: list[AnalysisResult] = []

        for index, ioc in enumerate(iocs, start=1):
            if progress:
                progress(index, total, ioc)

            enrichment = None
            if self.provider is not None:
                try:
                    enrichment = self.provider.enrich(ioc)
                except Exception as exc:  # noqa: BLE001 — защита от чужого кода
                    logger.exception("Непредвиденная ошибка обогащения %s: %s",
                                     ioc.value, exc)
                    from .models import EnrichmentResult, EnrichmentStatus
                    enrichment = EnrichmentResult(
                        provider=getattr(self.provider, "name", "unknown"),
                        status=EnrichmentStatus.API_ERROR,
                        error=f"внутренняя ошибка провайдера: {exc}",
                    )

            results.append(calculate_verdict(ioc, enrichment, self.settings))

        return results

    @staticmethod
    def exit_code(results: list[AnalysisResult]) -> int:
        """Код возврата для CI/cron: 0 — чисто, 1 — есть находки, 2 — ошибки.

        Осмысленный exit code превращает инструмент в кирпичик пайплайна:
        ``ioc-analyzer ... || notify-soc``.
        """
        verdicts = {r.verdict for r in results}
        if verdicts & {Verdict.MALICIOUS, Verdict.SUSPICIOUS}:
            return 1
        if Verdict.ERROR in verdicts:
            return 2
        return 0
