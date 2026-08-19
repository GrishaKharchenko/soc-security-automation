"""Оркестратор: чтение логов -> детекты -> корреляция.

Вынесен из CLI по той же причине, что и в IOC Analyzer: конвейер должен
вызываться из планировщика, SOAR или веб-сервиса без переписывания.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .config import Settings
from .detection.engine import DetectionEngine, correlate
from .logging_setup import get_logger
from .models import AuthEvent, Detection, Incident, Severity
from .parsers.base import ParseStats
from .parsers.registry import load_events

logger = get_logger("analyzer")


@dataclass
class AnalysisRun:
    events: list[AuthEvent] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    parse_stats: ParseStats | None = None
    sources: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def metadata(self) -> dict[str, Any]:
        first = self.events[0].timestamp.isoformat() if self.events else None
        last = self.events[-1].timestamp.isoformat() if self.events else None
        return {
            "sources": self.sources,
            "duration_seconds": round(self.duration_seconds, 2),
            "events_analyzed": len(self.events),
            "time_range": {"first_event": first, "last_event": last},
            "parsing": self.parse_stats.to_dict() if self.parse_stats else {},
        }


class LogAnalyzer:
    """Конвейер анализа логов аутентификации."""

    def __init__(self, settings: Settings,
                 enabled_rules: Sequence[str] | None = None) -> None:
        self.settings = settings
        self.engine = DetectionEngine(settings, enabled_rules)

    def analyze(self, paths: Sequence[str | Path],
                parser_name: str = "auto") -> AnalysisRun:
        started = time.monotonic()

        events, parse_stats = load_events(paths, self.settings, parser_name)
        logger.info("Загружено событий: %d", len(events))

        detections = self.engine.run(events)
        incidents = correlate(detections)

        run = AnalysisRun(
            events=events,
            detections=detections,
            incidents=incidents,
            parse_stats=parse_stats,
            sources=[str(p) for p in paths],
            duration_seconds=time.monotonic() - started,
        )
        logger.info("Анализ завершён за %.2f с: %d находок, %d инцидентов",
                    run.duration_seconds, len(detections), len(incidents))
        return run

    @staticmethod
    def exit_code(detections: Sequence[Detection]) -> int:
        """Код возврата для планировщика: 0 — чисто, 1 — есть находки,
        2 — есть критические."""
        severities = {d.severity for d in detections}
        if Severity.CRITICAL in severities:
            return 2
        if severities:
            return 1
        return 0
