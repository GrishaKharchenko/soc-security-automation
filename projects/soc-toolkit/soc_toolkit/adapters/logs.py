"""Адаптер SOC Log Analyzer.

Перевод здесь самый простой из трёх: шкала критичности набора взята именно из
Log Analyzer, поэтому severity переносится один в один. Основная работа —
извлечь **сущности** (адреса, учётные записи, хосты) в единообразные поля,
чтобы находки связывались с результатами других инструментов.

Например, Log Analyzer хранит адрес источника в ``entities["source_ip"]``,
а IOC Analyzer — в ``entities["ip"]``. Пока имена расходятся, корреляция
между инструментами невозможна; приведение к общему словарю и есть цена
объединения.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..bootstrap import ModuleNotAvailable, require
from ..logging_setup import get_logger
from ..models import Confidence, Finding, Severity, Source
from .base import AdapterError, ToolAdapter

logger = get_logger("adapters.logs")


class LogsAdapter(ToolAdapter):
    """Запуск Log Analyzer и перевод его находок в общий формат."""

    name = "logs"
    description = "Анализ логов аутентификации Linux и Windows"

    @staticmethod
    def is_available() -> bool:
        try:
            require("log_analyzer")
            return True
        except ModuleNotAvailable:
            return False

    def run(
        self,
        input_files: Sequence[str | Path],
        rules: Sequence[str] | None = None,
        parser: str = "auto",
        year: int | None = None,
        timezone: str | None = None,
        env_file: str | None = None,
        **_: Any,
    ) -> list[Finding]:
        require("log_analyzer")

        import dataclasses

        from log_analyzer.analyzer import LogAnalyzer               # noqa: E402
        from log_analyzer.config import ConfigError, load_settings  # noqa: E402
        from log_analyzer.parsers.base import ParseError            # noqa: E402

        try:
            settings = load_settings(env_file)
            overrides: dict[str, Any] = {}
            if year:
                overrides["default_year"] = year
            if timezone:
                overrides["timezone"] = timezone
            if overrides:
                settings = dataclasses.replace(settings, **overrides)
                settings.validate()
        except ConfigError as exc:
            raise AdapterError(f"Конфигурация Log Analyzer: {exc}") from exc

        try:
            run = LogAnalyzer(settings, enabled_rules=rules).analyze(
                list(input_files), parser_name=parser
            )
        except ParseError as exc:
            raise AdapterError(f"Разбор логов: {exc}") from exc

        findings = [self._to_finding(detection) for detection in run.detections]
        logger.info("Log Analyzer: %d событий, %d находок",
                    len(run.events), len(findings))
        return findings

    @staticmethod
    def _to_finding(detection: Any) -> Finding:
        source_entities = detection.entities
        entities: dict[str, Any] = {}

        # Приведение имён полей к общему словарю набора.
        if source_entities.get("source_ip"):
            entities["ip"] = source_entities["source_ip"]
        elif source_entities.get("source_ips"):
            entities["ip"] = list(source_entities["source_ips"])
        if source_entities.get("username"):
            entities["username"] = source_entities["username"]
        elif source_entities.get("usernames"):
            entities["username"] = list(source_entities["usernames"])
        if source_entities.get("hostname"):
            entities["hostname"] = source_entities["hostname"]
        if source_entities.get("compromised_accounts"):
            entities["compromised_accounts"] = source_entities["compromised_accounts"]

        return Finding(
            source=Source.LOGS,
            rule_id=detection.rule_id,
            title=detection.title,
            description=detection.description,
            severity=Severity.parse(detection.severity.value),
            confidence=Confidence(detection.confidence.value),
            entities=entities,
            mitre_techniques=[
                {"technique_id": technique.technique_id,
                 "name": technique.name,
                 "tactic": technique.tactic}
                for technique in detection.mitre
            ],
            evidence=(f"событий: {detection.event_count}, "
                      f"длительность: {detection.duration_seconds:.0f} с"),
            recommendation=detection.recommendation,
            first_seen=detection.first_seen.isoformat() if detection.first_seen else None,
            last_seen=detection.last_seen.isoformat() if detection.last_seen else None,
            raw_reference=f"log-analyzer:{detection.rule_id}",
        )
