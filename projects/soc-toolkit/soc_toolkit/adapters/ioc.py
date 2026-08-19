"""Адаптер IOC Analyzer.

Главная работа адаптера — **перевод вердикта в единую шкалу критичности**.
IOC Analyzer оперирует вердиктом (``malicious`` … ``skipped``) и risk score
0–100, оболочка — пятиуровневой severity. Соответствие задано явной таблицей,
а не формулой: смысл вердикта важнее арифметики.

Отдельно стоит отметить, чего адаптер **не** делает: он не выдумывает техники
MITRE ATT&CK для индикаторов. Вредоносный хеш сам по себе не соответствует
никакой технике — техника описывает поведение, а не артефакт. Приписать
такому индикатору, скажем, T1071 было бы догадкой, выдаваемой за факт.
Техники в отчёт приходят из Log Analyzer, где они выведены из наблюдаемого
поведения.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..bootstrap import ModuleNotAvailable, require
from ..logging_setup import get_logger
from ..models import Confidence, Finding, Severity, Source
from .base import AdapterError, ToolAdapter

logger = get_logger("adapters.ioc")

# Вердикт IOC Analyzer -> критичность набора.
#
# «Ошибка проверки» намеренно попадает в LOW, а не отбрасывается: индикатор,
# который не удалось проверить, должен остаться на виду у аналитика.
# «Неизвестен VirusTotal» — тоже LOW: для свежесозданной инфраструктуры это
# ожидаемо и само по себе слегка подозрительно.
VERDICT_TO_SEVERITY: dict[str, Severity] = {
    "malicious": Severity.HIGH,
    "suspicious": Severity.MEDIUM,
    "unknown": Severity.LOW,
    "error": Severity.LOW,
    "clean": Severity.INFO,
    "skipped": Severity.INFO,
}

VERDICT_TO_CONFIDENCE: dict[str, Confidence] = {
    "malicious": Confidence.HIGH,
    "suspicious": Confidence.MEDIUM,
    "unknown": Confidence.LOW,
    "error": Confidence.LOW,
    "clean": Confidence.HIGH,
    "skipped": Confidence.LOW,
}

# Тип индикатора -> имя сущности в общей модели. Нужно, чтобы находки разных
# инструментов связывались по одинаково названным полям.
TYPE_TO_ENTITY: dict[str, str] = {
    "ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url",
    "md5": "hash", "sha1": "hash", "sha256": "hash",
}


class IOCAdapter(ToolAdapter):
    """Запуск IOC Analyzer и перевод его результатов в общий формат."""

    name = "ioc"
    description = "Анализ индикаторов компрометации через VirusTotal"

    @staticmethod
    def is_available() -> bool:
        try:
            require("ioc_analyzer")
            return True
        except ModuleNotAvailable:
            return False

    def run(
        self,
        input_file: str | Path,
        offline: bool = False,
        limit: int | None = None,
        only_types: Sequence[str] | None = None,
        env_file: str | None = None,
        include_clean: bool = False,
        **_: Any,
    ) -> list[Finding]:
        require("ioc_analyzer")

        from ioc_analyzer.analyzer import IOCAnalyzer            # noqa: E402
        from ioc_analyzer.config import ConfigError, load_settings  # noqa: E402
        from ioc_analyzer.models import IOCType                  # noqa: E402

        try:
            settings = load_settings(env_file)
        except ConfigError as exc:
            raise AdapterError(f"Конфигурация IOC Analyzer: {exc}") from exc

        provider = None
        if not offline:
            try:
                from ioc_analyzer.enrichment.virustotal import VirusTotalClient
                provider = VirusTotalClient(settings)
            except ConfigError as exc:
                raise AdapterError(
                    f"{exc} Для работы без ключа используйте --offline."
                ) from exc

        types = [IOCType(value) for value in only_types] if only_types else None

        from ioc_analyzer.parsers.reader import InputError          # noqa: E402

        try:
            run = IOCAnalyzer(settings, provider=provider).analyze_file(
                input_file, limit=limit, only_types=types
            )
        except InputError as exc:
            # Исключения модуля переводятся в AdapterError — иначе они
            # прорастают сквозь оболочку и роняют весь прогон, в том числе
            # результаты других модулей, которые уже успели отработать.
            raise AdapterError(f"Входные данные IOC Analyzer: {exc}") from exc
        finally:
            if provider is not None:
                provider.close()

        findings = [
            self._to_finding(result, str(input_file))
            for result in run.results
            if include_clean or result.verdict.value not in {"clean", "skipped"}
        ]
        logger.info("IOC Analyzer: %d индикаторов, %d находок в отчёт",
                    len(run.results), len(findings))
        return findings

    @staticmethod
    def _to_finding(result: Any, source_file: str) -> Finding:
        ioc = result.ioc
        verdict = result.verdict.value
        enrichment = result.enrichment

        entity_key = TYPE_TO_ENTITY.get(ioc.type.value, "indicator")
        severity = VERDICT_TO_SEVERITY.get(verdict, Severity.INFO)

        # Risk score уточняет позицию внутри вердикта: 60/70 детектов
        # серьёзнее, чем 4/70, хотя вердикт у обоих malicious.
        if verdict == "malicious" and result.risk_score >= 85:
            severity = Severity.CRITICAL

        evidence = ""
        if enrichment:
            evidence = (f"детекты {enrichment.detection_ratio}, "
                        f"репутация {enrichment.reputation}")
            if enrichment.detection_names:
                evidence += f", имена: {', '.join(enrichment.detection_names[:3])}"

        return Finding(
            source=Source.IOC,
            rule_id=f"IOC-{verdict.upper()}",
            title=f"Индикатор {ioc.value} — вердикт «{verdict}»",
            description=" ".join(result.reasons) or "Причины не зафиксированы.",
            severity=severity,
            confidence=VERDICT_TO_CONFIDENCE.get(verdict, Confidence.LOW),
            entities={entity_key: ioc.value, "ioc_type": ioc.type.value},
            evidence=evidence,
            recommendation=_recommendation(verdict),
            first_seen=result.analyzed_at,
            last_seen=result.analyzed_at,
            raw_reference=f"{source_file}:{ioc.value}",
        )


def _recommendation(verdict: str) -> str:
    return {
        "malicious": ("Заблокировать индикатор на периметре (firewall, прокси, "
                      "DNS), найти обращения к нему в логах, проверить хосты, "
                      "которые с ним взаимодействовали."),
        "suspicious": ("Проверить вручную: детектов мало, возможен false "
                       "positive. Сопоставить с контекстом появления индикатора."),
        "unknown": ("Индикатор неизвестен VirusTotal. Для свежесозданной "
                    "инфраструктуры это ожидаемо и слегка подозрительно — "
                    "проверить возраст домена и репутацию сети."),
        "error": ("Проверку выполнить не удалось. Повторить запрос или "
                  "проверить индикатор вручную."),
    }.get(verdict, "Действий не требуется.")
