"""Сохранение результатов анализа в JSON и CSV.

Два формата закрывают два разных сценария:

* **JSON** — полная вложенная структура с метаданными прогона. Это машинный
  формат: его забирает SOAR/SIEM, по нему строится автоматика, он же — архив
  доказательств для последующего разбора инцидента.
* **CSV** — плоская таблица, один IOC = одна строка. Это человеческий формат:
  открывается в Excel, вставляется в тикет, отправляется заказчику.

Оба писателя ничего не знают про VirusTotal — они работают с моделью
``AnalysisResult``, поэтому смена провайдера отчётов не касается.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..logging_setup import get_logger
from ..models import CSV_COLUMNS, AnalysisResult, Verdict

logger = get_logger("reporting.writers")


def build_summary(results: list[AnalysisResult]) -> dict[str, Any]:
    """Агрегаты по прогону: сводка, которую аналитик читает первой."""
    verdict_counts = Counter(r.verdict.value for r in results)
    type_counts = Counter(r.ioc.type.value for r in results)
    scores = [r.risk_score for r in results]
    high_risk = [
        {"value": r.ioc.value, "type": r.ioc.type.value,
         "verdict": r.verdict.value, "risk_score": r.risk_score}
        for r in sorted(results, key=lambda x: -x.risk_score)
        if r.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
    ][:10]

    return {
        "total_iocs": len(results),
        "by_verdict": dict(verdict_counts),
        "by_type": dict(type_counts),
        "max_risk_score": max(scores, default=0),
        "avg_risk_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
        "actionable": verdict_counts.get(Verdict.MALICIOUS.value, 0)
        + verdict_counts.get(Verdict.SUSPICIOUS.value, 0),
        "top_risky": high_risk,
    }


def sort_results(results: list[AnalysisResult]) -> list[AnalysisResult]:
    """Опасное — наверх. Внутри одного вердикта сортируем по risk score."""
    return sorted(results, key=lambda r: (-r.verdict.severity, -r.risk_score, r.ioc.value))


def _timestamped(directory: Path, stem: str, suffix: str, timestamp: str | None) -> Path:
    """Имя файла с меткой времени: отчёты не перетирают друг друга."""
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return directory / f"{stem}_{ts}.{suffix}"


def write_json(
    results: list[AnalysisResult],
    output_dir: str | Path,
    metadata: dict[str, Any] | None = None,
    stem: str = "ioc_report",
    timestamp: str | None = None,
) -> Path:
    """Записать полный отчёт в JSON."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _timestamped(output_dir, stem, "json", timestamp)

    results = sort_results(results)
    document = {
        "report": {
            "tool": "ioc-analyzer",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **(metadata or {}),
        },
        "summary": build_summary(results),
        "results": [r.to_dict() for r in results],
    }

    # ensure_ascii=False — кириллица в reasons должна остаться читаемой.
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("JSON-отчёт сохранён: %s (%d индикаторов)", path, len(results))
    return path


def write_csv(
    results: list[AnalysisResult],
    output_dir: str | Path,
    stem: str = "ioc_report",
    timestamp: str | None = None,
) -> Path:
    """Записать плоский отчёт в CSV."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _timestamped(output_dir, stem, "csv", timestamp)

    results = sort_results(results)
    # utf-8-sig: BOM заставляет Excel открыть файл в UTF-8, иначе кириллица
    # превращается в кракозябры — мелочь, которая ломает отчёт для заказчика.
    # newline="" — требование модуля csv, иначе в Windows появятся пустые строки.
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for result in results:
            writer.writerow(result.to_flat_row())

    logger.info("CSV-отчёт сохранён: %s (%d строк)", path, len(results))
    return path


def render_console_summary(results: list[AnalysisResult], limit: int = 20) -> str:
    """Краткая сводка в терминал — чтобы не открывать файлы ради результата."""
    summary = build_summary(results)
    lines = [
        "",
        "=" * 78,
        f"  ИТОГИ АНАЛИЗА: {summary['total_iocs']} уникальных индикаторов",
        "=" * 78,
    ]

    order = [Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.UNKNOWN,
             Verdict.ERROR, Verdict.SKIPPED, Verdict.CLEAN]
    labels = {
        Verdict.MALICIOUS: "ВРЕДОНОСНЫЕ",
        Verdict.SUSPICIOUS: "ПОДОЗРИТЕЛЬНЫЕ",
        Verdict.UNKNOWN: "НЕИЗВЕСТНЫЕ",
        Verdict.ERROR: "ОШИБКА ПРОВЕРКИ",
        Verdict.SKIPPED: "ПРОПУЩЕНЫ",
        Verdict.CLEAN: "ЧИСТЫЕ",
    }
    for verdict in order:
        count = summary["by_verdict"].get(verdict.value, 0)
        if count:
            lines.append(f"  {labels[verdict]:<18} {count:>4}")

    lines.append("-" * 78)
    lines.append(f"  Типы: " + ", ".join(f"{k}={v}" for k, v in summary["by_type"].items()))
    lines.append(f"  Максимальный risk score: {summary['max_risk_score']} | "
                 f"требуют внимания: {summary['actionable']}")

    actionable = [r for r in sort_results(results)
                  if r.verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.ERROR}]
    if actionable:
        lines.append("-" * 78)
        lines.append(f"  {'VERDICT':<11}{'SCORE':>6}  {'RATIO':>7}  IOC")
        for result in actionable[:limit]:
            ratio = result.enrichment.detection_ratio if result.enrichment else "-"
            value = result.ioc.value if len(result.ioc.value) <= 44 else result.ioc.value[:41] + "..."
            lines.append(f"  {result.verdict.value:<11}{result.risk_score:>6}  {ratio:>7}  {value}")
        if len(actionable) > limit:
            lines.append(f"  ... ещё {len(actionable) - limit}, полный список — в отчёте")

    lines.append("=" * 78)
    return "\n".join(lines)
