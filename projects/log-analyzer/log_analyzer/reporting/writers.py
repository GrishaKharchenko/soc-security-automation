"""Сохранение результатов анализа в JSON и CSV.

Формат сознательно повторяет подход IOC Analyzer: блок метаданных прогона,
сводка, затем находки. Единообразие здесь не эстетика — оно позволит на этапе
объединения проектов свести оба формата к общей модели без переписывания
потребителей отчётов.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .. import __version__
from ..logging_setup import get_logger
from ..models import CSV_COLUMNS, Detection, Incident, Severity

logger = get_logger("reporting.writers")


def build_summary(detections: Sequence[Detection],
                  incidents: Sequence[Incident]) -> dict[str, Any]:
    by_severity = Counter(d.severity.value for d in detections)
    by_rule = Counter(d.rule_id for d in detections)
    techniques = Counter(
        technique.technique_id for d in detections for technique in d.mitre
    )
    tactics = Counter(
        tactic.strip()
        for d in detections for technique in d.mitre
        for tactic in technique.tactic.split(",")
    )

    return {
        "total_detections": len(detections),
        "total_incidents": len(incidents),
        "by_severity": dict(by_severity),
        "by_rule": dict(by_rule),
        "mitre_techniques": dict(techniques.most_common()),
        "mitre_tactics": dict(tactics.most_common()),
        "critical_and_high": by_severity.get("critical", 0) + by_severity.get("high", 0),
        "top_incidents": [i.to_dict() for i in incidents[:5]],
    }


def _timestamped(directory: Path, stem: str, suffix: str,
                 timestamp: str | None) -> Path:
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return directory / f"{stem}_{ts}.{suffix}"


def write_json(
    detections: Sequence[Detection],
    incidents: Sequence[Incident],
    output_dir: str | Path,
    metadata: dict[str, Any] | None = None,
    stem: str = "log_report",
    timestamp: str | None = None,
    evidence_limit: int = 10,
) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _timestamped(output_dir, stem, "json", timestamp)

    document = {
        "report": {
            "tool": "soc-log-analyzer",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **(metadata or {}),
        },
        "summary": build_summary(detections, incidents),
        "incidents": [i.to_dict() for i in incidents],
        "detections": [d.to_dict(evidence_limit=evidence_limit) for d in detections],
    }
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("JSON-отчёт сохранён: %s (%d находок, %d инцидентов)",
                path, len(detections), len(incidents))
    return path


def write_csv(
    detections: Sequence[Detection],
    incidents: Sequence[Incident],
    output_dir: str | Path,
    stem: str = "log_report",
    timestamp: str | None = None,
) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _timestamped(output_dir, stem, "csv", timestamp)

    # Обратная связь «находка -> инцидент», чтобы в плоской таблице сохранилась
    # информация о группировке.
    incident_of: dict[int, str] = {}
    for incident in incidents:
        for detection in incident.detections:
            incident_of[id(detection)] = incident.incident_id

    # utf-8-sig — иначе Excel покажет кириллицу кракозябрами.
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for detection in detections:
            entities = detection.entities
            writer.writerow({
                "severity": detection.severity.value,
                "severity_score": detection.severity.score,
                "confidence": detection.confidence.value,
                "rule_id": detection.rule_id,
                "title": detection.title,
                "mitre_techniques": ";".join(t.technique_id for t in detection.mitre),
                "source_ip": entities.get("source_ip")
                or ";".join(map(str, entities.get("source_ips", [])[:5])),
                "username": entities.get("username")
                or ";".join(map(str, entities.get("usernames", [])[:5])),
                "hostname": entities.get("hostname", ""),
                "event_count": detection.event_count,
                "first_seen": detection.first_seen.isoformat() if detection.first_seen else "",
                "last_seen": detection.last_seen.isoformat() if detection.last_seen else "",
                "duration_seconds": round(detection.duration_seconds, 1),
                "incident_id": incident_of.get(id(detection), ""),
                "recommendation": detection.recommendation,
                "description": detection.description,
            })

    logger.info("CSV-отчёт сохранён: %s (%d строк)", path, len(detections))
    return path


_SEVERITY_LABELS = {
    Severity.CRITICAL: "КРИТИЧЕСКИЕ",
    Severity.HIGH: "ВЫСОКИЕ",
    Severity.MEDIUM: "СРЕДНИЕ",
    Severity.LOW: "НИЗКИЕ",
    Severity.INFO: "ИНФОРМАЦИОННЫЕ",
}


def render_console_summary(
    detections: Sequence[Detection],
    incidents: Sequence[Incident],
    limit: int = 15,
) -> str:
    summary = build_summary(detections, incidents)
    width = 96
    lines = ["", "=" * width,
             f"  РЕЗУЛЬТАТЫ АНАЛИЗА: {len(detections)} находок, "
             f"{len(incidents)} инцидентов",
             "=" * width]

    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                     Severity.LOW, Severity.INFO):
        count = summary["by_severity"].get(severity.value, 0)
        if count:
            lines.append(f"  {_SEVERITY_LABELS[severity]:<16} {count:>4}")

    if summary["mitre_techniques"]:
        lines.append("-" * width)
        lines.append("  MITRE ATT&CK: " + ", ".join(
            f"{tid} ({count})" for tid, count in summary["mitre_techniques"].items()))

    if incidents:
        lines.append("-" * width)
        lines.append("  ИНЦИДЕНТЫ (связанные находки):")
        for incident in incidents[:limit]:
            lines.append(
                f"  [{incident.severity.value.upper():<8}] {incident.incident_id}  "
                f"{incident.title}"
            )
            for detection in incident.detections:
                techniques = ",".join(t.technique_id for t in detection.mitre)
                lines.append(
                    f"      └─ {detection.rule_id} {detection.title[:56]:<56} "
                    f"{techniques}"
                )

    lines.append("=" * width)
    return "\n".join(lines)
