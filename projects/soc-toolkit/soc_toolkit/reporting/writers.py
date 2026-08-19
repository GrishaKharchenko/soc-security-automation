"""Единые отчёты набора: JSON, CSV и консольная сводка."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .. import __version__
from ..logging_setup import get_logger
from ..models import CSV_COLUMNS, CorrelatedGroup, Finding, Severity

logger = get_logger("reporting")


def build_summary(findings: Sequence[Finding],
                  groups: Sequence[CorrelatedGroup]) -> dict[str, Any]:
    by_severity = Counter(f.severity.value for f in findings)
    by_source = Counter(f.source.value for f in findings)
    techniques = Counter(
        technique["technique_id"]
        for f in findings for technique in f.mitre_techniques
        if technique.get("technique_id")
    )
    tactics = Counter(
        tactic.strip()
        for f in findings for technique in f.mitre_techniques
        for tactic in str(technique.get("tactic", "")).split(",")
        if tactic.strip()
    )
    cross_tool = [g for g in groups if g.is_cross_tool]

    return {
        "total_findings": len(findings),
        "by_severity": dict(by_severity),
        "by_source": dict(by_source),
        "mitre_techniques": dict(techniques.most_common()),
        "mitre_tactics": dict(tactics.most_common()),
        "correlated_groups": len(groups),
        "cross_tool_confirmations": len(cross_tool),
        "actionable": (by_severity.get("critical", 0)
                       + by_severity.get("high", 0)
                       + by_severity.get("medium", 0)),
        "top_correlations": [g.to_dict() for g in cross_tool[:5]],
    }


def sort_findings(findings: Sequence[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.score, f.source.value, f.title))


def _timestamped(directory: Path, stem: str, suffix: str,
                 timestamp: str | None) -> Path:
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return directory / f"{stem}_{ts}.{suffix}"


def write_json(findings: Sequence[Finding], groups: Sequence[CorrelatedGroup],
               output_dir: str | Path, metadata: dict[str, Any] | None = None,
               stem: str = "soc_report", timestamp: str | None = None) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _timestamped(output_dir, stem, "json", timestamp)

    findings = sort_findings(findings)
    document = {
        "report": {
            "tool": "soc-automation-toolkit",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **(metadata or {}),
        },
        "summary": build_summary(findings, groups),
        "correlations": [group.to_dict() for group in groups],
        "findings": [finding.to_dict() for finding in findings],
    }
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    logger.info("JSON-отчёт: %s (%d находок)", path, len(findings))
    return path


def write_csv(findings: Sequence[Finding], output_dir: str | Path,
              stem: str = "soc_report", timestamp: str | None = None) -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = _timestamped(output_dir, stem, "csv", timestamp)

    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS,
                                extrasaction="ignore")
        writer.writeheader()
        for finding in sort_findings(findings):
            writer.writerow(finding.to_flat_row())

    logger.info("CSV-отчёт: %s (%d строк)", path, len(findings))
    return path


_LABELS = {
    Severity.CRITICAL: "КРИТИЧЕСКИЕ",
    Severity.HIGH: "ВЫСОКИЕ",
    Severity.MEDIUM: "СРЕДНИЕ",
    Severity.LOW: "НИЗКИЕ",
    Severity.INFO: "ИНФОРМАЦИОННЫЕ",
}


def render_console_summary(findings: Sequence[Finding],
                           groups: Sequence[CorrelatedGroup],
                           limit: int = 20) -> str:
    summary = build_summary(findings, groups)
    width = 100
    lines = ["", "=" * width,
             f"  SOC AUTOMATION TOOLKIT — {len(findings)} находок",
             "=" * width]

    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                     Severity.LOW, Severity.INFO):
        count = summary["by_severity"].get(severity.value, 0)
        if count:
            lines.append(f"  {_LABELS[severity]:<16} {count:>4}")

    lines.append("-" * width)
    lines.append("  Источники: " + ", ".join(
        f"{name} ({count})" for name, count in summary["by_source"].items()))

    if summary["mitre_techniques"]:
        lines.append("  MITRE ATT&CK: " + ", ".join(
            f"{tid} ({count})" for tid, count in summary["mitre_techniques"].items()))

    cross_tool = [g for g in groups if g.is_cross_tool]
    if cross_tool:
        lines.append("-" * width)
        lines.append("  ПОДТВЕРЖДЕНО НЕСКОЛЬКИМИ ИНСТРУМЕНТАМИ "
                     "(наивысший приоритет разбора):")
        for group in cross_tool[:limit]:
            lines.append(f"  ▸ {group.key_type}={group.key}  "
                         f"[{group.severity.value.upper()}]  "
                         f"источники: {', '.join(group.sources)}")
            for finding in group.findings:
                lines.append(f"      └─ [{finding.source.value:<13}] "
                             f"{finding.title[:60]}")

    ranked = sort_findings(findings)
    important = [f for f in ranked
                 if f.severity in {Severity.CRITICAL, Severity.HIGH}]
    if important:
        lines.append("-" * width)
        lines.append("  НАИБОЛЕЕ КРИТИЧНЫЕ НАХОДКИ:")
        for finding in important[:limit]:
            lines.append(f"  [{finding.severity.value.upper():<8}] "
                         f"{finding.source.value:<13} {finding.rule_id:<18} "
                         f"{finding.title[:52]}")
        if len(important) > limit:
            lines.append(f"  … ещё {len(important) - limit}, полный список — в отчёте")

    lines.append("=" * width)
    return "\n".join(lines)
