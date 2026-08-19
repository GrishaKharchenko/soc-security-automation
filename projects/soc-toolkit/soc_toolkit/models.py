"""Единый формат результата для всех инструментов набора.

Это центральная идея объединения. Три инструмента отвечают на разные вопросы
и выдают разные структуры:

* IOC Analyzer  — вердикт по индикатору (``malicious`` … ``skipped``) плюс
  risk score 0–100;
* Log Analyzer  — находку по правилу с severity и техниками ATT&CK;
* Linux Triage  — признак компрометации хоста с severity и доказательством.

Сводить их к общему знаменателю нужно не ради красоты. Аналитик работает с
одним инцидентом, а не с тремя инструментами: подозрительный адрес из фида,
перебор паролей с него же в логах и свежий SSH-ключ на хосте — это одна
история. Пока каждый инструмент говорит на своём языке, связать их может
только человек вручную.

Общий знаменатель — :class:`Finding`: что нашли, насколько это серьёзно,
к каким сущностям относится и что делать.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Source(str, Enum):
    """Инструмент, породивший находку."""

    IOC = "ioc-analyzer"
    LOGS = "log-analyzer"
    TRIAGE = "linux-triage"


class Severity(str, Enum):
    """Единая шкала критичности набора.

    Взята шкала Log Analyzer как самая выразительная из трёх: пять уровней
    позволяют отличить «разбирать немедленно» от «разобрать сегодня».
    Вердикты IOC Analyzer и находки триажа приводятся к ней адаптерами.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {
            Severity.CRITICAL: 100, Severity.HIGH: 75, Severity.MEDIUM: 50,
            Severity.LOW: 25, Severity.INFO: 10,
        }[self]

    @classmethod
    def parse(cls, value: str, default: "Severity | None" = None) -> "Severity":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return default or cls.INFO


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    """Одна находка любого инструмента набора."""

    source: Source
    rule_id: str                        # AUTH-001, VT-VERDICT, TRIAGE-ACCOUNTS…
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    # Сущности — то, по чему находки связываются между собой:
    # ip, domain, url, hash, username, hostname.
    entities: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    evidence: str = ""
    recommendation: str = ""
    first_seen: str | None = None
    last_seen: str | None = None
    raw_reference: str = ""             # откуда взято: файл, индикатор, правило
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    @property
    def finding_id(self) -> str:
        """Стабильный идентификатор: одна и та же находка не меняет id между
        прогонами, что позволяет сравнивать отчёты и отслеживать динамику."""
        seed = f"{self.source.value}:{self.rule_id}:{self.title}:{sorted(self.entity_values())}"
        return f"F-{hashlib.sha1(seed.encode('utf-8')).hexdigest()[:10]}"

    def entity_values(self) -> list[str]:
        """Плоский список значений сущностей — для связывания находок."""
        values: list[str] = []
        for value in self.entities.values():
            if isinstance(value, (list, tuple, set)):
                values.extend(str(item) for item in value if item)
            elif value:
                values.append(str(value))
        return values

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "source": self.source.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "severity_score": self.severity.score,
            "confidence": self.confidence.value,
            "entities": self.entities,
            "mitre_techniques": self.mitre_techniques,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "raw_reference": self.raw_reference,
            "detected_at": self.detected_at,
        }

    def to_flat_row(self) -> dict[str, Any]:
        entities = self.entities
        return {
            "finding_id": self.finding_id,
            "severity": self.severity.value,
            "severity_score": self.severity.score,
            "confidence": self.confidence.value,
            "source": self.source.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "ip": _join(entities.get("ip")),
            "domain": _join(entities.get("domain")),
            "url": _join(entities.get("url")),
            "hash": _join(entities.get("hash")),
            "username": _join(entities.get("username")),
            "hostname": _join(entities.get("hostname")),
            "mitre_techniques": ";".join(t.get("technique_id", "")
                                         for t in self.mitre_techniques),
            "first_seen": self.first_seen or "",
            "last_seen": self.last_seen or "",
            "evidence": self.evidence[:300],
            "recommendation": self.recommendation,
            "description": self.description,
            "detected_at": self.detected_at,
        }


def _join(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(item) for item in value if item)
    return str(value)


CSV_COLUMNS: list[str] = [
    "finding_id", "severity", "severity_score", "confidence", "source",
    "rule_id", "title", "ip", "domain", "url", "hash", "username", "hostname",
    "mitre_techniques", "first_seen", "last_seen", "evidence",
    "recommendation", "description", "detected_at",
]


@dataclass
class CorrelatedGroup:
    """Находки разных инструментов, связанные общей сущностью.

    Ради этого всё и затевалось: адрес, помеченный VirusTotal как вредоносный,
    он же в логах как источник перебора паролей, он же в артефактах хоста в
    списке активных соединений — три находки трёх инструментов и одна атака.
    """

    key: str                       # значение сущности (адрес, учётная запись…)
    key_type: str                  # ip, username, domain, hash…
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return max((f.severity for f in self.findings), key=lambda s: s.score)

    @property
    def sources(self) -> list[str]:
        return sorted({f.source.value for f in self.findings})

    @property
    def is_cross_tool(self) -> bool:
        """Подтверждение из нескольких независимых источников — сильный сигнал."""
        return len(self.sources) > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "key_type": self.key_type,
            "severity": self.severity.value,
            "sources": self.sources,
            "cross_tool_confirmation": self.is_cross_tool,
            "finding_count": len(self.findings),
            "findings": [f.finding_id for f in self.findings],
            "titles": [f.title for f in self.findings],
        }
