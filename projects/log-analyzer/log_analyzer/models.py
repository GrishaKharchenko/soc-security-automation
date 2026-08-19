"""Модели предметной области.

Ключевая идея проекта — **единое нормализованное событие** :class:`AuthEvent`.
Linux пишет ``Failed password for invalid user admin from 192.0.2.10``,
Windows отдаёт событие 4625 с полями ``TargetUserName`` и ``IpAddress``.
Правила детектирования не должны знать об этой разнице: они работают с
общей моделью, а вся специфика форматов заперта в парсерах.

Именно поэтому добавить новый источник (Cisco ASA, VPN, Okta) = написать один
парсер, не трогая ни одного правила.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventOutcome(str, Enum):
    """Исход попытки аутентификации."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Platform(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Критичность находки.

    Пять уровней вместо трёх — потому что в реальном SOC нужно отличать
    «разбирать немедленно» от «разобрать сегодня». ``score`` используется
    для сортировки и агрегации.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {
            Severity.CRITICAL: 100,
            Severity.HIGH: 75,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFO: 10,
        }[self]

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 45:
            return cls.MEDIUM
        if score >= 20:
            return cls.LOW
        return cls.INFO


class Confidence(str, Enum):
    """Уверенность в срабатывании — отделена от критичности.

    Это разные оси. «Успешный вход после 50 неудач» — высокая критичность и
    высокая уверенность. «Вход в 3 часа ночи» — низкая уверенность (админ мог
    работать ночью), но потенциально высокая критичность. Смешивать их в один
    показатель значит терять информацию, нужную аналитику для приоритизации.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AuthEvent:
    """Одно нормализованное событие аутентификации."""

    timestamp: datetime
    outcome: EventOutcome
    platform: Platform = Platform.UNKNOWN
    username: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    hostname: str | None = None
    service: str | None = None          # sshd, sudo, su, RDP…
    event_type: str = "auth"            # ssh_login, sudo_command, account_lockout…
    event_id: str | None = None         # код события Windows: 4624, 4625…
    logon_type: str | None = None       # тип входа Windows: 3 (сеть), 10 (RDP)…
    invalid_user: bool = False          # логина не существует в системе
    raw: str = ""
    source_file: str = ""
    line_number: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_failure(self) -> bool:
        return self.outcome is EventOutcome.FAILURE

    @property
    def is_success(self) -> bool:
        return self.outcome is EventOutcome.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "outcome": self.outcome.value,
            "platform": self.platform.value,
            "username": self.username,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "hostname": self.hostname,
            "service": self.service,
            "event_type": self.event_type,
            "event_id": self.event_id,
            "logon_type": self.logon_type,
            "invalid_user": self.invalid_user,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "raw": self.raw,
        }


@dataclass
class MitreTechnique:
    """Техника MITRE ATT&CK с обоснованием выбора.

    Поле ``rationale`` — не украшение. Маппинг на ATT&CK без объяснения
    «почему именно эта техника» бесполезен: аналитик не сможет ни проверить
    его, ни защитить на разборе инцидента. Здесь для каждого правила записано,
    какое именно наблюдаемое поведение соответствует технике.
    """

    technique_id: str
    name: str
    tactic: str
    rationale: str
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "rationale": self.rationale,
            "url": self.url or f"https://attack.mitre.org/techniques/"
                                f"{self.technique_id.replace('.', '/')}/",
        }


@dataclass
class Detection:
    """Срабатывание одного правила."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    mitre: list[MitreTechnique] = field(default_factory=list)
    entities: dict[str, Any] = field(default_factory=dict)   # user, ip, host
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    evidence: list[AuthEvent] = field(default_factory=list)
    recommendation: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds()

    def to_dict(self, evidence_limit: int = 10) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "severity_score": self.severity.score,
            "confidence": self.confidence.value,
            "mitre": [t.to_dict() for t in self.mitre],
            "entities": self.entities,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "duration_seconds": round(self.duration_seconds, 1),
            "event_count": self.event_count,
            "metrics": self.metrics,
            "recommendation": self.recommendation,
            "evidence": [e.to_dict() for e in self.evidence[:evidence_limit]],
        }


@dataclass
class Incident:
    """Несколько связанных срабатываний вокруг общей сущности.

    Смысл группировки: одна атака порождает несколько детектов. Перебор
    паролей с адреса ``192.0.2.10``, затем успешный вход, затем sudo — это
    три срабатывания и **один** инцидент. Аналитику нужно видеть цепочку
    целиком, а не три отдельные строки, между которыми он должен сам
    догадаться о связи.
    """

    incident_id: str
    title: str
    key_type: str                      # по чему связаны: source_ip или username
    key_value: str
    severity: Severity
    detections: list[Detection] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def mitre_techniques(self) -> list[str]:
        seen: list[str] = []
        for detection in self.detections:
            for technique in detection.mitre:
                if technique.technique_id not in seen:
                    seen.append(technique.technique_id)
        return seen

    @property
    def total_events(self) -> int:
        return sum(d.event_count for d in self.detections)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "correlation_key": {"type": self.key_type, "value": self.key_value},
            "severity": self.severity.value,
            "severity_score": self.severity.score,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "detection_count": len(self.detections),
            "total_events": self.total_events,
            "mitre_techniques": self.mitre_techniques,
            "detections": [d.rule_id for d in self.detections],
        }


CSV_COLUMNS: list[str] = [
    "severity", "severity_score", "confidence", "rule_id", "title",
    "mitre_techniques", "source_ip", "username", "hostname",
    "event_count", "first_seen", "last_seen", "duration_seconds",
    "incident_id", "recommendation", "description",
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
