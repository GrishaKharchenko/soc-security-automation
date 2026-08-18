"""Модели предметной области.

Датаклассы вместо «голых» словарей: тип IOC, результат обогащения и итог
анализа описаны явно. Это даёт автодополнение, статическую проверку и один
контроль качества — метод ``to_dict`` рядом с данными, а не в сериализаторе.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class IOCType(str, Enum):
    """Поддерживаемые типы индикаторов.

    Наследование от ``str`` даёт бесплатную JSON-сериализацию и сравнение
    со строками (``ioc.type == "ipv4"``).
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"

    @property
    def is_hash(self) -> bool:
        return self in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}

    @property
    def is_ip(self) -> bool:
        return self in {IOCType.IPV4, IOCType.IPV6}


class Verdict(str, Enum):
    """Итоговая оценка индикатора.

    Порядок важен: ``severity`` используется для сортировки отчёта — аналитик
    должен видеть самое опасное сверху.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"      # VT не знает такой индикатор (404)
    ERROR = "error"          # обогащение не удалось (сеть, лимиты, 5xx)
    SKIPPED = "skipped"      # обогащение не выполнялось (--offline)

    @property
    def severity(self) -> int:
        return {
            Verdict.MALICIOUS: 5,
            Verdict.SUSPICIOUS: 4,
            Verdict.ERROR: 3,
            Verdict.UNKNOWN: 2,
            Verdict.SKIPPED: 1,
            Verdict.CLEAN: 0,
        }[self]


class EnrichmentStatus(str, Enum):
    """Технический статус похода в API — отделён от вердикта.

    Важное разделение: «VT не ответил» (ERROR) и «VT ответил, что чисто»
    (CLEAN) — принципиально разные вещи для аналитика.
    """

    OK = "ok"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"
    NETWORK_ERROR = "network_error"
    API_ERROR = "api_error"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"


@dataclass
class IOC:
    """Один нормализованный индикатор."""

    value: str                      # нормализованное значение (ключ дедупликации)
    type: IOCType
    raw: str                        # как было записано в исходном файле
    source_lines: list[int] = field(default_factory=list)
    occurrences: int = 1            # сколько раз встретился во входных данных
    defanged: bool = False          # был ли записан в «обезвреженном» виде

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "type": self.type.value,
            "raw": self.raw,
            "source_lines": self.source_lines,
            "occurrences": self.occurrences,
            "defanged": self.defanged,
        }


@dataclass
class EnrichmentResult:
    """Ответ провайдера обогащения, приведённый к общему виду.

    Клиент VirusTotal возвращает именно это, а не сырой JSON: скоринг и отчёты
    зависят от стабильной внутренней структуры, а не от формата вендора.
    Подключить AbuseIPDB или OTX = написать ещё один класс с тем же выходом.
    """

    provider: str
    status: EnrichmentStatus
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    reputation: int = 0
    total_engines: int = 0
    detection_names: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    country: str | None = None
    as_owner: str | None = None
    first_seen: str | None = None
    last_analysis_date: str | None = None
    permalink: str | None = None
    error: str | None = None
    from_cache: bool = False

    @property
    def has_data(self) -> bool:
        return self.status is EnrichmentStatus.OK

    @property
    def detection_ratio(self) -> str:
        """Классическая запись «5/72», привычная любому SOC-аналитику."""
        if not self.total_engines:
            return "0/0"
        return f"{self.malicious}/{self.total_engines}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status.value,
            "stats": {
                "malicious": self.malicious,
                "suspicious": self.suspicious,
                "harmless": self.harmless,
                "undetected": self.undetected,
                "timeout": self.timeout,
                "total_engines": self.total_engines,
                "detection_ratio": self.detection_ratio,
            },
            "reputation": self.reputation,
            "detection_names": self.detection_names,
            "tags": self.tags,
            "country": self.country,
            "as_owner": self.as_owner,
            "first_seen": self.first_seen,
            "last_analysis_date": self.last_analysis_date,
            "permalink": self.permalink,
            "error": self.error,
            "from_cache": self.from_cache,
        }


@dataclass
class AnalysisResult:
    """IOC + обогащение + вердикт. Единица итогового отчёта."""

    ioc: IOC
    enrichment: EnrichmentResult | None = None
    verdict: Verdict = Verdict.UNKNOWN
    risk_score: int = 0                       # 0..100
    reasons: list[str] = field(default_factory=list)
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc": self.ioc.to_dict(),
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "analyzed_at": self.analyzed_at,
            "enrichment": self.enrichment.to_dict() if self.enrichment else None,
        }

    def to_flat_row(self) -> dict[str, Any]:
        """Плоская строка для CSV — формат, который открывают в Excel/Splunk."""
        e = self.enrichment
        return {
            "value": self.ioc.value,
            "type": self.ioc.type.value,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "detection_ratio": e.detection_ratio if e else "",
            "malicious": e.malicious if e else "",
            "suspicious": e.suspicious if e else "",
            "harmless": e.harmless if e else "",
            "undetected": e.undetected if e else "",
            "reputation": e.reputation if e else "",
            "country": (e.country or "") if e else "",
            "as_owner": (e.as_owner or "") if e else "",
            "tags": ";".join(e.tags) if e else "",
            "detection_names": ";".join(e.detection_names[:5]) if e else "",
            "enrichment_status": e.status.value if e else "",
            "error": (e.error or "") if e else "",
            "occurrences": self.ioc.occurrences,
            "source_lines": ";".join(str(n) for n in self.ioc.source_lines),
            "raw": self.ioc.raw,
            "permalink": (e.permalink or "") if e else "",
            "reasons": " | ".join(self.reasons),
            "analyzed_at": self.analyzed_at,
        }


CSV_COLUMNS: list[str] = [
    "value", "type", "verdict", "risk_score", "detection_ratio",
    "malicious", "suspicious", "harmless", "undetected", "reputation",
    "country", "as_owner", "tags", "detection_names", "enrichment_status",
    "error", "occurrences", "source_lines", "raw", "permalink",
    "reasons", "analyzed_at",
]
