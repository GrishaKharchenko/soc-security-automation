"""Движок детектирования и корреляция событий в инциденты.

Две задачи модуля:

1. **Прогнать все правила** по общему потоку событий. Правила независимы и не
   влияют друг на друга, поэтому порядок запуска не важен, а сбой одного
   правила не должен ронять остальные.

2. **Связать срабатывания в инциденты.** Это требование «группировки связанных
   событий»: одна атака порождает несколько детектов, и аналитику нужна
   цепочка, а не разрозненные строки.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

from ..config import Settings
from ..logging_setup import get_logger
from ..models import AuthEvent, Detection, Incident, Severity
from .access import AccountLockoutRule, PrivilegeAbuseRule, SuccessAfterFailuresRule
from .anomalies import NewSourceForUserRule, OffHoursLoginRule
from .base import DetectionRule
from .bruteforce import BruteForceRule, DistributedBruteForceRule
from .spraying import PasswordSprayingRule, UserEnumerationRule

logger = get_logger("detection.engine")

RULE_CLASSES: tuple[type[DetectionRule], ...] = (
    BruteForceRule,
    DistributedBruteForceRule,
    PasswordSprayingRule,
    UserEnumerationRule,
    SuccessAfterFailuresRule,
    PrivilegeAbuseRule,
    AccountLockoutRule,
    OffHoursLoginRule,
    NewSourceForUserRule,
)

RULE_IDS: dict[str, type[DetectionRule]] = {cls.rule_id: cls for cls in RULE_CLASSES}


class DetectionEngine:
    """Запуск правил и построение инцидентов."""

    def __init__(self, settings: Settings,
                 enabled_rules: Sequence[str] | None = None) -> None:
        self.settings = settings
        selected = RULE_CLASSES
        if enabled_rules:
            wanted = {r.upper() for r in enabled_rules}
            selected = tuple(cls for cls in RULE_CLASSES if cls.rule_id in wanted)
            if not selected:
                raise ValueError(
                    f"Неизвестные правила: {sorted(wanted)}. "
                    f"Доступны: {sorted(RULE_IDS)}"
                )
        self.rules = [cls(settings) for cls in selected]

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        """Прогнать правила. Сбой одного правила не останавливает остальные."""
        detections: list[Detection] = []

        for rule in self.rules:
            try:
                found = rule.run(events)
            except Exception as exc:  # noqa: BLE001 — изоляция правил друг от друга
                logger.exception("Правило %s упало: %s", rule.rule_id, exc)
                continue
            if found:
                logger.info("%s (%s): %d срабатываний",
                            rule.rule_id, rule.title, len(found))
            detections.extend(found)

        detections.sort(key=lambda d: (-d.severity.score, d.first_seen or d.last_seen))
        return detections


def correlate(detections: Sequence[Detection]) -> list[Incident]:
    """Объединить срабатывания в инциденты по общей сущности.

    Ключ связывания — адрес источника, а при его отсутствии имя учётной записи.
    Обоснование выбора: подавляющее большинство цепочек в логах аутентификации
    разворачивается вокруг одного источника — разведка, перебор, успешный вход
    приходят с одного адреса. Учётная запись как запасной ключ нужна для
    событий без адреса: sudo и блокировки его не содержат.

    Ограничение, о котором честно стоит помнить: инцидент, где атакующий
    сменил адрес после успешного входа, распадётся на два. Полноценное решение —
    граф связей сущностей, где узлы соединяются по любому общему атрибуту;
    для учебного проекта это избыточно, но именно так устроены промышленные
    системы корреляции.
    """
    buckets: dict[tuple[str, str], list[Detection]] = {}

    for detection in detections:
        entities = detection.entities
        key: tuple[str, str] | None = None

        if entities.get("source_ip"):
            key = ("source_ip", str(entities["source_ip"]))
        elif entities.get("username"):
            key = ("username", str(entities["username"]))
        elif len(entities.get("source_ips") or []) == 1:
            key = ("source_ip", str(entities["source_ips"][0]))
        elif len(entities.get("usernames") or []) == 1:
            key = ("username", str(entities["usernames"][0]))
        # Находки, охватывающие много сущностей сразу (распределённая атака,
        # массовая блокировка), не привязываются к первой попавшейся из них:
        # инцидент «активность с учётной записи jsmith» для блокировки пяти
        # записей дезориентирует аналитика. Такие находки группируются
        # по правилу.

        if key is None:
            key = ("rule", detection.rule_id)
        buckets.setdefault(key, []).append(detection)

    incidents: list[Incident] = []
    for (key_type, key_value), group in buckets.items():
        group.sort(key=lambda d: d.first_seen or d.last_seen)
        severity = max((d.severity for d in group), key=lambda s: s.score)
        starts = [d.first_seen for d in group if d.first_seen]
        ends = [d.last_seen for d in group if d.last_seen]

        digest = hashlib.sha1(f"{key_type}:{key_value}".encode()).hexdigest()[:8]
        incident = Incident(
            incident_id=f"INC-{digest}",
            title=_incident_title(key_type, key_value, group),
            key_type=key_type,
            key_value=key_value,
            severity=severity,
            detections=group,
            first_seen=min(starts) if starts else None,
            last_seen=max(ends) if ends else None,
        )
        incidents.append(incident)

    incidents.sort(key=lambda i: (-i.severity.score, i.first_seen or i.last_seen))
    logger.info("Корреляция: %d срабатываний объединены в %d инцидентов",
                len(detections), len(incidents))
    return incidents


def _incident_title(key_type: str, key_value: str, group: Sequence[Detection]) -> str:
    stages = len({d.rule_id for d in group})
    if key_type == "rule":
        return group[0].title

    subject = (f"адреса {key_value}" if key_type == "source_ip"
               else f"учётной записи {key_value}")

    if stages >= 3:
        return f"Многоэтапная атака с {subject} ({stages} этапа)"
    if any(d.severity is Severity.CRITICAL for d in group):
        return f"Компрометация, связанная с {subject}"
    return f"Подозрительная активность с {subject}"
