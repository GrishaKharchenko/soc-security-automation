"""Поведенческие аномалии: время входа и новый источник.

Отличие этих правил от пороговых: здесь нет «плохого» события как такового.
Вход в 3 часа ночи — не атака, админ вполне может работать ночью. Это
**слабый сигнал**, ценность которого проявляется только в сочетании с другими.

Именно поэтому у правил низкая ``confidence`` и умеренная ``severity``.
Выставить им HIGH означало бы утопить аналитика в ложных срабатываниях —
верный способ добиться, чтобы систему перестали читать. Их задача — не поднять
тревогу самостоятельно, а добавить веса инциденту, когда рядом сработало
что-то ещё; связывание происходит на этапе корреляции.
"""

from __future__ import annotations

from typing import Sequence

from .. import mitre
from ..logging_setup import get_logger
from ..models import AuthEvent, Confidence, Detection, Severity
from .base import DetectionRule, group_by

logger = get_logger("detection.anomalies")


class OffHoursLoginRule(DetectionRule):
    """Успешные входы вне рабочего времени."""

    rule_id = "AUTH-008"
    primary_techniques = ("T1078",)
    title = "Вход вне рабочего времени"
    description = (
        "Успешная аутентификация в нерабочие часы или в выходной день — "
        "слабый сигнал, значимый в сочетании с другими находками."
    )

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        detections: list[Detection] = []
        successes = [e for e in events if e.is_success and e.username
                     and e.event_type not in {"sudo_command"}]

        for username, group in group_by(successes, lambda e: e.username).items():
            odd = [e for e in group if self._is_off_hours(e)]
            if not odd:
                continue

            hours = sorted({e.timestamp.hour for e in odd})
            sources = sorted({e.source_ip for e in odd if e.source_ip})
            weekend = any(e.timestamp.weekday() >= 5 for e in odd)

            detections.append(Detection(
                rule_id=self.rule_id,
                title=f"Вход вне рабочего времени: {username}",
                description=(
                    f"Учётная запись «{username}» использовалась для входа "
                    f"{len(odd)} раз вне рабочего окна "
                    f"{self.settings.business_hours_start}:00–"
                    f"{self.settings.business_hours_end}:00 "
                    f"(часы: {', '.join(f'{h:02d}:00' for h in hours)})."
                    + (" Часть входов пришлась на выходные." if weekend else "")
                    + " Само по себе это не инцидент — оценивать следует в "
                    "контексте роли пользователя и других находок."
                ),
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                mitre=[mitre.T1078],
                entities={"username": username, "source_ips": sources[:10]},
                first_seen=odd[0].timestamp,
                last_seen=odd[-1].timestamp,
                event_count=len(odd),
                evidence=odd,
                metrics={"off_hours_logins": len(odd), "hours": hours,
                         "includes_weekend": weekend},
                recommendation=(
                    "Сверить с графиком работы сотрудника и заявками на доступ. "
                    "Если рядом есть находки о переборе с тех же адресов — "
                    "повысить приоритет и проверить действия в этих сессиях."
                ),
            ))

        logger.debug("%s: срабатываний %d", self.rule_id, len(detections))
        return detections

    def _is_off_hours(self, event: AuthEvent) -> bool:
        if self.settings.flag_weekend_logins and event.timestamp.weekday() >= 5:
            return True
        hour = event.timestamp.hour
        return not (self.settings.business_hours_start
                    <= hour < self.settings.business_hours_end)


class NewSourceForUserRule(DetectionRule):
    """Успешный вход с адреса, ранее не встречавшегося у этой учётной записи.

    Реализовано как базовая линия **внутри анализируемого набора**: первый
    успешный вход с каждого адреса считается «нормой», последующие new_sources
    адреса — отклонением. Это честное упрощение, и его границы надо понимать:
    для одного файла за сутки базовая линия слишком короткая, чтобы делать
    сильные выводы. В продуктивной системе историю входов копят неделями и
    хранят отдельно от анализируемых логов.
    """

    rule_id = "AUTH-009"
    primary_techniques = ("T1078",)
    title = "Вход с нового источника"
    description = (
        "Учётная запись успешно вошла с адреса, не встречавшегося у неё ранее "
        "в анализируемом наборе данных."
    )

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        detections: list[Detection] = []
        successes = [e for e in events
                     if e.is_success and e.username and e.source_ip]

        # Минимальная база: пока у учётной записи меньше стольких успешных
        # входов, называть очередной адрес «непривычным» не на чем. Без этого
        # порога правило срабатывало на пользователе, вошедшем всего дважды.
        MIN_BASELINE_LOGINS = 3

        for username, group in group_by(successes, lambda e: e.username).items():
            group = sorted(group, key=lambda e: e.timestamp)
            if len(group) < MIN_BASELINE_LOGINS:
                continue
            known: set[str] = set()
            new_sources: list[AuthEvent] = []

            for event in group:
                if event.source_ip not in known:
                    if known:            # первый адрес — это базовая линия
                        new_sources.append(event)
                    known.add(event.source_ip)

            if not new_sources:
                continue

            detections.append(Detection(
                rule_id=self.rule_id,
                title=f"Новые источники входа: {username} ({len(new_sources)})",
                description=(
                    f"Учётная запись «{username}» успешно вошла с "
                    f"{len(new_sources)} адресов, ранее у неё не встречавшихся: "
                    f"{', '.join(e.source_ip for e in new_sources[:5])}. "
                    f"Всего различных источников у записи: {len(known)}. "
                    "Базовая линия построена по анализируемому набору, поэтому "
                    "для коротких выгрузок сигнал слабый."
                ),
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                mitre=[mitre.T1078],
                entities={"username": username,
                          "new_source_ips": [e.source_ip for e in new_sources][:10],
                          "known_source_count": len(known)},
                first_seen=new_sources[0].timestamp,
                last_seen=new_sources[-1].timestamp,
                event_count=len(new_sources),
                evidence=new_sources,
                metrics={"new_sources": len(new_sources), "total_sources": len(known)},
                recommendation=(
                    "Проверить, соответствует ли адрес известным сетям организации, "
                    "VPN или домашнему интернету сотрудника. При расхождении — "
                    "запросить подтверждение у владельца учётной записи."
                ),
            ))

        logger.debug("%s: срабатываний %d", self.rule_id, len(detections))
        return detections
