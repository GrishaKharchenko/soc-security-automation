"""Password spraying (T1110.003) и перебор имён учётных записей (T1087).

**Почему spraying нужен отдельным правилом.** Политика блокировки считает
неудачи по каждой учётной записи: пять промахов — блокировка. Атакующий,
который знает это, берёт один-два самых вероятных пароля (``Winter2026!``,
``Password1``) и пробует их по сотне логинов. По каждому аккаунту — две
попытки, порог блокировки не превышен, счётчик «неудач на пользователя»
молчит. Детект brute force такую атаку **не увидит принципиально**: он смотрит
не туда.

Разворот ключа группировки — вот всё содержание правила. Считаем не попытки
на пользователя, а **число различных пользователей на источник**, и требуем,
чтобы попыток на каждого было мало. Второе условие обязательно: без него
правило сработает на обычный brute force и продублирует AUTH-001.

**Перебор имён (T1087)** — соседнее, но другое поведение. Источник обращается
к НЕСУЩЕСТВУЮЩИМ учётным записям (``invalid user`` в Linux, статус
``0xc0000064`` в Windows). Цель не подобрать пароль, а выяснить, какие логины
вообще есть в системе — это разведка перед атакой, тактика Discovery.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Sequence

from .. import mitre
from ..logging_setup import get_logger
from ..models import AuthEvent, Confidence, Detection, Severity
from .base import DetectionRule, group_by, sliding_windows

logger = get_logger("detection.spraying")


class PasswordSprayingRule(DetectionRule):
    """Один источник, много учётных записей, мало попыток на каждую."""

    rule_id = "AUTH-003"
    primary_techniques = ("T1110.003",)   # + T1078, если пароль подошёл
    title = "Password spraying"
    description = (
        "Источник перебирает большое число различных учётных записей, делая по "
        "каждой лишь несколько попыток — обход политики блокировки."
    )

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        # Попытки по НЕСУЩЕСТВУЮЩИМ учётным записям исключаются намеренно:
        # это разведка имён (T1087, правило AUTH-004), а не распыление пароля.
        # Без этого фильтра оба правила давали алерт на одно и то же поведение,
        # и аналитик получал дубль с разными техниками ATT&CK.
        failures = [e for e in events
                    if e.is_failure and e.username and e.source_ip
                    and not e.invalid_user]
        detections: list[Detection] = []

        for source_ip, group in group_by(failures, lambda e: e.source_ip).items():
            for burst in sliding_windows(
                group,
                window_seconds=self.settings.spraying_window,
                min_size=self.settings.spraying_min_users,
            ):
                attempts_per_user: dict[str, int] = {}
                for event in burst:
                    attempts_per_user[event.username] = \
                        attempts_per_user.get(event.username, 0) + 1

                users = sorted(attempts_per_user)
                if len(users) < self.settings.spraying_min_users:
                    continue

                max_attempts = max(attempts_per_user.values())
                # Ключевое условие: попыток на аккаунт мало. Иначе это обычный
                # подбор пароля, и его уже поймало правило AUTH-001.
                if max_attempts > self.settings.spraying_max_attempts_per_user:
                    continue

                detections.append(self._build(source_ip, burst, users,
                                              attempts_per_user, events))

        logger.debug("%s: срабатываний %d", self.rule_id, len(detections))
        return detections

    def _build(self, source_ip, burst, users, attempts_per_user, all_events) -> Detection:
        duration = (burst[-1].timestamp - burst[0].timestamp).total_seconds()

        # Успешный вход с того же адреса означает, что распыление сработало:
        # один из паролей подошёл, и мы знаем к какой учётной записи.
        #
        # Горизонт намеренно шире всплеска. Атакующий сначала прогоняет весь
        # список логинов, смотрит результат и только потом заходит под тем,
        # где пароль подошёл, — успех приходит уже ПОСЛЕ последней неудачи.
        # При проверке строго внутри всплеска самая важная находка (распыление
        # удалось) терялась, что и показал прогон по тестовым данным.
        horizon = burst[-1].timestamp + timedelta(seconds=self.settings.spraying_window)
        compromised = sorted({
            event.username for event in all_events
            if event.is_success and event.source_ip == source_ip
            and burst[0].timestamp <= event.timestamp <= horizon
        })

        if compromised:
            severity, confidence = Severity.CRITICAL, Confidence.HIGH
        elif len(users) >= self.settings.spraying_min_users * 3:
            severity, confidence = Severity.HIGH, Confidence.HIGH
        else:
            severity, confidence = Severity.HIGH, Confidence.MEDIUM

        techniques = [mitre.T1110_003]
        if compromised:
            techniques.append(mitre.T1078)

        return Detection(
            rule_id=self.rule_id,
            title=f"Password spraying с {source_ip}: {len(users)} учётных записей",
            description=(
                f"Адрес {source_ip} за {duration:.0f} с обратился к {len(users)} "
                f"различным учётным записям, максимум {max(attempts_per_user.values())} "
                "попыток на каждую. Малое число попыток на аккаунт при большом "
                "охвате — характерный признак обхода политики блокировки: счётчик "
                "неудач по каждой учётной записи не превышается."
                + (f" УСПЕШНЫЙ ВХОД: {', '.join(compromised)} — "
                   "пароль подобран." if compromised else "")
            ),
            severity=severity,
            confidence=confidence,
            mitre=techniques,
            entities={"source_ip": source_ip, "usernames": users[:30],
                      "compromised_accounts": compromised},
            first_seen=burst[0].timestamp,
            last_seen=burst[-1].timestamp,
            event_count=len(burst),
            evidence=burst,
            metrics={"distinct_users": len(users), "attempts": len(burst),
                     "max_attempts_per_user": max(attempts_per_user.values()),
                     "duration_seconds": round(duration, 1),
                     "compromised_accounts": compromised},
            recommendation=(
                f"Немедленно заблокировать {source_ip}. "
                + (f"Сбросить пароли: {', '.join(compromised)}, завершить их сессии, "
                   "проверить дальнейшую активность. " if compromised else "")
                + "Проверить, не используются ли в организации словарные пароли, "
                "включить MFA, настроить оповещение на массовые неудачи с одного адреса."
            ),
        )


class UserEnumerationRule(DetectionRule):
    """Перебор имён несуществующих учётных записей — разведка."""

    rule_id = "AUTH-004"
    primary_techniques = ("T1087",)
    title = "Перебор имён учётных записей"
    description = (
        "Источник обращается к множеству несуществующих учётных записей, "
        "выясняя, какие логины есть в системе."
    )

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        invalid = [e for e in events if e.is_failure and e.invalid_user
                   and e.username and e.source_ip]
        detections: list[Detection] = []

        for source_ip, group in group_by(invalid, lambda e: e.source_ip).items():
            for burst in sliding_windows(
                group,
                window_seconds=self.settings.enumeration_window,
                min_size=self.settings.enumeration_min_invalid_users,
            ):
                users = sorted({e.username for e in burst})
                if len(users) < self.settings.enumeration_min_invalid_users:
                    continue

                duration = (burst[-1].timestamp - burst[0].timestamp).total_seconds()
                detections.append(Detection(
                    rule_id=self.rule_id,
                    title=f"Разведка учётных записей с {source_ip}: {len(users)} имён",
                    description=(
                        f"Адрес {source_ip} за {duration:.0f} с попытался войти под "
                        f"{len(users)} НЕСУЩЕСТВУЮЩИМИ учётными записями "
                        f"({', '.join(users[:8])}"
                        f"{'…' if len(users) > 8 else ''}). Перебор словаря типовых "
                        "имён — подготовительный этап: атакующий выясняет, какие "
                        "логины существуют, чтобы затем подбирать к ним пароли."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    mitre=[mitre.T1087],
                    entities={"source_ip": source_ip, "attempted_usernames": users[:30]},
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    event_count=len(burst),
                    evidence=burst,
                    metrics={"distinct_invalid_users": len(users),
                             "attempts": len(burst),
                             "duration_seconds": round(duration, 1)},
                    recommendation=(
                        f"Заблокировать {source_ip}. Ожидать переход к подбору паролей "
                        "по существующим учётным записям — усилить мониторинг. "
                        "Проверить, не раскрывает ли сервис существование логинов "
                        "различием в ответах или во времени отклика."
                    ),
                ))

        logger.debug("%s: срабатываний %d", self.rule_id, len(detections))
        return detections
