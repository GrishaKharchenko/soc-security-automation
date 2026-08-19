"""Детект перебора пароля (T1110.001) и его распределённой формы.

**Что такое brute force в логах.** Атакующий знает или предполагает имя
существующей учётной записи и перебирает пароли. В логах это выглядит как
плотная серия неудачных входов по ОДНОМУ логину с ОДНОГО адреса.

**Почему ключ группировки — пара (пользователь, источник), а не что-то одно.**
Группировка только по пользователю смешала бы в кучу забывчивого сотрудника,
у которого не подставился пароль на трёх устройствах, и настоящую атаку.
Группировка только по адресу превратила бы в brute force распылённую атаку,
у которой совсем другая природа и другая техника ATT&CK. Пара даёт точный
портрет именно подбора пароля к конкретному аккаунту.

**Почему нужен отдельный распределённый вариант.** Если атакующий перебирает
пароль к одной учётной записи с двадцати адресов ботнета, то по каждой паре
(пользователь, адрес) попыток будет мало и основной порог не сработает.
Смотреть надо на пользователя и считать число различных источников.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Sequence

from .. import mitre
from ..logging_setup import get_logger
from ..models import AuthEvent, Confidence, Detection, Severity
from .base import DetectionRule, group_by, sliding_windows

logger = get_logger("detection.bruteforce")


class BruteForceRule(DetectionRule):
    """Множественные неудачные входы по одной учётной записи с одного адреса."""

    rule_id = "AUTH-001"
    primary_techniques = ("T1110.001",)   # + T1078, если подбор удался
    title = "Подбор пароля к учётной записи"
    description = (
        "Серия неудачных попыток аутентификации по одной учётной записи "
        "с одного источника за короткий промежуток времени."
    )

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        failures = [e for e in events if e.is_failure and e.username and e.source_ip]
        detections: list[Detection] = []

        for (username, source_ip), group in group_by(
            failures, lambda e: (e.username, e.source_ip)
        ).items():
            for burst in sliding_windows(
                group,
                window_seconds=self.settings.bruteforce_window,
                min_size=self.settings.bruteforce_threshold,
            ):
                detections.append(self._build(username, source_ip, burst, events))

        logger.debug("%s: срабатываний %d", self.rule_id, len(detections))
        return detections

    def _build(
        self, username: str, source_ip: str,
        burst: list[AuthEvent], all_events: Sequence[AuthEvent],
    ) -> Detection:
        attempts = len(burst)
        duration = (burst[-1].timestamp - burst[0].timestamp).total_seconds()
        rate = attempts / (duration / 60) if duration > 0 else float(attempts)

        # Успешный вход тем же пользователем с того же адреса сразу после серии
        # неудач означает, что подбор УДАЛСЯ. Это переводит находку в критичные:
        # атакующий уже внутри, и счёт идёт на минуты.
        horizon = burst[-1].timestamp + timedelta(seconds=self.settings.bruteforce_window)
        breached = any(
            event.is_success
            and event.username == username
            and event.source_ip == source_ip
            and burst[0].timestamp <= event.timestamp <= horizon
            for event in all_events
        )

        if breached:
            severity, confidence = Severity.CRITICAL, Confidence.HIGH
        elif attempts >= self.settings.bruteforce_threshold * 4:
            severity, confidence = Severity.HIGH, Confidence.HIGH
        elif rate > 10:
            # Больше 10 попыток в минуту — человек так пароль не вспоминает.
            severity, confidence = Severity.HIGH, Confidence.HIGH
        else:
            severity, confidence = Severity.MEDIUM, Confidence.MEDIUM

        techniques = [mitre.T1110_001]
        if breached:
            techniques.append(mitre.T1078)

        privileged = username.lower() in {"root", "administrator", "admin", "администратор"}
        if privileged and severity is Severity.MEDIUM:
            # Привилегированная учётная запись — цена ошибки выше.
            severity = Severity.HIGH

        return Detection(
            rule_id=self.rule_id,
            title=f"Подбор пароля: {username} с {source_ip}",
            description=(
                f"С адреса {source_ip} зафиксировано {attempts} неудачных попыток "
                f"входа под учётной записью «{username}» за {duration:.0f} с "
                f"({rate:.1f} попыток/мин). Порог правила: "
                f"{self.settings.bruteforce_threshold} за "
                f"{self.settings.bruteforce_window} с."
                + (" ЗАФИКСИРОВАН ПОСЛЕДУЮЩИЙ УСПЕШНЫЙ ВХОД — "
                   "учётная запись считается скомпрометированной." if breached else "")
            ),
            severity=severity,
            confidence=confidence,
            mitre=techniques,
            entities={"username": username, "source_ip": source_ip,
                      "hostname": burst[0].hostname},
            first_seen=burst[0].timestamp,
            last_seen=burst[-1].timestamp,
            event_count=attempts,
            evidence=burst,
            metrics={"attempts": attempts, "duration_seconds": round(duration, 1),
                     "attempts_per_minute": round(rate, 1),
                     "privileged_account": privileged, "successful_breach": breached},
            recommendation=(
                "Немедленно: заблокировать учётную запись, принудительно сменить "
                "пароль, завершить активные сессии, проверить действия после входа."
                if breached else
                f"Заблокировать {source_ip} на периметре, проверить политику "
                f"блокировки учётных записей, при повторении — включить MFA."
            ),
        )


class DistributedBruteForceRule(DetectionRule):
    """Одна учётная запись атакуется с множества адресов.

    Признак ботнета или прокси-сети. Каждый отдельный источник делает мало
    попыток и под основной порог не подпадает — атака видна только если
    смотреть на учётную запись целиком.
    """

    rule_id = "AUTH-002"
    primary_techniques = ("T1110",)
    title = "Распределённый подбор пароля"
    description = (
        "Неудачные попытки входа по одной учётной записи приходят с большого "
        "числа различных адресов — признак использования ботнета."
    )

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        failures = [e for e in events if e.is_failure and e.username and e.source_ip]
        detections: list[Detection] = []

        for username, group in group_by(failures, lambda e: e.username).items():
            for burst in sliding_windows(
                group,
                window_seconds=self.settings.distributed_window,
                min_size=self.settings.distributed_min_sources,
            ):
                sources = sorted({e.source_ip for e in burst if e.source_ip})
                if len(sources) < self.settings.distributed_min_sources:
                    continue

                duration = (burst[-1].timestamp - burst[0].timestamp).total_seconds()
                severity = (Severity.HIGH if len(sources) >= 10 else Severity.MEDIUM)

                detections.append(Detection(
                    rule_id=self.rule_id,
                    title=f"Распределённый подбор: {username} с {len(sources)} адресов",
                    description=(
                        f"Учётная запись «{username}» атакована с {len(sources)} "
                        f"различных адресов ({len(burst)} попыток за {duration:.0f} с). "
                        "Распределение по источникам обходит блокировку по IP и "
                        "маскирует атаку под фоновый шум."
                    ),
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    mitre=[mitre.T1110],
                    entities={"username": username, "source_ips": sources[:20]},
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    event_count=len(burst),
                    evidence=burst,
                    metrics={"distinct_sources": len(sources),
                             "attempts": len(burst),
                             "duration_seconds": round(duration, 1)},
                    recommendation=(
                        "Блокировка по отдельным адресам неэффективна. Включить MFA "
                        "для учётной записи, рассмотреть ограничение доступа по "
                        "геолокации или спискам разрешённых сетей, проверить, не "
                        "утёк ли пароль (сервисы мониторинга утечек)."
                    ),
                ))

        logger.debug("%s: срабатываний %d", self.rule_id, len(detections))
        return detections
