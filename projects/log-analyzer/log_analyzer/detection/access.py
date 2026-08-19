"""Правила вокруг успешного доступа: компрометация, привилегии, блокировки.

Здесь собраны детекты, которые срабатывают не на самой попытке подбора, а на
её последствиях. Для SOC это самые важные находки: неудачный перебор — это
шум, который идёт круглосуточно на любом публичном сервисе; удавшийся перебор —
это инцидент.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Sequence

from .. import mitre
from ..logging_setup import get_logger
from ..models import AuthEvent, Confidence, Detection, Severity
from .base import DetectionRule, group_by, sliding_windows

logger = get_logger("detection.access")


class SuccessAfterFailuresRule(DetectionRule):
    """Успешный вход сразу после серии неудач — подбор пароля удался.

    Это правило корреляции, а не порога: оно смотрит не на количество событий,
    а на их **последовательность**. Отдельно взятые «пять неудач» и «один
    успех» ничего не значат — обычный пользователь ошибается паролем. Значение
    имеет именно порядок: серия провалов, а затем успех по той же учётной
    записи в пределах короткого окна.

    Почему это самый ценный детект в проекте: он ловит момент **перехода**
    атаки из стадии Credential Access в стадию Initial Access. До него в логах
    только шум, после него — злоумышленник внутри, и все его дальнейшие
    действия выглядят как действия легитимного пользователя.
    """

    rule_id = "AUTH-005"
    primary_techniques = ("T1078", "T1110.001", "T1021.004", "T1021.001")
    title = "Успешный вход после серии неудачных"
    description = (
        "По учётной записи зафиксирована серия неудачных попыток, за которой "
        "последовал успешный вход — признак удавшегося подбора пароля."
    )

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        detections: list[Detection] = []
        window = timedelta(seconds=self.settings.success_after_failures_window)
        minimum = self.settings.success_after_failures_min

        for username, group in group_by(events, lambda e: e.username).items():
            group = sorted(group, key=lambda e: e.timestamp)

            # Адреса, с которых учётная запись успешно входила ранее, —
            # база «привычного» поведения для этого пользователя.
            known_good: set[str] = set()

            for index, event in enumerate(group):
                if not event.is_success:
                    continue

                # Собираем неудачи, предшествующие успеху в пределах окна.
                preceding: list[AuthEvent] = []
                for earlier in reversed(group[:index]):
                    if event.timestamp - earlier.timestamp > window:
                        break
                    if earlier.is_failure:
                        preceding.append(earlier)
                    else:
                        # Предыдущий успешный вход обрывает серию: значит
                        # пользователь уже входил нормально, и это не подбор.
                        break

                familiar_source = event.source_ip in known_good
                if event.source_ip:
                    known_good.add(event.source_ip)

                if len(preceding) < minimum:
                    continue

                preceding.reverse()
                detections.append(
                    self._build(username, event, preceding, familiar_source)
                )

        logger.debug("%s: срабатываний %d", self.rule_id, len(detections))
        return detections

    def _build(self, username: str, success: AuthEvent,
               failures: list[AuthEvent], familiar_source: bool = False) -> Detection:
        sources = sorted({e.source_ip for e in failures if e.source_ip})
        same_source = success.source_ip in sources
        gap = (success.timestamp - failures[-1].timestamp).total_seconds()

        # Три градации вместо двух — иначе правило тонет в ложных срабатываниях.
        #
        # 1. Адрес уже использовался этой учётной записью для успешного входа
        #    ранее. Человек забыл пароль, помучился и вошёл со своего же
        #    рабочего места — самый частый сценарий в реальных логах. Понижаем
        #    до MEDIUM/LOW: находку стоит увидеть, но поднимать по ней тревогу
        #    среди ночи не надо.
        # 2. Адрес новый и совпадает с источником перебора — перебор удался.
        # 3. Адрес новый, но перебор шёл с других адресов — неоднозначно.
        if familiar_source:
            severity, confidence = Severity.MEDIUM, Confidence.LOW
        elif same_source:
            severity, confidence = Severity.CRITICAL, Confidence.HIGH
        else:
            severity, confidence = Severity.HIGH, Confidence.MEDIUM

        techniques = [mitre.T1078, mitre.T1110_001]
        if success.service and success.service.lower().startswith("sshd"):
            techniques.append(mitre.T1021_004)
        if success.logon_type in {"10", "7"}:
            techniques.append(mitre.T1021_001)

        return Detection(
            rule_id=self.rule_id,
            title=f"Вероятная компрометация: {username} с {success.source_ip}",
            description=(
                f"Учётной записи «{username}» предшествовало {len(failures)} "
                f"неудачных попыток входа, после чего через {gap:.0f} с "
                f"зафиксирован УСПЕШНЫЙ вход с адреса {success.source_ip}. "
                + ("Адрес уже использовался этой учётной записью для успешного "
                   "входа ранее, поэтому наиболее вероятное объяснение — "
                   "пользователь забыл пароль. Проверить стоит, но как рутинную "
                   "задачу, а не как инцидент."
                   if familiar_source else
                   "Успешный вход выполнен с того же адреса, с которого шёл "
                   "перебор — учётные данные следует считать скомпрометированными."
                   if same_source else
                   f"Перебор шёл с других адресов ({', '.join(sources[:5])}), "
                   "успешный вход — с иного источника. Требуется подтверждение "
                   "у владельца учётной записи.")
            ),
            severity=severity,
            confidence=confidence,
            mitre=techniques,
            entities={"username": username, "source_ip": success.source_ip,
                      "failure_sources": sources, "hostname": success.hostname},
            first_seen=failures[0].timestamp,
            last_seen=success.timestamp,
            event_count=len(failures) + 1,
            evidence=failures + [success],
            metrics={"preceding_failures": len(failures),
                     "seconds_to_success": round(gap, 1),
                     "same_source": same_source,
                     "source_previously_used_by_account": familiar_source},
            recommendation=(
                "Считать учётную запись скомпрометированной: заблокировать, "
                "сбросить пароль, завершить все сессии. Собрать историю действий "
                "после входа (команды, обращения к файлам, сетевые соединения), "
                "проверить закрепление: новые ключи SSH, задания cron, новые учётные "
                "записи. Проверить, не использовался ли тот же пароль в других "
                "системах."
            ),
        )


class PrivilegeAbuseRule(DetectionRule):
    """Повторяющиеся неудачные попытки повышения привилегий (sudo)."""

    rule_id = "AUTH-006"
    primary_techniques = ("T1548.003",)
    title = "Неудачные попытки повышения привилегий"
    description = (
        "Серия неуспешных вызовов sudo — попытка получить права root при "
        "отсутствии пароля пользователя."
    )

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        sudo_failures = [
            e for e in events
            if e.is_failure and e.username
            and e.event_type in {"sudo_auth", "sudo_not_permitted", "su_auth"}
        ]
        detections: list[Detection] = []

        for username, group in group_by(sudo_failures, lambda e: e.username).items():
            for burst in sliding_windows(
                group,
                window_seconds=self.settings.sudo_failure_window,
                min_size=self.settings.sudo_failure_threshold,
            ):
                not_in_sudoers = any(e.event_type == "sudo_not_permitted" for e in burst)
                hostname = burst[0].hostname

                detections.append(Detection(
                    rule_id=self.rule_id,
                    title=f"Попытки повышения привилегий: {username}",
                    description=(
                        f"Пользователь «{username}» на хосте {hostname} совершил "
                        f"{len(burst)} неудачных попыток выполнить sudo. "
                        + ("Учётная запись вообще отсутствует в sudoers — "
                           "попытка выйти за пределы своих прав. " if not_in_sudoers else "")
                        + "В сочетании с внешним входом это типичный второй шаг "
                        "атаки: закрепиться и повысить привилегии."
                    ),
                    severity=Severity.HIGH if not_in_sudoers else Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    mitre=[mitre.T1548_003],
                    entities={"username": username, "hostname": hostname},
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    event_count=len(burst),
                    evidence=burst,
                    metrics={"failed_sudo_attempts": len(burst),
                             "not_in_sudoers": not_in_sudoers},
                    recommendation=(
                        "Уточнить у владельца учётной записи, его ли это действия. "
                        "Проверить, как был выполнен вход в систему под этим "
                        "пользователем и с какого адреса. Просмотреть историю "
                        "команд и содержимое sudoers на предмет изменений."
                    ),
                ))

        logger.debug("%s: срабатываний %d", self.rule_id, len(detections))
        return detections


class AccountLockoutRule(DetectionRule):
    """Блокировки учётных записей (Windows 4740)."""

    rule_id = "AUTH-007"
    primary_techniques = ("T1531", "T1110")
    title = "Блокировка учётных записей"
    description = "Учётные записи блокируются политикой — как правило, из-за перебора."

    def run(self, events: Sequence[AuthEvent]) -> list[Detection]:
        lockouts = [e for e in events if e.event_type == "windows_account_lockout"]
        if not lockouts:
            return []

        accounts = sorted({e.username for e in lockouts if e.username})
        mass = len(accounts) >= 5

        return [Detection(
            rule_id=self.rule_id,
            title=(f"Массовая блокировка учётных записей: {len(accounts)}"
                   if mass else f"Блокировка учётных записей: {', '.join(accounts)}"),
            description=(
                f"Зафиксировано {len(lockouts)} событий блокировки "
                f"({len(accounts)} учётных записей). Блокировка срабатывает после "
                "превышения порога неудачных входов, то есть является следствием "
                "перебора."
                + (" Массовый характер указывает либо на широкую атаку, либо на "
                   "намеренный отказ в обслуживании: заблокированные сотрудники "
                   "не могут работать." if mass else "")
            ),
            severity=Severity.HIGH if mass else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            mitre=[mitre.T1531] if mass else [mitre.T1110],
            entities={"usernames": accounts[:30]},
            first_seen=lockouts[0].timestamp,
            last_seen=lockouts[-1].timestamp,
            event_count=len(lockouts),
            evidence=lockouts,
            metrics={"locked_accounts": len(accounts), "lockout_events": len(lockouts)},
            recommendation=(
                "Найти источник неудачных входов (события 4625 по тем же учётным "
                "записям) и заблокировать его. Проверить, не связаны ли блокировки "
                "с устаревшими сохранёнными паролями в службах и планировщике — "
                "частая причина ложных блокировок."
            ),
        )]
