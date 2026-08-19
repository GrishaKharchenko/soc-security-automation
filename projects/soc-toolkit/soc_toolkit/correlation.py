"""Кросс-инструментальная корреляция находок.

Ради этого объединение и делалось. Каждый инструмент по отдельности видит
свой срез:

* IOC Analyzer  — «адрес 192.0.2.66 помечен как вредоносный»;
* Log Analyzer  — «с адреса 192.0.2.66 шёл перебор пароля к root»;
* Linux Triage  — «на хосте появился новый SSH-ключ».

По отдельности первая находка — рутина (вредоносных адресов в любом фиде
сотни), вторая — фоновый шум для сервера в интернете, третья — возможно,
плановая работа админа. Вместе это одна атака, доведённая до закрепления.

Связывание идёт по значениям сущностей: адресам, учётным записям, доменам,
хешам, именам хостов. Ключевой признак — ``cross_tool_confirmation``:
подтверждение из нескольких независимых источников резко повышает
достоверность и должно поднимать приоритет разбора.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

from .logging_setup import get_logger
from .models import CorrelatedGroup, Finding, Severity

logger = get_logger("correlation")

# Поля сущностей, по которым имеет смысл связывать находки. Порядок задаёт
# приоритет типа ключа при отображении.
CORRELATION_KEYS: tuple[str, ...] = (
    "ip", "domain", "url", "hash", "username", "hostname",
)

# Значения, которые встречаются почти в каждой находке и связывают всё со
# всем, не неся информации. Имя хоста здесь особенно коварно: при разборе
# логов одного сервера оно одинаково у всех находок.
GENERIC_VALUES: frozenset[str] = frozenset({
    "-", "unknown", "неизвестный хост", "n/a", "none", "root@localhost",
})


def correlate(
    findings: Sequence[Finding],
    min_group_size: int = 2,
    skip_keys: Sequence[str] = ("hostname",),
) -> list[CorrelatedGroup]:
    """Сгруппировать находки по общим сущностям.

    ``skip_keys`` по умолчанию исключает имя хоста: в рамках одного прогона
    оно одинаково у всех находок триажа и склеило бы их в одну бессмысленную
    группу. Связывание по нему включается явно, когда анализируются данные
    нескольких хостов.
    """
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)

    for finding in findings:
        for key_type in CORRELATION_KEYS:
            if key_type in skip_keys:
                continue
            value = finding.entities.get(key_type)
            if not value:
                continue
            values = value if isinstance(value, (list, tuple, set)) else [value]
            for item in values:
                text = str(item).strip()
                if not text or text.lower() in GENERIC_VALUES:
                    continue
                buckets[(key_type, text)].append(finding)

    groups: list[CorrelatedGroup] = []
    for (key_type, key_value), group_findings in buckets.items():
        # Дедупликация: одна находка могла попасть в группу дважды, если
        # сущность указана и в единственном, и во множественном поле.
        unique: dict[str, Finding] = {f.finding_id: f for f in group_findings}
        if len(unique) < min_group_size:
            continue
        groups.append(CorrelatedGroup(
            key=key_value, key_type=key_type,
            findings=sorted(unique.values(), key=lambda f: -f.severity.score),
        ))

    # Сначала подтверждённые несколькими инструментами, затем по критичности.
    groups.sort(key=lambda g: (not g.is_cross_tool, -g.severity.score, g.key))

    cross_tool = sum(1 for g in groups if g.is_cross_tool)
    logger.info("Корреляция: %d групп, из них подтверждённых несколькими "
                "инструментами: %d", len(groups), cross_tool)
    return groups


def escalate_cross_tool(
    findings: Sequence[Finding], groups: Sequence[CorrelatedGroup]
) -> int:
    """Повысить критичность находок, подтверждённых другим инструментом.

    Обоснование: независимое подтверждение — сильнейший из доступных сигналов.
    Адрес, который одновременно числится вредоносным в Threat Intelligence и
    фигурирует в логах как источник перебора, — это уже не гипотеза.

    Повышение ровно на один уровень и только до HIGH: превращать всё
    подтверждённое в CRITICAL значит обесценить сам уровень.
    """
    ladder = {
        Severity.INFO: Severity.LOW,
        Severity.LOW: Severity.MEDIUM,
        Severity.MEDIUM: Severity.HIGH,
    }
    escalated: set[str] = set()

    for group in groups:
        if not group.is_cross_tool:
            continue
        for finding in group.findings:
            new_severity = ladder.get(finding.severity)
            if new_severity and finding.finding_id not in escalated:
                logger.info("Повышаю критичность %s: %s -> %s "
                            "(подтверждено источниками: %s)",
                            finding.title[:50], finding.severity.value,
                            new_severity.value, ", ".join(group.sources))
                finding.severity = new_severity
                finding.description += (
                    f" Находка подтверждена независимо несколькими "
                    f"инструментами набора ({', '.join(group.sources)}) "
                    f"по общей сущности {group.key_type}={group.key}, "
                    "поэтому критичность повышена."
                )
                escalated.add(finding.finding_id)

    return len(escalated)
