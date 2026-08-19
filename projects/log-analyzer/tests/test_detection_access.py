"""Тесты правил вокруг успешного доступа."""

from tests.helpers import event, failures

from log_analyzer.detection.access import (
    AccountLockoutRule, PrivilegeAbuseRule, SuccessAfterFailuresRule,
)
from log_analyzer.models import Confidence, EventOutcome, Severity


def test_success_after_failures_detected(settings):
    events = failures(4, step=20) + [event(seconds=100, outcome=EventOutcome.SUCCESS)]
    found = SuccessAfterFailuresRule(settings).run(events)
    assert len(found) == 1
    assert found[0].rule_id == "AUTH-005"
    assert found[0].metrics["preceding_failures"] == 4


def test_too_few_preceding_failures(settings):
    """Порог 3: две ошибки перед входом — обычное дело."""
    events = failures(2, step=20) + [event(seconds=100, outcome=EventOutcome.SUCCESS)]
    assert SuccessAfterFailuresRule(settings).run(events) == []


def test_failures_outside_window_are_ignored(settings):
    events = failures(4, step=20) + [event(seconds=99999,
                                           outcome=EventOutcome.SUCCESS)]
    assert SuccessAfterFailuresRule(settings).run(events) == []


def test_same_source_is_critical(settings):
    events = failures(4, step=20, source_ip="192.0.2.66") + \
             [event(seconds=100, outcome=EventOutcome.SUCCESS,
                    source_ip="192.0.2.66")]
    found = SuccessAfterFailuresRule(settings).run(events)
    assert found[0].severity is Severity.CRITICAL
    assert found[0].metrics["same_source"] is True


def test_different_source_is_less_certain(settings):
    events = failures(4, step=20, source_ip="192.0.2.66") + \
             [event(seconds=100, outcome=EventOutcome.SUCCESS,
                    source_ip="198.51.100.9")]
    found = SuccessAfterFailuresRule(settings).run(events)
    assert found[0].severity is Severity.HIGH
    assert found[0].confidence is Confidence.MEDIUM


def test_familiar_source_is_downgraded(settings):
    """Пользователь уже входил с этого адреса — вероятнее забытый пароль.

    Регрессия на ложное срабатывание, найденное при прогоне по тестовым логам:
    сотрудник трижды ошибся паролем на своём же рабочем месте и получил
    вердикт «вероятная компрометация» с критической важностью.
    """
    events = [event(seconds=0, outcome=EventOutcome.SUCCESS,
                    source_ip="198.51.100.12")]
    events += failures(4, step=20, start=1000, source_ip="198.51.100.12")
    events.append(event(seconds=1100, outcome=EventOutcome.SUCCESS,
                        source_ip="198.51.100.12"))

    found = SuccessAfterFailuresRule(settings).run(events)
    assert len(found) == 1
    assert found[0].severity is Severity.MEDIUM
    assert found[0].confidence is Confidence.LOW
    assert found[0].metrics["source_previously_used_by_account"] is True


def test_intervening_success_breaks_the_series(settings):
    """Успешный вход в середине серии означает, что подбора не было."""
    events = (failures(2, step=10)
              + [event(seconds=25, outcome=EventOutcome.SUCCESS)]
              + failures(2, step=10, start=30)
              + [event(seconds=60, outcome=EventOutcome.SUCCESS)])
    assert SuccessAfterFailuresRule(settings).run(events) == []


def test_sudo_failures_detected(settings):
    events = failures(4, step=30, event_type="sudo_auth",
                      source_ip=None, username="backup")
    found = PrivilegeAbuseRule(settings).run(events)
    assert len(found) == 1
    assert found[0].rule_id == "AUTH-006"
    assert [t.technique_id for t in found[0].mitre] == ["T1548.003"]


def test_not_in_sudoers_raises_severity(settings):
    plain = PrivilegeAbuseRule(settings).run(
        failures(3, step=30, event_type="sudo_auth", source_ip=None))
    escalated = PrivilegeAbuseRule(settings).run(
        failures(3, step=30, event_type="sudo_not_permitted", source_ip=None))
    assert escalated[0].severity.score > plain[0].severity.score
    assert escalated[0].metrics["not_in_sudoers"] is True


def test_mass_lockout_is_high(settings):
    events = [event(seconds=i * 20, username=f"user{i}",
                    event_type="windows_account_lockout") for i in range(6)]
    found = AccountLockoutRule(settings).run(events)
    assert found[0].severity is Severity.HIGH
    assert found[0].metrics["locked_accounts"] == 6
    assert "T1531" in [t.technique_id for t in found[0].mitre]


def test_single_lockout_is_medium(settings):
    events = [event(seconds=0, username="alice",
                    event_type="windows_account_lockout")]
    found = AccountLockoutRule(settings).run(events)
    assert found[0].severity is Severity.MEDIUM


def test_no_lockouts_no_detection(settings):
    assert AccountLockoutRule(settings).run(failures(3)) == []
