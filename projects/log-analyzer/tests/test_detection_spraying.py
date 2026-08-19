"""Тесты password spraying и разведки имён учётных записей."""

from tests.helpers import event, failures

from log_analyzer.detection.bruteforce import BruteForceRule
from log_analyzer.detection.spraying import PasswordSprayingRule, UserEnumerationRule
from log_analyzer.models import EventOutcome, Severity


def spray_events(users: int, attempts: int = 2, source_ip: str = "192.0.2.77"):
    """Распыление: много логинов, мало попыток на каждый."""
    events = []
    for index in range(users):
        for attempt in range(attempts):
            events.append(event(seconds=index * 30 + attempt * 5,
                                username=f"user{index}", source_ip=source_ip))
    return sorted(events, key=lambda e: e.timestamp)


def test_spraying_detected(settings):
    found = PasswordSprayingRule(settings).run(spray_events(users=8))
    assert len(found) == 1
    assert found[0].rule_id == "AUTH-003"
    assert found[0].metrics["distinct_users"] == 8
    assert "T1110.003" in [t.technique_id for t in found[0].mitre]


def test_bruteforce_rule_is_blind_to_spraying(settings):
    """Главный смысл отдельного правила: детект перебора такую атаку не видит."""
    events = spray_events(users=8, attempts=2)
    assert BruteForceRule(settings).run(events) == []
    assert PasswordSprayingRule(settings).run(events) != []


def test_too_few_users_does_not_trigger(settings):
    assert PasswordSprayingRule(settings).run(spray_events(users=3)) == []


def test_many_attempts_per_user_is_bruteforce_not_spraying(settings):
    """Если по каждому логину много попыток — это AUTH-001, а не распыление."""
    events = spray_events(users=8, attempts=10)
    assert PasswordSprayingRule(settings).run(events) == []


def test_invalid_users_excluded_from_spraying(settings):
    """Перебор несуществующих логинов — разведка (T1087), а не распыление."""
    events = []
    for index in range(8):
        events.append(event(seconds=index * 10, username=f"ghost{index}",
                            invalid_user=True))
    assert PasswordSprayingRule(settings).run(events) == []
    assert UserEnumerationRule(settings).run(events) != []


def test_successful_spray_is_critical(settings):
    """Если один из паролей подошёл — это уже компрометация."""
    events = spray_events(users=8)
    events.append(event(seconds=400, outcome=EventOutcome.SUCCESS,
                        username="user3", source_ip="192.0.2.77"))
    found = PasswordSprayingRule(settings).run(events)
    assert found[0].severity is Severity.CRITICAL
    assert "user3" in found[0].metrics["compromised_accounts"]


def test_success_after_burst_still_counts(settings):
    """Успех приходит ПОСЛЕ перебора списка — это нормальный ход атаки."""
    events = spray_events(users=8)           # последняя неудача ~ на 245 с
    events.append(event(seconds=900, outcome=EventOutcome.SUCCESS,
                        username="user1", source_ip="192.0.2.77"))
    found = PasswordSprayingRule(settings).run(events)
    assert found[0].metrics["compromised_accounts"] == ["user1"]


def test_enumeration_requires_invalid_users(settings):
    """Разведка — это обращения к НЕСУЩЕСТВУЮЩИМ учётным записям."""
    valid = [event(seconds=i * 10, username=f"user{i}") for i in range(8)]
    assert UserEnumerationRule(settings).run(valid) == []


def test_enumeration_detected(settings):
    events = [event(seconds=i * 10, username=f"ghost{i}", invalid_user=True)
              for i in range(6)]
    found = UserEnumerationRule(settings).run(events)
    assert len(found) == 1
    assert found[0].metrics["distinct_invalid_users"] == 6
    assert [t.technique_id for t in found[0].mitre] == ["T1087"]
