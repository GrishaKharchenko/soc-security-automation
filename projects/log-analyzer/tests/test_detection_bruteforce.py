"""Тесты детектов перебора пароля."""

from tests.helpers import event, failures

from log_analyzer.detection.bruteforce import BruteForceRule, DistributedBruteForceRule
from log_analyzer.models import EventOutcome, Severity


def test_burst_above_threshold_triggers(settings):
    events = failures(6, step=10)
    found = BruteForceRule(settings).run(events)
    assert len(found) == 1
    assert found[0].rule_id == "AUTH-001"
    assert found[0].event_count == 6
    assert "T1110.001" in [t.technique_id for t in found[0].mitre]


def test_below_threshold_does_not_trigger(settings):
    """Порог 5: четыре неудачи — это забытый пароль, а не атака."""
    assert BruteForceRule(settings).run(failures(4, step=10)) == []


def test_slow_attempts_outside_window_do_not_trigger(settings):
    """Шесть попыток за сутки — не перебор: окно 300 с."""
    assert BruteForceRule(settings).run(failures(6, step=4000)) == []


def test_one_burst_yields_one_detection(settings):
    """50 попыток подряд должны дать ОДИН алерт, а не 45."""
    found = BruteForceRule(settings).run(failures(50, step=5))
    assert len(found) == 1
    assert found[0].event_count == 50


def test_two_separate_waves_yield_two_detections(settings):
    events = failures(6, step=10) + failures(6, step=10, start=7200)
    found = BruteForceRule(settings).run(events)
    assert len(found) == 2


def test_different_users_are_not_mixed(settings):
    """Ключ группировки — пара (пользователь, источник)."""
    events = failures(3, step=10, username="alice") + \
             failures(3, step=10, start=1, username="bob")
    assert BruteForceRule(settings).run(events) == []


def test_different_sources_are_not_mixed(settings):
    events = failures(3, step=10, source_ip="192.0.2.1") + \
             failures(3, step=10, start=1, source_ip="192.0.2.2")
    assert BruteForceRule(settings).run(events) == []


def test_successful_breach_is_critical(settings):
    """Успех после перебора с того же адреса — компрометация."""
    events = failures(6, step=10) + [event(seconds=70, outcome=EventOutcome.SUCCESS)]
    found = BruteForceRule(settings).run(events)
    assert found[0].severity is Severity.CRITICAL
    assert found[0].metrics["successful_breach"] is True
    assert "T1078" in [t.technique_id for t in found[0].mitre]


def test_privileged_account_raises_severity(settings):
    normal = BruteForceRule(settings).run(failures(5, step=30, username="alice"))
    root = BruteForceRule(settings).run(failures(5, step=30, username="root"))
    assert root[0].severity.score > normal[0].severity.score
    assert root[0].metrics["privileged_account"] is True


def test_successes_alone_do_not_trigger(settings):
    events = [event(seconds=i * 10, outcome=EventOutcome.SUCCESS) for i in range(10)]
    assert BruteForceRule(settings).run(events) == []


def test_distributed_attack_detected(settings):
    """Мало попыток с каждого адреса — основной порог молчит, нужен AUTH-002."""
    events = []
    for index in range(5):
        events += failures(2, step=10, start=index * 100,
                           source_ip=f"203.0.113.{index}", username="admin")
    assert BruteForceRule(settings).run(events) == []

    found = DistributedBruteForceRule(settings).run(events)
    assert len(found) == 1
    assert found[0].metrics["distinct_sources"] == 5


def test_distributed_requires_enough_sources(settings):
    events = failures(6, step=10, source_ip="192.0.2.1", username="admin")
    assert DistributedBruteForceRule(settings).run(events) == []
