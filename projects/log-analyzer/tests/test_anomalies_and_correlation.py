"""Тесты поведенческих аномалий, корреляции и движка."""

from datetime import timedelta

from tests.conftest import BASE_TIME
from tests.helpers import event, failures

from log_analyzer.detection.anomalies import NewSourceForUserRule, OffHoursLoginRule
from log_analyzer.detection.engine import DetectionEngine, correlate
from log_analyzer.models import EventOutcome, Severity


# ----------------------------------------------------------------- аномалии

def test_off_hours_login_detected(settings):
    """BASE_TIME — 12:00, рабочее окно 8–20, поэтому берём 03:00."""
    night = event(seconds=-9 * 3600, outcome=EventOutcome.SUCCESS)
    found = OffHoursLoginRule(settings).run([night])
    assert len(found) == 1
    assert found[0].severity is Severity.LOW      # слабый сигнал, не тревога


def test_business_hours_login_ignored(settings):
    assert OffHoursLoginRule(settings).run(
        [event(seconds=0, outcome=EventOutcome.SUCCESS)]) == []


def test_failures_are_not_off_hours_findings(settings):
    """Правило про успешные входы: неудачи покрыты другими правилами."""
    assert OffHoursLoginRule(settings).run(failures(3, start=-9 * 3600)) == []


def test_new_source_requires_baseline(settings):
    """Два входа — слишком короткая база, чтобы называть адрес непривычным."""
    events = [event(seconds=0, outcome=EventOutcome.SUCCESS, source_ip="198.51.100.1"),
              event(seconds=100, outcome=EventOutcome.SUCCESS, source_ip="203.0.113.9")]
    assert NewSourceForUserRule(settings).run(events) == []


def test_new_source_detected_with_baseline(settings):
    events = [event(seconds=i * 100, outcome=EventOutcome.SUCCESS,
                    source_ip="198.51.100.1") for i in range(3)]
    events.append(event(seconds=500, outcome=EventOutcome.SUCCESS,
                        source_ip="203.0.113.9"))
    found = NewSourceForUserRule(settings).run(events)
    assert len(found) == 1
    assert found[0].metrics["new_sources"] == 1


# ------------------------------------------------------------------ движок

def test_engine_runs_all_rules(settings):
    events = failures(6, step=10) + [event(seconds=70, outcome=EventOutcome.SUCCESS)]
    found = DetectionEngine(settings).run(events)
    rule_ids = {d.rule_id for d in found}
    assert "AUTH-001" in rule_ids
    assert "AUTH-005" in rule_ids


def test_engine_can_run_subset(settings):
    events = failures(6, step=10) + [event(seconds=70, outcome=EventOutcome.SUCCESS)]
    found = DetectionEngine(settings, enabled_rules=["AUTH-001"]).run(events)
    assert {d.rule_id for d in found} == {"AUTH-001"}


def test_engine_rejects_unknown_rule(settings):
    import pytest
    with pytest.raises(ValueError, match="Неизвестные правила"):
        DetectionEngine(settings, enabled_rules=["AUTH-999"])


def test_engine_survives_broken_rule(settings):
    """Сбой одного правила не должен останавливать анализ."""
    engine = DetectionEngine(settings, enabled_rules=["AUTH-001"])

    class Broken:
        rule_id = "AUTH-BROKEN"
        title = "падающее правило"

        def run(self, events):
            raise RuntimeError("умышленный сбой")

    engine.rules.insert(0, Broken())
    found = engine.run(failures(6, step=10))
    assert {d.rule_id for d in found} == {"AUTH-001"}


def test_engine_sorts_by_severity(settings):
    events = failures(6, step=10) + [event(seconds=70, outcome=EventOutcome.SUCCESS)]
    found = DetectionEngine(settings).run(events)
    scores = [d.severity.score for d in found]
    assert scores == sorted(scores, reverse=True)


# -------------------------------------------------------------- корреляция

def test_related_detections_form_one_incident(settings):
    """Перебор и последующий успех с одного адреса — один инцидент."""
    events = failures(6, step=10, source_ip="192.0.2.66") + \
             [event(seconds=70, outcome=EventOutcome.SUCCESS, source_ip="192.0.2.66")]
    found = DetectionEngine(settings, enabled_rules=["AUTH-001", "AUTH-005"]).run(events)
    incidents = correlate(found)
    assert len(incidents) == 1
    assert len(incidents[0].detections) == 2
    assert incidents[0].key_value == "192.0.2.66"


def test_unrelated_detections_stay_separate(settings):
    events = failures(6, step=10, source_ip="192.0.2.1", username="alice") + \
             failures(6, step=10, start=5000, source_ip="192.0.2.2", username="bob")
    incidents = correlate(DetectionEngine(settings, enabled_rules=["AUTH-001"]).run(events))
    assert len(incidents) == 2


def test_incident_severity_is_the_worst_of_its_detections(settings):
    events = failures(6, step=10, source_ip="192.0.2.66") + \
             [event(seconds=70, outcome=EventOutcome.SUCCESS, source_ip="192.0.2.66")]
    incidents = correlate(DetectionEngine(settings).run(events))
    assert incidents[0].severity is Severity.CRITICAL


def test_incident_collects_mitre_techniques(settings):
    events = failures(6, step=10, source_ip="192.0.2.66") + \
             [event(seconds=70, outcome=EventOutcome.SUCCESS, source_ip="192.0.2.66")]
    incidents = correlate(DetectionEngine(settings).run(events))
    assert "T1110.001" in incidents[0].mitre_techniques
    assert "T1078" in incidents[0].mitre_techniques


def test_multi_entity_detection_gets_its_own_incident(settings):
    """Массовая блокировка не должна называться именем первой учётной записи."""
    events = [event(seconds=i * 20, username=f"user{i}", source_ip=None,
                    event_type="windows_account_lockout") for i in range(6)]
    incidents = correlate(DetectionEngine(settings, enabled_rules=["AUTH-007"]).run(events))
    assert incidents[0].key_type == "rule"
    assert "user0" not in incidents[0].title
