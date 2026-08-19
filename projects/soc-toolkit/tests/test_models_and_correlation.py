"""Тесты единой модели и кросс-инструментальной корреляции."""

import pytest

from soc_toolkit.correlation import correlate, escalate_cross_tool
from soc_toolkit.models import Confidence, Finding, Severity, Source


def test_severity_scale_is_ordered():
    assert (Severity.CRITICAL.score > Severity.HIGH.score
            > Severity.MEDIUM.score > Severity.LOW.score > Severity.INFO.score)


def test_severity_parse_falls_back():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse("чепуха") is Severity.INFO
    assert Severity.parse("чепуха", Severity.LOW) is Severity.LOW


def test_finding_id_is_stable(finding_factory):
    """Идентификатор не должен меняться между прогонами: иначе нельзя
    сравнивать отчёты и отслеживать динамику."""
    first = finding_factory(ip="192.0.2.1")
    second = finding_factory(ip="192.0.2.1")
    assert first.finding_id == second.finding_id


def test_finding_id_differs_for_different_entities(finding_factory):
    assert (finding_factory(ip="192.0.2.1").finding_id
            != finding_factory(ip="192.0.2.2").finding_id)


def test_entity_values_flattens_lists(finding_factory):
    finding = finding_factory(ip=["192.0.2.1", "192.0.2.2"], username="root")
    assert sorted(finding.entity_values()) == ["192.0.2.1", "192.0.2.2", "root"]


# ---------------------------------------------------------------- корреляция

def test_findings_sharing_an_ip_are_grouped(finding_factory):
    findings = [
        finding_factory(source=Source.IOC, ip="192.0.2.66"),
        finding_factory(source=Source.LOGS, ip="192.0.2.66"),
    ]
    groups = correlate(findings)
    assert len(groups) == 1
    assert groups[0].key == "192.0.2.66"
    assert groups[0].is_cross_tool is True


def test_single_finding_is_not_a_group(finding_factory):
    assert correlate([finding_factory(ip="192.0.2.66")]) == []


def test_same_tool_findings_are_not_cross_tool(finding_factory):
    findings = [
        finding_factory(source=Source.LOGS, rule_id="AUTH-001", ip="192.0.2.66"),
        finding_factory(source=Source.LOGS, rule_id="AUTH-005", ip="192.0.2.66"),
    ]
    groups = correlate(findings)
    assert len(groups) == 1
    assert groups[0].is_cross_tool is False


def test_hostname_is_skipped_by_default(finding_factory):
    """Иначе все находки триажа с одного хоста склеятся в бессмысленную группу."""
    findings = [
        finding_factory(source=Source.TRIAGE, rule_id="T-1", hostname="web01"),
        finding_factory(source=Source.TRIAGE, rule_id="T-2", hostname="web01"),
    ]
    assert correlate(findings) == []
    assert len(correlate(findings, skip_keys=())) == 1


def test_generic_values_do_not_correlate(finding_factory):
    findings = [
        finding_factory(source=Source.IOC, ip="-"),
        finding_factory(source=Source.LOGS, ip="-"),
    ]
    assert correlate(findings) == []


def test_cross_tool_groups_come_first(finding_factory):
    findings = [
        finding_factory(source=Source.LOGS, rule_id="A", ip="192.0.2.1"),
        finding_factory(source=Source.LOGS, rule_id="B", ip="192.0.2.1"),
        finding_factory(source=Source.IOC, rule_id="C", ip="192.0.2.2"),
        finding_factory(source=Source.LOGS, rule_id="D", ip="192.0.2.2"),
    ]
    groups = correlate(findings)
    assert groups[0].is_cross_tool is True


# ----------------------------------------------------------------- эскалация

def test_cross_tool_confirmation_raises_severity(finding_factory):
    """Независимое подтверждение — сильнейший доступный сигнал."""
    ioc = finding_factory(source=Source.IOC, severity=Severity.MEDIUM,
                          ip="192.0.2.66")
    logs = finding_factory(source=Source.LOGS, severity=Severity.HIGH,
                           ip="192.0.2.66")
    groups = correlate([ioc, logs])
    escalated = escalate_cross_tool([ioc, logs], groups)

    assert escalated == 1
    assert ioc.severity is Severity.HIGH
    assert "подтверждена независимо" in ioc.description


def test_escalation_stops_at_high(finding_factory):
    """Повышение только до HIGH: иначе уровень CRITICAL обесценится."""
    first = finding_factory(source=Source.IOC, severity=Severity.HIGH,
                            ip="192.0.2.66")
    second = finding_factory(source=Source.LOGS, severity=Severity.HIGH,
                             ip="192.0.2.66")
    escalate_cross_tool([first, second], correlate([first, second]))
    assert first.severity is Severity.HIGH
    assert second.severity is Severity.HIGH


def test_no_escalation_without_cross_tool(finding_factory):
    findings = [
        finding_factory(source=Source.LOGS, rule_id="A", severity=Severity.LOW,
                        ip="192.0.2.66"),
        finding_factory(source=Source.LOGS, rule_id="B", severity=Severity.LOW,
                        ip="192.0.2.66"),
    ]
    assert escalate_cross_tool(findings, correlate(findings)) == 0
    assert all(f.severity is Severity.LOW for f in findings)


def test_finding_is_escalated_once(finding_factory):
    """Находка, попавшая в две подтверждённые группы, не должна расти дважды."""
    shared = finding_factory(source=Source.IOC, severity=Severity.LOW,
                             ip="192.0.2.66", username="root")
    other_ip = finding_factory(source=Source.LOGS, rule_id="X",
                               severity=Severity.HIGH, ip="192.0.2.66")
    other_user = finding_factory(source=Source.TRIAGE, rule_id="Y",
                                 severity=Severity.HIGH, username="root")
    findings = [shared, other_ip, other_user]
    escalate_cross_tool(findings, correlate(findings))
    assert shared.severity is Severity.MEDIUM
