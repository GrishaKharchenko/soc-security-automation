"""Тесты адаптеров: перевод результатов инструментов в общий формат."""

import json

import pytest

from soc_toolkit.adapters.base import AdapterError
from soc_toolkit.adapters.ioc import VERDICT_TO_SEVERITY, IOCAdapter
from soc_toolkit.adapters.triage import TriageAdapter, extract_entities
from soc_toolkit.models import Severity, Source

REPO_SAMPLE = "../linux-triage/samples/findings.json"


# ------------------------------------------------------------ адаптер IOC

def test_every_verdict_has_a_severity():
    """Новый вердикт не должен молча проваливаться в INFO."""
    from soc_toolkit.bootstrap import require
    require("ioc_analyzer")
    from ioc_analyzer.models import Verdict

    for verdict in Verdict:
        assert verdict.value in VERDICT_TO_SEVERITY, \
            f"вердикт {verdict.value} не сопоставлен с критичностью"


def test_error_verdict_is_not_dropped():
    """Индикатор, который не удалось проверить, должен остаться на виду."""
    assert VERDICT_TO_SEVERITY["error"] is not Severity.INFO
    assert VERDICT_TO_SEVERITY["unknown"] is not Severity.INFO


def test_clean_is_informational():
    assert VERDICT_TO_SEVERITY["clean"] is Severity.INFO


def test_ioc_adapter_offline(tmp_path):
    feed = tmp_path / "iocs.txt"
    feed.write_text("192.0.2.66\nexample.com\n", encoding="utf-8")

    findings = IOCAdapter().run(input_file=feed, offline=True,
                                include_clean=True,
                                env_file=str(tmp_path / "нет.env"))
    assert len(findings) == 2
    assert all(f.source is Source.IOC for f in findings)
    assert findings[0].entities.get("ip") or findings[0].entities.get("domain")


def test_ioc_adapter_filters_clean_by_default(tmp_path):
    feed = tmp_path / "iocs.txt"
    feed.write_text("192.0.2.66\n", encoding="utf-8")
    findings = IOCAdapter().run(input_file=feed, offline=True,
                                env_file=str(tmp_path / "нет.env"))
    assert findings == []


def test_ioc_adapter_maps_types_to_entities(tmp_path):
    feed = tmp_path / "iocs.txt"
    feed.write_text("192.0.2.66\nexample.com\n"
                    "d41d8cd98f00b204e9800998ecf8427e\n", encoding="utf-8")
    findings = IOCAdapter().run(input_file=feed, offline=True,
                                include_clean=True,
                                env_file=str(tmp_path / "нет.env"))
    keys = set()
    for finding in findings:
        keys |= set(finding.entities) - {"ioc_type"}
    assert keys == {"ip", "domain", "hash"}


def test_ioc_adapter_reports_missing_key(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "")
    feed = tmp_path / "iocs.txt"
    feed.write_text("192.0.2.66\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="--offline"):
        IOCAdapter().run(input_file=feed, offline=False,
                         env_file=str(tmp_path / "нет.env"))


# --------------------------------------------------------- адаптер триажа

def test_extract_ip_from_evidence():
    entities = extract_entities("Успешный вход с адреса 192.0.2.66",
                                "Accepted password from 192.0.2.66")
    assert entities["ip"] == ["192.0.2.66"]


def test_extract_account_from_title():
    entities = extract_entities("Учётная запись «backdoor» имеет UID 0", "")
    assert entities["username"] == ["backdoor"]


def test_wildcard_address_is_not_an_entity():
    """0.0.0.0 означает «все интерфейсы», а не конкретный узел."""
    assert extract_entities("tcp LISTEN 0.0.0.0:4444", "") == {}


def test_triage_adapter_parses_report(tmp_path):
    report = tmp_path / "findings.json"
    report.write_text(json.dumps({
        "hostname": "web01", "collected_as_root": True,
        "collected_at": "2026-08-18T21:00:00Z",
        "findings": [{"severity": "critical", "category": "accounts",
                      "title": "Учётная запись «evil» имеет UID 0",
                      "description": "описание", "evidence": "evil:x:0:0"}],
    }), encoding="utf-8")

    findings = TriageAdapter().run(report=report)
    assert len(findings) == 1
    assert findings[0].source is Source.TRIAGE
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].rule_id == "TRIAGE-ACCOUNTS"
    assert findings[0].entities["username"] == ["evil"]


def test_triage_adapter_warns_when_collected_without_root(tmp_path):
    """Неполный сбор нельзя выдавать за полную картину."""
    report = tmp_path / "findings.json"
    report.write_text(json.dumps({
        "hostname": "web01", "collected_as_root": False,
        "findings": [{"severity": "medium", "category": "network",
                      "title": "порт", "description": "описание"}],
    }), encoding="utf-8")

    findings = TriageAdapter().run(report=report)
    assert "без прав root" in findings[0].description


def test_triage_adapter_rejects_missing_report(tmp_path):
    with pytest.raises(AdapterError, match="не найден"):
        TriageAdapter().run(report=tmp_path / "нет.json")


def test_triage_adapter_rejects_broken_json(tmp_path):
    report = tmp_path / "findings.json"
    report.write_text("{это не json", encoding="utf-8")
    with pytest.raises(AdapterError, match="повреждён"):
        TriageAdapter().run(report=report)


def test_triage_adapter_requires_a_source():
    with pytest.raises(AdapterError, match="Не указан отчёт"):
        TriageAdapter().run()


def test_bundled_sample_report_parses():
    """Демонстрационный отчёт в репозитории должен оставаться разбираемым."""
    from pathlib import Path
    sample = Path(__file__).resolve().parents[2] / "linux-triage" / "samples" / "findings.json"
    findings = TriageAdapter().run(report=sample)
    assert len(findings) == 6
    assert any(f.severity is Severity.CRITICAL for f in findings)
    assert any("192.0.2.66" in (f.entities.get("ip") or []) for f in findings)
