"""Тесты CLI и сводных отчётов оболочки."""

import csv
import json
from pathlib import Path

import pytest

from soc_toolkit.cli import EXIT_CRITICAL, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from soc_toolkit.correlation import correlate
from soc_toolkit.models import CSV_COLUMNS, Severity, Source
from soc_toolkit.reporting.writers import (
    build_summary, render_console_summary, write_csv, write_json,
)

REPO = Path(__file__).resolve().parents[3]
IOC_SAMPLE = REPO / "projects" / "ioc-analyzer" / "data" / "sample_iocs.txt"
LOG_SAMPLE = REPO / "projects" / "log-analyzer" / "data" / "auth.log"
TRIAGE_SAMPLE = REPO / "projects" / "linux-triage" / "samples" / "findings.json"
TOOLKIT_IOCS = REPO / "projects" / "soc-toolkit" / "samples" / "incident_iocs.txt"


@pytest.fixture
def mixed_findings(finding_factory):
    findings = [
        finding_factory(source=Source.IOC, rule_id="IOC-MALICIOUS",
                        severity=Severity.HIGH, ip="192.0.2.66"),
        finding_factory(source=Source.LOGS, rule_id="AUTH-001",
                        severity=Severity.CRITICAL, ip="192.0.2.66",
                        username="root"),
        finding_factory(source=Source.TRIAGE, rule_id="TRIAGE-ACCOUNTS",
                        severity=Severity.MEDIUM, username="evil"),
    ]
    findings[1].mitre_techniques = [
        {"technique_id": "T1110.001", "name": "Password Guessing",
         "tactic": "Credential Access"}]
    return findings, correlate(findings)


# --------------------------------------------------------------- отчёты

def test_json_report_structure(mixed_findings, tmp_path):
    findings, groups = mixed_findings
    path = write_json(findings, groups, tmp_path, metadata={"modules": ["a"]})
    document = json.loads(path.read_text(encoding="utf-8"))

    assert document["report"]["tool"] == "soc-automation-toolkit"
    assert document["report"]["modules"] == ["a"]
    assert document["summary"]["total_findings"] == 3
    assert document["summary"]["by_source"]["ioc-analyzer"] == 1
    assert "T1110.001" in document["summary"]["mitre_techniques"]
    assert document["findings"][0]["severity"] == "critical"


def test_json_keeps_cyrillic_readable(mixed_findings, tmp_path):
    path = write_json(*mixed_findings, tmp_path)
    assert "тестовая находка" in path.read_text(encoding="utf-8")


def test_csv_report_structure(mixed_findings, tmp_path):
    findings, _ = mixed_findings
    path = write_csv(findings, tmp_path)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert rows[0]["severity"] == "critical"
    assert rows[0]["ip"] == "192.0.2.66"


def test_csv_has_bom_for_excel(mixed_findings, tmp_path):
    findings, _ = mixed_findings
    assert write_csv(findings, tmp_path).read_bytes().startswith(b"\xef\xbb\xbf")


def test_summary_counts_cross_tool(mixed_findings):
    findings, groups = mixed_findings
    summary = build_summary(findings, groups)
    assert summary["cross_tool_confirmations"] >= 1
    assert summary["by_source"]["linux-triage"] == 1


def test_console_summary_highlights_cross_tool(mixed_findings):
    text = render_console_summary(*mixed_findings)
    assert "ПОДТВЕРЖДЕНО НЕСКОЛЬКИМИ ИНСТРУМЕНТАМИ" in text
    assert "192.0.2.66" in text


def test_empty_reports_do_not_crash(tmp_path):
    assert write_json([], [], tmp_path).exists()
    assert write_csv([], tmp_path).exists()


# ------------------------------------------------------------------ CLI

def test_status_lists_modules(capsys):
    assert main(["status"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "IOC Analyzer" in out and "Linux Incident Triage" in out


def test_ioc_command_offline(tmp_path):
    code = main(["ioc", "-i", str(IOC_SAMPLE), "--offline", "--include-clean",
                 "-q", "-o", str(tmp_path / "out"), "-f", "json",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code in (EXIT_OK, EXIT_FINDINGS)
    assert len(list((tmp_path / "out").glob("*.json"))) == 1


def test_logs_command(tmp_path):
    code = main(["logs", "-i", str(LOG_SAMPLE), "--year", "2026", "-q",
                 "-o", str(tmp_path / "out"), "-f", "both",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_CRITICAL
    assert len(list((tmp_path / "out").glob("*.json"))) == 1
    assert len(list((tmp_path / "out").glob("*.csv"))) == 1


def test_triage_command_imports_report(tmp_path):
    code = main(["triage", "--report", str(TRIAGE_SAMPLE), "-q",
                 "-o", str(tmp_path / "out"), "-f", "json",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_CRITICAL

    document = json.loads(next((tmp_path / "out").glob("*.json"))
                          .read_text(encoding="utf-8"))
    assert document["summary"]["by_source"]["linux-triage"] == 6


def test_run_correlates_across_tools(tmp_path):
    """Главный сценарий набора: три инструмента сходятся на одном адресе."""
    code = main(["run",
                 "--iocs", str(TOOLKIT_IOCS), "--offline", "--include-clean",
                 "--logs", str(LOG_SAMPLE), "--year", "2026",
                 "--triage-report", str(TRIAGE_SAMPLE),
                 "-q", "-o", str(tmp_path / "out"), "-f", "json",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_CRITICAL

    document = json.loads(next((tmp_path / "out").glob("*.json"))
                          .read_text(encoding="utf-8"))
    assert set(document["report"]["modules"]) == {
        "ioc-analyzer", "log-analyzer", "linux-triage"}

    cross_tool = [g for g in document["correlations"]
                  if g["cross_tool_confirmation"]]
    assert cross_tool, "ожидалось подтверждение несколькими инструментами"

    attacker = next((g for g in cross_tool if g["key"] == "192.0.2.66"), None)
    assert attacker is not None
    assert len(attacker["sources"]) == 3


def test_run_requires_at_least_one_source(tmp_path, capsys):
    code = main(["run", "-q", "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_USAGE
    assert "Не указан ни один источник" in capsys.readouterr().err


def test_run_survives_a_failing_module(tmp_path, capsys):
    """Сбой одного модуля не должен отменять результаты остальных."""
    code = main(["run",
                 "--iocs", str(tmp_path / "нет-такого-файла.txt"), "--offline",
                 "--logs", str(LOG_SAMPLE), "--year", "2026",
                 "-q", "-o", str(tmp_path / "out"), "-f", "json",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_CRITICAL          # логи всё равно дали находки
    err = capsys.readouterr().err
    assert "Часть модулей не отработала" in err

    document = json.loads(next((tmp_path / "out").glob("*.json"))
                          .read_text(encoding="utf-8"))
    assert document["report"]["modules"] == ["log-analyzer"]
    assert document["report"]["failed_modules"]


def test_min_severity_filter(tmp_path, capsys):
    code = main(["logs", "-i", str(LOG_SAMPLE), "--year", "2026", "-q",
                 "-f", "none", "--min-severity", "critical",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_CRITICAL
    assert "МЕДИУМ" not in capsys.readouterr().out


def test_no_escalate_flag(tmp_path):
    """Флаг должен отключать повышение критичности."""
    code = main(["run",
                 "--iocs", str(TOOLKIT_IOCS), "--offline", "--include-clean",
                 "--logs", str(LOG_SAMPLE), "--year", "2026",
                 "--no-escalate", "-q", "-o", str(tmp_path / "out"),
                 "-f", "json", "--env-file", str(tmp_path / "нет.env")])
    assert code in (EXIT_FINDINGS, EXIT_CRITICAL)
    document = json.loads(next((tmp_path / "out").glob("*.json"))
                          .read_text(encoding="utf-8"))
    assert document["report"]["escalated_findings"] == 0


def test_missing_log_file_is_usage_error(tmp_path, capsys):
    code = main(["logs", "-i", str(tmp_path / "нет.log"), "-q",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_USAGE


def test_bad_argument_exits_with_usage_code():
    """Код 2 означает критические находки — ошибка в аргументах даёт 3."""
    with pytest.raises(SystemExit) as exit_info:
        main(["logs", "-i", "x.log", "--parser", "чепуха"])
    assert exit_info.value.code == EXIT_USAGE


def test_missing_required_argument_exits_with_usage_code():
    with pytest.raises(SystemExit) as exit_info:
        main(["ioc"])
    assert exit_info.value.code == EXIT_USAGE
