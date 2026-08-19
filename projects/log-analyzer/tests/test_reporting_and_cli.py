"""Тесты отчётов, конфигурации и CLI — конвейер целиком."""

import csv
import json

import pytest

from tests.helpers import event, failures

from log_analyzer.analyzer import LogAnalyzer
from log_analyzer.cli import EXIT_CRITICAL, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from log_analyzer.config import ConfigError, Settings, load_settings
from log_analyzer.detection.engine import DetectionEngine, correlate
from log_analyzer.models import CSV_COLUMNS, EventOutcome, Severity
from log_analyzer.reporting.writers import build_summary, write_csv, write_json

SAMPLE_LOG = """\
Aug 18 12:00:00 web01 sshd[1]: Failed password for root from 192.0.2.66 port 1 ssh2
Aug 18 12:00:10 web01 sshd[2]: Failed password for root from 192.0.2.66 port 2 ssh2
Aug 18 12:00:20 web01 sshd[3]: Failed password for root from 192.0.2.66 port 3 ssh2
Aug 18 12:00:30 web01 sshd[4]: Failed password for root from 192.0.2.66 port 4 ssh2
Aug 18 12:00:40 web01 sshd[5]: Failed password for root from 192.0.2.66 port 5 ssh2
Aug 18 12:00:50 web01 sshd[6]: Failed password for root from 192.0.2.66 port 6 ssh2
Aug 18 12:01:00 web01 sshd[7]: Accepted password for root from 192.0.2.66 port 7 ssh2
"""


@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(SAMPLE_LOG, encoding="utf-8")
    return path


@pytest.fixture
def findings(settings):
    events = failures(6, step=10, source_ip="192.0.2.66") + \
             [event(seconds=70, outcome=EventOutcome.SUCCESS, source_ip="192.0.2.66")]
    detections = DetectionEngine(settings).run(events)
    return detections, correlate(detections)


# ------------------------------------------------------------------ отчёты

def test_json_report_structure(findings, tmp_path):
    detections, incidents = findings
    path = write_json(detections, incidents, tmp_path, metadata={"sources": ["x.log"]})
    document = json.loads(path.read_text(encoding="utf-8"))

    assert document["report"]["tool"] == "soc-log-analyzer"
    assert document["report"]["sources"] == ["x.log"]
    assert document["summary"]["total_detections"] == len(detections)
    assert "T1110.001" in document["summary"]["mitre_techniques"]
    assert document["detections"][0]["mitre"][0]["rationale"]


def test_json_keeps_cyrillic_readable(findings, tmp_path):
    path = write_json(*findings, tmp_path)
    assert "Подбор пароля" in path.read_text(encoding="utf-8")


def test_csv_report_structure(findings, tmp_path):
    detections, incidents = findings
    path = write_csv(detections, incidents, tmp_path)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert rows[0]["severity"] == "critical"
    assert rows[0]["incident_id"].startswith("INC-")


def test_csv_has_bom_for_excel(findings, tmp_path):
    path = write_csv(*findings, tmp_path)
    assert path.read_bytes().startswith(b"\xef\xbb\xbf")


def test_summary_counts_tactics(findings):
    summary = build_summary(*findings)
    assert summary["total_detections"] > 0
    assert "Credential Access" in summary["mitre_tactics"]


def test_empty_reports_do_not_crash(tmp_path):
    assert write_json([], [], tmp_path).exists()
    assert write_csv([], [], tmp_path).exists()


# ------------------------------------------------------------ конфигурация

def test_env_file_is_loaded(tmp_path, monkeypatch):
    monkeypatch.delenv("BRUTEFORCE_THRESHOLD", raising=False)
    env = tmp_path / ".env"
    env.write_text("BRUTEFORCE_THRESHOLD=42\nLOG_TIMEZONE=Europe/Moscow\n",
                   encoding="utf-8")
    settings = load_settings(env)
    assert settings.bruteforce_threshold == 42
    assert settings.timezone == "Europe/Moscow"


def test_invalid_threshold_rejected():
    with pytest.raises(ConfigError, match="BRUTEFORCE_THRESHOLD"):
        Settings(bruteforce_threshold=0).validate()


def test_invalid_timezone_rejected():
    with pytest.raises(ConfigError, match="часовой пояс"):
        Settings(timezone="Планета/Марс").validate()


def test_business_hours_validation():
    with pytest.raises(ConfigError):
        Settings(business_hours_start=20, business_hours_end=8).validate()


# ------------------------------------------------------------------- CLI

def test_analyze_writes_both_reports(log_file, tmp_path):
    code = main(["analyze", "-i", str(log_file), "-q", "--year", "2026",
                 "-o", str(tmp_path / "out"), "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_CRITICAL          # подбор завершился успешным входом
    assert len(list((tmp_path / "out").glob("*.json"))) == 1
    assert len(list((tmp_path / "out").glob("*.csv"))) == 1


def test_exit_code_without_findings(tmp_path):
    quiet = tmp_path / "quiet.log"
    quiet.write_text("Aug 18 12:00:00 web01 sshd[1]: Accepted password for alice "
                     "from 198.51.100.5 port 1 ssh2\n", encoding="utf-8")
    code = main(["analyze", "-i", str(quiet), "-q", "--year", "2026",
                 "-f", "none", "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_OK


def test_min_severity_filter(log_file, tmp_path, capsys):
    code = main(["analyze", "-i", str(log_file), "-q", "--year", "2026",
                 "-f", "none", "--min-severity", "critical",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_CRITICAL


def test_rules_filter(log_file, tmp_path, capsys):
    main(["analyze", "-i", str(log_file), "-q", "--year", "2026", "-f", "none",
          "--rules", "AUTH-001", "--env-file", str(tmp_path / "нет.env")])
    assert "AUTH-005" not in capsys.readouterr().out


def test_unknown_rule_is_usage_error(log_file, tmp_path, capsys):
    code = main(["analyze", "-i", str(log_file), "-q", "--rules", "AUTH-999",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_USAGE


def test_missing_file_is_usage_error(tmp_path, capsys):
    code = main(["analyze", "-i", str(tmp_path / "нет.log"), "-q",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_USAGE
    assert "не найден" in capsys.readouterr().err


def test_unknown_format_is_usage_error(tmp_path, capsys):
    weird = tmp_path / "weird.log"
    weird.write_text("это не похоже ни на один известный формат логов\n" * 5,
                     encoding="utf-8")
    code = main(["analyze", "-i", str(weird), "-q",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_USAGE


def test_events_subcommand(log_file, tmp_path, capsys):
    code = main(["events", "-i", str(log_file), "-q", "--year", "2026",
                 "--env-file", str(tmp_path / "нет.env")])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "192.0.2.66" in out
    assert "Всего событий: 7" in out


def test_rules_subcommand_lists_techniques(capsys):
    assert main(["rules"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "AUTH-001" in out and "T1110.001" in out


def test_multiple_files_are_merged(tmp_path, log_file):
    """События из разных источников должны попасть в общую хронологию."""
    windows = tmp_path / "sec.csv"
    windows.write_text(
        "TimeCreated,Id,Computer,TargetUserName,IpAddress,IpPort,LogonType,Status\n"
        "2026-08-18T12:00:05Z,4625,DC01,admin,192.0.2.99,1,3,0xc000006a\n",
        encoding="utf-8")

    from log_analyzer.parsers.registry import load_events
    settings = Settings(default_year=2026, output_dir=tmp_path)
    events, stats = load_events([log_file, windows], settings)

    assert len(events) == 8
    assert events == sorted(events, key=lambda e: e.timestamp)
    assert {e.platform.value for e in events} == {"linux", "windows"}


def test_bad_argument_exits_with_usage_code(log_file):
    """Код 2 занят под «есть критические находки», поэтому ошибка в
    аргументах обязана давать 3, а не 2."""
    with pytest.raises(SystemExit) as exit_info:
        main(["analyze", "-i", str(log_file), "--parser", "чепуха"])
    assert exit_info.value.code == EXIT_USAGE


def test_unknown_subcommand_exits_with_usage_code():
    with pytest.raises(SystemExit) as exit_info:
        main(["чепуха"])
    assert exit_info.value.code == EXIT_USAGE
