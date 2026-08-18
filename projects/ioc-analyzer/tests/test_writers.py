"""Тесты формирования отчётов."""

import csv
import json

import pytest

from ioc_analyzer.models import (
    CSV_COLUMNS, IOC, AnalysisResult, EnrichmentResult, EnrichmentStatus,
    IOCType, Verdict,
)
from ioc_analyzer.reporting.writers import (
    build_summary, render_console_summary, sort_results, write_csv, write_json,
)


@pytest.fixture
def results():
    def make(value, ioc_type, verdict, score, malicious=0):
        return AnalysisResult(
            ioc=IOC(value=value, type=ioc_type, raw=value),
            enrichment=EnrichmentResult(
                "virustotal", EnrichmentStatus.OK, malicious=malicious,
                harmless=70 - malicious, total_engines=70,
            ),
            verdict=verdict,
            risk_score=score,
            reasons=[f"тестовая причина для {value}"],
        )

    return [
        make("clean.test", IOCType.DOMAIN, Verdict.CLEAN, 0),
        make("bad.test", IOCType.DOMAIN, Verdict.MALICIOUS, 90, malicious=40),
        make("192.0.2.1", IOCType.IPV4, Verdict.SUSPICIOUS, 35, malicious=1),
        make("worse.test", IOCType.DOMAIN, Verdict.MALICIOUS, 100, malicious=60),
    ]


def test_results_sorted_by_severity_then_score(results):
    ordered = sort_results(results)
    assert [r.ioc.value for r in ordered] == [
        "worse.test", "bad.test", "192.0.2.1", "clean.test"
    ]


def test_summary_counts(results):
    summary = build_summary(results)
    assert summary["total_iocs"] == 4
    assert summary["by_verdict"]["malicious"] == 2
    assert summary["by_type"]["domain"] == 3
    assert summary["max_risk_score"] == 100
    assert summary["actionable"] == 3
    assert summary["top_risky"][0]["value"] == "worse.test"


def test_json_report_structure(results, tmp_path):
    path = write_json(results, tmp_path, metadata={"source_file": "feed.txt"})
    document = json.loads(path.read_text(encoding="utf-8"))

    assert document["report"]["tool"] == "ioc-analyzer"
    assert document["report"]["source_file"] == "feed.txt"
    assert document["summary"]["total_iocs"] == 4
    assert len(document["results"]) == 4
    assert document["results"][0]["ioc"]["value"] == "worse.test"
    assert document["results"][0]["enrichment"]["stats"]["detection_ratio"] == "60/70"


def test_json_keeps_cyrillic_readable(results, tmp_path):
    """ensure_ascii=False: отчёт читают люди, \\u0442\\u0435\\u0441\\u0442 в файле недопустим."""
    path = write_json(results, tmp_path)
    assert "тестовая причина" in path.read_text(encoding="utf-8")


def test_csv_report_structure(results, tmp_path):
    path = write_csv(results, tmp_path)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 4
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert rows[0]["value"] == "worse.test"
    assert rows[0]["verdict"] == "malicious"
    assert rows[0]["detection_ratio"] == "60/70"


def test_csv_has_bom_for_excel(results, tmp_path):
    """Без BOM Excel открывает кириллицу кракозябрами."""
    path = write_csv(results, tmp_path)
    assert path.read_bytes().startswith(b"\xef\xbb\xbf")


def test_reports_do_not_overwrite_each_other(results, tmp_path):
    first = write_json(results, tmp_path, timestamp="20260101_000000")
    second = write_json(results, tmp_path, timestamp="20260101_000001")
    assert first != second
    assert first.exists() and second.exists()


def test_output_directory_is_created(results, tmp_path):
    target = tmp_path / "глубоко" / "вложенный" / "путь"
    path = write_json(results, target)
    assert path.exists()


def test_empty_results_do_not_crash(tmp_path):
    assert write_json([], tmp_path).exists()
    assert write_csv([], tmp_path).exists()
    assert build_summary([])["total_iocs"] == 0


def test_console_summary_mentions_findings(results):
    text = render_console_summary(results)
    assert "ВРЕДОНОСНЫЕ" in text
    assert "worse.test" in text
    assert "clean.test" not in text   # чистые не засоряют сводку
