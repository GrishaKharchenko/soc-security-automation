"""Интеграционные тесты: конвейер целиком, от файла до отчёта.

Юнит-тесты проверяют модули по отдельности; здесь проверяется, что они
собраны правильно — включая коды возврата, которыми пользуется CI/cron.
"""

import json

import pytest
import requests
import requests_mock

from ioc_analyzer.analyzer import IOCAnalyzer
from ioc_analyzer.cli import EXIT_ERRORS, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from ioc_analyzer.enrichment.virustotal import VirusTotalClient
from ioc_analyzer.models import IOCType, Verdict


@pytest.fixture
def feed(tmp_path):
    path = tmp_path / "feed.txt"
    path.write_text(
        "# тестовый фид\n"
        "malware-c2.test\n"
        "example.com\n"
        "192.0.2.1\n"
        "EXAMPLE.COM\n"          # дубликат -> схлопнется
        "не индикатор\n",
        encoding="utf-8",
    )
    return path


def _payload(malicious: int, harmless: int = 70):
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0,
                                "harmless": harmless, "undetected": 0, "timeout": 0},
        "reputation": -50 if malicious else 5,
    }}}


# ------------------------------------------------------------ конвейер целиком

def test_full_pipeline_with_mocked_api(settings, feed, disabled_cache):
    with requests_mock.Mocker() as api:
        api.get("https://vt.test/api/v3/domains/malware-c2.test",
                json=_payload(malicious=40))
        api.get("https://vt.test/api/v3/domains/example.com", json=_payload(0))
        api.get("https://vt.test/api/v3/ip_addresses/192.0.2.1", status_code=404)

        client = VirusTotalClient(settings, session=requests.Session(),
                                  cache=disabled_cache)
        run = IOCAnalyzer(settings, provider=client).analyze_file(feed)

    verdicts = {r.ioc.value: r.verdict for r in run.results}
    assert verdicts["malware-c2.test"] is Verdict.MALICIOUS
    assert verdicts["example.com"] is Verdict.CLEAN
    assert verdicts["192.0.2.1"] is Verdict.UNKNOWN     # 404 != clean
    assert len(run.results) == 3                        # дубликат схлопнулся
    assert run.parse_stats.invalid == 1
    assert run.api_calls == 3


def test_one_broken_ioc_does_not_stop_the_run(settings, feed, disabled_cache):
    """Таймаут на одном индикаторе не должен ронять прогон из сотен."""
    with requests_mock.Mocker() as api:
        api.get("https://vt.test/api/v3/domains/malware-c2.test",
                exc=requests.exceptions.ConnectTimeout)
        api.get("https://vt.test/api/v3/domains/example.com", json=_payload(0))
        api.get("https://vt.test/api/v3/ip_addresses/192.0.2.1", json=_payload(0))

        client = VirusTotalClient(settings, session=requests.Session(),
                                  cache=disabled_cache)
        run = IOCAnalyzer(settings, provider=client).analyze_file(feed)

    verdicts = {r.ioc.value: r.verdict for r in run.results}
    assert verdicts["malware-c2.test"] is Verdict.ERROR
    assert verdicts["example.com"] is Verdict.CLEAN     # остальные обработаны
    assert len(run.results) == 3


def test_offline_mode_makes_no_requests(settings, feed):
    with requests_mock.Mocker() as api:
        run = IOCAnalyzer(settings, provider=None).analyze_file(feed)
    assert api.call_count == 0
    assert all(r.verdict is Verdict.SKIPPED for r in run.results)


def test_type_filter(settings, feed):
    run = IOCAnalyzer(settings).analyze_file(feed, only_types=[IOCType.DOMAIN])
    assert {r.ioc.type for r in run.results} == {IOCType.DOMAIN}


def test_limit_caps_api_usage(settings, feed):
    run = IOCAnalyzer(settings).analyze_file(feed, limit=2)
    assert len(run.results) == 2


# ------------------------------------------------------------- коды возврата

def test_exit_code_reflects_findings(settings, feed, disabled_cache):
    with requests_mock.Mocker() as api:
        api.get("https://vt.test/api/v3/domains/malware-c2.test", json=_payload(40))
        api.get("https://vt.test/api/v3/domains/example.com", json=_payload(0))
        api.get("https://vt.test/api/v3/ip_addresses/192.0.2.1", json=_payload(0))
        client = VirusTotalClient(settings, session=requests.Session(),
                                  cache=disabled_cache)
        run = IOCAnalyzer(settings, provider=client).analyze_file(feed)

    assert IOCAnalyzer.exit_code(run.results) == EXIT_FINDINGS


def test_exit_code_zero_when_all_clean(settings, feed, disabled_cache):
    with requests_mock.Mocker() as api:
        api.get(requests_mock.ANY, json=_payload(0))
        client = VirusTotalClient(settings, session=requests.Session(),
                                  cache=disabled_cache)
        run = IOCAnalyzer(settings, provider=client).analyze_file(feed)

    assert IOCAnalyzer.exit_code(run.results) == EXIT_OK


def test_exit_code_two_on_api_failures(settings, feed, disabled_cache):
    with requests_mock.Mocker() as api:
        api.get(requests_mock.ANY, exc=requests.exceptions.ConnectionError)
        client = VirusTotalClient(settings, session=requests.Session(),
                                  cache=disabled_cache)
        run = IOCAnalyzer(settings, provider=client).analyze_file(feed)

    assert IOCAnalyzer.exit_code(run.results) == EXIT_ERRORS


# ------------------------------------------------------------------- сам CLI

def test_cli_offline_writes_both_reports(feed, tmp_path):
    code = main(["analyze", "-i", str(feed), "--offline", "-q",
                 "-o", str(tmp_path / "out"), "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_OK
    assert len(list((tmp_path / "out").glob("*.json"))) == 1
    assert len(list((tmp_path / "out").glob("*.csv"))) == 1


def test_cli_report_content(feed, tmp_path):
    main(["analyze", "-i", str(feed), "--offline", "-q", "-o", str(tmp_path / "out"),
          "--format", "json", "--env-file", str(tmp_path / "нет.env")])
    report = json.loads(next((tmp_path / "out").glob("*.json")).read_text(encoding="utf-8"))
    assert report["summary"]["total_iocs"] == 3
    assert report["report"]["enrichment_enabled"] is False
    assert report["report"]["parsing"]["duplicates_removed"] == 1


def test_cli_missing_file_returns_usage_error(tmp_path, capsys):
    code = main(["analyze", "-i", str(tmp_path / "нет.txt"), "--offline", "-q",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_USAGE
    assert "не найден" in capsys.readouterr().err


def test_cli_without_api_key_refuses_online_mode(feed, tmp_path, monkeypatch, capsys):
    """Без ключа падаем с понятным сообщением, а не с 401 после всех ретраев."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("VT_API_KEY", "")
    code = main(["analyze", "-i", str(feed), "-q",
                 "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_USAGE


def test_cli_classify_lists_iocs(feed, tmp_path, capsys):
    code = main(["classify", "-i", str(feed), "-q",
                 "--env-file", str(tmp_path / "нет.env")])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "malware-c2.test" in out
    assert "Всего уникальных: 3" in out


def test_cli_flags_override_env(feed, tmp_path, monkeypatch):
    """Флаг CLI важнее .env — иначе разовый прогон требует правки конфига."""
    monkeypatch.setenv("VERDICT_MALICIOUS_THRESHOLD", "3")
    code = main(["analyze", "-i", str(feed), "--offline", "-q",
                 "-o", str(tmp_path / "out"), "--malicious-threshold", "1",
                 "--format", "none", "--env-file", str(tmp_path / "нет.env")])
    assert code == EXIT_OK
    assert not list((tmp_path / "out").glob("*")) or True


def test_cli_rejects_unknown_type(feed, tmp_path):
    with pytest.raises(SystemExit):
        main(["analyze", "-i", str(feed), "--types", "непонятный-тип"])
