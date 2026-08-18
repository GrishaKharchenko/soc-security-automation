"""Тесты логики вердикта — самая ответственная часть: цена ошибки здесь
пропущенный инцидент или ложная тревога на весь SOC."""

import dataclasses

import pytest

from ioc_analyzer.models import (
    IOC, EnrichmentResult, EnrichmentStatus, IOCType, Verdict,
)
from ioc_analyzer.scoring.verdict import calculate_risk_score, calculate_verdict


@pytest.fixture
def ioc():
    return IOC(value="malware-c2.test", type=IOCType.DOMAIN, raw="malware-c2.test")


def _ok(**kwargs) -> EnrichmentResult:
    defaults = dict(provider="virustotal", status=EnrichmentStatus.OK,
                    harmless=60, undetected=10, total_engines=70)
    defaults.update(kwargs)
    return EnrichmentResult(**defaults)


# ----------------------------------------------------------------- вердикты

def test_many_detections_is_malicious(ioc, settings):
    result = calculate_verdict(ioc, _ok(malicious=42, total_engines=70), settings)
    assert result.verdict is Verdict.MALICIOUS
    assert result.risk_score >= 60
    assert "42" in result.reasons[0]


def test_exactly_at_threshold_is_malicious(ioc, settings):
    result = calculate_verdict(ioc, _ok(malicious=3), settings)
    assert result.verdict is Verdict.MALICIOUS


def test_single_detection_is_suspicious_not_malicious(ioc, settings):
    """Один движок из 70 — почти всегда false positive, но игнорировать нельзя."""
    result = calculate_verdict(ioc, _ok(malicious=1), settings)
    assert result.verdict is Verdict.SUSPICIOUS
    assert "false positive" in " ".join(result.reasons)


def test_suspicious_engines_trigger_suspicious(ioc, settings):
    result = calculate_verdict(ioc, _ok(malicious=0, suspicious=2), settings)
    assert result.verdict is Verdict.SUSPICIOUS


def test_bad_reputation_alone_is_suspicious(ioc, settings):
    """Детектов нет, но сообщество VT массово жалуется — это сигнал."""
    result = calculate_verdict(ioc, _ok(malicious=0, reputation=-80), settings)
    assert result.verdict is Verdict.SUSPICIOUS


def test_no_detections_is_clean(ioc, settings):
    result = calculate_verdict(ioc, _ok(malicious=0, reputation=10), settings)
    assert result.verdict is Verdict.CLEAN
    assert result.risk_score == 0


# --------------------------- ключевое: отсутствие данных не равно чистоте

@pytest.mark.parametrize("status", [
    EnrichmentStatus.NETWORK_ERROR,
    EnrichmentStatus.RATE_LIMITED,
    EnrichmentStatus.AUTH_ERROR,
    EnrichmentStatus.API_ERROR,
])
def test_api_failure_is_error_never_clean(ioc, settings, status):
    """Сбой обогащения обязан быть виден аналитику, а не выглядеть как 'чисто'."""
    result = calculate_verdict(ioc, EnrichmentResult("virustotal", status,
                                                     error="сбой"), settings)
    assert result.verdict is Verdict.ERROR
    assert result.verdict is not Verdict.CLEAN
    assert "ручная проверка" in " ".join(result.reasons)


def test_not_found_is_unknown_not_clean(ioc, settings):
    """VT не знает индикатор ≠ индикатор безопасен."""
    result = calculate_verdict(
        ioc, EnrichmentResult("virustotal", EnrichmentStatus.NOT_FOUND), settings)
    assert result.verdict is Verdict.UNKNOWN
    assert result.risk_score > 0


def test_offline_mode_is_skipped(ioc, settings):
    result = calculate_verdict(ioc, None, settings)
    assert result.verdict is Verdict.SKIPPED
    assert result.risk_score == 0


def test_unsupported_type_is_skipped(ioc, settings):
    result = calculate_verdict(
        ioc, EnrichmentResult("virustotal", EnrichmentStatus.UNSUPPORTED,
                              error="тип не поддерживается"), settings)
    assert result.verdict is Verdict.SKIPPED


# --------------------------------------------------------- пороги и score

def test_thresholds_are_configurable(ioc, settings):
    """Разные команды имеют разную толерантность к FP — порог в .env."""
    strict = dataclasses.replace(settings, malicious_threshold=1)
    lenient = dataclasses.replace(settings, malicious_threshold=10)
    enrichment = _ok(malicious=2)

    assert calculate_verdict(ioc, enrichment, strict).verdict is Verdict.MALICIOUS
    assert calculate_verdict(ioc, enrichment, lenient).verdict is Verdict.SUSPICIOUS


def test_risk_score_is_bounded(ioc, settings):
    high = calculate_risk_score(_ok(malicious=70, total_engines=70, reputation=-999),
                                settings)
    low = calculate_risk_score(_ok(malicious=0, reputation=100), settings)
    assert 0 <= low <= high <= 100
    assert high == 100


def test_risk_score_grows_with_detections(ioc, settings):
    scores = [calculate_verdict(ioc, _ok(malicious=n), settings).risk_score
              for n in (0, 1, 5, 20)]
    assert scores == sorted(scores)


def test_score_never_contradicts_verdict(ioc, settings):
    """SUSPICIOUS обязан стоять в очереди триажа выше, чем UNKNOWN."""
    suspicious = calculate_verdict(ioc, _ok(malicious=1), settings)
    unknown = calculate_verdict(
        ioc, EnrichmentResult("virustotal", EnrichmentStatus.NOT_FOUND), settings)
    assert suspicious.risk_score > unknown.risk_score


def test_verdict_severity_ordering():
    """Порядок серьёзности определяет сортировку отчёта."""
    assert Verdict.MALICIOUS.severity > Verdict.SUSPICIOUS.severity
    assert Verdict.SUSPICIOUS.severity > Verdict.ERROR.severity
    assert Verdict.ERROR.severity > Verdict.UNKNOWN.severity
    assert Verdict.UNKNOWN.severity > Verdict.CLEAN.severity


# ------------------------------------------------------------- объяснимость

def test_every_verdict_has_reasons(ioc, settings):
    """Вердикт без объяснения аналитик проверить не сможет — и не будет ему верить."""
    cases = [
        _ok(malicious=42), _ok(malicious=1), _ok(malicious=0),
        EnrichmentResult("virustotal", EnrichmentStatus.NOT_FOUND),
        EnrichmentResult("virustotal", EnrichmentStatus.NETWORK_ERROR, error="x"),
        None,
    ]
    for enrichment in cases:
        assert calculate_verdict(ioc, enrichment, settings).reasons


def test_occurrences_are_mentioned(settings):
    ioc = IOC(value="a.test", type=IOCType.DOMAIN, raw="a.test", occurrences=40)
    result = calculate_verdict(ioc, _ok(malicious=5), settings)
    assert "40" in " ".join(result.reasons)
