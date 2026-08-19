"""Общие фикстуры тестов.

Главное правило: **ни один тест не ходит в реальный VirusTotal**. Сеть в
тестах — это флаки, зависимость от квоты и невозможность воспроизвести
редкие ответы (429, 5xx). Весь HTTP замокан через ``requests-mock``.
"""

from __future__ import annotations

import pytest

from ioc_analyzer.config import Settings
from ioc_analyzer.enrichment.cache import ResponseCache
from ioc_analyzer.models import IOC, IOCType


@pytest.fixture
def settings(tmp_path) -> Settings:
    """Настройки для тестов: без пауз, без кеша на диске в проекте."""
    return Settings(
        vt_api_key="test-api-key-0123456789",
        vt_base_url="https://vt.test/api/v3",
        vt_requests_per_minute=1000,   # rate limiter не должен тормозить тесты
        vt_timeout=5,
        vt_max_retries=2,
        vt_backoff_factor=0.0,         # backoff = 0 -> тесты не спят
        output_dir=tmp_path / "reports",
        log_file=tmp_path / "logs" / "test.log",
        cache_enabled=False,
        cache_file=tmp_path / "cache.json",
    )


@pytest.fixture
def disabled_cache(tmp_path) -> ResponseCache:
    return ResponseCache(tmp_path / "cache.json", enabled=False)


@pytest.fixture
def domain_ioc() -> IOC:
    return IOC(value="malware-c2.example.com", type=IOCType.DOMAIN, raw="malware-c2.example.com")


@pytest.fixture
def vt_payload() -> dict:
    """Урезанный, но структурно достоверный ответ VirusTotal API v3."""
    return {
        "data": {
            "id": "malware-c2.example.com",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 60, "malicious": 8, "suspicious": 2,
                    "undetected": 4, "timeout": 0,
                },
                "last_analysis_results": {
                    "EngineA": {"category": "malicious", "result": "Trojan.TestSample"},
                    "EngineB": {"category": "malicious", "result": "Malware.Generic"},
                    "EngineC": {"category": "harmless", "result": "clean"},
                    "EngineD": {"category": "suspicious", "result": None},
                },
                "reputation": -45,
                "tags": ["dga", "newly-registered"],
                "country": "NL",
                "as_owner": "TEST-AS",
                "last_analysis_date": 1_760_000_000,
                "first_submission_date": 1_750_000_000,
            },
        }
    }
