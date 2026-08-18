"""Тесты инфраструктурных модулей: конфигурация, лимитер, кеш, логирование."""

import time

import pytest

from ioc_analyzer.config import ConfigError, Settings, load_settings
from ioc_analyzer.enrichment.cache import ResponseCache
from ioc_analyzer.enrichment.rate_limiter import RateLimiter
from ioc_analyzer.logging_setup import setup_logging


# ------------------------------------------------------------- конфигурация

def test_env_file_is_loaded(tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VERDICT_MALICIOUS_THRESHOLD", raising=False)
    env = tmp_path / ".env"
    env.write_text("VT_API_KEY=from-file-key\nVERDICT_MALICIOUS_THRESHOLD=7\n",
                   encoding="utf-8")

    settings = load_settings(env)
    assert settings.vt_api_key == "from-file-key"
    assert settings.malicious_threshold == 7


def test_real_environment_wins_over_env_file(tmp_path, monkeypatch):
    """В CI/докере переменная окружения должна перекрывать файл."""
    monkeypatch.setenv("VT_API_KEY", "from-environment")
    env = tmp_path / ".env"
    env.write_text("VT_API_KEY=from-file\n", encoding="utf-8")
    assert load_settings(env).vt_api_key == "from-environment"


def test_invalid_int_raises_config_error(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_TIMEOUT", "не-число")
    with pytest.raises(ConfigError, match="VT_TIMEOUT"):
        load_settings(tmp_path / "нет.env")


def test_validation_rejects_nonsense_values():
    with pytest.raises(ConfigError):
        Settings(vt_requests_per_minute=0).validate()
    with pytest.raises(ConfigError):
        Settings(malicious_threshold=0).validate()
    with pytest.raises(ConfigError):
        Settings(log_level="ГРОМКО").validate()


def test_require_api_key_error_is_actionable():
    """Сообщение должно подсказывать выход, а не просто ругаться."""
    with pytest.raises(ConfigError, match="--offline"):
        Settings(vt_api_key="").require_api_key()


# ----------------------------------------------------------------- лимитер

def test_rate_limiter_allows_burst_within_window():
    limiter = RateLimiter(max_calls=4, period=60.0)
    started = time.monotonic()
    for _ in range(4):
        limiter.acquire()
    assert time.monotonic() - started < 0.1   # 4 вызова подряд не тормозят


def test_rate_limiter_blocks_when_window_is_full():
    """Пятый вызов при лимите 4 обязан подождать."""
    limiter = RateLimiter(max_calls=4, period=0.3)
    for _ in range(4):
        limiter.acquire()
    started = time.monotonic()
    limiter.acquire()
    assert time.monotonic() - started >= 0.2


def test_rate_limiter_window_slides():
    limiter = RateLimiter(max_calls=2, period=0.2)
    limiter.acquire()
    limiter.acquire()
    time.sleep(0.25)                          # окно уехало
    started = time.monotonic()
    limiter.acquire()
    assert time.monotonic() - started < 0.05  # ждать не пришлось


def test_rate_limiter_rejects_bad_config():
    with pytest.raises(ValueError):
        RateLimiter(max_calls=0)


# --------------------------------------------------------------------- кеш

def test_cache_roundtrip(tmp_path):
    path = tmp_path / "c.json"
    cache = ResponseCache(path, ttl=3600)
    cache.set("k", {"data": 1})
    cache.save()

    reopened = ResponseCache(path, ttl=3600)
    assert reopened.get("k") == {"data": 1}
    assert reopened.hits == 1


def test_cache_respects_ttl(tmp_path):
    cache = ResponseCache(tmp_path / "c.json", ttl=0)
    cache.set("k", {"data": 1})
    time.sleep(0.01)
    assert cache.get("k") is None
    assert cache.misses == 1


def test_disabled_cache_stores_nothing(tmp_path):
    cache = ResponseCache(tmp_path / "c.json", enabled=False)
    cache.set("k", {"data": 1})
    assert cache.get("k") is None
    cache.save()
    assert not (tmp_path / "c.json").exists()


def test_corrupted_cache_does_not_crash(tmp_path):
    """Битый кеш — не повод падать: начинаем с пустого."""
    path = tmp_path / "c.json"
    path.write_text("{это не json", encoding="utf-8")
    cache = ResponseCache(path)
    assert cache.get("k") is None


def test_cache_save_is_atomic(tmp_path):
    """После сохранения не должно остаться временных файлов."""
    path = tmp_path / "c.json"
    cache = ResponseCache(path)
    cache.set("k", {"data": 1})
    cache.save()
    assert path.exists()
    assert not list(tmp_path.glob("*.tmp"))


# ------------------------------------------------------------- логирование

def test_api_key_is_redacted_from_logs(tmp_path, caplog):
    """Логи уходят в тикеты и чаты — ключ туда попасть не должен."""
    log_file = tmp_path / "app.log"
    logger = setup_logging("DEBUG", log_file=log_file,
                           secrets=["super-secret-api-key-123"], quiet=True)
    logger.info("Запрос с ключом super-secret-api-key-123 отправлен")

    for handler in logger.handlers:
        handler.flush()
    content = log_file.read_text(encoding="utf-8")
    assert "super-secret-api-key-123" not in content
    assert "***REDACTED***" in content


def test_setup_logging_is_idempotent(tmp_path):
    """Повторный вызов не должен плодить обработчики (и дублировать строки)."""
    first = setup_logging("INFO", log_file=tmp_path / "a.log", quiet=True)
    count = len(first.handlers)
    second = setup_logging("INFO", log_file=tmp_path / "a.log", quiet=True)
    assert len(second.handlers) == count
