"""Конфигурация приложения.

Единственное место, где читается окружение. Весь остальной код получает уже
провалидированный объект :class:`Settings` и ничего не знает про os.environ —
это делает модули чистыми и легко тестируемыми.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(RuntimeError):
    """Некорректная или отсутствующая конфигурация."""


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:  # noqa: TRY003
        raise ConfigError(f"{name} должен быть целым числом, получено: {raw!r}") from exc


def _get_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} должен быть числом, получено: {raw!r}") from exc


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


@dataclass(frozen=True)
class Settings:
    """Иммутабельный снимок настроек запуска."""

    # VirusTotal
    vt_api_key: str = ""
    vt_base_url: str = "https://www.virustotal.com/api/v3"
    vt_requests_per_minute: int = 4
    vt_timeout: int = 20
    vt_max_retries: int = 3
    vt_backoff_factor: float = 2.0

    # Пороги вердикта
    malicious_threshold: int = 3
    suspicious_threshold: int = 2
    reputation_floor: int = -20

    # Вывод / логирование
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    log_level: str = "INFO"
    log_file: Path = field(default_factory=lambda: Path("logs/ioc_analyzer.log"))
    log_max_bytes: int = 1_048_576
    log_backup_count: int = 3

    # Кеш
    cache_enabled: bool = True
    cache_file: Path = field(default_factory=lambda: Path(".cache/vt_cache.json"))
    cache_ttl: int = 86_400

    @property
    def has_api_key(self) -> bool:
        return bool(self.vt_api_key)

    def require_api_key(self) -> str:
        """Вернуть ключ или упасть с понятной ошибкой (а не с 401 от VT)."""
        if not self.vt_api_key:
            raise ConfigError(
                "VT_API_KEY не задан. Укажите ключ в .env или запустите "
                "анализ с флагом --offline (без обогащения)."
            )
        return self.vt_api_key

    def validate(self) -> None:
        """Проверки, которые дешевле сделать на старте, чем поймать в рантайме."""
        if self.vt_requests_per_minute < 1:
            raise ConfigError("VT_REQUESTS_PER_MINUTE должен быть >= 1")
        if self.vt_timeout < 1:
            raise ConfigError("VT_TIMEOUT должен быть >= 1")
        if self.vt_max_retries < 0:
            raise ConfigError("VT_MAX_RETRIES не может быть отрицательным")
        if self.malicious_threshold < 1:
            raise ConfigError("VERDICT_MALICIOUS_THRESHOLD должен быть >= 1")
        if self.suspicious_threshold < 1:
            raise ConfigError("VERDICT_SUSPICIOUS_THRESHOLD должен быть >= 1")
        if self.log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigError(f"Неизвестный LOG_LEVEL: {self.log_level}")


def load_settings(env_file: str | os.PathLike[str] | None = None) -> Settings:
    """Прочитать .env (если есть) и собрать :class:`Settings`.

    ``override=False``: переменные, уже выставленные в окружении (например, в
    CI или в docker run -e), имеют приоритет над файлом .env.
    """
    if env_file is not None:
        load_dotenv(env_file, override=False)
    else:
        load_dotenv(override=False)

    settings = Settings(
        vt_api_key=_get_str("VT_API_KEY"),
        vt_base_url=_get_str("VT_BASE_URL", "https://www.virustotal.com/api/v3").rstrip("/"),
        vt_requests_per_minute=_get_int("VT_REQUESTS_PER_MINUTE", 4),
        vt_timeout=_get_int("VT_TIMEOUT", 20),
        vt_max_retries=_get_int("VT_MAX_RETRIES", 3),
        vt_backoff_factor=_get_float("VT_BACKOFF_FACTOR", 2.0),
        malicious_threshold=_get_int("VERDICT_MALICIOUS_THRESHOLD", 3),
        suspicious_threshold=_get_int("VERDICT_SUSPICIOUS_THRESHOLD", 2),
        reputation_floor=_get_int("VERDICT_REPUTATION_FLOOR", -20),
        output_dir=Path(_get_str("OUTPUT_DIR", "reports")),
        log_level=_get_str("LOG_LEVEL", "INFO").upper(),
        log_file=Path(_get_str("LOG_FILE", "logs/ioc_analyzer.log")),
        log_max_bytes=_get_int("LOG_MAX_BYTES", 1_048_576),
        log_backup_count=_get_int("LOG_BACKUP_COUNT", 3),
        cache_enabled=_get_bool("CACHE_ENABLED", True),
        cache_file=Path(_get_str("CACHE_FILE", ".cache/vt_cache.json")),
        cache_ttl=_get_int("CACHE_TTL", 86_400),
    )
    settings.validate()
    return settings
