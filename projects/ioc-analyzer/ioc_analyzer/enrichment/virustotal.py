"""Клиент VirusTotal API v3.

Отвечает ровно за три вещи:

1. построить правильный запрос под тип индикатора;
2. пережить всё, что может пойти не так в сети и в API;
3. привести ответ вендора к нашей внутренней модели ``EnrichmentResult``.

Главный принцип: **метод ``enrich`` никогда не выбрасывает исключение**.
Любая проблема превращается в результат с соответствующим ``EnrichmentStatus``.
Прогон из 500 индикаторов не должен падать целиком из-за одного таймаута.
"""

from __future__ import annotations

import base64
import time
from datetime import datetime, timezone
from typing import Any

import requests

from ..config import Settings
from ..logging_setup import get_logger
from ..ioc.scope import check_enrichable
from ..models import IOC, EnrichmentResult, EnrichmentStatus, IOCType
from .base import EnrichmentProvider
from .cache import ResponseCache
from .rate_limiter import RateLimiter

logger = get_logger("enrichment.virustotal")

# Тип IOC -> раздел API. Единственное место, где знание об эндпоинтах VT.
_ENDPOINTS: dict[IOCType, str] = {
    IOCType.IPV4: "ip_addresses",
    IOCType.IPV6: "ip_addresses",
    IOCType.DOMAIN: "domains",
    IOCType.URL: "urls",
    IOCType.MD5: "files",
    IOCType.SHA1: "files",
    IOCType.SHA256: "files",
}

# Коды, которые имеет смысл повторить: временные проблемы на стороне VT.
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class VirusTotalClient(EnrichmentProvider):
    """Обогащение индикаторов через VirusTotal API v3."""

    name = "virustotal"

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
        cache: ResponseCache | None = None,
    ) -> None:
        self.settings = settings
        self.api_key = settings.require_api_key()
        self.base_url = settings.vt_base_url.rstrip("/")
        # Сессия переиспользует TCP/TLS-соединение — заметно быстрее на пачке
        # запросов. Инъекция сессии снаружи нужна тестам (requests-mock).
        self.session = session or requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "accept": "application/json",
            "user-agent": "ioc-analyzer/1.0 (SOC automation)",
        })
        self.rate_limiter = RateLimiter(settings.vt_requests_per_minute, period=60.0)
        self.cache = cache if cache is not None else ResponseCache(
            settings.cache_file, ttl=settings.cache_ttl, enabled=settings.cache_enabled
        )
        self.api_calls = 0

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def url_to_id(url: str) -> str:
        """VT адресует URL как base64url(URL) без ``=``-паддинга.

        Документированное поведение API v3: идентификатор URL — это
        ``base64.urlsafe_b64encode(url).strip('=')``.
        """
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    def _cache_key(self, ioc_type: IOCType, value: str) -> str:
        return f"{self.name}:{ioc_type.value}:{value}"

    @staticmethod
    def _file_hash_keys(payload: dict[str, Any]) -> list[tuple[IOCType, str]]:
        """Все хеши файла из ответа VT.

        VirusTotal резолвит MD5, SHA1 и SHA256 одного файла в один объект и
        возвращает все три в ``attributes``. Живой прогон показал, что фид с
        MD5 и SHA256 одного и того же образца тратит два запроса вместо одного.
        Раскладывая ответ в кеш под все три ключа, второй хеш мы отдаём уже
        бесплатно — на больших фидах это заметная экономия суточной квоты.
        """
        attributes = (payload.get("data") or {}).get("attributes") or {}
        pairs = [
            (IOCType.MD5, attributes.get("md5")),
            (IOCType.SHA1, attributes.get("sha1")),
            (IOCType.SHA256, attributes.get("sha256")),
        ]
        return [(t, v.lower()) for t, v in pairs if isinstance(v, str) and v]

    def _object_id(self, ioc: IOC) -> str:
        if ioc.type is IOCType.URL:
            return self.url_to_id(ioc.value)
        return ioc.value

    def _endpoint(self, ioc: IOC) -> str | None:
        section = _ENDPOINTS.get(ioc.type)
        if section is None:
            return None
        return f"{self.base_url}/{section}/{self._object_id(ioc)}"

    # ------------------------------------------------------------ HTTP-уровень

    def _request(self, url: str) -> tuple[dict[str, Any] | None, EnrichmentStatus, str | None]:
        """Выполнить GET с ретраями. Вернуть ``(json, статус, текст ошибки)``.

        Стратегия обработки ответов:
        * **200** — успех;
        * **404** — VT просто не знает индикатор. Это НЕ ошибка: для нового
          домена такой ответ нормален, статус ``NOT_FOUND``;
        * **401/403** — проблема с ключом. Ретраить бессмысленно, выходим сразу;
        * **429** — превышен лимит. Ждём ``Retry-After`` (если прислали) или
          экспоненциальную паузу и пробуем снова;
        * **5xx / таймаут / обрыв связи** — временный сбой, экспоненциальный
          backoff.
        """
        last_error: str | None = None
        last_status = EnrichmentStatus.API_ERROR

        for attempt in range(self.settings.vt_max_retries + 1):
            self.rate_limiter.acquire()
            try:
                self.api_calls += 1
                logger.debug("GET %s (попытка %d/%d)",
                             url, attempt + 1, self.settings.vt_max_retries + 1)
                response = self.session.get(url, timeout=self.settings.vt_timeout)
            except requests.exceptions.Timeout as exc:
                last_error = f"таймаут запроса ({self.settings.vt_timeout} с): {exc}"
                last_status = EnrichmentStatus.NETWORK_ERROR
            except requests.exceptions.ConnectionError as exc:
                last_error = f"ошибка соединения: {exc}"
                last_status = EnrichmentStatus.NETWORK_ERROR
            except requests.exceptions.RequestException as exc:
                last_error = f"ошибка HTTP-клиента: {exc}"
                last_status = EnrichmentStatus.NETWORK_ERROR
            else:
                status_code = response.status_code

                if status_code == 200:
                    try:
                        return response.json(), EnrichmentStatus.OK, None
                    except ValueError as exc:
                        return None, EnrichmentStatus.API_ERROR, f"невалидный JSON: {exc}"

                if status_code == 404:
                    logger.debug("VT не знает индикатор (404): %s", url)
                    return None, EnrichmentStatus.NOT_FOUND, None

                if status_code in (401, 403):
                    detail = self._error_message(response)
                    logger.error("VirusTotal отверг ключ (HTTP %d): %s", status_code, detail)
                    # Ретраи не помогут — ключ не станет валидным сам собой.
                    return None, EnrichmentStatus.AUTH_ERROR, detail

                if status_code == 429:
                    last_status = EnrichmentStatus.RATE_LIMITED
                    last_error = "превышен лимит запросов VirusTotal (HTTP 429)"
                    wait = self._retry_after(response, attempt)
                    logger.warning("HTTP 429 от VirusTotal, пауза %.1f с "
                                   "(попытка %d)", wait, attempt + 1)
                    if attempt < self.settings.vt_max_retries:
                        time.sleep(wait)
                    continue

                if status_code in _RETRYABLE_STATUS:
                    last_status = EnrichmentStatus.API_ERROR
                    last_error = f"временная ошибка VirusTotal: HTTP {status_code}"
                elif status_code in (400, 422):
                    # Провайдер отверг сам индикатор: "not a valid domain
                    # pattern", некорректный формат хеша и т.п. Это НЕ сбой —
                    # ни повтор, ни ручная проверка аналитиком ничего не дадут,
                    # поэтому статус UNSUPPORTED, а не API_ERROR.
                    detail = self._error_message(response)
                    logger.debug("VT не принимает индикатор (HTTP %d): %s",
                                 status_code, detail)
                    return None, EnrichmentStatus.UNSUPPORTED, detail
                else:
                    # Прочие неожиданные коды: повтор не поможет.
                    detail = self._error_message(response)
                    return None, EnrichmentStatus.API_ERROR, f"HTTP {status_code}: {detail}"

            if attempt < self.settings.vt_max_retries:
                backoff = self.settings.vt_backoff_factor * (2 ** attempt)
                logger.warning("%s — повтор через %.1f с", last_error, backoff)
                time.sleep(backoff)

        logger.error("Запрос не удался после %d попыток: %s",
                     self.settings.vt_max_retries + 1, last_error)
        return None, last_status, last_error

    def _retry_after(self, response: requests.Response, attempt: int) -> float:
        """Уважать заголовок ``Retry-After``, если сервер его прислал."""
        header = response.headers.get("Retry-After")
        if header:
            try:
                return max(float(header), 1.0)
            except ValueError:
                pass
        return self.settings.vt_backoff_factor * (2 ** attempt)

    @staticmethod
    def _error_message(response: requests.Response) -> str:
        """Достать человекочитаемое описание ошибки из тела ответа VT."""
        try:
            payload = response.json()
        except ValueError:
            return (response.text or "").strip()[:200] or "нет тела ответа"
        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        return error.get("message") or error.get("code") or str(payload)[:200]

    # --------------------------------------------------------------- разбор

    @staticmethod
    def _ts_to_iso(value: Any) -> str | None:
        """Unix-время VT -> читаемый ISO-8601 в UTC."""
        if not isinstance(value, (int, float)) or value <= 0:
            return None
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds")
        except (OverflowError, OSError, ValueError):
            return None

    def _parse(self, payload: dict[str, Any], ioc: IOC, from_cache: bool) -> EnrichmentResult:
        """Привести ответ VT к нашей модели.

        Всё читается защищённо (``.get`` с дефолтами): VT возвращает разный
        набор полей для файлов, доменов, IP и URL, а часть полей отсутствует
        у малоизвестных индикаторов. Падать из-за этого нельзя.
        """
        attributes = (payload.get("data") or {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}

        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        timeout = int(stats.get("timeout") or 0)

        results = attributes.get("last_analysis_results") or {}
        detection_names = sorted({
            (engine_result or {}).get("result")
            for engine_result in results.values()
            if isinstance(engine_result, dict)
            and engine_result.get("category") in {"malicious", "suspicious"}
            and engine_result.get("result")
        })

        tags = [str(tag) for tag in (attributes.get("tags") or [])]
        # У файлов «имя угрозы» лежит отдельно и полезнее сырых вердиктов.
        threat_label = ((attributes.get("popular_threat_classification") or {})
                        .get("suggested_threat_label"))
        if threat_label:
            tags.append(f"threat_label:{threat_label}")

        return EnrichmentResult(
            provider=self.name,
            status=EnrichmentStatus.OK,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            timeout=timeout,
            total_engines=malicious + suspicious + harmless + undetected + timeout,
            reputation=int(attributes.get("reputation") or 0),
            detection_names=[name for name in detection_names if name][:20],
            tags=tags[:20],
            country=attributes.get("country"),
            as_owner=attributes.get("as_owner"),
            first_seen=self._ts_to_iso(
                attributes.get("first_submission_date")
                or attributes.get("creation_date")
                or attributes.get("whois_date")
            ),
            last_analysis_date=self._ts_to_iso(attributes.get("last_analysis_date")),
            permalink=self._permalink(ioc),
            from_cache=from_cache,
        )

    def _permalink(self, ioc: IOC) -> str:
        """Ссылка на карточку в веб-интерфейсе — аналитик пойдёт смотреть руками."""
        gui = "https://www.virustotal.com/gui"
        if ioc.type.is_hash:
            return f"{gui}/file/{ioc.value}"
        if ioc.type.is_ip:
            return f"{gui}/ip-address/{ioc.value}"
        if ioc.type is IOCType.URL:
            return f"{gui}/url/{self.url_to_id(ioc.value)}"
        return f"{gui}/domain/{ioc.value}"

    # ------------------------------------------------------------ публичный API

    def enrich(self, ioc: IOC) -> EnrichmentResult:
        """Обогатить один индикатор. Исключений не выбрасывает — никогда."""
        endpoint = self._endpoint(ioc)
        if endpoint is None:
            logger.debug("Тип %s не поддерживается VirusTotal", ioc.type.value)
            return self.unsupported(f"VirusTotal не работает с типом {ioc.type.value}")

        # Индикаторы, которые провайдер не может проверить в принципе
        # (зарезервированные зоны DNS, приватные адреса), отсекаем до запроса:
        # это экономит квоту и не засоряет отчёт бесполезными ошибками.
        skip_reason = check_enrichable(ioc)
        if skip_reason is not None:
            logger.info("Пропускаю %s (%s): %s", ioc.value, ioc.type.value, skip_reason)
            return self.unsupported(skip_reason)

        cache_key = self._cache_key(ioc.type, ioc.value)
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.info("Из кеша: %s (%s)", ioc.value, ioc.type.value)
            return self._parse(cached, ioc, from_cache=True)

        payload, status, error = self._request(endpoint)

        if status is EnrichmentStatus.OK and payload is not None:
            self.cache.set(cache_key, payload)
            if ioc.type.is_hash:
                # Тот же файл под остальными своими хешами — следующий запрос
                # по любому из них уйдёт в кеш, а не в API.
                for hash_type, hash_value in self._file_hash_keys(payload):
                    self.cache.set(self._cache_key(hash_type, hash_value), payload)
            result = self._parse(payload, ioc, from_cache=False)
            logger.info("VT: %s (%s) -> детекты %s, репутация %d",
                        ioc.value, ioc.type.value, result.detection_ratio, result.reputation)
            return result

        if status is EnrichmentStatus.NOT_FOUND:
            logger.info("VT: %s (%s) -> индикатор не найден в базе",
                        ioc.value, ioc.type.value)
        else:
            logger.warning("VT: %s (%s) -> %s: %s",
                           ioc.value, ioc.type.value, status.value, error)

        return EnrichmentResult(
            provider=self.name,
            status=status,
            error=error,
            permalink=self._permalink(ioc),
        )

    def close(self) -> None:
        """Сохранить кеш и закрыть HTTP-сессию."""
        self.cache.save()
        self.session.close()
