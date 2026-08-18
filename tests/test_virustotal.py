"""Тесты клиента VirusTotal.

Ни одного реального запроса: весь HTTP замокан. Это позволяет
воспроизводимо проверить именно то, что в жизни ловится редко и больно —
429, 5xx, таймауты, битый JSON, отсутствующие поля.
"""

import pytest
import requests
import requests_mock

from ioc_analyzer.enrichment.virustotal import VirusTotalClient
from ioc_analyzer.models import IOC, EnrichmentStatus, IOCType


@pytest.fixture
def client(settings, disabled_cache):
    session = requests.Session()
    return VirusTotalClient(settings, session=session, cache=disabled_cache)


@pytest.fixture
def mock_api():
    with requests_mock.Mocker() as m:
        yield m


# --------------------------------------------------------------- маршрутизация

@pytest.mark.parametrize("value,ioc_type,expected_path", [
    ("192.0.2.1", IOCType.IPV4, "/ip_addresses/192.0.2.1"),
    ("2001:db8::1", IOCType.IPV6, "/ip_addresses/2001:db8::1"),
    ("example.com", IOCType.DOMAIN, "/domains/example.com"),
    ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5,
     "/files/d41d8cd98f00b204e9800998ecf8427e"),
])
def test_endpoint_per_ioc_type(client, value, ioc_type, expected_path):
    ioc = IOC(value=value, type=ioc_type, raw=value)
    assert client._endpoint(ioc).endswith(expected_path)


def test_url_id_is_base64url_without_padding():
    """Документированный формат VT API v3 для идентификатора URL."""
    assert (VirusTotalClient.url_to_id("http://example.com/index.html")
            == "aHR0cDovL2V4YW1wbGUuY29tL2luZGV4Lmh0bWw")
    assert "=" not in VirusTotalClient.url_to_id("http://a.test/")


# ------------------------------------------------------------------ успех

def test_successful_enrichment(client, mock_api, domain_ioc, vt_payload):
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test", json=vt_payload)
    result = client.enrich(domain_ioc)

    assert result.status is EnrichmentStatus.OK
    assert result.malicious == 8
    assert result.suspicious == 2
    assert result.total_engines == 74
    assert result.detection_ratio == "8/74"
    assert result.reputation == -45
    assert result.country == "NL"
    assert "Trojan.TestSample" in result.detection_names
    assert "dga" in result.tags
    assert result.last_analysis_date.startswith("2025-")
    assert result.permalink.endswith("/domain/malware-c2.test")


def test_missing_fields_do_not_crash(client, mock_api, domain_ioc):
    """У малоизвестных индикаторов половины полей нет — KeyError недопустим."""
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 json={"data": {"attributes": {}}})
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.OK
    assert result.malicious == 0
    assert result.total_engines == 0
    assert result.detection_ratio == "0/0"


def test_completely_empty_payload_does_not_crash(client, mock_api, domain_ioc):
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test", json={})
    assert client.enrich(domain_ioc).status is EnrichmentStatus.OK


# ------------------------------------------------------------- ошибки API

def test_404_means_not_found_not_error(client, mock_api, domain_ioc):
    """404 — «VT не знает индикатор». Это не сбой и не повод для ретраев."""
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 status_code=404, json={"error": {"code": "NotFoundError"}})
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.NOT_FOUND
    assert mock_api.call_count == 1


def test_401_stops_immediately(client, mock_api, domain_ioc):
    """Плохой ключ ретраями не чинится — не тратим попытки и время."""
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 status_code=401, json={"error": {"message": "Wrong API key"}})
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.AUTH_ERROR
    assert "Wrong API key" in result.error
    assert mock_api.call_count == 1


def test_429_is_retried_then_succeeds(client, mock_api, domain_ioc, vt_payload):
    """Классический сценарий: словили лимит, подождали, получили данные."""
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test", [
        {"status_code": 429, "headers": {"Retry-After": "0"}},
        {"status_code": 200, "json": vt_payload},
    ])
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.OK
    assert mock_api.call_count == 2


def test_429_exhausts_retries(client, mock_api, domain_ioc):
    """Если лимит не отпускает — честно сообщаем RATE_LIMITED, а не 'чисто'."""
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 status_code=429, headers={"Retry-After": "0"})
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.RATE_LIMITED
    assert mock_api.call_count == client.settings.vt_max_retries + 1


def test_500_is_retried(client, mock_api, domain_ioc, vt_payload):
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test", [
        {"status_code": 500},
        {"status_code": 503},
        {"status_code": 200, "json": vt_payload},
    ])
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.OK
    assert mock_api.call_count == 3


def test_400_is_not_retried(client, mock_api, domain_ioc):
    """Некорректный запрос повтором не исправить."""
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 status_code=400, json={"error": {"message": "Bad request"}})
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.API_ERROR
    assert mock_api.call_count == 1


def test_timeout_is_retried_then_reported(client, mock_api, domain_ioc):
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 exc=requests.exceptions.ConnectTimeout)
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.NETWORK_ERROR
    assert mock_api.call_count == client.settings.vt_max_retries + 1


def test_connection_error_is_handled(client, mock_api, domain_ioc):
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 exc=requests.exceptions.ConnectionError)
    assert client.enrich(domain_ioc).status is EnrichmentStatus.NETWORK_ERROR


def test_invalid_json_is_handled(client, mock_api, domain_ioc):
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 status_code=200, text="<html>502 Bad Gateway</html>")
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.API_ERROR
    assert "JSON" in result.error


def test_enrich_never_raises(client, mock_api, domain_ioc):
    """Контракт провайдера: исключения наружу не выходят никогда."""
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test",
                 exc=requests.exceptions.SSLError)
    result = client.enrich(domain_ioc)   # не должно упасть
    assert result.status is EnrichmentStatus.NETWORK_ERROR


def test_unsupported_type_is_not_requested(client, mock_api):
    ioc = IOC(value="что-то", type=IOCType.UNKNOWN, raw="что-то")
    result = client.enrich(ioc)
    assert result.status is EnrichmentStatus.UNSUPPORTED
    assert mock_api.call_count == 0


# ---------------------------------------------------------------------- кеш

def test_cache_prevents_second_api_call(settings, tmp_path, mock_api,
                                        domain_ioc, vt_payload):
    """Повторный запрос того же IOC не должен тратить квоту."""
    from ioc_analyzer.enrichment.cache import ResponseCache

    cache = ResponseCache(tmp_path / "c.json", ttl=3600, enabled=True)
    client = VirusTotalClient(settings, session=requests.Session(), cache=cache)
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test", json=vt_payload)

    first = client.enrich(domain_ioc)
    second = client.enrich(domain_ioc)

    assert mock_api.call_count == 1
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.malicious == first.malicious


def test_api_key_is_sent_in_header(client, mock_api, domain_ioc, vt_payload):
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.test", json=vt_payload)
    client.enrich(domain_ioc)
    assert mock_api.last_request.headers["x-apikey"] == "test-api-key-0123456789"


def test_missing_api_key_raises_config_error(settings):
    import dataclasses

    from ioc_analyzer.config import ConfigError

    with pytest.raises(ConfigError, match="VT_API_KEY"):
        VirusTotalClient(dataclasses.replace(settings, vt_api_key=""))
