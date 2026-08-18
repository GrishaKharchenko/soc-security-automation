"""Тесты нормализации и дедупликации."""

import pytest

from ioc_analyzer.ioc.normalizer import (
    deduplicate, normalize, normalize_url, refang, strip_noise,
)
from ioc_analyzer.models import IOCType


@pytest.mark.parametrize("raw,expected", [
    ("hxxp://evil[.]test/a", "http://evil.test/a"),
    ("hxxps://evil[.]test", "https://evil.test"),
    ("evil[.]test", "evil.test"),
    ("evil(.)test", "evil.test"),
    ("evil[dot]test", "evil.test"),
    ("192[.]0[.]2[.]1", "192.0.2.1"),
    ("user[at]example.com", "user@example.com"),
])
def test_refang(raw, expected):
    """Defanged-запись — индустриальный стандарт, инструмент обязан её понимать."""
    result, was_defanged = refang(raw)
    assert result == expected
    assert was_defanged is True


def test_refang_leaves_clean_value_untouched():
    result, was_defanged = refang("example.com")
    assert result == "example.com"
    assert was_defanged is False


@pytest.mark.parametrize("raw,expected", [
    ('"example.com"', "example.com"),
    ("<example.com>", "example.com"),
    ("example.com,", "example.com"),
    ("  example.com  ", "example.com"),
    ("(example.com);", "example.com"),
])
def test_strip_noise(raw, expected):
    assert strip_noise(raw) == expected


def test_domain_normalization():
    ioc = normalize("EVIL.TEST.")
    assert ioc.value == "evil.test"
    assert ioc.type is IOCType.DOMAIN


def test_idn_domain_converted_to_punycode():
    """VT знает IDN-домены в punycode, значит и мы должны их так отправлять."""
    ioc = normalize("мой-сайт.рф")
    assert ioc.value == "xn----8sbzclmxk.xn--p1ai"
    assert ioc.type is IOCType.DOMAIN


def test_ipv6_compressed():
    ioc = normalize("2001:0db8:0000:0000:0000:0000:0000:0001")
    assert ioc.value == "2001:db8::1"


def test_hash_lowercased():
    ioc = normalize("D41D8CD98F00B204E9800998ECF8427E")
    assert ioc.value == "d41d8cd98f00b204e9800998ecf8427e"
    assert ioc.type is IOCType.MD5


@pytest.mark.parametrize("raw,expected", [
    ("http://EXAMPLE.com/Path", "http://example.com/Path"),   # путь регистрозависим!
    ("https://example.com:443/a", "https://example.com/a"),   # дефолтный порт убран
    ("http://example.com:80/", "http://example.com/"),
    ("example.com/a", "http://example.com/a"),                # схема достроена
    ("http://example.com", "http://example.com/"),            # пустой путь -> /
])
def test_url_normalization(raw, expected):
    assert normalize_url(raw) == expected


def test_url_path_case_is_preserved():
    """'/Login' и '/login' — разные ресурсы, схлопывать их нельзя."""
    assert normalize("http://a.test/Login").value != normalize("http://a.test/login").value


def test_normalize_returns_none_for_garbage():
    assert normalize("совсем не индикатор") is None
    assert normalize("") is None
    assert normalize("   ") is None


def test_defanged_flag_is_recorded():
    assert normalize("evil[.]test").defanged is True
    assert normalize("evil.test").defanged is False


def test_deduplicate_merges_occurrences_and_lines():
    """Дубликаты не выбрасываются молча: считаем и запоминаем строки."""
    iocs = [
        normalize("EVIL.TEST", 1),
        normalize("evil[.]test", 5),
        normalize("evil.test.", 9),
        normalize("example.com", 12),
    ]
    result = deduplicate(iocs)
    assert len(result) == 2

    evil = next(i for i in result if i.value == "evil.test")
    assert evil.occurrences == 3
    assert evil.source_lines == [1, 5, 9]
    assert evil.defanged is True  # хотя бы одна запись была обезврежена


def test_deduplicate_keeps_different_types_apart():
    """Один и тот же текст с разным типом — разные индикаторы."""
    iocs = [normalize("example.com"), normalize("example.com/a")]
    assert len(deduplicate(iocs)) == 2
