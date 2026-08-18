"""Тесты определения типа IOC — сердце классификации."""

import pytest

from ioc_analyzer.ioc.detector import detect_type, looks_like_domain, looks_like_hash
from ioc_analyzer.models import IOCType


@pytest.mark.parametrize("value,expected", [
    # --- IPv4/IPv6 ---
    ("192.0.2.1", IOCType.IPV4),
    ("8.8.8.8", IOCType.IPV4),
    ("2001:db8::1", IOCType.IPV6),
    ("2001:0db8:0000:0000:0000:0000:0000:0001", IOCType.IPV6),
    # --- хеши ---
    ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5),
    ("D41D8CD98F00B204E9800998ECF8427E", IOCType.MD5),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.SHA1),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.SHA256),
    # --- домены ---
    ("example.com", IOCType.DOMAIN),
    ("sub.domain.example.org", IOCType.DOMAIN),
    ("xn----8sbzclmxk.xn--p1ai", IOCType.DOMAIN),
    # --- URL ---
    ("http://example.com/index.html", IOCType.URL),
    ("https://example.com:8443/a/b?c=d#e", IOCType.URL),
    ("ftp://files.example.net/pub", IOCType.URL),
    ("example.com/login.php", IOCType.URL),   # без схемы, но с путём
    # --- мусор ---
    ("", IOCType.UNKNOWN),
    ("   ", IOCType.UNKNOWN),
    ("not-an-ioc", IOCType.UNKNOWN),
    ("just some words", IOCType.UNKNOWN),
    ("192.0.2.999", IOCType.UNKNOWN),          # невалидный октет
    ("zzzz8cd98f00b204e9800998ecf8427e", IOCType.UNKNOWN),  # не hex
    ("d41d8cd98f00b204e9800998ecf8427", IOCType.UNKNOWN),   # 31 символ
])
def test_detect_type(value, expected):
    assert detect_type(value) is expected


def test_ip_wins_over_domain():
    """Регрессия: наивная FQDN-регулярка матчит '8.8.8.8' как домен."""
    assert detect_type("8.8.8.8") is IOCType.IPV4
    assert detect_type("1.1.1.1") is not IOCType.DOMAIN


def test_url_wins_over_domain():
    """'example.com/path' — это URL, а не домен с мусором."""
    assert detect_type("example.com/path") is IOCType.URL


def test_hash_length_is_strict():
    """Длина хеша проверяется точно: 31 и 33 символа — не MD5."""
    assert looks_like_hash("a" * 32) is IOCType.MD5
    assert looks_like_hash("a" * 31) is None
    assert looks_like_hash("a" * 33) is None


def test_domain_requires_valid_tld():
    assert looks_like_domain("example.com") is True
    assert looks_like_domain("localhost") is False   # одна метка
    assert looks_like_domain("example.1") is False   # цифровой TLD
    assert looks_like_domain("a" * 300 + ".com") is False
