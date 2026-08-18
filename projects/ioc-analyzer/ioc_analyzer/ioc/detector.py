"""Определение типа индикатора компрометации.

Порядок проверок неслучаен и является главной логикой модуля:

1. **hash**   — чистая шестнадцатеричная строка фиксированной длины (32/40/64);
2. **url**    — есть схема (http/ftp) или путь/параметры;
3. **ip**     — валидный IPv4/IPv6 (проверяем стандартным ``ipaddress``);
4. **domain** — всё остальное, что похоже на FQDN с известной структурой.

Почему именно так: ``8.8.8.8`` подходит и под «домен» по наивной регулярке,
а ``example.com/path`` — и под домен, и под URL. Идём от самого строгого
формата к самому свободному, иначе получим ложные срабатывания.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from ..models import IOCType

# Хеши: длина строго фиксирована, поэтому одной регуляркой на алфавит не обойтись.
_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
_HASH_LENGTHS: dict[int, IOCType] = {
    32: IOCType.MD5,
    40: IOCType.SHA1,
    64: IOCType.SHA256,
}

# Схемы, которые встречаются во входных фидах.
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

# Метка домена: буквы/цифры/дефис, дефис не по краям; поддержаны IDN (punycode
# приходит уже нормализованным, юникод-буквы разрешены явно).
_LABEL = r"[a-zA-Z0-9¡-￿](?:[a-zA-Z0-9¡-￿-]{0,61}[a-zA-Z0-9¡-￿])?"
# TLD: либо буквенный (com, рф), либо punycode-форма IDN (xn--p1ai) —
# у неё внутри есть цифры и дефисы, обычный буквенный класс её не примет.
_TLD = r"(?:xn--[a-zA-Z0-9-]{2,59}|[a-zA-Z¡-￿]{2,63})"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_TLD}$")


def looks_like_hash(value: str) -> IOCType | None:
    """MD5/SHA1/SHA256 определяются по длине + шестнадцатеричному алфавиту."""
    if not _HASH_RE.match(value):
        return None
    return _HASH_LENGTHS.get(len(value))


def looks_like_ip(value: str) -> IOCType | None:
    """Валидацию IP отдаём стандартной библиотеке — регулярки тут ошибаются."""
    candidate = value
    # IPv6 в URL-нотации: [2001:db8::1]
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6


def looks_like_url(value: str) -> bool:
    """URL = есть схема, либо есть путь/query/fragment после хоста."""
    if _SCHEME_RE.match(value):
        return True
    # Без схемы: 'example.com/login.php', 'evil.test:8080/a?b=1'
    head = value.split("#", 1)[0]
    return "/" in head or "?" in head


def looks_like_domain(value: str) -> bool:
    """FQDN: минимум две метки, длина <= 253, валидный TLD."""
    if len(value) > 253 or "." not in value:
        return False
    return bool(_DOMAIN_RE.match(value))


def detect_type(value: str) -> IOCType:
    """Определить тип уже **очищенного** (refang + trim) индикатора.

    Функция намеренно не занимается нормализацией: одна функция — одна
    ответственность, и тесты на детекцию не зависят от правил нормализации.
    """
    value = value.strip()
    if not value:
        return IOCType.UNKNOWN

    if (hash_type := looks_like_hash(value)) is not None:
        return hash_type

    if looks_like_url(value):
        return IOCType.URL

    if (ip_type := looks_like_ip(value)) is not None:
        return ip_type

    if looks_like_domain(value):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def detect_url_host_type(url: str) -> IOCType:
    """Тип хоста внутри URL — полезно в отчётах и для будущего pivot-анализа."""
    host = urlsplit(url if _SCHEME_RE.match(url) else f"http://{url}").hostname or ""
    if (ip_type := looks_like_ip(host)) is not None:
        return ip_type
    return IOCType.DOMAIN if looks_like_domain(host) else IOCType.UNKNOWN
