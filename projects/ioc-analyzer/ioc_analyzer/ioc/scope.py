"""Проверка, имеет ли смысл вообще запрашивать индикатор у Threat Intelligence.

Модуль появился после первого прогона по реальному VirusTotal. Выяснилось, что
часть индикаторов провайдер не просто «не знает», а **отказывается принимать**:

    HTTP 400: Domain "malware-c2.test" is not a valid domain pattern

Зоны ``.test`` и ``.example`` зарезервированы RFC 2606 и не существуют в корне
публичного DNS — искать их негде, и никакой провайдер их не проверит.

То же самое с частными и служебными IP: ``10.0.0.1`` из внутреннего лога SIEM
попадает в фид регулярно, но запрашивать его у VirusTotal бессмысленно —
адрес принадлежит вашей же сети.

Смысл модуля — отсеять такие индикаторы **до** обращения к API. Это экономит
квоту (500 запросов в сутки у публичного ключа) и, что важнее, не засоряет
отчёт записями со статусом «ошибка», которые аналитик всё равно не разберёт.
"""

from __future__ import annotations

import ipaddress

from ..models import IOC, IOCType

# Зоны, зарезервированные RFC 2606 и RFC 6761: в публичном DNS их не бывает.
RESERVED_TLDS: frozenset[str] = frozenset({
    "test",       # RFC 2606 — тестовые данные
    "example",    # RFC 2606 — документация
    "invalid",    # RFC 2606 — заведомо некорректное имя
    "localhost",  # RFC 6761 — петля
    "local",      # RFC 6762 — mDNS, только внутри сегмента
})

# Специальные суффиксы (проверяются целиком, а не по последней метке).
RESERVED_SUFFIXES: tuple[str, ...] = (
    ".home.arpa",   # RFC 8375 — домашние сети
    ".in-addr.arpa",
    ".ip6.arpa",
)

# Диапазоны, которые не маршрутизируются в интернете.
#
# ВАЖНО: сюда намеренно НЕ включены документационные диапазоны RFC 5737
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) и RFC 3849 (2001:db8::/32).
# Стандартный ``ipaddress.is_private`` считает их приватными, но VirusTotal
# их принимает и отдаёт данные — проверено живым запросом. Отсекать то, что
# провайдер обрабатывает, было бы потерей функциональности.
_NON_ROUTABLE_V4 = tuple(ipaddress.ip_network(cidr) for cidr in (
    "0.0.0.0/8",        # «этот» хост
    "10.0.0.0/8",       # RFC 1918
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local
    "172.16.0.0/12",    # RFC 1918
    "192.168.0.0/16",   # RFC 1918
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # зарезервировано
))
_NON_ROUTABLE_V6 = tuple(ipaddress.ip_network(cidr) for cidr in (
    "::/128",           # неопределённый адрес
    "::1/128",          # loopback
    "fc00::/7",         # unique local
    "fe80::/10",        # link-local
    "ff00::/8",         # multicast
))


def is_reserved_domain(value: str) -> bool:
    """Домен в зоне, которой не существует в публичном DNS."""
    value = value.strip().rstrip(".").lower()
    if not value:
        return False
    if any(value.endswith(suffix) for suffix in RESERVED_SUFFIXES):
        return True
    return value.rsplit(".", 1)[-1] in RESERVED_TLDS


def is_non_routable_ip(value: str) -> bool:
    """IP из диапазона, который не встречается в публичном интернете."""
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    networks = _NON_ROUTABLE_V4 if ip.version == 4 else _NON_ROUTABLE_V6
    return any(ip in network for network in networks)


def check_enrichable(ioc: IOC) -> str | None:
    """Вернуть причину, по которой индикатор не стоит отправлять в TI.

    ``None`` означает «отправлять можно». Возврат строки, а не булева значения,
    сделан намеренно: причина попадает прямо в отчёт, и аналитик видит, почему
    индикатор пропущен, вместо молчаливого исчезновения из результатов.
    """
    if ioc.type is IOCType.DOMAIN and is_reserved_domain(ioc.value):
        return (
            f"Домен в зарезервированной зоне «.{ioc.value.rsplit('.', 1)[-1]}» "
            "(RFC 2606/6761) — в публичном DNS не существует, "
            "Threat Intelligence его не проверит. Похоже на тестовые данные."
        )

    if ioc.type.is_ip and is_non_routable_ip(ioc.value):
        return (
            "Немаршрутизируемый адрес (приватная сеть, loopback или multicast) — "
            "во внешних источниках данных о нём нет. Проверяйте по внутренним "
            "системам: DHCP, инвентаризация, логи."
        )

    if ioc.type is IOCType.URL:
        from urllib.parse import urlsplit

        host = urlsplit(ioc.value).hostname or ""
        if is_reserved_domain(host):
            return (
                "Хост URL находится в зарезервированной зоне (RFC 2606/6761) — "
                "Threat Intelligence такой адрес не проверит."
            )
        if is_non_routable_ip(host):
            return "Хост URL — немаршрутизируемый адрес, внешняя проверка невозможна."

    return None
