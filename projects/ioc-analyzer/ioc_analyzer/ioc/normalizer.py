"""Нормализация индикаторов и дедупликация.

Зачем это нужно в реальном SOC: один и тот же индикатор приезжает из разных
источников в разном виде — ``HXXP://Evil[.]Test/Login``, ``evil.test``,
``EVIL.TEST.`` — и без приведения к канонической форме мы трижды сожжём
квоту API и трижды покажем аналитику одно и то же.

Ключевой шаг — **refang**: «обезвреженная» запись (``hxxp``, ``[.]``, ``(.)``)
это стандарт индустрии для передачи IOC в письмах и тикетах, чтобы никто
случайно не кликнул. Инструмент обязан её понимать.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from ..logging_setup import get_logger
from ..models import IOC, IOCType
from .detector import detect_type

logger = get_logger("ioc.normalizer")

# Паттерны «обезвреживания». Порядок важен: сначала схема, потом разделители.
_DEFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^h(?:xx|XX|\*\*)p(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"^h(?:xx|XX)ps?\[:\]//", re.IGNORECASE), "https://"),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\s*\[\s*(?:at|@)\s*\]\s*", re.IGNORECASE), "@"),
    (re.compile(r"\s*\[\s*dot\s*\]\s*", re.IGNORECASE), "."),
    (re.compile(r"^\s*(?:hxxp|meow|hXXp)\b", re.IGNORECASE), "http"),
]

# Мусор, которым обрастает IOC при копировании из отчётов и тикетов.
_WRAPPERS = "\"'`<>«»()[]{}"
_TRAILING_PUNCT = ".,;:!?"


def refang(value: str) -> tuple[str, bool]:
    """Вернуть «боевую» форму индикатора и флаг, была ли запись обезврежена."""
    original = value
    for pattern, replacement in _DEFANG_PATTERNS:
        value = pattern.sub(replacement, value)
    return value, value != original


def strip_noise(value: str) -> str:
    """Убрать кавычки, скобки и хвостовую пунктуацию из строки фида.

    Чистим в цикле, а не за один проход: обёртки и пунктуация чередуются
    (``(example.com);``), и одного прохода не хватает.
    """
    value = value.strip()
    while True:
        stripped = value.strip().strip(_WRAPPERS).strip()
        # Хвостовую точку/запятую режем, но не трогаем точку внутри домена.
        while stripped and stripped[-1] in _TRAILING_PUNCT:
            stripped = stripped[:-1]
        stripped = stripped.strip()
        if stripped == value:
            return stripped
        value = stripped


def normalize_domain(value: str) -> str:
    """Домен: нижний регистр, без корневой точки, IDN -> punycode."""
    value = value.strip().rstrip(".").lower()
    try:
        # idna кодирует «мой-сайт.рф» в xn--... — именно так его знает VT.
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # Не-IDN или слишком длинная метка — оставляем как есть, тип уже проверен.
        pass
    return value


def normalize_ip(value: str) -> str:
    """IP: сжатая каноническая форма (``2001:0db8::0001`` -> ``2001:db8::1``)."""
    import ipaddress

    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return candidate


def normalize_url(value: str) -> str:
    """URL: схема и хост в нижний регистр, путь — как есть.

    Путь и query регистрозависимы (``/Login`` и ``/login`` — разные ресурсы),
    поэтому трогать их нельзя. Отсутствующую схему достраиваем до ``http://``,
    иначе VirusTotal не примет индикатор.
    """
    value = value.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", value):
        value = f"http://{value}"
    parts = urlsplit(value)
    netloc = parts.netloc.lower()
    # Убираем дефолтные порты: http://a.test:80/ == http://a.test/
    if parts.scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif parts.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, parts.fragment))


def normalize_hash(value: str) -> str:
    """Хеш: нижний регистр — VT и большинство фидов используют именно его."""
    return value.strip().lower()


_NORMALIZERS = {
    IOCType.DOMAIN: normalize_domain,
    IOCType.URL: normalize_url,
    IOCType.IPV4: normalize_ip,
    IOCType.IPV6: normalize_ip,
    IOCType.MD5: normalize_hash,
    IOCType.SHA1: normalize_hash,
    IOCType.SHA256: normalize_hash,
}


def normalize(raw: str, line_number: int = 0) -> IOC | None:
    """Превратить сырую строку в объект :class:`IOC`.

    Возвращает ``None``, если строка пустая или тип определить не удалось —
    вызывающий код решает, что делать с мусором (мы его логируем и считаем).
    """
    cleaned = strip_noise(raw)
    if not cleaned:
        return None

    refanged, was_defanged = refang(cleaned)
    refanged = strip_noise(refanged)

    ioc_type = detect_type(refanged)
    if ioc_type is IOCType.UNKNOWN:
        logger.debug("Строка %s: не удалось определить тип IOC: %r", line_number, raw)
        return None

    normalizer = _NORMALIZERS.get(ioc_type)
    value = normalizer(refanged) if normalizer else refanged

    return IOC(
        value=value,
        type=ioc_type,
        raw=raw.strip(),
        source_lines=[line_number] if line_number else [],
        defanged=was_defanged,
    )


def deduplicate(iocs: list[IOC]) -> list[IOC]:
    """Слить дубликаты по ключу ``(тип, значение)``, сохранив статистику.

    Дубликаты не выбрасываются молча: у выжившего IOC растёт ``occurrences`` и
    копится список ``source_lines``. Аналитику важно знать, что индикатор
    встретился в фиде 40 раз — это сигнал сам по себе.
    """
    merged: dict[tuple[IOCType, str], IOC] = {}
    for ioc in iocs:
        key = (ioc.type, ioc.value)
        existing = merged.get(key)
        if existing is None:
            merged[key] = ioc
            continue
        existing.occurrences += 1
        existing.source_lines.extend(ioc.source_lines)
        # Если хоть где-то индикатор пришёл обезвреженным — фиксируем это.
        existing.defanged = existing.defanged or ioc.defanged

    removed = len(iocs) - len(merged)
    if removed:
        logger.info("Дедупликация: удалено %d повторов, осталось %d уникальных",
                    removed, len(merged))
    return list(merged.values())
