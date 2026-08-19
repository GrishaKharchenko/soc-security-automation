"""Парсер выгрузки Windows Security Log (CSV или JSON).

**Почему не бинарный .evtx.** Разбор нативного формата требует внешней
библиотеки и возни с бинарной структурой, которая к обнаружению атак
отношения не имеет. В реальной работе аналитик почти никогда не держит в
руках сырой EVTX: события приезжают из SIEM, из ``Get-WinEvent | Export-Csv``
или из выгрузки коллектора — то есть уже в CSV или JSON. Поддерживать надо
именно этот вход.

**Какие события разбираются:**

===== ======================================== ==============================
Код   Событие                                  Зачем нужно
===== ======================================== ==============================
4624  Успешный вход                            фиксация успеха, тип входа
4625  Неудачный вход                           основа детектов перебора
4634  Выход                                    контекст сессии
4648  Вход с явными учётными данными           runas, боковое перемещение
4672  Назначены особые привилегии                 вход администратора
4720  Создана учётная запись                   закрепление в системе
4740  Учётная запись заблокирована             следствие перебора
4776  Проверка учётных данных (NTLM)           перебор по NTLM
===== ======================================== ==============================

Названия колонок в выгрузках различаются («TimeCreated» или «Дата и время»,
«Id» или «EventID»), поэтому сопоставление идёт по списку кандидатов — так же,
как в IOC Analyzer при поиске колонки с индикатором.
"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from zoneinfo import ZoneInfo

from ..logging_setup import get_logger
from ..models import AuthEvent, EventOutcome, Platform
from .base import LogParser, read_text

logger = get_logger("parsers.windows")

# Код события -> (исход, тип события)
EVENT_IDS: dict[str, tuple[EventOutcome, str]] = {
    "4624": (EventOutcome.SUCCESS, "windows_logon"),
    "4625": (EventOutcome.FAILURE, "windows_logon"),
    "4634": (EventOutcome.UNKNOWN, "windows_logoff"),
    "4648": (EventOutcome.SUCCESS, "windows_explicit_credentials"),
    "4672": (EventOutcome.SUCCESS, "windows_privileged_logon"),
    "4720": (EventOutcome.SUCCESS, "windows_account_created"),
    "4740": (EventOutcome.FAILURE, "windows_account_lockout"),
    "4776": (EventOutcome.UNKNOWN, "windows_credential_validation"),
}

# Типы входа Windows — важны для трактовки события.
LOGON_TYPES: dict[str, str] = {
    "2": "Interactive (консоль)",
    "3": "Network (сетевой доступ, SMB)",
    "4": "Batch (планировщик)",
    "5": "Service (служба)",
    "7": "Unlock (разблокировка экрана)",
    "8": "NetworkCleartext (пароль открытым текстом)",
    "9": "NewCredentials (runas /netonly)",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive (кешированные учётные данные)",
}

# Кандидаты имён колонок: выгрузки различаются от инструмента к инструменту.
_FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timecreated", "timegenerated", "eventtime", "timestamp",
                  "date", "@timestamp", "created", "дата и время", "время"),
    "event_id": ("id", "eventid", "event_id", "eventcode", "код события"),
    "computer": ("computer", "computername", "machinename", "hostname",
                 "host", "компьютер"),
    "username": ("targetusername", "target_user_name", "accountname",
                 "username", "user", "subjectusername", "имя учетной записи"),
    "source_ip": ("ipaddress", "ip_address", "sourcenetworkaddress",
                  "clientaddress", "sourceip", "workstationip", "ip"),
    "source_port": ("ipport", "sourceport", "port"),
    "logon_type": ("logontype", "logon_type", "тип входа"),
    "status": ("status", "substatus", "failurereason", "result"),
    "workstation": ("workstationname", "workstation", "рабочая станция"),
    "message": ("message", "description", "renderedmessage", "сообщение"),
}

# Коды отказа Windows: без расшифровки они бесполезны для аналитика.
FAILURE_REASONS: dict[str, str] = {
    "0xc000006a": "неверный пароль",
    "0xc0000064": "учётная запись не существует",
    "0xc0000234": "учётная запись заблокирована",
    "0xc0000072": "учётная запись отключена",
    "0xc000006f": "вход вне разрешённого времени",
    "0xc0000070": "вход с недопустимой рабочей станции",
    "0xc0000071": "срок действия пароля истёк",
    "0xc0000193": "срок действия учётной записи истёк",
    "0xc0000133": "рассинхронизация времени с контроллером домена",
}

_IP_CLEANUP = re.compile(r"^::ffff:", re.IGNORECASE)


class WindowsEventLogParser(LogParser):
    """Разбор Security Log, выгруженного в CSV или JSON."""

    name = "windows_export"
    description = "Выгрузка Windows Security Log в CSV или JSON (события 46xx/47xx)"

    def __init__(self, tz: str = "UTC") -> None:
        super().__init__()
        self.tz = ZoneInfo(tz)

    # ------------------------------------------------------------------ sniff

    @classmethod
    def sniff(cls, sample: str, path: Path) -> bool:
        suffix = path.suffix.lower()
        if suffix not in {".csv", ".json", ".jsonl", ".tsv"}:
            return False
        lowered = sample.lower()
        markers = ("targetusername", "eventid", "timecreated", "logontype",
                   '"id"', "ipaddress", "4625", "4624")
        return any(marker in lowered for marker in markers)

    # ------------------------------------------------------------- сопоставление

    @staticmethod
    def _build_field_map(fieldnames: list[str]) -> dict[str, str]:
        """Сопоставить реальные колонки файла с нашими логическими полями."""
        normalized = {name.strip().lower().lstrip("﻿"): name
                      for name in fieldnames if name}
        mapping: dict[str, str] = {}
        for logical, candidates in _FIELD_CANDIDATES.items():
            for candidate in candidates:
                if candidate in normalized:
                    mapping[logical] = normalized[candidate]
                    break
        return mapping

    @staticmethod
    def _value(row: dict[str, Any], mapping: dict[str, str], key: str) -> str:
        column = mapping.get(key)
        if column is None:
            return ""
        value = row.get(column)
        return "" if value is None else str(value).strip()

    # ------------------------------------------------------------------ время

    def _parse_timestamp(self, raw: str) -> datetime | None:
        if not raw:
            return None
        text = raw.strip().replace("Z", "+00:00")
        # ISO 8601 — самый частый случай в выгрузках и SIEM.
        try:
            parsed = datetime.fromisoformat(text.replace(" ", "T", 1)
                                            if "T" not in text else text)
        except ValueError:
            parsed = None

        if parsed is None:
            for fmt in ("%m/%d/%Y %I:%M:%S %p", "%d.%m.%Y %H:%M:%S",
                        "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
                try:
                    parsed = datetime.strptime(raw.strip(), fmt)
                    break
                except ValueError:
                    continue

        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=self.tz)
        return parsed.astimezone(timezone.utc)

    # ------------------------------------------------------------------ разбор

    def parse(self, path: Path) -> Iterator[AuthEvent]:
        text = read_text(path)
        suffix = path.suffix.lower()
        rows = (self._iter_json(text) if suffix in {".json", ".jsonl"}
                else self._iter_csv(text, suffix))

        for line_number, row in rows:
            self.stats.total_lines += 1
            event = self._row_to_event(row, path, line_number)
            if event is not None:
                self.stats.parsed += 1
                yield event

    def _iter_csv(self, text: str, suffix: str) -> Iterator[tuple[int, dict[str, Any]]]:
        delimiter = "\t" if suffix == ".tsv" else ","
        if suffix != ".tsv":
            try:
                delimiter = csv.Sniffer().sniff(
                    "\n".join(text.splitlines()[:20]), delimiters=",;\t|"
                ).delimiter
            except csv.Error:
                delimiter = ","
        reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
        self._field_map = self._build_field_map(reader.fieldnames or [])
        if "event_id" not in self._field_map:
            logger.warning("В файле нет колонки с кодом события — "
                           "проверьте, та ли это выгрузка")
        for line_number, row in enumerate(reader, start=2):
            yield line_number, row

    def _iter_json(self, text: str) -> Iterator[tuple[int, dict[str, Any]]]:
        text = text.strip()
        records: list[dict[str, Any]] = []
        if text.startswith("["):
            try:
                loaded = json.loads(text)
                records = [r for r in loaded if isinstance(r, dict)]
            except json.JSONDecodeError as exc:
                logger.error("Некорректный JSON: %s", exc)
        else:
            # JSON Lines — по объекту на строку, типичный экспорт SIEM.
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    self.stats.note_unparsed(line)
                    continue
                if isinstance(record, dict):
                    records.append(record)

        if records:
            keys: list[str] = []
            for record in records[:50]:
                for key in record:
                    if key not in keys:
                        keys.append(key)
            self._field_map = self._build_field_map(keys)
        else:
            self._field_map = {}

        for line_number, record in enumerate(records, start=1):
            yield line_number, record

    def _row_to_event(
        self, row: dict[str, Any], path: Path, line_number: int
    ) -> AuthEvent | None:
        mapping = getattr(self, "_field_map", {})
        event_id = self._value(row, mapping, "event_id")
        # Код может приехать как "4625" или как "Microsoft-Windows-Security/4625"
        event_id = event_id.rsplit("/", 1)[-1].strip()

        if event_id not in EVENT_IDS:
            self.stats.skipped_irrelevant += 1
            return None

        timestamp = self._parse_timestamp(self._value(row, mapping, "timestamp"))
        if timestamp is None:
            self.stats.note_unparsed(str(row)[:200])
            return None

        outcome, event_type = EVENT_IDS[event_id]
        username = self._value(row, mapping, "username") or None
        # Служебные учётные записи компьютеров (WEB01$) и SYSTEM — шум.
        if username and (username.endswith("$") or username.upper() in {"SYSTEM", "-"}):
            self.stats.skipped_irrelevant += 1
            return None

        source_ip = self._value(row, mapping, "source_ip") or None
        if source_ip in {"-", "::1", "127.0.0.1", ""}:
            source_ip = None
        if source_ip:
            source_ip = _IP_CLEANUP.sub("", source_ip)

        port_raw = self._value(row, mapping, "source_port")
        logon_type = self._value(row, mapping, "logon_type") or None
        status = self._value(row, mapping, "status").lower()

        extra: dict[str, Any] = {}
        if logon_type:
            extra["logon_type_name"] = LOGON_TYPES.get(logon_type, f"тип {logon_type}")
        if status:
            extra["status_code"] = status
            reason = FAILURE_REASONS.get(status)
            if reason:
                extra["failure_reason"] = reason
        workstation = self._value(row, mapping, "workstation")
        if workstation and workstation != "-":
            extra["workstation"] = workstation

        return AuthEvent(
            timestamp=timestamp,
            outcome=outcome,
            platform=Platform.WINDOWS,
            username=username,
            source_ip=source_ip,
            source_port=int(port_raw) if port_raw.isdigit() and port_raw != "0" else None,
            hostname=self._value(row, mapping, "computer") or None,
            service="security",
            event_type=event_type,
            event_id=event_id,
            logon_type=logon_type,
            # Код 0xc0000064 означает «такой учётной записи не существует» —
            # прямой аналог «invalid user» в Linux, важен для детекта разведки.
            invalid_user=status == "0xc0000064",
            raw=self._value(row, mapping, "message")[:500] or str(row)[:500],
            source_file=str(path),
            line_number=line_number,
            extra=extra,
        )
