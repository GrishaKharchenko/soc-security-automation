"""Парсер Linux-логов аутентификации (``/var/log/auth.log``, ``/var/log/secure``).

Разбираются события sshd, sudo и su — это три основных источника данных об
аутентификации на Linux-хосте.

Отдельная сложность формата: **классический syslog не содержит ни года, ни
часового пояса**.

    Aug 18 21:01:00 web01 sshd[1234]: Failed password for root from 192.0.2.10

Год приходится брать извне (из конфигурации или из времени изменения файла),
а часовой пояс — из конфигурации. Игнорировать это нельзя: все правила
работают с временными окнами, и ошибка в поясе на три часа развалит
корреляцию. Современный rsyslog умеет писать ISO 8601 со смещением — такой
формат тоже поддержан и предпочтителен.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from zoneinfo import ZoneInfo

from ..logging_setup import get_logger
from ..models import AuthEvent, EventOutcome, Platform
from .base import LogParser, read_text

logger = get_logger("parsers.linux_auth")

# Заголовок строки: время + хост + сервис[pid]: остаток
_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)
_ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# --- шаблоны сообщений sshd -------------------------------------------------
_SSH_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive\S*)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    r"(?:\s+port\s+(?P<port>\d+))?"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive\S*)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
)
_SSH_INVALID_USER = re.compile(
    r"^Invalid user\s+(?P<user>\S*)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
)
_SSH_PREAUTH_CLOSE = re.compile(
    r"^Connection (?:closed|reset) by (?:authenticating |invalid )?user\s+"
    r"(?P<user>\S+)\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_PAM_FAILURE = re.compile(
    r"pam_unix\((?P<svc>[\w-]+):auth\): authentication failure;.*?"
    r"(?:rhost=(?P<ip>\S+))?.*?(?:user=(?P<user>\S+))?$"
)

# --- шаблоны сообщений sudo -------------------------------------------------
_SUDO_OK = re.compile(
    r"^(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*"
    r"USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
)
_SUDO_FAIL = re.compile(
    r"^(?P<user>\S+)\s*:\s*(?P<count>\d+)\s+incorrect password attempts?"
)
_SUDO_NOT_ALLOWED = re.compile(
    r"^(?P<user>\S+)\s*:\s*user NOT in sudoers"
)

# Строки, которые заведомо не про аутентификацию — не считаем их «нераспознанными».
_IRRELEVANT_MARKERS = (
    "session opened for user", "session closed for user", "New session",
    "Removed session", "Starting", "Stopped", "Reloading",
    "pam_unix(cron:session)", "CRON", "Server listening on",
    "Received signal", "error: kex_exchange_identification",
    "Disconnected from", "Received disconnect", "banner exchange",
)


class LinuxAuthParser(LogParser):
    """Разбор auth.log / secure."""

    name = "linux_auth"
    description = "Linux /var/log/auth.log и /var/log/secure (sshd, sudo, su)"

    def __init__(self, tz: str = "UTC", default_year: int | None = None) -> None:
        super().__init__()
        self.tz = ZoneInfo(tz)
        self.default_year = default_year

    # ------------------------------------------------------------------ sniff

    @classmethod
    def sniff(cls, sample: str, path: Path) -> bool:
        if path.suffix.lower() in {".csv", ".json", ".jsonl"}:
            return False
        for line in sample.splitlines()[:60]:
            if _SYSLOG_RE.match(line) or _ISO_SYSLOG_RE.match(line):
                return True
        return False

    # -------------------------------------------------------------- время

    def _resolve_year(self, path: Path) -> int:
        """Год для syslog-записей: из конфигурации, иначе из mtime файла.

        Брать текущий год «на всякий случай» опасно: анализ прошлогоднего
        архива тогда получит будущие даты, и окна корреляции сойдутся неверно.
        Время модификации файла — более честное приближение.
        """
        if self.default_year:
            return self.default_year
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=self.tz).year
        except OSError:
            return datetime.now(tz=self.tz).year

    def _parse_syslog_ts(self, raw: str, year: int) -> datetime | None:
        try:
            month_name, day, clock = raw.split(maxsplit=2)
            month = _MONTHS[month_name]
            hour, minute, second = (int(x) for x in clock.split(":"))
            local = datetime(year, month, int(day), hour, minute, second, tzinfo=self.tz)
        except (ValueError, KeyError):
            return None
        return local.astimezone(timezone.utc)

    @staticmethod
    def _parse_iso_ts(raw: str) -> datetime | None:
        text = raw.replace("Z", "+00:00").replace(" ", "T", 1)
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    # -------------------------------------------------------------- разбор

    def parse(self, path: Path) -> Iterator[AuthEvent]:
        text = read_text(path)
        year = self._resolve_year(path)
        rollover_guard: datetime | None = None

        for line_number, line in enumerate(text.splitlines(), start=1):
            self.stats.total_lines += 1
            if not line.strip():
                continue

            match = _ISO_SYSLOG_RE.match(line)
            if match:
                timestamp = self._parse_iso_ts(match.group("ts"))
            else:
                match = _SYSLOG_RE.match(line)
                if not match:
                    self.stats.skipped_irrelevant += 1
                    continue
                timestamp = self._parse_syslog_ts(match.group("ts"), year)
                # Переход через новый год: если время «прыгнуло» назад более
                # чем на полгода, значит начался следующий год.
                if timestamp and rollover_guard and \
                        (rollover_guard - timestamp) > timedelta(days=180):
                    year += 1
                    timestamp = self._parse_syslog_ts(match.group("ts"), year)
                if timestamp:
                    rollover_guard = timestamp

            if timestamp is None:
                self.stats.note_unparsed(line)
                continue

            event = self._parse_message(
                timestamp=timestamp,
                hostname=match.group("host"),
                service=match.group("service"),
                message=match.group("message"),
                raw=line,
                path=path,
                line_number=line_number,
            )
            if event is None:
                continue
            self.stats.parsed += 1
            yield event

    def _parse_message(
        self, timestamp: datetime, hostname: str, service: str,
        message: str, raw: str, path: Path, line_number: int,
    ) -> AuthEvent | None:
        base = dict(
            timestamp=timestamp, platform=Platform.LINUX, hostname=hostname,
            service=service, raw=raw, source_file=str(path), line_number=line_number,
        )
        service_name = service.lower()

        if service_name.startswith("sshd"):
            return self._parse_sshd(message, base)
        if service_name.startswith("sudo"):
            return self._parse_sudo(message, base)
        if service_name.startswith("su"):
            return self._parse_su(message, base)

        if any(marker in message for marker in _IRRELEVANT_MARKERS):
            self.stats.skipped_irrelevant += 1
        else:
            self.stats.skipped_irrelevant += 1
        return None

    def _parse_sshd(self, message: str, base: dict) -> AuthEvent | None:
        if (m := _SSH_FAILED.match(message)):
            return AuthEvent(
                outcome=EventOutcome.FAILURE,
                username=m.group("user"),
                source_ip=m.group("ip"),
                source_port=int(m.group("port")) if m.group("port") else None,
                invalid_user=bool(m.group("invalid")),
                event_type="ssh_login",
                extra={"method": m.group("method")},
                **base,
            )

        if (m := _SSH_ACCEPTED.match(message)):
            return AuthEvent(
                outcome=EventOutcome.SUCCESS,
                username=m.group("user"),
                source_ip=m.group("ip"),
                source_port=int(m.group("port")) if m.group("port") else None,
                event_type="ssh_login",
                extra={"method": m.group("method")},
                **base,
            )

        if (m := _SSH_INVALID_USER.match(message)):
            return AuthEvent(
                outcome=EventOutcome.FAILURE,
                username=m.group("user") or "(пусто)",
                source_ip=m.group("ip"),
                source_port=int(m.group("port")) if m.group("port") else None,
                invalid_user=True,
                event_type="ssh_invalid_user",
                **base,
            )

        if (m := _SSH_PREAUTH_CLOSE.match(message)):
            return AuthEvent(
                outcome=EventOutcome.FAILURE,
                username=m.group("user"),
                source_ip=m.group("ip"),
                source_port=int(m.group("port")),
                event_type="ssh_preauth_close",
                **base,
            )

        if (m := _PAM_FAILURE.search(message)):
            return AuthEvent(
                outcome=EventOutcome.FAILURE,
                username=m.group("user"),
                source_ip=m.group("ip"),
                event_type="pam_auth_failure",
                **base,
            )

        self.stats.skipped_irrelevant += 1
        return None

    def _parse_sudo(self, message: str, base: dict) -> AuthEvent | None:
        if (m := _SUDO_FAIL.match(message)):
            return AuthEvent(
                outcome=EventOutcome.FAILURE,
                username=m.group("user"),
                event_type="sudo_auth",
                extra={"attempts": int(m.group("count"))},
                **base,
            )

        if (m := _SUDO_NOT_ALLOWED.match(message)):
            return AuthEvent(
                outcome=EventOutcome.FAILURE,
                username=m.group("user"),
                event_type="sudo_not_permitted",
                **base,
            )

        if (m := _SUDO_OK.match(message)):
            return AuthEvent(
                outcome=EventOutcome.SUCCESS,
                username=m.group("user"),
                event_type="sudo_command",
                extra={"target_user": m.group("target"),
                       "command": m.group("command")[:300],
                       "tty": m.group("tty")},
                **base,
            )

        if (m := _PAM_FAILURE.search(message)):
            return AuthEvent(
                outcome=EventOutcome.FAILURE,
                username=m.group("user"),
                event_type="sudo_auth",
                **base,
            )

        self.stats.skipped_irrelevant += 1
        return None

    def _parse_su(self, message: str, base: dict) -> AuthEvent | None:
        lowered = message.lower()
        if "authentication failure" in lowered or "failed su" in lowered:
            m = _PAM_FAILURE.search(message)
            return AuthEvent(
                outcome=EventOutcome.FAILURE,
                username=m.group("user") if m else None,
                event_type="su_auth",
                **base,
            )
        self.stats.skipped_irrelevant += 1
        return None
