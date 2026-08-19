"""Тесты парсера Linux auth.log."""

from datetime import timezone

import pytest

from log_analyzer.models import EventOutcome, Platform
from log_analyzer.parsers.base import ParseError
from log_analyzer.parsers.linux_auth import LinuxAuthParser


def write(tmp_path, content: str, name: str = "auth.log"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def parser():
    return LinuxAuthParser(tz="UTC", default_year=2026)


def test_failed_password(parser, tmp_path):
    path = write(tmp_path, "Aug 18 21:01:00 web01 sshd[1]: Failed password for "
                           "root from 192.0.2.10 port 51234 ssh2\n")
    events = list(parser.parse(path))
    assert len(events) == 1
    assert events[0].outcome is EventOutcome.FAILURE
    assert events[0].username == "root"
    assert events[0].source_ip == "192.0.2.10"
    assert events[0].source_port == 51234
    assert events[0].platform is Platform.LINUX
    assert events[0].invalid_user is False


def test_invalid_user_flag(parser, tmp_path):
    """Пометка invalid user отличает разведку имён от подбора пароля."""
    path = write(tmp_path, "Aug 18 21:01:00 web01 sshd[1]: Failed password for "
                           "invalid user oracle from 192.0.2.10 port 1 ssh2\n")
    events = list(parser.parse(path))
    assert events[0].invalid_user is True
    assert events[0].username == "oracle"


def test_accepted_password_and_publickey(parser, tmp_path):
    path = write(tmp_path,
                 "Aug 18 21:05:00 web01 sshd[1]: Accepted password for alice "
                 "from 198.51.100.5 port 4321 ssh2\n"
                 "Aug 18 21:06:00 web01 sshd[2]: Accepted publickey for bob "
                 "from 198.51.100.6 port 4322 ssh2: RSA SHA256:AAAA\n")
    events = list(parser.parse(path))
    assert [e.outcome for e in events] == [EventOutcome.SUCCESS, EventOutcome.SUCCESS]
    assert events[1].extra["method"] == "publickey"


def test_sudo_failure_and_success(parser, tmp_path):
    path = write(tmp_path,
                 "Aug 18 21:06:00 web01 sudo: bob : 3 incorrect password attempts ; "
                 "TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash\n"
                 "Aug 18 21:07:00 web01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
                 "USER=root ; COMMAND=/usr/bin/id\n")
    events = list(parser.parse(path))
    assert events[0].event_type == "sudo_auth"
    assert events[0].outcome is EventOutcome.FAILURE
    assert events[1].event_type == "sudo_command"
    assert events[1].extra["target_user"] == "root"


def test_iso_timestamps_supported(parser, tmp_path):
    """Современный rsyslog пишет ISO 8601 со смещением — тоже должно работать."""
    path = write(tmp_path, "2026-08-18T21:01:00+03:00 web01 sshd[1]: Failed password "
                           "for root from 192.0.2.10 port 1 ssh2\n")
    events = list(parser.parse(path))
    assert events[0].timestamp.tzinfo == timezone.utc
    assert events[0].timestamp.hour == 18   # 21:00 MSK -> 18:00 UTC


def test_timezone_is_applied(tmp_path):
    """Часовой пояс из конфигурации: syslog его не содержит."""
    path = write(tmp_path, "Aug 18 21:00:00 web01 sshd[1]: Failed password for "
                           "root from 192.0.2.10 port 1 ssh2\n")
    moscow = LinuxAuthParser(tz="Europe/Moscow", default_year=2026)
    events = list(moscow.parse(path))
    assert events[0].timestamp.hour == 18   # 21:00 MSK == 18:00 UTC


def test_year_is_taken_from_settings(parser, tmp_path):
    path = write(tmp_path, "Aug 18 21:00:00 web01 sshd[1]: Failed password for "
                           "root from 192.0.2.10 port 1 ssh2\n")
    assert list(parser.parse(path))[0].timestamp.year == 2026


def test_irrelevant_lines_are_not_counted_as_errors(parser, tmp_path):
    """Строки не про аутентификацию не должны портить метрику покрытия."""
    path = write(tmp_path,
                 "Aug 18 21:00:00 web01 systemd[1]: Started Daily apt activities.\n"
                 "Aug 18 21:00:10 web01 CRON[900]: pam_unix(cron:session): "
                 "session opened for user root by (uid=0)\n"
                 "Aug 18 21:01:00 web01 sshd[1]: Failed password for root "
                 "from 192.0.2.10 port 1 ssh2\n")
    events = list(parser.parse(path))
    assert len(events) == 1
    assert parser.stats.unparsed == 0
    assert parser.stats.coverage == 100.0


def test_missing_file(parser, tmp_path):
    with pytest.raises(ParseError, match="не найден"):
        list(parser.parse(tmp_path / "нет.log"))


def test_sniff_recognises_syslog(tmp_path):
    path = write(tmp_path, "Aug 18 21:01:00 web01 sshd[1]: Failed password for "
                           "root from 192.0.2.10 port 1 ssh2\n")
    assert LinuxAuthParser.sniff(path.read_text(), path) is True


def test_sniff_rejects_csv(tmp_path):
    path = write(tmp_path, "TimeCreated,Id\n2026-01-01,4625\n", name="x.csv")
    assert LinuxAuthParser.sniff(path.read_text(), path) is False
