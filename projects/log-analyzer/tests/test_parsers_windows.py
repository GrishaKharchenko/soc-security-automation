"""Тесты парсера выгрузки Windows Security Log."""

import json

import pytest

from log_analyzer.models import EventOutcome, Platform
from log_analyzer.parsers.windows_evtx_export import WindowsEventLogParser

HEADER = ("TimeCreated,Id,Computer,TargetUserName,IpAddress,IpPort,"
          "LogonType,Status,WorkstationName\n")


@pytest.fixture
def parser():
    return WindowsEventLogParser(tz="UTC")


def write(tmp_path, content, name="sec.csv"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_failed_logon_4625(parser, tmp_path):
    path = write(tmp_path, HEADER + "2026-08-18T10:00:00Z,4625,DC01,admin,"
                                    "192.0.2.77,50122,3,0xc000006a,WKS-01\n")
    events = list(parser.parse(path))
    assert events[0].outcome is EventOutcome.FAILURE
    assert events[0].platform is Platform.WINDOWS
    assert events[0].event_id == "4625"
    assert events[0].extra["failure_reason"] == "неверный пароль"


def test_nonexistent_account_maps_to_invalid_user(parser, tmp_path):
    """Статус 0xc0000064 — прямой аналог «invalid user» в Linux."""
    path = write(tmp_path, HEADER + "2026-08-18T10:00:00Z,4625,DC01,nosuchuser,"
                                    "192.0.2.77,1,3,0xc0000064,WKS-01\n")
    assert list(parser.parse(path))[0].invalid_user is True


def test_rdp_logon_type_is_decoded(parser, tmp_path):
    path = write(tmp_path, HEADER + "2026-08-18T10:00:00Z,4624,DC01,alice,"
                                    "198.51.100.9,1,10,0x0,WKS-02\n")
    event = list(parser.parse(path))[0]
    assert event.logon_type == "10"
    assert "RDP" in event.extra["logon_type_name"]


def test_machine_and_system_accounts_are_skipped(parser, tmp_path):
    """DC01$ и SYSTEM — служебный шум, засоряющий детекты."""
    path = write(tmp_path, HEADER
                 + "2026-08-18T10:00:00Z,4624,DC01,DC01$,-,0,3,0x0,-\n"
                   "2026-08-18T10:00:01Z,4624,DC01,SYSTEM,-,0,5,0x0,-\n"
                   "2026-08-18T10:00:02Z,4624,DC01,alice,198.51.100.9,1,10,0x0,W\n")
    events = list(parser.parse(path))
    assert len(events) == 1
    assert events[0].username == "alice"


def test_unknown_event_ids_are_ignored(parser, tmp_path):
    path = write(tmp_path, HEADER + "2026-08-18T10:00:00Z,5058,DC01,alice,-,0,,,-\n")
    assert list(parser.parse(path)) == []
    assert parser.stats.skipped_irrelevant == 1


def test_alternative_column_names(parser, tmp_path):
    """Выгрузки разных инструментов называют колонки по-разному."""
    path = write(tmp_path, "TimeGenerated,EventID,MachineName,AccountName,SourceIP\n"
                           "2026-08-18 10:00:00,4625,DC01,admin,192.0.2.77\n")
    events = list(parser.parse(path))
    assert len(events) == 1
    assert events[0].username == "admin"
    assert events[0].source_ip == "192.0.2.77"


def test_semicolon_delimiter(parser, tmp_path):
    path = write(tmp_path, "TimeCreated;Id;TargetUserName;IpAddress\n"
                           "2026-08-18T10:00:00Z;4625;admin;192.0.2.77\n")
    assert len(list(parser.parse(path))) == 1


def test_json_array_input(parser, tmp_path):
    records = [{"TimeCreated": "2026-08-18T10:00:00Z", "Id": 4625,
                "TargetUserName": "admin", "IpAddress": "192.0.2.77",
                "LogonType": "3", "Status": "0xc000006a"}]
    path = write(tmp_path, json.dumps(records), name="sec.json")
    events = list(parser.parse(path))
    assert len(events) == 1
    assert events[0].outcome is EventOutcome.FAILURE


def test_jsonl_input(parser, tmp_path):
    lines = "\n".join(json.dumps({"TimeCreated": f"2026-08-18T10:00:0{i}Z",
                                  "Id": 4625, "TargetUserName": "admin",
                                  "IpAddress": "192.0.2.77"}) for i in range(3))
    path = write(tmp_path, lines, name="sec.jsonl")
    assert len(list(parser.parse(path))) == 3


def test_us_date_format(parser, tmp_path):
    path = write(tmp_path, HEADER + "8/18/2026 10:00:00 AM,4625,DC01,admin,"
                                    "192.0.2.77,1,3,0xc000006a,W\n")
    events = list(parser.parse(path))
    assert len(events) == 1
    assert events[0].timestamp.hour == 10


def test_localhost_addresses_are_dropped(parser, tmp_path):
    """127.0.0.1 и «-» не несут информации об источнике."""
    path = write(tmp_path, HEADER + "2026-08-18T10:00:00Z,4625,DC01,admin,"
                                    "127.0.0.1,1,2,0xc000006a,W\n")
    assert list(parser.parse(path))[0].source_ip is None


def test_sniff(tmp_path):
    path = write(tmp_path, HEADER + "2026-08-18T10:00:00Z,4625,DC01,a,-,0,3,0x0,-\n")
    assert WindowsEventLogParser.sniff(path.read_text(), path) is True
