"""Генератор безопасных синтетических логов для демонстрации и тестов.

Настоящие логи содержат реальные адреса, имена сотрудников и внутренние
хосты — публиковать их в репозитории нельзя. Поэтому данные генерируются:
адреса берутся из документационных диапазонов RFC 5737, имена вымышлены,
никаких реальных систем не упоминается.

Сценарии подобраны так, чтобы каждое правило имело и срабатывание, и
контрпример — иначе невозможно отличить работающий детект от детекта,
который срабатывает на что угодно.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(20260818)   # воспроизводимость: одинаковые данные при каждом запуске

HOST = "web01"
START = datetime(2026, 8, 17, 9, 0, 0)

LEGIT_USERS = ["alice", "bob", "carol", "dmitry", "elena"]
LEGIT_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]

ATTACKER_BRUTE = "192.0.2.66"        # подбор пароля к root
ATTACKER_SPRAY = "192.0.2.77"        # распыление по многим логинам
ATTACKER_ENUM = "192.0.2.88"         # перебор имён
BOTNET = [f"203.0.113.{n}" for n in (11, 12, 13, 14, 15)]

SPRAY_USERS = ["alice", "bob", "carol", "dmitry", "elena",
               "finance", "backup", "jenkins", "postgres", "webadmin"]
ENUM_USERS = ["oracle", "test", "guest", "ftpuser", "mysql", "ubuntu", "pi", "git"]


def ts(offset_seconds: int) -> str:
    return (START + timedelta(seconds=offset_seconds)).strftime("%b %e %H:%M:%S").replace("  ", "  ")


def line(offset: int, service: str, pid: int, message: str) -> str:
    return f"{ts(offset)} {HOST} {service}[{pid}]: {message}"


def build_auth_log() -> str:
    rows: list[tuple[int, str]] = []

    # --- фон: обычная работа сотрудников ------------------------------------
    for index, user in enumerate(LEGIT_USERS):
        offset = 600 + index * 900
        ip = LEGIT_IPS[index % len(LEGIT_IPS)]
        rows.append((offset, line(offset, "sshd", 2000 + index,
                                  f"Accepted publickey for {user} from {ip} "
                                  f"port {40000 + index} ssh2: RSA "
                                  f"SHA256:AAAA{index}BBBB")))
        rows.append((offset + 5, line(offset + 5, "systemd-logind", 500,
                                      f"New session {index + 3} of user {user}.")))

    # Контрпример: человек трижды ошибся паролем и вошёл. Порог = 5, поэтому
    # правило AUTH-001 сработать НЕ должно — это проверка на ложные срабатывания.
    for attempt in range(3):
        offset = 5400 + attempt * 20
        rows.append((offset, line(offset, "sshd", 2100 + attempt,
                                  f"Failed password for carol from 198.51.100.12 "
                                  f"port {41000 + attempt} ssh2")))
    rows.append((5500, line(5500, "sshd", 2110,
                            "Accepted password for carol from 198.51.100.12 "
                            "port 41100 ssh2")))

    # --- сценарий 1: разведка имён учётных записей (AUTH-004, T1087) --------
    for index, user in enumerate(ENUM_USERS):
        offset = 9000 + index * 12
        rows.append((offset, line(offset, "sshd", 3000 + index,
                                  f"Invalid user {user} from {ATTACKER_ENUM} "
                                  f"port {50000 + index}")))
        rows.append((offset + 1, line(offset + 1, "sshd", 3000 + index,
                                      f"Failed password for invalid user {user} "
                                      f"from {ATTACKER_ENUM} port {50000 + index} ssh2")))

    # --- сценарий 2: подбор пароля к root, БЕЗ успеха (AUTH-001, T1110.001) -
    for attempt in range(18):
        offset = 12000 + attempt * 8
        rows.append((offset, line(offset, "sshd", 4000 + attempt,
                                  f"Failed password for root from {ATTACKER_BRUTE} "
                                  f"port {51000 + attempt} ssh2")))

    # --- сценарий 3: password spraying, УСПЕШНЫЙ (AUTH-003 + AUTH-005) ------
    # По каждому логину только две попытки — политика блокировки не срабатывает.
    for index, user in enumerate(SPRAY_USERS):
        for attempt in range(2):
            offset = 20000 + index * 40 + attempt * 6
            rows.append((offset, line(offset, "sshd", 5000 + index,
                                      f"Failed password for {user} from "
                                      f"{ATTACKER_SPRAY} port {52000 + index} ssh2")))
    # Один пароль подошёл — момент компрометации.
    rows.append((20500, line(20500, "sshd", 5100,
                             f"Accepted password for backup from {ATTACKER_SPRAY} "
                             "port 52500 ssh2")))
    # Дальнейшие действия атакующего: попытки повысить привилегии (AUTH-006).
    for attempt in range(4):
        offset = 20600 + attempt * 30
        rows.append((offset, f"{ts(offset)} {HOST} sudo: backup : "
                             f"{attempt + 1} incorrect password attempts ; "
                             f"TTY=pts/2 ; PWD=/home/backup ; USER=root ; "
                             f"COMMAND=/bin/bash"))
    rows.append((20800, f"{ts(20800)} {HOST} sudo: backup : user NOT in sudoers ; "
                        f"TTY=pts/2 ; PWD=/home/backup ; USER=root ; "
                        f"COMMAND=/usr/bin/id"))

    # --- сценарий 4: распределённый подбор к одной записи (AUTH-002) --------
    for index, ip in enumerate(BOTNET):
        for attempt in range(2):
            offset = 26000 + index * 90 + attempt * 15
            rows.append((offset, line(offset, "sshd", 6000 + index,
                                      f"Failed password for admin from {ip} "
                                      f"port {53000 + index} ssh2")))

    # --- сценарий 5: успешный вход глубокой ночью (AUTH-008) ---------------
    night = 61200   # 02:00 следующих суток
    rows.append((night, line(night, "sshd", 7000,
                             "Accepted password for dmitry from 203.0.113.200 "
                             "port 54000 ssh2")))
    rows.append((night + 120, f"{ts(night + 120)} {HOST} sudo: dmitry : "
                              "TTY=pts/3 ; PWD=/home/dmitry ; USER=root ; "
                              "COMMAND=/usr/bin/apt update"))

    # --- шум, который парсер обязан игнорировать ---------------------------
    rows.append((3000, f"{ts(3000)} {HOST} CRON[9001]: pam_unix(cron:session): "
                       "session opened for user root by (uid=0)"))
    rows.append((3060, f"{ts(3060)} {HOST} systemd[1]: Started Daily apt "
                       "download activities."))
    rows.append((3120, f"{ts(3120)} {HOST} sshd[9100]: Server listening on "
                       "0.0.0.0 port 22."))

    rows.sort(key=lambda item: item[0])
    header = (
        "# Синтетический auth.log для SOC Log Analyzer.\n"
        "# Адреса — из документационных диапазонов RFC 5737, имена вымышлены.\n"
        "# Реальных систем и вредоносной активности здесь нет.\n"
    )
    return header + "\n".join(text for _, text in rows) + "\n"


def build_windows_csv() -> str:
    rows = ["TimeCreated,Id,Computer,TargetUserName,IpAddress,IpPort,LogonType,"
            "Status,WorkstationName"]

    def add(offset: int, event_id: str, user: str, ip: str, port: int,
            logon_type: str, status: str, workstation: str) -> None:
        stamp = (START + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows.append(f"{stamp},{event_id},DC01,{user},{ip},{port},{logon_type},"
                    f"{status},{workstation}")

    # Обычная работа
    for index, user in enumerate(LEGIT_USERS[:3]):
        add(700 + index * 800, "4624", user, f"198.51.100.{20 + index}",
            49000 + index, "3", "0x0", f"WKS-{index:02d}")

    # Подбор пароля к administrator по RDP с последующим успехом:
    # AUTH-001 (критично, т.к. успех) + AUTH-005 + T1021.001
    for attempt in range(9):
        add(30000 + attempt * 10, "4625", "administrator", "192.0.2.150",
            50000 + attempt, "10", "0xc000006a", "KALI-BOX")
    add(30100, "4624", "administrator", "192.0.2.150", 50100, "10", "0x0", "KALI-BOX")
    add(30110, "4672", "administrator", "192.0.2.150", 50100, "10", "0x0", "KALI-BOX")

    # Блокировки учётных записей — следствие перебора (AUTH-007)
    for index, user in enumerate(["jsmith", "mjones", "pbrown", "kwhite", "rgreen"]):
        add(31000 + index * 30, "4740", user, "-", 0, "", "", "-")

    # Шум, который парсер должен отбросить: машинная учётная запись и logoff
    add(31500, "4634", "DC01$", "-", 0, "3", "", "-")
    add(31600, "4624", "SYSTEM", "-", 0, "5", "0x0", "-")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    here = Path(__file__).parent
    (here / "auth.log").write_text(build_auth_log(), encoding="utf-8")
    (here / "windows_security.csv").write_text(build_windows_csv(), encoding="utf-8")
    print("Созданы:", here / "auth.log", "и", here / "windows_security.csv")
