"""Адаптер Linux Incident Triage.

Инструмент написан на Bash, поэтому адаптер работает двумя способами:

**Запуск** (``run_script=True``) — вызвать ``triage.sh`` через
``subprocess`` и разобрать созданный ``findings.json``. Требует Linux или WSL.

**Импорт** (по умолчанию) — прочитать уже готовый ``findings.json``, собранный
ранее на другой машине. Это не запасной вариант, а основной сценарий: триаж
запускается на исследуемом хосте, а разбор результатов ведётся в другом месте,
часто на другой платформе. Именно поэтому Bash-скрипт с самого начала пишет
машиночитаемый отчёт.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..bootstrap import TRIAGE_SCRIPT
from ..logging_setup import get_logger
from ..models import Confidence, Finding, Severity, Source
from .base import AdapterError, ToolAdapter

logger = get_logger("adapters.triage")

CATEGORY_PREFIX = "TRIAGE"

# Bash-скрипт не выделяет сущности отдельными полями: он оперирует текстом
# находки и строкой-доказательством. Чтобы его результаты связывались с
# находками других инструментов, адреса и учётные записи извлекаются из
# текста регулярными выражениями.
#
# Это компромисс, и о нём стоит говорить прямо. Правильнее было бы, чтобы
# скрипт сам заполнял структурированное поле entities. Разбор текста
# работает, но зависит от формулировок: изменится текст находки — сломается
# извлечение. В продуктивной системе такой связи между модулями быть не
# должно; здесь она осознанно оставлена как минимальная цена интеграции
# инструмента на другом языке.
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)
# Учётная запись в кавычках-ёлочках: «backdoor», «www-data».
_ACCOUNT_RE = re.compile(r"«([A-Za-z0-9._\-]{1,32})»")


def extract_entities(*texts: str) -> dict[str, list[str]]:
    """Вытащить адреса и учётные записи из текста находки."""
    joined = " ".join(text for text in texts if text)
    entities: dict[str, list[str]] = {}

    addresses = sorted({
        address for address in _IPV4_RE.findall(joined)
        # 0.0.0.0 в выводе ss означает «все интерфейсы», а не конкретный узел.
        if address not in {"0.0.0.0", "255.255.255.255"}
    })
    if addresses:
        entities["ip"] = addresses

    accounts = sorted(set(_ACCOUNT_RE.findall(joined)))
    if accounts:
        entities["username"] = accounts

    return entities


class TriageAdapter(ToolAdapter):
    """Запуск Bash-скрипта триажа либо импорт его отчёта."""

    name = "triage"
    description = "Сбор DFIR-артефактов с Linux-хоста (Bash)"

    @staticmethod
    def is_available() -> bool:
        return TRIAGE_SCRIPT.is_file()

    @staticmethod
    def can_execute() -> bool:
        """Можно ли запустить скрипт прямо здесь.

        На Windows Bash отсутствует, поэтому режим запуска недоступен — но
        импорт готового отчёта работает на любой платформе.
        """
        return sys.platform != "win32" and TRIAGE_SCRIPT.is_file()

    def run(
        self,
        report: str | Path | None = None,
        run_script: bool = False,
        output_dir: str | Path | None = None,
        timeout: int = 600,
        **_: Any,
    ) -> list[Finding]:
        if run_script:
            report = self._execute(output_dir, timeout)
        if report is None:
            raise AdapterError(
                "Не указан отчёт триажа. Передайте путь к findings.json "
                "(--report) либо запустите сбор (--run, только Linux/WSL)."
            )
        return self._parse_report(Path(report))

    # ------------------------------------------------------------- запуск

    def _execute(self, output_dir: str | Path | None, timeout: int) -> Path:
        if not self.can_execute():
            raise AdapterError(
                "Запуск сбора недоступен: нужен Linux или WSL. "
                "На Windows соберите артефакты в WSL и импортируйте отчёт "
                "командой --report путь/к/findings.json."
            )

        target = Path(output_dir or ".").resolve()
        target.mkdir(parents=True, exist_ok=True)
        logger.info("Запускаю %s -o %s", TRIAGE_SCRIPT, target)

        try:
            completed = subprocess.run(
                ["bash", str(TRIAGE_SCRIPT), "-o", str(target), "--no-archive", "-q"],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(f"Сбор не завершился за {timeout} с") from exc
        except OSError as exc:
            raise AdapterError(f"Не удалось запустить bash: {exc}") from exc

        # Коды 0/1/2 штатные (нет находок / есть / есть критические),
        # 3 — ошибка запуска.
        if completed.returncode == 3:
            raise AdapterError(
                f"Скрипт триажа завершился ошибкой запуска: "
                f"{completed.stderr.strip()[:300]}"
            )

        results = sorted(target.glob("triage_*/findings.json"),
                         key=lambda p: p.stat().st_mtime, reverse=True)
        if not results:
            raise AdapterError(
                f"Скрипт отработал (код {completed.returncode}), но отчёт "
                f"findings.json не найден в {target}"
            )
        logger.info("Отчёт триажа: %s", results[0])
        return results[0]

    # ------------------------------------------------------------- разбор

    @staticmethod
    def _parse_report(path: Path) -> list[Finding]:
        if not path.exists():
            raise AdapterError(f"Отчёт триажа не найден: {path}")

        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AdapterError(f"Отчёт триажа повреждён ({path}): {exc}") from exc
        if not isinstance(document, dict):
            raise AdapterError(f"Неожиданная структура отчёта: {path}")

        hostname = document.get("hostname") or "неизвестный хост"
        collected_at = document.get("collected_at")
        as_root = document.get("collected_as_root")

        findings: list[Finding] = []
        for item in document.get("findings", []):
            if not isinstance(item, dict):
                continue
            category = str(item.get("category", "general"))
            description = str(item.get("description", ""))
            if as_root is False:
                description += (" ВНИМАНИЕ: сбор выполнялся без прав root, "
                                "часть артефактов недоступна, отсутствие других "
                                "находок ничего не доказывает.")

            title = str(item.get("title", "находка триажа"))
            evidence = str(item.get("evidence", ""))
            entities: dict[str, Any] = {"hostname": hostname}
            entities.update(extract_entities(title, evidence, description))

            findings.append(Finding(
                source=Source.TRIAGE,
                rule_id=f"{CATEGORY_PREFIX}-{category.upper()}",
                title=title,
                description=description,
                severity=Severity.parse(str(item.get("severity", "info"))),
                confidence=Confidence.MEDIUM,
                entities=entities,
                evidence=evidence,
                recommendation=(
                    "Проверить находку вручную по собранным артефактам: это "
                    "эвристика, а не доказательство. Сопоставить с результатами "
                    "анализа логов и индикаторов."
                ),
                first_seen=item.get("detected_at") or collected_at,
                last_seen=item.get("detected_at") or collected_at,
                raw_reference=str(path),
            ))

        logger.info("Триаж: импортировано находок %d (хост %s)",
                    len(findings), hostname)
        return findings
