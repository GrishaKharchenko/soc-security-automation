"""Единая командная оболочка набора SOC Automation Toolkit."""

from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .adapters.base import AdapterError
from .adapters.ioc import IOCAdapter
from .adapters.logs import LogsAdapter
from .adapters.triage import TriageAdapter
from .bootstrap import ModuleNotAvailable, available_modules
from .config import ConfigError, Settings, load_settings
from .correlation import correlate, escalate_cross_tool
from .logging_setup import get_logger, setup_logging
from .models import Finding, Severity
from .reporting.writers import render_console_summary, write_csv, write_json

logger = get_logger("cli")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_CRITICAL = 2
EXIT_USAGE = 3


class _ArgumentParser(argparse.ArgumentParser):
    """argparse при ошибке в аргументах завершает процесс кодом 2.

    В контракте этого инструмента код 2 занят и означает содержательный
    результат (есть критические находки). Опечатка в команде, отдающая тот же код, заставит
    пайплайн принять её за результат анализа. Поэтому ошибки разбора
    аргументов переводятся в код EXIT_USAGE, отведённый под проблемы запуска.
    """

    def error(self, message: str) -> None:  # noqa: D401
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: ошибка: {message}\n")



def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="soc-toolkit",
        description="Единая оболочка над инструментами автоматизации SOC.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
модули:
  ioc      анализ индикаторов компрометации (VirusTotal)
  logs     анализ логов аутентификации Linux/Windows
  triage   сбор DFIR-артефактов с Linux-хоста (Bash)
  run      несколько модулей за один проход с общей корреляцией
  status   какие модули доступны в текущем окружении

примеры:
  # индикаторы без обращения к API
  python -m soc_toolkit ioc -i ../ioc-analyzer/data/sample_iocs.txt --offline

  # логи аутентификации
  python -m soc_toolkit logs -i ../log-analyzer/data/auth.log --year 2026

  # импорт готового отчёта триажа (работает и на Windows)
  python -m soc_toolkit triage --report samples/findings.json

  # всё сразу: находки трёх инструментов сводятся и коррелируются
  python -m soc_toolkit run --iocs ../ioc-analyzer/data/sample_iocs.txt \\
                            --logs ../log-analyzer/data/auth.log \\
                            --triage-report samples/findings.json \\
                            --offline --year 2026

коды возврата:
  0 — находок нет
  1 — есть находки
  2 — есть критические находки
  3 — ошибка запуска
""",
    )
    parser.add_argument("--version", action="version",
                        version=f"soc-automation-toolkit {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ------------------------------------------------------------------ ioc
    ioc = subparsers.add_parser("ioc", help="анализ индикаторов компрометации")
    ioc.add_argument("-i", "--input", required=True, metavar="FILE")
    ioc.add_argument("--offline", action="store_true",
                     help="не обращаться к VirusTotal")
    ioc.add_argument("--limit", type=int, metavar="N")
    ioc.add_argument("--types", nargs="+", metavar="TYPE")
    ioc.add_argument("--include-clean", action="store_true",
                     help="включать в отчёт чистые индикаторы")
    ioc.add_argument("--module-env", metavar="FILE",
                     help="путь к .env модуля ioc-analyzer")

    # ----------------------------------------------------------------- logs
    logs = subparsers.add_parser("logs", help="анализ логов аутентификации")
    logs.add_argument("-i", "--input", required=True, nargs="+", metavar="FILE")
    logs.add_argument("--rules", nargs="+", metavar="ID")
    logs.add_argument("--parser", default="auto",
                      choices=["auto", "linux", "windows"])
    logs.add_argument("--year", type=int, metavar="YYYY")
    logs.add_argument("--timezone", metavar="TZ")
    logs.add_argument("--module-env", metavar="FILE")

    # --------------------------------------------------------------- triage
    triage = subparsers.add_parser("triage", help="DFIR-артефакты Linux-хоста")
    triage_mode = triage.add_mutually_exclusive_group(required=True)
    triage_mode.add_argument("--report", metavar="FILE",
                             help="импорт готового findings.json")
    triage_mode.add_argument("--run", action="store_true",
                             help="запустить сбор (только Linux/WSL)")
    triage.add_argument("--triage-output", metavar="DIR", default=".",
                        help="куда собирать артефакты при --run")

    # ------------------------------------------------------------------ run
    run_cmd = subparsers.add_parser(
        "run", help="несколько модулей за один проход с общей корреляцией")
    run_cmd.add_argument("--iocs", metavar="FILE", help="файл с индикаторами")
    run_cmd.add_argument("--logs", nargs="+", metavar="FILE", help="файлы логов")
    run_cmd.add_argument("--triage-report", metavar="FILE",
                         help="готовый findings.json триажа")
    run_cmd.add_argument("--triage-run", action="store_true",
                         help="запустить сбор триажа (только Linux/WSL)")
    run_cmd.add_argument("--offline", action="store_true")
    run_cmd.add_argument("--limit", type=int, metavar="N")
    run_cmd.add_argument("--year", type=int, metavar="YYYY")
    run_cmd.add_argument("--timezone", metavar="TZ")
    run_cmd.add_argument("--include-clean", action="store_true")

    # --------------------------------------------------------------- status
    subparsers.add_parser("status", help="какие модули доступны")

    # ------------------------------------------------------------ общие
    for subparser in (ioc, logs, triage, run_cmd):
        subparser.add_argument("-o", "--output-dir", metavar="DIR")
        subparser.add_argument("-f", "--format",
                               choices=["json", "csv", "both", "none"],
                               default="both")
        subparser.add_argument("--min-severity",
                               choices=[s.value for s in Severity])
        subparser.add_argument("--no-escalate", action="store_true",
                               help="не повышать критичность при подтверждении "
                                    "несколькими инструментами")
        subparser.add_argument("--env-file", metavar="FILE",
                               help="путь к .env самой оболочки")
        subparser.add_argument("--log-level",
                               choices=["DEBUG", "INFO", "WARNING", "ERROR"])
        subparser.add_argument("-q", "--quiet", action="store_true")

    return parser


def apply_overrides(settings: Settings, args: argparse.Namespace) -> Settings:
    overrides: dict[str, object] = {}
    if getattr(args, "output_dir", None):
        overrides["output_dir"] = Path(args.output_dir)
    if getattr(args, "log_level", None):
        overrides["log_level"] = args.log_level
    if getattr(args, "no_escalate", False):
        overrides["escalate_cross_tool"] = False
    if not overrides:
        return settings
    updated = dataclasses.replace(settings, **overrides)
    updated.validate()
    return updated


def _run_status() -> int:
    modules = available_modules()
    print("\nМОДУЛИ НАБОРА\n" + "-" * 62)
    labels = {
        "ioc_analyzer": "IOC Analyzer (Python)",
        "log_analyzer": "SOC Log Analyzer (Python)",
        "linux_triage": "Linux Incident Triage (Bash)",
    }
    for key, label in labels.items():
        mark = "доступен" if modules.get(key) else "НЕ НАЙДЕН"
        print(f"  {label:<34} {mark}")

    print("-" * 62)
    print(f"  Запуск сбора триажа из оболочки: "
          f"{'да' if TriageAdapter.can_execute() else 'нет (нужен Linux или WSL)'}")
    print("  Импорт готового отчёта триажа:   да, на любой платформе")
    print("-" * 62)
    if not all(modules.values()):
        print("  Отсутствующие модули означают, что репозиторий склонирован\n"
              "  не целиком либо структура каталогов изменена.\n")
    return EXIT_OK


def _finalize(findings: list[Finding], settings: Settings,
              args: argparse.Namespace, metadata: dict) -> int:
    """Корреляция, эскалация, отчёты, код возврата — общий финал всех команд."""
    if not findings:
        print("Находок нет.")
        return EXIT_OK

    groups = correlate(findings)
    escalated = 0
    if settings.escalate_cross_tool:
        escalated = escalate_cross_tool(findings, groups)
        if escalated:
            # После изменения критичности группы пересобираются, чтобы
            # сортировка и сводка отражали новое состояние.
            groups = correlate(findings)

    if args.min_severity:
        floor = Severity(args.min_severity).score
        findings = [f for f in findings if f.severity.score >= floor]
        groups = correlate(findings)
        if not findings:
            print(f"Находок с критичностью не ниже «{args.min_severity}» нет.")
            return EXIT_OK

    metadata["escalated_findings"] = escalated

    if args.format in {"json", "both"}:
        print(f"JSON: {write_json(findings, groups, settings.output_dir, metadata)}")
    if args.format in {"csv", "both"}:
        print(f"CSV:  {write_csv(findings, settings.output_dir)}")

    print(render_console_summary(findings, groups))

    if any(f.severity is Severity.CRITICAL for f in findings):
        return EXIT_CRITICAL
    return EXIT_FINDINGS


def _run_ioc(args: argparse.Namespace, settings: Settings) -> int:
    findings = IOCAdapter().run(
        input_file=args.input, offline=args.offline, limit=args.limit,
        only_types=args.types, env_file=args.module_env,
        include_clean=args.include_clean,
    )
    return _finalize(list(findings), settings, args,
                     {"modules": ["ioc-analyzer"], "inputs": [args.input]})


def _run_logs(args: argparse.Namespace, settings: Settings) -> int:
    findings = LogsAdapter().run(
        input_files=args.input, rules=args.rules, parser=args.parser,
        year=args.year, timezone=args.timezone, env_file=args.module_env,
    )
    return _finalize(list(findings), settings, args,
                     {"modules": ["log-analyzer"], "inputs": list(args.input)})


def _run_triage(args: argparse.Namespace, settings: Settings) -> int:
    findings = TriageAdapter().run(
        report=args.report, run_script=args.run, output_dir=args.triage_output,
    )
    return _finalize(list(findings), settings, args,
                     {"modules": ["linux-triage"],
                      "inputs": [args.report or "живой сбор"]})


def _run_all(args: argparse.Namespace, settings: Settings) -> int:
    """Несколько модулей за один проход.

    Сбой одного модуля не отменяет остальные: получить часть картины лучше,
    чем не получить ничего. Ошибки собираются и показываются в конце.
    """
    def _collect(label: str, sources: list[str], action) -> None:
        """Выполнить один модуль, изолировав его сбой от остальных.

        Перехватывается не только AdapterError, но и любое исключение:
        модули разрабатывались независимо, и оболочка не может знать полный
        перечень их ошибок. Получить часть картины лучше, чем не получить
        ничего, — поэтому сбой одного модуля попадает в список ошибок отчёта,
        а не прерывает прогон.
        """
        try:
            findings.extend(action())
        except (AdapterError, ModuleNotAvailable) as exc:
            errors.append(f"{label}: {exc}")
            logger.error("Модуль %s пропущен: %s", label, exc)
            return
        except Exception as exc:  # noqa: BLE001 — изоляция чужого кода
            errors.append(f"{label}: непредвиденная ошибка — {exc}")
            logger.exception("Модуль %s упал: %s", label, exc)
            return
        used.append(label)
        inputs.extend(sources)

    if not any((args.iocs, args.logs, args.triage_report, args.triage_run)):
        print("Не указан ни один источник данных. Используйте --iocs, --logs, "
              "--triage-report или --triage-run.", file=sys.stderr)
        return EXIT_USAGE

    findings: list[Finding] = []
    used: list[str] = []
    inputs: list[str] = []
    errors: list[str] = []

    if args.iocs:
        _collect("ioc-analyzer", [str(args.iocs)], lambda: IOCAdapter().run(
            input_file=args.iocs, offline=args.offline, limit=args.limit,
            include_clean=args.include_clean))

    if args.logs:
        _collect("log-analyzer", [str(path) for path in args.logs],
                 lambda: LogsAdapter().run(input_files=args.logs,
                                           year=args.year,
                                           timezone=args.timezone))

    if args.triage_report or args.triage_run:
        _collect("linux-triage", [str(args.triage_report or "живой сбор")],
                 lambda: TriageAdapter().run(report=args.triage_report,
                                             run_script=args.triage_run))

    if errors:
        print("\nЧасть модулей не отработала:", file=sys.stderr)
        for error in errors:
            print(f"  · {error}", file=sys.stderr)
        print(file=sys.stderr)

    if not used:
        print("Ни один модуль не отработал.", file=sys.stderr)
        return EXIT_USAGE

    code = _finalize(findings, settings, args,
                     {"modules": used, "inputs": inputs,
                      "failed_modules": errors})
    # Частичный сбой не должен выглядеть как чистый результат.
    return max(code, EXIT_FINDINGS) if errors and code == EXIT_OK else code


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "status":
        return _run_status()

    try:
        settings = load_settings(getattr(args, "env_file", None))
        settings = apply_overrides(settings, args)
    except ConfigError as exc:
        print(f"Ошибка конфигурации: {exc}", file=sys.stderr)
        return EXIT_USAGE

    setup_logging(level=settings.log_level, log_file=settings.log_file,
                  max_bytes=settings.log_max_bytes,
                  backup_count=settings.log_backup_count, quiet=args.quiet)

    handlers = {"ioc": _run_ioc, "logs": _run_logs,
                "triage": _run_triage, "run": _run_all}
    try:
        return handlers[args.command](args, settings)
    except (AdapterError, ModuleNotAvailable) as exc:
        logger.error("%s", exc)
        print(f"Ошибка: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        logger.warning("Прервано пользователем")
        return EXIT_USAGE
    except Exception as exc:  # noqa: BLE001
        logger.exception("Непредвиденная ошибка: %s", exc)
        print(f"Непредвиденная ошибка: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
