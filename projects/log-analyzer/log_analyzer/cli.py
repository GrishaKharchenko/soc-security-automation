"""Командный интерфейс SOC Log Analyzer."""

from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

from . import __version__
from .analyzer import LogAnalyzer
from .config import ConfigError, Settings, load_settings
from .detection.engine import RULE_IDS
from .logging_setup import get_logger, setup_logging
from .models import Severity
from .parsers.base import ParseError
from .parsers.registry import PARSER_NAMES
from .reporting.writers import render_console_summary, write_csv, write_json

logger = get_logger("cli")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_CRITICAL = 2
EXIT_USAGE = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Анализ логов аутентификации Linux/Windows и поиск атак на учётные записи.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
примеры:
  # разбор Linux auth.log со всеми правилами
  python -m log_analyzer analyze -i data/auth.log

  # несколько источников сразу: события сводятся в общую хронологию
  python -m log_analyzer analyze -i data/auth.log data/windows_security.csv

  # только детекты перебора, отчёт в CSV
  python -m log_analyzer analyze -i data/auth.log --rules AUTH-001 AUTH-003 -f csv

  # какие события вообще разобрались (без детектов)
  python -m log_analyzer events -i data/auth.log --limit 40

  # список правил и их привязка к MITRE ATT&CK
  python -m log_analyzer rules

коды возврата:
  0 — находок нет
  1 — есть находки
  2 — есть критические находки
  3 — ошибка запуска
""",
    )
    parser.add_argument("--version", action="version",
                        version=f"soc-log-analyzer {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="полный анализ логов")
    analyze.add_argument("-i", "--input", required=True, nargs="+", metavar="FILE",
                         help="один или несколько файлов логов")
    analyze.add_argument("-o", "--output-dir", metavar="DIR",
                         help="каталог для отчётов")
    analyze.add_argument("-f", "--format", choices=["json", "csv", "both", "none"],
                         default="both", help="формат отчётов (по умолчанию: both)")
    analyze.add_argument("--parser", choices=PARSER_NAMES, default="auto",
                         help="формат логов (по умолчанию определяется автоматически)")
    analyze.add_argument("--rules", nargs="+", metavar="ID",
                         help=f"только указанные правила: {', '.join(sorted(RULE_IDS))}")
    analyze.add_argument("--min-severity",
                         choices=[s.value for s in Severity],
                         help="показывать находки не ниже указанной критичности")
    analyze.add_argument("--timezone", metavar="TZ",
                         help="часовой пояс исходных логов, напр. Europe/Moscow")
    analyze.add_argument("--year", type=int, metavar="YYYY",
                         help="год для записей syslog без года")

    events = subparsers.add_parser("events", help="показать разобранные события")
    events.add_argument("-i", "--input", required=True, nargs="+", metavar="FILE")
    events.add_argument("--parser", choices=PARSER_NAMES, default="auto")
    events.add_argument("--limit", type=int, default=50, metavar="N")
    events.add_argument("--failures-only", action="store_true",
                        help="только неудачные попытки")
    events.add_argument("--timezone", metavar="TZ")
    events.add_argument("--year", type=int, metavar="YYYY")

    subparsers.add_parser("rules", help="список правил и техник MITRE ATT&CK")

    for subparser in (analyze, events):
        subparser.add_argument("--env-file", metavar="FILE")
        subparser.add_argument("--log-level",
                               choices=["DEBUG", "INFO", "WARNING", "ERROR"])
        subparser.add_argument("-q", "--quiet", action="store_true",
                               help="не писать логи в консоль")
    return parser


def apply_overrides(settings: Settings, args: argparse.Namespace) -> Settings:
    overrides: dict[str, object] = {}
    if getattr(args, "output_dir", None):
        overrides["output_dir"] = Path(args.output_dir)
    if getattr(args, "log_level", None):
        overrides["log_level"] = args.log_level
    if getattr(args, "timezone", None):
        overrides["timezone"] = args.timezone
    if getattr(args, "year", None):
        overrides["default_year"] = args.year
    if not overrides:
        return settings
    updated = dataclasses.replace(settings, **overrides)
    updated.validate()
    return updated


def _run_rules() -> int:
    """Показать правила и их привязку к ATT&CK — справка для аналитика."""
    from .detection.engine import RULE_CLASSES

    from . import mitre

    print(f"\n{'ID':<10} {'ПРАВИЛО':<44} MITRE ATT&CK")
    print("=" * 100)
    for rule_class in RULE_CLASSES:
        techniques = ", ".join(rule_class.primary_techniques) or "—"
        print(f"{rule_class.rule_id:<10} {rule_class.title:<44} {techniques}")
        print(f"{'':10} {rule_class.description}")
        for technique_id in rule_class.primary_techniques:
            technique = mitre.get(technique_id)
            if technique:
                print(f"{'':10} · {technique.technique_id} {technique.name} "
                      f"[{technique.tactic}]")
        print()
    print("Обоснование выбора каждой техники — в log_analyzer/mitre.py, "
          "поле rationale.")
    return EXIT_OK


def _run_events(args: argparse.Namespace, settings: Settings) -> int:
    from .parsers.registry import load_events

    events, stats = load_events(args.input, settings, args.parser)
    if args.failures_only:
        events = [e for e in events if e.is_failure]

    print(f"\n{'ВРЕМЯ (UTC)':<20} {'ИСХОД':<8} {'ПОЛЬЗОВАТЕЛЬ':<18} "
          f"{'ИСТОЧНИК':<16} {'ТИП СОБЫТИЯ':<26} ХОСТ")
    print("-" * 118)
    for event in events[:args.limit]:
        print(f"{event.timestamp:%Y-%m-%d %H:%M:%S}  {event.outcome.value:<8} "
              f"{str(event.username or '-'):<18} {str(event.source_ip or '-'):<16} "
              f"{event.event_type:<26} {event.hostname or '-'}")
    if len(events) > args.limit:
        print(f"... ещё {len(events) - args.limit} событий")

    print("-" * 118)
    print(f"Всего событий: {len(events)} | строк прочитано: {stats.total_lines} | "
          f"покрытие разбора: {stats.coverage}%")
    if stats.unparsed:
        print(f"Не разобрано строк: {stats.unparsed}. Примеры: "
              f"{stats.unparsed_samples[:3]}")
    return EXIT_OK


def _run_analyze(args: argparse.Namespace, settings: Settings) -> int:
    analyzer = LogAnalyzer(settings, enabled_rules=args.rules)
    run = analyzer.analyze(args.input, parser_name=args.parser)

    if not run.events:
        print("В указанных файлах не найдено событий аутентификации.")
        return EXIT_OK

    detections = run.detections
    if args.min_severity:
        floor = Severity(args.min_severity).score
        detections = [d for d in detections if d.severity.score >= floor]
        logger.info("Фильтр по критичности >= %s: осталось %d из %d",
                    args.min_severity, len(detections), len(run.detections))

    if not detections:
        print(f"\nПроанализировано событий: {len(run.events)}. Находок нет.")
        return EXIT_OK

    if args.format in {"json", "both"}:
        path = write_json(detections, run.incidents, settings.output_dir,
                          metadata=run.metadata())
        print(f"JSON: {path}")
    if args.format in {"csv", "both"}:
        path = write_csv(detections, run.incidents, settings.output_dir)
        print(f"CSV:  {path}")

    print(render_console_summary(detections, run.incidents))
    return LogAnalyzer.exit_code(detections)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        return _run_rules()

    try:
        settings = load_settings(getattr(args, "env_file", None))
        settings = apply_overrides(settings, args)
    except ConfigError as exc:
        print(f"Ошибка конфигурации: {exc}", file=sys.stderr)
        return EXIT_USAGE

    setup_logging(
        level=settings.log_level,
        log_file=settings.log_file,
        max_bytes=settings.log_max_bytes,
        backup_count=settings.log_backup_count,
        quiet=args.quiet,
    )

    try:
        if args.command == "events":
            return _run_events(args, settings)
        return _run_analyze(args, settings)
    except ParseError as exc:
        logger.error("Ошибка разбора: %s", exc)
        print(f"Ошибка разбора: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (ConfigError, ValueError) as exc:
        logger.error("Ошибка: %s", exc)
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
