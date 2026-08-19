"""Командный интерфейс IOC Analyzer.

CLI намеренно «тонкий»: он разбирает аргументы, собирает настройки, запускает
:class:`~ioc_analyzer.analyzer.IOCAnalyzer` и печатает результат. Вся доменная
логика живёт в модулях — это позволяет использовать тот же код из SOAR,
Airflow или веб-сервиса, ничего не переписывая.

Приоритет источников настроек (от низшего к высшему):
    значения по умолчанию -> .env -> переменные окружения -> флаги CLI.
Это стандартное для рабочих утилит поведение: разово переопределить порог
флагом можно, не трогая конфигурацию.
"""

from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

from . import __version__
from .analyzer import IOCAnalyzer
from .config import ConfigError, Settings, load_settings
from .enrichment.virustotal import VirusTotalClient
from .logging_setup import get_logger, setup_logging
from .models import IOC, IOCType
from .parsers.reader import InputError
from .reporting.writers import render_console_summary, write_csv, write_json

logger = get_logger("cli")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERRORS = 2
EXIT_USAGE = 3


class _ArgumentParser(argparse.ArgumentParser):
    """argparse при ошибке в аргументах завершает процесс кодом 2.

    В контракте этого инструмента код 2 занят и означает содержательный
    результат (часть индикаторов проверить не удалось). Опечатка в команде, отдающая тот же код, заставит
    пайплайн принять её за результат анализа. Поэтому ошибки разбора
    аргументов переводятся в код EXIT_USAGE, отведённый под проблемы запуска.
    """

    def error(self, message: str) -> None:  # noqa: D401
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: ошибка: {message}\n")



def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="ioc-analyzer",
        description="Автоматизированный анализ индикаторов компрометации (SOC).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
примеры:
  # полный анализ TXT-файла с обогащением через VirusTotal
  python -m ioc_analyzer analyze -i data/sample_iocs.txt

  # без обращений к API: только разбор, нормализация и дедупликация
  python -m ioc_analyzer analyze -i data/sample_iocs.csv --offline

  # только домены и URL, максимум 20 индикаторов, отчёт только в CSV
  python -m ioc_analyzer analyze -i feed.csv --types domain url --limit 20 --format csv

  # быстрый просмотр разбора файла без записи отчётов
  python -m ioc_analyzer classify -i data/sample_iocs.txt

коды возврата:
  0 — вредоносных и подозрительных индикаторов не найдено
  1 — есть находки (malicious/suspicious)
  2 — часть индикаторов проверить не удалось
  3 — ошибка запуска (нет файла, некорректная конфигурация)
""",
    )
    parser.add_argument("--version", action="version", version=f"ioc-analyzer {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---------------------------------------------------------------- analyze
    analyze = subparsers.add_parser(
        "analyze", help="полный анализ: разбор, обогащение, вердикт, отчёты"
    )
    analyze.add_argument("-i", "--input", required=True, metavar="FILE",
                         help="входной файл с индикаторами (TXT или CSV)")
    analyze.add_argument("-o", "--output-dir", metavar="DIR",
                         help="каталог для отчётов (по умолчанию из .env: OUTPUT_DIR)")
    analyze.add_argument("-f", "--format", choices=["json", "csv", "both", "none"],
                         default="both", help="формат отчётов (по умолчанию: both)")
    analyze.add_argument("--offline", action="store_true",
                         help="не обращаться к VirusTotal (разбор и дедупликация)")
    analyze.add_argument("--types", nargs="+", metavar="TYPE",
                         choices=[t.value for t in IOCType if t is not IOCType.UNKNOWN],
                         help="анализировать только указанные типы IOC")
    analyze.add_argument("--limit", type=int, metavar="N",
                         help="ограничить число индикаторов (экономия квоты API)")
    analyze.add_argument("--no-dedupe", action="store_true",
                         help="не удалять дубликаты (для отладки разбора)")
    analyze.add_argument("--no-cache", action="store_true",
                         help="игнорировать локальный кеш ответов VirusTotal")
    analyze.add_argument("--rpm", type=int, metavar="N",
                         help="лимит запросов в минуту (перекрывает VT_REQUESTS_PER_MINUTE)")
    analyze.add_argument("--malicious-threshold", type=int, metavar="N",
                         help="сколько детектов делают вердикт MALICIOUS")

    # --------------------------------------------------------------- classify
    classify = subparsers.add_parser(
        "classify", help="только разбор и классификация, без обращения к API"
    )
    classify.add_argument("-i", "--input", required=True, metavar="FILE",
                          help="входной файл с индикаторами (TXT или CSV)")
    classify.add_argument("--no-dedupe", action="store_true",
                          help="не удалять дубликаты")

    # ------------------------------------------------------------ общие флаги
    for subparser in (analyze, classify):
        subparser.add_argument("--env-file", metavar="FILE",
                               help="путь к файлу .env (по умолчанию — ./.env)")
        subparser.add_argument("--log-level",
                               choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                               help="уровень логирования")
        subparser.add_argument("--log-file", metavar="FILE",
                               help="файл лога (по умолчанию из .env: LOG_FILE)")
        subparser.add_argument("-q", "--quiet", action="store_true",
                               help="не писать логи в консоль (в файл — пишутся)")

    return parser


def apply_overrides(settings: Settings, args: argparse.Namespace) -> Settings:
    """Наложить флаги CLI поверх настроек из .env.

    ``Settings`` иммутабелен, поэтому создаём копию через ``dataclasses.replace``:
    так исключены неожиданные мутации конфигурации в середине работы.
    """
    overrides: dict[str, object] = {}
    if getattr(args, "output_dir", None):
        overrides["output_dir"] = Path(args.output_dir)
    if getattr(args, "log_level", None):
        overrides["log_level"] = args.log_level
    if getattr(args, "log_file", None):
        overrides["log_file"] = Path(args.log_file)
    if getattr(args, "no_cache", False):
        overrides["cache_enabled"] = False
    if getattr(args, "rpm", None):
        overrides["vt_requests_per_minute"] = args.rpm
    if getattr(args, "malicious_threshold", None):
        overrides["malicious_threshold"] = args.malicious_threshold

    if not overrides:
        return settings
    updated = dataclasses.replace(settings, **overrides)
    updated.validate()
    return updated


def _progress(index: int, total: int, ioc: IOC) -> None:
    logger.info("[%d/%d] %s (%s)", index, total, ioc.value, ioc.type.value)


def _run_classify(args: argparse.Namespace, settings: Settings) -> int:
    """Режим ``classify``: показать, как разобран файл. В сеть не ходим."""
    from .parsers.reader import read_iocs

    iocs, stats = read_iocs(args.input, dedupe=not args.no_dedupe)
    if not iocs:
        print("Индикаторы не найдены.")
        return EXIT_OK

    print(f"\n{'ТИП':<8} {'ВСТР.':>6}  ИНДИКАТОР")
    print("-" * 78)
    for ioc in sorted(iocs, key=lambda x: (x.type.value, x.value)):
        flag = " [defanged]" if ioc.defanged else ""
        print(f"{ioc.type.value:<8} {ioc.occurrences:>6}  {ioc.value}{flag}")

    print("-" * 78)
    print(f"Всего уникальных: {len(iocs)} | дубликатов удалено: {stats.duplicates} | "
          f"нераспознано: {stats.invalid}")
    if stats.invalid_samples:
        print(f"Нераспознанные строки: {', '.join(stats.invalid_samples[:5])}")
    return EXIT_OK


def _run_analyze(args: argparse.Namespace, settings: Settings) -> int:
    """Режим ``analyze``: полный конвейер с обогащением и отчётами."""
    provider = None
    if not args.offline:
        try:
            provider = VirusTotalClient(settings)
        except ConfigError as exc:
            logger.error("%s", exc)
            return EXIT_USAGE

    analyzer = IOCAnalyzer(settings, provider=provider)
    only_types = [IOCType(value) for value in args.types] if args.types else None

    try:
        run = analyzer.analyze_file(
            args.input,
            limit=args.limit,
            only_types=only_types,
            dedupe=not args.no_dedupe,
            progress=_progress if not args.quiet else None,
        )
    finally:
        # Кеш и сессия закрываются даже при Ctrl+C: уже полученные ответы
        # не должны пропасть, иначе следующий запуск снова сожжёт квоту.
        if provider is not None:
            provider.close()

    if not run.results:
        print("Индикаторы не найдены — нечего анализировать.")
        return EXIT_OK

    if args.format in {"json", "both"}:
        path = write_json(run.results, settings.output_dir, metadata=run.metadata())
        print(f"JSON: {path}")
    if args.format in {"csv", "both"}:
        path = write_csv(run.results, settings.output_dir)
        print(f"CSV:  {path}")

    print(render_console_summary(run.results))
    return IOCAnalyzer.exit_code(run.results)


def main(argv: list[str] | None = None) -> int:
    """Точка входа. Возвращает код возврата (не вызывает ``sys.exit``)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.env_file)
        settings = apply_overrides(settings, args)
    except ConfigError as exc:
        print(f"Ошибка конфигурации: {exc}", file=sys.stderr)
        return EXIT_USAGE

    setup_logging(
        level=settings.log_level,
        log_file=settings.log_file,
        max_bytes=settings.log_max_bytes,
        backup_count=settings.log_backup_count,
        secrets=[settings.vt_api_key],
        quiet=args.quiet,
    )
    logger.debug("Запуск: %s", vars(args))

    try:
        if args.command == "classify":
            return _run_classify(args, settings)
        return _run_analyze(args, settings)
    except InputError as exc:
        logger.error("Ошибка входных данных: %s", exc)
        print(f"Ошибка входных данных: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ConfigError as exc:
        logger.error("Ошибка конфигурации: %s", exc)
        print(f"Ошибка конфигурации: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        logger.warning("Прервано пользователем (Ctrl+C)")
        return EXIT_ERRORS
    except Exception as exc:  # noqa: BLE001 — верхний уровень, логируем и выходим
        logger.exception("Непредвиденная ошибка: %s", exc)
        print(f"Непредвиденная ошибка: {exc}", file=sys.stderr)
        return EXIT_ERRORS


if __name__ == "__main__":
    sys.exit(main())
