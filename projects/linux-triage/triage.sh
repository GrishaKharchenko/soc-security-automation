#!/usr/bin/env bash
# ============================================================================
#  Linux Incident Triage — первичный сбор артефактов с хоста, на котором
#  подозревается компрометация.
#
#  ГАРАНТИИ БЕЗОПАСНОСТИ
#
#  Скрипт работает ТОЛЬКО НА ЧТЕНИЕ. Он не изменяет и не удаляет файлы на
#  исследуемой системе, не останавливает процессы, не меняет конфигурацию и
#  не содержит эксплойтов. Единственная запись — в каталог результатов,
#  который задаётся аргументом и по умолчанию создаётся в текущем каталоге.
#
#  Это не педантизм. Изменяя систему во время реагирования, вы уничтожаете
#  доказательства и делаете результат непригодным для расследования: любое
#  ваше действие потом невозможно отличить от действий атакующего.
#
#  ПРАВА
#
#  Скрипт работает и без root, но часть артефактов будет недоступна
#  (/etc/shadow, чужие crontab, журналы аутентификации, правила firewall).
#  Недоступное честно помечается в отчёте, а не выдаётся за отсутствующее.
#
#  ИСПОЛЬЗОВАНИЕ
#
#      sudo ./triage.sh [-o КАТАЛОГ] [--no-archive] [-q] [-h]
#
#  Автор: personal cybersecurity project.
# ============================================================================

set -uo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# --- значения по умолчанию --------------------------------------------------
OUTPUT_BASE="$(pwd)"
MAKE_ARCHIVE=1
QUIET=0

usage() {
    cat <<'USAGE'
Linux Incident Triage — сбор DFIR-артефактов с подозреваемого хоста.

ИСПОЛЬЗОВАНИЕ
    sudo ./triage.sh [ПАРАМЕТРЫ]

ПАРАМЕТРЫ
    -o, --output КАТАЛОГ   куда сохранить результаты (по умолчанию: текущий каталог)
        --no-archive       не упаковывать результат в tar.gz
    -q, --quiet            не выводить ход работы в консоль
    -h, --help             эта справка
    -V, --version          версия

ПРИМЕРЫ
    sudo ./triage.sh                          # полный сбор в текущий каталог
    sudo ./triage.sh -o /mnt/usb              # результат на внешний носитель
    ./triage.sh --no-archive                  # без root, без архива

КОДЫ ВОЗВРАТА
    0   сбор выполнен, подозрительного не найдено
    1   сбор выполнен, есть находки
    2   сбор выполнен, есть КРИТИЧЕСКИЕ находки
    3   ошибка запуска (нет каталога, нет прав на запись)

ЗАМЕЧАНИЕ
    Скрипт работает только на чтение и ничего не меняет на исследуемой
    системе. Запускать его следует с внешнего носителя, а результаты
    сохранять вне исследуемого хоста.
USAGE
}

# --- разбор аргументов ------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            [[ $# -ge 2 ]] || { printf 'Ошибка: у %s отсутствует значение\n' "$1" >&2; exit 3; }
            OUTPUT_BASE="$2"; shift 2 ;;
        --no-archive) MAKE_ARCHIVE=0; shift ;;
        -q|--quiet)   QUIET=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        -V|--version) printf 'linux-incident-triage %s\n' "$VERSION"; exit 0 ;;
        *)
            printf 'Неизвестный параметр: %s\n\n' "$1" >&2
            usage >&2
            exit 3 ;;
    esac
done

export QUIET

# --- подключение библиотек --------------------------------------------------
for library in common.sh collect.sh analyze.sh; do
    if [[ ! -r "${SCRIPT_DIR}/lib/${library}" ]]; then
        printf 'Ошибка: не найдена библиотека lib/%s рядом со скриптом.\n' "$library" >&2
        exit 3
    fi
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/lib/${library}"
done

# --- подготовка каталога результатов ---------------------------------------
HOSTNAME_SAFE="$(hostname 2>/dev/null | tr -cd '[:alnum:]._-' || printf 'unknown')"
TIMESTAMP="$(date -u '+%Y%m%d_%H%M%SZ')"
OUTPUT_DIR="${OUTPUT_BASE%/}/triage_${HOSTNAME_SAFE}_${TIMESTAMP}"

if [[ ! -d "$OUTPUT_BASE" ]]; then
    printf 'Ошибка: каталог %s не существует.\n' "$OUTPUT_BASE" >&2
    exit 3
fi
if [[ ! -w "$OUTPUT_BASE" ]]; then
    printf 'Ошибка: нет прав на запись в %s.\n' "$OUTPUT_BASE" >&2
    exit 3
fi
if ! mkdir -p "$OUTPUT_DIR"; then
    printf 'Ошибка: не удалось создать %s.\n' "$OUTPUT_DIR" >&2
    exit 3
fi

TRIAGE_LOG="${OUTPUT_DIR}/00_triage.log"
FINDINGS_FILE="${OUTPUT_DIR}/.findings.jsonl"
: > "$TRIAGE_LOG"
: > "$FINDINGS_FILE"
export OUTPUT_DIR TRIAGE_LOG FINDINGS_FILE

START_EPOCH="$(date -u '+%s')"

# --- сбор -------------------------------------------------------------------
log_info "############################################################"
log_info "  Linux Incident Triage ${VERSION}"
log_info "  Хост       : ${HOSTNAME_SAFE}"
log_info "  Время (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log_info "  Права      : $(is_root && printf 'root' || printf 'обычный пользователь')"
log_info "  Результаты : ${OUTPUT_DIR}"
log_info "############################################################"

if ! is_root; then
    log_warn "Запуск без root: часть артефактов будет недоступна."
    log_warn "Недоступное помечается в отчёте явно, а не пропускается молча."
fi

# Порядок соответствует принципу «от летучего к устойчивому» (RFC 3227).
collect_system_info
collect_users
collect_processes
collect_network
collect_services
collect_cron
collect_accounts
collect_ssh
collect_logs
collect_persistence

# --- анализ -----------------------------------------------------------------
run_all_checks

# --- сборка отчёта ----------------------------------------------------------
END_EPOCH="$(date -u '+%s')"
DURATION=$(( END_EPOCH - START_EPOCH ))
FINDING_COUNT="$(count_findings)"

# Подсчёт находок по уровням.
#
# Осторожно с идиомой «grep -c ... || printf 0»: grep -c при нуле совпадений
# УЖЕ печатает 0 и при этом возвращает код 1, поэтому запасная ветка
# добавляет второй ноль и переменная становится "0\n0". Дальше любое
# арифметическое сравнение падает. Правильно — привязывать запасное значение
# к присваиванию, а не к конвейеру.
count_severity() {
    local level="$1" value
    value="$(grep -c "\"severity\":\"${level}\"" "$FINDINGS_FILE" 2>/dev/null)" || value=0
    printf '%s' "${value:-0}"
}

CRITICAL_COUNT="$(count_severity critical)"
HIGH_COUNT="$(count_severity high)"
MEDIUM_COUNT="$(count_severity medium)"
LOW_COUNT="$(count_severity low)"
INFO_COUNT="$(count_severity info)"

# Машиночитаемый отчёт. Формат специально совместим с остальными
# инструментами набора: единая CLI-оболочка читает именно его.
{
    printf '{\n'
    printf '  "tool": "linux-incident-triage",\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "hostname": "%s",\n' "$(json_escape "$HOSTNAME_SAFE")"
    printf '  "collected_at": "%s",\n' "$(date -u -d "@${START_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "duration_seconds": %d,\n' "$DURATION"
    printf '  "collected_as_root": %s,\n' "$(is_root && printf 'true' || printf 'false')"
    printf '  "output_directory": "%s",\n' "$(json_escape "$OUTPUT_DIR")"
    printf '  "summary": {\n'
    printf '    "total": %s,\n' "$FINDING_COUNT"
    printf '    "critical": %s,\n' "$CRITICAL_COUNT"
    printf '    "high": %s,\n' "$HIGH_COUNT"
    printf '    "medium": %s,\n' "$MEDIUM_COUNT"
    printf '    "low": %s,\n' "$LOW_COUNT"
    printf '    "info": %s\n' "$INFO_COUNT"
    printf '  },\n'
    printf '  "findings": [\n'
    if [[ -s "$FINDINGS_FILE" ]]; then
        # Собираем массив из JSON Lines: запятая после каждой строки, кроме последней.
        sed -e 's/$/,/' -e '$ s/,$//' "$FINDINGS_FILE" | sed 's/^/    /'
    fi
    printf '  ]\n'
    printf '}\n'
} > "${OUTPUT_DIR}/findings.json"

# Человекочитаемая сводка.
{
    printf '===============================================================\n'
    printf '  ОТЧЁТ О ПЕРВИЧНОМ СБОРЕ АРТЕФАКТОВ\n'
    printf '===============================================================\n'
    printf 'Хост            : %s\n' "$HOSTNAME_SAFE"
    printf 'Время сбора UTC : %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'Длительность    : %d с\n' "$DURATION"
    printf 'Права           : %s\n' "$(is_root && printf 'root' || printf 'обычный пользователь (сбор неполный)')"
    printf 'Каталог         : %s\n' "$OUTPUT_DIR"
    printf '\n'
    printf 'НАХОДКИ\n'
    printf '  критических : %s\n' "$CRITICAL_COUNT"
    printf '  высоких     : %s\n' "$HIGH_COUNT"
    printf '  средних     : %s\n' "$MEDIUM_COUNT"
    printf '  низких      : %s\n' "$LOW_COUNT"
    printf '  информация  : %s\n' "$INFO_COUNT"
    printf '  ВСЕГО       : %s\n' "$FINDING_COUNT"
    printf '\n'
    if [[ -s "$FINDINGS_FILE" ]]; then
        printf 'ПЕРЕЧЕНЬ НАХОДОК\n'
        printf -- '---------------------------------------------------------------\n'
        local_severity=""
        while IFS= read -r finding; do
            severity="$(printf '%s' "$finding" | sed -n 's/.*"severity":"\([^"]*\)".*/\1/p')"
            title="$(printf '%s' "$finding" | sed -n 's/.*"title":"\([^"]*\)".*/\1/p')"
            printf '[%-8s] %s\n' "$severity" "$title"
        done < "$FINDINGS_FILE"
        printf '\n'
    else
        printf 'Подозрительных признаков не обнаружено.\n\n'
    fi
    printf 'ВАЖНО\n'
    printf 'Находки являются эвристиками, а не доказательствами. Каждую\n'
    printf 'следует проверить вручную по собранным артефактам: у любой\n'
    printf 'из них возможно легитимное объяснение.\n'
    printf '===============================================================\n'
} > "${OUTPUT_DIR}/SUMMARY.txt"

# Контрольные суммы: доказательство целостности собранного. Без них нельзя
# подтвердить, что файлы не изменились после сбора, — а это первый вопрос,
# который задают материалам расследования.
if have_cmd sha256sum; then
    ( cd "$OUTPUT_DIR" && sha256sum ./* > MANIFEST.sha256 2>/dev/null )
    log_ok "Контрольные суммы собранных файлов записаны в MANIFEST.sha256"
fi

rm -f "$FINDINGS_FILE"

# --- архив ------------------------------------------------------------------
if [[ "$MAKE_ARCHIVE" == "1" ]] && have_cmd tar; then
    ARCHIVE="${OUTPUT_DIR}.tar.gz"
    if tar -czf "$ARCHIVE" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>/dev/null; then
        log_ok "Архив: ${ARCHIVE}"
        have_cmd sha256sum && sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"
    else
        log_warn "Не удалось создать архив"
    fi
fi

# --- итог -------------------------------------------------------------------
if [[ "$QUIET" != "1" ]]; then
    printf '\n'
    cat "${OUTPUT_DIR}/SUMMARY.txt"
    printf '\nСобранные артефакты: %s\n' "$OUTPUT_DIR"
    printf 'Машиночитаемый отчёт: %s/findings.json\n\n' "$OUTPUT_DIR"
fi

if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
    exit 2
elif [[ "$FINDING_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
