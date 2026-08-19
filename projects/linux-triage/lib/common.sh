#!/usr/bin/env bash
# ============================================================================
#  common.sh — базовые утилиты: логирование, безопасный запуск команд,
#  регистрация находок.
#
#  Здесь собрано всё, что отличает рабочий инструмент реагирования от
#  скрипта «на коленке»: аккуратная обработка отсутствующих команд, единый
#  журнал сбора и машиночитаемый список находок.
# ============================================================================

# --- режим оболочки ---------------------------------------------------------
# set -u   — обращение к неинициализированной переменной считать ошибкой:
#            опечатка в имени переменной иначе молча даст пустую строку,
#            а в скрипте, который ходит по путям файловой системы, пустая
#            строка — это катастрофа вида "rm -rf $DIR/".
# set -o pipefail — код возврата конвейера берётся от упавшего звена, иначе
#            "grep ... | tail" всегда «успешен», даже если grep не нашёл файл.
#
# Намеренно НЕ используется set -e. Скрипт триажа обязан собрать максимум
# доступного: если на хосте нет `ss` или недоступен /var/log/secure, это не
# повод прервать сбор и потерять все остальные артефакты. Ошибки
# обрабатываются явно, каждой командой.
set -uo pipefail

# --- цвета (только для интерактивного терминала) ----------------------------
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""
fi

QUIET="${QUIET:-0}"

# --- логирование ------------------------------------------------------------
# Каждое сообщение уходит и в консоль, и в файл журнала внутри каталога
# результатов: журнал — часть доказательной базы, по нему видно, что именно
# и когда собиралось, и что собрать не удалось.

_log() {
    local level="$1" color="$2" message="$3"
    local stamp
    stamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    if [[ "$QUIET" != "1" ]]; then
        printf '%s %s%-7s%s %s\n' "$stamp" "$color" "$level" "$C_RESET" "$message" >&2
    fi
    if [[ -n "${TRIAGE_LOG:-}" ]]; then
        printf '%s %-7s %s\n' "$stamp" "$level" "$message" >> "$TRIAGE_LOG"
    fi
}

log_info()  { _log "INFO"  "$C_BLUE"   "$1"; }
log_ok()    { _log "OK"    "$C_GREEN"  "$1"; }
log_warn()  { _log "WARN"  "$C_YELLOW" "$1"; }
log_error() { _log "ERROR" "$C_RED"    "$1"; }

die() {
    log_error "$1"
    exit "${2:-1}"
}

# --- проверки окружения -----------------------------------------------------

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

is_root() {
    [[ "$(id -u)" -eq 0 ]]
}

# --- сбор артефактов --------------------------------------------------------

# collect_cmd <файл> <описание> <команда...>
#
# Выполняет команду, складывая вывод в файл каталога результатов. Ключевые
# свойства: отсутствие команды и ошибка её выполнения — разные ситуации, и
# обе фиксируются в файле и в журнале, а не проглатываются. Аналитик,
# читающий результат через неделю, должен понимать разницу между «данных нет»
# и «данные не собрали».
collect_cmd() {
    local outfile="$1" description="$2"
    shift 2
    local target="${OUTPUT_DIR}/${outfile}"

    {
        printf '# %s\n' "$description"
        printf '# команда: %s\n' "$*"
        printf '# время (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '# %s\n\n' "$(printf '=%.0s' {1..70})"
    } > "$target"

    if ! have_cmd "$1"; then
        printf '[НЕ СОБРАНО] команда «%s» отсутствует в системе\n' "$1" >> "$target"
        log_warn "${description}: команда «$1» недоступна"
        return 1
    fi

    local stderr_file exit_code
    stderr_file="$(mktemp)"
    "$@" >> "$target" 2> "$stderr_file"
    exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        {
            printf '\n[ОШИБКА] команда завершилась с кодом %d\n' "$exit_code"
            sed 's/^/[stderr] /' "$stderr_file"
        } >> "$target"
        log_warn "${description}: код возврата ${exit_code}"
    else
        log_ok "$description"
    fi

    rm -f "$stderr_file"
    return $exit_code
}

# collect_file <файл-результата> <описание> <путь...>
#
# Копирует содержимое файлов конфигурации. Проверяется и существование, и
# право на чтение: без root часть артефактов недоступна, и это надо честно
# отметить, а не выдать пустой файл за «всё чисто».
collect_file() {
    local outfile="$1" description="$2"
    shift 2
    local target="${OUTPUT_DIR}/${outfile}"

    {
        printf '# %s\n' "$description"
        printf '# время (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '# %s\n\n' "$(printf '=%.0s' {1..70})"
    } > "$target"

    local found=0 path
    for path in "$@"; do
        if [[ ! -e "$path" ]]; then
            printf '### %s — отсутствует\n\n' "$path" >> "$target"
            continue
        fi
        if [[ ! -r "$path" ]]; then
            printf '### %s — НЕТ ПРАВ НА ЧТЕНИЕ (требуется root)\n\n' "$path" >> "$target"
            log_warn "${description}: нет доступа к ${path}"
            continue
        fi
        printf '### %s\n' "$path" >> "$target"
        printf '# %s\n' "$(stat -c 'владелец=%U:%G права=%a изменён=%y' "$path" 2>/dev/null)" >> "$target"
        cat "$path" >> "$target" 2>/dev/null
        printf '\n\n' >> "$target"
        found=1
    done

    [[ $found -eq 1 ]] && log_ok "$description" || log_warn "${description}: файлы недоступны"
    return 0
}

# --- находки ----------------------------------------------------------------

# Находки копятся построчно в формате JSON Lines, а в конце собираются в
# массив. Промежуточный формат выбран специально: дописать строку в файл —
# атомарная и надёжная операция, а собирать JSON конкатенацией по ходу
# работы значит рисковать испорченным файлом при любом сбое.

json_escape() {
    # Экранирование по RFC 8259: обратный слеш, кавычка, управляющие символы.
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    text="${text//$'\n'/\\n}"
    text="${text//$'\r'/\\r}"
    text="${text//$'\t'/\\t}"
    printf '%s' "$text"
}

# add_finding <severity> <категория> <заголовок> <описание> <доказательство>
add_finding() {
    local severity="$1" category="$2" title="$3" description="$4" evidence="${5:-}"

    printf '{"severity":"%s","category":"%s","title":"%s","description":"%s","evidence":"%s","detected_at":"%s"}\n' \
        "$(json_escape "$severity")" \
        "$(json_escape "$category")" \
        "$(json_escape "$title")" \
        "$(json_escape "$description")" \
        "$(json_escape "$evidence")" \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        >> "$FINDINGS_FILE"

    case "$severity" in
        critical) log_error "[КРИТИЧНО] ${title}" ;;
        high)     log_error "[ВЫСОКАЯ] ${title}" ;;
        medium)   log_warn  "[СРЕДНЯЯ] ${title}" ;;
        *)        log_info  "[${severity}] ${title}" ;;
    esac
}

count_findings() {
    # Явные ветки вместо цепочки && ||: в этой идиоме легко получить вывод
    # обеих частей сразу, если середина вернёт ненулевой код.
    if [[ -s "$FINDINGS_FILE" ]]; then
        wc -l < "$FINDINGS_FILE" | tr -d ' \n'
    else
        printf '0'
    fi
}
