#!/usr/bin/env bash
# ============================================================================
#  analyze.sh — проверки на подозрительные признаки.
#
#  Важное ограничение, которое надо понимать и уметь объяснить: это
#  ЭВРИСТИКИ, а не доказательства. Открытый порт 4444 не означает
#  компрометацию — так мог быть настроен разработчик. Учётная запись с UID 0
#  может быть легитимной. Задача проверок — сократить объём ручного разбора,
#  указав аналитику, куда смотреть в первую очередь, а не вынести приговор.
#
#  Отсюда следуют два правила оформления находок: у каждой есть доказательство
#  (конкретная строка, а не «что-то подозрительное») и обоснование, почему это
#  признак. Находка без доказательства бесполезна: её невозможно проверить.
# ============================================================================

# --- подменяемые пути -------------------------------------------------------
# Проверки читают системные файлы через переменные, а не по жёстко зашитым
# путям. Это сделано ради тестируемости: в тестах подставляется каталог с
# заготовленными «уликами», и проверки удаётся прогнать на воспроизводимых
# данных, не имея скомпрометированной машины под рукой.
PASSWD_FILE="${PASSWD_FILE:-/etc/passwd}"
SHADOW_FILE="${SHADOW_FILE:-/etc/shadow}"
LD_PRELOAD_FILE="${LD_PRELOAD_FILE:-/etc/ld.so.preload}"

# --- 1. учётные записи с UID 0 ---------------------------------------------

check_uid0_accounts() {
    log_info "--- Проверка: учётные записи с UID 0 ---"
    [[ -r "$PASSWD_FILE" ]] || { log_warn "${PASSWD_FILE} недоступен"; return 0; }

    local account uid
    while IFS=: read -r account _ uid _ _ _ _; do
        [[ "$uid" == "0" ]] || continue
        if [[ "$account" == "root" ]]; then
            continue
        fi
        add_finding "critical" "accounts" \
            "Учётная запись «${account}» имеет UID 0" \
            "Любая запись с UID 0 обладает полными правами root независимо от имени. Создание такой записи — классический способ закрепления: она незаметнее, чем изменение пароля root, и переживает его смену." \
            "$(grep "^${account}:" "$PASSWD_FILE" 2>/dev/null | head -1)"
    done < "$PASSWD_FILE"
}

# --- 2. подозрительные учётные записи --------------------------------------

check_suspicious_accounts() {
    log_info "--- Проверка: подозрительные учётные записи ---"
    [[ -r "$PASSWD_FILE" ]] || return 0

    local account uid shell home
    while IFS=: read -r account _ uid _ _ home shell; do
        # Сервисная учётная запись с интерактивной оболочкой — аномалия:
        # службам оболочка не нужна, её наличие означает возможность входа.
        if [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] && \
           [[ "$shell" =~ (bash|sh|zsh|ksh|fish)$ ]]; then
            add_finding "medium" "accounts" \
                "Служебная запись «${account}» имеет интерактивную оболочку" \
                "Учётным записям служб оболочка не требуется. Её назначение позволяет войти в систему под этой записью и часто добавляется атакующим для закрепления." \
                "${account}: uid=${uid} shell=${shell}"
        fi

        # Домашний каталог в нестандартном месте
        if [[ "$uid" -ge 1000 && -n "$home" ]] && \
           [[ ! "$home" =~ ^/home/ ]] && [[ "$home" != "/root" ]] && \
           [[ "$home" != "/nonexistent" ]] && [[ "$home" != "/" ]]; then
            add_finding "low" "accounts" \
                "Нестандартный домашний каталог у «${account}»" \
                "Домашний каталог обычного пользователя вне /home встречается редко и заслуживает проверки: он может указывать на созданную вручную запись." \
                "${account}: home=${home}"
        fi
    done < "$PASSWD_FILE"

    # Пустые пароли: вход без аутентификации.
    if [[ -r "$SHADOW_FILE" ]]; then
        local hash
        while IFS=: read -r account hash _; do
            if [[ -z "$hash" ]]; then
                add_finding "critical" "accounts" \
                    "У учётной записи «${account}» пустой пароль" \
                    "Пустой пароль позволяет войти без аутентификации. Даже если запись создана легитимно, это грубая ошибка конфигурации, которой воспользуются в первую очередь." \
                    "${account}: поле пароля пустое"
            fi
        done < "$SHADOW_FILE"
    fi
}

# --- 3. подозрительные слушающие порты -------------------------------------

# Порты, которые чаще всего встречаются у средств удалённого управления и
# обратных подключений. Список — не признак вредоносности сам по себе, а
# повод посмотреть, какой процесс их занял.
SUSPICIOUS_PORTS="1080 1337 2222 3127 3128 4444 4445 5555 6666 6667 7777 8888 9001 9050 9999 12345 31337 54321"

check_listening_ports() {
    log_info "--- Проверка: слушающие порты ---"

    local listing="${OUTPUT_DIR}/04_listening.txt"
    [[ -r "$listing" ]] || { log_warn "Список сокетов не собран"; return 0; }

    local port line
    for port in $SUSPICIOUS_PORTS; do
        # Ищем ":ПОРТ " именно как локальный порт, а не как часть адреса.
        line="$(grep -E "[:.]${port}[[:space:]]" "$listing" 2>/dev/null | grep -i listen | head -1)"
        if [[ -n "$line" ]]; then
            add_finding "high" "network" \
                "Служба слушает нетипичный порт ${port}" \
                "Порт ${port} часто используется средствами удалённого управления, прокси и обратными подключениями. Сам по себе он ничего не доказывает — необходимо установить, какой процесс его занял и легитимен ли он." \
                "$line"
        fi
    done

    # Служба, слушающая на всех интерфейсах, доступна из сети. Для базы данных
    # или средства управления это ошибка конфигурации либо намеренное открытие
    # доступа атакующим.
    local exposed
    exposed="$(grep -E '(0\.0\.0\.0|\[::\]):[0-9]+' "$listing" 2>/dev/null | grep -i listen | wc -l)"
    if [[ "$exposed" -gt 0 ]]; then
        add_finding "info" "network" \
            "Служб, доступных со всех интерфейсов: ${exposed}" \
            "Такие службы доступны из сети. Требуется сверить список с ожидаемым: каждая лишняя точка входа расширяет поверхность атаки." \
            "$(grep -E '(0\.0\.0\.0|\[::\]):[0-9]+' "$listing" 2>/dev/null | grep -i listen | head -5 | tr '\n' '; ')"
    fi
}

# --- 4. задания планировщика -----------------------------------------------

check_cron_jobs() {
    log_info "--- Проверка: задания планировщика ---"

    # Признаки загрузки и немедленного исполнения полезной нагрузки прямо в
    # строке задания. Это не «плохие слова», а конструкции, которые в обычном
    # обслуживающем задании не встречаются.
    local patterns='curl .*\|.*(ba)?sh|wget .*\|.*(ba)?sh|base64 -d|base64 --decode|python -c|perl -e|nc -|/dev/tcp/|eval '
    local cronfile

    for cronfile in "${OUTPUT_DIR}/06_crontab_system.txt" \
                    "${OUTPUT_DIR}/06_crontab_users.txt"; do
        [[ -r "$cronfile" ]] || continue
        local hits
        hits="$(grep -inE "$patterns" "$cronfile" 2>/dev/null | grep -v '^\s*#' | head -5)"
        if [[ -n "$hits" ]]; then
            add_finding "high" "persistence" \
                "Задание cron содержит признаки загрузки и исполнения кода" \
                "В задании обнаружены конструкции вида «скачать и сразу выполнить», декодирование base64 или обратное подключение. Обслуживающие задания так не пишут — это характерный вид полезной нагрузки, обеспечивающей закрепление." \
                "$(printf '%s' "$hits" | tr '\n' ' | ')"
        fi
    done

    # Задание, выполняющееся ежеминутно, — типичный «сторож» для
    # восстановления вредоносного процесса после его завершения.
    if [[ -r "${OUTPUT_DIR}/06_crontab_users.txt" ]]; then
        local frequent
        frequent="$(grep -E '^\s*(\*/1|\*)\s+\*' "${OUTPUT_DIR}/06_crontab_users.txt" 2>/dev/null | head -3)"
        if [[ -n "$frequent" ]]; then
            add_finding "medium" "persistence" \
                "Задание cron выполняется ежеминутно" \
                "Ежеминутный запуск характерен для «сторожа», перезапускающего вредоносный процесс после его остановки. Проверьте, что именно запускается." \
                "$(printf '%s' "$frequent" | tr '\n' ' | ')"
        fi
    fi
}

# --- 5. ключи SSH ----------------------------------------------------------

check_ssh_keys() {
    log_info "--- Проверка: ключи SSH ---"

    local keysfile="${OUTPUT_DIR}/08_authorized_keys.txt"
    [[ -r "$keysfile" ]] || return 0

    local key_count
    key_count="$(grep -cE '^(ssh-|ecdsa-|sk-)' "$keysfile" 2>/dev/null)" || key_count=0
    if [[ "$key_count" -gt 0 ]]; then
        add_finding "info" "persistence" \
            "Ключей SSH, разрешённых для входа: ${key_count}" \
            "Каждый ключ — это самостоятельный способ входа, не зависящий от пароля. Список нужно сверить с ожидаемым: лишний ключ обеспечивает атакующему доступ даже после смены всех паролей." \
            "$(grep -E '^(ssh-|ecdsa-|sk-)' "$keysfile" 2>/dev/null | awk '{print $NF}' | tr '\n' ' ')"
    fi

    # Опции принудительного выполнения команды при подключении по ключу.
    local forced
    forced="$(grep -nE 'command=|no-pty|permitopen=' "$keysfile" 2>/dev/null | head -3)"
    if [[ -n "$forced" ]]; then
        add_finding "medium" "persistence" \
            "Ключ SSH с принудительной командой" \
            "Опция command= выполняет заданную команду при каждом подключении по этому ключу, независимо от того, что запросил клиент. Применяется и легитимно (ограниченный доступ для скриптов), и для скрытого закрепления." \
            "$(printf '%s' "$forced" | tr '\n' ' | ')"
    fi

    # Ключ root по SSH при разрешённом входе root — прямой административный
    # доступ извне.
    if grep -qE '^\s*PermitRootLogin\s+(yes|prohibit-password|without-password)' \
        "${OUTPUT_DIR}/08_sshd_config.txt" 2>/dev/null; then
        add_finding "medium" "configuration" \
            "SSH разрешает вход под root" \
            "Прямой вход root по SSH лишает возможности связать действия с конкретным человеком и убирает промежуточный барьер sudo. Рекомендуется PermitRootLogin no." \
            "$(grep -E '^\s*PermitRootLogin' "${OUTPUT_DIR}/08_sshd_config.txt" 2>/dev/null | head -1)"
    fi
}

# --- 6. неудачные входы ----------------------------------------------------

check_failed_logins() {
    log_info "--- Проверка: неудачные попытки входа ---"

    local authlog="${OUTPUT_DIR}/09_auth_log.txt"
    [[ -r "$authlog" ]] || { log_warn "Журнал аутентификации не собран"; return 0; }

    local failed
    failed="$(grep -ciE 'Failed password|authentication failure|Invalid user' \
        "$authlog" 2>/dev/null)" || failed=0

    if [[ "$failed" -ge 100 ]]; then
        add_finding "high" "authentication" \
            "Большое число неудачных входов: ${failed}" \
            "В собранном фрагменте журнала ${failed} неудачных попыток аутентификации. Это указывает на активный перебор паролей. Определите источники и проверьте, не завершилась ли какая-либо серия успешным входом." \
            "$(grep -iE 'Failed password' "$authlog" 2>/dev/null \
               | grep -oE 'from [0-9a-fA-F:.]+' | sort | uniq -c | sort -rn \
               | head -5 | tr '\n' ' | ')"
    elif [[ "$failed" -ge 20 ]]; then
        add_finding "medium" "authentication" \
            "Неудачных попыток входа: ${failed}" \
            "Умеренное число неудачных попыток. Для сервера, доступного из интернета, фоновый перебор — норма; проверьте распределение по источникам." \
            "$(grep -iE 'Failed password' "$authlog" 2>/dev/null \
               | grep -oE 'from [0-9a-fA-F:.]+' | sort | uniq -c | sort -rn \
               | head -3 | tr '\n' ' | ')"
    fi

    # Успешный вход с адреса, с которого до этого шли неудачи, — тот самый
    # переход от попытки к достигнутому доступу.
    local suspicious_ips
    suspicious_ips="$(grep -iE 'Failed password' "$authlog" 2>/dev/null \
        | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' \
        | sort -u)"
    local ip
    for ip in $suspicious_ips; do
        if grep -qE "Accepted (password|publickey|keyboard-interactive) .* from ${ip}( |$)" \
            "$authlog" 2>/dev/null; then
            add_finding "critical" "authentication" \
                "Успешный вход с адреса ${ip}, с которого шёл перебор" \
                "С этого адреса зафиксированы и неудачные, и успешные попытки входа. Наиболее вероятное объяснение — подбор пароля завершился успешно, и учётные данные скомпрометированы. Требуется немедленная проверка действий в этих сессиях." \
                "$(grep -E "Accepted .* from ${ip}" "$authlog" 2>/dev/null | head -2 | tr '\n' ' | ')"
        fi
    done
}

# --- 7. процессы -----------------------------------------------------------

check_processes() {
    log_info "--- Проверка: процессы ---"

    local binaries="${OUTPUT_DIR}/03_process_binaries.txt"
    if [[ -r "$binaries" ]]; then
        # Удалённый бинарник у работающего процесса — сильный признак сокрытия.
        # Легитимная причина существует (обновление пакета на лету), поэтому
        # severity высокая, но не критическая.
        local deleted
        deleted="$(grep '(deleted)' "$binaries" 2>/dev/null | head -5)"
        if [[ -n "$deleted" ]]; then
            add_finding "high" "processes" \
                "Процессы с удалённым исполняемым файлом" \
                "Исполняемый файл удалён с диска, а процесс продолжает работать. Приём применяется для сокрытия: файла нет, антивирус его не найдёт, а код исполняется. Возможна и легитимная причина — обновление пакета без перезапуска службы." \
                "$(printf '%s' "$deleted" | tr '\n' ' | ')"
        fi

        # Исполняемые файлы, запущенные из каталогов, доступных всем на запись.
        local from_tmp
        from_tmp="$(grep -E '/(tmp|var/tmp|dev/shm)/' "$binaries" 2>/dev/null | head -5)"
        if [[ -n "$from_tmp" ]]; then
            add_finding "high" "processes" \
                "Процессы, запущенные из временных каталогов" \
                "Штатное программное обеспечение устанавливается в /usr, /opt или /bin. Запуск из /tmp, /var/tmp или /dev/shm характерен для полезной нагрузки: эти каталоги доступны на запись любому пользователю." \
                "$(printf '%s' "$from_tmp" | tr '\n' ' | ')"
        fi
    fi

    # Процессы, маскирующиеся под системные (пробел или точка в конце имени).
    local ps_file="${OUTPUT_DIR}/03_ps_full.txt"
    if [[ -r "$ps_file" ]]; then
        local masquerading
        masquerading="$(grep -E '\[(kworker|kthreadd|ksoftirqd)[^]]*\][[:space:]]*$' "$ps_file" 2>/dev/null \
            | grep -vE '^\s*root' | head -3)"
        if [[ -n "$masquerading" ]]; then
            add_finding "medium" "processes" \
                "Процесс имитирует системный поток ядра" \
                "Потоки ядра (имена в квадратных скобках) всегда принадлежат root. Процесс с таким именем от имени другого пользователя — маскировка." \
                "$(printf '%s' "$masquerading" | tr '\n' ' | ')"
        fi
    fi
}

# --- 8. закрепление --------------------------------------------------------

check_persistence() {
    log_info "--- Проверка: механизмы закрепления ---"

    # LD_PRELOAD подгружает библиотеку в каждый запускаемый процесс. Файл
    # /etc/ld.so.preload на обычной системе отсутствует; его наличие —
    # серьёзный сигнал.
    if [[ -f "$LD_PRELOAD_FILE" ]]; then
        add_finding "critical" "persistence" \
            "Обнаружен файл /etc/ld.so.preload" \
            "Библиотеки из этого файла подгружаются в КАЖДЫЙ запускаемый процесс и могут подменять системные вызовы, скрывая файлы, процессы и сетевые соединения. На штатно настроенной системе файл отсутствует. Это признак руткита пользовательского уровня." \
            "$(cat "$LD_PRELOAD_FILE" 2>/dev/null | tr '\n' ' ')"
    fi

    # Подозрительные конструкции в файлах автозагрузки оболочки.
    local startup="${OUTPUT_DIR}/10_shell_startup.txt"
    if [[ -r "$startup" ]]; then
        local hits
        hits="$(grep -inE 'curl .*\|.*sh|wget .*\|.*sh|base64 -d|/dev/tcp/|nc -e' \
            "$startup" 2>/dev/null | head -3)"
        if [[ -n "$hits" ]]; then
            add_finding "high" "persistence" \
                "Файл автозагрузки оболочки содержит подозрительные команды" \
                "Команда, дописанная в .bashrc или .profile, выполняется при каждом входе пользователя. Обнаружены конструкции загрузки и исполнения кода или обратного подключения." \
                "$(printf '%s' "$hits" | tr '\n' ' | ')"
        fi
    fi

    # SUID-файлы вне стандартных каталогов.
    local suid="${OUTPUT_DIR}/10_suid_sgid.txt"
    if [[ -r "$suid" ]]; then
        local unusual
        unusual="$(grep -E '/(tmp|home|var/tmp|dev/shm|opt)/' "$suid" 2>/dev/null | head -5)"
        if [[ -n "$unusual" ]]; then
            add_finding "critical" "persistence" \
                "SUID-файл вне системных каталогов" \
                "Файл с битом SUID выполняется с правами владельца. SUID-root на бинарнике в /tmp или домашнем каталоге — готовый механизм повышения привилегий, оставленный для возврата в систему." \
                "$(printf '%s' "$unusual" | tr '\n' ' | ')"
        fi
    fi

    # Исполняемые файлы во временных каталогах.
    local tmpexec="${OUTPUT_DIR}/10_executables_in_tmp.txt"
    if [[ -r "$tmpexec" ]]; then
        local count
        count="$(grep -cE '^[0-9]{4}-' "$tmpexec" 2>/dev/null)" || count=0
        if [[ "$count" -gt 0 ]]; then
            add_finding "medium" "persistence" \
                "Исполняемые файлы во временных каталогах: ${count}" \
                "Каталоги /tmp, /var/tmp и /dev/shm доступны на запись всем пользователям и служат обычным местом размещения полезной нагрузки. Проверьте происхождение каждого файла." \
                "$(grep -E '^[0-9]{4}-' "$tmpexec" 2>/dev/null | head -3 | tr '\n' ' | ')"
        fi
    fi
}

# --- запуск всех проверок ---------------------------------------------------

run_all_checks() {
    log_info "############ АНАЛИЗ СОБРАННОГО ############"
    check_uid0_accounts
    check_suspicious_accounts
    check_listening_ports
    check_cron_jobs
    check_ssh_keys
    check_failed_logins
    check_processes
    check_persistence
}
