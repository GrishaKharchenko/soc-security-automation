#!/usr/bin/env bash
# ============================================================================
#  collect.sh — сбор артефактов.
#
#  Порядок сбора важен и выбран по принципу «от самого летучего к самому
#  устойчивому» (RFC 3227, Order of Volatility). Сначала снимается то, что
#  исчезнет при первом же изменении состояния системы: список процессов,
#  открытые сетевые соединения, вошедшие пользователи. Потом — то, что лежит
#  на диске и никуда не денется: конфигурации, ключи, задания планировщика.
#
#  Каждый артефакт складывается в отдельный файл, чтобы результат можно было
#  читать глазами и сравнивать с эталонным хостом построчно.
# ============================================================================

# ---------------------------------------------------------------- 1. система

collect_system_info() {
    log_info "=== Системная информация ==="

    {
        printf '# Сводка по хосту\n# время сбора (UTC): %s\n\n' \
            "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'hostname          : %s\n' "$(hostname 2>/dev/null || printf 'н/д')"
        printf 'hostname -f       : %s\n' "$(hostname -f 2>/dev/null || printf 'н/д')"
        printf 'ядро              : %s\n' "$(uname -a 2>/dev/null)"
        printf 'аптайм            : %s\n' "$(uptime 2>/dev/null | sed 's/^ *//')"
        printf 'дата хоста        : %s\n' "$(date 2>/dev/null)"
        printf 'дата UTC          : %s\n' "$(date -u 2>/dev/null)"
        printf 'часовой пояс      : %s\n' "$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || printf 'н/д')"
        printf 'права сбора       : %s\n' "$(is_root && printf 'root' || printf "обычный пользователь ($(id -un))")"
        printf '\n# Дистрибутив\n'
        cat /etc/os-release 2>/dev/null || printf 'н/д\n'
    } > "${OUTPUT_DIR}/01_system_info.txt"
    log_ok "Сводка по хосту"

    # Аптайм важен сам по себе: недавняя перезагрузка может означать установку
    # руткита уровня ядра или заметание следов.
    collect_cmd "01_uptime.txt" "Время работы и загрузка" uptime
    collect_cmd "01_kernel_modules.txt" "Загруженные модули ядра" lsmod
}

# ------------------------------------------------------- 2. пользователи

collect_users() {
    log_info "=== Пользователи и сессии ==="

    # Кто в системе ПРЯМО СЕЙЧАС — самый летучий артефакт. Если атакующий
    # активен, здесь видна его сессия и адрес, с которого он подключён.
    collect_cmd "02_who.txt"  "Активные сессии (who)" who -a
    collect_cmd "02_w.txt"    "Активные сессии с командами (w)" w
    collect_cmd "02_id.txt"   "Текущий пользователь и группы" id
    collect_cmd "02_last.txt" "История входов (last)" last -Faiw -n 200

    # lastlog показывает последний вход КАЖДОЙ учётной записи. Вход под
    # сервисной учётной записью, которая по замыслу вообще не должна логиниться,
    # — сильный признак компрометации.
    collect_cmd "02_lastlog.txt" "Последний вход каждой учётной записи" lastlog

    # Неудачные входы: btmp читается только root.
    if have_cmd lastb; then
        collect_cmd "02_lastb.txt" "Неудачные попытки входа (lastb)" lastb -Faiw -n 200
    fi
}

# ---------------------------------------------------------- 3. процессы

collect_processes() {
    log_info "=== Процессы ==="

    collect_cmd "03_ps_full.txt" "Полный список процессов" \
        ps auxwwf
    collect_cmd "03_ps_sorted_cpu.txt" "Процессы по загрузке CPU" \
        ps aux --sort=-%cpu
    collect_cmd "03_ps_sorted_mem.txt" "Процессы по потреблению памяти" \
        ps aux --sort=-%mem

    # Соответствие процесса исполняемому файлу. Классический приём сокрытия —
    # удалить свой бинарник после запуска: процесс работает, а ссылка ведёт
    # в «(deleted)». Ниже это отдельно проверяется в analyze.sh.
    {
        printf '# Исполняемые файлы процессов (/proc/PID/exe)\n'
        printf '# «(deleted)» означает, что бинарник удалён с диска при\n'
        printf '# работающем процессе — типичный признак сокрытия.\n\n'
        printf '%-8s %-14s %s\n' "PID" "ПОЛЬЗОВАТЕЛЬ" "ИСПОЛНЯЕМЫЙ ФАЙЛ"
        local pid owner exe
        for pid in $(ls -1 /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n); do
            [[ -e "/proc/${pid}/exe" ]] || continue
            owner="$(stat -c '%U' "/proc/${pid}" 2>/dev/null || printf '?')"
            exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || printf 'недоступно')"
            printf '%-8s %-14s %s\n' "$pid" "$owner" "$exe"
        done
    } > "${OUTPUT_DIR}/03_process_binaries.txt" 2>/dev/null
    log_ok "Исполняемые файлы процессов"
}

# ------------------------------------------------------------- 4. сеть

collect_network() {
    log_info "=== Сеть ==="

    # ss пришёл на смену netstat; поддерживаем оба, потому что на старых
    # системах и в минимальных контейнерах может не быть ни того, ни другого.
    if have_cmd ss; then
        collect_cmd "04_listening.txt" "Слушающие сокеты" ss -tulpn
        collect_cmd "04_connections.txt" "Активные соединения" ss -tupn
    elif have_cmd netstat; then
        collect_cmd "04_listening.txt" "Слушающие сокеты (netstat)" netstat -tulpn
        collect_cmd "04_connections.txt" "Активные соединения (netstat)" netstat -tupn
    else
        log_warn "Ни ss, ни netstat не найдены — сетевые артефакты не собраны"
    fi

    if have_cmd ip; then
        collect_cmd "04_addresses.txt" "Сетевые интерфейсы" ip -o addr show
        collect_cmd "04_routes.txt" "Таблица маршрутизации" ip route show
        collect_cmd "04_arp.txt" "ARP-таблица (соседи)" ip neigh show
    else
        collect_cmd "04_addresses.txt" "Сетевые интерфейсы (ifconfig)" ifconfig -a
        collect_cmd "04_routes.txt" "Таблица маршрутизации (route)" route -n
    fi

    # Изменённый DNS или подставленные записи в hosts — способ перенаправить
    # трафик на инфраструктуру атакующего.
    collect_file "04_dns_hosts.txt" "Настройки DNS и файл hosts" \
        /etc/resolv.conf /etc/hosts /etc/nsswitch.conf

    if is_root && have_cmd iptables; then
        collect_cmd "04_firewall_iptables.txt" "Правила iptables" iptables -L -n -v
    fi
    if have_cmd nft && is_root; then
        collect_cmd "04_firewall_nft.txt" "Правила nftables" nft list ruleset
    fi
}

# ------------------------------------------------------------- 5. службы

collect_services() {
    log_info "=== Службы ==="

    if have_cmd systemctl; then
        collect_cmd "05_services_running.txt" "Работающие юниты systemd" \
            systemctl list-units --type=service --state=running --no-pager
        collect_cmd "05_services_enabled.txt" "Юниты в автозапуске" \
            systemctl list-unit-files --type=service --state=enabled --no-pager
        collect_cmd "05_services_failed.txt" "Юниты с ошибками" \
            systemctl list-units --state=failed --no-pager
        # Таймеры systemd — современная и часто упускаемая замена cron.
        collect_cmd "05_timers.txt" "Таймеры systemd" \
            systemctl list-timers --all --no-pager
    else
        collect_cmd "05_services_sysv.txt" "Службы SysV" service --status-all
    fi
}

# ------------------------------------------------------------ 6. планировщик

collect_cron() {
    log_info "=== Задания планировщика ==="

    collect_file "06_crontab_system.txt" "Системный crontab и каталоги cron" \
        /etc/crontab /etc/cron.d /etc/anacrontab

    {
        printf '# Каталоги периодических заданий\n\n'
        local dir
        for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
            printf '### %s\n' "$dir"
            if [[ -d "$dir" ]]; then
                ls -la "$dir" 2>/dev/null || printf 'нет доступа\n'
            else
                printf 'отсутствует\n'
            fi
            printf '\n'
        done
    } > "${OUTPUT_DIR}/06_cron_dirs.txt"
    log_ok "Каталоги cron"

    # Персональные crontab каждого пользователя. Читаются только с правами
    # root; без них ограничиваемся своим.
    {
        printf '# Персональные задания cron\n\n'
        if is_root; then
            local user
            while IFS=: read -r user _ _ _ _ _ _; do
                local jobs
                jobs="$(crontab -u "$user" -l 2>/dev/null)"
                if [[ -n "$jobs" ]]; then
                    printf '### пользователь: %s\n%s\n\n' "$user" "$jobs"
                fi
            done < /etc/passwd
        else
            printf '# Без прав root доступен только собственный crontab.\n\n'
            printf '### пользователь: %s\n' "$(id -un)"
            crontab -l 2>/dev/null || printf '(заданий нет)\n'
        fi
    } > "${OUTPUT_DIR}/06_crontab_users.txt"
    log_ok "Персональные задания cron"

    collect_file "06_at_jobs.txt" "Отложенные задания at" /var/spool/cron/atjobs
}

# --------------------------------------------------------- 7. учётные записи

collect_accounts() {
    log_info "=== Учётные записи ==="

    collect_file "07_passwd.txt" "Учётные записи (/etc/passwd)" /etc/passwd
    collect_file "07_group.txt"  "Группы (/etc/group)" /etc/group

    # Сам /etc/shadow НЕ копируется: это хеши паролей. Их выгрузка создаёт
    # новый носитель секретов и сама по себе является риском. Фиксируем
    # только метаданные, которых достаточно для триажа: у кого пустой пароль,
    # когда пароль менялся.
    if is_root && [[ -r /etc/shadow ]]; then
        {
            printf '# Метаданные /etc/shadow (БЕЗ хешей паролей)\n'
            printf '# Хеши намеренно не выгружаются: это создало бы новый\n'
            printf '# носитель секретов. Для триажа достаточно метаданных.\n\n'
            printf '%-20s %-12s %s\n' "УЧЁТНАЯ ЗАПИСЬ" "СТАТУС" "ИЗМЕНЁН (дней с 1970)"
            local account hash changed status
            while IFS=: read -r account hash _ _ _ _ _ _ _; do
                case "$hash" in
                    "")    status="ПУСТОЙ ПАРОЛЬ" ;;
                    "!"*|"*") status="заблокирован" ;;
                    *)     status="задан" ;;
                esac
                changed="$(awk -F: -v a="$account" '$1==a{print $3}' /etc/shadow 2>/dev/null)"
                printf '%-20s %-12s %s\n' "$account" "$status" "${changed:-н/д}"
            done < /etc/shadow
        } > "${OUTPUT_DIR}/07_shadow_metadata.txt"
        log_ok "Метаданные /etc/shadow (без хешей)"
    else
        printf '# /etc/shadow недоступен: требуются права root.\n' \
            > "${OUTPUT_DIR}/07_shadow_metadata.txt"
        log_warn "Метаданные /etc/shadow: нужен root"
    fi

    collect_file "07_sudoers.txt" "Конфигурация sudo" /etc/sudoers /etc/sudoers.d
    if have_cmd sudo && is_root; then
        collect_cmd "07_sudo_list.txt" "Действующие правила sudo" sudo -ll
    fi
}

# ------------------------------------------------------------------ 8. SSH

collect_ssh() {
    log_info "=== SSH ==="

    collect_file "08_sshd_config.txt" "Конфигурация сервера SSH" \
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d

    # Добавленный публичный ключ в authorized_keys — один из самых частых
    # способов закрепления: он переживает смену пароля и не требует эксплойта.
    {
        printf '# Ключи SSH, разрешённые для входа (authorized_keys)\n'
        printf '# Добавление своего ключа — типичный механизм закрепления:\n'
        printf '# доступ сохраняется даже после смены пароля.\n\n'

        local home user keyfile
        while IFS=: read -r user _ _ _ _ home _; do
            [[ -d "$home" ]] || continue
            for keyfile in "${home}/.ssh/authorized_keys" "${home}/.ssh/authorized_keys2"; do
                [[ -f "$keyfile" ]] || continue
                printf '### %s (пользователь %s)\n' "$keyfile" "$user"
                if [[ -r "$keyfile" ]]; then
                    printf '# %s\n' "$(stat -c 'владелец=%U права=%a изменён=%y' "$keyfile" 2>/dev/null)"
                    cat "$keyfile"
                else
                    printf '# НЕТ ПРАВ НА ЧТЕНИЕ\n'
                fi
                printf '\n'
            done
        done < /etc/passwd

        # Ключи root в нестандартных расположениях
        for keyfile in /root/.ssh/authorized_keys /etc/ssh/authorized_keys; do
            [[ -f "$keyfile" && -r "$keyfile" ]] || continue
            printf '### %s\n' "$keyfile"
            cat "$keyfile"
            printf '\n'
        done
    } > "${OUTPUT_DIR}/08_authorized_keys.txt" 2>/dev/null
    log_ok "Ключи SSH (authorized_keys)"

    collect_file "08_ssh_known_hosts.txt" "Известные хосты SSH" \
        /etc/ssh/ssh_known_hosts
}

# -------------------------------------------------------------------- 9. логи

collect_logs() {
    log_info "=== Журналы ==="

    # Копируется только «хвост»: полный auth.log может весить гигабайты, а для
    # первичного триажа нужна недавняя история. Полные журналы изымаются
    # отдельно, при полноценном сборе образа.
    local logfile
    for logfile in /var/log/auth.log /var/log/secure; do
        if [[ -r "$logfile" ]]; then
            {
                printf '# Последние 2000 строк %s\n' "$logfile"
                printf '# Полный журнал изымается отдельно при сборе образа.\n\n'
                tail -n 2000 "$logfile"
            } > "${OUTPUT_DIR}/09_auth_log.txt" 2>/dev/null
            log_ok "Журнал аутентификации: ${logfile}"
            break
        fi
    done
    [[ -f "${OUTPUT_DIR}/09_auth_log.txt" ]] || {
        printf '# Журнал аутентификации недоступен (нужен root либо journald).\n' \
            > "${OUTPUT_DIR}/09_auth_log.txt"
        log_warn "Журнал аутентификации недоступен"
    }

    if have_cmd journalctl; then
        collect_cmd "09_journal_auth.txt" "Journald: аутентификация" \
            journalctl _COMM=sshd _COMM=sudo _COMM=su --no-pager -n 1000
        collect_cmd "09_journal_boot.txt" "Journald: текущая загрузка (ошибки)" \
            journalctl -p err -b --no-pager -n 500
    fi

    for logfile in /var/log/syslog /var/log/messages; do
        if [[ -r "$logfile" ]]; then
            { printf '# Последние 1000 строк %s\n\n' "$logfile"
              tail -n 1000 "$logfile"; } > "${OUTPUT_DIR}/09_syslog.txt" 2>/dev/null
            log_ok "Системный журнал: ${logfile}"
            break
        fi
    done

    # Пустой или обнулённый журнал сам по себе — находка: заметание следов.
    collect_cmd "09_log_files_listing.txt" "Список файлов журналов с размерами" \
        ls -la /var/log/
}

# ------------------------------------------------------ 10. закрепление

collect_persistence() {
    log_info "=== Механизмы закрепления ==="

    # Файлы автозагрузки оболочки: строка в .bashrc выполняется при каждом
    # интерактивном входе и переживает перезагрузку.
    {
        printf '# Файлы автозагрузки оболочки\n'
        printf '# Команда, дописанная в конец такого файла, выполняется при\n'
        printf '# каждом входе пользователя — простой и живучий способ закрепления.\n\n'
        local home user shellfile
        while IFS=: read -r user _ _ _ _ home _; do
            [[ -d "$home" ]] || continue
            for shellfile in .bashrc .bash_profile .profile .bash_login .zshrc; do
                [[ -r "${home}/${shellfile}" ]] || continue
                printf '### %s/%s (%s)\n' "$home" "$shellfile" "$user"
                printf '# %s\n' "$(stat -c 'изменён=%y размер=%s' "${home}/${shellfile}" 2>/dev/null)"
                tail -n 30 "${home}/${shellfile}"
                printf '\n'
            done
        done < /etc/passwd
    } > "${OUTPUT_DIR}/10_shell_startup.txt" 2>/dev/null
    log_ok "Файлы автозагрузки оболочки"

    collect_file "10_rc_local.txt" "Скрипты автозапуска rc.local" \
        /etc/rc.local /etc/rc.d/rc.local

    # LD_PRELOAD — способ подгрузить свою библиотеку в каждый процесс,
    # классика подмены системных вызовов и сокрытия файлов.
    collect_file "10_ld_preload.txt" "Предзагружаемые библиотеки (LD_PRELOAD)" \
        /etc/ld.so.preload

    {
        printf '# Файлы юнитов systemd, изменённые за последние 30 дней\n'
        printf '# Свой юнит systemd — устойчивый механизм закрепления с\n'
        printf '# автоматическим перезапуском.\n\n'
        find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
            -type f -mtime -30 2>/dev/null | head -100 || printf '(не найдено)\n'
    } > "${OUTPUT_DIR}/10_recent_systemd_units.txt"
    log_ok "Недавно изменённые юниты systemd"

    # Файлы с установленным SUID-битом выполняются с правами владельца.
    # SUID на нестандартном бинарнике — прямой путь к повышению привилегий.
    {
        printf '# Файлы с битами SUID/SGID\n'
        printf '# Такой файл выполняется с правами владельца, а не запустившего.\n'
        printf '# SUID-root на нестандартном бинарнике — механизм повышения привилегий.\n\n'
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
            -printf '%M %u:%g %10s %p\n' 2>/dev/null | sort -k4 || printf '(поиск не выполнен)\n'
    } > "${OUTPUT_DIR}/10_suid_sgid.txt"
    log_ok "Файлы SUID/SGID"

    {
        printf '# Файлы, изменённые в /etc за последние 7 дней\n'
        printf '# Недавние изменения конфигурации — отправная точка для\n'
        printf '# построения временной шкалы инцидента.\n\n'
        find /etc -type f -mtime -7 -printf '%T+ %p\n' 2>/dev/null \
            | sort -r | head -200 || printf '(поиск не выполнен)\n'
    } > "${OUTPUT_DIR}/10_recent_etc_changes.txt"
    log_ok "Недавние изменения в /etc"

    # Каталоги, доступные всем на запись, — типичное место размещения полезной
    # нагрузки. Исполняемые файлы там особенно подозрительны.
    {
        printf '# Исполняемые файлы во временных каталогах\n'
        printf '# /tmp, /var/tmp и /dev/shm доступны на запись всем, поэтому\n'
        printf '# служат обычным местом для полезной нагрузки.\n\n'
        find /tmp /var/tmp /dev/shm -type f -executable \
            -printf '%T+ %M %u %10s %p\n' 2>/dev/null | head -100 || printf '(не найдено)\n'
    } > "${OUTPUT_DIR}/10_executables_in_tmp.txt"
    log_ok "Исполняемые файлы во временных каталогах"
}
