# Запуск набора на своей машине

Инструкция для Windows, Linux и macOS. Все команды проверены на чистом клоне
репозитория.

---

## Что понадобится

| | Зачем | Проверка |
|---|---|---|
| **Python 3.10+** | три из четырёх проектов | `python --version` |
| **git** | получить репозиторий | `git --version` |
| **Bash** | только для Linux Incident Triage | `bash --version` |
| Ключ VirusTotal | только для живых запросов IOC Analyzer | необязателен, есть режим `--offline` |

**На Windows** Bash-скрипт триажа не запускается. Варианта два: поставить WSL
(`wsl --install` в PowerShell от администратора) либо использовать готовый
отчёт `projects/linux-triage/samples/findings.json` — оболочка умеет его
импортировать, и вся кросс-корреляция при этом работает.

---

## Шаг 1. Получить репозиторий

```bash
git clone https://github.com/GrishaKharchenko/soc-security-automation.git
cd soc-security-automation
git checkout claude/ioc-analyzer-soc-98gwly
```

## Шаг 2. Одно окружение на весь набор

Проекты самодостаточны и могут иметь отдельные окружения, но для
демонстрации удобнее одно общее — оболочке всё равно нужны зависимости всех
модулей.

**Windows (cmd):**
```
python -m venv .venv
.venv\Scripts\activate
pip install -r projects\ioc-analyzer\requirements.txt
pip install -r projects\log-analyzer\requirements.txt
pip install -r projects\soc-toolkit\requirements.txt
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r projects/ioc-analyzer/requirements.txt
pip install -r projects/log-analyzer/requirements.txt
pip install -r projects/soc-toolkit/requirements.txt
```

Признак включённого окружения — `(.venv)` в начале строки приглашения. В
каждом новом окне терминала окружение нужно активировать заново.

## Шаг 3. Убедиться, что всё работает

```bash
cd projects/ioc-analyzer  && python -m pytest && cd ../..
cd projects/log-analyzer  && python -m pytest && cd ../..
cd projects/soc-toolkit   && python -m pytest && cd ../..
```

Ожидается `170 passed`, `93 passed`, `50 passed`.

Тесты Bash-скрипта (Linux/WSL):
```bash
cd projects/linux-triage && bash tests/run_tests.sh && cd ../..
```
Ожидается `Всего: 44 | пройдено: 44 | провалено: 0`.

---

## Демонстрация: что показывать

Порядок подобран так, чтобы каждая команда добавляла что-то новое.

### 1. Разбор индикаторов без сети (30 секунд)

```bash
cd projects/ioc-analyzer
python -m ioc_analyzer classify -i data/sample_iocs.txt
```

Обратить внимание: `evil.test` со счётчиком `2` — схлопнулись `EVIL.TEST.` и
`evil[.]test`; пометки `[defanged]`; `xn----8sbzclmxk.xn--p1ai` — это
`мой-сайт.рф` в punycode.

### 2. Живой запрос к VirusTotal (если есть ключ)

```bash
copy .env.example .env      # Linux/macOS: cp .env.example .env
# вписать VT_API_KEY в .env
python -m ioc_analyzer analyze -i data/sample_iocs.txt --types md5 sha256
```

Хеши EICAR получат вердикт `MALICIOUS` с соотношением около `63/67`.
`--types md5 sha256` — это ровно 4 запроса, лимит бесплатного ключа 4/мин.

### 3. Обнаружение атак в логах (30 секунд, сеть не нужна)

```bash
cd ../log-analyzer
python -m log_analyzer analyze -i data/auth.log data/windows_security.csv --year 2026
```

Показать: инциденты объединяют по несколько находок; техники ATT&CK у каждой;
`AUTH-003` поймал password spraying, который детект перебора не видит
принципиально.

```bash
python -m log_analyzer rules      # справочник правил с обоснованием техник
```

### 4. Сбор артефактов с хоста (только Linux/WSL)

```bash
cd ../linux-triage
sudo ./triage.sh -o /tmp/demo
cat /tmp/demo/triage_*/SUMMARY.txt
```

### 5. Объединение — главный номер программы

```bash
cd ../soc-toolkit
python -m soc_toolkit run \
    --iocs samples/incident_iocs.txt --offline --include-clean \
    --logs ../log-analyzer/data/auth.log --year 2026 \
    --triage-report ../linux-triage/samples/findings.json
```

Показать блок «ПОДТВЕРЖДЕНО НЕСКОЛЬКИМИ ИНСТРУМЕНТАМИ»: адрес `192.0.2.66`
найден независимо всеми тремя инструментами.

На Windows команда работает полностью — триаж подключается импортом отчёта.

---

## Типичные проблемы

| Симптом | Причина | Решение |
|---|---|---|
| `python не является внутренней командой` | не отмечена галочка «Add python.exe to PATH» | переустановить Python с галочкой либо использовать `py` |
| Открывается Microsoft Store вместо Python | заглушка Store перехватывает команду | Параметры → Приложения → Дополнительные параметры → Псевдонимы выполнения → выключить `python.exe` |
| `ModuleNotFoundError: No module named 'requests'` | не активировано окружение или не установлены зависимости | активировать `.venv`, выполнить `pip install -r ...` |
| `Файл не найден: data/auth.log` | команда запущена не из каталога проекта | `cd projects/log-analyzer` |
| `VT_API_KEY не задан` | нет ключа VirusTotal | добавить ключ в `.env` либо использовать `--offline` |
| `Модуль «ioc_analyzer» недоступен` | репозиторий склонирован не целиком | проверить наличие `projects/ioc-analyzer` |
| Кракозябры вместо кириллицы в консоли Windows | кодовая страница cmd | `chcp 65001` перед запуском |
| Bash-скрипт не запускается на Windows | Bash отсутствует | WSL либо импорт готового отчёта |

---

## Коды возврата

Одинаковы во всех инструментах и годятся для пайплайна:

| Код | Значение |
|---|---|
| 0 | находок нет |
| 1 | есть находки |
| 2 | есть критические находки (у IOC Analyzer — не удалось проверить часть индикаторов) |
| 3 | ошибка запуска: нет файла, неверный аргумент, некорректная конфигурация |

```bash
python -m soc_toolkit run --logs /var/log/auth.log -q
[ $? -ge 2 ] && echo "требуется внимание аналитика"
```
