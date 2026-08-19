# Разбор кода: SOC Security Automation

Документ объясняет **каждый модуль и каждую значимую конструкцию** всех четырёх
проектов набора: что делает код, почему написан именно так, какие альтернативы
были и чем они хуже.

## Как читать этот документ

* **Часть 0** — языковые конструкции Python и Bash, встречающиеся в проекте.
  Если какая-то запись в коде непонятна, ответ, скорее всего, здесь.
* **Части 1–4** — разбор проектов, модуль за модулем, в том порядке, в котором
  данные проходят через код.
* **Часть 5** — сквозные решения и вопросы, которые задают на собеседовании.

Формат разбора каждого модуля одинаков: назначение, ключевые фрагменты кода с
пояснениями, и «что спросят» — вопрос, который по этому модулю вероятен на
собеседовании, с готовым ответом.

## Оглавление

**Часть 0. Языковые конструкции** — `from __future__ import annotations`,
датаклассы, Enum, ABC, оператор «морж», генераторы, `set -uo pipefail`,
`[[ ]]`, подстановки параметров Bash.

**Часть 1. IOC Analyzer**
`config.py` · `models.py` · `logging_setup.py` · `ioc/detector.py` ·
`ioc/normalizer.py` · `ioc/scope.py` · `parsers/reader.py` ·
`enrichment/base.py` · `enrichment/rate_limiter.py` · `enrichment/cache.py` ·
`enrichment/virustotal.py` · `scoring/verdict.py` · `reporting/writers.py` ·
`analyzer.py` · `cli.py`

**Часть 2. SOC Log Analyzer**
`models.py` · `mitre.py` · `parsers/base.py` · `parsers/linux_auth.py` ·
`parsers/windows_evtx_export.py` · `parsers/registry.py` ·
`detection/base.py` (скользящее окно) · `detection/bruteforce.py` ·
`detection/spraying.py` · `detection/access.py` · `detection/anomalies.py` ·
`detection/engine.py` · `reporting/writers.py` · `analyzer.py` · `cli.py`

**Часть 3. Linux Incident Triage**
`lib/common.sh` · `lib/collect.sh` · `lib/analyze.sh` · `triage.sh`

**Часть 4. SOC Automation Toolkit**
`bootstrap.py` · `models.py` · `adapters/base.py` · `adapters/ioc.py` ·
`adapters/logs.py` · `adapters/triage.py` · `correlation.py` · `cli.py` ·
устройство тестов

**Часть 5. Сквозные решения** — общие конвенции, принцип «отсутствие данных ≠
отсутствие проблемы», три уровня тестирования, таблица найденных ошибок, что
сделал бы иначе.

---

---

# Часть 0. Языковые конструкции

## 0.1. `from __future__ import annotations`

Стоит первой строкой почти в каждом модуле.

```python
from __future__ import annotations
```

**Что делает.** Заставляет Python трактовать все аннотации типов как строки и
не вычислять их при импорте.

**Зачем.** Без этой строки запись `def f(x: int | None)` требует Python 3.10+,
а `list[str]` — Python 3.9+. С ней такой синтаксис работает начиная с 3.7,
потому что аннотация не вычисляется. Второй эффект — можно ссылаться на класс
внутри его же определения:

```python
@classmethod
def from_score(cls, score: int) -> "Severity":   # без future нужны кавычки
```

**Что спросят:** «зачем эта строка?» → «чтобы использовать современный
синтаксис аннотаций на старых версиях Python и ссылаться на классы до их
полного определения; аннотации при этом не вычисляются в рантайме, что ещё и
чуть ускоряет импорт».

## 0.2. `@dataclass`

```python
@dataclass(frozen=True)
class Settings:
    vt_api_key: str = ""
    vt_requests_per_minute: int = 4
```

**Что делает.** Автоматически генерирует `__init__`, `__repr__`, `__eq__` по
объявленным полям.

**`frozen=True`** делает объект неизменяемым: попытка `settings.vt_timeout = 5`
поднимет `FrozenInstanceError`. Это выбрано намеренно — конфигурация не должна
меняться в середине работы. Когда изменение всё же нужно (флаги CLI поверх
`.env`), создаётся копия:

```python
updated = dataclasses.replace(settings, **overrides)
```

**Важная деталь — `field(default_factory=...)`:**

```python
output_dir: Path = field(default_factory=lambda: Path("reports"))
source_lines: list[int] = field(default_factory=list)
```

Изменяемый объект (`list`, `dict`, `Path`) нельзя задать значением по умолчанию
напрямую: он будет **общим для всех экземпляров** класса. Классическая ошибка:

```python
source_lines: list[int] = []        # ОШИБКА: один список на все объекты
```

Python это даже запрещает в датаклассах и падает с `ValueError: mutable default`.
`default_factory` вызывает функцию для каждого нового объекта.

**Что спросят:** «почему датакласс, а не обычный класс или словарь?» →
«датакласс даёт автодополнение в IDE, проверку типов и явную схему данных;
словарь — это `KeyError` в рантайме вместо ошибки на этапе разработки».

## 0.3. `Enum`, наследующий `str`

```python
class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
```

**Зачем наследовать `str`.** Три бесплатных свойства:

1. `json.dumps(verdict)` работает без преобразования — объект и есть строка;
2. сравнение со строкой: `if verdict == "malicious"` истинно;
3. `verdict.value` даёт чистую строку для отчётов.

**Свойства на Enum.** Enum — полноценный класс, у него могут быть методы:

```python
@property
def severity(self) -> int:
    return {Verdict.MALICIOUS: 5, Verdict.SUSPICIOUS: 4, ...}[self]
```

Так порядок серьёзности живёт рядом с определением вердиктов, а не в отдельном
словаре, который со временем разойдётся с ним.

**Что спросят:** «почему Enum, а не строковые константы?» → «Enum ограничивает
множество значений: опечатка `"malicous"` в сравнении со строкой пройдёт молча,
а `Verdict.MALICOUS` упадёт с `AttributeError` сразу».

## 0.4. `ABC` и `@abstractmethod`

```python
class EnrichmentProvider(ABC):
    @abstractmethod
    def enrich(self, ioc: IOC) -> EnrichmentResult:
        """..."""
```

**Что делает.** Класс нельзя создать, пока не реализованы все абстрактные
методы. Попытка `EnrichmentProvider()` поднимет `TypeError`.

**Зачем.** Это машинно проверяемый контракт. Если кто-то напишет провайдер для
AbuseIPDB и забудет `enrich`, ошибка возникнет при создании объекта, а не в
середине анализа фида из 500 индикаторов.

## 0.5. Оператор «морж» `:=`

```python
if (hash_type := looks_like_hash(value)) is not None:
    return hash_type
```

Присваивает и одновременно проверяет. Без него потребовалось бы две строки:

```python
hash_type = looks_like_hash(value)
if hash_type is not None:
    return hash_type
```

В цепочке из четырёх проверок (`detect_type`) это экономит восемь строк и
делает структуру «проверил — вернул» видимой глазом.

## 0.6. Генераторы и `yield`

```python
def parse(self, path: Path) -> Iterator[AuthEvent]:
    for line_number, line in enumerate(text.splitlines(), start=1):
        ...
        yield event
```

**Что делает.** Функция возвращает не список, а генератор: события выдаются по
одному, по мере разбора.

**Зачем для логов.** Файл `auth.log` на реальном сервере — сотни мегабайт.
Список всех событий занял бы гигабайты памяти; генератор держит в памяти одно
событие. Вызывающий код при необходимости материализует список сам
(`list(parser.parse(path))`) — и делает это осознанно.

## 0.7. Типы `X | None` и `dict[str, Any]`

```python
def normalize(raw: str, line_number: int = 0) -> IOC | None:
```

`X | None` — современная запись `Optional[X]` (Python 3.10+, а с
`from __future__ import annotations` — и раньше). Возврат `None` здесь
осмысленный: «строка не является индикатором», и вызывающий код обязан это
обработать.

## 0.8. `# noqa: BLE001` и подобные пометки

```python
except Exception as exc:  # noqa: BLE001 — защита от чужого кода
```

Комментарий для линтера: «я знаю, что перехват широкого `Exception` обычно
плохая практика, здесь это сделано намеренно». Рядом всегда стоит объяснение
причины. Молча подавлять предупреждение линтера — плохо; подавить с
обоснованием — нормально.

## 0.9. Bash: `set -uo pipefail`

```bash
set -uo pipefail
```

* `set -u` — обращение к неинициализированной переменной считать ошибкой.
  Без него опечатка `$OUTPUT_DIRR` даёт пустую строку, а `rm -rf $DIR/` с
  пустым `$DIR` превращается в `rm -rf /`.
* `set -o pipefail` — код возврата конвейера берётся от **упавшего** звена.
  Без него `grep ... | tail` всегда «успешен», даже если `grep` не нашёл файл.
* **`set -e` намеренно НЕ включён.** Он прерывает скрипт на первой ошибке, а
  скрипт триажа обязан собрать максимум доступного: отсутствие `ss` не повод
  потерять все остальные артефакты.

**Что спросят:** «почему не `set -e`, ведь это стандартный совет?» → «потому
что для скрипта реагирования цель — собрать как можно больше, а не упасть при
первой недоступной команде. Ошибки обрабатываются явно, каждой командой».

## 0.10. Bash: `[[ ]]` вместо `[ ]`

```bash
if [[ "$uid" -lt 1000 && "$shell" =~ (bash|sh|zsh)$ ]]; then
```

`[[ ]]` — встроенная конструкция Bash, а `[ ]` — внешняя программа `test`.
Различия, которые важны на практике:

* `[[ ]]` не выполняет разбиение слов, поэтому `[[ $var == "x" ]]` безопасен
  даже с пробелами внутри `$var`;
* поддерживает `&&`, `||` внутри скобок;
* поддерживает сравнение с регулярным выражением через `=~`.

## 0.11. Bash: подстановки параметров

```bash
QUIET="${QUIET:-0}"                    # значение по умолчанию
OUTPUT_DIR="${OUTPUT_BASE%/}/triage_…"  # убрать хвостовой слеш
value="${value//\\/\\\\}"               # заменить все вхождения
```

* `${VAR:-default}` — подставить `default`, если переменная не задана или пуста;
* `${VAR%/}` — удалить `/` с конца (одно вхождение), `%%` — жадно;
* `${VAR//что/на_что}` — заменить все вхождения (одиночный `/` — только первое).

Эти подстановки работают без запуска внешних процессов, в отличие от `sed`,
и потому быстрее и надёжнее.

---

# Часть 1. IOC Analyzer

Конвейер: **файл → парсер → детектор типа → нормализатор → отсев непроверяемых
→ VirusTotal → вердикт → отчёт**.

## 1.1. `config.py` — конфигурация

### Функции-читатели окружения

```python
def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} должен быть целым числом, получено: {raw!r}") from exc
```

Разбор строка за строкой:

* `os.getenv(name)` возвращает `None`, если переменной нет. Проверка
  `raw is None or not raw.strip()` покрывает два случая: переменной нет вовсе и
  переменная задана пустой (`VT_TIMEOUT=` в `.env`). Второй случай встречается
  постоянно и должен означать «используй значение по умолчанию», а не ошибку.
* `int(raw.strip())` — `strip()` обязателен: в `.env` часто остаются пробелы
  после значения.
* `raise ... from exc` — сохраняет исходное исключение в цепочке
  (`__cause__`). В трассировке будет видно и понятное сообщение, и
  первопричину. Просто `raise ConfigError(...)` потерял бы контекст.
* `{raw!r}` — `!r` вызывает `repr()` вместо `str()`. Для строки это добавляет
  кавычки: в сообщении будет `получено: 'abc '`, и станет видно, что проблема
  в пробеле. Без `!r` было бы `получено: abc ` — и хвостовой пробел незаметен.

### Префикс подчёркивания у имён

`_get_int`, а не `get_int`. Соглашение Python: имя, начинающееся с
подчёркивания, — внутреннее, не входит в публичный интерфейс модуля.
Технически ничто не мешает вызвать его извне, но это сигнал «не рассчитывай,
что оно не изменится».

### Метод `require_api_key`

```python
def require_api_key(self) -> str:
    if not self.vt_api_key:
        raise ConfigError(
            "VT_API_KEY не задан. Укажите ключ в .env или запустите "
            "анализ с флагом --offline (без обогащения)."
        )
    return self.vt_api_key
```

Два принципа сразу:

1. **Провал как можно раньше.** Проверка ключа при создании клиента, а не при
   первом запросе. Иначе пользователь узнает о проблеме после того, как
   инструмент прочитал файл, нормализовал 500 индикаторов и получил 401.
2. **Сообщение об ошибке говорит, что делать.** Не «ключ отсутствует», а
   «укажите в .env или используйте `--offline`». На это есть тест:
   `test_require_api_key_error_is_actionable` проверяет, что в тексте есть
   `--offline`.

### `validate()`

```python
def validate(self) -> None:
    if self.vt_requests_per_minute < 1:
        raise ConfigError("VT_REQUESTS_PER_MINUTE должен быть >= 1")
```

Проверки, которые дешевле сделать на старте. `vt_requests_per_minute = 0`
привёл бы к `ZeroDivisionError` или вечному ожиданию внутри лимитера —
ошибка проявилась бы далеко от причины.

### `load_dotenv(override=False)`

```python
load_dotenv(env_file, override=False)
```

`override=False` означает: переменные, уже присутствующие в окружении, **не**
перезаписываются значениями из файла. Порядок приоритета получается такой:

```
значения по умолчанию → .env → переменные окружения → флаги CLI
```

Это стандартное поведение рабочих утилит: в CI или в `docker run -e KEY=...`
переменная окружения должна побеждать файл, иначе контейнер невозможно
настроить извне.

**Что спросят:** «зачем отдельный модуль конфигурации, почему не читать
`os.environ` там, где нужно?» → «тогда каждый модуль зависит от глобального
состояния: его нельзя протестировать, не подменяя окружение, и невозможно
запустить два анализа с разными настройками в одном процессе. Здесь окружение
читается в одном месте, а дальше передаётся объект».

## 1.2. `models.py` — модели данных

### `IOCType` и свойства-предикаты

```python
class IOCType(str, Enum):
    IPV4 = "ipv4"
    ...
    @property
    def is_hash(self) -> bool:
        return self in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}
```

Свойство `is_hash` вместо проверки `ioc.type in ("md5", "sha1", "sha256")` по
всему коду. Если добавится SHA512, правка нужна в одном месте. Множество `{}`
вместо списка `[]` — проверка вхождения в множество занимает константное время
против линейного, и, что важнее, множество лучше выражает смысл «набор без
порядка».

### Ключевое решение: `EnrichmentStatus` отдельно от `Verdict`

```python
class EnrichmentStatus(str, Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"
    NETWORK_ERROR = "network_error"
    API_ERROR = "api_error"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
```

`EnrichmentStatus` — **технический** результат обращения к API.
`Verdict` — **аналитический** вывод об индикаторе. Это разные вещи:

| Ситуация | `EnrichmentStatus` | `Verdict` |
|---|---|---|
| VT ответил, детектов нет | `OK` | `CLEAN` |
| VT ответил 404 | `NOT_FOUND` | `UNKNOWN` |
| Сеть упала | `NETWORK_ERROR` | `ERROR` |
| Не проверяли (`--offline`) | — | `SKIPPED` |

Слияние этих понятий в один enum — типичная ошибка, из-за которой сбой сети
превращается в «индикатор безопасен». Именно на это есть отдельная группа
тестов `test_api_failure_is_error_never_clean`.

### `detection_ratio`

```python
@property
def detection_ratio(self) -> str:
    if not self.total_engines:
        return "0/0"
    return f"{self.malicious}/{self.total_engines}"
```

Формат `5/72` привычен любому SOC-аналитику — это то, что он видит в интерфейсе
VirusTotal. Проверка `if not self.total_engines` предотвращает деление на ноль
и заодно корректно обрабатывает случай «данных нет».

### `to_dict()` рядом с данными

Каждая модель умеет сериализовать себя сама. Альтернатива — отдельный
сериализатор, который знает про все модели, — приводит к тому, что при
добавлении поля правки нужны в двух местах, и второе про них забывают.

### `to_flat_row()` и `CSV_COLUMNS`

```python
CSV_COLUMNS: list[str] = ["value", "type", "verdict", ...]
```

Список колонок — модульная константа, а `to_flat_row()` возвращает словарь с
теми же ключами. Связь проверяется тестом: `list(rows[0].keys()) == CSV_COLUMNS`.
Так расхождение между объявленной схемой и фактическими данными ловится
тестом, а не пользователем.

## 1.3. `logging_setup.py` — логирование

### Два независимых канала

```python
console.setLevel(logger.level)         # уровень из конфигурации
file_handler.setLevel(logging.DEBUG)   # в файл всегда DEBUG
```

В консоль — то, что просил пользователь. В файл — всегда всё: разбор инцидента
задним числом дороже места на диске. Аналитик, который вечером увидел странный
вердикт, должен иметь возможность посмотреть, какие именно запросы уходили.

### `RotatingFileHandler`

```python
file_handler = logging.handlers.RotatingFileHandler(
    log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
)
```

При достижении `maxBytes` файл переименовывается в `.log.1`, начинается новый.
Хранится `backupCount` архивов. Без ротации лог демона, запускаемого по
расписанию, за месяц съест диск — и это происходит именно тогда, когда логи
нужнее всего.

### Фильтр, вырезающий секреты

```python
class SecretRedactingFilter(logging.Filter):
    def __init__(self, secrets: list[str]) -> None:
        super().__init__()
        self._secrets = [s for s in secrets if s and len(s) >= 8]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for secret in self._secrets:
                record.msg = record.msg.replace(secret, "***REDACTED***")
        if record.args:
            record.args = tuple(self._redact(arg) for arg in _as_tuple(record.args))
        return True
```

Разбор:

* `logging.Filter` в Python может не только фильтровать, но и **изменять**
  запись: возврат `True` означает «пропустить дальше», и модификации
  сохраняются. Это документированный способ редактирования логов.
* `len(s) >= 8` — короткие значения не маскируются. Если бы ключ был строкой
  `"a"`, замена испортила бы каждое слово в каждом сообщении.
* Обрабатывается и `record.msg`, и `record.args`. Логирование обычно вызывают
  как `logger.info("ключ %s", key)` — тогда сам ключ лежит в `args`, а не в
  сообщении. Обработка только `msg` пропустила бы утечку.

**Зачем вообще.** Логи попадают в тикеты, в чаты, в системы сбора. Утечка
ключа API оттуда — реальный инцидент. На это есть тест:
`test_api_key_is_redacted_from_logs` пишет ключ в лог и проверяет, что в файле
его нет.

### Идемпотентность

```python
logger.handlers.clear()
logger.propagate = False
```

`clear()` — повторный вызов `setup_logging` не добавит второй набор
обработчиков (иначе каждая строка будет дублироваться, и в тестах это
проявляется сразу). `propagate = False` — не передавать записи корневому
логгеру, иначе сообщения продублируются его обработчиками.

## 1.4. `ioc/detector.py` — определение типа

### Порядок проверок — это и есть логика модуля

```python
def detect_type(value: str) -> IOCType:
    value = value.strip()
    if not value:
        return IOCType.UNKNOWN
    if (hash_type := looks_like_hash(value)) is not None:
        return hash_type
    if looks_like_url(value):
        return IOCType.URL
    if (ip_type := looks_like_ip(value)) is not None:
        return ip_type
    if looks_like_domain(value):
        return IOCType.DOMAIN
    return IOCType.UNKNOWN
```

Порядок от самого строгого формата к самому свободному. Почему именно так:

* **hash первым** — самый жёсткий формат: только hex, только длина 32/40/64.
  Ложное срабатывание практически невозможно.
* **url раньше ip и domain** — `example.com/login.php` подходит и под домен
  (если наивно отрезать путь), и под URL. Правильный ответ — URL.
* **ip раньше domain** — `8.8.8.8` матчится регулярным выражением для FQDN.
  Это реальная ловушка, на неё есть тест `test_ip_wins_over_domain`.

### Валидация IP стандартной библиотекой

```python
def looks_like_ip(value: str) -> IOCType | None:
    candidate = value
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
```

* `ipaddress.ip_address` вместо регулярного выражения. Регулярка для IPv4
  должна отвергать `192.0.2.999`, регулярка для IPv6 — учитывать сжатие `::`,
  встроенный IPv4 (`::ffff:1.2.3.4`) и зоны (`%eth0`). Практически все
  самописные регулярки для IPv6 содержат ошибки.
* Снятие квадратных скобок — IPv6 в URL записывается как `[2001:db8::1]:443`.
* `ip.version` даёт 4 или 6 — так один вызов различает оба типа.

### Регулярное выражение для домена

```python
_LABEL = r"[a-zA-Z0-9¡-￿](?:[a-zA-Z0-9¡-￿-]{0,61}[a-zA-Z0-9¡-￿])?"
_TLD = r"(?:xn--[a-zA-Z0-9-]{2,59}|[a-zA-Z¡-￿]{2,63})"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_TLD}$")
```

Разбор по частям:

* `_LABEL` — одна метка домена. Структура `первый_символ(середина+последний)?`
  реализует правило «дефис не может быть первым или последним символом метки».
  `{0,61}` — метка не длиннее 63 символов (1 + 61 + 1).
* `¡-￿` — диапазон юникод-символов, чтобы принимать IDN в родном виде
  (`мой-сайт.рф`) до преобразования в punycode.
* `_TLD` — **это была ошибка, найденная тестом.** Изначально TLD описывался
  только буквенным классом, и `xn--p1ai` (punycode-форма `.рф`) не проходил:
  внутри него есть цифры и дефисы. Все IDN-домены молча терялись. Альтернатива
  `xn--...` добавлена после падения теста.
* `rf"..."` — комбинация raw-строки (обратные слеши не экранируются) и
  f-строки (подстановка `{_LABEL}`).
* `(?:...)` — незапоминающая группа. Обычная `(...)` заставила бы движок
  сохранять содержимое для обратных ссылок; в проверке соответствия это лишняя
  работа.
* `^` и `$` — привязка к началу и концу строки. Без них выражение найдёт домен
  внутри произвольного текста, и «not-an-ioc-example.com-junk» будет принят.

## 1.5. `ioc/normalizer.py` — нормализация

### Refang — понимание «обезвреженных» индикаторов

```python
_DEFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^h(?:xx|XX|\*\*)p(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\s*\[\s*(?:at|@)\s*\]\s*", re.IGNORECASE), "@"),
    ...
]
```

**Что это.** В индустрии принято передавать индикаторы в «обезвреженном» виде,
чтобы получатель случайно не кликнул: `hxxp://evil[.]test`. Инструмент обязан
это понимать, иначе половина входных данных из писем и тикетов окажется
«нераспознанной».

Технические детали:

* `r"http\1://"` — `\1` вставляет содержимое первой группы `(s?)`, то есть
  сохраняет `https` против `http`.
* `\s*` вокруг разделителей — в реальных данных встречается `evil [ . ] test`.
* Список кортежей `(шаблон, замена)` вместо цепочки `if` — правила
  применяются в цикле, добавление нового правила не требует менять код.
* Порядок в списке важен: схема (`hxxp://`) обрабатывается раньше, чем
  разделители, иначе `[:]` в `hxxp[:]//` будет заменён преждевременно.

Функция возвращает **кортеж**:

```python
def refang(value: str) -> tuple[str, bool]:
    original = value
    for pattern, replacement in _DEFANG_PATTERNS:
        value = pattern.sub(replacement, value)
    return value, value != original
```

Второй элемент — был ли индикатор обезврежен. Этот факт попадает в отчёт
(`defanged: true`): он говорит о происхождении данных — индикатор пришёл из
письма или тикета, а не из машинного фида.

### `strip_noise` — цикл вместо одного проходa

```python
def strip_noise(value: str) -> str:
    value = value.strip()
    while True:
        stripped = value.strip().strip(_WRAPPERS).strip()
        while stripped and stripped[-1] in _TRAILING_PUNCT:
            stripped = stripped[:-1]
        stripped = stripped.strip()
        if stripped == value:
            return stripped
        value = stripped
```

**Это исправление ошибки, найденной тестом.** Первая версия делала один проход
и на входе `(example.com);` оставляла `example.com)`: сначала снимались
обёртки (убрался `(`, но `;` не в списке обёрток и остановил обработку), потом
хвостовая пунктуация (убрался `;`), а закрывающая скобка так и осталась.

Обёртки и пунктуация чередуются, поэтому чистка идёт в цикле до стабилизации:
условие выхода `stripped == value` означает «за проход ничего не изменилось».

* `str.strip(chars)` — снимает **любые** символы из набора с обоих концов, а не
  подстроку целиком. Частое недопонимание: `"abcba".strip("ab")` даёт `"c"`.
* Внутренний `while` для хвостовой пунктуации нужен отдельно, потому что точку
  нельзя добавить в `_WRAPPERS`: она снялась бы и с начала строки.

### Нормализация URL: что можно и что нельзя менять

```python
def normalize_url(value: str) -> str:
    value = value.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", value):
        value = f"http://{value}"
    parts = urlsplit(value)
    netloc = parts.netloc.lower()
    if parts.scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif parts.scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, parts.fragment))
```

Ключевое: **схема и хост приводятся к нижнему регистру, путь — нет.**
DNS-имена регистронезависимы, а путь на сервере — нет: `/Login` и `/login`
могут быть разными ресурсами. Схлопнуть их значит потерять индикатор. На это
есть отдельный тест `test_url_path_case_is_preserved`.

* `urlsplit`/`urlunsplit` из стандартной библиотеки вместо ручного разбора
  строки: они корректно обрабатывают порты, аутентификацию в URL,
  IPv6-литералы в квадратных скобках.
* Достройка схемы обязательна: VirusTotal не принимает URL без схемы.
* Удаление порта по умолчанию — `http://a.test:80/` и `http://a.test/`
  указывают на один ресурс, и это два запроса к API вместо одного.

### IDN в punycode

```python
def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return value
```

* `rstrip(".")` — корневая точка. `example.com.` и `example.com` — один домен;
  запись с точкой встречается в выгрузках DNS.
* `.encode("idna")` — встроенный в Python кодек, превращает `мой-сайт.рф` в
  `xn----8sbzclmxk.xn--p1ai`. Именно в такой форме домен знает VirusTotal, и
  без преобразования запрос вернёт «не найдено».
* `except ... pass` здесь оправдан и прокомментирован: кодек падает на
  слишком длинных метках и на некоторых непечатаемых символах. Тип уже
  определён как домен, так что оставить значение как есть — разумная
  деградация, а не проглатывание ошибки.

### Дедупликация со слиянием

```python
def deduplicate(iocs: list[IOC]) -> list[IOC]:
    merged: dict[tuple[IOCType, str], IOC] = {}
    for ioc in iocs:
        key = (ioc.type, ioc.value)
        existing = merged.get(key)
        if existing is None:
            merged[key] = ioc
            continue
        existing.occurrences += 1
        existing.source_lines.extend(ioc.source_lines)
        existing.defanged = existing.defanged or ioc.defanged
    return list(merged.values())
```

* **Ключ — кортеж `(тип, значение)`.** Кортеж хешируем, поэтому годится в
  качестве ключа словаря (список — нет). Тип входит в ключ намеренно:
  `example.com` как домен и `example.com` как часть URL — разные индикаторы.
* **Дубликаты не выбрасываются, а сливаются.** Растёт `occurrences`, копятся
  `source_lines`. Индикатор, встреченный в фиде 40 раз, — сигнал сам по себе;
  а `source_lines` позволяют аналитику вернуться к исходным строкам.
* `existing.defanged or ioc.defanged` — если хоть одна из записей пришла
  обезвреженной, флаг сохраняется.
* Словарь в Python сохраняет порядок вставки, поэтому результат детерминирован
  и совпадает с порядком первого появления индикаторов.

## 1.6. `ioc/scope.py` — отсев непроверяемых индикаторов

Модуль появился после первого прогона по реальному VirusTotal.

```python
RESERVED_TLDS: frozenset[str] = frozenset({
    "test", "example", "invalid", "localhost", "local",
})
```

* `frozenset` вместо `set` — неизменяемое множество. Константу нельзя случайно
  изменить из другого модуля, и она хешируема.
* Зоны из RFC 2606 и RFC 6761 не существуют в корне публичного DNS. VirusTotal
  на такой домен отвечает не 404, а **400 «not a valid domain pattern»** —
  искать его негде.

```python
_NON_ROUTABLE_V4 = tuple(ipaddress.ip_network(cidr) for cidr in (
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
))
```

* Сети создаются **один раз при импорте модуля**, а не на каждый вызов.
  `ipaddress.ip_network` — не бесплатная операция, а функция проверки
  вызывается для каждого индикатора.
* **Диапазоны RFC 5737 (`192.0.2.0/24` и соседние) сюда намеренно не включены.**
  Стандартный `ipaddress.is_private` считает их приватными, но живой запрос
  показал, что VirusTotal их принимает и отдаёт данные. Отсекать то, что
  провайдер обрабатывает, — потеря функциональности. Это записано комментарием
  в коде, чтобы через полгода никто не «исправил» обратно, и закреплено тестом
  `test_documentation_ips_are_still_queried`.

### Возврат причины, а не булева значения

```python
def check_enrichable(ioc: IOC) -> str | None:
    if ioc.type is IOCType.DOMAIN and is_reserved_domain(ioc.value):
        return (
            f"Домен в зарезервированной зоне «.{ioc.value.rsplit('.', 1)[-1]}» "
            "(RFC 2606/6761) — в публичном DNS не существует…"
        )
    return None
```

Функция возвращает **текст причины** или `None`. Это сделано намеренно: причина
попадает прямо в отчёт, и аналитик видит, почему индикатор пропущен, вместо его
молчаливого исчезновения из результатов. Булево значение потребовало бы
формировать текст на стороне вызывающего кода — то есть дублировать знание.

* `ioc.value.rsplit('.', 1)[-1]` — последняя метка домена. `rsplit` с
  ограничением `1` разбивает только по последней точке: эффективнее, чем
  `split('.')[-1]`, который создаёт список из всех меток.
* `is` вместо `==` для Enum (`ioc.type is IOCType.DOMAIN`) — сравнение по
  идентичности. Для Enum это идиоматично, элементы существуют в единственном
  экземпляре.

## 1.7. `parsers/reader.py` — чтение входных файлов

### Подбор кодировки

```python
_ENCODINGS = ("utf-8-sig", "utf-8", "cp1251", "latin-1")

def _read_text(path: Path) -> str:
    last_error: Exception | None = None
    for encoding in _ENCODINGS:
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError as exc:
            last_error = exc
            continue
    raise InputError(f"Не удалось определить кодировку файла {path}: {last_error}")
```

Порядок кодировок не случаен:

* **`utf-8-sig` первой** — это UTF-8 с автоматическим снятием BOM. Excel при
  экспорте CSV добавляет BOM (`\xef\xbb\xbf`), и без этой кодировки байты BOM
  приклеятся к первому индикатору: `﻿192.0.2.1` не распознается.
  Если BOM нет, `utf-8-sig` работает как обычный `utf-8` — то есть она строго
  лучше и должна идти первой.
* `cp1251` — русскоязычные Windows-системы и старые серверы.
* `latin-1` последней — она **никогда не падает**: любой байт отображается в
  символ. Это гарантирует, что функция что-то вернёт, а не упадёт. Замыкающая
  кодировка в такой цепочке обязательна.

### Автоопределение разделителя CSV

```python
sample = "\n".join(text.splitlines()[:20])
try:
    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    delimiter = dialect.delimiter
except csv.Error:
    delimiter = ","
```

* `csv.Sniffer` — часть стандартной библиотеки, анализирует образец и
  определяет разделитель. `delimiters=",;\t|"` ограничивает набор кандидатов:
  без ограничения `Sniffer` иногда «находит» разделителем букву.
* Образец из первых 20 строк, а не весь файл: `Sniffer` на файле в сотни
  мегабайт работал бы недопустимо долго.
* `except csv.Error: delimiter = ","` — `Sniffer` поднимает исключение, если не
  смог решить (например, в файле одна колонка). Запятая как дефолт разумна.

### Поиск колонки с индикатором

```python
IOC_COLUMN_CANDIDATES = (
    "ioc", "indicator", "value", "artifact", "observable",
    "ip", "ip_address", "domain", "hostname", "url", "hash",
    "md5", "sha1", "sha256", "индикатор", "значение",
)

def _pick_ioc_columns(header: list[str]) -> list[int]:
    normalized = [h.strip().lower().lstrip("﻿") for h in header]
    matched = [i for i, name in enumerate(normalized) if name in IOC_COLUMN_CANDIDATES]
    if matched:
        return matched
    return list(range(len(header)))
```

* Стратегия из двух уровней: сначала ищем колонку с «говорящим» именем, и
  только если не нашли — сканируем все колонки. Лучше просканировать лишнее
  (детектор типов отбросит мусор), чем потерять индикатор.
* `lstrip("﻿")` — страховка от BOM, если он всё-таки просочился.
* Проверяется именно **точное** совпадение имени, а не вхождение подстроки:
  иначе колонка `ip_reputation_score` попала бы в кандидаты.
* На тестовых данных это работает: из CSV с колонками
  `timestamp,source,indicator,notes` берётся только `indicator`, а метки
  времени не засоряют результат.

### Определение, является ли первая строка заголовком

```python
def _looks_like_header(row: list[str]) -> bool:
    return not any(normalize(cell) for cell in row if cell.strip())
```

Изящный приём: строка считается заголовком, если **ни одна её ячейка не
распознаётся как индикатор**. Не нужно ни списка известных заголовков, ни
эвристик про регистр — используется уже имеющийся детектор.

`any(...)` с генератором останавливается на первом истинном значении, то есть
на первом же распознанном индикаторе.

### Разделение inline-комментария и разделителя

```python
def _split_inline(token: str) -> Iterable[str]:
    if _is_comment(token):
        return []
    token = token.split("#", 1)[0]
    parts = [p for chunk in token.split(",") for p in chunk.split(";")]
    return [p.strip() for p in parts if p.strip()]
```

**Это исправление ошибки, найденной тестом.** Первая версия отсекала
inline-комментарии по всем префиксам, включая `;`. Но `;` — ещё и разделитель
индикаторов в одной строке, поэтому `1.1.1.1; 2.2.2.2` терял второй адрес.

Теперь `;` считается комментарием только в начале строки (это проверяет
`_is_comment`), а внутри строки — разделителем. `//` тоже исключён из
inline-обработки: он живёт внутри URL.

* Вложенное списковое включение `[p for chunk in token.split(",") for p in chunk.split(";")]`
  читается как двойной цикл: внешний по частям, разделённым запятой, внутренний
  по частям, разделённым точкой с запятой. Порядок `for` такой же, как во
  вложенном цикле.
* `token.split("#", 1)` — ограничение `1` означает «разбить только по первому
  вхождению»: остальные `#` останутся в отброшенной части, и это дешевле.

### `ParseStats` и метрика покрытия

```python
@dataclass
class ParseStats:
    total_lines: int = 0
    parsed: int = 0
    invalid: int = 0
    invalid_samples: list[str] = field(default_factory=list)
```

Статистика — не украшение. Если парсер понял 5% файла, детекты построены на 5%
данных, и молчание инструмента означает не «всё чисто», а «мы почти ничего не
увидели». `invalid_samples` хранит до 10 примеров нераспознанных строк —
достаточно, чтобы понять причину, и не настолько много, чтобы раздуть отчёт.

## 1.8. `enrichment/base.py` — абстракция провайдера

```python
class EnrichmentProvider(ABC):
    name: str = "base"

    @abstractmethod
    def enrich(self, ioc: IOC) -> EnrichmentResult:
        """Не должен выбрасывать исключения: любая ошибка становится
        EnrichmentResult со статусом ошибки."""

    def unsupported(self, reason: str = "…") -> EnrichmentResult:
        return EnrichmentResult(
            provider=self.name, status=EnrichmentStatus.UNSUPPORTED, error=reason
        )

    def close(self) -> None:
        """Освободить ресурсы. По умолчанию — ничего."""
```

Три элемента и зачем каждый:

* `enrich` — абстрактный, обязателен к реализации.
* `unsupported` — готовый ответ для неподдерживаемого типа. Вынесен в базовый
  класс, чтобы каждый провайдер не собирал его заново.
* `close` — **не** абстрактный, с пустой реализацией. Провайдер, которому нечего
  освобождать, не обязан писать заглушку, но вызывающий код всегда может
  вызвать `close()`.

**Смысл абстракции.** Скоринг и отчёты зависят от `EnrichmentResult`, а не от
формата VirusTotal. Добавить AbuseIPDB, AlienVault OTX или внутренний MISP =
написать один класс. Это принцип инверсии зависимостей: и высокоуровневый
модуль (скоринг), и низкоуровневый (клиент VT) зависят от общей абстракции.

## 1.9. `enrichment/rate_limiter.py` — ограничитель частоты

```python
class RateLimiter:
    def __init__(self, max_calls: int, period: float = 60.0) -> None:
        if max_calls < 1:
            raise ValueError("max_calls должен быть >= 1")
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()
        self.total_waited = 0.0

    def acquire(self) -> float:
        with self._lock:
            now = time.monotonic()
            self._evict(now)
            if len(self._calls) < self.max_calls:
                self._calls.append(now)
                return 0.0
            sleep_for = self._calls[0] + self.period - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                self.total_waited += sleep_for
            now = time.monotonic()
            self._evict(now)
            self._calls.append(now)
            return max(sleep_for, 0.0)

    def _evict(self, now: float) -> None:
        while self._calls and now - self._calls[0] >= self.period:
            self._calls.popleft()
```

Разбор построчно:

* **`time.monotonic()`, а не `time.time()`.** Это принципиально. `time.time()`
  возвращает системные часы, которые могут прыгнуть назад при синхронизации по
  NTP или при переходе на зимнее время — и лимитер начнёт ждать час.
  `monotonic()` гарантированно не идёт назад.
* **`deque` вместо списка.** `popleft()` у `deque` — константное время, у списка
  `pop(0)` — линейное, потому что все элементы сдвигаются. Очередь заполняется
  и опустошается постоянно, поэтому это заметно.
* **`_evict`** выбрасывает из окна вызовы старше периода. Условие
  `now - self._calls[0] >= self.period` проверяет самый старый элемент; цикл
  продолжается, пока такие есть.
* **`self._calls[0] + self.period - now`** — сколько осталось ждать до момента,
  когда самый старый вызов выпадет из окна. Именно столько нужно спать, ни
  секундой больше.
* **`threading.Lock`** — на случай, если появится многопоточность. Сейчас код
  однопоточный, но лимитер — ровно то место, где состояние разделяемое.
* **Повторный `_evict` после сна** — за время сна окно уехало, и надо
  пересчитать состояние перед добавлением своего вызова.

**Главное решение — проактивность.** Лимит соблюдается заранее, а не через
обработку HTTP 429. У публичного ключа VirusTotal 4 запроса в минуту, и
систематическое превышение ведёт к блокировке ключа.

**Почему не `sleep(60 / rpm)` после каждого запроса.** Такой подход тормозит,
когда запросов мало (попадания в кеш, неподдерживаемые типы — паузы всё равно
будут), и не позволяет использовать разрешённый всплеск. Скользящее окно
пропускает первые 4 запроса без задержки и ждёт только на пятом — что и видно
в живом логе: `Rate limit 4/60с достигнут — пауза 55.2 с`.

## 1.10. `enrichment/cache.py` — файловый кеш

### Структура записи

```python
def set(self, key: str, payload: dict[str, Any]) -> None:
    self._data[key] = {"cached_at": time.time(), "payload": payload}
    self._dirty = True
```

Хранится время записи рядом с данными — так реализуется TTL. Здесь
`time.time()` уместен (в отличие от лимитера): значение сохраняется между
запусками программы, а `monotonic()` привязан к времени работы процесса и
после перезапуска ничего не значит.

### Проверка срока годности

```python
def get(self, key: str) -> dict[str, Any] | None:
    if not self.enabled:
        return None
    entry = self._data.get(key)
    if entry is None:
        self.misses += 1
        return None
    age = time.time() - entry.get("cached_at", 0)
    if age > self.ttl:
        self._data.pop(key, None)
        self._dirty = True
        self.misses += 1
        return None
    self.hits += 1
    return entry.get("payload")
```

* `entry.get("cached_at", 0)` — защита от записи старого формата без этого поля:
  возраст получится огромным, запись просто протухнет. Без дефолта был бы
  `KeyError` на кеше, созданном предыдущей версией программы.
* Устаревшая запись **удаляется**, а не просто игнорируется: иначе файл кеша
  растёт бесконечно.
* `self._data.pop(key, None)` — второй аргумент делает удаление безопасным,
  если ключа уже нет.

### Атомарная запись

```python
def save(self) -> None:
    if not self.enabled or not self._dirty:
        return
    try:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)
        self._dirty = False
    except OSError as exc:
        logger.warning("Не удалось сохранить кеш %s: %s", self.path, exc)
```

* **`_dirty`** — если ничего не менялось, файл не перезаписывается. Экономит
  ввод-вывод при прогоне, целиком попавшем в кеш.
* **Запись во временный файл и `replace`.** `Path.replace()` использует
  системный вызов `rename`, который атомарен в пределах файловой системы: либо
  старый файл, либо новый, промежуточного состояния не бывает. Прямая запись в
  целевой файл при падении программы посередине оставила бы обрезанный JSON.
* **`mkdir(parents=True, exist_ok=True)`** — создать всю цепочку каталогов,
  не падать, если каталог уже есть.
* **Ошибка записи кеша не роняет программу.** Кеш — оптимизация; если диск
  переполнен, анализ должен завершиться, просто без кеширования.

### Битый кеш не ломает работу

```python
def _load(self) -> None:
    if not self.path.exists():
        return
    try:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            self._data = raw
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Не удалось прочитать кеш %s (%s), начинаю с пустого", self.path, exc)
        self._data = {}
```

Проверка `isinstance(raw, dict)` — файл может содержать корректный JSON, но не
объект (например, список). Тогда `self._data` останется пустым словарём, а не
станет списком, на котором упадёт первый же `.get()`.

## 1.11. `enrichment/virustotal.py` — клиент API

Самый важный модуль проекта для собеседования.

### Таблица эндпоинтов

```python
_ENDPOINTS: dict[IOCType, str] = {
    IOCType.IPV4: "ip_addresses",
    IOCType.IPV6: "ip_addresses",
    IOCType.DOMAIN: "domains",
    IOCType.URL: "urls",
    IOCType.MD5: "files",
    IOCType.SHA1: "files",
    IOCType.SHA256: "files",
}
```

Словарь вместо цепочки `if/elif`. Единственное место в коде, где хранится знание
о структуре API VirusTotal. Тип, которого нет в словаре, автоматически даёт
`UNSUPPORTED` — новый тип IOC не сломает клиент.

### Идентификатор URL

```python
@staticmethod
def url_to_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
```

VirusTotal адресует URL не самой строкой, а её base64-представлением. Разбор:

* `url.encode("utf-8")` — base64 работает с байтами, не со строками.
* `urlsafe_b64encode` — вариант base64, где `+` и `/` заменены на `-` и `_`,
  чтобы результат можно было подставить в путь URL.
* `.decode("ascii")` — обратно в строку: результат base64 всегда ASCII.
* `.rstrip("=")` — VirusTotal требует форму **без** padding. Это
  документированная особенность API v3, и без `rstrip` запрос вернёт ошибку.

Проверено тестом с эталонным значением:
`url_to_id("http://example.com/index.html") == "aHR0cDovL2V4YW1wbGUuY29tL2luZGV4Lmh0bWw"`.

### Сессия `requests` и её инъекция

```python
def __init__(self, settings, session=None, cache=None) -> None:
    self.session = session or requests.Session()
    self.session.headers.update({
        "x-apikey": self.api_key,
        "accept": "application/json",
        "user-agent": "ioc-analyzer/1.0 (SOC automation)",
    })
```

* **`requests.Session`** переиспользует TCP- и TLS-соединение между запросами.
  На пачке из 100 индикаторов это экономит 100 рукопожатий TLS — заметный
  выигрыш.
* **Заголовки задаются один раз** на сессии, а не в каждом вызове.
* **`session=None` в параметрах** — инъекция зависимости. В тестах передаётся
  сессия, перехваченная `requests-mock`. Без этого пришлось бы патчить
  глобальный `requests`, что хрупко и мешает параллельным тестам.
* **`x-apikey`** — способ аутентификации VirusTotal API v3 (не
  `Authorization: Bearer`).
* **`user-agent`** — хорошая практика: владелец API видит, какой инструмент
  обращается, и может связаться при проблемах.

### Метод `_request` — сердце обработки ошибок

```python
for attempt in range(self.settings.vt_max_retries + 1):
    self.rate_limiter.acquire()
    try:
        response = self.session.get(url, timeout=self.settings.vt_timeout)
    except requests.exceptions.Timeout as exc:
        last_error = f"таймаут запроса ({self.settings.vt_timeout} с): {exc}"
        last_status = EnrichmentStatus.NETWORK_ERROR
    except requests.exceptions.ConnectionError as exc:
        ...
    else:
        status_code = response.status_code
        if status_code == 200:
            return response.json(), EnrichmentStatus.OK, None
        if status_code == 404:
            return None, EnrichmentStatus.NOT_FOUND, None
        if status_code in (401, 403):
            return None, EnrichmentStatus.AUTH_ERROR, detail
        if status_code == 429:
            wait = self._retry_after(response, attempt)
            if attempt < self.settings.vt_max_retries:
                time.sleep(wait)
            continue
        ...
    if attempt < self.settings.vt_max_retries:
        backoff = self.settings.vt_backoff_factor * (2 ** attempt)
        time.sleep(backoff)
```

Каждое решение здесь осознанно:

* **`range(max_retries + 1)`** — `max_retries=3` означает 3 **повтора**, то есть
  4 попытки всего. Классическая ошибка на единицу: без `+ 1` было бы 3 попытки.
* **`try/except/else`.** Блок `else` выполняется, только если исключения не
  было. Это чище, чем помещать разбор ответа в `try`: иначе исключение из
  кода разбора было бы перехвачено как сетевая ошибка.
* **404 → `NOT_FOUND`, без повторов.** VirusTotal просто не знает индикатор.
  Для домена, зарегистрированного вчера под фишинг, это ожидаемо. Повторять
  бессмысленно — ответ не изменится.
* **401/403 → выход немедленно.** Ключ не станет валидным от повторов. Каждая
  лишняя попытка — потраченное время и ещё одна запись в счётчик лимитов.
* **429 → уважаем `Retry-After`.** Сервер сам говорит, сколько ждать, и это
  всегда лучше собственной оценки.
* **`continue`** для 429 — переход к следующей итерации, минуя общий backoff в
  конце цикла: пауза уже сделана.
* **Экспоненциальный backoff `factor * 2 ** attempt`.** При `factor=2.0` паузы
  составят 2, 4, 8 секунд. Смысл экспоненты: если сервис перегружен, дружное
  возвращение всех клиентов через фиксированную секунду добьёт его.
* **Лимитер вызывается на каждой попытке** — повтор это тоже запрос, и он тоже
  расходует квоту.

### `_retry_after`

```python
def _retry_after(self, response, attempt: int) -> float:
    header = response.headers.get("Retry-After")
    if header:
        try:
            return max(float(header), 1.0)
        except ValueError:
            pass
    return self.settings.vt_backoff_factor * (2 ** attempt)
```

* `max(float(header), 1.0)` — не спать меньше секунды, даже если сервер
  прислал `Retry-After: 0`. Мгновенный повтор с высокой вероятностью снова
  получит 429.
* `except ValueError: pass` — заголовок по стандарту может содержать дату
  (`Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`), а не число секунд. Разбирать
  дату для нашей задачи излишне, поэтому падаем на экспоненциальный backoff.

### Защищённый разбор ответа

```python
attributes = (payload.get("data") or {}).get("attributes") or {}
stats = attributes.get("last_analysis_stats") or {}
malicious = int(stats.get("malicious") or 0)
```

Разбор идиомы `x.get(k) or {}`:

* `.get("data")` вернёт `None`, если ключа нет — тогда `or {}` подставит пустой
  словарь, и следующий `.get` не упадёт.
* `or {}` вместо `.get("data", {})` неспроста: если ключ **есть**, но его
  значение `None` (а VirusTotal так делает), то `.get("data", {})` вернёт
  `None`, и вызов `.get` на нём упадёт. Конструкция с `or` покрывает оба
  случая.
* `int(stats.get("malicious") or 0)` — та же логика плюс приведение типа:
  в JSON число может приехать строкой.

**Почему это важно.** VirusTotal возвращает разный набор полей для файлов,
домена, IP и URL, а у малоизвестных индикаторов половины полей нет вовсе.
`KeyError` в середине анализа фида — недопустим. Есть тесты
`test_missing_fields_do_not_crash` и `test_completely_empty_payload_does_not_crash`.

### Извлечение имён детектов

```python
results = attributes.get("last_analysis_results") or {}
detection_names = sorted({
    (engine_result or {}).get("result")
    for engine_result in results.values()
    if isinstance(engine_result, dict)
    and engine_result.get("category") in {"malicious", "suspicious"}
    and engine_result.get("result")
})
```

* **Множественное включение `{...}`** — сразу отбрасывает дубликаты: разные
  антивирусы часто дают одинаковое имя.
* `sorted(...)` вокруг — детерминированный порядок в отчёте. Множество в Python
  не сохраняет порядок, и без сортировки два прогона по тем же данным давали бы
  разные отчёты, что мешает их сравнивать.
* `isinstance(engine_result, dict)` — страховка на случай неожиданной
  структуры.
* Фильтр по `category` — берём только вердикты «вредоносно» и «подозрительно».
  Строка `result` есть и у чистых движков (обычно `None` или `"clean"`), она не
  нужна.

### Преобразование времени

```python
@staticmethod
def _ts_to_iso(value: Any) -> str | None:
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None
```

* `tz=timezone.utc` **обязателен**. Без него `fromtimestamp` использует
  локальный часовой пояс машины, и один и тот же отчёт на серверах в разных
  зонах покажет разное время.
* `timespec="seconds"` убирает микросекунды: в отчёте они только мешают.
* Перехват `OverflowError, OSError, ValueError` — VirusTotal может отдать
  бессмысленное значение (отрицательное, или год 100000), и на разных
  платформах это даёт разные исключения.

### Метод `enrich` — публичный контракт

```python
def enrich(self, ioc: IOC) -> EnrichmentResult:
    endpoint = self._endpoint(ioc)
    if endpoint is None:
        return self.unsupported(f"VirusTotal не работает с типом {ioc.type.value}")

    skip_reason = check_enrichable(ioc)
    if skip_reason is not None:
        return self.unsupported(skip_reason)

    cache_key = self._cache_key(ioc.type, ioc.value)
    cached = self.cache.get(cache_key)
    if cached is not None:
        return self._parse(cached, ioc, from_cache=True)

    payload, status, error = self._request(endpoint)

    if status is EnrichmentStatus.OK and payload is not None:
        self.cache.set(cache_key, payload)
        if ioc.type.is_hash:
            for hash_type, hash_value in self._file_hash_keys(payload):
                self.cache.set(self._cache_key(hash_type, hash_value), payload)
        return self._parse(payload, ioc, from_cache=False)
    ...
```

Порядок проверок — от самой дешёвой к самой дорогой:

1. тип не поддерживается — ноль работы;
2. индикатор непроверяем в принципе — ноль запросов;
3. есть в кеше — ноль запросов;
4. только теперь идём в сеть.

**Кеширование файла под всеми хешами** — исправление, найденное живым прогоном.
Фид содержал MD5 и SHA256 одного образца EICAR, и это стоило двух запросов из
500 суточных. Дедупликация их свести не могла: вывести SHA256 из MD5
невозможно. Но ответ VirusTotal содержит все три хеша файла в `attributes`,
поэтому результат раскладывается в кеш под каждым.

**Контракт: `enrich` никогда не выбрасывает исключение.** Любая проблема
превращается в результат со статусом. Прогон из 500 индикаторов не имеет права
упасть целиком из-за одного таймаута на 47-м. На это есть тест
`test_enrich_never_raises`.

## 1.12. `scoring/verdict.py` — расчёт вердикта

### Веса и их обоснование

```python
_WEIGHT_MALICIOUS = 12
_WEIGHT_SUSPICIOUS = 4
_WEIGHT_BAD_REPUTATION = 15
_WEIGHT_RATIO = 40
_SCORE_UNKNOWN = 25
_SCORE_ERROR = 20

_SCORE_FLOOR: dict[str, int] = {
    Verdict.MALICIOUS.value: 60,
    Verdict.SUSPICIOUS.value: 30,
}
```

`_SCORE_UNKNOWN = 25` и `_SCORE_ERROR = 20` — **ненулевые**. «Не знаю» и «не
смог проверить» — это не нулевой риск.

`_SCORE_FLOOR` появился после проверки согласованности: индикатор с одним
детектом набирал по весам всего 13 баллов и оказывался в очереди триажа **ниже**,
чем «VirusTotal о нём не знает» (25). Вердикт `SUSPICIOUS` при score 13
противоречит сам себе, поэтому введён пол по вердикту.

### Формула score

```python
def calculate_risk_score(enrichment: EnrichmentResult, settings: Settings) -> int:
    if enrichment.status is EnrichmentStatus.NOT_FOUND:
        return _SCORE_UNKNOWN
    if not enrichment.has_data:
        return _SCORE_ERROR

    score = 0.0
    score += enrichment.malicious * _WEIGHT_MALICIOUS
    score += enrichment.suspicious * _WEIGHT_SUSPICIOUS
    if enrichment.total_engines:
        ratio = enrichment.malicious / enrichment.total_engines
        score += ratio * _WEIGHT_RATIO
    if enrichment.reputation < settings.reputation_floor:
        score += _WEIGHT_BAD_REPUTATION
    elif enrichment.reputation > 0 and enrichment.malicious == 0:
        score -= 5
    return _clamp(score)
```

* **Абсолютное число детектов и доля учитываются оба.** 5 детектов из 10
  движков и 5 из 70 — разные ситуации: во втором случае большинство движков
  молчит. Доля это отражает.
* **`if enrichment.total_engines`** — защита от деления на ноль.
* **Хорошая репутация снижает score только при нулевых детектах.** Это прямое
  следствие наблюдения из живого прогона: у EICAR репутация **+3788**, потому
  что `reputation` в VirusTotal — голоса сообщества, а не оценка вредоносности.
  Все узнают тест-файл и голосуют «полезный». Если бы репутация могла снижать
  score при наличии детектов, EICAR получил бы вердикт «чисто».
* **`_clamp`** ограничивает результат диапазоном 0–100.

### Структура `calculate_verdict` — порядок ветвей

```python
if enrichment is None:                      # --offline
    result.verdict = Verdict.SKIPPED
elif enrichment.status is EnrichmentStatus.UNSUPPORTED:
    result.verdict = Verdict.SKIPPED
elif enrichment.status in {RATE_LIMITED, AUTH_ERROR, NETWORK_ERROR, API_ERROR, SKIPPED}:
    result.verdict = Verdict.ERROR
elif enrichment.status is EnrichmentStatus.NOT_FOUND:
    result.verdict = Verdict.UNKNOWN
else:
    # только здесь есть данные, только здесь считаем
```

Ветви идут от «данных нет вовсе» к «данные есть». Такой порядок исключает
попадание случая без данных в расчёт: последняя ветвь гарантированно работает
с `status == OK`.

### Логика вердикта при наличии данных

```python
if malicious >= settings.malicious_threshold:
    result.verdict = Verdict.MALICIOUS
elif malicious > 0 or suspicious >= settings.suspicious_threshold:
    result.verdict = Verdict.SUSPICIOUS
    if malicious:
        result.reasons.append(
            f"Детектов мало ({malicious} < порога {settings.malicious_threshold}), "
            "но они есть — возможен false positive, нужна проверка аналитиком"
        )
elif enrichment.reputation < settings.reputation_floor:
    result.verdict = Verdict.SUSPICIOUS
else:
    result.verdict = Verdict.CLEAN
```

**Почему порог 3, а не «хотя бы один детект».** Один сработавший антивирус из
70 — почти всегда false positive: эвристика, PUA, подозрительный упаковщик.
Если поднимать инцидент по одному детекту, SOC утонет в шуме и перестанет
доверять инструменту. При этом 1–2 детекта не игнорируются — они дают
`SUSPICIOUS` с явной пометкой о возможном FP.

**Все пороги — из конфигурации.** У разных команд разная толерантность к
ложным срабатываниям. Тест `test_thresholds_are_configurable` проверяет, что
при `malicious_threshold=1` два детекта дают `MALICIOUS`, а при `=10` — только
`SUSPICIOUS`.

### Объяснимость

```python
result.reasons.append(
    f"{malicious} антивирусных движка(ов) из {enrichment.total_engines} "
    f"классифицировали индикатор как вредоносный "
    f"(порог: {settings.malicious_threshold})"
)
```

В причине указан и факт, и порог, с которым он сравнивался. Аналитик может
проверить вывод, не читая исходники. Тест `test_every_verdict_has_reasons`
требует непустой список причин для **каждого** возможного вердикта.

## 1.13. `reporting/writers.py` — отчёты

### Сортировка

```python
def sort_results(results: list[AnalysisResult]) -> list[AnalysisResult]:
    return sorted(results, key=lambda r: (-r.verdict.severity, -r.risk_score, r.ioc.value))
```

* Кортеж как ключ сортировки — сравнение по элементам слева направо: сначала
  серьёзность вердикта, при равенстве — risk score, при равенстве — значение
  индикатора.
* **Минус перед числом** даёт убывающий порядок для этого поля, тогда как
  третье поле остаётся возрастающим. Через `reverse=True` так не получится —
  он развернул бы всё.
* Третий элемент нужен для **стабильности**: без него порядок одинаковых по
  оценке индикаторов зависел бы от порядка во входном файле, и два отчёта по
  тем же данным различались бы.

### CSV: две детали, которые всегда всплывают

```python
with path.open("w", encoding="utf-8-sig", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
```

* **`encoding="utf-8-sig"`** — записывает BOM. Excel без BOM считает CSV
  файлом в системной кодировке и показывает кириллицу кракозябрами. Мелочь,
  которая портит отчёт для заказчика. Есть тест `test_csv_has_bom_for_excel`.
* **`newline=""`** — требование документации модуля `csv`. Модуль сам
  управляет переводами строк; без этого параметра в Windows появятся пустые
  строки между записями.
* **`extrasaction="ignore"`** — лишние ключи в словаре не вызовут ошибку.
  Страховка при рассинхронизации `to_flat_row` и `CSV_COLUMNS`.

### JSON: читаемость для человека

```python
path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
```

* **`ensure_ascii=False`** — иначе кириллица превратится в `те...`.
  Формально это валидный JSON, но отчёт читают люди.
* **`indent=2`** — форматирование с отступами. Файл больше, зато его можно
  открыть и просмотреть глазами, а diff между двумя отчётами читаем.

### Метка времени в имени файла

```python
def _timestamped(directory, stem, suffix, timestamp: str | None) -> Path:
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return directory / f"{stem}_{ts}.{suffix}"
```

Параметр `timestamp` существует **ради тестов**: в них передаётся фиксированное
значение, и можно проверить, что два отчёта с разными метками не перетирают
друг друга. Без параметра тест зависел бы от того, попали ли два вызова в одну
секунду — классический источник «мерцающих» тестов.

## 1.14. `analyzer.py` — оркестратор

### Изоляция сбоя провайдера

```python
for index, ioc in enumerate(iocs, start=1):
    if progress:
        progress(index, total, ioc)
    enrichment = None
    if self.provider is not None:
        try:
            enrichment = self.provider.enrich(ioc)
        except Exception as exc:  # noqa: BLE001 — защита от чужого кода
            logger.exception("Непредвиденная ошибка обогащения %s: %s", ioc.value, exc)
            enrichment = EnrichmentResult(
                provider=getattr(self.provider, "name", "unknown"),
                status=EnrichmentStatus.API_ERROR,
                error=f"внутренняя ошибка провайдера: {exc}",
            )
    results.append(calculate_verdict(ioc, enrichment, self.settings))
```

* Провайдер **по контракту** не выбрасывает исключений, но перехват всё равно
  есть: контракт может нарушить чужая реализация. Устойчивость важнее
  «красивого» стектрейса.
* `logger.exception` вместо `logger.error` — записывает полную трассировку.
  Для непредвиденной ошибки это именно то, что нужно.
* `getattr(self.provider, "name", "unknown")` — сторонний провайдер может не
  объявить `name`.
* `enumerate(iocs, start=1)` — нумерация с 1 для отображения человеку
  (`[3/18]`).

### Коды возврата

```python
@staticmethod
def exit_code(results: list[AnalysisResult]) -> int:
    verdicts = {r.verdict for r in results}
    if verdicts & {Verdict.MALICIOUS, Verdict.SUSPICIOUS}:
        return 1
    if Verdict.ERROR in verdicts:
        return 2
    return 0
```

* Множественное включение `{r.verdict for r in results}` — уникальные вердикты
  одним проходом.
* `verdicts & {...}` — пересечение множеств вместо двух отдельных проверок
  `any()`.
* Порядок проверок задаёт приоритет: находки важнее ошибок. Прогон, где есть и
  вредоносный индикатор, и таймаут, вернёт 1 — потому что реагировать надо на
  находку.

Осмысленный код возврата превращает инструмент в кирпичик пайплайна:
`ioc-analyzer ... || notify-soc`.

## 1.15. `cli.py` — командный интерфейс

### Подкласс `ArgumentParser`

```python
class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: ошибка: {message}\n")
```

**Это исправление, найденное проверкой CLI.** `argparse` по умолчанию
завершает процесс кодом **2** при ошибке в аргументах. Но код 2 в контракте
уже занят («часть индикаторов проверить не удалось»). Пайплайн, проверяющий
`$? -eq 2`, принял бы опечатку в команде за результат анализа.

Переопределение `error()` — документированный способ изменить это поведение.
Подпарсеры наследуют класс родителя автоматически, поэтому правка в одном
месте покрывает все подкоманды.

### Наложение флагов на конфигурацию

```python
def apply_overrides(settings: Settings, args: argparse.Namespace) -> Settings:
    overrides: dict[str, object] = {}
    if getattr(args, "output_dir", None):
        overrides["output_dir"] = Path(args.output_dir)
    ...
    if not overrides:
        return settings
    updated = dataclasses.replace(settings, **overrides)
    updated.validate()
    return updated
```

* `dataclasses.replace` создаёт **копию** с изменёнными полями. `Settings`
  иммутабелен, прямое присваивание невозможно — и это хорошо: исключены
  неожиданные мутации конфигурации в середине работы.
* `getattr(args, "output_dir", None)` вместо `args.output_dir` — у разных
  подкоманд разный набор аргументов, и обращение к отсутствующему полю дало бы
  `AttributeError`.
* **Повторная `validate()`** после наложения: `--rpm 0` должен быть отвергнут
  так же, как `VT_REQUESTS_PER_MINUTE=0` в `.env`.
* `if not overrides: return settings` — не создавать копию без необходимости.

### `finally` для закрытия провайдера

```python
try:
    run = analyzer.analyze_file(...)
finally:
    if provider is not None:
        provider.close()
```

`finally` выполняется при любом выходе из блока, включая `KeyboardInterrupt`.
Это важно: `close()` сохраняет кеш. Без `finally` прерывание по Ctrl+C потеряло
бы все полученные ответы, и следующий запуск заново сжёг бы квоту.

### Верхний уровень обработки ошибок

```python
except InputError as exc:
    logger.error("Ошибка входных данных: %s", exc)
    print(f"Ошибка входных данных: {exc}", file=sys.stderr)
    return EXIT_USAGE
except KeyboardInterrupt:
    logger.warning("Прервано пользователем (Ctrl+C)")
    return EXIT_ERRORS
except Exception as exc:  # noqa: BLE001
    logger.exception("Непредвиденная ошибка: %s", exc)
    print(f"Непредвиденная ошибка: {exc}", file=sys.stderr)
    return EXIT_ERRORS
```

* Ошибки идут в **stderr**, а пути к отчётам — в stdout. Это позволяет
  перенаправить полезный вывод, не смешивая его с диагностикой:
  `ioc-analyzer ... > report_paths.txt`.
* Ожидаемые ошибки (`InputError`, `ConfigError`) выводятся коротким сообщением
  без трассировки: пользователю не нужен стектрейс, чтобы узнать, что файла нет.
* Непредвиденные — с трассировкой в лог, но с коротким сообщением на экран.
* `main()` возвращает код, а не вызывает `sys.exit()`. Это позволяет вызывать
  `main([...])` прямо из тестов и проверять возвращённое значение.
  `sys.exit` вызывается только в `__main__.py`.

**Что спросят:** «зачем `main` возвращает int вместо вызова `sys.exit`?» →
«чтобы функция была тестируемой: тест вызывает `main(["analyze", "-i", ...])` и
сравнивает результат с ожидаемым кодом. С `sys.exit` пришлось бы перехватывать
`SystemExit` в каждом тесте».

---

# Часть 2. SOC Log Analyzer

Конвейер: **файлы логов → парсеры → единое событие `AuthEvent` → 9 правил →
находки → корреляция в инциденты → отчёт**.

## 2.1. `models.py` — единое событие

### `AuthEvent` — центральная абстракция проекта

```python
@dataclass
class AuthEvent:
    timestamp: datetime
    outcome: EventOutcome
    platform: Platform = Platform.UNKNOWN
    username: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    hostname: str | None = None
    service: str | None = None
    event_type: str = "auth"
    event_id: str | None = None
    logon_type: str | None = None
    invalid_user: bool = False
    raw: str = ""
    source_file: str = ""
    line_number: int = 0
    extra: dict[str, Any] = field(default_factory=dict)
```

**Смысл модели.** Linux пишет
`Failed password for invalid user admin from 192.0.2.10`, Windows отдаёт
событие 4625 с полями `TargetUserName` и `IpAddress`. Правила детектирования не
должны знать об этой разнице.

Разбор полей:

* **`timestamp: datetime`** — всегда с часовым поясом и всегда приведён к UTC.
  Смешивать naive и aware даты нельзя: попытка их сравнить даёт `TypeError`.
* **`outcome`** вместо булева `success` — нужен третий вариант `UNKNOWN`
  (событие выхода из системы не является ни успехом, ни неудачей).
* **`invalid_user: bool`** — отдельный флаг, а не часть `outcome`. Это ключ к
  разделению перебора паролей и разведки имён: в Linux это пометка
  `invalid user`, в Windows — статус `0xc0000064`. Одно поле объединяет два
  разных представления.
* **`raw`** — исходная строка. Обязательное поле для инструмента
  реагирования: аналитик должен иметь возможность увидеть, из чего сделан
  вывод.
* **`source_file` и `line_number`** — точная ссылка на источник. При работе с
  несколькими файлами без них невозможно понять, откуда взялось событие.
* **`extra: dict`** — расширение для полей, специфичных для платформы (тип входа
  Windows, метод аутентификации SSH). Без него пришлось бы добавлять в модель
  поля, осмысленные только для одного парсера.

### `Severity` с числовым весом

```python
class Severity(str, Enum):
    CRITICAL = "critical"
    ...
    @property
    def score(self) -> int:
        return {Severity.CRITICAL: 100, Severity.HIGH: 75, ...}[self]

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        ...
```

Пять уровней вместо трёх: нужно отличать «разбирать немедленно» от «разобрать
сегодня». `score` даёт сортировку и агрегацию, `from_score` — обратное
преобразование, когда критичность вычисляется из числа.

### `Confidence` — вторая ось

```python
class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
```

**Критичность и уверенность — разные вещи.** «Успешный вход после 50 неудач» —
высокая критичность и высокая уверенность. «Вход в 3 часа ночи» — низкая
уверенность (админ мог работать ночью), но потенциально высокая критичность.
Смешивание их в один показатель теряет информацию, нужную аналитику для
приоритизации.

### `MitreTechnique` с полем `rationale`

```python
@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    rationale: str
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            ...,
            "url": self.url or f"https://attack.mitre.org/techniques/"
                                f"{self.technique_id.replace('.', '/')}/",
        }
```

* **`rationale` обязателен** (нет значения по умолчанию) — техника не может быть
  добавлена без объяснения, почему выбрана именно она.
* **Построение URL из идентификатора.** В ATT&CK подтехника `T1110.003`
  адресуется как `/techniques/T1110/003/` — точка заменяется на слеш. Одна
  строка избавляет от необходимости хранить URL для каждой техники и
  поддерживать их в актуальном виде.

### `Detection` и `Incident`

```python
@dataclass
class Detection:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    mitre: list[MitreTechnique] = field(default_factory=list)
    entities: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    evidence: list[AuthEvent] = field(default_factory=list)
    recommendation: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
```

* **`evidence: list[AuthEvent]`** — сами события, приведшие к находке. Хранятся
  объекты, а не строки: аналитик получает структурированные данные, а в отчёт
  выводится ограниченное число (`evidence_limit=10`), чтобы файл не разросся.
* **`entities: dict`** — сущности находки. Именно по ним потом идёт корреляция.
* **`metrics: dict`** — числовые характеристики (скорость попыток, число
  источников). Отделены от `description`: текст для человека, метрики для
  автоматики.
* **`recommendation`** — что делать. Находка без рекомендации перекладывает на
  аналитика работу, которую инструмент мог сделать сам.

```python
@property
def duration_seconds(self) -> float:
    if not self.first_seen or not self.last_seen:
        return 0.0
    return (self.last_seen - self.first_seen).total_seconds()
```

Вычитание двух `datetime` даёт `timedelta`; `total_seconds()` переводит его в
секунды (в отличие от `.seconds`, который даёт только секундную часть без дней —
классическая ловушка).

## 2.2. `mitre.py` — справочник техник

```python
T1110_003 = MitreTechnique(
    technique_id="T1110.003",
    name="Brute Force: Password Spraying",
    tactic="Credential Access",
    rationale=(
        "Один источник пробует МНОГО разных учётных записей, но по каждой делает "
        "лишь одну-две попытки. Это осознанный обход блокировки: политика "
        "lockout срабатывает по счётчику неудач на аккаунт, а распылённая атака "
        "его не превышает…"
    ),
)

ALL_TECHNIQUES: dict[str, MitreTechnique] = {
    t.technique_id: t for t in (T1110, T1110_001, T1110_003, T1087, T1078, ...)
}
```

* Техники — **модульные константы**, а не создаются на каждое срабатывание.
  Один объект переиспользуется всеми находками: экономия памяти и гарантия
  идентичности описаний.
* `ALL_TECHNIQUES` собирается **включением по кортежу** — при добавлении новой
  техники достаточно дописать её в кортеж, словарь построится сам.
* В `rationale` каждой техники объяснено не только «что это», но и **чем она
  отличается от соседней**. Это ровно то, что спрашивают на собеседовании:
  «почему T1087, а не T1110?»

## 2.3. `parsers/base.py` — контракт парсера и метрика покрытия

```python
@dataclass
class ParseStats:
    total_lines: int = 0
    parsed: int = 0
    skipped_irrelevant: int = 0
    unparsed: int = 0
    unparsed_samples: list[str] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        meaningful = self.parsed + self.unparsed
        return round(self.parsed / meaningful * 100, 1) if meaningful else 100.0
```

**Три категории вместо двух.** Различаются:

* `parsed` — событие разобрано;
* `skipped_irrelevant` — строка не про аутентификацию (запуск службы, cron).
  Это **не ошибка**, и включать её в метрику покрытия неправильно: иначе
  покрытие на нормальном логе будет 10%, и метрика перестанет что-либо значить;
* `unparsed` — строка похожа на событие, но разобрать не удалось. **Вот это
  ошибка**, и она попадает в метрику.

`coverage` возвращает `100.0` при нулевом знаменателе — пустой файл не должен
давать деление на ноль или «0% покрытия».

### Чтение с UTF-16

```python
raw = path.read_bytes()
if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
    return raw.decode("utf-16")
```

Выгрузки Windows часто приходят в UTF-16 (так пишет `Export-Csv` в некоторых
версиях PowerShell). Байты `\xff\xfe` — это BOM UTF-16 LE, `\xfe\xff` — BE.
`str.startswith` принимает кортеж вариантов, поэтому одна проверка покрывает
оба.

## 2.4. `parsers/linux_auth.py` — разбор auth.log

### Регулярное выражение заголовка syslog

```python
_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)
```

* **`(?P<имя>...)`** — именованные группы. Обращение `match.group("host")`
  вместо `match.group(2)`: при добавлении группы в середину номера сдвинутся, а
  имена нет.
* **`\s+` между полями** — в syslog день месяца выравнивается пробелами
  (`Aug  1` против `Aug 18`), поэтому фиксированное число пробелов не подойдёт.
* **`[\w./-]+?` для имени службы** — ленивый квантификатор `+?`. Он берёт
  минимально возможное, отдавая приоритет следующей группе `(?:\[(\d+)\])?`.
  С жадным `+` имя службы «съело» бы часть, и PID не выделился бы.
* **`(?:\[(?P<pid>\d+)\])?`** — PID необязателен: у некоторых записей
  (например, от `sudo`) его нет.
* **`(?P<message>.*)$`** — остаток строки. Разбирается отдельно, в зависимости
  от службы: так регулярки для sshd не проверяются на сообщениях sudo.

### Определение года

```python
def _resolve_year(self, path: Path) -> int:
    if self.default_year:
        return self.default_year
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=self.tz).year
    except OSError:
        return datetime.now(tz=self.tz).year
```

**Проблема формата.** Классический syslog не содержит года:

```
Aug 18 21:01:00 web01 sshd[1234]: Failed password for root from 192.0.2.10
```

**Почему не «текущий год».** Анализ прошлогоднего архива получил бы будущие
даты, и окна корреляции сошлись бы неверно. Время модификации файла — более
честное приближение. Приоритет: явное указание (`--year`) → mtime файла →
текущий год как последний резерв.

### Переход через новый год внутри файла

```python
if timestamp and rollover_guard and \
        (rollover_guard - timestamp) > timedelta(days=180):
    year += 1
    timestamp = self._parse_syslog_ts(match.group("ts"), year)
if timestamp:
    rollover_guard = timestamp
```

Лог, охватывающий декабрь и январь, без этой проверки дал бы события января с
прошлым годом — то есть на 11 месяцев раньше декабрьских, и вся хронология
развалилась бы.

Логика: если время «прыгнуло назад» больше чем на полгода, значит начался
следующий год. Порог 180 дней выбран как половина года: он надёжно отличает
переход через новый год от обычной перестановки строк на секунды (что в логах
бывает).

### Работа с часовым поясом

```python
local = datetime(year, month, int(day), hour, minute, second, tzinfo=self.tz)
return local.astimezone(timezone.utc)
```

* Сначала строится дата **в поясе исходного лога** (`tzinfo=self.tz`), потом
  переводится в UTC. Обратный порядок дал бы неверный результат.
* Внутри всего проекта время хранится в UTC. Это избавляет от вопроса «в каком
  поясе эта метка» при сравнении событий из разных источников.
* `ZoneInfo` из стандартной библиотеки (Python 3.9+) — не требует `pytz`.

### Разбор сообщений sshd

```python
_SSH_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive\S*)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    r"(?:\s+port\s+(?P<port>\d+))?"
)
```

* **`(?P<invalid>invalid user\s+)?`** — необязательная группа. Если она
  совпала, значит логина не существует. Это ключевой признак для разделения
  T1110 (подбор пароля) и T1087 (разведка имён), и он извлекается из той же
  регулярки, что и остальные поля.
* **Порядок проверок в `_parse_sshd`** — от самых частых сообщений к редким:
  `Failed password`, `Accepted`, `Invalid user`, `Connection closed`,
  общий `pam_unix`. На большом файле это заметно: типичный лог на 90% состоит
  из первых двух.

### Использование `:=` в цепочке проверок

```python
if (m := _SSH_FAILED.match(message)):
    return AuthEvent(...)
if (m := _SSH_ACCEPTED.match(message)):
    return AuthEvent(...)
```

Оператор «морж» позволяет проверить совпадение и сразу использовать результат.
Без него каждая проверка занимала бы две строки, и цепочка из шести шаблонов
стала бы вдвое длиннее.

### Передача общих полей через `**base`

```python
base = dict(
    timestamp=timestamp, platform=Platform.LINUX, hostname=hostname,
    service=service, raw=raw, source_file=str(path), line_number=line_number,
)
...
return AuthEvent(outcome=EventOutcome.FAILURE, username=m.group("user"), **base)
```

Семь одинаковых полей не повторяются в каждом из шести мест создания события.
`**base` распаковывает словарь в именованные аргументы. Добавление нового
общего поля — правка в одном месте.

## 2.5. `parsers/windows_evtx_export.py` — разбор выгрузки Windows

### Почему не бинарный EVTX

Разбор нативного формата требует внешней библиотеки и возни с бинарной
структурой, которая к обнаружению атак отношения не имеет. В реальной работе
аналитик почти никогда не держит сырой EVTX: события приезжают из SIEM или из
`Get-WinEvent | Export-Csv` уже разобранными. Поддерживать надо этот вход.

### Таблицы кодов

```python
EVENT_IDS: dict[str, tuple[EventOutcome, str]] = {
    "4624": (EventOutcome.SUCCESS, "windows_logon"),
    "4625": (EventOutcome.FAILURE, "windows_logon"),
    "4634": (EventOutcome.UNKNOWN, "windows_logoff"),
    "4648": (EventOutcome.SUCCESS, "windows_explicit_credentials"),
    "4672": (EventOutcome.SUCCESS, "windows_privileged_logon"),
    "4720": (EventOutcome.SUCCESS, "windows_account_created"),
    "4740": (EventOutcome.FAILURE, "windows_account_lockout"),
    "4776": (EventOutcome.UNKNOWN, "windows_credential_validation"),
}

LOGON_TYPES: dict[str, str] = {
    "2": "Interactive (консоль)",
    "3": "Network (сетевой доступ, SMB)",
    "10": "RemoteInteractive (RDP)",
    ...
}

FAILURE_REASONS: dict[str, str] = {
    "0xc000006a": "неверный пароль",
    "0xc0000064": "учётная запись не существует",
    "0xc0000234": "учётная запись заблокирована",
    ...
}
```

Расшифровка кодов — не косметика. Аналитик, читающий отчёт, не обязан помнить,
что `0xc0000064` означает «нет такой учётной записи». А для инструмента этот
код — основание выставить `invalid_user=True`:

```python
invalid_user=status == "0xc0000064",
```

Так признак разведки имён определяется в Windows точно так же, как в Linux
определяется по пометке `invalid user`. Это и есть работа нормализации.

### Гибкое сопоставление колонок

```python
_FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timecreated", "timegenerated", "eventtime", "timestamp",
                  "date", "@timestamp", "created", "дата и время", "время"),
    "event_id": ("id", "eventid", "event_id", "eventcode", "код события"),
    ...
}

@staticmethod
def _build_field_map(fieldnames: list[str]) -> dict[str, str]:
    normalized = {name.strip().lower().lstrip("﻿"): name
                  for name in fieldnames if name}
    mapping: dict[str, str] = {}
    for logical, candidates in _FIELD_CANDIDATES.items():
        for candidate in candidates:
            if candidate in normalized:
                mapping[logical] = normalized[candidate]
                break
    return mapping
```

Выгрузки разных инструментов называют колонки по-разному: `TimeCreated` в
PowerShell, `TimeGenerated` в старом API, `@timestamp` в Elastic, локализованные
имена в русской Windows. Сопоставление идёт по списку кандидатов.

* Словарное включение строит отображение «нормализованное имя → исходное имя»:
  искать удобно по нормализованному, а обращаться к строке CSV нужно по
  исходному.
* `break` после первого совпадения — порядок кандидатов задаёт приоритет.
* Ключ `logical` — внутреннее имя поля, не зависящее от формата выгрузки.

### Отсев служебных учётных записей

```python
if username and (username.endswith("$") or username.upper() in {"SYSTEM", "-"}):
    self.stats.skipped_irrelevant += 1
    return None
```

В Windows учётные записи компьютеров заканчиваются на `$` (`DC01$`), и события
от них идут постоянно. `SYSTEM` — локальная системная учётная запись. Без
отсева детекты утонули бы в этом шуме: правило «много неудач» срабатывало бы на
служебном трафике каждые несколько минут.

### Разбор нескольких форматов даты

```python
try:
    parsed = datetime.fromisoformat(text.replace(" ", "T", 1) if "T" not in text else text)
except ValueError:
    parsed = None

if parsed is None:
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%d.%m.%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            parsed = datetime.strptime(raw.strip(), fmt)
            break
        except ValueError:
            continue
```

Сначала пробуется ISO 8601 (`fromisoformat` быстрее `strptime`), затем
локальные форматы: американский с AM/PM, европейский с точками, ISO без `T`.
`%I` — 12-часовой формат, работает только в паре с `%p` (AM/PM).

```python
if parsed.tzinfo is None:
    parsed = parsed.replace(tzinfo=self.tz)
return parsed.astimezone(timezone.utc)
```

Если в строке не было указания пояса, применяется пояс из конфигурации; если
было — оно уважается. `replace(tzinfo=...)` **не** сдвигает время, а только
помечает его поясом — это именно то, что нужно для naive-даты.

## 2.6. `parsers/registry.py` — автоопределение формата

```python
def detect_parser(path: Path, settings: Settings) -> LogParser:
    sample = read_text(path)[:8192]
    if not sample.strip():
        raise ParseError(f"Файл пуст: {path}")
    for parser_class, key in ((WindowsEventLogParser, "windows"),
                              (LinuxAuthParser, "linux")):
        if parser_class.sniff(sample, path):
            return build_parser(key, settings)
    raise ParseError(
        f"Не удалось определить формат файла {path}. Поддерживаются: "
        "Linux auth.log/secure и выгрузка Windows Security Log в CSV/JSON. "
        "Формат можно задать явно флагом --format."
    )
```

* Определение **по содержимому**, а не по расширению: файл вполне может
  называться `export.txt` и быть выгрузкой Windows в CSV.
* Образец `[:8192]` — первых 8 КБ достаточно для распознавания.
* Windows-парсер проверяется первым: его `sniff` строже (требует и расширение
  из списка, и характерные маркеры в тексте), поэтому ложное срабатывание
  менее вероятно.
* Сообщение об ошибке перечисляет поддерживаемые форматы и подсказывает выход.

### Слияние источников

```python
events.sort(key=lambda e: e.timestamp)
```

Одна строка, но принципиальная. События из разных файлов складываются в общий
поток и сортируются по времени. Без этого правила, работающие со скользящим
окном, не увидят связь между Linux-хостом и контроллером домена: они полагаются
на хронологический порядок.

## 2.7. `detection/base.py` — контракт правила и скользящее окно

### Группировка

```python
def group_by(events: Iterable[AuthEvent],
             key: Callable[[AuthEvent], K | None]) -> dict[K, list[AuthEvent]]:
    grouped: dict[K, list[AuthEvent]] = defaultdict(list)
    for event in events:
        value = key(event)
        if value is not None:
            grouped[value].append(event)
    return dict(grouped)
```

* **`defaultdict(list)`** — обращение к отсутствующему ключу создаёт пустой
  список. Заменяет `if key not in grouped: grouped[key] = []`.
* **`return dict(grouped)`** — преобразование обратно в обычный словарь.
  Так вызывающий код не получит «сюрприз»: обращение к несуществующему ключу
  даст `KeyError`, а не создаст пустую запись молча.
* **`key: Callable`** — функция извлечения ключа передаётся снаружи. Одна
  функция обслуживает группировку по пользователю, по адресу и по паре:
  `group_by(events, lambda e: (e.username, e.source_ip))`.
* **`K = TypeVar("K")`** — параметр типа: ключ может быть строкой, кортежем,
  чем угодно. Проверяющий типов сохранит связь между типом ключа функции и
  типом ключа результата.

### Скользящее окно — ядро всех пороговых детектов

```python
def sliding_windows(events: Sequence[AuthEvent], window_seconds: int,
                    min_size: int) -> Iterator[list[AuthEvent]]:
    if min_size <= 0 or not events:
        return

    window = timedelta(seconds=window_seconds)
    total = len(events)
    index = 0

    while index < total:
        edge = index
        while edge + 1 < total and \
                events[edge + 1].timestamp - events[index].timestamp <= window:
            edge += 1

        if edge - index + 1 >= min_size:
            last = edge
            while last + 1 < total and \
                    events[last + 1].timestamp - events[last].timestamp <= window:
                last += 1
            yield list(events[index:last + 1])
            index = last + 1
        else:
            index += 1
```

Это самая содержательная функция проекта. Разбор:

**Первый внутренний цикл** находит правую границу окна, начинающегося в
`events[index]`: расширяет `edge`, пока события укладываются в `window` от
начала.

**Проверка `edge - index + 1 >= min_size`** — сколько событий попало в окно.
`+1` потому что индексы включительные.

**Второй внутренний цикл** — «поглощение всплеска». Расширяет группу вперёд,
пока разрыв между **соседними** событиями не превышает окно. Обратите внимание
на разницу: первый цикл сравнивает с началом окна (`events[index]`), второй — с
предыдущим событием (`events[last]`).

**`index = last + 1`** — поиск продолжается за границей найденной группы.

**Две ошибки, которых это избегает:**

1. **Фиксированные отрезки.** Если считать события по календарным
   пятиминуткам, атака, попавшая на границу отрезков, разделится пополам и не
   превысит порог ни в одной половине. Скользящее окно проверяет любой
   промежуток нужной длины.

2. **Дробление одной атаки на десятки алертов.** Это была реальная ошибка
   первой версии: на 12 событиях подряд функция выдавала **6 групп по 7
   событий** вместо одной. Аналитик получил бы 45 почти одинаковых алертов на
   одну атаку из 50 попыток. Поглощение всплеска решает проблему.

**Сложность O(n).** Каждый элемент посещается ограниченное число раз, потому
что `index` только растёт и никогда не возвращается назад.

Поведение закреплено тестами на границах:

| Вход | Результат | Смысл |
|---|---|---|
| 12 событий по 10 с, окно 60 с, порог 5 | `[12]` — одна группа | всплеск поглощён целиком |
| 6 событий по 600 с | `[]` | слишком редко, не атака |
| 5 подряд + пауза час + 5 подряд | `[5, 5]` | две отдельные волны |
| ровно 5 при пороге 5 | `[5]` | граница включительно |
| 4 при пороге 5 | `[]` | на один меньше — не срабатывает |

## 2.8. `detection/bruteforce.py` — AUTH-001 и AUTH-002

### Ключ группировки — главное решение правила

```python
for (username, source_ip), group in group_by(
    failures, lambda e: (e.username, e.source_ip)
).items():
```

**Пара `(пользователь, источник)`, а не что-то одно.** Обоснование:

* группировка только по пользователю смешала бы забывчивого сотрудника, у
  которого не подставился пароль на трёх устройствах, с настоящей атакой;
* группировка только по адресу приняла бы за перебор пароля распылённую атаку
  (password spraying), у которой другая природа и другая техника ATT&CK.

Распаковка кортежа прямо в `for (username, source_ip), group in ...` — ключ
словаря разбирается на составляющие сразу, без обращения `key[0]`, `key[1]`.

### Фильтр входных событий

```python
failures = [e for e in events if e.is_failure and e.username and e.source_ip]
```

Требуются **все три** условия. События без имени пользователя или без адреса
(например, sudo) не могут участвовать в этом детекте: ключ группировки был бы
неполным, и разные атаки склеились бы в одну.

### Определение, удался ли подбор

```python
horizon = burst[-1].timestamp + timedelta(seconds=self.settings.bruteforce_window)
breached = any(
    event.is_success
    and event.username == username
    and event.source_ip == source_ip
    and burst[0].timestamp <= event.timestamp <= horizon
    for event in all_events
)
```

* **`horizon` шире всплеска.** Успешный вход приходит **после** последней
  неудачи — это нормальный ход событий. Проверка строго внутри всплеска
  пропустила бы самое важное.
* **`any()` с генератором** останавливается на первом найденном успехе: нет
  смысла проверять остальные события.
* **Цепочка сравнений `a <= x <= b`** — питоновская запись двойного неравенства,
  вычисляется один раз (в отличие от C-подобных языков).
* Проверяются `all_events`, а не только `burst`: успешный вход в всплеск неудач
  не входит по определению.

Первая версия этого кода была написана нечитаемым выражением с
`replace(microsecond=0)` и арифметикой над `timedelta` — я переписал его явно,
потому что код, который нельзя прочитать, нельзя и проверить.

### Расчёт критичности

```python
attempts = len(burst)
duration = (burst[-1].timestamp - burst[0].timestamp).total_seconds()
rate = attempts / (duration / 60) if duration > 0 else float(attempts)

if breached:
    severity, confidence = Severity.CRITICAL, Confidence.HIGH
elif attempts >= self.settings.bruteforce_threshold * 4:
    severity, confidence = Severity.HIGH, Confidence.HIGH
elif rate > 10:
    severity, confidence = Severity.HIGH, Confidence.HIGH
else:
    severity, confidence = Severity.MEDIUM, Confidence.MEDIUM

privileged = username.lower() in {"root", "administrator", "admin", "администратор"}
if privileged and severity is Severity.MEDIUM:
    severity = Severity.HIGH
```

* **`if duration > 0 else float(attempts)`** — если все события в одну секунду,
  деление на ноль. Тогда скоростью считается само число попыток.
* **`rate > 10`** — больше 10 попыток в минуту. Человек так пароль не
  вспоминает; это автоматизированный инструмент.
* **`threshold * 4`** — критичность зависит от порога, а не от абсолютного
  числа. Если команда подняла порог до 20, то 80 попыток по-прежнему «в четыре
  раза выше порога», и логика не ломается.
* **Привилегированная учётная запись повышает критичность** — цена
  компрометации root несопоставима с обычным пользователем. Повышение только с
  `MEDIUM`, чтобы не понижать более серьёзные вердикты.
* Присваивание пары через кортеж `severity, confidence = ...` — одна строка
  вместо двух, и связь между значениями видна.

### AUTH-002: распределённая атака

```python
for burst in sliding_windows(group, window_seconds=self.settings.distributed_window,
                             min_size=self.settings.distributed_min_sources):
    sources = sorted({e.source_ip for e in burst if e.source_ip})
    if len(sources) < self.settings.distributed_min_sources:
        continue
```

**Зачем отдельное правило.** Если атакующий перебирает пароль к одной учётной
записи с двадцати адресов ботнета, то по каждой паре (пользователь, адрес)
попыток мало, и AUTH-001 не срабатывает. Смотреть надо на пользователя и
считать число **различных источников**.

Двойная проверка: `sliding_windows` гарантирует минимум событий в окне, а
дополнительная проверка — минимум **различных адресов**. Пять событий могли
прийти с одного адреса, и тогда это работа для AUTH-001.

Тест `test_distributed_attack_detected` проверяет именно это: на данных
«5 адресов по 2 попытки» AUTH-001 возвращает пустой список, а AUTH-002
срабатывает.

## 2.9. `detection/spraying.py` — AUTH-003 и AUTH-004

### Почему это отдельное правило — суть проекта

Политика блокировки считает неудачи **по каждой учётной записи**: пять
промахов — блокировка. Атакующий, который это знает, берёт один-два вероятных
пароля (`Winter2026!`, `Password1`) и пробует их по сотне логинов. По каждому
аккаунту — две попытки, порог не превышен, счётчик «неудач на пользователя»
молчит.

**Детект brute force такую атаку не увидит принципиально** — он смотрит не туда.

```python
for source_ip, group in group_by(failures, lambda e: e.source_ip).items():
    for burst in sliding_windows(group, window_seconds=self.settings.spraying_window,
                                 min_size=self.settings.spraying_min_users):
        attempts_per_user: dict[str, int] = {}
        for event in burst:
            attempts_per_user[event.username] = attempts_per_user.get(event.username, 0) + 1

        users = sorted(attempts_per_user)
        if len(users) < self.settings.spraying_min_users:
            continue

        max_attempts = max(attempts_per_user.values())
        if max_attempts > self.settings.spraying_max_attempts_per_user:
            continue
```

* **Ключ группировки развёрнут**: адрес источника, а внутри считается число
  различных пользователей. Это и есть всё содержание правила.
* **Второе условие обязательно.** Без проверки «попыток на аккаунт мало»
  правило срабатывало бы и на обычном переборе, дублируя AUTH-001 с неверной
  техникой ATT&CK.
* `sorted(attempts_per_user)` — сортировка словаря даёт список **ключей**
  (имён пользователей), отсортированный. Детерминированный порядок в отчёте.
* `dict.get(key, 0) + 1` — идиома подсчёта. Можно было взять
  `collections.Counter`, но здесь счётчик заполняется в том же цикле, где
  проверяются другие условия.

### Исключение несуществующих учётных записей

```python
failures = [e for e in events
            if e.is_failure and e.username and e.source_ip
            and not e.invalid_user]
```

**Это исправление, найденное первым прогоном.** Правило срабатывало на
разведке имён: атака на 8 несуществующих логинов формально выглядит как
распыление. Но это T1087 (Discovery), а не T1110.003 (Credential Access) —
разные тактики, разные рекомендации. Одно поведение получало два алерта с
разными техниками.

Строка `and not e.invalid_user` разделяет два правила чисто и однозначно.

### Определение успеха распыления

```python
horizon = burst[-1].timestamp + timedelta(seconds=self.settings.spraying_window)
compromised = sorted({
    event.username for event in all_events
    if event.is_success and event.source_ip == source_ip
    and burst[0].timestamp <= event.timestamp <= horizon
})
```

**Вторая ошибка, найденная прогоном.** Изначально проверка шла строго внутри
всплеска (`<= burst[-1].timestamp`), и успешный вход через 134 секунды после
последней неудачи не учитывался. Между тем это нормальный ход атаки: сначала
прогоняется весь список логинов, атакующий смотрит результат и только потом
заходит под тем, где пароль подошёл.

Из-за этой ошибки **самая важная находка сценария** — «распыление удалось» —
терялась, и критичность оставалась `HIGH` вместо `CRITICAL`.

### AUTH-004: разведка имён

```python
invalid = [e for e in events if e.is_failure and e.invalid_user
           and e.username and e.source_ip]
```

Зеркальное условие: берутся **только** попытки по несуществующим учётным
записям. Цель атакующего здесь не подобрать пароль, а выяснить, какие логины
существуют — система отвечает на валидный и невалидный логин по-разному
(разным текстом или разным временем отклика). Это разведка, тактика Discovery.

## 2.10. `detection/access.py` — AUTH-005, AUTH-006, AUTH-007

### AUTH-005: правило корреляции, а не порога

```python
for username, group in group_by(events, lambda e: e.username).items():
    group = sorted(group, key=lambda e: e.timestamp)
    known_good: set[str] = set()

    for index, event in enumerate(group):
        if not event.is_success:
            continue

        preceding: list[AuthEvent] = []
        for earlier in reversed(group[:index]):
            if event.timestamp - earlier.timestamp > window:
                break
            if earlier.is_failure:
                preceding.append(earlier)
            else:
                break

        familiar_source = event.source_ip in known_good
        if event.source_ip:
            known_good.add(event.source_ip)

        if len(preceding) < minimum:
            continue

        preceding.reverse()
        detections.append(self._build(username, event, preceding, familiar_source))
```

Разбор:

* **`reversed(group[:index])`** — идём назад от успешного входа. Так можно
  остановиться, как только вышли за окно, вместо просмотра всей истории.
* **`break` на предыдущем успехе** — это важная деталь. Успешный вход в
  середине серии означает, что пользователь уже входил нормально, и подбора не
  было. Без этого условия последовательность «неудача, неудача, успех, неудача,
  неудача, успех» дала бы ложное срабатывание. Есть тест
  `test_intervening_success_breaks_the_series`.
* **`preceding.reverse()`** — вернуть хронологический порядок перед сохранением
  в доказательства: собирали-то в обратном.
* **`known_good`** — множество адресов, с которых учётная запись успешно
  входила **ранее**. Пополняется по ходу прохода, то есть отражает состояние на
  момент рассматриваемого события, а не итоговое.

**Почему `known_good` — самое важное здесь.** Это исправление ложного
срабатывания, найденного на тестовых данных с контрпримером: сотрудница трижды
ошиблась паролем со своего рабочего места и вошла — правило выдало `CRITICAL`
«вероятная компрометация». Это ровно тот шум, из-за которого аналитики
перестают читать алерты.

```python
if familiar_source:
    severity, confidence = Severity.MEDIUM, Confidence.LOW
elif same_source:
    severity, confidence = Severity.CRITICAL, Confidence.HIGH
else:
    severity, confidence = Severity.HIGH, Confidence.MEDIUM
```

Три градации вместо двух:

1. адрес уже использовался этой учётной записью успешно — вероятнее забытый
   пароль, `MEDIUM` с низкой уверенностью;
2. адрес новый и совпадает с источником перебора — подбор удался, `CRITICAL`;
3. адрес новый, но перебор шёл с других адресов — неоднозначно, `HIGH`.

Именно так рассуждает аналитик: знакомый адрес меняет интерпретацию тех же
событий.

### Динамическое добавление техник

```python
techniques = [mitre.T1078, mitre.T1110_001]
if success.service and success.service.lower().startswith("sshd"):
    techniques.append(mitre.T1021_004)
if success.logon_type in {"10", "7"}:
    techniques.append(mitre.T1021_001)
```

Техники зависят от того, **как именно** был выполнен вход: по SSH — T1021.004,
по RDP (тип входа 10 или 7) — T1021.001. Маппинг выводится из наблюдаемого
поведения, а не приписывается всему правилу целиком.

### AUTH-006: sudo

```python
sudo_failures = [
    e for e in events
    if e.is_failure and e.username
    and e.event_type in {"sudo_auth", "sudo_not_permitted", "su_auth"}
]
```

Фильтр по `event_type`, а не по имени службы: три разных типа событий (неверный
пароль sudo, отсутствие в sudoers, неудачный su) означают одно — попытку
повысить привилегии.

```python
not_in_sudoers = any(e.event_type == "sudo_not_permitted" for e in burst)
severity=Severity.HIGH if not_in_sudoers else Severity.MEDIUM,
```

«Пользователя нет в sudoers» серьёзнее, чем «неверный пароль»: во втором случае
человек имеет право на sudo и просто ошибся, в первом — пытается выйти за
пределы своих прав.

### AUTH-007: блокировки

```python
accounts = sorted({e.username for e in lockouts if e.username})
mass = len(accounts) >= 5
...
mitre=[mitre.T1531] if mass else [mitre.T1110],
```

**Техника зависит от масштаба.** Блокировка одной-двух записей — следствие
перебора (T1110). Массовая блокировка — это уже возможный намеренный отказ в
обслуживании: заблокированные сотрудники не могут работать, и это T1531
(Account Access Removal, тактика Impact). Одно и то же событие в разном
количестве означает разные вещи.

## 2.11. `detection/anomalies.py` — AUTH-008 и AUTH-009

### Слабые сигналы и почему у них низкая критичность

```python
severity=Severity.LOW,
confidence=Confidence.LOW,
```

Отличие этих правил от пороговых: здесь нет «плохого» события как такового.
Вход в 3 часа ночи — не атака, админ вполне может работать ночью. Выставить им
`HIGH` означало бы утопить аналитика в ложных срабатываниях — верный способ
добиться, чтобы систему перестали читать.

Их задача — не поднять тревогу самостоятельно, а **добавить веса инциденту**,
когда рядом сработало что-то ещё. Связывание происходит на этапе корреляции.

### Определение нерабочего времени

```python
def _is_off_hours(self, event: AuthEvent) -> bool:
    if self.settings.flag_weekend_logins and event.timestamp.weekday() >= 5:
        return True
    hour = event.timestamp.hour
    return not (self.settings.business_hours_start
                <= hour < self.settings.business_hours_end)
```

* `weekday()` возвращает 0–6, где 0 — понедельник; `>= 5` это суббота и
  воскресенье.
* `start <= hour < end` — левая граница включительная, правая нет. При
  `start=8, end=20` рабочими считаются часы 8..19, то есть до 20:00. Это
  соответствует бытовому пониманию «с 8 до 20».
* Проверка выходных управляется флагом: в организациях со сменным графиком её
  нужно отключать.

### Минимальная база для «нового источника»

```python
MIN_BASELINE_LOGINS = 3

for username, group in group_by(successes, lambda e: e.username).items():
    group = sorted(group, key=lambda e: e.timestamp)
    if len(group) < MIN_BASELINE_LOGINS:
        continue
    known: set[str] = set()
    new_sources: list[AuthEvent] = []

    for event in group:
        if event.source_ip not in known:
            if known:            # первый адрес — это база, не аномалия
                new_sources.append(event)
            known.add(event.source_ip)
```

**Это исправление шума, найденное прогоном.** Без порога базы правило
срабатывало на пользователе, вошедшем всего дважды: первый адрес — база, второй
уже «новый». Из двух входов невозможно сделать вывод о привычном поведении.

* `if known:` внутри проверки — первый адрес добавляется в базу, но аномалией
  не считается. Иначе каждый пользователь получал бы находку на самом первом
  своём входе.
* Ограничение метода честно описано в докстринге: базовая линия строится
  **внутри анализируемого набора**, и для короткой выгрузки сигнал слабый. В
  продуктивной системе историю входов копят неделями и хранят отдельно.

## 2.12. `detection/engine.py` — движок и корреляция

### Реестр правил

```python
RULE_CLASSES: tuple[type[DetectionRule], ...] = (
    BruteForceRule, DistributedBruteForceRule, PasswordSprayingRule,
    UserEnumerationRule, SuccessAfterFailuresRule, PrivilegeAbuseRule,
    AccountLockoutRule, OffHoursLoginRule, NewSourceForUserRule,
)

RULE_IDS: dict[str, type[DetectionRule]] = {cls.rule_id: cls for cls in RULE_CLASSES}
```

* **`type[DetectionRule]`** — аннотация «класс, а не экземпляр». В кортеже лежат
  сами классы, экземпляры создаются позже, с настройками.
* `RULE_IDS` строится включением из `RULE_CLASSES` — добавление правила требует
  правки в одном месте.
* Кортеж, а не список: реестр не должен меняться в рантайме.

### Изоляция сбоя правила

```python
for rule in self.rules:
    try:
        found = rule.run(events)
    except Exception as exc:  # noqa: BLE001 — изоляция правил друг от друга
        logger.exception("Правило %s упало: %s", rule.rule_id, exc)
        continue
    detections.extend(found)
```

Ошибка в одном правиле не должна лишать аналитика результатов остальных восьми.
Правила независимы и не имеют общего состояния, поэтому такая изоляция
корректна: пропуск одного правила не искажает работу других.

Есть тест `test_engine_survives_broken_rule`: в движок подставляется правило,
которое всегда падает, и проверяется, что остальные отработали.

### Выбор подмножества правил

```python
if enabled_rules:
    wanted = {r.upper() for r in enabled_rules}
    selected = tuple(cls for cls in RULE_CLASSES if cls.rule_id in wanted)
    if not selected:
        raise ValueError(
            f"Неизвестные правила: {sorted(wanted)}. Доступны: {sorted(RULE_IDS)}"
        )
```

* `.upper()` — пользователь может написать `auth-001`.
* **Проверка на пустой результат обязательна.** Без неё опечатка в имени
  правила привела бы к запуску нуля правил и отчёту «находок нет» — самый
  опасный вид ошибки, потому что он выглядит как хороший результат.
* Сообщение перечисляет доступные правила.

### Корреляция в инциденты

```python
for detection in detections:
    entities = detection.entities
    key: tuple[str, str] | None = None

    if entities.get("source_ip"):
        key = ("source_ip", str(entities["source_ip"]))
    elif entities.get("username"):
        key = ("username", str(entities["username"]))
    elif len(entities.get("source_ips") or []) == 1:
        key = ("source_ip", str(entities["source_ips"][0]))
    elif len(entities.get("usernames") or []) == 1:
        key = ("username", str(entities["usernames"][0]))

    if key is None:
        key = ("rule", detection.rule_id)
    buckets.setdefault(key, []).append(detection)
```

* **Приоритет ключей**: адрес источника, затем учётная запись. Обоснование:
  большинство цепочек в логах аутентификации разворачивается вокруг одного
  источника — разведка, перебор, успешный вход приходят с одного адреса.
  Учётная запись как запасной ключ нужна для событий без адреса (sudo,
  блокировки).
* **`len(...) == 1`** — это исправление. Находки с множеством сущностей
  (распределённая атака, массовая блокировка) раньше привязывались к **первой**
  из них, и инцидент назывался «активность с учётной записи jsmith» для
  блокировки пяти аккаунтов. Теперь такие находки группируются по правилу.
* **`entities.get("source_ips") or []`** — защита и от отсутствия ключа, и от
  значения `None`.
* **`buckets.setdefault(key, []).append(...)`** — идиома «создать список, если
  нет, и добавить». Одна операция вместо проверки и присваивания.

### Идентификатор инцидента

```python
digest = hashlib.sha1(f"{key_type}:{key_value}".encode()).hexdigest()[:8]
incident = Incident(incident_id=f"INC-{digest}", ...)
```

Хеш от ключа связывания, а не случайное значение и не счётчик. Следствие:
**один и тот же инцидент получает один и тот же идентификатор между прогонами**.
Это позволяет сравнивать отчёты за разные дни и видеть, что инцидент
`INC-964f3fa9` продолжается. Со счётчиком идентификаторы менялись бы при каждом
запуске.

SHA-1 здесь используется не как криптографическая функция, а как способ
получить короткий детерминированный идентификатор из строки — для этой задачи
его известные слабости не имеют значения.

### Максимум критичности через `key`

```python
severity = max((d.severity for d in group), key=lambda s: s.score)
```

`max` с `key` — нужен, потому что сравнивать сами элементы `Severity` нельзя:
это строковый Enum, и `max` сравнивал бы строки лексикографически
(`"low" > "critical"` — истина, что абсурдно). `key=lambda s: s.score`
сравнивает по числовому весу.

### Название инцидента по числу этапов

```python
def _incident_title(key_type: str, key_value: str, group: Sequence[Detection]) -> str:
    stages = len({d.rule_id for d in group})
    if key_type == "rule":
        return group[0].title
    subject = (f"адреса {key_value}" if key_type == "source_ip"
               else f"учётной записи {key_value}")
    if stages >= 3:
        return f"Многоэтапная атака с {subject} ({stages} этапа)"
    if any(d.severity is Severity.CRITICAL for d in group):
        return f"Компрометация, связанная с {subject}"
    return f"Подозрительная активность с {subject}"
```

Число **различных правил** (не находок) в инциденте — мера продвинутости атаки.
Три и более разных правила означают, что атакующий прошёл несколько этапов:
разведка, перебор, доступ. Название отчёта сразу говорит аналитику, с чем он
имеет дело.

## 2.13. `analyzer.py` и `cli.py` Log Analyzer

Структура повторяет IOC Analyzer — это осознанное решение, а не копирование.
Одинаковые конвенции в обоих проектах сделали объединение в четвёртом проекте
слиянием, а не переписыванием.

### Коды возврата с иной семантикой

```python
@staticmethod
def exit_code(detections: Sequence[Detection]) -> int:
    severities = {d.severity for d in detections}
    if Severity.CRITICAL in severities:
        return 2
    if severities:
        return 1
    return 0
```

Здесь код 2 означает «есть **критические** находки», тогда как в IOC Analyzer —
«часть индикаторов проверить не удалось». Семантика разная, потому что задачи
разные, и это описано в справке каждого инструмента. Именно из-за этой занятости
кода 2 ошибки в аргументах переведены на код 3.

### Подкоманда `rules` — справка, построенная из кода

```python
for rule_class in RULE_CLASSES:
    techniques = ", ".join(rule_class.primary_techniques) or "—"
    print(f"{rule_class.rule_id:<10} {rule_class.title:<44} {techniques}")
    for technique_id in rule_class.primary_techniques:
        technique = mitre.get(technique_id)
        if technique:
            print(f"{'':10} · {technique.technique_id} {technique.name} "
                  f"[{technique.tactic}]")
```

* **`primary_techniques` объявлен на уровне класса** каждого правила:

  ```python
  class BruteForceRule(DetectionRule):
      rule_id = "AUTH-001"
      primary_techniques = ("T1110.001",)   # + T1078, если подбор удался
  ```

  Так справка строится из самого кода и не может разойтись с реальностью.
  Отдельный список правил в документации неизбежно устарел бы.
* **`f"{value:<10}"`** — выравнивание по левому краю в поле шириной 10. Даёт
  ровные колонки без ручных пробелов.
* **`f"{'':10}"`** — пустая строка, занимающая 10 позиций: отступ для
  подчинённых строк.
* **`or "—"`** — если у правила нет техник, вместо пустого места будет прочерк.

---

# Часть 3. Linux Incident Triage (Bash)

Структура: `triage.sh` — точка входа, `lib/common.sh` — утилиты,
`lib/collect.sh` — сбор, `lib/analyze.sh` — проверки.

## 3.1. `lib/common.sh` — базовые утилиты

### Определение цвета только для терминала

```bash
if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""
fi
```

* **`[[ -t 1 ]]`** — проверка «файловый дескриптор 1 (stdout) является
  терминалом». Если вывод перенаправлен в файл или в конвейер, escape-коды цвета
  превратились бы в мусор вида `^[[31m`. Обязательная проверка для любого
  скрипта, который что-то раскрашивает.
* **`$'\033[0m'`** — синтаксис `$'...'` в Bash интерпретирует escape-
  последовательности. В обычных кавычках `"\033"` осталось бы четырьмя
  символами.

### Функция логирования

```bash
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
```

* **`local`** — переменные видны только внутри функции. Без него любая
  переменная в Bash глобальна, и `message` в одной функции затрёт `message` в
  другой. Это одна из главных причин трудноуловимых ошибок в shell-скриптах.
* **Объявление и присваивание разделены** (`local stamp` отдельно от
  `stamp="$(...)"`). Причина: `local stamp="$(cmd)"` маскирует код возврата
  `cmd` — `local` всегда успешен, и `set -e` (если он включён) не заметит
  ошибку. Это рекомендация shellcheck (SC2155).
* **`printf`, а не `echo`.** `echo` по-разному ведёт себя в разных оболочках с
  флагами и escape-последовательностями; `printf` предсказуем. Кроме того,
  `echo "$var"` со значением `-n` выведет пустую строку.
* **`>&2`** — консольный вывод идёт в **stderr**. Логика: stdout скрипта — это
  результат (пути к файлам, сводка), stderr — диагностика. Так можно сделать
  `./triage.sh > results.txt` и по-прежнему видеть прогресс.
* **`${TRIAGE_LOG:-}`** — подстановка пустой строки, если переменная не задана.
  При `set -u` обращение к неустановленной переменной иначе прервало бы скрипт.
  Это позволяет использовать `_log` до того, как каталог результатов создан.
* **`%-7s`** — выравнивание уровня по левому краю в 7 позициях: `INFO   `,
  `WARN   `, `ERROR  `. Колонки в логе выстраиваются ровно.

### Безопасный запуск команды

```bash
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
```

Ключевые приёмы:

* **`shift 2`** — сдвигает позиционные параметры на два, после чего `"$@"`
  содержит только команду с её аргументами. Так функция принимает произвольную
  команду: `collect_cmd "02_who.txt" "Активные сессии" who -a`.
* **`"$@"` против `"$*"`.** `"$@"` разворачивается в **отдельные** слова с
  сохранением кавычек — именно так надо запускать команду. `"$*"` склеивает всё
  в одну строку — годится только для вывода в заголовок файла. Путаница между
  ними — одна из самых частых ошибок в Bash.
* **Группировка `{ ... } > "$target"`** — весь блок перенаправляется одним
  открытием файла, а не пятью. Заодно первое перенаправление `>` создаёт файл
  заново, а последующие `>>` дописывают.
* **`printf '=%.0s' {1..70}`** — трюк для повторения символа 70 раз. `%.0s`
  означает «вывести 0 символов аргумента», то есть аргументы просто отсчитывают
  итерации, а выводится литерал `=`. Компактнее цикла.
* **Отсутствие команды и её ошибка — разные ситуации**, и обе фиксируются в
  файле. Аналитик, читающий результат через неделю, должен понимать разницу
  между «данных нет» и «данные не собрали».
* **`exit_code=$?` сразу после команды.** `$?` меняется после любой следующей
  команды, поэтому сохранять надо немедленно.
* **`mktemp`** для stderr — гарантированно уникальное имя, без гонок.
* **`sed 's/^/[stderr] /'`** — префикс к каждой строке ошибки, чтобы её было
  видно в общем файле.

### Проверка доступности файлов

```bash
collect_file() {
    ...
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
        ...
    done
}
```

* **`-e` и `-r` проверяются отдельно.** «Файла нет» и «нет прав на чтение» —
  принципиально разные результаты для DFIR. Второе означает, что данные есть,
  но мы их не увидели, и отсутствие находок ничего не доказывает.
* **`stat -c`** записывает метаданные: владелец, права, время изменения.
  Для файла вроде `authorized_keys` время изменения — прямая улика.
* **`2>/dev/null`** у `stat` — на некоторых системах (BusyBox) нет флага `-c`,
  и сообщение об ошибке не должно попасть в артефакт.

### Экранирование JSON вручную

```bash
json_escape() {
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    text="${text//$'\n'/\\n}"
    text="${text//$'\r'/\\r}"
    text="${text//$'\t'/\\t}"
    printf '%s' "$text"
}
```

* **Порядок замен критичен.** Обратный слеш экранируется **первым**: если бы
  сначала обрабатывались кавычки, то добавленные слеши потом удвоились бы, и
  результат был бы неверным.
* **`${text//что/на_что}`** — замена всех вхождений средствами оболочки, без
  вызова `sed`. Быстрее и не зависит от внешних утилит.
* **`$'\n'`** — реальный символ перевода строки, а `\\n` в замене — два символа
  для JSON.
* Почему вручную, а не `jq`: скрипт не должен требовать установки внешних
  инструментов. На хосте, который расследуют, `jq` может не быть, а ставить
  что-либо во время реагирования нельзя.

### Формат JSON Lines для находок

```bash
add_finding() {
    local severity="$1" category="$2" title="$3" description="$4" evidence="${5:-}"
    printf '{"severity":"%s","category":"%s",...}\n' \
        "$(json_escape "$severity")" ... >> "$FINDINGS_FILE"
    ...
}
```

Находки копятся **построчно**, по одному JSON-объекту на строку, и лишь в конце
собираются в массив. Обоснование: дописать строку в файл — атомарная и надёжная
операция. Собирать JSON конкатенацией по ходу работы значит рисковать
испорченным файлом при любом сбое посередине.

* **`${5:-}`** — пятый аргумент необязателен: доказательство есть не у каждой
  находки.
* Обратный слеш в конце строки — продолжение команды на следующей строке.

### Ловушка `grep -c`

```bash
count_findings() {
    if [[ -s "$FINDINGS_FILE" ]]; then
        wc -l < "$FINDINGS_FILE" | tr -d ' \n'
    else
        printf '0'
    fi
}
```

Изначально было написано через цепочку `&&`/`||`, и это дало ошибку. Отдельно
стоит разобрать родственную ловушку, которая реально сломала скрипт:

```bash
COUNT="$(grep -c 'шаблон' "$FILE" || printf '0')"   # НЕВЕРНО
```

`grep -c` при нуле совпадений **уже печатает `0`** и при этом возвращает код 1.
Запасная ветка `|| printf '0'` добавляет **второй** ноль, переменная становится
`"0\n0"`, и следующее арифметическое сравнение падает с
`syntax error in expression`. Правильно:

```bash
COUNT="$(grep -c 'шаблон' "$FILE" 2>/dev/null)" || COUNT=0
```

Здесь `||` привязан к присваиванию целиком, а не к конвейеру внутри подстановки.

* **`[[ -s FILE ]]`** — файл существует и непустой.
* **`wc -l < FILE`** вместо `wc -l FILE` — перенаправление вместо аргумента,
  тогда `wc` не печатает имя файла, и не нужно его отрезать.
* **`tr -d ' \n'`** — `wc` на некоторых системах выравнивает число пробелами.

## 3.2. `lib/collect.sh` — сбор артефактов

### Порядок сбора: принцип убывающей летучести

Порядок функций в скрипте соответствует RFC 3227 (Order of Volatility):

```bash
collect_system_info    # 1. система
collect_users          # 2. кто в системе ПРЯМО СЕЙЧАС — самое летучее
collect_processes      # 3. процессы
collect_network        # 4. сетевые соединения
collect_services       # 5. службы
collect_cron           # 6. планировщик
collect_accounts       # 7. учётные записи
collect_ssh            # 8. ключи
collect_logs           # 9. журналы
collect_persistence    # 10. закрепление — самое устойчивое
```

**Почему это важно.** Если начать с медленного поиска SUID-файлов по всей
файловой системе (минуты работы), процесс атакующего может успеть завершиться,
и его не будет в списке. Сессии, процессы и соединения исчезают при первом
изменении состояния системы; файлы на диске никуда не денутся.

### Соответствие процесса исполняемому файлу

```bash
for pid in $(ls -1 /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n); do
    [[ -e "/proc/${pid}/exe" ]] || continue
    owner="$(stat -c '%U' "/proc/${pid}" 2>/dev/null || printf '?')"
    exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || printf 'недоступно')"
    printf '%-8s %-14s %s\n' "$pid" "$owner" "$exe"
done
```

* **`grep -E '^[0-9]+$'`** — в `/proc` есть не только процессы, но и файлы
  вроде `cpuinfo`, `meminfo`. Фильтр оставляет только числовые имена (PID).
* **`sort -n`** — числовая сортировка, иначе PID 10 окажется перед PID 9.
* **`readlink /proc/PID/exe`** — символическая ссылка на исполняемый файл
  процесса. **Ключевой артефакт**: если бинарник удалён с диска при работающем
  процессе, ссылка ведёт в `/path/to/file (deleted)`. Это классический приём
  сокрытия — файла нет, антивирус его не найдёт, а код исполняется.
* **`[[ -e ... ]] || continue`** — короткая форма «если условие ложно, перейти к
  следующей итерации». Процесс мог завершиться между `ls` и `readlink`.
* **`|| printf '?'`** — процесс может принадлежать другому пользователю, и
  `stat` вернёт ошибку; сбор не должен из-за этого останавливаться.

### Поддержка `ss` и `netstat`

```bash
if have_cmd ss; then
    collect_cmd "04_listening.txt" "Слушающие сокеты" ss -tulpn
    collect_cmd "04_connections.txt" "Активные соединения" ss -tupn
elif have_cmd netstat; then
    collect_cmd "04_listening.txt" "Слушающие сокеты (netstat)" netstat -tulpn
    ...
else
    log_warn "Ни ss, ни netstat не найдены — сетевые артефакты не собраны"
fi
```

* `ss` пришёл на смену `netstat`, но на старых системах есть только второй, а в
  минимальных контейнерах может не быть ни одного. Поддерживаются все три
  случая, и последний — с явным предупреждением, а не молчаливым пропуском.
* Флаги `-tulpn`: `t` TCP, `u` UDP, `l` только слушающие, `p` процессы,
  `n` не разрешать имена. **`n` важен для DFIR**: разрешение имён породило бы
  DNS-запросы с исследуемого хоста, что и медленно, и оставляет следы, и может
  предупредить атакующего.

### Метаданные `/etc/shadow` без хешей

```bash
if is_root && [[ -r /etc/shadow ]]; then
    {
        printf '# Метаданные /etc/shadow (БЕЗ хешей паролей)\n'
        ...
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
fi
```

* **Хеши намеренно не выгружаются.** Их копирование создало бы новый носитель
  секретов, а для триажа они не нужны: важно, у кого пустой пароль и когда
  пароль менялся.
* **`while IFS=: read -r ...`** — разбор строки по двоеточию. `IFS=:` задаёт
  разделитель только для этой команды. `-r` отключает интерпретацию обратных
  слешей — обязателен всегда, кроме случаев, когда экранирование нужно осознанно.
* **`_` для ненужных полей** — соглашение «значение отбрасывается».
* **`case "$hash" in "!"*|"*")`** — сопоставление с образцом. `"!"*` означает
  «начинается с восклицательного знака» (так помечается заблокированная
  запись), `"*"` — ровно звёздочка (тоже блокировка). Вертикальная черта —
  «или».
* **`awk -F: -v a="$account"`** — передача переменной оболочки в awk через
  `-v`. Прямая подстановка `"$account"` в текст программы awk была бы
  уязвимостью: имя с кавычками сломало бы программу.
* **`${changed:-н/д}`** — подстановка на случай пустого результата.

### Обход домашних каталогов

```bash
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
    done
done < /etc/passwd
```

* Каталоги берутся из `/etc/passwd`, а не из `ls /home`: домашний каталог может
  быть где угодно, а системные учётные записи (`/root`, `/var/www`) в `/home` не
  лежат.
* Проверяется и `authorized_keys`, и `authorized_keys2` — устаревший, но всё
  ещё работающий вариант, про который забывают.
* **Время изменения файла ключей — прямая улика.** Ключ, добавленный вчера,
  когда никаких работ не велось, требует объяснения.

### Поиск SUID-файлов

```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    -printf '%M %u:%g %10s %p\n' 2>/dev/null | sort -k4
```

* **`-xdev`** — не выходить за пределы текущей файловой системы. Без него
  `find` уйдёт в сетевые монтирования и `/proc`, что может занять часы.
* **`\( ... -o ... \)`** — группировка условий с «или». Круглые скобки
  экранированы, потому что для оболочки они имеют своё значение.
* **`-perm -4000`** — SUID-бит. Знак минус означает «содержит эти биты»
  (а не «равно ровно этому значению»).
* **`-printf '%M %u:%g %10s %p\n'`** — формат вывода: права, владелец:группа,
  размер в 10 позициях, путь. Собственный формат `find` вместо конвейера с
  `ls -l` — на порядок быстрее, потому что не запускает процесс на каждый файл.
* **`2>/dev/null`** — ошибки «нет доступа» при обходе каталогов ожидаемы и не
  должны засорять артефакт.
* **`sort -k4`** — сортировка по четвёртому полю (путь), чтобы результат было
  удобно сравнивать с эталонным хостом.

## 3.3. `lib/analyze.sh` — проверки

### Подменяемые пути ради тестируемости

```bash
PASSWD_FILE="${PASSWD_FILE:-/etc/passwd}"
SHADOW_FILE="${SHADOW_FILE:-/etc/shadow}"
LD_PRELOAD_FILE="${LD_PRELOAD_FILE:-/etc/ld.so.preload}"
```

**Как тестировать скрипт реагирования, не имея заражённой машины.** Проверки
читают системные файлы через переменные, а не по жёстко зашитым путям. В тестах
подставляется каталог с заготовленными «уликами», и каждая проверка прогоняется
на воспроизводимых данных.

Это изменение было внесено специально ради тестов — и оно же сделало код чище:
зависимости модуля стали явными.

### Проверка UID 0

```bash
while IFS=: read -r account _ uid _ _ _ _; do
    [[ "$uid" == "0" ]] || continue
    if [[ "$account" == "root" ]]; then
        continue
    fi
    add_finding "critical" "accounts" \
        "Учётная запись «${account}» имеет UID 0" \
        "Любая запись с UID 0 обладает полными правами root независимо от имени…" \
        "$(grep "^${account}:" "$PASSWD_FILE" 2>/dev/null | head -1)"
done < "$PASSWD_FILE"
```

* **UID, а не имя** — определяющий признак. Учётная запись `svc-backup` с UID 0
  обладает полными правами root, и это незаметнее, чем изменение пароля root.
* **`root` исключается явно** — это легитимная запись с UID 0.
* **Доказательство** — конкретная строка из `/etc/passwd`, а не «обнаружена
  подозрительная запись». Находку без доказательства невозможно проверить.
* `head -1` — на случай дублирующихся записей.

### Служебная запись с интерактивной оболочкой

```bash
if [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] && \
   [[ "$shell" =~ (bash|sh|zsh|ksh|fish)$ ]]; then
    add_finding "medium" "accounts" \
        "Служебная запись «${account}» имеет интерактивную оболочку" ...
fi
```

* **UID < 1000** — по соглашению это системные и служебные учётные записи;
  обычные пользователи получают UID от 1000.
* **`-ne 0`** — root исключается: у него оболочка должна быть.
* **`=~ (bash|sh|zsh|ksh|fish)$`** — сравнение с регулярным выражением, доступно
  только в `[[ ]]`. Привязка `$` к концу строки важна: без неё `/usr/sbin/nologin`
  тоже совпал бы (в нём есть `log`... нет, но `/bin/false` и подобные пути
  требуют аккуратности, а `$` гарантирует, что оболочка именно такая).
* Смысл находки: службам оболочка не нужна, её наличие означает возможность
  войти в систему под этой записью.

### Поиск подозрительных портов

```bash
SUSPICIOUS_PORTS="1080 1337 2222 3127 3128 4444 4445 5555 6666 6667 7777 8888 9001 9050 9999 12345 31337 54321"

for port in $SUSPICIOUS_PORTS; do
    line="$(grep -E "[:.]${port}[[:space:]]" "$listing" 2>/dev/null | grep -i listen | head -1)"
    if [[ -n "$line" ]]; then
        add_finding "high" "network" "Служба слушает нетипичный порт ${port}" ...
    fi
done
```

* **`[:.]${port}[[:space:]]`** — порт должен идти после `:` или `.` (разные
  форматы вывода) и заканчиваться пробелом. Без привязки поиск `4444` совпал бы
  с портом `14444` или с частью IP-адреса.
* **`[[:space:]]`** — POSIX-класс символов, работает во всех реализациях grep
  (в отличие от `\s`, которое есть не везде).
* **Два `grep` в конвейере** вместо одного сложного выражения: сначала порт,
  потом состояние LISTEN. Читается проще, а скорость на файле из сотни строк не
  важна.
* **`$SUSPICIOUS_PORTS` без кавычек в `for`** — здесь это намеренно: нужно
  разбиение по пробелам, чтобы получить отдельные элементы.
* Список портов — **не признак вредоносности**, а повод посмотреть, какой
  процесс их занял. Это подчёркнуто в тексте находки.

### Поиск «скачать и выполнить» в cron

```bash
local patterns='curl .*\|.*(ba)?sh|wget .*\|.*(ba)?sh|base64 -d|base64 --decode|python -c|perl -e|nc -|/dev/tcp/|eval '
hits="$(grep -inE "$patterns" "$cronfile" 2>/dev/null | grep -v '^\s*#' | head -5)"
```

* Ищутся не «плохие слова», а **конструкции, которых не бывает в обслуживающем
  задании**: скачать и сразу передать в оболочку, декодировать base64, открыть
  обратное соединение через `/dev/tcp/`.
* **`\|`** внутри шаблона — экранированная вертикальная черта, то есть литерал
  `|` (конвейер в команде), а не «или» регулярного выражения. Неэкранированные
  `|` между альтернативами работают как «или» благодаря `-E`.
* **`-i`** — регистронезависимо, **`-n`** — с номерами строк (номер попадает в
  доказательство).
* **`grep -v '^\s*#'`** — отбросить закомментированные строки: это не активные
  задания.
* **`head -5`** — доказательство ограничено, чтобы находка не раздулась.

### Успешный вход с адреса, с которого шёл перебор

```bash
suspicious_ips="$(grep -iE 'Failed password' "$authlog" 2>/dev/null \
    | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' \
    | sort -u)"
for ip in $suspicious_ips; do
    if grep -qE "Accepted (password|publickey|keyboard-interactive) .* from ${ip}( |$)" \
        "$authlog" 2>/dev/null; then
        add_finding "critical" "authentication" \
            "Успешный вход с адреса ${ip}, с которого шёл перебор" ...
    fi
done
```

Это самая ценная проверка скрипта — тот же принцип, что в правиле AUTH-005
Log Analyzer, но реализованный средствами оболочки.

* **`grep -oE`** — вывести только совпавшую часть, а не всю строку.
* **`awk '{print $2}'`** — из `from 192.0.2.66` взять второе слово.
* **`sort -u`** — уникальные адреса; иначе проверка выполнялась бы сотни раз для
  одного адреса.
* **`grep -q`** — «тихий» режим: не печатать, только вернуть код. Останавливается
  на первом совпадении, то есть быстрее полного прохода.
* **`from ${ip}( |$)`** — привязка: адрес должен заканчиваться пробелом или
  концом строки. Без неё `192.0.2.6` совпало бы внутри `192.0.2.66`.

### `/etc/ld.so.preload`

```bash
if [[ -f "$LD_PRELOAD_FILE" ]]; then
    add_finding "critical" "persistence" \
        "Обнаружен файл /etc/ld.so.preload" \
        "Библиотеки из этого файла подгружаются в КАЖДЫЙ запускаемый процесс…" \
        "$(cat "$LD_PRELOAD_FILE" 2>/dev/null | tr '\n' ' ')"
fi
```

**Самая недооценённая проверка.** Библиотека, указанная в этом файле,
загружается в каждый запускаемый процесс и может подменять системные вызовы —
скрывать файлы, процессы и сетевые соединения от штатных утилит. Это руткит
пользовательского уровня.

Критичность максимальная, потому что **на штатно настроенной системе этого файла
просто нет**. Само его наличие — аномалия, а не эвристика.

`tr '\n' ' '` — превратить многострочное содержимое в одну строку для поля
доказательства в JSON.

## 3.4. `triage.sh` — точка входа

### Определение каталога скрипта

```bash
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
```

Идиома для получения абсолютного пути к каталогу скрипта. Разбор:

* **`${BASH_SOURCE[0]}`** — путь к текущему файлу. Надёжнее `$0`: при
  подключении через `source` `$0` содержит имя вызывающей оболочки.
* **`dirname`** — отбросить имя файла, оставить каталог.
* **`cd ... && pwd`** — превратить относительный путь в абсолютный.
* **`--`** — конец опций. Защита от пути, начинающегося с дефиса: без этого
  `dirname -foo` был бы воспринят как флаг.

Зачем: скрипт подключает библиотеки из `lib/` и должен находить их независимо от
того, из какого каталога его запустили.

### Разбор аргументов

```bash
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
```

* **`while [[ $# -gt 0 ]]`** — пока есть необработанные аргументы. `$#` — их
  количество, `shift` уменьшает.
* **`-o|--output`** — короткая и длинная форма в одной ветви `case`.
* **`[[ $# -ge 2 ]] ||`** — проверка, что после флага есть значение. Без неё
  `./triage.sh -o` привёл бы к обращению к `$2`, которого нет, и при `set -u`
  скрипт упал бы с невнятной ошибкой вместо понятного сообщения. На это есть
  тест.
* **`{ ...; exit 3; }`** — группировка команд. Точка с запятой перед закрывающей
  скобкой обязательна.
* **`*)`** — ветвь по умолчанию: неизвестный флаг даёт справку в stderr и код 3.
  Молча игнорировать неизвестный флаг нельзя: пользователь будет думать, что
  он подействовал.

### Подключение библиотек с проверкой

```bash
for library in common.sh collect.sh analyze.sh; do
    if [[ ! -r "${SCRIPT_DIR}/lib/${library}" ]]; then
        printf 'Ошибка: не найдена библиотека lib/%s рядом со скриптом.\n' "$library" >&2
        exit 3
    fi
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/lib/${library}"
done
```

* Проверка перед подключением даёт понятное сообщение вместо `command not found`
  при первом вызове функции. **Именно это сообщение и обнаружило проблему с
  `.gitignore`**, когда каталог `lib/` не попал в репозиторий.
* **`# shellcheck source=/dev/null`** — указание линтеру не пытаться
  анализировать подключаемый файл (путь вычисляется в рантайме, статически
  его не разрешить).

### Имя каталога результатов

```bash
HOSTNAME_SAFE="$(hostname 2>/dev/null | tr -cd '[:alnum:]._-' || printf 'unknown')"
TIMESTAMP="$(date -u '+%Y%m%d_%H%M%SZ')"
OUTPUT_DIR="${OUTPUT_BASE%/}/triage_${HOSTNAME_SAFE}_${TIMESTAMP}"
```

* **`tr -cd '[:alnum:]._-'`** — удалить (`-d`) все символы, **кроме** (`-c`,
  дополнение набора) буквенно-цифровых, точки, подчёркивания и дефиса. Имя
  хоста может содержать что угодно, а оно попадает в путь файловой системы.
  Это защита от инъекции пути.
* **`date -u`** — время в UTC. Артефакты с разных хостов в разных зонах должны
  сравниваться напрямую, а `Z` в конце имени фиксирует это явно.
* **`${OUTPUT_BASE%/}`** — снять хвостовой слеш, чтобы не получить `//` в пути.

### Проверки каталога результатов

```bash
if [[ ! -d "$OUTPUT_BASE" ]]; then
    printf 'Ошибка: каталог %s не существует.\n' "$OUTPUT_BASE" >&2
    exit 3
fi
if [[ ! -w "$OUTPUT_BASE" ]]; then
    printf 'Ошибка: нет прав на запись в %s.\n' "$OUTPUT_BASE" >&2
    exit 3
fi
if ! mkdir -p "$OUTPUT_DIR"; then
    ...
fi
```

Три отдельные проверки с разными сообщениями. Проверяются **до** начала сбора:
обнаружить отсутствие прав на запись после десяти минут сбора артефактов — это
потерять всю работу.

### Сборка JSON-массива из JSON Lines

```bash
printf '  "findings": [\n'
if [[ -s "$FINDINGS_FILE" ]]; then
    sed -e 's/$/,/' -e '$ s/,$//' "$FINDINGS_FILE" | sed 's/^/    /'
fi
printf '  ]\n'
```

Изящный приём преобразования построчного формата в массив:

* **`s/$/,/`** — добавить запятую в конец каждой строки;
* **`$ s/,$//`** — у **последней** строки (адрес `$` в sed означает последнюю
  строку) убрать добавленную запятую. Именно это делает JSON валидным: в массиве
  после последнего элемента запятой быть не должно;
* **`sed 's/^/    /'`** — отступ для читаемости.

Валидность результата проверяется тестом:
`python3 -c "import json; json.load(open('findings.json'))"`.

### Контрольные суммы

```bash
if have_cmd sha256sum; then
    ( cd "$OUTPUT_DIR" && sha256sum ./* > MANIFEST.sha256 2>/dev/null )
fi
```

* **Зачем.** Первый вопрос к материалам расследования — «не менялись ли они
  после сбора». Без контрольных сумм на него нечего ответить.
* **Круглые скобки** создают подоболочку: `cd` внутри не меняет текущий каталог
  основного скрипта. Альтернатива — запоминать и восстанавливать путь вручную.
* **`./*`** вместо `*` — защита от файла с именем, начинающимся на дефис:
  `sha256sum -foo` был бы воспринят как флаг.

### Коды возврата

```bash
if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
    exit 2
elif [[ "$FINDING_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
```

Порядок проверок задаёт приоритет: критические находки важнее просто находок.
Скрипт годится для пайплайна:
`./triage.sh -o /mnt/usb || echo "требуется внимание"`.

---

# Часть 4. SOC Automation Toolkit

## 4.1. `bootstrap.py` — подключение соседних проектов

```python
PROJECTS_DIR = Path(__file__).resolve().parent.parent.parent

MODULE_PATHS: dict[str, Path] = {
    "ioc_analyzer": PROJECTS_DIR / "ioc-analyzer",
    "log_analyzer": PROJECTS_DIR / "log-analyzer",
}
TRIAGE_SCRIPT = PROJECTS_DIR / "linux-triage" / "triage.sh"
```

* **`Path(__file__).resolve()`** — абсолютный путь к текущему файлу с
  разрешением символических ссылок. Без `resolve()` относительный путь зависел
  бы от текущего каталога запуска.
* **Три `.parent`** поднимаются от
  `projects/soc-toolkit/soc_toolkit/bootstrap.py` до `projects/`. Цепочка
  хрупкая по своей природе, поэтому она собрана в одном месте, а не разбросана
  по импортам.
* **Оператор `/` для `Path`** — конкатенация путей, работающая одинаково на
  Windows и Unix. Ручная склейка через `+ "/"` сломалась бы на Windows.

### Понятная ошибка вместо `ImportError`

```python
def require(module_name: str):
    register_paths()
    try:
        return __import__(module_name)
    except ImportError as exc:
        expected = MODULE_PATHS.get(module_name, "неизвестно")
        raise ModuleNotAvailable(
            f"Модуль «{module_name}» недоступен: {exc}. "
            f"Ожидался каталог: {expected}. "
            "Проверьте, что репозиторий склонирован целиком и что установлены "
            "зависимости этого модуля (pip install -r requirements.txt)."
        ) from exc
```

`ImportError: No module named 'ioc_analyzer'` не говорит пользователю, что
делать. Своё исключение сообщает, где именно ожидался модуль и какие две
причины наиболее вероятны.

`__import__` вместо `import` — потому что имя модуля известно только в рантайме.

### Честность про компромисс

Докстринг модуля прямо говорит: промышленный путь — оформить каждый проект как
устанавливаемый пакет (`pyproject.toml`) и объявить зависимостями. Здесь выбран
более простой вариант ради запуска без установки, и ограничение названо: при
переносе оболочки отдельно от репозитория импорт сломается.

**Почему это важно.** На собеседовании такой компромисс лучше назвать самому,
чем ждать вопроса. Инженер, который видит границы своего решения, вызывает
больше доверия, чем тот, кто их не замечает.

## 4.2. `models.py` — единая модель находки

### `Finding` — общий знаменатель трёх инструментов

```python
@dataclass
class Finding:
    source: Source
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    entities: dict[str, Any] = field(default_factory=dict)
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    evidence: str = ""
    recommendation: str = ""
    ...
```

Три инструмента отвечали на разные вопросы: вердикт с risk score, находка
правила с severity и техниками, признак компрометации хоста. Общий знаменатель —
**что нашли, насколько серьёзно, к каким сущностям относится, что делать**.

**`mitre_techniques: list[dict[str, str]]`**, а не список объектов
`MitreTechnique`. Обоснование: оболочка не должна импортировать модель из
Log Analyzer — иначе появилась бы жёсткая зависимость от его внутренней
структуры. Простые словари развязывают проекты.

### Стабильный идентификатор находки

```python
@property
def finding_id(self) -> str:
    seed = f"{self.source.value}:{self.rule_id}:{self.title}:{sorted(self.entity_values())}"
    return f"F-{hashlib.sha1(seed.encode('utf-8')).hexdigest()[:10]}"
```

* Идентификатор — **хеш от содержания**, а не счётчик и не случайное значение.
  Следствие: одна и та же находка получает один и тот же id между прогонами,
  и отчёты можно сравнивать, отслеживая динамику.
* **`sorted(...)`** внутри seed — множества и словари не гарантируют порядок, и
  без сортировки id менялся бы от запуска к запуску при тех же данных.
* `@property`, а не поле: значение всегда согласовано с содержимым и не может
  «отстать» после изменения полей.

Есть тесты `test_finding_id_is_stable` и
`test_finding_id_differs_for_different_entities`.

### Извлечение значений сущностей

```python
def entity_values(self) -> list[str]:
    values: list[str] = []
    for value in self.entities.values():
        if isinstance(value, (list, tuple, set)):
            values.extend(str(item) for item in value if item)
        elif value:
            values.append(str(value))
    return values
```

Сущность может быть одиночным значением (`ip="192.0.2.66"`) или коллекцией
(`ip=["192.0.2.1", "192.0.2.2"]`) — инструменты дают и то, и другое. Функция
приводит всё к плоскому списку строк, на котором работает корреляция.

`if item` внутри включения отбрасывает пустые и `None`.

## 4.3. `adapters/ioc.py` — перевод вердиктов

### Таблица соответствия

```python
VERDICT_TO_SEVERITY: dict[str, Severity] = {
    "malicious": Severity.HIGH,
    "suspicious": Severity.MEDIUM,
    "unknown": Severity.LOW,
    "error": Severity.LOW,
    "clean": Severity.INFO,
    "skipped": Severity.INFO,
}
```

**Явная таблица, а не формула.** Смысл вердикта важнее арифметики.

Два решения, которые стоит защищать на собеседовании:

* **`"error": Severity.LOW`, а не `INFO`.** Индикатор, который не удалось
  проверить, должен остаться на виду у аналитика. Если бы он попадал в `INFO`,
  то отсеивался бы фильтром `--min-severity` и исчезал из отчёта. «Не проверили»
  не равно «безопасно».
* **`"unknown": Severity.LOW`.** VirusTotal не знает индикатор — для
  свежесозданной инфраструктуры это ожидаемо и само по себе слегка
  подозрительно.

На полноту таблицы есть тест:

```python
def test_every_verdict_has_a_severity():
    from ioc_analyzer.models import Verdict
    for verdict in Verdict:
        assert verdict.value in VERDICT_TO_SEVERITY
```

Он перебирает **все** вердикты исходного модуля. Если там появится новый, тест
упадёт, а не позволит вердикту молча провалиться в `INFO`. Это типичная ошибка
интеграции: добавили значение в одном проекте, забыли в другом.

### Уточнение критичности по risk score

```python
severity = VERDICT_TO_SEVERITY.get(verdict, Severity.INFO)
if verdict == "malicious" and result.risk_score >= 85:
    severity = Severity.CRITICAL
```

Вердикт задаёт базовый уровень, risk score уточняет позицию внутри него:
60 детектов из 70 серьёзнее, чем 4 из 70, хотя вердикт у обоих `malicious`.

### Приведение имён сущностей

```python
TYPE_TO_ENTITY: dict[str, str] = {
    "ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url",
    "md5": "hash", "sha1": "hash", "sha256": "hash",
}
...
entity_key = TYPE_TO_ENTITY.get(ioc.type.value, "indicator")
```

`ipv4` и `ipv6` оба становятся `ip`, три типа хешей — `hash`. Без этого
приведения находка про IPv4-адрес не связалась бы с находкой Log Analyzer,
который называет то же поле просто `ip`.

### Чего адаптер намеренно НЕ делает

Он **не выдумывает техники MITRE ATT&CK для индикаторов**. Вредоносный хеш сам
по себе не соответствует никакой технике: техника описывает **поведение**, а не
артефакт. Приписать такому индикатору, скажем, T1071 (Application Layer
Protocol) было бы догадкой, выдаваемой за факт.

Техники в отчёт приходят из Log Analyzer, где выведены из наблюдаемого
поведения. Это записано в докстринге модуля.

### Перевод исключений модуля

```python
from ioc_analyzer.parsers.reader import InputError

try:
    run = IOCAnalyzer(settings, provider=provider).analyze_file(...)
except InputError as exc:
    raise AdapterError(f"Входные данные IOC Analyzer: {exc}") from exc
finally:
    if provider is not None:
        provider.close()
```

**Это исправление, найденное тестом.** Режим `run` (несколько модулей за проход)
ловил только `AdapterError` и `ModuleNotAvailable`. Исключение `InputError` из
IOC Analyzer прорастало сквозь оболочку и роняло весь прогон — в том числе
результаты модулей, которые уже успели отработать.

Задача адаптера — быть границей: наружу выходят только его собственные типы
исключений.

## 4.4. `adapters/triage.py` — интеграция Bash-инструмента

### Два режима работы

```python
@staticmethod
def can_execute() -> bool:
    return sys.platform != "win32" and TRIAGE_SCRIPT.is_file()
```

* **Запуск** (`run_script=True`) — вызвать `triage.sh` через `subprocess`.
  Требует Linux или WSL.
* **Импорт** (по умолчанию) — прочитать готовый `findings.json`.

Импорт — **основной** сценарий, а не запасной: триаж запускается на исследуемом
хосте, а разбор результатов ведётся в другом месте, часто на другой платформе.
Именно поэтому Bash-скрипт с самого начала пишет машиночитаемый отчёт.

### Вызов внешнего процесса

```python
completed = subprocess.run(
    ["bash", str(TRIAGE_SCRIPT), "-o", str(target), "--no-archive", "-q"],
    capture_output=True, text=True, timeout=timeout, check=False,
)
```

* **Список аргументов, а не строка.** `subprocess.run("bash script.sh")` с
  `shell=True` запустил бы оболочку и открыл возможность инъекции команд через
  имя файла. Список передаётся напрямую в `exec`, минуя оболочку.
* **`capture_output=True`** — перехватить stdout и stderr вместо смешивания с
  выводом оболочки.
* **`text=True`** — получить строки, а не байты.
* **`timeout`** — обязателен. Без него зависший скрипт заблокировал бы оболочку
  навсегда.
* **`check=False`** — **не** поднимать исключение при ненулевом коде. Здесь это
  принципиально: коды 1 и 2 означают «есть находки» и являются нормальным
  результатом, а не ошибкой.

```python
if completed.returncode == 3:
    raise AdapterError(
        f"Скрипт триажа завершился ошибкой запуска: {completed.stderr.strip()[:300]}"
    )
```

Только код 3 трактуется как сбой — в соответствии с контрактом скрипта.
`[:300]` ограничивает объём чужого вывода в сообщении об ошибке.

### Поиск свежего отчёта

```python
results = sorted(target.glob("triage_*/findings.json"),
                 key=lambda p: p.stat().st_mtime, reverse=True)
```

* **`glob` с шаблоном каталога** — имя каталога содержит метку времени и имя
  хоста, заранее неизвестно.
* Сортировка по времени изменения, `reverse=True` — самый свежий первым.
  Нужно, если в целевом каталоге лежат результаты нескольких прогонов.

### Извлечение сущностей из текста

```python
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)
_ACCOUNT_RE = re.compile(r"«([A-Za-z0-9._\-]{1,32})»")

def extract_entities(*texts: str) -> dict[str, list[str]]:
    joined = " ".join(text for text in texts if text)
    entities: dict[str, list[str]] = {}
    addresses = sorted({
        address for address in _IPV4_RE.findall(joined)
        if address not in {"0.0.0.0", "255.255.255.255"}
    })
    if addresses:
        entities["ip"] = addresses
    accounts = sorted(set(_ACCOUNT_RE.findall(joined)))
    if accounts:
        entities["username"] = accounts
    return entities
```

* **Регулярка IPv4 с проверкой диапазона.** Альтернативы
  `25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d` описывают числа 0–255, поэтому
  `999.1.1.1` не совпадёт. Порядок альтернатив от большего к меньшему
  обязателен: движок берёт первую подходящую, и при обратном порядке `250`
  распалось бы на `25` и `0`.
* **`\b`** — граница слова: адрес не должен быть частью более длинного числа.
* **`«([A-Za-z0-9._\-]{1,32})»`** — имя учётной записи извлекается из
  типографских кавычек, в которые его ставит Bash-скрипт. Ограничение длины
  защищает от захвата длинного текста.
* **`0.0.0.0` исключён** — в выводе `ss` он означает «все интерфейсы», а не
  конкретный узел. Связывать по нему находки означало бы склеить всё со всем.
* **`*texts: str`** — переменное число аргументов: функция принимает заголовок,
  доказательство и описание одним вызовом.

**Честно о компромиссе.** Правильнее было бы, чтобы Bash-скрипт сам заполнял
структурированное поле `entities`. Разбор текста работает, но зависит от
формулировок: изменится текст находки — сломается извлечение. Это записано и в
докстринге модуля, и в README как известное ограничение.

### Предупреждение о неполном сборе

```python
if as_root is False:
    description += (" ВНИМАНИЕ: сбор выполнялся без прав root, "
                    "часть артефактов недоступна, отсутствие других "
                    "находок ничего не доказывает.")
```

**`if as_root is False`**, а не `if not as_root`. Разница принципиальна: поле
может отсутствовать в отчёте, и тогда `as_root` будет `None`. При `not None`
условие сработало бы, и предупреждение добавилось бы к отчёту, про который мы
просто не знаем, как он собран. Проверка на точное `False` покрывает только
достоверно известный случай.

## 4.5. `correlation.py` — кросс-инструментальная корреляция

### Ключи корреляции

```python
CORRELATION_KEYS: tuple[str, ...] = ("ip", "domain", "url", "hash", "username", "hostname")

GENERIC_VALUES: frozenset[str] = frozenset({
    "-", "unknown", "неизвестный хост", "n/a", "none", "root@localhost",
})
```

`GENERIC_VALUES` — значения, которые встречаются почти в каждой находке и
связывают всё со всем, не несут информации.

### Группировка с исключением имени хоста

```python
def correlate(findings, min_group_size: int = 2,
              skip_keys: Sequence[str] = ("hostname",)) -> list[CorrelatedGroup]:
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)

    for finding in findings:
        for key_type in CORRELATION_KEYS:
            if key_type in skip_keys:
                continue
            value = finding.entities.get(key_type)
            if not value:
                continue
            values = value if isinstance(value, (list, tuple, set)) else [value]
            for item in values:
                text = str(item).strip()
                if not text or text.lower() in GENERIC_VALUES:
                    continue
                buckets[(key_type, text)].append(finding)
```

* **`skip_keys=("hostname",)` по умолчанию.** В рамках одного прогона имя хоста
  одинаково у **всех** находок триажа, и связывание по нему склеило бы их в одну
  бессмысленную группу. Параметр позволяет включить связывание, когда
  анализируются данные нескольких хостов. Есть тест
  `test_hostname_is_skipped_by_default`.
* Одна находка может попасть в несколько групп — по адресу и по учётной записи.
  Это правильно: она действительно связана с обеими сущностями.

### Дедупликация внутри группы

```python
unique: dict[str, Finding] = {f.finding_id: f for f in group_findings}
if len(unique) < min_group_size:
    continue
```

Одна находка могла попасть в группу дважды, если сущность указана и в
единственном поле (`ip`), и во множественном (`source_ips`). Словарь по
`finding_id` устраняет дубликаты — и здесь стабильный идентификатор оказывается
полезен ещё раз.

### Сортировка групп

```python
groups.sort(key=lambda g: (not g.is_cross_tool, -g.severity.score, g.key))
```

* **`not g.is_cross_tool`** — булево значение в ключе сортировки. `False`
  сортируется перед `True`, поэтому инверсия ставит кросс-инструментальные
  группы **первыми**. Это приём, который стоит знать: он избавляет от отдельного
  разделения списка на две части.
* Дальше по убыванию критичности, затем по значению ключа для стабильности.

### Эскалация при подтверждении

```python
def escalate_cross_tool(findings, groups) -> int:
    ladder = {
        Severity.INFO: Severity.LOW,
        Severity.LOW: Severity.MEDIUM,
        Severity.MEDIUM: Severity.HIGH,
    }
    escalated: set[str] = set()

    for group in groups:
        if not group.is_cross_tool:
            continue
        for finding in group.findings:
            new_severity = ladder.get(finding.severity)
            if new_severity and finding.finding_id not in escalated:
                finding.severity = new_severity
                finding.description += (
                    f" Находка подтверждена независимо несколькими "
                    f"инструментами набора ({', '.join(group.sources)})…"
                )
                escalated.add(finding.finding_id)
    return len(escalated)
```

* **`ladder` как словарь переходов** — компактнее цепочки `if/elif`. Ключ
  `HIGH` в словаре отсутствует, поэтому `ladder.get(Severity.HIGH)` вернёт
  `None`, и повышения не будет. **Ограничение до HIGH встроено в структуру
  данных**, а не в дополнительное условие: `CRITICAL` не должен обесцениваться.
* **`escalated: set`** — находка, попавшая в две подтверждённые группы (по
  адресу и по учётной записи), повышается **один раз**. Без этого множества она
  выросла бы на два уровня. Есть тест `test_finding_is_escalated_once`.
* **Описание дополняется объяснением.** Аналитик, увидев `HIGH` вместо
  `MEDIUM`, должен понимать причину.
* Функция возвращает **число** повышенных находок — попадает в метаданные
  отчёта.

**Обоснование самой идеи.** Независимое подтверждение — сильнейший из доступных
сигналов. Адрес, который одновременно числится вредоносным в Threat Intelligence
и фигурирует в логах как источник перебора, — это уже не гипотеза.

## 4.6. `cli.py` оболочки — изоляция сбоя модуля

```python
def _collect(label: str, sources: list[str], action) -> None:
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
```

* **Замыкание.** Функция определена внутри `_run_all` и пользуется его
  переменными `findings`, `errors`, `used`, `inputs`. Это позволяет вызвать её
  три раза, не передавая четыре списка каждый раз.
* **`action` — функция без аргументов** (передаётся как `lambda`). Так вызов
  модуля откладывается до момента внутри `try`, а не выполняется при подготовке
  аргументов.
* **Два блока `except`.** Первый — известные ошибки адаптера, второй — любые
  прочие: модули разрабатывались независимо, и оболочка не может знать полный
  перечень их исключений. Получить часть картины лучше, чем не получить ничего.
* **`used.append` только после успеха** — в метаданных отчёта окажутся лишь
  реально отработавшие модули.

Первая версия этой логики была написана с проверками вида
`if not any(e.startswith(label) for e in errors)` — работало, но читалось
плохо. Переписано на явный ранний `return`.

### Код возврата при частичном сбое

```python
code = _finalize(findings, settings, args, {...})
return max(code, EXIT_FINDINGS) if errors and code == EXIT_OK else code
```

Прогон, в котором один модуль упал, а остальные не нашли ничего, **не должен**
возвращать 0. Иначе неполный результат выглядел бы как чистый — самый опасный
вид ошибки. Есть тест `test_run_survives_a_failing_module`.

### Общий финал всех команд

```python
def _finalize(findings, settings, args, metadata) -> int:
    if not findings:
        print("Находок нет.")
        return EXIT_OK

    groups = correlate(findings)
    escalated = 0
    if settings.escalate_cross_tool:
        escalated = escalate_cross_tool(findings, groups)
        if escalated:
            groups = correlate(findings)
    ...
```

* Все четыре команды (`ioc`, `logs`, `triage`, `run`) заканчиваются одной
  функцией: корреляция, эскалация, отчёты, код возврата. Логика не дублируется
  четыре раза.
* **Повторный `correlate` после эскалации** — критичность изменилась, и группы
  надо пересобрать, чтобы сортировка и сводка отражали новое состояние.
  Без этого отчёт содержал бы устаревшие значения в блоке корреляций.

## 2.14. `reporting/writers.py` Log Analyzer

Отличия от писателя IOC Analyzer — в агрегации по ATT&CK и в связи находок с
инцидентами.

```python
techniques = Counter(
    technique.technique_id for d in detections for technique in d.mitre
)
tactics = Counter(
    tactic.strip()
    for d in detections for technique in d.mitre
    for tactic in technique.tactic.split(",")
)
```

* **`Counter`** из `collections` — подсчёт вхождений одной строкой. `Counter`
  умеет `most_common()`, что даёт отсортированный по частоте список.
* **Тройное включение для тактик** — техника может относиться к нескольким
  тактикам, они записаны через запятую (`"Defense Evasion, Persistence"`).
  Внешний цикл по находкам, средний по техникам, внутренний по тактикам после
  разбиения. `strip()` убирает пробелы после запятой.

```python
incident_of: dict[int, str] = {}
for incident in incidents:
    for detection in incident.detections:
        incident_of[id(detection)] = incident.incident_id
```

**`id(detection)`** — встроенная функция, возвращающая уникальный
идентификатор объекта в памяти. Использована потому, что `Detection` —
изменяемый датакласс без `__hash__`, и его нельзя положить в словарь ключом.
Обратное отображение «находка → инцидент» нужно, чтобы в плоском CSV сохранилась
информация о группировке.

Приём работает, потому что объекты живут в памяти всё время формирования отчёта.
Для долговременного хранения он не годится — и это именно тот случай, когда
`id()` уместен.

### Консольная сводка с деревом инцидентов

```python
for incident in incidents[:limit]:
    lines.append(f"  [{incident.severity.value.upper():<8}] {incident.incident_id}  "
                 f"{incident.title}")
    for detection in incident.detections:
        techniques = ",".join(t.technique_id for t in detection.mitre)
        lines.append(f"      └─ {detection.rule_id} {detection.title[:56]:<56} {techniques}")
```

Символ `└─` рисует дерево: инцидент и подчинённые ему находки. Аналитик видит
цепочку атаки одним взглядом, а не читает плоский список.

`detection.title[:56]:<56` — сначала обрезка до 56 символов, потом выравнивание
до той же ширины. Так колонка с техниками не съезжает независимо от длины
заголовка.

---

## 4.7. `adapters/base.py` и `adapters/logs.py`

### Базовый адаптер

```python
class ToolAdapter(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    def run(self, **kwargs: Any) -> Sequence[Finding]:
        """Запустить инструмент и вернуть находки в общем формате."""

    @staticmethod
    def is_available() -> bool:
        return True
```

**`**kwargs: Any` в абстрактном методе** — у трёх адаптеров разные параметры
(файл индикаторов, список логов, путь к отчёту). Жёсткая сигнатура заставила бы
придумывать общий набор аргументов, которого не существует. Каждый адаптер
объявляет свои параметры явно, а `**kwargs` в базе фиксирует только сам факт
наличия метода.

`is_available` — не абстрактный, с разумным значением по умолчанию: адаптер,
которому нечего проверять, не обязан писать заглушку.

### Адаптер логов: приведение имён полей

```python
if source_entities.get("source_ip"):
    entities["ip"] = source_entities["source_ip"]
elif source_entities.get("source_ips"):
    entities["ip"] = list(source_entities["source_ips"])
if source_entities.get("username"):
    entities["username"] = source_entities["username"]
elif source_entities.get("usernames"):
    entities["username"] = list(source_entities["usernames"])
```

Log Analyzer хранит адрес в `entities["source_ip"]`, IOC Analyzer — в
`entities["ip"]`. Пока имена расходятся, корреляция между инструментами
**невозможна**. Приведение к общему словарю и есть цена объединения.

`elif` для множественной формы: правило заполняет либо единственное поле, либо
множественное, но не оба.

```python
mitre_techniques=[
    {"technique_id": technique.technique_id,
     "name": technique.name,
     "tactic": technique.tactic}
    for technique in detection.mitre
],
```

Объекты `MitreTechnique` преобразуются в простые словари. Обоснование: оболочка
не должна зависеть от внутренней модели Log Analyzer — иначе изменение там
сломало бы её. Поле `rationale` намеренно не переносится: в сводном отчёте оно
избыточно, а полное обоснование доступно в отчёте самого Log Analyzer.

### Переопределение настроек модуля

```python
import dataclasses
...
overrides: dict[str, Any] = {}
if year:
    overrides["default_year"] = year
if timezone:
    overrides["timezone"] = timezone
if overrides:
    settings = dataclasses.replace(settings, **overrides)
    settings.validate()
```

Оболочка передаёт свои флаги (`--year`, `--timezone`) в конфигурацию модуля тем
же механизмом, которым модуль обрабатывает собственные флаги CLI. Повторная
`validate()` обязательна: некорректный часовой пояс должен быть отвергнут.

## 4.8. Отчёты и конфигурация оболочки

### Почему у оболочки свой `.env`

```python
@dataclass(frozen=True)
class Settings:
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    log_level: str = "INFO"
    ...
    escalate_cross_tool: bool = True
```

Здесь только параметры **самой оболочки**. Ключ VirusTotal остаётся в
`projects/ioc-analyzer/.env`, пороги детектирования — в
`projects/log-analyzer/.env`.

**Обоснование.** Заставить модули читать общий конфиг означало бы сломать их
автономность, а она нужна: каждый инструмент должен оставаться пригодным к
самостоятельному использованию. Оболочка — потребитель модулей, а не их
владелец.

### Сводка с блоком кросс-подтверждений

```python
cross_tool = [g for g in groups if g.is_cross_tool]
if cross_tool:
    lines.append("  ПОДТВЕРЖДЕНО НЕСКОЛЬКИМИ ИНСТРУМЕНТАМИ "
                 "(наивысший приоритет разбора):")
    for group in cross_tool[:limit]:
        lines.append(f"  ▸ {group.key_type}={group.key}  "
                     f"[{group.severity.value.upper()}]  "
                     f"источники: {', '.join(group.sources)}")
        for finding in group.findings:
            lines.append(f"      └─ [{finding.source.value:<13}] {finding.title[:60]}")
```

Блок кросс-подтверждений идёт **выше** списка критичных находок. Это
приоритизация в чистом виде: находка, подтверждённая двумя независимыми
инструментами, требует внимания раньше, чем одиночная находка той же
критичности.

---

# Часть 4.9. Тесты: как устроены

## Разделение фикстур и конструкторов

```
tests/
├── conftest.py     фикстуры pytest (settings, finding_factory)
├── helpers.py      конструкторы событий (event, failures)
└── test_*.py
```

`conftest.py` **не предназначен для прямого импорта** — pytest подгружает его
сам, чтобы предоставить фикстуры. Попытка `from conftest import event` падает с
`ModuleNotFoundError`, что и произошло при первом запуске. Конструкторы вынесены
в `helpers.py`, который импортируется обычным образом:
`from tests.helpers import event, failures`.

## Фабрики тестовых данных

```python
def event(seconds: int = 0, outcome=EventOutcome.FAILURE, username="alice",
          source_ip="192.0.2.10", event_type="ssh_login",
          invalid_user=False, ...) -> AuthEvent:
    return AuthEvent(timestamp=BASE_TIME + timedelta(seconds=seconds), ...)

def failures(count: int, step: int = 10, start: int = 0, **kwargs) -> list[AuthEvent]:
    kwargs.setdefault("outcome", EventOutcome.FAILURE)
    return [event(seconds=start + index * step, **kwargs) for index in range(count)]
```

* **Все параметры со значениями по умолчанию.** Тест указывает только то, что
  для него существенно: `event(seconds=70, outcome=EventOutcome.SUCCESS)`.
  Остальное неважно и не засоряет тест.
* **`seconds` как смещение от `BASE_TIME`**, а не абсолютная дата. Тесты
  читаются как «через 70 секунд после начала», и не зависят от текущей даты.
* **`kwargs.setdefault`** — установить значение, только если его не передали.
  Позволяет `failures(5, outcome=EventOutcome.SUCCESS)` для нетипичного случая.

## Параметризация

```python
@pytest.mark.parametrize("value,expected", [
    ("192.0.2.1", IOCType.IPV4),
    ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5),
    ("xn----8sbzclmxk.xn--p1ai", IOCType.DOMAIN),
    ("192.0.2.999", IOCType.UNKNOWN),
    ...
])
def test_detect_type(value, expected):
    assert detect_type(value) is expected
```

Один тест на 22 случая вместо 22 функций. Каждый случай в отчёте pytest виден
отдельной строкой с подставленным значением, поэтому при падении сразу понятно,
какой именно вход сломался — именно так была найдена ошибка с punycode-TLD.

## Тесты HTTP без сети

```python
@pytest.fixture
def mock_api():
    with requests_mock.Mocker() as m:
        yield m

def test_429_is_retried_then_succeeds(client, mock_api, domain_ioc, vt_payload):
    mock_api.get("https://vt.test/api/v3/domains/malware-c2.example.com", [
        {"status_code": 429, "headers": {"Retry-After": "0"}},
        {"status_code": 200, "json": vt_payload},
    ])
    result = client.enrich(domain_ioc)
    assert result.status is EnrichmentStatus.OK
    assert mock_api.call_count == 2
```

* **Фикстура с `yield`** — код до `yield` выполняется перед тестом, после — при
  завершении. Здесь контекстный менеджер `Mocker()` активен на время теста.
* **Список ответов** — последовательные вызовы получают их по порядку. Так
  моделируется «сначала 429, потом успех».
* **`call_count`** — проверка числа запросов. Так тестируется наличие ретрая:
  не только результат, но и то, что попытка была повторена.
* **Настройки тестов с `vt_backoff_factor=0.0`** — иначе тест ретраев спал бы
  секунды.

## Тесты Bash

```bash
setup_case() {
    OUTPUT_DIR="$(mktemp -d)"
    FINDINGS_FILE="${OUTPUT_DIR}/.findings.jsonl"
    PASSWD_FILE="${OUTPUT_DIR}/passwd"
    export OUTPUT_DIR FINDINGS_FILE PASSWD_FILE ...
}

assert_finding() {
    local pattern="$1" description="$2"
    if grep -q "$pattern" "$FINDINGS_FILE" 2>/dev/null; then
        pass "$description"
    else
        fail "$description" "ожидалась находка по шаблону: ${pattern}"
    fi
}
```

Своя минимальная тестовая обвязка вместо внешнего фреймворка (`bats`): скрипт
не должен требовать установки инструментов, которых может не быть на
исследуемом хосте.

**Проверка «только чтение» через канарейку:**

```bash
CANARY="$(mktemp)"
printf 'канарейка\n' > "$CANARY"
CANARY_BEFORE="$(sha256sum "$CANARY" | awk '{print $1}')"
"${PROJECT_DIR}/triage.sh" -o "$RUN_DIR" --no-archive -q >/dev/null 2>&1
CANARY_AFTER="$(sha256sum "$CANARY" | awk '{print $1}')"
assert_equals "$CANARY_AFTER" "$CANARY_BEFORE" 'скрипт не изменяет посторонние файлы'
```

Машинная проверка главной гарантии инструмента. Утверждение «скрипт работает
только на чтение» из документации подтверждается тестом, а не словом автора.

---

# Часть 5. Сквозные решения

## 5.1. Почему одинаковые конвенции во всех проектах

`config.py`, `logging_setup.py`, структура `cli.py`, формат отчётов — почти
одинаковы в трёх Python-проектах. Это не копирование от лени, а осознанное
решение: благодаря нему четвёртый проект стал **объединением**, а не
переписыванием.

Общий модуль не был выделен заранее намеренно — по правилу «дублирование
терпимо до третьего раза». Преждевременная абстракция обошлась бы дороже: пока
не написаны все три инструмента, неизвестно, какая именно часть окажется общей.

**Что спросят:** «почему не вынесли общий код сразу?» → «потому что до
написания трёх инструментов я не знал, что именно окажется общим. Абстракция,
построенная на одном примере, почти всегда неверна. Дублирование в двух местах
дешевле, чем неправильная абстракция в трёх».

## 5.2. Единый принцип: отсутствие данных ≠ отсутствие проблемы

Проведён через все четыре проекта:

| Проект | Проявление |
|---|---|
| IOC Analyzer | сбой API даёт `ERROR`, не `CLEAN`; 404 даёт `UNKNOWN` |
| Log Analyzer | метрика покрытия разбора в отчёте: 5% разобранных строк видно |
| Linux Triage | недоступный без root артефакт помечается явно |
| Toolkit | `error` и `unknown` попадают в `LOW`, а не `INFO`; частичный сбой не даёт код 0 |

Ошибка, замаскированная под благополучие, опаснее видимой ошибки — она не
вызывает действий.

## 5.3. Тестирование: три уровня

**Юнит-тесты правил** — списками событий, без файлов на диске. Прямое следствие
архитектуры: правило не знает о форматах логов, значит и проверять его надо в
отрыве от них.

**Моки HTTP** (`requests-mock`) — воспроизводимая проверка того, что в жизни
ловится редко и болезненно: 429 с `Retry-After`, серия 5xx, обрыв соединения,
HTML вместо JSON, пустой ответ.

**Контрпримеры** — в каждом наборе тестовых данных есть легитимное поведение,
похожее на атаку: сотрудник, забывший пароль; `certbot renew` в cron; postgres
на localhost; штатные SUID-файлы. Детект, срабатывающий на что угодно,
бесполезен, и без контрпримеров этого не увидеть.

**Чего моки не дают.** Живой прогон по реальному VirusTotal нашёл три
проблемы, которых в моках не было: HTTP 400 вместо ожидаемого 404 на
зарезервированных зонах, двойной расход квоты на MD5 и SHA256 одного файла,
положительная репутация у EICAR. Нужны оба вида проверки.

## 5.4. Ошибки, найденные в процессе, и что они показывают

| Ошибка | Как найдена | Что показывает |
|---|---|---|
| Punycode-TLD не проходил регулярку | тест на IDN | параметризованные тесты покрывают то, о чём не думаешь |
| `strip_noise` не чистил `(example.com);` | тест на мусор | нужен цикл до стабилизации, а не один проход |
| `;` был и разделителем, и комментарием | тест на несколько IOC в строке | конфликт значений одного символа |
| Скользящее окно дробило атаку на 6 групп | ручная проверка вывода | тест на «одна атака = один алерт» |
| Ложное срабатывание на забытом пароле | контрпример в данных | контекст меняет интерпретацию |
| Spraying срабатывал на разведке имён | прогон по данным | два правила на одно поведение — дефект |
| Пропуск удавшегося spraying | прогон по данным | окно поиска успеха должно быть шире всплеска |
| `grep -c \|\| echo 0` даёт два нуля | запуск скрипта | идиома Bash с неочевидным поведением |
| Аргумент-ошибка давала код 2 | проверка CLI | конфликт с занятым кодом контракта |
| `lib/` не попал в git из-за `.gitignore` | **проверка на чистом клоне** | репозиторий, работающий только у автора |

Последняя строка — самая показательная. Ошибка была невидима локально: файлы
лежали в рабочем каталоге, всё работало. Обнаружить её мог только этап проверки
на чистой копии.

## 5.5. Что бы сделал иначе

Честный список, который лучше назвать самому:

1. **Оформил бы Python-проекты как устанавливаемые пакеты** (`pyproject.toml`)
   вместо правки `sys.path` в оболочке.
2. **Заставил бы Bash-скрипт заполнять структурированное поле `entities`**
   вместо разбора его текста регулярками на стороне оболочки.
3. **Заменил бы корреляцию по точному совпадению на граф сущностей** с учётом
   подсетей, доменов второго уровня и временной близости — так устроены
   промышленные корреляторы.
4. **Добавил бы базовую линию поведения, хранимую отдельно** от анализируемых
   логов: правило «новый источник» на одном файле за сутки даёт слабый сигнал.
5. **Вынес бы общий код в пакет ядра** — теперь, когда три инструмента написаны
   и видно, что именно у них общего.
