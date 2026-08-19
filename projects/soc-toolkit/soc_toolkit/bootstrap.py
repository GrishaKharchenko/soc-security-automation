"""Подключение соседних проектов набора.

Три инструмента разрабатывались независимо и живут в соседних каталогах
репозитория. Оболочке нужно их импортировать.

**Честно о выбранном решении.** Промышленный путь — оформить каждый проект
как устанавливаемый пакет (``pyproject.toml``) и объявить их зависимостями
оболочки: тогда импорт работает штатно, а версии фиксируются. Здесь выбран
более простой вариант — добавление соседних каталогов в ``sys.path``, потому
что он позволяет запустить набор без единой команды установки, а весь
«магический» код сосредоточен в одном явном месте, а не размазан по импортам.

Ограничение известно: при переносе оболочки отдельно от репозитория импорт
сломается. Для учебного проекта это приемлемо, и на собеседовании такой
компромисс лучше назвать самому, чем делать вид, что его нет.
"""

from __future__ import annotations

import sys
from pathlib import Path

# projects/soc-toolkit/soc_toolkit/bootstrap.py -> projects/
PROJECTS_DIR = Path(__file__).resolve().parent.parent.parent

MODULE_PATHS: dict[str, Path] = {
    "ioc_analyzer": PROJECTS_DIR / "ioc-analyzer",
    "log_analyzer": PROJECTS_DIR / "log-analyzer",
}

TRIAGE_SCRIPT = PROJECTS_DIR / "linux-triage" / "triage.sh"


class ModuleNotAvailable(RuntimeError):
    """Модуль набора не найден или не импортируется."""


def register_paths() -> None:
    """Добавить каталоги соседних проектов в ``sys.path``."""
    for path in MODULE_PATHS.values():
        text = str(path)
        if path.is_dir() and text not in sys.path:
            sys.path.insert(0, text)


def require(module_name: str):
    """Импортировать модуль набора, дав понятную ошибку вместо ImportError."""
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


def available_modules() -> dict[str, bool]:
    """Какие модули набора присутствуют на диске."""
    status = {name: path.is_dir() for name, path in MODULE_PATHS.items()}
    status["linux_triage"] = TRIAGE_SCRIPT.is_file()
    return status
