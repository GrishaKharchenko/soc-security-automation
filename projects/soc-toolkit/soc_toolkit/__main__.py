"""Запуск оболочки: ``python -m soc_toolkit``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
