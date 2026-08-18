"""Позволяет запускать пакет как ``python -m ioc_analyzer``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
