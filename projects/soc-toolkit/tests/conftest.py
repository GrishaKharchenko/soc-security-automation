"""Фикстуры тестов оболочки."""

from __future__ import annotations

import pytest

from soc_toolkit.config import Settings
from soc_toolkit.models import Confidence, Finding, Severity, Source


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        output_dir=tmp_path / "reports",
        log_file=tmp_path / "logs" / "toolkit.log",
    )


@pytest.fixture
def finding_factory():
    def make(source: Source = Source.LOGS,
             severity: Severity = Severity.MEDIUM,
             rule_id: str = "TEST-001",
             title: str = "тестовая находка",
             **entities) -> Finding:
        return Finding(
            source=source, rule_id=rule_id, title=title,
            description="описание", severity=severity,
            confidence=Confidence.MEDIUM, entities=entities,
        )
    return make
