"""Тесты чтения входных файлов: реальные фиды бывают грязными."""

import pytest

from ioc_analyzer.models import IOCType
from ioc_analyzer.parsers.reader import InputError, read_iocs


def _write(tmp_path, name, content, encoding="utf-8"):
    path = tmp_path / name
    path.write_text(content, encoding=encoding)
    return path


def test_reads_plain_txt(tmp_path):
    path = _write(tmp_path, "f.txt", "192.0.2.1\nexample.com\nhttp://example.com/a\n")
    iocs, stats = read_iocs(path)
    assert {i.type for i in iocs} == {IOCType.IPV4, IOCType.DOMAIN, IOCType.URL}
    assert stats.parsed == 3
    assert stats.invalid == 0


def test_skips_comments_and_blank_lines(tmp_path):
    path = _write(tmp_path, "f.txt", "# заголовок\n\n192.0.2.1\n// коммент\n; ещё\n\n")
    iocs, stats = read_iocs(path)
    assert len(iocs) == 1
    assert stats.skipped_comments == 3


def test_inline_comment_after_ioc(tmp_path):
    path = _write(tmp_path, "f.txt", "192.0.2.1  # C2 сервер\n")
    iocs, _ = read_iocs(path)
    assert iocs[0].value == "192.0.2.1"


def test_multiple_iocs_on_one_line(tmp_path):
    path = _write(tmp_path, "f.txt", "192.0.2.1, 198.51.100.14; 203.0.113.77\n")
    iocs, _ = read_iocs(path)
    assert len(iocs) == 3


def test_invalid_rows_are_counted_not_fatal(tmp_path):
    """Мусор во входных данных не должен ронять разбор."""
    path = _write(tmp_path, "f.txt", "192.0.2.1\nсовсем не индикатор\n192.0.2.999\n")
    iocs, stats = read_iocs(path)
    assert len(iocs) == 1
    assert stats.invalid == 2
    assert len(stats.invalid_samples) == 2


def test_csv_with_named_indicator_column(tmp_path):
    """Из CSV берём колонку с индикатором, а не timestamp и заметки."""
    path = _write(tmp_path, "f.csv",
                  "timestamp,source,indicator,notes\n"
                  "2026-01-01T00:00:00Z,fw,192.0.2.1,заметка\n"
                  "2026-01-01T00:01:00Z,fw,example.com,ещё заметка\n")
    iocs, _ = read_iocs(path)
    assert sorted(i.value for i in iocs) == ["192.0.2.1", "example.com"]


def test_csv_semicolon_delimiter(tmp_path):
    path = _write(tmp_path, "f.csv", "source;indicator\nfw;192.0.2.1\nfw;198.51.100.14\n")
    iocs, _ = read_iocs(path)
    assert len(iocs) == 2


def test_csv_without_header(tmp_path):
    path = _write(tmp_path, "f.csv", "192.0.2.1,заметка\nexample.com,заметка\n")
    iocs, _ = read_iocs(path)
    assert len(iocs) == 2


def test_bom_is_stripped(tmp_path):
    """Excel добавляет BOM; без utf-8-sig он приклеится к первому индикатору."""
    path = _write(tmp_path, "f.csv", "indicator\n192.0.2.1\n", encoding="utf-8-sig")
    iocs, _ = read_iocs(path)
    assert iocs[0].value == "192.0.2.1"


def test_cp1251_encoding_is_handled(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes("# комментарий на кириллице\n192.0.2.1\n".encode("cp1251"))
    iocs, _ = read_iocs(path)
    assert iocs[0].value == "192.0.2.1"


def test_deduplication_happens_by_default(tmp_path):
    path = _write(tmp_path, "f.txt", "EXAMPLE.COM\nexample[.]com\nexample.com.\n")
    iocs, stats = read_iocs(path)
    assert len(iocs) == 1
    assert iocs[0].occurrences == 3
    assert stats.duplicates == 2


def test_dedupe_can_be_disabled(tmp_path):
    path = _write(tmp_path, "f.txt", "example.com\nexample.com\n")
    iocs, _ = read_iocs(path, dedupe=False)
    assert len(iocs) == 2


def test_missing_file_raises_input_error(tmp_path):
    with pytest.raises(InputError, match="не найден"):
        read_iocs(tmp_path / "нет-такого.txt")


def test_empty_file_raises_input_error(tmp_path):
    path = _write(tmp_path, "empty.txt", "   \n\n")
    with pytest.raises(InputError, match="пуст"):
        read_iocs(path)


def test_directory_raises_input_error(tmp_path):
    with pytest.raises(InputError, match="не файл"):
        read_iocs(tmp_path)
