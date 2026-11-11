import gzip
import io
import os
from pathlib import Path

import pytest

from kallyel.ingest import (
    MAX_LINE_BYTES,
    InputError,
    iter_input_files,
    read_file_lines,
    read_stdin_lines,
)


def test_reads_plain_file_with_both_line_endings(tmp_path: Path) -> None:
    f = tmp_path / "a.log"
    f.write_bytes(b"um\r\ndois\ntres")
    lines = list(read_file_lines(f))
    assert [ln.text for ln in lines] == ["um", "dois", "tres"]
    assert [ln.line_no for ln in lines] == [1, 2, 3]


def test_reads_gzip_by_content_not_extension(tmp_path: Path) -> None:
    f = tmp_path / "access.log.1"  # rotacionado, sem .gz
    f.write_bytes(gzip.compress(b"a\nb\n"))
    assert [ln.text for ln in read_file_lines(f)] == ["a", "b"]


def test_invalid_utf8_does_not_crash(tmp_path: Path) -> None:
    f = tmp_path / "a.log"
    f.write_bytes(b"ol\xe1 \xff\n")
    (line,) = list(read_file_lines(f))
    assert line.text.startswith("ol")


def test_giant_line_is_truncated_and_following_lines_survive(tmp_path: Path) -> None:
    f = tmp_path / "a.log"
    f.write_bytes(b"A" * (MAX_LINE_BYTES * 5 + 123) + b"\nsegunda\n")
    lines = list(read_file_lines(f))
    assert len(lines) == 2
    assert lines[0].truncated
    assert len(lines[0].text) == MAX_LINE_BYTES
    assert lines[1].text == "segunda"
    assert lines[1].line_no == 2
    assert not lines[1].truncated


def test_line_of_exactly_max_size_is_not_truncated(tmp_path: Path) -> None:
    f = tmp_path / "a.log"
    f.write_bytes(b"B" * MAX_LINE_BYTES + b"\n")
    (line,) = list(read_file_lines(f))
    assert not line.truncated


def test_corrupt_gzip_is_input_error(tmp_path: Path) -> None:
    f = tmp_path / "bad.gz"
    f.write_bytes(b"\x1f\x8b\x08\x00garbage")
    with pytest.raises(InputError):
        list(read_file_lines(f))


def test_stdin_reader() -> None:
    lines = list(read_stdin_lines(io.BytesIO(b"x\ny\n")))
    assert [ln.text for ln in lines] == ["x", "y"]
    assert lines[0].source_file == "<stdin>"


def test_missing_path_is_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError):
        list(iter_input_files([tmp_path / "nao-existe"]))


def test_directory_walk_is_recursive_and_sorted(tmp_path: Path) -> None:
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "2.log").write_text("x")
    (tmp_path / "1.log").write_text("x")
    names = [p.name for p in iter_input_files([tmp_path])]
    assert names == ["1.log", "2.log"]


def test_symlinks_inside_directories_are_not_followed(tmp_path: Path) -> None:
    secret_dir = tmp_path / "fora"
    secret_dir.mkdir()
    (secret_dir / "segredo.log").write_text("conteudo")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "real.log").write_text("ok")
    try:
        os.symlink(secret_dir / "segredo.log", logs / "link.log")
        os.symlink(secret_dir, logs / "linkdir", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks indisponíveis neste ambiente (Windows sem privilégio)")
    names = [p.name for p in iter_input_files([logs])]
    assert names == ["real.log"]
    followed = sorted(p.name for p in iter_input_files([logs], follow_symlinks=True))
    assert "segredo.log" in followed


def test_stdin_gzip_is_detected_by_content() -> None:
    import io

    raw = gzip.compress(b"a\nb\n")
    # BufferedReader (como sys.stdin.buffer) permite espiar os 2 primeiros bytes
    lines = list(read_stdin_lines(io.BufferedReader(io.BytesIO(raw))))
    assert [ln.text for ln in lines] == ["a", "b"]
    assert lines[0].source_file == "<stdin>"


def test_stdin_corrupt_gzip_is_input_error() -> None:
    import io

    bad = io.BufferedReader(io.BytesIO(b"\x1f\x8b\x08\x00garbage"))
    with pytest.raises(InputError):
        list(read_stdin_lines(bad))
