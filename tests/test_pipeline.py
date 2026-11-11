from pathlib import Path

from kallyel.pipeline import UNPARSED_SAMPLE_LIMIT, IngestStats, iter_events

GOOD = '203.0.113.7 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.0"'


def test_counts_unparsed_lines_and_keeps_samples(tmp_path: Path) -> None:
    f = tmp_path / "access.log"
    f.write_text("\n".join([GOOD, "lixo 1", GOOD, "lixo 2"]) + "\n", encoding="utf-8")
    stats = IngestStats()
    events = list(iter_events([f], stats))
    assert len(events) == 2
    assert (stats.lines, stats.parsed, stats.unparsed) == (4, 2, 2)
    assert [e.raw for e in stats.unparsed_samples] == ["lixo 1", "lixo 2"]
    assert stats.unparsed_samples[0].line_no == 2


def test_unparsed_samples_are_bounded(tmp_path: Path) -> None:
    f = tmp_path / "access.log"
    f.write_text("\n".join([GOOD] * 60 + ["x"] * 100) + "\n", encoding="utf-8")
    stats = IngestStats()
    list(iter_events([f], stats))
    assert stats.unparsed == 100
    assert len(stats.unparsed_samples) == UNPARSED_SAMPLE_LIMIT


def test_file_with_unknown_format_is_reported_not_silent(tmp_path: Path) -> None:
    f = tmp_path / "estranho.txt"
    f.write_text("nada\nreconhecivel\n", encoding="utf-8")
    stats = IngestStats()
    assert list(iter_events([f], stats)) == []
    assert stats.skipped_files == [str(f)]
    assert stats.lines == 2


def test_truncated_lines_are_counted(tmp_path: Path) -> None:
    f = tmp_path / "access.log"
    f.write_bytes(GOOD.encode() + b"\n" + b"Z" * 20000 + b"\n")
    stats = IngestStats()
    list(iter_events([f], stats))
    assert stats.truncated_lines == 1
