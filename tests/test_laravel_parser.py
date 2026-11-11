"""Parser do laravel.log: registros de várias linhas, níveis, fuso e limites."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from kallyel.ingest import RawLine
from kallyel.model import Event
from kallyel.parsers import LaravelParser, ParserOptions
from kallyel.parsers.laravel import MAX_RECORD_CHARS, MAX_RECORD_LINES

TRACE = """\
[2024-03-15 10:20:30] production.ERROR: Undefined variable $user {"exception":"[object] (ErrorException(code: 0): Undefined variable $user at /var/www/app/Http/Controllers/UserController.php:42)
[stacktrace]
#0 /var/www/vendor/laravel/framework/src/Illuminate/Foundation/Bootstrap/HandleExceptions.php(255): Illuminate\\Foundation\\Bootstrap\\HandleExceptions->handleError(2, 'Undefined varia...', '/var/www/app/Ht...', 42)
#1 {main}
"}
[2024-03-15 10:20:31] production.INFO: User logged in {"id":7}
[2024-03-15 10:20:32] local.WARNING: Deprecated call
"""


def lines(text: str, name: str = "laravel.log") -> list[RawLine]:
    return [RawLine(name, i, t) for i, t in enumerate(text.split("\n")[:-1], start=1)]


def parse(text: str, *, offset: timedelta = timedelta(0)) -> list[Event]:
    parser = LaravelParser(ParserOptions(utc_offset=offset))
    return list(parser.parse_stream(lines(text)))


def test_multiline_record_is_one_event_with_trace_in_message() -> None:
    events = parse(TRACE)
    assert [e.action for e in events] == ["app.error", "app.info", "app.warning"]
    err = events[0]
    assert err.line_no == 1 and err.line_count == 5
    assert err.message is not None
    assert "Undefined variable $user" in err.message
    assert "[stacktrace]" in err.message and "#1 {main}" in err.message
    assert err.timestamp == datetime(2024, 3, 15, 10, 20, 30, tzinfo=timezone.utc)
    assert err.source_type == "laravel" and err.client_ip is None
    assert (events[1].line_no, events[1].line_count) == (6, 1)


@pytest.mark.parametrize(
    ("level", "action"),
    [
        ("DEBUG", "app.info"),
        ("INFO", "app.info"),
        ("NOTICE", "app.info"),
        ("WARNING", "app.warning"),
        ("ERROR", "app.error"),
        ("CRITICAL", "app.error"),
        ("ALERT", "app.error"),
        ("EMERGENCY", "app.error"),
        ("error", "app.error"),
    ],
)
def test_levels_map_to_actions(level: str, action: str) -> None:
    (ev,) = parse(f"[2024-03-15 10:00:00] production.{level}: msg\n")
    assert ev.action == action


def test_timestamp_variants_and_server_offset() -> None:
    (naive,) = parse("[2024-03-15 10:00:00] production.INFO: x\n", offset=timedelta(hours=-3))
    assert naive.timestamp == datetime(2024, 3, 15, 13, 0, 0, tzinfo=timezone.utc)
    (iso,) = parse(
        "[2024-03-15T10:00:00.123456+02:00] production.INFO: x\n", offset=timedelta(hours=-3)
    )
    assert iso.timestamp == datetime(
        2024, 3, 15, 8, 0, 0, 123456, tzinfo=timezone.utc
    )  # fuso explícito vence


def test_continuation_lines_before_any_header_are_unparsed_not_dropped() -> None:
    events = parse(
        "#3 /var/www/x.php(1): foo()\n#4 {main}\n[2024-03-15 10:00:00] production.INFO: ok\n"
    )
    assert [(e.parse_ok, e.line_no) for e in events] == [(False, 1), (False, 2), (True, 3)]


def test_header_with_impossible_date_is_unparsed() -> None:
    events = parse("[2024-13-45 10:00:00] production.ERROR: x\n  continua\n")
    assert [e.parse_ok for e in events] == [False, False]


def test_blank_lines_inside_a_record_are_kept_in_the_count() -> None:
    (ev,) = parse("[2024-03-15 10:00:00] production.ERROR: a\n\nb\n")
    assert ev.line_count == 3


def test_huge_record_is_capped_in_memory_but_counted() -> None:
    body = "\n".join(
        f"#{i} /var/www/vendor/x.php({i}): call()" for i in range(MAX_RECORD_LINES * 3)
    )
    (ev,) = parse(f"[2024-03-15 10:00:00] production.ERROR: boom\n{body}\n")
    assert ev.line_count == MAX_RECORD_LINES * 3 + 1
    assert ev.message is not None
    assert ev.message.count("\n") <= MAX_RECORD_LINES + 1
    assert ev.message.endswith("…[truncado]")


def test_record_char_cap() -> None:
    long_line = "A" * 5000
    text = "[2024-03-15 10:00:00] production.ERROR: x\n" + "\n".join([long_line] * 40) + "\n"
    (ev,) = parse(text)
    assert ev.message is not None
    assert len(ev.message) < MAX_RECORD_CHARS + 100
    assert ev.message.endswith("…[truncado]")


def test_raw_is_bounded() -> None:
    (ev,) = parse(TRACE.split("\n[2024-03-15 10:20:31]")[0] + "\n")
    assert len(ev.raw) <= 1100


def test_sniff() -> None:
    p = LaravelParser()
    first = "[2024-03-15 10:00:00] production.ERROR: x"
    assert p.sniff([first, "#0 trace", "#1 {main}"]) == 1.0
    assert (
        p.sniff(["#0 trace", "#1 {main}", first]) == 0.5
    )  # arquivo rotacionado no meio de um trace
    assert p.sniff(["Mar 15 10:20:30 srv sshd[1]: x"]) == 0.0
    assert p.sniff([]) == 0.0


@pytest.mark.parametrize(
    "payload",
    [
        "[2024-03-15 10:00:00] " + "a" * 8000,
        "[2024-03-15 10:00:00] " + "a." * 4000,
        "[2024-03-15 10:00:00] " + "-" * 8000 + ".ERROR: x",
        "[" * 8000,
        "[2024-03-15 10:00:00] production." + "E" * 8000,
    ],
)
def test_pathological_headers_are_fast(payload: str) -> None:
    import time

    start = time.perf_counter()
    parse(payload[:8192] + "\n")
    assert time.perf_counter() - start < 0.25
