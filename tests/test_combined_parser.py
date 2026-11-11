from datetime import datetime, timezone

import pytest

from kallyel.ingest import RawLine
from kallyel.parsers.combined import CombinedParser, parse_clf_timestamp

parser = CombinedParser()

GOOD = (
    '203.0.113.7 - - [10/Oct/2023:13:55:36 -0300] "GET /index.php?id=5&x=y HTTP/1.1" '
    '200 2326 "https://example.test/" "Mozilla/5.0 (X11; Linux x86_64)"'
)


def parse(text: str, source_type: str = "nginx"):  # type: ignore[no-untyped-def]
    return parser.parse_line(RawLine("access.log", 1, text), source_type)


def test_parses_combined_line() -> None:
    ev = parse(GOOD)
    assert ev.parse_ok
    assert ev.action == "http.request"
    assert ev.client_ip == "203.0.113.7"
    assert ev.http_method == "GET"
    assert ev.http_path == "/index.php"
    assert ev.http_query == "id=5&x=y"
    assert ev.http_path_query == "/index.php?id=5&x=y"
    assert ev.http_status == 200
    assert ev.http_bytes == 2326
    assert ev.referrer == "https://example.test/"
    assert ev.user_agent == "Mozilla/5.0 (X11; Linux x86_64)"
    assert ev.user is None


def test_timestamp_converted_to_utc() -> None:
    ev = parse(GOOD)
    assert ev.timestamp == datetime(2023, 10, 10, 16, 55, 36, tzinfo=timezone.utc)


def test_positive_offset_and_locale_independent_month() -> None:
    ts = parse_clf_timestamp("01/Mar/2024:00:30:00 +0530")
    assert ts == datetime(2024, 2, 29, 19, 0, 0, tzinfo=timezone.utc)


def test_authenticated_user_and_dash_bytes() -> None:
    ev = parse(
        '198.51.100.2 - maria [10/Oct/2023:13:55:36 +0000] "POST /login HTTP/2.0" 302 - '
        '"-" "curl/8.0"'
    )
    assert ev.user == "maria"
    assert ev.http_bytes is None
    assert ev.referrer is None
    assert ev.http_method == "POST"


def test_common_format_without_referrer_and_ua() -> None:
    ev = parse('198.51.100.2 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.0" 200 10')
    assert ev.parse_ok
    assert ev.user_agent is None


def test_escaped_quote_in_user_agent_stays_inside_field() -> None:
    ev = parse(
        '203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 5 "-" "evil\\"agent"'
    )
    assert ev.parse_ok
    assert ev.user_agent == 'evil"agent'


def test_ipv6_client() -> None:
    ev = parse('2001:db8::1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 404 0 "-" "-"')
    assert ev.client_ip == "2001:db8::1"
    assert ev.http_status == 404


def test_malformed_request_keeps_raw_text_as_path() -> None:
    ev = parse('203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
    assert ev.parse_ok
    assert ev.http_method is None
    assert ev.http_path is not None
    assert "x16" in ev.http_path


def test_absolute_form_target() -> None:
    ev = parse(
        '203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "GET http://example.test/a?b=1 HTTP/1.1" '
        '200 1 "-" "-"'
    )
    assert ev.http_path == "/a"
    assert ev.http_query == "b=1"


def test_empty_query_and_root_path() -> None:
    ev = parse('203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "GET /? HTTP/1.1" 200 1 "-" "-"')
    assert ev.http_path == "/"
    assert ev.http_query is None


@pytest.mark.parametrize(
    "text",
    [
        "isto não é um log",
        '203.0.113.9 - - [31/Foo/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1',
        '203.0.113.9 - - [31/Feb/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1',
        '203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 2000 1',
    ],
)
def test_unrecognised_lines_are_flagged_not_dropped(text: str) -> None:
    ev = parse(text)
    assert not ev.parse_ok
    assert ev.action == "unparsed"
    assert ev.raw == text


def test_raw_is_truncated() -> None:
    long_ua = "A" * 5000
    ev = parse(
        f'203.0.113.9 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "{long_ua}"'
    )
    assert ev.parse_ok
    assert len(ev.raw) < 1100
    assert ev.raw.endswith("[truncado]")


def test_source_type_hint_from_filename() -> None:
    assert parser.default_source_type("/var/log/apache2/access.log") == "apache"
    assert parser.default_source_type("/var/log/nginx/access.log") == "nginx"


def test_sniff() -> None:
    assert parser.sniff([GOOD, GOOD]) == 1.0
    assert parser.sniff(["lixo", GOOD]) == 0.5
    assert parser.sniff([]) == 0.0
