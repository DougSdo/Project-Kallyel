"""Parser de auth.log: sshd, sudo, useradd; ano, fuso e entrada hostil."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from kallyel.ingest import RawLine
from kallyel.model import Event
from kallyel.parsers import AuthLogParser, ParserOptions
from kallyel.parsers.authlog import infer_year_datetime

REF = datetime(2024, 3, 15, 12, 0, 0, tzinfo=timezone.utc)


def parse(text: str, *, offset: timedelta = timedelta(0), ref: datetime = REF) -> Event:
    parser = AuthLogParser(ParserOptions(utc_offset=offset, reference_time=ref))
    return parser.parse_line(RawLine("auth.log", 1, text), "authlog")


def sshd(msg: str, prog: str = "sshd[1234]") -> str:
    return f"Mar 15 10:20:30 srv {prog}: {msg}"


# ------------------------------------------------------------------ sshd
def test_failed_password() -> None:
    ev = parse(sshd("Failed password for root from 203.0.113.5 port 51234 ssh2"))
    assert (ev.parse_ok, ev.action, ev.user, ev.client_ip) == (
        True,
        "auth.failure",
        "root",
        "203.0.113.5",
    )
    assert ev.timestamp == datetime(2024, 3, 15, 10, 20, 30, tzinfo=timezone.utc)
    assert ev.source_type == "authlog"


def test_failed_password_invalid_user_and_other_methods() -> None:
    ev = parse(sshd("Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"))
    assert (ev.action, ev.user) == ("auth.failure", "admin")
    for msg in (
        "Failed publickey for deploy from 203.0.113.5 port 22 ssh2: RSA SHA256:abcDEF123",
        "Failed keyboard-interactive/pam for bob from 203.0.113.5 port 22 ssh2",
        "Failed none for bob from 203.0.113.5 port 22 ssh2",
    ):
        assert parse(sshd(msg)).action == "auth.failure", msg


def test_accepted() -> None:
    ev = parse(
        sshd("Accepted publickey for deploy from 198.51.100.9 port 40000 ssh2: ED25519 SHA256:xyz")
    )
    assert (ev.action, ev.user, ev.client_ip) == ("auth.success", "deploy", "198.51.100.9")
    ev = parse(sshd("Accepted password for maria from 2001:db8::7 port 22 ssh2"))
    assert (ev.action, ev.client_ip) == ("auth.success", "2001:db8::7")


def test_sshd_session_prog_name_of_openssh_9_8() -> None:
    ev = parse(sshd("Failed password for root from 203.0.113.5 port 22 ssh2", "sshd-session[99]"))
    assert ev.action == "auth.failure"


def test_informational_sshd_lines_do_not_count_as_failures() -> None:
    inv = parse(sshd("Invalid user oracle from 203.0.113.5 port 3333"))
    assert (inv.action, inv.client_ip) == ("auth.invalid_user", "203.0.113.5")
    mx = parse(
        sshd(
            "error: maximum authentication attempts exceeded for root from 203.0.113.5 port 22 ssh2 [preauth]"
        )
    )
    assert mx.action == "auth.max_attempts"


def test_username_cannot_spoof_the_client_ip() -> None:
    # O nome de usuário é escolhido por quem ataca e imita o resto da linha.
    evil_user = "x from 10.9.9.9 port 1 ssh2: y"
    line = sshd(f"Failed password for invalid user {evil_user} from 203.0.113.5 port 22 ssh2")
    ev = parse(line)
    assert ev.client_ip == "203.0.113.5"
    assert ev.action == "auth.failure"
    assert ev.user == evil_user


def test_text_appended_after_the_real_ip_is_not_accepted_as_failure() -> None:
    ev = parse(
        sshd(
            "Failed password for root from 203.0.113.5 port 22 ssh2 from 10.9.9.9 port 1 ssh2 extra"
        )
    )
    assert ev.action == "log.other"


def test_invalid_ip_in_message_yields_no_client_ip() -> None:
    ev = parse(sshd("Failed password for root from not-an-ip port 22 ssh2"))
    assert ev.action == "auth.failure" and ev.client_ip is None


@pytest.mark.parametrize(
    "inner",
    [
        "Failed password for root from 203.0.113.5 port 22 ssh2",
        "Failed password for root from 203.0.113.5 port 22 ssh2 ",
    ],
)
def test_message_repeated_is_unwrapped_once(inner: str) -> None:
    ev = parse(sshd(f"message repeated 3 times: [ {inner}]"))
    assert (ev.action, ev.client_ip) == ("auth.failure", "203.0.113.5")


# ------------------------------------------------------------------ sudo
def test_sudo_command_message_is_the_command_only() -> None:
    line = "Mar 15 10:20:30 srv sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
    ev = parse(line)
    assert (ev.action, ev.user, ev.message, ev.client_ip) == (
        "sudo.command",
        "alice",
        "/usr/bin/apt update",
        None,
    )


def test_sudo_command_with_semicolons_in_arguments() -> None:
    line = "Mar 15 10:20:30 srv sudo:   alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c 'a; COMMAND=b'"
    ev = parse(line)
    assert ev.message == "/bin/sh -c 'a; COMMAND=b'"


@pytest.mark.parametrize(
    "msg",
    [
        "  alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
        "  bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
        "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice",
    ],
)
def test_sudo_failures(msg: str) -> None:
    ev = parse(f"Mar 15 10:20:30 srv sudo: {msg}")
    assert ev.action == "sudo.failure"


def test_failed_sudo_that_mentions_command_is_not_an_executed_command() -> None:
    # Falhas também trazem COMMAND=, mas nada foi executado
    ev = parse(
        "Mar 15 10:20:30 srv sudo:   alice : 3 incorrect password attempts ; COMMAND=/bin/bash"
    )
    assert ev.action == "sudo.failure"


# --------------------------------------------------------------- useradd
def test_useradd_new_user() -> None:
    ev = parse(
        "Mar 15 10:20:30 srv useradd[777]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0"
    )
    assert (ev.action, ev.user) == ("user.created", "backdoor")
    assert ev.message is not None and ev.message.startswith("new user:")


# ----------------------------------------------------- envelope e reconhecimento
def test_unknown_program_with_valid_envelope_is_recognised_as_log_other() -> None:
    ev = parse("Mar 15 10:20:30 srv CRON[55]: pam_unix(cron:session): session opened for user root")
    assert ev.parse_ok and ev.action == "log.other"


def test_unknown_sshd_message_is_log_other_not_unparsed() -> None:
    assert parse(sshd("Server listening on 0.0.0.0 port 22.")).action == "log.other"


@pytest.mark.parametrize(
    "text",
    [
        "isto não é syslog",
        "Mar 15 10:20:30 srv sem-dois-pontos mensagem",
        "Xyz 99 99:99:99 h p: m",
        "",
    ],
)
def test_lines_without_syslog_envelope_are_unparsed(text: str) -> None:
    ev = parse(text)
    assert not ev.parse_ok and ev.action == "unparsed"


def test_single_digit_day_with_padding() -> None:
    ev = parse("Mar  5 01:02:03 srv sshd[1]: Failed password for a from 203.0.113.5 port 1 ssh2")
    assert ev.timestamp == datetime(2024, 3, 5, 1, 2, 3, tzinfo=timezone.utc)


# --------------------------------------------------------------- horário
def test_iso_timestamps_keep_their_own_offset() -> None:
    ev = parse(
        "2024-03-15T10:20:30.123456-03:00 srv sshd[1]: Failed password for a from 203.0.113.5 port 1 ssh2"
    )
    assert ev.parse_ok
    assert ev.timestamp == datetime(2024, 3, 15, 13, 20, 30, 123456, tzinfo=timezone.utc)
    z = parse(
        "2024-03-15T10:20:30Z srv sshd[1]: Failed password for a from 203.0.113.5 port 1 ssh2"
    )
    assert z.timestamp == datetime(2024, 3, 15, 10, 20, 30, tzinfo=timezone.utc)


def test_server_offset_applies_to_syslog_without_zone() -> None:
    ev = parse(
        sshd("Failed password for a from 203.0.113.5 port 1 ssh2"), offset=timedelta(hours=-3)
    )
    assert ev.timestamp == datetime(2024, 3, 15, 13, 20, 30, tzinfo=timezone.utc)  # 10:20 em UTC-3


def test_year_is_inferred_and_december_in_a_january_file_is_last_year() -> None:
    ref = datetime(2024, 1, 10, tzinfo=timezone.utc)
    dec = parse(
        "Dec 31 23:59:59 srv sshd[1]: Failed password for a from 203.0.113.5 port 1 ssh2", ref=ref
    )
    jan = parse(
        "Jan  2 00:00:01 srv sshd[1]: Failed password for a from 203.0.113.5 port 1 ssh2", ref=ref
    )
    assert dec.timestamp == datetime(2023, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert jan.timestamp == datetime(2024, 1, 2, 0, 0, 1, tzinfo=timezone.utc)
    assert dec.timestamp is not None and jan.timestamp is not None
    assert dec.timestamp < jan.timestamp


def test_leap_day_without_leap_year_in_reference() -> None:
    assert infer_year_datetime(
        2, 29, 0, 0, 0, datetime(2025, 3, 1, tzinfo=timezone.utc)
    ) == datetime(2024, 2, 29, tzinfo=timezone.utc)
    assert infer_year_datetime(2, 30, 0, 0, 0, REF) is None


def test_year_comes_from_file_mtime_when_no_reference_given(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import os

    f = tmp_path / "auth.log"
    f.write_text("x\n", encoding="utf-8")
    mtime = datetime(2022, 8, 1, tzinfo=timezone.utc).timestamp()
    os.utime(f, (mtime, mtime))
    parser = AuthLogParser()
    ev = parser.parse_line(
        RawLine(
            str(f),
            1,
            "Jul 30 10:00:00 srv sshd[1]: Failed password for a from 203.0.113.5 port 1 ssh2",
        ),
        "authlog",
    )
    assert ev.timestamp is not None and ev.timestamp.year == 2022


# ------------------------------------------------------------ stream e sniff
def test_stream_skips_blank_lines_and_keeps_line_numbers() -> None:
    parser = AuthLogParser(ParserOptions(reference_time=REF))
    lines = [
        RawLine("auth.log", 1, sshd("Failed password for a from 203.0.113.5 port 1 ssh2")),
        RawLine("auth.log", 2, ""),
        RawLine("auth.log", 3, "lixo"),
    ]
    events = list(parser.parse_stream(lines))
    assert [(e.line_no, e.parse_ok) for e in events] == [(1, True), (3, False)]


def test_sniff_prefers_syslog_over_other_formats() -> None:
    parser = AuthLogParser(ParserOptions(reference_time=REF))
    good = sshd("Failed password for a from 203.0.113.5 port 1 ssh2")
    assert parser.sniff([good, good]) == 1.0
    assert (
        parser.sniff(['203.0.113.7 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 5']) == 0.0
    )


# ----------------------------------------------------------------- ReDoS
@pytest.mark.parametrize(
    "payload",
    [
        "Failed password for " + "x from " * 1000 + "y",
        "Failed password for " + " from 1.1.1.1 port 1 ssh2" * 300,
        "Failed password for " + "a" * 8000,
        "Invalid user " + " from " * 1200,
        "Accepted password for " + "port 1 " * 1000,
        "  " + "a : " * 2000,
        "  alice : " + "COMMAND" * 1000,
        "message repeated 3 times: [ " + "[ " * 3000,
        "new user: name=" + "a" * 8000,
    ],
)
def test_pathological_lines_are_parsed_fast(payload: str) -> None:
    for prog in ("sshd[1]", "sudo", "useradd[1]"):
        start = time.perf_counter()
        parse(f"Mar 15 10:20:30 srv {prog}: {payload}"[:8192])
        assert time.perf_counter() - start < 0.25, prog
