"""Do log bruto ao achado, com os três formatos juntos (dados 100% sintéticos)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from kallyel.analysis import analyze
from kallyel.cli import app
from kallyel.redact import Redactor
from kallyel.report import build_report
from kallyel.rules import load_builtin_rules
from kallyel.rules.engine import match_snippet

runner = CliRunner()
RULES = load_builtin_rules()
ATTACKER = "203.0.113.50"


def nginx(ip: str, h: int, m: int, s: int, req: str, status: int, ua: str = "Mozilla/5.0") -> str:
    return f'{ip} - - [01/Jan/2024:{h:02d}:{m:02d}:{s:02d} +0000] "{req}" {status} 512 "-" "{ua}"'


def attack_nginx() -> str:
    lines = [
        nginx(ATTACKER, 12, 0, i, f"GET /x{i} HTTP/1.1", 404, "Nikto/2.1.6") for i in range(40)
    ]
    lines += [nginx(ATTACKER, 12, 1, 40 + i % 20, "POST /login HTTP/1.1", 401) for i in range(20)]
    lines += [nginx("198.51.100.7", 12, 2, 0, "GET /index.html HTTP/1.1", 200)]
    return "\n".join(lines) + "\n"


def attack_auth_iso() -> str:
    """Força bruta (6 falhas) e login com sucesso do mesmo IP, em ISO 8601 com fuso."""
    out = [
        f"2024-01-01T12:03:{20 + i:02d}+00:00 srv sshd[10]: "
        f"Failed password for root from {ATTACKER} port 4000{i} ssh2"
        for i in range(6)
    ]
    out.append(
        f"2024-01-01T12:03:30+00:00 srv sshd[10]: Accepted password for root from {ATTACKER} port 40010 ssh2"
    )
    out.append(
        "2024-01-01T12:04:00+00:00 srv sudo:   root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"
    )
    out.append(
        "2024-01-01T12:04:10+00:00 srv useradd[11]: new user: name=support, UID=1001, GID=1001, "
        "home=/home/support, shell=/bin/bash, from=/dev/pts/0"
    )
    out.append(
        "2024-01-01T12:04:20+00:00 srv CRON[12]: pam_unix(cron:session): session opened for user root"
    )
    return "\n".join(out) + "\n"


LARAVEL_LEAK = (
    '[2024-01-01 12:05:00] production.ERROR: Connection failed {"exception":"[object] (PDOException(code: 1045): '
    "SQLSTATE[HY000] [1045] Access denied)\n[stacktrace]\n"
    + "\n".join(f"#{i} /var/www/vendor/x/Frame{i}.php({i}): call()" for i in range(30))
    + "\n#30 /var/www/config/database.php(9): env('DB_PASSWORD=Sup3rS3cretValue')\n#31 {main}\n\"}\n"
    '[2024-01-01 12:06:00] production.INFO: User logged in {"id":7}\n'
)


def make_logs(tmp_path: Path) -> Path:
    d = tmp_path / "logs"
    d.mkdir()
    (d / "access.log").write_text(attack_nginx(), encoding="utf-8")
    (d / "auth.log").write_text(attack_auth_iso(), encoding="utf-8")
    (d / "laravel.log").write_text(LARAVEL_LEAK, encoding="utf-8")
    return d


# ------------------------------------------------------------------- análise
def test_all_three_formats_produce_the_expected_findings(tmp_path: Path) -> None:
    result = analyze([make_logs(tmp_path)], RULES)
    ids = {f.rule_id for f in result.findings}
    assert ids == {
        "KALLYEL-WEB-005",
        "KALLYEL-WEB-007",
        "KALLYEL-WEB-008",
        "KALLYEL-AUTH-001",
        "KALLYEL-AUTH-002",
        "KALLYEL-AUTH-003",
        "KALLYEL-APP-001",
    }
    by_id = {f.rule_id: f for f in result.findings}
    assert by_id["KALLYEL-AUTH-003"].count == 2  # sudo bash + useradd
    assert by_id["KALLYEL-APP-001"].client_ip is None  # log de aplicação não traz IP
    assert result.stats.files == 3
    assert result.stats.unparsed == 0
    assert result.out_of_order == 0 and not result.warnings


def test_scan_then_bruteforce_then_success_is_one_story_for_one_ip(tmp_path: Path) -> None:
    result = analyze([make_logs(tmp_path)], RULES)
    (report,) = result.ip_reports
    assert report.ip == ATTACKER
    assert [s.phase for s in report.phases] == ["recon", "attempt", "success"]
    assert report.score.band in {"alto", "crítico"}
    assert {"KALLYEL-AUTH-001", "KALLYEL-AUTH-002", "KALLYEL-WEB-007"} <= {
        f.rule_id for f in report.findings
    }


def test_cli_timeline_shows_the_full_sequence_across_files(tmp_path: Path) -> None:
    result = runner.invoke(app, ["timeline", "--ip", ATTACKER, str(make_logs(tmp_path))])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "reconhecimento → tentativa → sucesso" in out
    # a ordem das linhas na tabela: varredura, depois login web, depois SSH, depois sucesso
    positions = [
        out.index(m)
        for m in ("KALLYEL-WEB-007", "KALLYEL-WEB-008", "KALLYEL-AUTH-001", "KALLYEL-AUTH-002")
    ]
    assert positions == sorted(positions)


def test_clean_logs_of_all_three_formats_trigger_nothing(tmp_path: Path) -> None:
    d = tmp_path / "clean"
    d.mkdir()
    (d / "access.log").write_text(
        "\n".join(
            nginx("198.51.100.7", 12, 0, i, "GET /index.html HTTP/1.1", 200) for i in range(30)
        )
        + "\n",
        encoding="utf-8",
    )
    (d / "auth.log").write_text(
        "2024-01-01T12:00:00+00:00 srv sshd[1]: Accepted publickey for deploy from 198.51.100.9 port 22 ssh2: ED25519 SHA256:abc\n"
        "2024-01-01T12:00:05+00:00 srv sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update\n"
        "2024-01-01T12:00:06+00:00 srv sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx\n"
        "2024-01-01T12:00:10+00:00 srv CRON[9]: pam_unix(cron:session): session opened for user root\n"
        "2024-01-01T12:00:11+00:00 srv systemd[1]: Started Daily apt download activities.\n",
        encoding="utf-8",
    )
    (d / "laravel.log").write_text(
        '[2024-01-01 12:00:00] production.INFO: Order created {"id":1}\n'
        "[2024-01-01 12:00:01] production.WARNING: Cache miss\n"
        '[2024-01-01 12:00:02] production.ERROR: Undefined index: name {"exception":"[object] (ErrorException)\n'
        '[stacktrace]\n#0 /var/www/app/Http/Controllers/OrderController.php(10): index()\n#1 {main}\n"}\n',
        encoding="utf-8",
    )
    result = analyze([d], RULES)
    assert result.findings == []
    assert result.stats.unparsed == 0
    assert result.events_analyzed > 30


def test_failed_sudo_is_not_reported_as_an_executed_command(tmp_path: Path) -> None:
    f = tmp_path / "auth.log"
    f.write_text(
        "2024-01-01T12:00:00+00:00 srv sudo:   bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash\n"
        "2024-01-01T12:00:01+00:00 srv sudo:   bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash\n",
        encoding="utf-8",
    )
    assert analyze([f], RULES).findings == []


def test_username_spoofing_in_auth_log_blames_the_real_ip_only(tmp_path: Path) -> None:
    evil = "x from 10.9.9.9 port 1 ssh2: y"
    f = tmp_path / "auth.log"
    f.write_text(
        "".join(
            f"2024-01-01T12:00:{i:02d}+00:00 srv sshd[1]: Failed password for invalid user {evil} "
            f"from {ATTACKER} port 22 ssh2\n"
            for i in range(6)
        ),
        encoding="utf-8",
    )
    result = analyze([f], RULES)
    assert {f.client_ip for f in result.findings} == {ATTACKER}
    assert "10.9.9.9" not in {f.client_ip for f in result.findings}


# ------------------------------------------------------------ multilinha
def test_multiline_records_are_counted_in_lines_read_and_parsed(tmp_path: Path) -> None:
    f = tmp_path / "laravel.log"
    f.write_text(LARAVEL_LEAK, encoding="utf-8")
    result = analyze([f], RULES)
    total_lines = LARAVEL_LEAK.count("\n")
    assert result.stats.lines == total_lines
    assert result.stats.parsed == total_lines  # as linhas do stack trace contam como reconhecidas
    assert result.stats.unparsed == 0


def test_laravel_evidence_shows_the_context_of_the_match_deep_in_the_trace(tmp_path: Path) -> None:
    f = tmp_path / "laravel.log"
    f.write_text(LARAVEL_LEAK, encoding="utf-8")
    result = analyze([f], RULES)
    (finding,) = result.findings
    assert finding.rule_id == "KALLYEL-APP-001"
    evidence = finding.evidence[0].raw
    assert "DB_PASSWORD" in evidence  # o trecho está na linha 32, bem além do começo do registro
    assert "Frame1.php" not in evidence  # e não é só o início do registro

    masked = build_report(result, redact=Redactor())
    raw_text = json.dumps(masked, ensure_ascii=False)
    assert "Sup3rS3cretValue" not in raw_text
    assert "DB_PASSWORD=[REDACTED]" in raw_text or "[REDACTED]" in raw_text


def test_match_snippet_does_not_cut_tokens() -> None:
    import re

    text = "aaa " * 100 + "TOKEN=" + "x" * 300 + " " + "bbb " * 100
    found = re.search(r"TOKEN=x+", text)
    assert found is not None
    snippet = match_snippet(text, found)
    assert snippet.startswith("…") and snippet.endswith("…")
    assert "TOKEN=" + "x" * 300 in snippet
    assert all(w in {"aaa", "bbb", "…aaa", "bbb…", f"TOKEN={'x' * 300}"} for w in snippet.split())


# --------------------------------------------------------------- fuso e ano
def traditional_auth(tmp_path: Path) -> Path:
    """auth.log tradicional (sem ano e sem fuso) escrito por um servidor em UTC-3."""
    f = tmp_path / "auth.log"
    f.write_text(
        "".join(
            f"Jan  1 09:03:{20 + i:02d} srv sshd[10]: Failed password for root from {ATTACKER} port 4000{i} ssh2\n"
            for i in range(6)
        )
        + f"Jan  1 09:03:30 srv sshd[10]: Accepted password for root from {ATTACKER} port 40010 ssh2\n",
        encoding="utf-8",
    )
    mtime = datetime(2024, 1, 2, tzinfo=timezone.utc).timestamp()
    os.utime(f, (mtime, mtime))  # o ano vem daqui
    return f


def test_syslog_year_comes_from_file_date(tmp_path: Path) -> None:
    result = analyze([traditional_auth(tmp_path)], RULES)
    (report,) = result.ip_reports
    assert report.first_seen is not None and report.first_seen.year == 2024


def test_wrong_timezone_scrambles_the_story_and_the_offset_fixes_it(tmp_path: Path) -> None:
    web = tmp_path / "access.log"
    web.write_text(attack_nginx(), encoding="utf-8")  # nginx grava com fuso: 12:00 UTC
    auth = traditional_auth(tmp_path)  # 09:03 hora local = 12:03 UTC

    wrong = runner.invoke(app, ["timeline", "--ip", ATTACKER, str(web), str(auth)])
    right = runner.invoke(
        app, ["timeline", "--ip", ATTACKER, str(web), str(auth), "--log-utc-offset", "-03:00"]
    )
    assert wrong.exit_code == 0 and right.exit_code == 0
    assert "reconhecimento → tentativa → sucesso" in right.output
    # Sem o ajuste, o SSH aparece 3 h antes do varredor e a história sai na ordem errada.
    assert "reconhecimento → tentativa → sucesso" not in wrong.output
    assert (
        "sucesso → reconhecimento" in wrong.output
        or "tentativa → sucesso → reconhecimento" in wrong.output
    )


def test_invalid_utc_offset_is_a_usage_error(tmp_path: Path) -> None:
    f = tmp_path / "access.log"
    f.write_text(attack_nginx(), encoding="utf-8")
    assert runner.invoke(app, ["analyze", str(f), "--log-utc-offset", "tres"]).exit_code == 2
    assert (
        runner.invoke(
            app, ["timeline", "--ip", ATTACKER, str(f), "--log-utc-offset", "+99:00"]
        ).exit_code
        == 2
    )


def test_utc_offset_from_config_file(tmp_path: Path) -> None:
    cfg = tmp_path / "kallyel.toml"
    cfg.write_text('log_utc_offset = "-03:00"\n', encoding="utf-8")
    web = tmp_path / "access.log"
    web.write_text(attack_nginx(), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "timeline",
            "--ip",
            ATTACKER,
            str(web),
            str(traditional_auth(tmp_path)),
            "--config",
            str(cfg),
        ],
    )
    assert "reconhecimento → tentativa → sucesso" in result.output


# --------------------------------------------------- ordem entre arquivos
def test_files_of_different_formats_do_not_trigger_out_of_order_warning(tmp_path: Path) -> None:
    # auth.log é lido depois do nginx e tem horários anteriores: não é "fora de ordem"
    web = tmp_path / "access.log"
    web.write_text(nginx("198.51.100.7", 15, 0, 0, "GET / HTTP/1.1", 200) + "\n", encoding="utf-8")
    auth = tmp_path / "auth.log"
    auth.write_text(
        "2024-01-01T08:00:00+00:00 srv sshd[1]: Accepted publickey for a from 198.51.100.9 port 22 ssh2\n",
        encoding="utf-8",
    )
    result = analyze([web, auth], RULES)
    assert result.out_of_order == 0


def test_parsers_list_shows_all_formats() -> None:
    out = runner.invoke(app, ["parsers", "list"]).output
    for name in ("combined", "authlog", "laravel"):
        assert name in out


def test_table_shows_the_line_that_matched_in_a_stack_trace_and_masks_it(tmp_path: Path) -> None:
    f = tmp_path / "laravel.log"
    f.write_text(LARAVEL_LEAK, encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(f)])
    assert "KALLYEL-APP-001" in result.output
    assert (
        "DB_PASSWORD" in result.output
    )  # a linha do casamento aparece, não só o começo do registro
    assert "Sup3rS3cretValue" not in result.output  # mas o segredo sai mascarado
    assert "[REDACTED]" in result.output
