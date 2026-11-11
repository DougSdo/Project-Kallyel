from pathlib import Path

import pytest
from typer.testing import CliRunner

from kallyel.analysis import AnalysisOptions, analyze
from kallyel.cli import app
from kallyel.netutil import parse_networks
from kallyel.rules import load_builtin_rules
from kallyel.timeutil import parse_user_time

runner = CliRunner()
RULES = load_builtin_rules()

SCANNER_IP = "203.0.113.50"


def line(ip: str, second: int, request: str, status: int, ua: str = "Mozilla/5.0") -> str:
    minute, sec = divmod(second, 60)
    return f'{ip} - - [01/Jan/2024:12:{minute:02d}:{sec:02d} +0000] "{request}" {status} 512 "-" "{ua}"'


def write_log(tmp_path: Path, extra: list[str] | None = None) -> Path:
    lines = [line(SCANNER_IP, i, f"GET /x{i} HTTP/1.1", 404, "Nikto/2.1.6") for i in range(40)]
    lines += [line("198.51.100.7", 100 + i, "GET /index.html HTTP/1.1", 200) for i in range(5)]
    lines += [line(SCANNER_IP, 100 + i, "POST /login HTTP/1.1", 401) for i in range(20)]
    lines += extra or []
    f = tmp_path / "access.log"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f


# ----------------------------------------------------------------- analyze
def test_analyze_groups_findings_by_ip_and_scores_them(tmp_path: Path) -> None:
    result = analyze([write_log(tmp_path)], RULES)
    assert [r.ip for r in result.ip_reports] == [SCANNER_IP]
    report = result.ip_reports[0]
    assert {f.rule_id for f in report.findings} >= {
        "KALLYEL-WEB-005",
        "KALLYEL-WEB-007",
        "KALLYEL-WEB-008",
    }
    assert [s.phase for s in report.phases] == ["recon", "attempt"]
    assert report.score.components
    assert result.events_analyzed == 65


def test_private_ips_are_ignored_by_default_and_can_be_included(tmp_path: Path) -> None:
    priv = [line("10.0.0.5", i, "GET /.env HTTP/1.1", 404) for i in range(3)]
    log = write_log(tmp_path, priv)
    ignored = analyze([log], RULES)
    assert "10.0.0.5" not in {r.ip for r in ignored.ip_reports}
    assert ignored.events_ignored_ip == 3
    included = analyze([log], RULES, AnalysisOptions(ignore_private=False))
    assert "10.0.0.5" in {r.ip for r in included.ip_reports}


def test_extra_ignored_networks(tmp_path: Path) -> None:
    opts = AnalysisOptions(ignore_networks=parse_networks(["203.0.113.0/24"]))
    result = analyze([write_log(tmp_path)], RULES, opts)
    assert result.ip_reports == []
    assert result.events_ignored_ip == 60


def test_time_filters(tmp_path: Path) -> None:
    log = write_log(tmp_path)
    opts = AnalysisOptions(since=parse_user_time("2024-01-01T12:01:00"))  # só depois de 12:01:00
    result = analyze([log], RULES, opts)
    assert result.events_out_of_range == 40 + 0  # as 40 varreduras (12:00:00-12:00:39) ficam fora
    assert {f.rule_id for f in result.findings} == {"KALLYEL-WEB-008"}
    none = analyze([log], RULES, AnalysisOptions(until=parse_user_time("2023-12-31")))
    assert none.findings == []


def test_out_of_order_events_are_reported(tmp_path: Path) -> None:
    f = tmp_path / "access.log"
    f.write_text(
        line("203.0.113.9", 500, "GET / HTTP/1.1", 200)
        + "\n"
        + line("203.0.113.9", 0, "GET / HTTP/1.1", 200)
        + "\n",
        encoding="utf-8",
    )
    result = analyze([f], RULES)
    assert result.out_of_order == 1
    assert any("fora de ordem" in w for w in result.warnings)


def test_unrecognised_file_is_warned(tmp_path: Path) -> None:
    f = tmp_path / "x.txt"
    f.write_text("nada\nque\nse\nreconheça\n", encoding="utf-8")
    result = analyze([f], RULES)
    assert any("não reconhecido" in w for w in result.warnings)


# --------------------------------------------------------------------- CLI
def test_cli_timeline_shows_scan_then_bruteforce(tmp_path: Path) -> None:
    result = runner.invoke(app, ["timeline", "--ip", SCANNER_IP, str(write_log(tmp_path))])
    assert result.exit_code == 0, result.output
    out = result.output
    assert f"Linha do tempo de {SCANNER_IP}" in out
    assert out.index("reconhecimento") < out.index("tentativa")
    assert "KALLYEL-WEB-005" in out and "KALLYEL-WEB-008" in out
    assert "Pontuação de risco" in out
    assert "Gravidade" in out  # componentes explicados


def test_cli_timeline_masks_sensitive_data_by_default_and_not_with_flag(tmp_path: Path) -> None:
    attack = line(
        SCANNER_IP,
        300,
        "GET /p?id=1+UNION+SELECT+1&password=hunter2xyz&e=ana@example.test HTTP/1.1",
        200,
    )
    log = write_log(tmp_path, [attack])
    masked = runner.invoke(app, ["timeline", "--ip", SCANNER_IP, str(log)])
    assert masked.exit_code == 0, masked.output
    assert "KALLYEL-WEB-001" in masked.output  # o evento está mesmo na saída
    assert "hunter2xyz" not in masked.output
    assert "ana@example.test" not in masked.output
    assert "[REDACTED]" in masked.output
    raw = runner.invoke(app, ["timeline", "--ip", SCANNER_IP, "--no-redact", str(log)])
    assert "hunter2xyz" in raw.output


def test_cli_timeline_neutralises_ansi_and_markup_from_logs(tmp_path: Path) -> None:
    hostile = "\x1b[2J\x1b]0;pwned\x07[bold red]X[/bold red]<script>alert(1)</script>"
    lines = [line(SCANNER_IP, 0, f"GET /{hostile} HTTP/1.1", 404)]
    lines += [line(SCANNER_IP, i, f"GET /h{i} HTTP/1.1", 404) for i in range(1, 40)]
    f = tmp_path / "access.log"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = runner.invoke(app, ["timeline", "--ip", SCANNER_IP, str(f)])
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output
    assert "\x07" not in result.output
    assert "KALLYEL-WEB-007" in result.output
    assert "\\x1b" in result.output  # o ESC aparece como texto visível
    assert "[bold red]X[/bold red]" in result.output  # a marcação do rich não foi interpretada


def test_cli_timeline_rejects_bad_ip_and_bad_input(tmp_path: Path) -> None:
    log = write_log(tmp_path)
    bad_ip = runner.invoke(app, ["timeline", "--ip", "999.1.1.1", str(log)])
    assert bad_ip.exit_code == 2
    missing = runner.invoke(app, ["timeline", "--ip", SCANNER_IP, str(tmp_path / "nao-existe")])
    assert missing.exit_code == 2
    bad_date = runner.invoke(app, ["timeline", "--ip", SCANNER_IP, "--since", "ontem", str(log)])
    assert bad_date.exit_code == 2


def test_cli_timeline_for_ip_without_events_is_not_an_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["timeline", "--ip", "203.0.113.200", str(write_log(tmp_path))])
    assert result.exit_code == 0
    assert "Nenhum evento encontrado" in result.output


def test_cli_timeline_explicit_private_ip_is_not_filtered(tmp_path: Path) -> None:
    log = write_log(tmp_path, [line("10.0.0.5", 5, "GET /ok HTTP/1.1", 200)])
    result = runner.invoke(app, ["timeline", "--ip", "10.0.0.5", str(log)])
    assert result.exit_code == 0
    assert "Eventos deste IP analisados: 1" in result.output


def test_cli_timeline_reads_stdin(tmp_path: Path) -> None:
    text = write_log(tmp_path).read_text(encoding="utf-8")
    result = runner.invoke(app, ["timeline", "--ip", SCANNER_IP, "-"], input=text)
    assert result.exit_code == 0, result.output
    assert "reconhecimento" in result.output


@pytest.mark.parametrize("args", [["timeline"], ["timeline", "--ip", SCANNER_IP]])
def test_cli_timeline_requires_arguments(args: list[str]) -> None:
    assert runner.invoke(app, args).exit_code == 2
