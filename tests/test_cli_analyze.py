"""Comando ``analyze``, códigos de saída e demais comandos da CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kallyel.cli import app

runner = CliRunner()


def access_line(ip: str, second: int, request: str, status: int, ua: str = "Mozilla/5.0") -> str:
    minute, sec = divmod(second, 60)
    return f'{ip} - - [01/Jan/2024:12:{minute:02d}:{sec:02d} +0000] "{request}" {status} 512 "-" "{ua}"'


def attack_log(tmp_path: Path, name: str = "access.log") -> Path:
    lines = [
        access_line("203.0.113.50", i, f"GET /x{i} HTTP/1.1", 404, "Nikto/2.1.6") for i in range(40)
    ]
    lines += [access_line("203.0.113.50", 70, "GET /p?id=1+UNION+SELECT+1 HTTP/1.1", 500)]
    f = tmp_path / name
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f


def clean_log(tmp_path: Path) -> Path:
    f = tmp_path / "clean.log"
    lines = [access_line("203.0.113.9", i, "GET /index.html HTTP/1.1", 200) for i in range(10)]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f


# ----------------------------------------------------------- códigos de saída
def test_exit_0_when_no_findings(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", str(clean_log(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "Achados: 0" in result.output


def test_exit_1_when_findings_at_threshold_or_above(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    assert runner.invoke(app, ["analyze", str(log)]).exit_code == 1
    assert (
        runner.invoke(app, ["analyze", str(log), "--fail-on", "high"]).exit_code == 1
    )  # SQLi é alta
    assert runner.invoke(app, ["analyze", str(log), "--fail-on", "critical"]).exit_code == 0


def test_exit_2_on_usage_and_input_errors(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    assert runner.invoke(app, ["analyze"]).exit_code == 2
    assert runner.invoke(app, ["analyze", str(tmp_path / "nao-existe")]).exit_code == 2
    assert runner.invoke(app, ["analyze", str(log), "--format", "xml"]).exit_code == 2
    assert runner.invoke(app, ["analyze", str(log), "--fail-on", "enorme"]).exit_code == 2
    assert runner.invoke(app, ["analyze", str(log), "--since", "ontem"]).exit_code == 2
    assert runner.invoke(app, ["analyze", str(log), "--rules", str(tmp_path / "x")]).exit_code == 2


# -------------------------------------------------------------------- formatos
@pytest.mark.parametrize("fmt", ["table", "json", "jsonl", "html", "md"])
def test_every_format_works_to_stdout(tmp_path: Path, fmt: str) -> None:
    result = runner.invoke(app, ["analyze", str(attack_log(tmp_path)), "-f", fmt])
    assert result.exit_code == 1, result.output  # há achados
    assert "KALLYEL-WEB-001" in result.output


def test_json_stdout_is_pure_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", str(attack_log(tmp_path)), "-f", "json"])
    data = json.loads(result.stdout)
    assert data["summary"]["findings"] >= 3


@pytest.mark.parametrize(
    ("fmt", "marker"), [("html", "<!doctype html>"), ("md", "# Dossiê"), ("json", '"findings"')]
)
def test_out_writes_file_in_utf8(tmp_path: Path, fmt: str, marker: str) -> None:
    out = tmp_path / f"relatorio.{fmt}"
    result = runner.invoke(app, ["analyze", str(attack_log(tmp_path)), "-f", fmt, "-o", str(out)])
    assert result.exit_code == 1
    assert marker in out.read_text(encoding="utf-8")
    assert "KALLYEL-WEB-001" not in result.stdout  # nada duplicado no terminal


def test_table_out_file_has_no_terminal_codes(tmp_path: Path) -> None:
    out = tmp_path / "saida.txt"
    runner.invoke(app, ["analyze", str(attack_log(tmp_path)), "-o", str(out)])
    text = out.read_text(encoding="utf-8")
    assert "\x1b" not in text
    assert "IPs por risco" in text


def test_out_refuses_to_overwrite_an_input_file(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    before = log.read_text(encoding="utf-8")
    result = runner.invoke(app, ["analyze", str(log), "-f", "json", "-o", str(log)])
    assert result.exit_code == 2
    assert log.read_text(encoding="utf-8") == before


def test_out_in_missing_directory_is_an_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "analyze",
            str(attack_log(tmp_path)),
            "-f",
            "json",
            "-o",
            str(tmp_path / "nada" / "r.json"),
        ],
    )
    assert result.exit_code == 2


# ----------------------------------------------------------------- entradas
def test_unparsed_lines_counted_and_samples_on_request(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    with log.open("a", encoding="utf-8") as fh:
        fh.write("isto não é log\nnem isto\n")
    plain = runner.invoke(app, ["analyze", str(log)])
    assert "NÃO reconhecidas: 2" in plain.output
    assert "isto não é log" not in plain.output
    assert "--show-unparsed" in plain.output
    shown = runner.invoke(app, ["analyze", str(log), "--show-unparsed"])
    assert "isto não é log" in shown.output


def test_directory_and_stdin_inputs(tmp_path: Path) -> None:
    attack_log(tmp_path, "a.log")
    by_dir = runner.invoke(app, ["analyze", str(tmp_path), "-f", "json"])
    assert json.loads(by_dir.stdout)["summary"]["files"] == 1
    text = attack_log(tmp_path, "b.log").read_text(encoding="utf-8")
    by_stdin = runner.invoke(app, ["analyze", "-", "-f", "json"], input=text)
    assert json.loads(by_stdin.stdout)["summary"]["findings"] >= 3


def test_since_until_filters_apply(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    result = runner.invoke(
        app, ["analyze", str(log), "-f", "json", "--since", "2024-01-01T12:01:00"]
    )
    data = json.loads(result.stdout)
    assert {f["rule_id"] for f in data["findings"]} == {"KALLYEL-WEB-001"}


def test_private_ips_ignored_unless_requested(tmp_path: Path) -> None:
    f = tmp_path / "priv.log"
    f.write_text(
        "\n".join(access_line("10.0.0.7", i, f"GET /x{i} HTTP/1.1", 404) for i in range(40)) + "\n",
        encoding="utf-8",
    )
    assert runner.invoke(app, ["analyze", str(f)]).exit_code == 0
    assert runner.invoke(app, ["analyze", str(f), "--include-private"]).exit_code == 1


def test_custom_rules_dir(tmp_path: Path) -> None:
    rules = tmp_path / "regras"
    rules.mkdir()
    (rules / "x.yaml").write_text(
        "id: KALLYEL-TST-001\ntitle: Acesso a /secret\nseverity: critical\nsources: [nginx]\n"
        "match:\n  field: http_path\n  any_regex: ['^/secret$']\n"
        "explain: x\nfalse_positives: y\nmitigation: z\n",
        encoding="utf-8",
    )
    f = tmp_path / "a.log"
    f.write_text(
        access_line("203.0.113.9", 1, "GET /secret HTTP/1.1", 200) + "\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["analyze", str(f), "--rules", str(rules), "--fail-on", "critical"])
    assert result.exit_code == 1
    assert "KALLYEL-TST-001" in result.output


# --------------------------------------------------------- demais comandos
def test_rules_list_show_validate(tmp_path: Path) -> None:
    listing = runner.invoke(app, ["rules", "list"])
    assert listing.exit_code == 0
    assert listing.output.count("KALLYEL-") == 13
    show = runner.invoke(app, ["rules", "show", "kallyel-web-006"])
    assert show.exit_code == 0 and "CWE-78" in show.output
    assert runner.invoke(app, ["rules", "show", "KALLYEL-NAO-999"]).exit_code == 2

    good = tmp_path / "good"
    good.mkdir()
    (good / "r.yaml").write_text(
        "id: KALLYEL-TST-002\ntitle: t\nseverity: low\nsources: [nginx]\n"
        "match:\n  field: http_path\n  any_regex: ['x']\nexplain: a\nfalse_positives: b\nmitigation: c\n",
        encoding="utf-8",
    )
    assert runner.invoke(app, ["rules", "validate", str(good)]).exit_code == 0
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "r.yaml").write_text("id: nope\n", encoding="utf-8")
    assert runner.invoke(app, ["rules", "validate", str(bad)]).exit_code == 2
    assert (
        runner.invoke(app, ["rules", "validate", str(tmp_path / "vazia-inexistente")]).exit_code
        == 2
    )
    empty = tmp_path / "empty"
    empty.mkdir()
    assert runner.invoke(app, ["rules", "validate", str(empty)]).exit_code == 2


def test_rules_list_with_extra_dir_error(tmp_path: Path) -> None:
    assert runner.invoke(app, ["rules", "list", "--rules", str(tmp_path / "x")]).exit_code == 2


def test_version_and_parsers() -> None:
    assert runner.invoke(app, ["version"]).exit_code == 0
    assert runner.invoke(app, ["parsers", "list"]).exit_code == 0
