"""A jornada sintética realista: detecta exatamente o gabarito, inclusive as lacunas conhecidas."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kallyel.analysis import analyze
from kallyel.rules import load_builtin_rules
from tests.data import realistic_day as rd

RULES = load_builtin_rules()


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, object]]:
    out = tmp_path_factory.mktemp("jornada") / "logs"
    manifest = rd.build(out, nginx_lines=30_000, auth_lines=2_000, laravel_lines=600, seed=5)
    return out, manifest


def test_logs_and_ground_truth_are_in_separate_folders(
    built: tuple[Path, dict[str, object]],
) -> None:
    out, manifest = built
    assert sorted(p.name for p in out.iterdir()) == ["access.log", "auth.log", "laravel.log"]
    gabarito = Path(str(manifest["gabarito_dir"]))
    assert gabarito != out
    assert (gabarito / "gabarito.json").exists() and (gabarito / "gabarito.md").exists()


def test_analysis_matches_the_ground_truth_exactly(built: tuple[Path, dict[str, object]]) -> None:
    out, manifest = built
    result = analyze([out], RULES)
    found = {(f.rule_id, f.client_ip or "") for f in result.findings}
    expected = {tuple(e) for e in manifest["expected"]}  # type: ignore[attr-defined]
    assert found == expected
    assert result.stats.unparsed == 0
    assert not result.warnings


def test_known_gaps_are_really_missed(built: tuple[Path, dict[str, object]]) -> None:
    out, _ = built
    result = analyze([out], RULES)
    by_ip: dict[str, set[str]] = {}
    for f in result.findings:
        by_ip.setdefault(f.client_ip or "", set()).add(f.rule_id)
    # varredura lenta: o volume (WEB-007) não vê, mas o arquivo sensível (WEB-004) sim
    assert by_ip["203.0.113.230"] == {"KALLYEL-WEB-004"}
    # força bruta de SSH lenta: nenhuma regra vê
    assert "203.0.113.231" not in by_ip


def test_attackers_vary_in_tool_ip_family_and_time(built: tuple[Path, dict[str, object]]) -> None:
    out, manifest = built
    ips = {s["ip"] for s in manifest["scenarios"]}  # type: ignore[attr-defined]
    assert len(ips) >= 14
    assert any(":" in str(ip) for ip in ips)  # há um atacante IPv6
    web = (out / "access.log").read_text(encoding="utf-8")
    for tool in ("Nikto", "sqlmap", "gobuster"):
        assert tool in web
    # varredura disfarçada de navegador: a regra de scanner NÃO dispara para ela
    result = analyze([out], RULES)
    disguised = next(s for s in manifest["scenarios"] if "DISFARÇADA" in s["description"])  # type: ignore[attr-defined]
    rules_for = {f.rule_id for f in result.findings if f.client_ip == disguised["ip"]}
    assert "KALLYEL-WEB-005" not in rules_for and "KALLYEL-WEB-007" in rules_for


def test_gabarito_markdown_lists_every_episode(built: tuple[Path, dict[str, object]]) -> None:
    _, manifest = built
    text = (Path(str(manifest["gabarito_dir"])) / "gabarito.md").read_text(encoding="utf-8")
    assert "lacuna conhecida" in text
    for s in manifest["scenarios"]:  # type: ignore[attr-defined]
        assert f"`{s['ip'] or '-'}`" in text
    data = json.loads(
        (Path(str(manifest["gabarito_dir"])) / "gabarito.json").read_text(encoding="utf-8")
    )
    assert data["files"] == manifest["files"]


# ------------------------------------------------------------------ modo cego
def analyze_to_json(logs: Path, dest: Path) -> Path:
    from typer.testing import CliRunner

    from kallyel.cli import app

    result = CliRunner().invoke(app, ["analyze", str(logs), "-f", "json", "-o", str(dest)])
    assert result.exit_code in {0, 1}, result.output
    return dest


def test_blind_mode_is_deterministic_and_varies_with_the_seed(tmp_path: Path) -> None:
    a = rd.build(
        tmp_path / "a", nginx_lines=8000, auth_lines=600, laravel_lines=200, seed=1, blind=True
    )
    b = rd.build(
        tmp_path / "b", nginx_lines=8000, auth_lines=600, laravel_lines=200, seed=1, blind=True
    )
    c = rd.build(
        tmp_path / "c", nginx_lines=8000, auth_lines=600, laravel_lines=200, seed=2, blind=True
    )
    assert a["expected"] == b["expected"]
    assert (tmp_path / "a" / "access.log").read_bytes() == (
        tmp_path / "b" / "access.log"
    ).read_bytes()
    assert a["expected"] != c["expected"]  # outra semente, outra prova


def test_blind_dataset_is_detected_exactly_and_hides_the_answers(tmp_path: Path) -> None:
    out = tmp_path / "prova"
    manifest = rd.build(
        out, nginx_lines=12_000, auth_lines=800, laravel_lines=300, seed=11, blind=True
    )
    gabarito = Path(str(manifest["gabarito_dir"]))
    # só o JSON (nada legível em Markdown) e fora da pasta dos logs
    assert sorted(p.name for p in gabarito.iterdir()) == ["gabarito.json"]
    assert sorted(p.name for p in out.iterdir()) == ["access.log", "auth.log", "laravel.log"]
    result = analyze_to_json(out, tmp_path / "resultado.json")
    outcome = rd.check(result, gabarito / "gabarito.json")
    assert outcome["exact"], rd.render_check(outcome)


def test_blind_generation_does_not_print_the_contents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = rd.main(
        ["--out", str(tmp_path / "p"), "--blind", "--seed", "3", "--nginx-lines", "5000"]
    )
    shown = capsys.readouterr().out
    assert code == 0
    for spoiler in ("SQLi", "Varredura", "Força bruta", "203.0.113.2", "KALLYEL-"):
        assert spoiler not in shown, spoiler
    assert "NAO abra" in shown


def test_check_command_grades_the_user_analysis(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "p"
    rd.build(out, nginx_lines=8000, auth_lines=600, laravel_lines=200, seed=4, blind=True)
    result = analyze_to_json(out, tmp_path / "r.json")
    gabarito = tmp_path / "p-gabarito" / "gabarito.json"
    assert rd.main(["--check", str(result), "--gabarito", str(gabarito)]) == 0
    assert "Correspondência exata" in capsys.readouterr().out

    # se a pessoa deixar de achar algo, o check mostra o que faltou (só depois de corrigir)
    data = json.loads(result.read_text(encoding="utf-8"))
    removed = data["findings"].pop(0)
    result.write_text(json.dumps(data), encoding="utf-8")
    assert rd.main(["--check", str(result), "--gabarito", str(gabarito)]) == 1
    text = capsys.readouterr().out
    assert "FALTOU" in text and removed["rule_id"] in text


def test_check_requires_a_gabarito(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        rd.main(["--check", "x.json"])
    with pytest.raises(SystemExit):
        rd.main([])
