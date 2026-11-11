"""A pasta exercicios/ versionada tem de continuar igual ao que o gerador produz com a semente."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kallyel.cli import app
from tests.data import realistic_day as rd

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "exercicios"
PROVA = EX / "prova-01"
README = EX / "README.md"
# Parâmetros da prova 01: precisam bater com os comandos do README.
SEED, NGINX, AUTH, LARAVEL = 2024, 6000, 500, 200


def normalised(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")  # o git no Windows pode converter LF em CRLF


def test_the_exercise_folder_is_small_and_has_only_logs() -> None:
    assert sorted(p.name for p in PROVA.iterdir()) == ["access.log", "auth.log", "laravel.log"]
    assert sum(p.stat().st_size for p in PROVA.iterdir()) < 3 * 2**20  # amostra pequena (<3 MB)


def test_readme_commands_use_the_same_parameters_as_this_test() -> None:
    text = README.read_text(encoding="utf-8")
    for needle in (
        f"--seed {SEED}",
        f"--nginx-lines {NGINX}",
        f"--auth-lines {AUTH}",
        f"--laravel-lines {LARAVEL}",
    ):
        assert needle in text, needle
    assert "--blind" in text and "--check" in text


def test_the_committed_logs_equal_what_the_seed_regenerates(tmp_path: Path) -> None:
    rd.build(
        tmp_path / "copia",
        nginx_lines=NGINX,
        auth_lines=AUTH,
        laravel_lines=LARAVEL,
        seed=SEED,
        blind=True,
    )
    for name in ("access.log", "auth.log", "laravel.log"):
        assert normalised(PROVA / name) == normalised(tmp_path / "copia" / name), (
            f"{name} mudou: o gerador foi alterado? Regere com o comando do exercicios/README.md"
        )


def test_the_exam_is_solved_exactly_by_the_tool_against_the_regenerated_answer_key(
    tmp_path: Path,
) -> None:
    manifest = rd.build(
        tmp_path / "copia",
        nginx_lines=NGINX,
        auth_lines=AUTH,
        laravel_lines=LARAVEL,
        seed=SEED,
        blind=True,
    )
    result = tmp_path / "r.json"
    run = CliRunner().invoke(app, ["analyze", str(PROVA), "-f", "json", "-o", str(result)])
    assert run.exit_code in {0, 1}, run.output
    outcome = rd.check(result, Path(str(manifest["gabarito_dir"])) / "gabarito.json")
    assert outcome["exact"], rd.render_check(outcome)


def test_the_answer_key_is_never_versioned() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/exercicios/*-gabarito/" in gitignore
    assert "!exercicios/**/*.log" in gitignore  # e os logs de exercício, sim
    assert not any("gabarito" in p.name for p in EX.iterdir() if p.is_file())


def test_exercise_logs_are_synthetic_only() -> None:
    # IPs de CLIENTE (quem acessa): primeiro campo do nginx e "from X port" do SSH. Endereços
    # que aparecem dentro de uma URL (alvo de um comando de teste) não são clientes.
    clients: set[str] = set()
    for line in (PROVA / "access.log").read_text(encoding="utf-8").splitlines():
        clients.add(line.split(" ", 1)[0])
    for line in (PROVA / "auth.log").read_text(encoding="utf-8").splitlines():
        found = re.search(r" from (\S+) port ", line)
        if found:
            clients.add(found.group(1))
    allowed = ("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:")
    bad = sorted(ip for ip in clients if not ip.startswith(allowed))
    assert clients and not bad, f"{len(bad)} IP(s) de cliente fora das faixas de documentação"
    blob = "".join(p.read_text(encoding="utf-8") for p in PROVA.iterdir())
    assert not re.search(r"[\w.]+@[\w-]+\.(com|org|net|br)\b", blob)


@pytest.mark.parametrize("link", ["../docs/avaliacao.md", "../docs/rules.md", "../docs/lab.md"])
def test_readme_links_exist(link: str) -> None:
    assert (EX / link).resolve().exists()
