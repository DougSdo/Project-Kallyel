"""O gerador de logs sintéticos e o que ele garante (inclusive 'tráfego limpo não gera achado')."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from kallyel.analysis import analyze
from kallyel.rules import load_builtin_rules
from tests.data import generate as gen

RULES = load_builtin_rules()
DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:")
ATTACKER_RANGE = re.compile(r"^203\.0\.113\.(2\d\d|20\d)$")
CLF_TIME = re.compile(r"\[(\d\d)/(\w{3})/(\d{4}):(\d\d):(\d\d):(\d\d) ")


def small(out: Path, *, scenarios: tuple[str, ...] = (), seed: int = 7) -> dict[str, object]:
    return gen.write_dataset(
        out, nginx_lines=4000, auth_lines=600, laravel_lines=300, scenarios=scenarios, seed=seed
    )


def files_of(d: Path) -> list[Path]:
    return [d / n for n in ("access.log", "auth.log", "laravel.log")]


# ------------------------------------------------------------ propriedades
def test_generator_is_deterministic_and_seed_sensitive(tmp_path: Path) -> None:
    small(tmp_path / "a", scenarios=tuple(gen.SCENARIOS))
    small(tmp_path / "b", scenarios=tuple(gen.SCENARIOS))
    small(tmp_path / "c", scenarios=tuple(gen.SCENARIOS), seed=8)
    for name in ("access.log", "auth.log", "laravel.log", "manifest.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
    assert (tmp_path / "a" / "access.log").read_bytes() != (
        tmp_path / "c" / "access.log"
    ).read_bytes()


def test_generator_does_not_depend_on_the_tool_it_evaluates() -> None:
    source = Path(gen.__file__).read_text(encoding="utf-8")
    assert not re.search(r"^\s*(?:from|import)\s+kallyel", source, re.MULTILINE)


def test_only_documentation_addresses_are_used(tmp_path: Path) -> None:
    small(tmp_path, scenarios=tuple(gen.SCENARIOS))
    ips = set()
    for line in (tmp_path / "access.log").read_text(encoding="utf-8").splitlines():
        ips.add(line.split(" ", 1)[0])
    for line in (tmp_path / "auth.log").read_text(encoding="utf-8").splitlines():
        m = re.search(r" from (\S+) port ", line)
        if m:
            ips.add(m.group(1))
    assert ips
    assert all(ip.startswith(DOC_PREFIXES) for ip in ips), sorted(
        i for i in ips if not i.startswith(DOC_PREFIXES)
    )


def test_background_traffic_never_uses_attacker_addresses(tmp_path: Path) -> None:
    small(tmp_path)  # sem cenários
    firsts = {
        ln.split(" ", 1)[0]
        for ln in (tmp_path / "access.log").read_text(encoding="utf-8").splitlines()
    }
    assert not any(ATTACKER_RANGE.match(ip) for ip in firsts)


def test_lines_are_in_chronological_order_after_merging_scenarios(tmp_path: Path) -> None:
    small(tmp_path, scenarios=tuple(gen.SCENARIOS))
    months = {m: i for i, m in enumerate(gen.MONTHS, 1)}
    stamps = []
    for line in (tmp_path / "access.log").read_text(encoding="utf-8").splitlines():
        m = CLF_TIME.search(line)
        assert m, line
        stamps.append((int(m[3]), months[m[2]], int(m[1]), int(m[4]), int(m[5]), int(m[6])))
    assert stamps == sorted(stamps)
    auth = [ln[:25] for ln in (tmp_path / "auth.log").read_text(encoding="utf-8").splitlines()]
    assert auth == sorted(auth)


def test_unknown_scenario_and_cli_errors(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="desconhecido"):
        gen.write_dataset(tmp_path, nginx_lines=10, scenarios=["nao-existe"])
    assert (
        gen.main(["--out", str(tmp_path / "x"), "--scenarios", "nao-existe", "--nginx-lines", "10"])
        == 2
    )
    assert (
        gen.main(
            [
                "--out",
                str(tmp_path / "y"),
                "--scenarios",
                "none",
                "--nginx-lines",
                "50",
                "--auth-lines",
                "0",
                "--laravel-lines",
                "0",
            ]
        )
        == 0
    )
    assert (tmp_path / "y" / "access.log").exists() and not (tmp_path / "y" / "auth.log").exists()


def test_every_builtin_rule_has_a_scenario_in_the_generator(tmp_path: Path) -> None:
    manifest = small(tmp_path, scenarios=tuple(gen.SCENARIOS))
    expected_rules = {e[0] for e in manifest["expected"]}  # type: ignore[attr-defined]
    assert expected_rules == {r.id for r in RULES}


# --------------------------------------------------------- avaliação real
def test_clean_traffic_produces_no_findings_and_no_unparsed_lines(tmp_path: Path) -> None:
    gen.write_dataset(tmp_path, nginx_lines=50_000, auth_lines=5_000, laravel_lines=2_000, seed=3)
    result = analyze(files_of(tmp_path), RULES)
    assert result.findings == []
    assert result.stats.unparsed == 0
    assert result.stats.parsed == result.stats.lines
    assert not result.warnings


def test_scenarios_are_detected_exactly_as_the_ground_truth_says(tmp_path: Path) -> None:
    manifest = small(tmp_path, scenarios=tuple(gen.SCENARIOS), seed=11)
    result = analyze(files_of(tmp_path), RULES)
    found = {(f.rule_id, f.client_ip or "") for f in result.findings}
    expected = {tuple(e) for e in manifest["expected"]}  # type: ignore[attr-defined]
    assert found == expected  # nem faltou detecção, nem sobrou falso positivo
    assert result.stats.unparsed == 0


def test_manifest_file_matches_returned_manifest(tmp_path: Path) -> None:
    manifest = small(tmp_path, scenarios=("sqli", "xss"))
    on_disk = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk["files"] == manifest["files"]
    assert [s["name"] for s in on_disk["scenarios"]] == ["sqli", "xss"]


def test_scenario_data_has_no_real_looking_secrets_or_emails(tmp_path: Path) -> None:
    small(tmp_path, scenarios=tuple(gen.SCENARIOS))
    blob = "".join(p.read_text(encoding="utf-8") for p in files_of(tmp_path))
    assert not re.search(r"[\w.]+@[\w-]+\.(com|org|net|br)\b", blob)
    assert "AKIA" not in blob
