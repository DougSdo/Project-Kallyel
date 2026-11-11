"""A documentação não pode mentir: gerada, com links válidos e com testes citados que existem."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from kallyel.analysis import analyze
from kallyel.rules import load_builtin_rules
from kallyel.rules.model import PatternRule
from tests.data import render_rules_doc as rd

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
MARKDOWN = [
    ROOT / "README.md",
    *sorted(DOCS.glob("*.md")),
    *sorted((ROOT / "packaging").rglob("*.md")),
]
SUBTITLE = "Kallyel: análise de logs para detecção de ataques web"


# ----------------------------------------------------------- docs/rules.md
def test_rules_doc_is_up_to_date() -> None:
    assert (DOCS / "rules.md").read_text(encoding="utf-8") == rd.render(), (
        "docs/rules.md está desatualizado: rode  python tests/data/render_rules_doc.py --update-docs"
    )


def test_every_rule_is_in_the_rules_doc_with_example_and_mitigation() -> None:
    text = (DOCS / "rules.md").read_text(encoding="utf-8")
    for rule in load_builtin_rules():
        assert f"### {rule.id}" in text
        assert rule.mitigation[:30] in text.replace("\\", "")
        assert rd.EXAMPLES[rule.id]


@pytest.mark.parametrize(
    "rule", [r for r in load_builtin_rules() if isinstance(r, PatternRule)], ids=lambda r: r.id
)
def test_displayed_examples_really_trigger_their_pattern_rule(
    rule: PatternRule, tmp_path: Path
) -> None:
    lines, _ = rd.example_lines(rule.id)
    if "laravel" in rule.sources:  # o registro multilinha é testado nos cenários
        pytest.skip("exemplo de várias linhas")
    f = tmp_path / ("auth.log" if "authlog" in rule.sources else "access.log")
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = analyze([f], [rule])
    assert [x.rule_id for x in result.findings] == [rule.id], lines


# ----------------------------------------------------------------- links
def slug(heading: str) -> str:
    """Âncora no estilo do GitHub: minúsculas, sem pontuação, espaços viram hífens."""
    text = re.sub(r"[^\w\s-]", "", heading.strip().lower())
    return re.sub(r"\s", "-", text)


def anchors(path: Path) -> set[str]:
    in_code = False
    found: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            in_code = not in_code
        elif not in_code and line.startswith("#"):
            found.add(slug(line.lstrip("#")))
    return found


@pytest.mark.parametrize("md", MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_and_anchors_resolve(md: Path) -> None:
    text = md.read_text(encoding="utf-8")
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)  # ignora blocos de código
    broken: list[str] = []
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        file_part, _, fragment = target.partition("#")
        dest = md if not file_part else (md.parent / file_part).resolve()
        if not dest.exists():
            broken.append(target)
            continue
        if fragment and dest.suffix == ".md" and fragment not in anchors(dest):
            broken.append(f"{target} (âncora inexistente)")
    assert not broken, broken


# ------------------------------------------------------------------ README
def test_readme_has_the_required_content() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert SUBTITLE in text  # subtítulo fixo para diferenciar de perfis pessoais
    assert "## O que o Kallyel NÃO detecta" in text
    assert "Triagem, não veredito" in text
    for needle in (
        "pipx install .",
        "kallyel timeline --ip",
        "--fail-on",
        "--no-redact",
        "--show-unparsed",
    ):
        assert needle in text
    for doc in ("rules.md", "avaliacao.md", "threat-model.md", "lab.md"):
        assert f"docs/{doc}" in text


def test_readme_documents_every_cli_flag_that_exists() -> None:
    from typer.main import get_command

    from kallyel.cli import app

    text = (ROOT / "README.md").read_text(encoding="utf-8")
    command = get_command(app)
    analyze_cmd = command.commands["analyze"]  # type: ignore[attr-defined]
    for param in analyze_cmd.params:
        for opt in getattr(param, "opts", []):
            if opt.startswith("--"):
                assert opt in text, f"{opt} não aparece no README"


def test_every_doc_has_the_fixed_subtitle() -> None:
    for name in ("avaliacao.md", "rules.md", "threat-model.md", "lab.md"):
        assert SUBTITLE in (DOCS / name).read_text(encoding="utf-8"), name


def test_lab_guide_contains_no_attack_commands() -> None:
    """O roteiro cita ferramentas pelo nome, mas não pode trazer linhas de comando ofensivas."""
    text = (DOCS / "lab.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```(?:bash|sh)?\n(.*?)```", text, flags=re.DOTALL)
    commands = "\n".join(blocks)
    for tool in (
        "sqlmap",
        "nikto",
        "hydra",
        "gobuster",
        "nmap",
        "metasploit",
        "msfconsole",
        "ffuf",
        "wfuzz",
        "john",
    ):
        assert tool not in commands.lower(), f"comando com {tool} em bloco de código do lab.md"
    assert all(
        line.strip().startswith(("#", "kallyel")) or not line.strip()
        for line in commands.splitlines()
    )
    assert "não contém scripts de ataque" in text


# ----------------------------------------------------------- threat model
def test_every_test_cited_in_the_threat_model_exists() -> None:
    text = (DOCS / "threat-model.md").read_text(encoding="utf-8")
    tests_dir = ROOT / "tests"
    defined = "\n".join(p.read_text(encoding="utf-8") for p in tests_dir.rglob("test_*.py"))
    cited = set(re.findall(r"`(test_[a-z0-9_]+)(\.py)?`", text))
    assert len(cited) > 20
    missing: list[str] = []
    for name, ext in cited:
        if ext:
            if not (tests_dir / f"{name}.py").exists():
                missing.append(f"{name}.py")
        elif f"def {name}(" not in defined:
            missing.append(name)
    assert not missing, f"o modelo de ameaça cita testes que não existem: {missing}"


def test_threat_model_lists_residual_risks() -> None:
    text = (DOCS / "threat-model.md").read_text(encoding="utf-8")
    assert "## Riscos residuais" in text
    assert len(re.findall(r"\*\*R\d+\.", text)) >= 8


# --------------------------------------------------------------- empacotamento
def test_packaging_scripts_are_well_formed() -> None:
    for name in ("build_deb.sh", "smoke_test_deb.sh"):
        data = (ROOT / "packaging" / name).read_bytes()
        assert data.startswith(b"#!/usr/bin/env bash\n"), name
        assert b"\r" not in data, f"{name} tem fim de linha CRLF (quebra no Linux)"
        assert b"set -euo pipefail" in data, name
    assert "*.sh text eol=lf" in (ROOT / ".gitattributes").read_text(encoding="utf-8")


def test_packaging_does_not_invent_a_license() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "license" not in pyproject.lower()
    assert not (ROOT / "LICENSE").exists()
    assert "Ainda não definida" in (ROOT / "README.md").read_text(encoding="utf-8")
