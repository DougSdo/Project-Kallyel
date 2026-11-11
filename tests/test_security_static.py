"""Garantias estáticas da fonte: sem rede, sem execução externa, sem escapes de template.

Examina a árvore sintática (``ast``) de tudo em ``src/kallyel``. São guardas contra regressão:
quem adicionar um ``import socket`` ou um ``eval`` por engano é avisado pelo teste.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kallyel.cli import app
from tests.data import generate as gen

SRC = Path(__file__).resolve().parents[1] / "src" / "kallyel"
SOURCES = sorted(SRC.rglob("*.py"))

NETWORK_MODULES = {
    "socket", "ssl", "http.client", "http.server", "urllib.request", "urllib3", "requests",
    "httpx", "aiohttp", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc",
    "xmlrpc.client", "websockets", "asyncio.streams", "socketserver",
}  # fmt: skip
EXEC_MODULES = {"subprocess", "pickle", "cPickle", "marshal", "shelve", "ctypes", "pty"}
DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__", "input"}
DANGEROUS_ATTRS = {
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execl"), ("os", "spawnl"),
    ("yaml", "load"), ("yaml", "unsafe_load"), ("yaml", "load_all"), ("yaml", "full_load"),
    ("importlib", "import_module"),
}  # fmt: skip


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def imported_modules(tree: ast.Module) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def test_source_tree_is_found() -> None:
    assert len(SOURCES) > 20


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(SRC)))
def test_source_has_no_network_modules(path: Path) -> None:
    mods = imported_modules(parse(path))
    bad = sorted(m for m in mods if m in NETWORK_MODULES or m.split(".")[0] in {"socket", "ssl"})
    assert not bad, f"{path.name} importa módulo de rede: {bad}"


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(SRC)))
def test_source_has_no_dangerous_calls(path: Path) -> None:
    tree = parse(path)
    mods = imported_modules(tree)
    assert not (mods & EXEC_MODULES), f"{path.name} importa {sorted(mods & EXEC_MODULES)}"
    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in DANGEROUS_CALLS:
                problems.append(f"{fn.id}() na linha {node.lineno}")
            if (
                isinstance(fn, ast.Attribute)
                and isinstance(fn.value, ast.Name)
                and (fn.value.id, fn.attr) in DANGEROUS_ATTRS
            ):
                problems.append(f"{fn.value.id}.{fn.attr}() na linha {node.lineno}")
            for kw in node.keywords:
                if kw.arg == "shell" and getattr(kw.value, "value", None) is True:
                    problems.append(f"shell=True na linha {node.lineno}")
    assert not problems, f"{path.name}: {problems}"


def test_only_safe_yaml_loading_is_used() -> None:
    used: set[str] = set()
    for path in SOURCES:
        for node in ast.walk(parse(path)):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "yaml"
            ):
                used.add(node.attr)
    assert "safe_load_all" in used, "o carregador de regras deveria usar yaml.safe_load_all"
    assert used <= {"safe_load_all", "safe_load", "YAMLError"}, used


def test_no_markup_escape_hatches_in_report_code() -> None:
    for path in (SRC / "report").rglob("*"):
        if path.suffix == ".j2":
            # no template (texto): nenhum filtro |safe, nem blocos que desliguem o escape
            text = path.read_text(encoding="utf-8").replace(" ", "")
            assert "|safe" not in text, path.name
            assert "{%raw" not in text and "{%autoescape" not in text, path.name
        elif path.suffix == ".py":
            # no código (árvore sintática): comentários e docstrings podem citar o assunto
            for node in ast.walk(parse(path)):
                if isinstance(node, ast.Call):
                    name = getattr(node.func, "id", getattr(node.func, "attr", ""))
                    assert name != "Markup", f"{path.name}:{node.lineno} usa Markup()"
                    for kw in node.keywords:
                        if kw.arg == "autoescape":
                            assert getattr(kw.value, "value", None) is True, (
                                f"{path.name}:{node.lineno} desliga o autoescape"
                            )


# ------------------------------------------------------------- em execução
def test_analysis_works_with_the_network_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Roda análise completa, em todos os formatos, com qualquer tentativa de conexão falhando."""

    def blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("o Kallyel tentou usar a rede")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)

    gen.write_dataset(
        tmp_path, nginx_lines=2000, auth_lines=300, laravel_lines=100, scenarios=list(gen.SCENARIOS)
    )
    runner = CliRunner()
    for fmt in ("table", "json", "jsonl", "html", "md"):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(tmp_path / "access.log"),
                str(tmp_path / "auth.log"),
                str(tmp_path / "laravel.log"),
                "-f",
                fmt,
            ],
        )
        assert result.exit_code in {0, 1}, (fmt, result.output[-300:])
        assert not isinstance(result.exception, AssertionError), fmt
    ok = runner.invoke(app, ["timeline", "--ip", "203.0.113.201", str(tmp_path / "access.log")])
    assert ok.exit_code == 0
    assert runner.invoke(app, ["rules", "list"]).exit_code == 0


def test_the_guards_themselves_detect_bad_code() -> None:
    """Alimenta os guardas com código ruim de propósito: eles precisam reclamar."""
    bad = ast.parse(
        "import socket\n"
        "from urllib import request\n"
        "import subprocess\n"
        "eval('1')\n"
        "os.system('x')\n"
        "yaml.load(s)\n"
        "run(x, shell=True)\n"
    )
    mods = imported_modules(bad)
    assert {"socket", "urllib.request", "subprocess"} <= mods
    assert mods & NETWORK_MODULES and mods & EXEC_MODULES
    calls = [n for n in ast.walk(bad) if isinstance(n, ast.Call)]
    names = {getattr(c.func, "id", None) for c in calls}
    attrs = {
        (c.func.value.id, c.func.attr)
        for c in calls
        if isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name)
    }
    assert names & DANGEROUS_CALLS
    assert attrs & DANGEROUS_ATTRS == {("os", "system"), ("yaml", "load")}
    assert any(k.arg == "shell" for c in calls for k in c.keywords)
