"""Relatórios: formatos, mascaramento e resistência a entrada hostil (logs são entrada do atacante)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, ClassVar

import pytest

from kallyel.analysis import AnalysisResult, analyze
from kallyel.redact import Redactor
from kallyel.report import (
    build_report,
    make_console,
    render_html,
    render_json,
    render_jsonl,
    render_markdown,
    render_table,
)
from kallyel.report.html import _environment, template_source
from kallyel.report.markdown import md_block, md_code, md_text
from kallyel.rules import load_builtin_rules

RULES = load_builtin_rules()

HOSTILE_UA = (
    "Nikto/2.1 <script>alert(1)</script> <img src=x onerror=alert(1)> "
    "\x1b[2J \x1b]0;pwned\x07 [bold red]x[/bold red] ``` # INJETADO"
)
HOSTILE_IP = "<img/src=x/onerror=alert(1)>"
SECRET_QUERY = "id=1+UNION+SELECT+1&password=hunter2xyz&mail=ana@example.test"  # noqa: S105 - dado sintetico
FIXED_NOW = datetime(2024, 5, 1, 10, 0, 0, tzinfo=timezone.utc)


def access_line(ip: str, second: int, request: str, status: int, ua: str = "Mozilla/5.0") -> str:
    minute, sec = divmod(second, 60)
    return f'{ip} - - [01/Jan/2024:12:{minute:02d}:{sec:02d} +0000] "{request}" {status} 512 "-" "{ua}"'


def hostile_log(tmp_path: Path, *, with_garbage: bool = False) -> Path:
    lines = [
        access_line("203.0.113.50", i, f"GET /x{i} HTTP/1.1", 404, HOSTILE_UA) for i in range(40)
    ]
    lines += [access_line(HOSTILE_IP, i, f"GET /y{i} HTTP/1.1", 404) for i in range(35)]
    lines.append(access_line("203.0.113.50", 70, f"GET /p?{SECRET_QUERY} HTTP/1.1", 200))
    if with_garbage:
        lines += [
            "linha que não é log password=segredo123 maria@example.test",
            "outra \x1b[31mlinha",
        ]
    f = tmp_path / "access.log"
    f.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    return f


def result_for(tmp_path: Path, **kwargs: bool) -> AnalysisResult:
    return analyze([hostile_log(tmp_path, **kwargs)], RULES)


def report_for(
    tmp_path: Path, *, redact: bool = True, show_unparsed: bool = False
) -> dict[str, Any]:
    result = result_for(tmp_path, with_garbage=True)
    return build_report(
        result, redact=Redactor(enabled=redact), show_unparsed=show_unparsed, now=FIXED_NOW
    )


# ------------------------------------------------------------------ dados
def test_report_data_shape_and_summary(tmp_path: Path) -> None:
    report = report_for(tmp_path)
    s = report["summary"]
    assert s["lines_read"] == 78
    assert s["lines_unparsed"] == 2
    assert s["lines_unparsed_percent"] == pytest.approx(2.56, abs=0.01)
    assert s["findings"] >= 3
    assert report["generated_at"] == "2024-05-01T10:00:00+00:00"
    assert report["redacted"] is True
    assert "triagem" in str(report["disclaimer"])


def test_report_has_no_control_characters_anywhere(tmp_path: Path) -> None:
    text = json.dumps(build_report(result_for(tmp_path), redact=Redactor()), ensure_ascii=False)
    assert "\x1b" not in text and "\x07" not in text
    assert "\\u001b" not in text  # nem como escape JSON: foi neutralizado antes


def test_unparsed_samples_only_with_flag(tmp_path: Path) -> None:
    hidden = report_for(tmp_path, show_unparsed=False)
    shown = report_for(tmp_path, show_unparsed=True)
    assert hidden["unparsed_samples"] == []
    assert len(shown["unparsed_samples"]) == 2
    raw = json.dumps(shown["unparsed_samples"])
    assert "segredo123" not in raw and "maria@example.test" not in raw  # mascarado também aqui


# --------------------------------------------------------------- mascaramento
@pytest.mark.parametrize("fmt", ["json", "jsonl", "md", "html"])
def test_redaction_on_by_default_in_every_format(tmp_path: Path, fmt: str) -> None:
    out = render(report_for(tmp_path), fmt)
    assert "hunter2xyz" not in out
    assert "ana@example.test" not in out


def test_no_redact_shows_data_and_warns(tmp_path: Path) -> None:
    report = report_for(tmp_path, redact=False)
    assert "hunter2xyz" in render_json(report)
    assert "DESLIGADO" in render_markdown(report)
    assert "mascaramento de dados pessoais foi desligado" in render_html(report)


def render(report: dict[str, Any], fmt: str) -> str:
    return {
        "json": render_json,
        "jsonl": render_jsonl,
        "md": render_markdown,
        "html": render_html,
    }[fmt](report)


# ------------------------------------------------------------------- JSON
def test_json_is_valid_and_complete(tmp_path: Path) -> None:
    data = json.loads(render_json(report_for(tmp_path)))
    assert {"tool", "summary", "ips", "findings", "warnings", "disclaimer"} <= set(data)
    finding = data["findings"][0]
    for key in (
        "rule_id",
        "severity",
        "evidence",
        "explain",
        "false_positives",
        "mitigation",
        "attack",
    ):
        assert key in finding
    assert data["ips"][0]["score"]["components"]  # pontuação explicada


def test_jsonl_one_valid_object_per_line(tmp_path: Path) -> None:
    text = render_jsonl(report_for(tmp_path, show_unparsed=True))
    records = [json.loads(line) for line in text.splitlines()]
    assert records[0]["type"] == "summary"
    types = {r["type"] for r in records}
    assert types == {"summary", "ip", "finding", "unparsed"}
    assert all("\n" not in json.dumps(r) for r in records)


# --------------------------------------------------------------------- HTML
class _Balance(HTMLParser):
    VOID: ClassVar[set[str]] = {"meta", "br", "hr", "img", "input", "link"}

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.tags: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.add(tag)
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"</{tag}> inesperado (pilha: {self.stack[-3:]})")
            return
        self.stack.pop()


def test_html_is_well_formed_and_has_no_script_or_external_resources(tmp_path: Path) -> None:
    html = render_html(report_for(tmp_path, show_unparsed=True))
    parser = _Balance()
    parser.feed(html)
    assert parser.errors == [] and parser.stack == []
    assert "script" not in parser.tags and "img" not in parser.tags and "iframe" not in parser.tags
    assert "link" not in parser.tags
    assert not re.search(r"https?://", html)
    assert "@import" not in html and "url(" not in html
    assert not re.search(r'(?:src|href)\s*=\s*"(?!#)', html)
    assert "default-src 'none'" in html  # CSP no próprio arquivo


def test_html_escapes_hostile_user_agent_and_ip(tmp_path: Path) -> None:
    html = render_html(report_for(tmp_path, show_unparsed=True))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img" not in html.lower()
    assert "onerror=alert(1)" in html  # presente, mas só como texto escapado
    assert "\x1b" not in html
    assert "&lt;img/src=x/onerror=alert(1)&gt;" in html  # o "IP" hostil, escapado


def test_html_template_never_disables_escaping() -> None:
    source = template_source()
    assert "|safe" not in source.replace(" ", "")
    assert "autoescape" not in source
    assert "{% raw" not in source
    assert _environment().autoescape is True


def test_html_shows_everything_the_analyst_needs(tmp_path: Path) -> None:
    html = render_html(report_for(tmp_path))
    for expected in (
        "KALLYEL-WEB-007",
        "Falsos positivos prováveis",
        "Mitigação",
        "Como a pontuação foi calculada",
        "linhas NÃO reconhecidas",
        "Triagem, não veredito",
    ):
        assert expected in html


# ----------------------------------------------------------------- Markdown
def test_md_block_fence_cannot_be_closed_by_content() -> None:
    hostile = "linha\n```\n# TÍTULO INJETADO\n<script>x</script>\n````\nfim"
    block = md_block(hostile)
    fence = block.split("\n", 1)[0].removesuffix("text")
    assert set(fence) == {"`"} and len(fence) >= 5  # maior que a maior sequência do conteúdo
    assert block.endswith(fence)
    inner = block[len(fence) + len("text\n") : -len(fence) - 1]
    assert inner == hostile


def test_md_inline_helpers_neutralise_markup() -> None:
    escaped = md_text("<script>x</script> [a](javascript:alert(1)) | **b** `c`")
    # todo caractere especial do Markdown/HTML vem precedido de barra invertida
    assert re.search(r"(?<!\\)[\[\]<>|*`]", escaped) is None
    assert "\\<script\\>" in escaped
    assert md_code("a`b") == "``a`b``"
    assert md_code("`x`").startswith("`` `")
    assert md_code("") == "`  `"  # vazio vira um span só de espaços, ainda válido


def test_markdown_dossier_content_and_hostile_data(tmp_path: Path) -> None:
    md = render_markdown(report_for(tmp_path, show_unparsed=True))
    assert md.startswith("# Dossiê de análise de logs")
    for expected in (
        "## Resumo",
        "## IPs por risco",
        "Como foi calculada",
        "**Motivo:**",
        "**Mitigação:**",
    ):
        assert expected in md
    # IP hostil: só aparece dentro de code span
    assert "`" + HOSTILE_IP + "`" in md
    # nenhuma linha começa com o texto injetado fora de cerca
    assert not any(line.startswith("# INJETADO") for line in md.splitlines())
    assert "\x1b" not in md


# ------------------------------------------------------------------ terminal
def test_table_output_neutralised_and_shows_unparsed_count(tmp_path: Path) -> None:
    console = make_console(width=220)
    with console.capture() as cap:
        render_table(console, report_for(tmp_path, show_unparsed=True))
    out = cap.get()
    assert "\x1b" not in out and "\x07" not in out
    assert "[bold red]x[/bold red]" in out  # marcação do rich não interpretada
    assert "NÃO reconhecidas: 2" in out
    assert "Como a pontuação foi calculada" in out
    assert "Falsos positivos prováveis" in out
    assert "hunter2xyz" not in out
    assert "Linhas não reconhecidas (amostras)" in out


def test_table_with_no_findings_does_not_claim_safety(tmp_path: Path) -> None:
    f = tmp_path / "ok.log"
    f.write_text(access_line("203.0.113.9", 1, "GET / HTTP/1.1", 200) + "\n", encoding="utf-8")
    result = analyze([f], RULES)
    console = make_console(width=200)
    with console.capture() as cap:
        render_table(console, build_report(result, redact=Redactor()))
    assert "Nenhum achado. Isso não prova ausência de ataque." in cap.get()
