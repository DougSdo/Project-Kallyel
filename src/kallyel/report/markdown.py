"""Dossiê em Markdown.

Texto vindo de log nunca é escrito solto: IPs e caminhos vão em ``code span`` e evidências
em bloco de código com cerca maior que qualquer sequência de crases do conteúdo, para o
atacante não conseguir "fechar" o bloco e injetar Markdown ou HTML.
"""

from __future__ import annotations

import re
from typing import Any

from kallyel.report.data import human_duration, human_time

_SPECIAL = re.compile(r"([\\`*_\[\]<>|&#~])")
_BACKTICKS = re.compile(r"`+")


def md_text(value: str) -> str:
    """Escapa caracteres especiais do Markdown (e de HTML) em texto corrido."""
    return _SPECIAL.sub(r"\\\1", value).replace("\n", " ")


def md_code(value: str) -> str:
    """Texto em ``code span``, seguro para qualquer conteúdo."""
    value = value.replace("\n", " ")
    longest = max((len(m.group()) for m in _BACKTICKS.finditer(value)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if value.startswith("`") or value.endswith("`") or not value else ""
    return f"{ticks}{pad}{value}{pad}{ticks}"


def md_block(value: str) -> str:
    """Bloco de código cercado, com cerca à prova de conteúdo."""
    longest = max((len(m.group()) for m in _BACKTICKS.finditer(value)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{value}\n{fence}"


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    out: list[str] = []
    add = out.append

    add("# Dossiê de análise de logs: Kallyel")
    add("")
    add("_Kallyel: análise de logs para detecção de ataques web_")
    add("")
    add(f"> **Aviso:** {md_text(report['disclaimer'])}")
    add("")
    add(
        f"Gerado em {md_code(human_time(report['generated_at']) + ' UTC')} por Kallyel {report['tool']['version']}."
    )
    if not report["redacted"]:
        add("")
        add(
            "**Atenção: o mascaramento de dados pessoais foi DESLIGADO (`--no-redact`). "
            "Trate este arquivo como dado sensível.**"
        )
    add("")
    add("## Resumo")
    add("")
    add("| Item | Valor |")
    add("|---|---|")
    rows = [
        ("Arquivos lidos", s["files"]),
        ("Linhas lidas", s["lines_read"]),
        ("Linhas reconhecidas", s["lines_parsed"]),
        ("Linhas NÃO reconhecidas", f"{s['lines_unparsed']} ({s['lines_unparsed_percent']}%)"),
        ("Linhas truncadas (acima do limite)", s["lines_truncated"]),
        ("Eventos analisados", s["events_analyzed"]),
        ("Eventos ignorados (IP privado ou configurado)", s["events_ignored_ip"]),
        ("Eventos fora do período", s["events_out_of_range"]),
        ("Achados", s["findings"]),
        ("IPs com achados", s["ips_with_findings"]),
    ]
    for label, value in rows:
        add(f"| {label} | {value} |")
    add("")

    if report["warnings"]:
        add("## Avisos")
        add("")
        for w in report["warnings"]:
            add(f"- {md_text(w)}")
        add("")

    findings_by_ip: dict[str | None, list[dict[str, Any]]] = {}
    for f in report["findings"]:
        findings_by_ip.setdefault(f["client_ip"], []).append(f)

    if report["ips"]:
        add("## IPs por risco")
        add("")
        add("| # | IP | Risco | Fases | Regras | Período (UTC) |")
        add("|---|---|---|---|---|---|")
        for i, ip in enumerate(report["ips"], start=1):
            phases = " → ".join(p["label"] for p in ip["phases"])
            period = f"{human_time(ip['first_seen'])} a {human_time(ip['last_seen'])}"
            add(
                f"| {i} | {md_code(ip['ip'])} | {ip['score']['total']}/100 ({ip['score']['band']}) "
                f"| {md_text(phases)} | {len(ip['rule_ids'])} | {md_text(period)} |"
            )
        add("")
        for i, ip in enumerate(report["ips"], start=1):
            add(f"## {i}. IP {md_code(ip['ip'])}")
            add("")
            score = ip["score"]
            add(
                f"**Pontuação de risco: {score['total']}/100 ({score['band']}).** Como foi calculada:"
            )
            add("")
            for comp in score["components"]:
                add(f"- +{comp['points']} **{md_text(comp['label'])}**: {md_text(comp['detail'])}")
            if score["capped"]:
                add(f"- Soma {score['raw']}, limitada a 100.")
            add("")
            chain = " → ".join(p["label"] for p in ip["phases"]) or "-"
            add(
                f"Período: {md_code(human_time(ip['first_seen']))} a {md_code(human_time(ip['last_seen']))} "
                f"(duração {human_duration(ip['duration_seconds'])}). Fases: {md_text(chain)}."
            )
            add("")
            for f in findings_by_ip.get(ip["ip"], []):
                _finding(out, f, level=3)

    orphans = findings_by_ip.get(None, [])
    if orphans:
        add("## Achados sem IP associado")
        add("")
        for f in orphans:
            _finding(out, f, level=3)

    if report["unparsed_samples_shown"]:
        add("## Linhas não reconhecidas (amostras)")
        add("")
        if not report["unparsed_samples"]:
            add("Nenhuma.")
            add("")
        for u in report["unparsed_samples"]:
            add(f"{md_code(u['source_file'] + ':' + str(u['line_no']))}")
            add("")
            add(md_block(u["raw"]))
            add("")
    elif s["lines_unparsed"]:
        add("_Há linhas não reconhecidas; use `--show-unparsed` para ver amostras._")
        add("")

    return "\n".join(out).rstrip() + "\n"


def _finding(out: list[str], f: dict[str, Any], *, level: int) -> None:
    add = out.append
    add(f"{'#' * level} [{f['severity_label']}] {md_code(f['rule_id'])} {md_text(f['title'])}")
    add("")
    refs = [*f["attack"], *f["cwe"], *([f["owasp"]] if f["owasp"] else [])]
    add(
        f"- **Ocorrências:** {f['count']}; de {md_code(human_time(f['first_seen']))} a {md_code(human_time(f['last_seen']))}; fase: {md_text(f['phase_label'])}"
    )
    if f["detail"]:
        add(f"- **Critério:** {md_text(f['detail'])}")
    if refs:
        add(f"- **Mapeamento:** {md_text(', '.join(refs))}")
    add(f"- **Motivo:** {md_text(f['explain'])}")
    add(f"- **Falsos positivos prováveis:** {md_text(f['false_positives'])}")
    add(f"- **Mitigação:** {md_text(f['mitigation'])}")
    add("")
    if f["evidence"]:
        add(f"**Evidências** (até {len(f['evidence'])} de {f['count']}):")
        add("")
        for e in f["evidence"]:
            add(
                f"{md_code(e['source_file'] + ':' + str(e['line_no']))} às {md_code(human_time(e['timestamp']))}"
            )
            add("")
            add(md_block(e["raw"]))
            add("")
