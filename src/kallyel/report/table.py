"""Saída em tabela para o terminal (a partir dos dados já higienizados do relatório).

Os textos são ``Text`` do rich (sem interpretação de marcação) e já passaram por
``neutralize`` e pelo mascaramento em ``build_report``.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from kallyel.report.data import human_duration, human_time

_SEV_STYLE = {"low": "green", "medium": "yellow", "high": "dark_orange", "critical": "bold red"}
_BAND_STYLE = {"baixo": "green", "médio": "yellow", "alto": "dark_orange", "crítico": "bold red"}
EVIDENCE_LINES_IN_TABLE = 3


def _p(console: Console, value: str = "", style: str = "") -> None:
    console.print(Text(value, style=style))


def render_table(console: Console, report: dict[str, Any]) -> None:
    s = report["summary"]
    _p(console, "Kallyel: análise de logs para detecção de ataques web", "bold")
    _p(
        console,
        f"Gerado em {human_time(report['generated_at'])} UTC · versão {report['tool']['version']}",
    )
    _p(console)
    _p(
        console,
        f"Arquivos: {s['files']}  Linhas lidas: {s['lines_read']}  Reconhecidas: {s['lines_parsed']}  "
        f"NÃO reconhecidas: {s['lines_unparsed']} ({s['lines_unparsed_percent']}%)  "
        f"Truncadas: {s['lines_truncated']}",
    )
    _p(
        console,
        f"Eventos analisados: {s['events_analyzed']}  Ignorados (IP privado/configurado): "
        f"{s['events_ignored_ip']}  Fora do período: {s['events_out_of_range']}",
    )
    _p(console, f"Achados: {s['findings']}  IPs com achados: {s['ips_with_findings']}", "bold")
    if not report["redacted"]:
        _p(
            console,
            "ATENÇÃO: mascaramento DESLIGADO (--no-redact); a saída pode conter dados pessoais.",
            "bold red",
        )
    for warning in report["warnings"]:
        _p(console, f"Aviso: {warning}", "yellow")

    if not report["findings"]:
        _p(console)
        _p(console, "Nenhum achado. Isso não prova ausência de ataque.")
    else:
        _ranking(console, report)
        by_ip: dict[str | None, list[dict[str, Any]]] = {}
        for f in report["findings"]:
            by_ip.setdefault(f["client_ip"], []).append(f)
        for ip in report["ips"]:
            _ip_block(console, ip, by_ip.get(ip["ip"], []))
        orphans = by_ip.get(None, [])
        if orphans:
            _p(console)
            _p(console, "Achados sem IP associado", "bold")
            for f in orphans:
                _finding(console, f)

    if report["unparsed_samples_shown"]:
        _p(console)
        _p(console, "Linhas não reconhecidas (amostras)", "bold")
        for u in report["unparsed_samples"] or []:
            _p(console, f"  {u['source_file']}:{u['line_no']}  {u['raw']}")
        if not report["unparsed_samples"]:
            _p(console, "  Nenhuma.")
    elif s["lines_unparsed"]:
        _p(console)
        _p(console, "Há linhas não reconhecidas; use --show-unparsed para ver amostras.", "dim")

    _p(console)
    _p(console, report["disclaimer"], "dim")


def _ranking(console: Console, report: dict[str, Any]) -> None:
    if not report["ips"]:
        return
    _p(console)
    table = Table(title="IPs por risco", header_style="bold", title_justify="left")
    for col in ("#", "IP", "Risco", "Fases", "Regras", "Período (UTC)"):
        table.add_column(col, overflow="fold")
    for i, ip in enumerate(report["ips"], start=1):
        score = ip["score"]
        table.add_row(
            Text(str(i)),
            Text(ip["ip"]),
            Text(
                f"{score['total']}/100 ({score['band']})", style=_BAND_STYLE.get(score["band"], "")
            ),
            Text(" → ".join(p["label"] for p in ip["phases"]) or "-"),
            Text(str(len(ip["rule_ids"]))),
            Text(f"{human_time(ip['first_seen'])} a {human_time(ip['last_seen'])}"),
        )
    console.print(table)


def _ip_block(console: Console, ip: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    score = ip["score"]
    _p(console)
    _p(console, f"IP {ip['ip']}: risco {score['total']}/100 ({score['band']})", "bold")
    _p(
        console,
        f"  Período {human_time(ip['first_seen'])} a {human_time(ip['last_seen'])} "
        f"(duração {human_duration(ip['duration_seconds'])})",
    )
    _p(console, "  Como a pontuação foi calculada:")
    for comp in score["components"]:
        _p(console, f"    +{comp['points']:<3} {comp['label']}: {comp['detail']}")
    if score["capped"]:
        _p(console, f"    Soma {score['raw']}, limitada a 100.")
    for f in findings:
        _finding(console, f)


def _finding(console: Console, f: dict[str, Any]) -> None:
    _p(console)
    _p(
        console,
        f"  [{f['severity_label']}] {f['rule_id']}: {f['title']}",
        _SEV_STYLE.get(f["severity"], ""),
    )
    _p(
        console,
        f"    {f['count']} ocorrência(s), de {human_time(f['first_seen'])} a "
        f"{human_time(f['last_seen'])}; fase: {f['phase_label']}",
    )
    if f["detail"]:
        _p(console, f"    Critério: {f['detail']}")
    refs = [*f["attack"], *f["cwe"], *([f["owasp"]] if f["owasp"] else [])]
    if refs:
        _p(console, f"    Mapeamento: {', '.join(refs)}")
    _p(console, f"    Motivo: {f['explain']}")
    _p(console, f"    Falsos positivos prováveis: {f['false_positives']}")
    _p(console, f"    Mitigação: {f['mitigation']}")
    shown = f["evidence"][:EVIDENCE_LINES_IN_TABLE]
    for e in shown:
        raw_lines = e["raw"].split("\n")
        _p(console, f"    · {e['source_file']}:{e['line_no']}  {raw_lines[0]}", "dim")
        for extra in raw_lines[1:EVIDENCE_LINES_IN_TABLE]:  # trecho de várias linhas (stack trace)
            _p(console, f"        {extra}", "dim")
    if len(f["evidence"]) > len(shown):
        _p(
            console,
            f"    · (+{len(f['evidence']) - len(shown)} evidência(s); use --format json, html ou md)",
            "dim",
        )
