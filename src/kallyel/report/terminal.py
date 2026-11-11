"""Saída para o terminal com ``rich``.

Todo texto vindo de log passa por ``neutralize`` (sem ANSI/controle) e por ``Redactor``
antes de ser impresso, e nunca é interpretado como marcação do rich (usa-se ``Text``).
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from kallyel.correlate import IpReport, Timeline
from kallyel.model import PHASE_LABELS
from kallyel.redact import Redactor
from kallyel.sanitize import neutralize

NON_TTY_WIDTH = 200

_PHASE_STYLE = {
    "recon": "cyan",
    "attempt": "yellow",
    "success": "bold red",
    "action": "bold magenta",
}


def make_console(*, width: int | None = None, file: TextIO | None = None) -> Console:
    """Console que não interpreta marcação nem emoji presentes no texto exibido.

    Fora de um terminal (pipe, arquivo), usa linhas largas em vez das 80 colunas padrão,
    para a saída não ser quebrada no meio de URLs e marcadores.
    """
    if file is not None:  # arquivo: sem cores nem códigos de terminal
        return Console(
            file=file,
            markup=False,
            highlight=False,
            emoji=False,
            width=width or NON_TTY_WIDTH,
            force_terminal=False,
            no_color=True,
        )
    if width is None and not sys.stdout.isatty():
        width = NON_TTY_WIDTH
    return Console(markup=False, highlight=False, emoji=False, width=width)


def fmt_time(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "-"


def fmt_duration(value: timedelta | None) -> str:
    if value is None:
        return "-"
    seconds = int(value.total_seconds())
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def safe_text(value: str | None, redact: Redactor) -> str:
    """Texto de log pronto para imprimir: controles neutralizados, dados pessoais mascarados."""
    return redact(neutralize(value or ""))


def render_score(console: Console, report: IpReport) -> None:
    score = report.score
    console.print(Text(f"Pontuação de risco: {score.total}/100 ({score.band})", style="bold"))
    for comp in score.components:
        console.print(Text(f"  +{comp.points:<3} {comp.label}: {comp.detail}"))
    if score.capped:
        console.print(Text(f"  Soma {score.raw}, limitada a 100."))


def render_timeline(
    console: Console,
    timeline: Timeline,
    report: IpReport | None,
    redact: Redactor,
    *,
    warnings: list[str] | None = None,
) -> None:
    ip = safe_text(timeline.ip, redact)
    console.print(Text(f"Linha do tempo de {ip}", style="bold"))

    if report is not None:
        chain = " → ".join(PHASE_LABELS.get(s.phase, s.phase) for s in report.phases)
        console.print(
            Text(
                f"Período dos achados: {fmt_time(report.first_seen)} → {fmt_time(report.last_seen)} UTC "
                f"(duração {fmt_duration(report.duration)})"
            )
        )
        console.print(Text(f"Fases: {chain or '-'}"))
    console.print(Text(f"Eventos deste IP analisados: {timeline.total_events}"))
    console.print()

    if not timeline.entries:
        console.print(Text("Nenhum evento encontrado para este IP no período analisado."))
    else:
        table = Table(show_lines=False, header_style="bold")
        for column in ("Hora (UTC)", "Fase", "Regra(s)", "Evento (arquivo:linha)"):
            table.add_column(column, overflow="fold")
        for entry in timeline.entries:
            phase = entry.phase
            description = safe_text(entry.description, redact)
            if entry.count > 1 and entry.phase is not None:
                until = f", até {fmt_time(entry.last_timestamp)}" if entry.last_timestamp else ""
                description += f"  (×{entry.count}{until})"
            where = safe_text(f"{entry.source_file}:{entry.line_no}", redact)
            table.add_row(
                Text(fmt_time(entry.timestamp)),
                Text(
                    PHASE_LABELS.get(phase, phase) if phase else "-",
                    style=_PHASE_STYLE.get(phase or "", "dim"),
                ),
                Text(", ".join(entry.rule_ids) or "-"),
                Text(f"{description}\n{where}"),
            )
        console.print(table)
        if timeline.truncated:
            console.print(
                Text("Linha do tempo truncada: há mais entradas do que o limite exibido.")
            )

    if report is not None:
        console.print()
        render_score(console, report)
    for warning in warnings or []:
        console.print(Text(f"Aviso: {safe_text(warning, redact)}", style="yellow"))
