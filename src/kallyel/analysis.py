"""Orquestra a análise: leitura, filtros, regras, correlação por IP."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from kallyel.correlate import IpReport, build_ip_reports
from kallyel.model import Event, Finding
from kallyel.netutil import IPNetwork, in_networks, is_private
from kallyel.parsers import ParserOptions, build_parsers
from kallyel.pipeline import IngestStats, iter_events
from kallyel.rules import Engine
from kallyel.rules.model import Rule

MAX_FOCUS_EVENTS = 200_000  # eventos guardados para a linha do tempo de um IP
OUT_OF_ORDER_TOLERANCE = timedelta(seconds=60)


@dataclass(slots=True)
class AnalysisOptions:
    ignore_private: bool = True
    ignore_networks: tuple[IPNetwork, ...] = ()
    since: datetime | None = None
    until: datetime | None = None
    follow_symlinks: bool = False
    focus_ip: str | None = None  # IP para o qual guardar todos os eventos (timeline)
    # Fuso dos logs sem fuso (auth.log tradicional, Laravel): horário local = UTC + este valor.
    log_utc_offset: timedelta = timedelta(0)


@dataclass(slots=True)
class AnalysisResult:
    stats: IngestStats
    findings: list[Finding]
    ip_reports: list[IpReport]
    warnings: list[str] = field(default_factory=list)
    events_analyzed: int = 0
    events_ignored_ip: int = 0  # IPs privados ou ignorados por configuração
    events_out_of_range: int = 0  # fora de --since/--until
    out_of_order: int = 0
    focus_events: list[Event] = field(default_factory=list)

    @property
    def findings_without_ip(self) -> list[Finding]:
        return [f for f in self.findings if f.client_ip is None]


def analyze(
    paths: Iterable[Path],
    rules: Iterable[Rule],
    options: AnalysisOptions | None = None,
    *,
    use_stdin: bool = False,
) -> AnalysisResult:
    opts = options or AnalysisOptions()
    stats = IngestStats()
    engine = Engine(rules)
    result = AnalysisResult(stats=stats, findings=[], ip_reports=[])
    previous: datetime | None = None
    previous_file: str | None = None
    focus_overflow = False
    parsers = build_parsers(ParserOptions(utc_offset=opts.log_utc_offset))

    for event in iter_events(
        paths, stats, use_stdin=use_stdin, follow_symlinks=opts.follow_symlinks, parsers=parsers
    ):
        ts = event.timestamp
        if ts is not None:
            if (opts.since and ts < opts.since) or (opts.until and ts > opts.until):
                result.events_out_of_range += 1
                continue
            if event.source_file != previous_file:  # a ordem só importa dentro de cada arquivo
                previous, previous_file = None, event.source_file
            if previous is not None and previous - ts > OUT_OF_ORDER_TOLERANCE:
                result.out_of_order += 1
            if previous is None or ts > previous:
                previous = ts

        ip = event.client_ip
        is_focus = opts.focus_ip is not None and ip == opts.focus_ip
        if ip is not None and not is_focus and _ignored(ip, opts):
            result.events_ignored_ip += 1
            continue

        result.events_analyzed += 1
        if is_focus:
            if len(result.focus_events) < MAX_FOCUS_EVENTS:
                result.focus_events.append(event)
            else:
                focus_overflow = True
        engine.feed(event)

    result.findings = engine.finish()
    result.ip_reports = build_ip_reports(result.findings)
    result.warnings.extend(engine.warnings)
    if focus_overflow:
        result.warnings.append(
            f"mais de {MAX_FOCUS_EVENTS} eventos para o IP {opts.focus_ip}; "
            "a linha do tempo mostra só os primeiros"
        )
    if result.out_of_order:
        result.warnings.append(
            f"{result.out_of_order} evento(s) fora de ordem cronológica; regras de sequência "
            "podem perder detecções (passe os arquivos rotacionados do mais antigo ao mais novo)"
        )
    if stats.truncated_lines:
        result.warnings.append(
            f"{stats.truncated_lines} linha(s) maiores que o limite foram truncadas; "
            "um payload após o corte não foi examinado"
        )
    for name in stats.skipped_files:
        result.warnings.append(f"formato não reconhecido, arquivo ignorado: {name}")
    return result


def _ignored(ip: str, opts: AnalysisOptions) -> bool:
    if opts.ignore_private and is_private(ip):
        return True
    return bool(opts.ignore_networks) and in_networks(ip, opts.ignore_networks)
