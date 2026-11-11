"""Linha do tempo de um IP: eventos relevantes em ordem cronológica, com fase.

Eventos sem achado são resumidos ("N requisições sem achado") para a leitura caber
numa tela. Sequências de eventos com o mesmo conjunto de regras viram uma linha só.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

from kallyel.model import Event, Finding
from kallyel.rules.engine import event_phase_for_rule
from kallyel.rules.model import Rule

MAX_ENTRIES = 500
_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class TimelineEntry:
    timestamp: datetime | None
    phase: str | None  # None = contexto, sem achado
    rule_ids: tuple[str, ...]
    description: str
    source_file: str
    line_no: int
    count: int = 1  # eventos agrupados nesta linha
    last_timestamp: datetime | None = None


@dataclass(slots=True)
class Timeline:
    ip: str
    entries: list[TimelineEntry] = field(default_factory=list)
    total_events: int = 0
    truncated: bool = False  # MAX_ENTRIES excedido


def describe(event: Event) -> str:
    """Resumo curto do evento, sem a linha bruta."""
    if event.http_method or event.http_path:
        target = event.http_path or "-"
        if event.http_query:
            target += f"?{event.http_query}"
        status = f" → {event.http_status}" if event.http_status is not None else ""
        return f"{event.http_method or '?'} {target}{status}".strip()
    if event.message:
        return event.message.splitlines()[0]
    return event.action


def _ordered(events: Iterable[Event]) -> list[Event]:
    return sorted(events, key=lambda e: e.timestamp or _EPOCH)


def build_timeline(
    ip: str,
    events: Iterable[Event],
    findings: Iterable[Finding],
    rules: Mapping[str, Rule],
) -> Timeline:
    """Monta a linha do tempo do IP. ``events`` deve conter só eventos desse IP."""
    ip_findings = [f for f in findings if f.client_ip == ip]
    relevant: list[tuple[Rule, Finding]] = [
        (rules[f.rule_id], f) for f in ip_findings if f.rule_id in rules
    ]
    timeline = Timeline(ip=ip)
    pending_quiet = 0
    quiet_first: Event | None = None

    def flush_quiet() -> None:
        nonlocal pending_quiet, quiet_first
        if pending_quiet and quiet_first is not None:
            timeline.entries.append(
                TimelineEntry(
                    timestamp=quiet_first.timestamp,
                    phase=None,
                    rule_ids=(),
                    description=f"{pending_quiet} evento(s) sem achado",
                    source_file=quiet_first.source_file,
                    line_no=quiet_first.line_no,
                    count=pending_quiet,
                )
            )
        pending_quiet, quiet_first = 0, None

    for event in _ordered(events):
        timeline.total_events += 1
        hits: list[tuple[str, str]] = []  # (rule_id, phase)
        for rule, finding in relevant:
            inside = (
                event.timestamp is not None
                and finding.first_seen is not None
                and finding.last_seen is not None
                and finding.first_seen <= event.timestamp <= finding.last_seen
            )
            if not inside:
                continue
            hit_phase = event_phase_for_rule(rule, event)
            if hit_phase is not None:
                hits.append((rule.id, hit_phase))

        phase: str | None = None
        rule_ids = tuple(sorted({rid for rid, _ in hits}))
        if hits:
            phase = _strongest_phase([p for _, p in hits])
        elif event.action == "auth.success":
            phase = "success"
        if phase is None:
            if pending_quiet == 0:
                quiet_first = event
            pending_quiet += 1
            continue

        flush_quiet()
        last = timeline.entries[-1] if timeline.entries else None
        if last is not None and last.phase == phase and last.rule_ids == rule_ids and rule_ids:
            last.count += 1
            last.last_timestamp = event.timestamp
            continue
        timeline.entries.append(
            TimelineEntry(
                timestamp=event.timestamp,
                phase=phase,
                rule_ids=rule_ids,
                description=describe(event),
                source_file=event.source_file,
                line_no=event.line_no,
                last_timestamp=event.timestamp,
            )
        )
    flush_quiet()

    if len(timeline.entries) > MAX_ENTRIES:
        del timeline.entries[MAX_ENTRIES:]
        timeline.truncated = True
    return timeline


def _strongest_phase(phases: list[str]) -> str:
    """Se o evento pertence a mais de uma fase, vale a mais avançada."""
    order = ("recon", "attempt", "success", "action")
    return max(phases, key=lambda p: order.index(p) if p in order else -1)
