"""Agrupa achados por IP e resume as fases do ataque."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from kallyel.correlate.score import RiskScore, phases_in_order, score_findings
from kallyel.model import Finding


@dataclass(frozen=True, slots=True)
class PhaseSpan:
    phase: str
    first_seen: datetime | None
    last_seen: datetime | None
    rule_ids: tuple[str, ...]


@dataclass(slots=True)
class IpReport:
    ip: str
    findings: list[Finding]
    score: RiskScore
    phases: list[PhaseSpan] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def duration(self) -> timedelta | None:
        if self.first_seen is None or self.last_seen is None:
            return None
        return self.last_seen - self.first_seen


def _span(phase: str, findings: list[Finding]) -> PhaseSpan:
    firsts = [f.first_seen for f in findings if f.first_seen]
    lasts = [f.last_seen for f in findings if f.last_seen]
    return PhaseSpan(
        phase=phase,
        first_seen=min(firsts) if firsts else None,
        last_seen=max(lasts) if lasts else None,
        rule_ids=tuple(sorted({f.rule_id for f in findings})),
    )


def build_ip_report(ip: str, findings: list[Finding]) -> IpReport:
    spans = [
        _span(phase, [f for f in findings if f.phase == phase])
        for phase in phases_in_order(findings)
    ]
    firsts = [f.first_seen for f in findings if f.first_seen]
    lasts = [f.last_seen for f in findings if f.last_seen]
    return IpReport(
        ip=ip,
        findings=sorted(findings, key=lambda f: (-int(f.severity), f.rule_id)),
        score=score_findings(findings),
        phases=spans,
        first_seen=min(firsts) if firsts else None,
        last_seen=max(lasts) if lasts else None,
    )


def build_ip_reports(findings: Iterable[Finding]) -> list[IpReport]:
    """Um relatório por IP, do maior risco para o menor. Achados sem IP ficam de fora."""
    by_ip: defaultdict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.client_ip is not None:
            by_ip[f.client_ip].append(f)
    reports = [build_ip_report(ip, items) for ip, items in by_ip.items()]
    return sorted(reports, key=lambda r: (-r.score.total, r.ip))
