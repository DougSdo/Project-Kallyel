"""Constrói os dados do relatório, uma única vez, já higienizados e mascarados.

Todos os formatos de saída (tabela, JSON, JSONL, HTML, Markdown) partem deste dicionário.
Assim, o tratamento de entrada hostil acontece em um só lugar: todo texto que veio de log
passa por ``neutralize`` (sem ANSI/controle) e por ``Redactor`` (dados pessoais).

O relatório nunca inclui corpo de requisição: os formatos suportados não o registram.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kallyel import __version__
from kallyel.analysis import AnalysisResult
from kallyel.correlate import IpReport
from kallyel.model import PHASE_LABELS, Evidence, Finding
from kallyel.redact import Redactor
from kallyel.sanitize import neutralize

SEVERITY_LABEL_PT = {"low": "baixa", "medium": "média", "high": "alta", "critical": "crítica"}

DISCLAIMER = (
    "Este relatório é uma triagem automática, não um veredito. Regras por padrão geram "
    "falsos positivos e não cobrem todos os ataques; confirme cada achado nos logs "
    "originais antes de agir."
)


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def human_time(value: str | None) -> str:
    """``2024-01-01T12:00:00+00:00`` -> ``2024-01-01 12:00:00``."""
    if not value:
        return "-"
    return value.replace("T", " ")[:19]


def human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    total = int(seconds)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


class _Cleaner:
    def __init__(self, redact: Redactor) -> None:
        self._redact = redact

    def line(self, value: str | None) -> str:
        """Texto de log em uma linha."""
        return self._redact(neutralize(value or ""))

    def block(self, value: str | None) -> str:
        """Texto de log que pode ter várias linhas (stack trace)."""
        return self._redact(neutralize(value or "", keep_newlines=True))

    @staticmethod
    def rule(value: str | None) -> str:
        """Texto que vem das regras: sem mascaramento, mas sem controles."""
        return neutralize(value or "", keep_newlines=True)


def _evidence(e: Evidence, c: _Cleaner) -> dict[str, Any]:
    return {
        "source_file": c.line(e.source_file),
        "line_no": e.line_no,
        "timestamp": iso(e.timestamp),
        "raw": c.block(e.raw),
    }


def _finding(f: Finding, c: _Cleaner) -> dict[str, Any]:
    return {
        "rule_id": c.rule(f.rule_id),
        "title": c.rule(f.title),
        "severity": f.severity.label,
        "severity_label": SEVERITY_LABEL_PT[f.severity.label],
        "phase": f.phase,
        "phase_label": PHASE_LABELS.get(f.phase, f.phase),
        "client_ip": c.line(f.client_ip) if f.client_ip else None,
        "count": f.count,
        "first_seen": iso(f.first_seen),
        "last_seen": iso(f.last_seen),
        "detail": c.rule(f.detail),
        "attack": [c.rule(a) for a in f.attack],
        "cwe": [c.rule(x) for x in f.cwe],
        "owasp": c.rule(f.owasp) if f.owasp else None,
        "explain": c.rule(f.explain),
        "false_positives": c.rule(f.false_positives),
        "mitigation": c.rule(f.mitigation),
        "evidence": [_evidence(e, c) for e in f.evidence],
    }


def _ip(report: IpReport, c: _Cleaner) -> dict[str, Any]:
    duration = report.duration
    return {
        "ip": c.line(report.ip),
        "score": {
            "total": report.score.total,
            "raw": report.score.raw,
            "capped": report.score.capped,
            "band": report.score.band,
            "components": [
                {"label": c.rule(k.label), "points": k.points, "detail": c.rule(k.detail)}
                for k in report.score.components
            ],
        },
        "highest_severity": report.findings[0].severity.label if report.findings else None,
        "first_seen": iso(report.first_seen),
        "last_seen": iso(report.last_seen),
        "duration_seconds": duration.total_seconds() if duration else None,
        "phases": [
            {
                "phase": s.phase,
                "label": PHASE_LABELS.get(s.phase, s.phase),
                "first_seen": iso(s.first_seen),
                "last_seen": iso(s.last_seen),
                "rules": [c.rule(r) for r in s.rule_ids],
            }
            for s in report.phases
        ],
        "rule_ids": sorted({c.rule(f.rule_id) for f in report.findings}),
    }


def build_report(
    result: AnalysisResult,
    *,
    redact: Redactor,
    show_unparsed: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    c = _Cleaner(redact)
    stats = result.stats
    findings = [_finding(f, c) for f in result.findings]
    highest = result.findings[0].severity.label if result.findings else None
    unparsed_pct = round(100 * stats.unparsed / stats.lines, 2) if stats.lines else 0.0
    return {
        "tool": {"name": "kallyel", "version": __version__},
        "generated_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "redacted": redact.enabled,
        "disclaimer": DISCLAIMER,
        "summary": {
            "files": stats.files,
            "lines_read": stats.lines,
            "lines_parsed": stats.parsed,
            "lines_unparsed": stats.unparsed,
            "lines_unparsed_percent": unparsed_pct,
            "lines_truncated": stats.truncated_lines,
            "files_unrecognised": [c.line(n) for n in stats.skipped_files],
            "events_analyzed": result.events_analyzed,
            "events_ignored_ip": result.events_ignored_ip,
            "events_out_of_range": result.events_out_of_range,
            "findings": len(findings),
            "ips_with_findings": len(result.ip_reports),
            "highest_severity": highest,
        },
        "warnings": [c.line(w) for w in result.warnings],
        "ips": [_ip(r, c) for r in result.ip_reports],
        "findings": findings,
        "unparsed_samples": [
            {"source_file": c.line(e.source_file), "line_no": e.line_no, "raw": c.line(e.raw)}
            for e in stats.unparsed_samples
        ]
        if show_unparsed
        else [],
        "unparsed_samples_shown": show_unparsed,
    }
