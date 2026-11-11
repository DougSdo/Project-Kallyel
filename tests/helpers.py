"""Utilidades de teste: eventos sintéticos e regras em texto."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from kallyel.model import Event
from kallyel.rules.loader import _parse_text
from kallyel.rules.model import Rule

T0 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def http_event(
    path: str = "/",
    *,
    query: str | None = None,
    ip: str = "203.0.113.10",
    status: int = 200,
    at: float = 0.0,
    ua: str | None = "Mozilla/5.0",
    line_no: int = 1,
    source_type: str = "nginx",
    method: str = "GET",
) -> Event:
    return Event(
        source_type=source_type,
        source_file="access.log",
        line_no=line_no,
        raw=f"{ip} {method} {path}{'?' + query if query else ''} {status}",
        timestamp=T0 + timedelta(seconds=at),
        client_ip=ip,
        http_method=method,
        http_path=path,
        http_query=query,
        http_status=status,
        user_agent=ua,
        action="http.request",
    )


def auth_event(
    action: str,
    *,
    ip: str = "198.51.100.5",
    at: float = 0.0,
    user: str = "root",
    line_no: int = 1,
) -> Event:
    return Event(
        source_type="authlog",
        source_file="auth.log",
        line_no=line_no,
        raw=f"sshd {action} {user} from {ip}",
        timestamp=T0 + timedelta(seconds=at),
        client_ip=ip,
        user=user,
        action=action,
    )


_COMMON = """
severity: medium
sources: [{sources}]
explain: texto
false_positives: texto
mitigation: texto
"""


def rule_from_yaml(body: str, *, sources: str = "nginx") -> Rule:
    text = body + _COMMON.format(sources=sources)
    (rule,) = _parse_text(text, "teste.yaml")
    return rule


def text_event(
    source_type: str,
    action: str,
    message: str,
    *,
    ip: str | None = None,
    at: float = 0.0,
    line_no: int = 1,
) -> Event:
    """Evento de log de aplicação ou de sistema (authlog, laravel) com mensagem livre."""
    return Event(
        source_type=source_type,
        source_file=f"{source_type}.log",
        line_no=line_no,
        raw=message,
        timestamp=T0 + timedelta(seconds=at),
        client_ip=ip,
        action=action,
        message=message,
    )
