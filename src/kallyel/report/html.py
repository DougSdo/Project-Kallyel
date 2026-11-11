"""Relatório HTML em arquivo único.

Segurança:

- Jinja2 com ``autoescape=True`` e nenhum uso de ``|safe``; um teste garante isso.
- Sem JavaScript e sem recursos externos (CSS inline). Uma política CSP restritiva
  (``default-src 'none'``) vai no próprio arquivo como segunda camada de defesa.
"""

from __future__ import annotations

from importlib import resources
from typing import Any

from jinja2 import Environment, StrictUndefined

from kallyel.report.data import human_duration, human_time

_TEMPLATE = "report.html.j2"


def _environment() -> Environment:
    env = Environment(
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.globals["time"] = human_time
    env.globals["duration"] = human_duration
    return env


def template_source() -> str:
    return (
        resources.files("kallyel.report")
        .joinpath("templates")
        .joinpath(_TEMPLATE)
        .read_text(encoding="utf-8")
    )


def render_html(report: dict[str, Any]) -> str:
    template = _environment().from_string(template_source())
    return template.render(r=report)
