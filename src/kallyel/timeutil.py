"""Leitura de datas informadas pelo usuário em ``--since`` e ``--until``."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone


class TimeParseError(ValueError):
    pass


_OFFSET = re.compile(r"^(?:Z|UTC|(?P<sign>[+-])(?P<h>\d{1,2})(?::?(?P<m>\d{2}))?)$", re.IGNORECASE)


def parse_utc_offset(value: str) -> timedelta:
    """Lê um deslocamento de fuso: ``-03:00``, ``-0300``, ``+5``, ``Z`` ou ``UTC``."""
    m = _OFFSET.match(value.strip())
    if not m:
        raise TimeParseError(
            f"deslocamento de fuso inválido: {value!r} (use, por exemplo, -03:00 ou +0530)"
        )
    if m["sign"] is None:
        return timedelta(0)
    delta = timedelta(hours=int(m["h"]), minutes=int(m["m"] or 0))
    if delta > timedelta(hours=14) or int(m["m"] or 0) > 59:
        raise TimeParseError(f"deslocamento de fuso fora do intervalo permitido: {value!r}")
    return -delta if m["sign"] == "-" else delta


def parse_user_time(value: str) -> datetime:
    """Aceita ISO 8601 (``2024-01-31``, ``2024-01-31T14:30``, com ou sem fuso).

    Sem fuso, assume UTC, o mesmo fuso em que o Kallyel normaliza os eventos.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise TimeParseError(
            f"data inválida: {value!r} (use o formato ISO 8601, ex.: 2024-01-31 ou 2024-01-31T14:30)"
        ) from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
