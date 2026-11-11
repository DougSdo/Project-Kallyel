"""Saídas estruturadas: JSON e JSON Lines."""

from __future__ import annotations

import json
from typing import Any


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"


def render_jsonl(report: dict[str, Any]) -> str:
    """Uma linha JSON por registro, com campo ``type``: summary, ip, finding ou unparsed.

    Pensado para ingestão linha a linha em outras ferramentas.
    """
    records: list[dict[str, Any]] = [
        {
            "type": "summary",
            "tool": report["tool"],
            "generated_at": report["generated_at"],
            "redacted": report["redacted"],
            "summary": report["summary"],
            "warnings": report["warnings"],
        }
    ]
    records += [{"type": "ip", **ip} for ip in report["ips"]]
    records += [{"type": "finding", **f} for f in report["findings"]]
    records += [{"type": "unparsed", **u} for u in report["unparsed_samples"]]
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
