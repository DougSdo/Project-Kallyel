"""Registro e detecção automática de parsers."""

from __future__ import annotations

from collections.abc import Sequence

from kallyel.parsers.authlog import AuthLogParser
from kallyel.parsers.base import LineParser, Parser, ParserOptions
from kallyel.parsers.combined import CombinedParser
from kallyel.parsers.laravel import LaravelParser

SNIFF_THRESHOLD = 0.5


def build_parsers(options: ParserOptions | None = None) -> tuple[Parser, ...]:
    """Cria os parsers com os ajustes de fuso e de referência de ano informados."""
    opts = options or ParserOptions()
    return (CombinedParser(), AuthLogParser(opts), LaravelParser(opts))


PARSERS: tuple[Parser, ...] = build_parsers()


def detect_parser(sample: Sequence[str], parsers: Sequence[Parser] | None = None) -> Parser | None:
    """Escolhe o parser que reconhece a maior fração da amostra (mínimo 50%)."""
    best: Parser | None = None
    best_score = 0.0
    for parser in PARSERS if parsers is None else parsers:
        score = parser.sniff(sample)
        if score > best_score:
            best, best_score = parser, score
    return best if best_score >= SNIFF_THRESHOLD else None


__all__ = [
    "PARSERS",
    "SNIFF_THRESHOLD",
    "AuthLogParser",
    "CombinedParser",
    "LaravelParser",
    "LineParser",
    "Parser",
    "ParserOptions",
    "build_parsers",
    "detect_parser",
]
