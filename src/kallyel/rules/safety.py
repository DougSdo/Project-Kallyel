"""Verificação estática de regex contra ReDoS (heurística, não prova).

Rejeita quantificadores ilimitados aninhados, como ``(a+)+`` ou ``(.*)*``, a causa
mais comum de backtracking exponencial. Não detecta todos os casos (por exemplo,
alternâncias sobrepostas como ``(a|a)*``); por isso o projeto também limita o
tamanho das linhas e mede o tempo das regras com entradas patológicas nos testes.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

try:  # Python 3.11+
    from re import _parser as _sre_parse  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - Python 3.10
    import sre_parse as _sre_parse

_REPEAT_OPS = {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}


def _subpatterns(value: Any) -> Iterator[Any]:
    if isinstance(value, _sre_parse.SubPattern):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _subpatterns(item)


def _nested_unbounded(pattern: Any, inside_unbounded: bool = False) -> bool:
    for op, av in pattern.data:
        if str(op) in _REPEAT_OPS:
            _lo, hi, sub = av
            unbounded = hi == _sre_parse.MAXREPEAT
            if unbounded and inside_unbounded:
                return True
            if _nested_unbounded(sub, inside_unbounded or unbounded):
                return True
        else:
            for child in _subpatterns(av):
                if _nested_unbounded(child, inside_unbounded):
                    return True
    return False


def has_nested_unbounded_quantifier(pattern: str) -> bool:
    """Verdadeiro se a regex tem um quantificador ilimitado dentro de outro."""
    return bool(_nested_unbounded(_sre_parse.parse(pattern)))
