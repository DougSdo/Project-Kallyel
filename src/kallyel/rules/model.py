"""Estruturas imutáveis que representam regras já validadas."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from kallyel.model import Event, Severity


@dataclass(frozen=True, slots=True)
class Condition:
    """Filtro simples: cada campo do evento deve ter um dos valores permitidos."""

    checks: tuple[tuple[str, frozenset[str]], ...] = ()

    def matches(self, event: Event) -> bool:
        if not self.checks:
            return True
        return all(str(getattr(event, name)) in allowed for name, allowed in self.checks)


@dataclass(frozen=True, kw_only=True)
class Rule:
    id: str
    title: str
    severity: Severity
    sources: frozenset[str]
    attack: tuple[str, ...]
    cwe: tuple[str, ...]
    owasp: str | None
    explain: str
    false_positives: str
    mitigation: str
    where: Condition
    origin: str  # arquivo de onde a regra veio
    phase: str = "attempt"  # fase do ataque: recon, attempt, success ou action

    kind: ClassVar[str] = "base"


@dataclass(frozen=True, kw_only=True)
class PatternRule(Rule):
    field: str
    patterns: tuple[str, ...]
    regexes: tuple[re.Pattern[str], ...]
    url_decode: bool

    kind: ClassVar[str] = "pattern"


@dataclass(frozen=True, kw_only=True)
class RateRule(Rule):
    threshold: int
    window_s: int

    kind: ClassVar[str] = "rate"


@dataclass(frozen=True, kw_only=True)
class SequenceStep:
    name: str
    where: Condition
    min_count: int


@dataclass(frozen=True, kw_only=True)
class SequenceRule(Rule):
    window_s: int
    steps: tuple[SequenceStep, ...]

    kind: ClassVar[str] = "sequence"
