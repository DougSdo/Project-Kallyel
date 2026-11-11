"""Mede o tempo das regras embutidas com entradas patológicas (proteção contra ReDoS)."""

from __future__ import annotations

import time

import pytest

from kallyel.model import Event
from kallyel.rules import Engine, load_builtin_rules
from kallyel.rules.model import PatternRule
from tests.helpers import http_event, text_event

# Linhas são limitadas a 8 KB na leitura; usamos tamanho próximo disso.
SIZE = 8000

PATHOLOGICAL = {
    "letras": "a" * SIZE,
    "espacos": " " * SIZE,
    "espacos-url": "%20" * (SIZE // 3),
    "mais": "+" * SIZE,
    "aspas": "'" * SIZE,
    "aspas-or": "' or " * (SIZE // 5),
    "union": "union" + "%20" * (SIZE // 3),
    "sleep": "sleep(" * (SIZE // 6),
    "pontos": "../" * (SIZE // 3),
    "pontos-url": "%2e%2e%2f" * (SIZE // 9),
    "tags": "<" * SIZE,
    "script": "<script" * (SIZE // 7),
    "ponto-e-virgula": ";" * SIZE,
    "ponto-e-virgula-espaco": "; " * (SIZE // 2),
    "dolar": "$(" * (SIZE // 2),
    "barras": "\\" * SIZE,
    "mistura": "a=1&" * (SIZE // 4),
    "segredos": "password=" * (SIZE // 9),
    "segredos-aspas": "password'" + " " * SIZE,
    "bearer": "Bearer " + "a" * SIZE,
    "base64": "base64:" + "A" * SIZE,
    "chave": "-----BEGIN " * (SIZE // 11),
    "nomes": "DB_PASSWORD " * (SIZE // 12),
    "env": "." * SIZE + "env",
    "wp": "wp-config" * (SIZE // 9),
}

BUDGET_SECONDS = 0.25  # por entrada e por regra; folga ampla para CI lento


def adversarial_event(rule: PatternRule, payload: str) -> Event:
    """Evento que passa pelo filtro ``where`` da regra e leva o payload no campo examinado."""
    source = next(iter(sorted(rule.sources)))
    if source in {"nginx", "apache"}:
        event = http_event("/", source_type=source)
    else:
        event = text_event(source, "x", "")
    for name, allowed in rule.where.checks:
        value = sorted(allowed)[0]
        setattr(event, name, int(value) if name == "http_status" else value)
    if rule.field == "http_path_query":
        event.http_path, event.http_query = "/", payload
    elif rule.field == "http_path":
        event.http_path = "/" + payload
    else:
        setattr(event, rule.field, payload)
    return event


@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_builtin_pattern_rules_stay_fast_on_pathological_input(name: str) -> None:
    payload = PATHOLOGICAL[name]
    rules = [r for r in load_builtin_rules() if isinstance(r, PatternRule)]
    assert len(rules) >= 8
    for rule in rules:
        event = adversarial_event(rule, payload)
        assert rule.where.matches(event), f"{rule.id}: evento adversarial não passa no where"
        assert getattr(event, rule.field) or rule.field == "http_path_query"
        engine = Engine([rule])
        start = time.perf_counter()
        engine.feed(event)
        elapsed = time.perf_counter() - start
        assert elapsed < BUDGET_SECONDS, f"{rule.id} levou {elapsed:.2f}s com entrada '{name}'"


def test_adversarial_event_really_reaches_the_regexes() -> None:
    """Salvaguarda: o payload certo, no campo certo, dispara cada regra de padrão."""
    samples = {
        "KALLYEL-WEB-001": "x=union select 1",
        "KALLYEL-WEB-004": ".env",
        "KALLYEL-WEB-005": "sqlmap",
        "KALLYEL-AUTH-003": "/bin/bash",
        "KALLYEL-APP-001": "DB_PASSWORD=Sup3rS3cret",
    }
    for rule in load_builtin_rules():
        if rule.id in samples and isinstance(rule, PatternRule):
            engine = Engine([rule])
            engine.feed(adversarial_event(rule, samples[rule.id]))
            assert [f.rule_id for f in engine.finish()] == [rule.id]
