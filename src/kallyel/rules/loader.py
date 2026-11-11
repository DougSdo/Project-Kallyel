"""Carrega e valida regras YAML (somente ``yaml.safe_load_all``)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from kallyel.model import PHASES, Severity
from kallyel.rules.model import (
    Condition,
    PatternRule,
    RateRule,
    Rule,
    SequenceRule,
    SequenceStep,
)
from kallyel.rules.safety import has_nested_unbounded_quantifier

MAX_RULE_FILE_BYTES = 256 * 1024
MAX_REGEX_LEN = 500
MAX_REGEXES_PER_RULE = 50

KNOWN_SOURCES = frozenset({"nginx", "apache", "authlog", "laravel"})
WHERE_FIELDS = frozenset({"action", "http_method", "http_status", "source_type", "user"})
MATCH_FIELDS = frozenset(
    {
        "http_path_query",
        "http_path",
        "http_query",
        "user_agent",
        "referrer",
        "message",
        "user",
        "raw",
    }
)
URL_FIELDS = frozenset({"http_path_query", "http_path", "http_query"})

_ID_RE = re.compile(r"^KALLYEL-[A-Z]{2,10}-\d{3}$")
_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_CWE_RE = re.compile(r"^CWE-\d{1,5}$")
_OWASP_RE = re.compile(r"^A\d{2}:\d{4}$")
_DURATION_RE = re.compile(r"^(\d{1,6})([smh])$")
_UNITS = {"s": 1, "m": 60, "h": 3600}

_COMMON_REQUIRED = (
    "id",
    "title",
    "severity",
    "sources",
    "explain",
    "false_positives",
    "mitigation",
)
_COMMON_OPTIONAL = ("type", "attack", "cwe", "owasp", "where", "phase")
_TYPE_KEYS: dict[str, tuple[str, ...]] = {
    "pattern": ("match",),
    "rate": ("rate",),
    "sequence": ("window", "steps"),
}


class RuleError(Exception):
    """Regra inválida. A mensagem já indica arquivo e regra."""


def _fail(origin: str, rule_id: str | None, message: str) -> RuleError:
    where = f"{origin} [{rule_id}]" if rule_id else origin
    return RuleError(f"{where}: {message}")


class _Ctx:
    def __init__(self, origin: str, rule_id: str | None = None) -> None:
        self.origin = origin
        self.rule_id = rule_id

    def err(self, message: str) -> RuleError:
        return _fail(self.origin, self.rule_id, message)


def _check_keys(data: Mapping[str, Any], allowed: set[str], ctx: _Ctx, what: str) -> None:
    unknown = sorted(str(k) for k in data if k not in allowed)
    if unknown:
        raise ctx.err(f"chave(s) desconhecida(s) em {what}: {', '.join(unknown)}")


def _str(data: Mapping[str, Any], key: str, ctx: _Ctx) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ctx.err(f"'{key}' é obrigatório e deve ser um texto não vazio")
    return value.strip()


def _str_list(
    data: Mapping[str, Any], key: str, ctx: _Ctx, pattern: re.Pattern[str]
) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ctx.err(f"'{key}' deve ser uma lista de textos")
    for item in value:
        if not pattern.match(item):
            raise ctx.err(f"valor inválido em '{key}': {item!r}")
    return tuple(value)


def parse_duration(value: Any, ctx: _Ctx, key: str) -> int:
    m = _DURATION_RE.match(value) if isinstance(value, str) else None
    if not m or int(m[1]) == 0:
        raise ctx.err(f"'{key}' inválido: use número + unidade, como 30s, 10m ou 1h")
    return int(m[1]) * _UNITS[m[2]]


def _positive_int(value: Any, ctx: _Ctx, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ctx.err(f"'{key}' deve ser um inteiro maior que zero")
    return value


def _parse_where(value: Any, ctx: _Ctx) -> Condition:
    if value is None:
        return Condition()
    if not isinstance(value, dict):
        raise ctx.err("'where' deve ser um mapa campo -> lista de valores")
    checks: list[tuple[str, frozenset[str]]] = []
    for name, allowed in value.items():
        if name not in WHERE_FIELDS:
            raise ctx.err(
                f"campo '{name}' não permitido em 'where' (use: {', '.join(sorted(WHERE_FIELDS))})"
            )
        values = allowed if isinstance(allowed, list) else [allowed]
        if not values or not all(
            isinstance(v, (str, int)) and not isinstance(v, bool) for v in values
        ):
            raise ctx.err(f"'where.{name}' deve ter um ou mais valores texto/número")
        checks.append((name, frozenset(str(v) for v in values)))
    return Condition(tuple(sorted(checks, key=lambda c: c[0])))


def _compile_patterns(raw: Any, ctx: _Ctx) -> tuple[tuple[str, ...], tuple[re.Pattern[str], ...]]:
    if not isinstance(raw, list) or not raw or not all(isinstance(p, str) for p in raw):
        raise ctx.err("'match.any_regex' deve ser uma lista não vazia de textos")
    if len(raw) > MAX_REGEXES_PER_RULE:
        raise ctx.err(f"'match.any_regex' tem mais de {MAX_REGEXES_PER_RULE} padrões")
    compiled: list[re.Pattern[str]] = []
    for pattern in raw:
        if len(pattern) > MAX_REGEX_LEN:
            raise ctx.err(
                f"regex longa demais (máx. {MAX_REGEX_LEN} caracteres): {pattern[:40]!r}…"
            )
        try:
            compiled.append(re.compile(pattern))
            unsafe = has_nested_unbounded_quantifier(pattern)
        except (re.error, RecursionError, OverflowError) as exc:
            raise ctx.err(f"regex inválida {pattern!r}: {exc}") from exc
        if unsafe:
            raise ctx.err(
                f"regex rejeitada por risco de ReDoS (quantificador ilimitado aninhado): {pattern!r}"
            )
    return tuple(raw), tuple(compiled)


def parse_rule(data: Any, origin: str) -> Rule:
    """Valida um mapa YAML e devolve a regra tipada."""
    ctx = _Ctx(origin)
    if not isinstance(data, dict):
        raise ctx.err("cada regra deve ser um mapa YAML (chave: valor)")
    if isinstance(data.get("id"), str):
        ctx.rule_id = data["id"]

    rule_type = data.get("type", "pattern")
    if rule_type not in _TYPE_KEYS:
        raise ctx.err(f"'type' inválido: {rule_type!r} (use: {', '.join(_TYPE_KEYS)})")
    allowed = set(_COMMON_REQUIRED) | set(_COMMON_OPTIONAL) | set(_TYPE_KEYS[rule_type])
    _check_keys(data, allowed, ctx, f"regra do tipo {rule_type}")
    for key in (*_COMMON_REQUIRED, *_TYPE_KEYS[rule_type]):
        if key not in data:
            raise ctx.err(f"campo obrigatório ausente: '{key}'")

    rule_id = _str(data, "id", ctx)
    if not _ID_RE.match(rule_id):
        raise ctx.err("'id' deve seguir KALLYEL-<CATEGORIA>-<NNN>, ex.: KALLYEL-WEB-001")
    try:
        severity = Severity.parse(_str(data, "severity", ctx))
    except ValueError as exc:
        raise ctx.err(str(exc)) from exc

    sources = data["sources"]
    if not isinstance(sources, list) or not sources or not all(isinstance(s, str) for s in sources):
        raise ctx.err("'sources' deve ser uma lista não vazia")
    unknown = sorted(set(sources) - KNOWN_SOURCES)
    if unknown:
        raise ctx.err(
            f"fonte(s) desconhecida(s): {', '.join(unknown)} (use: {', '.join(sorted(KNOWN_SOURCES))})"
        )

    owasp = data.get("owasp")
    if owasp is not None and (not isinstance(owasp, str) or not _OWASP_RE.match(owasp)):
        raise ctx.err("'owasp' deve ter o formato A03:2021")

    phase = data.get("phase", "attempt")
    if phase not in PHASES:
        raise ctx.err(f"'phase' inválida: {phase!r} (use: {', '.join(PHASES)})")

    common: dict[str, Any] = {
        "phase": phase,
        "id": rule_id,
        "title": _str(data, "title", ctx),
        "severity": severity,
        "sources": frozenset(sources),
        "attack": _str_list(data, "attack", ctx, _ATTACK_RE),
        "cwe": _str_list(data, "cwe", ctx, _CWE_RE),
        "owasp": owasp,
        "explain": _str(data, "explain", ctx),
        "false_positives": _str(data, "false_positives", ctx),
        "mitigation": _str(data, "mitigation", ctx),
        "where": _parse_where(data.get("where"), ctx),
        "origin": origin,
    }

    if rule_type == "pattern":
        return _parse_pattern(data, common, ctx)
    if rule_type == "rate":
        return _parse_rate(data, common, ctx)
    return _parse_sequence(data, common, ctx)


def _parse_pattern(data: Mapping[str, Any], common: dict[str, Any], ctx: _Ctx) -> PatternRule:
    match = data["match"]
    if not isinstance(match, dict):
        raise ctx.err("'match' deve ser um mapa com 'field' e 'any_regex'")
    _check_keys(match, {"field", "any_regex", "url_decode"}, ctx, "'match'")
    field = _str(match, "field", ctx)
    if field not in MATCH_FIELDS:
        raise ctx.err(f"'match.field' inválido: {field!r} (use: {', '.join(sorted(MATCH_FIELDS))})")
    url_decode = match.get("url_decode", field in URL_FIELDS)
    if not isinstance(url_decode, bool):
        raise ctx.err("'match.url_decode' deve ser true ou false")
    patterns, regexes = _compile_patterns(match.get("any_regex"), ctx)
    return PatternRule(
        **common, field=field, patterns=patterns, regexes=regexes, url_decode=url_decode
    )


def _parse_rate(data: Mapping[str, Any], common: dict[str, Any], ctx: _Ctx) -> RateRule:
    rate = data["rate"]
    if not isinstance(rate, dict):
        raise ctx.err("'rate' deve ser um mapa com 'threshold' e 'window'")
    _check_keys(rate, {"threshold", "window"}, ctx, "'rate'")
    if "threshold" not in rate or "window" not in rate:
        raise ctx.err("'rate' exige 'threshold' e 'window'")
    threshold = _positive_int(rate["threshold"], ctx, "rate.threshold")
    window = parse_duration(rate["window"], ctx, "rate.window")
    return RateRule(**common, threshold=threshold, window_s=window)


def _parse_sequence(data: Mapping[str, Any], common: dict[str, Any], ctx: _Ctx) -> SequenceRule:
    window = parse_duration(data["window"], ctx, "window")
    raw_steps = data["steps"]
    if not isinstance(raw_steps, list) or len(raw_steps) < 2:
        raise ctx.err("'steps' deve ter pelo menos 2 etapas")
    steps: list[SequenceStep] = []
    for i, raw in enumerate(raw_steps, start=1):
        if not isinstance(raw, dict):
            raise ctx.err(f"etapa {i} deve ser um mapa")
        _check_keys(raw, {"name", "where", "min_count"}, ctx, f"etapa {i}")
        if "where" not in raw:
            raise ctx.err(f"etapa {i} exige 'where'")
        where = _parse_where(raw["where"], ctx)
        if not where.checks:
            raise ctx.err(f"etapa {i}: 'where' não pode ser vazio")
        steps.append(
            SequenceStep(
                name=_str(raw, "name", ctx),
                where=where,
                min_count=_positive_int(raw.get("min_count", 1), ctx, f"etapa {i} min_count"),
            )
        )
    return SequenceRule(**common, window_s=window, steps=tuple(steps))


def load_rule_file(path: Path) -> list[Rule]:
    """Lê um arquivo YAML (um ou vários documentos ``---``) e valida cada regra."""
    origin = path.name
    try:
        size = path.stat().st_size
        if size > MAX_RULE_FILE_BYTES:
            raise _fail(
                origin, None, f"arquivo grande demais ({size} bytes; máx. {MAX_RULE_FILE_BYTES})"
            )
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise _fail(origin, None, f"não é UTF-8 válido: {exc}") from exc
    except OSError as exc:
        raise _fail(origin, None, f"não foi possível ler: {exc}") from exc
    return _parse_text(text, origin)


def _parse_text(text: str, origin: str) -> list[Rule]:
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise _fail(origin, None, f"YAML inválido: {exc}") from exc
    if not docs:
        raise _fail(origin, None, "arquivo sem nenhuma regra")
    return [parse_rule(doc, origin) for doc in docs]


def load_rules_dir(directory: Path) -> list[Rule]:
    """Carrega todos os ``*.yaml``/``*.yml`` de uma pasta; falha em id duplicado."""
    if not directory.is_dir():
        raise RuleError(f"pasta de regras não encontrada: {directory}")
    files = sorted(p for p in directory.iterdir() if p.suffix in {".yaml", ".yml"} and p.is_file())
    rules: list[Rule] = []
    for file in files:
        rules.extend(load_rule_file(file))
    return ensure_unique(rules)


def load_builtin_rules() -> list[Rule]:
    """Carrega as regras que acompanham o pacote."""
    root = resources.files("kallyel.rules").joinpath("builtin")
    rules: list[Rule] = []
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.name.endswith((".yaml", ".yml")):
            rules.extend(_parse_text(entry.read_text(encoding="utf-8"), entry.name))
    return ensure_unique(rules)


def ensure_unique(rules: list[Rule]) -> list[Rule]:
    seen: dict[str, str] = {}
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"id duplicado {rule.id}: {seen[rule.id]} e {rule.origin}")
        seen[rule.id] = rule.origin
    return rules
