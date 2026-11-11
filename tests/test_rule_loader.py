from pathlib import Path

import pytest

from kallyel.model import Severity
from kallyel.rules import (
    PatternRule,
    RateRule,
    RuleError,
    SequenceRule,
    load_builtin_rules,
    load_rule_file,
    load_rules_dir,
)
from kallyel.rules.safety import has_nested_unbounded_quantifier

VALID = """\
id: KALLYEL-TST-001
title: Teste
severity: high
sources: [nginx]
attack: [T1190]
cwe: [CWE-89]
owasp: "A03:2021"
match:
  field: http_path_query
  any_regex: ['union\\s+select']
explain: x
false_positives: y
mitigation: z
"""


ORIG = r"['union\s+select']"  # como aparece no YAML acima


def write(tmp_path: Path, text: str, name: str = "r.yaml") -> Path:
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return f


def test_valid_pattern_rule(tmp_path: Path) -> None:
    (rule,) = load_rule_file(write(tmp_path, VALID))
    assert isinstance(rule, PatternRule)
    assert rule.severity is Severity.HIGH
    assert rule.url_decode is True  # padrão para campos de URL
    assert rule.attack == ("T1190",)


def test_builtin_rules_load() -> None:
    rules = load_builtin_rules()
    assert any(r.id == "KALLYEL-WEB-001" for r in rules)


def test_rate_and_sequence_rules(tmp_path: Path) -> None:
    text = """\
id: KALLYEL-TST-002
title: Taxa
type: rate
severity: medium
sources: [nginx]
where: {http_status: [404]}
rate: {threshold: 30, window: 1m}
explain: x
false_positives: y
mitigation: z
---
id: KALLYEL-TST-003
title: Sequência
type: sequence
severity: critical
sources: [authlog]
window: 15m
steps:
  - {name: falhas, where: {action: [auth.failure]}, min_count: 5}
  - {name: sucesso, where: {action: [auth.success]}}
explain: x
false_positives: y
mitigation: z
"""
    rate, seq = load_rule_file(write(tmp_path, text))
    assert isinstance(rate, RateRule)
    assert (rate.threshold, rate.window_s) == (30, 60)
    assert isinstance(seq, SequenceRule)
    assert seq.window_s == 900
    assert [s.min_count for s in seq.steps] == [5, 1]


@pytest.mark.parametrize(
    ("mutation", "fragment"),
    [
        (lambda s: s.replace("id: KALLYEL-TST-001", "id: abc"), "KALLYEL-<CATEGORIA>"),
        (lambda s: s.replace("severity: high", "severity: enorme"), "gravidade inválida"),
        (lambda s: s.replace("sources: [nginx]", "sources: [iis]"), "fonte(s) desconhecida(s)"),
        (lambda s: s.replace("attack: [T1190]", "attack: [XYZ]"), "valor inválido em 'attack'"),
        (lambda s: s.replace("A03:2021", "OWASP-3"), "A03:2021"),
        (lambda s: s.replace("explain: x\n", ""), "campo obrigatório ausente: 'explain'"),
        (lambda s: s + "extra: 1\n", "desconhecida"),
        (lambda s: s.replace("http_path_query", "body"), "match.field"),
        (lambda s: s.replace(ORIG, "['(unclosed']"), "regex inválida"),
        (lambda s: s.replace(ORIG, "[]"), "any_regex"),
        (lambda s: "- lista\n- solta\n", "mapa YAML"),
        (lambda s: s.replace("title: Teste", "title: ''"), "'title'"),
        (lambda s: "id: [unclosed", "YAML inválido"),
    ],
)
def test_invalid_rules_fail_with_clear_message(tmp_path: Path, mutation, fragment: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(RuleError) as exc:
        load_rule_file(write(tmp_path, mutation(VALID)))
    assert fragment in str(exc.value)
    assert "r.yaml" in str(exc.value)


@pytest.mark.parametrize(
    "pattern",
    ["(a+)+$", "(.*)*x", r"(\w+\s?)*end", "((a+))+", r"(\d+)*", "(a*)*"],
)
def test_redos_prone_regex_is_rejected(tmp_path: Path, pattern: str) -> None:
    text = VALID.replace(ORIG, f"['{pattern}']")
    with pytest.raises(RuleError, match="ReDoS"):
        load_rule_file(write(tmp_path, text))


@pytest.mark.parametrize(
    "pattern",
    [
        r"(?i)union(\s|\+|%20)+select",
        r"a+b+",
        "(abc)+",
        "(a+)?",
        "(a+){0,1}",
        r"\.\./",
        r"(?i)(nikto|sqlmap)",
    ],
)
def test_ordinary_regex_is_accepted(pattern: str) -> None:
    assert not has_nested_unbounded_quantifier(pattern)


def test_duplicate_ids_rejected(tmp_path: Path) -> None:
    write(tmp_path, VALID, "a.yaml")
    write(tmp_path, VALID, "b.yaml")
    with pytest.raises(RuleError, match="duplicado"):
        load_rules_dir(tmp_path)


def test_yaml_object_tags_are_not_executed(tmp_path: Path) -> None:
    evil = "id: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(RuleError, match="YAML inválido"):
        load_rule_file(write(tmp_path, evil))


def test_huge_rule_file_rejected(tmp_path: Path) -> None:
    f = write(tmp_path, "# " + "x" * 300_000 + "\n" + VALID)
    with pytest.raises(RuleError, match="grande demais"):
        load_rule_file(f)


def test_sequence_needs_two_steps_and_valid_window(tmp_path: Path) -> None:
    base = """\
id: KALLYEL-TST-009
title: s
type: sequence
severity: low
sources: [authlog]
window: {window}
steps:
  - {{name: a, where: {{action: [auth.failure]}}}}
explain: x
false_positives: y
mitigation: z
"""
    with pytest.raises(RuleError, match="pelo menos 2"):
        load_rule_file(write(tmp_path, base.format(window="5m")))
    with pytest.raises(RuleError, match="window"):
        load_rule_file(write(tmp_path, base.format(window="cinco")))


def test_where_rejects_unknown_field(tmp_path: Path) -> None:
    text = VALID + "where: {senha: [x]}\n"
    with pytest.raises(RuleError, match="não permitido em 'where'"):
        load_rule_file(write(tmp_path, text))
