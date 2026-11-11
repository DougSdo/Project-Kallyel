from collections.abc import Iterable

import pytest

from kallyel.model import Event, Finding, Severity
from kallyel.rules import Engine, Rule
from tests.helpers import auth_event, http_event, rule_from_yaml

SQLI = rule_from_yaml(
    """
id: KALLYEL-TST-001
title: SQLi
match:
  field: http_path_query
  any_regex: ['(?i)union(\\s|\\+|%20)+select']
"""
)


def run(rules: list[Rule], events: Iterable[Event]) -> tuple[Engine, list[Finding]]:
    engine = Engine(rules)
    engine.feed_all(events)
    return engine, engine.finish()


# ------------------------------------------------------------------ pattern
def test_pattern_fires_on_attack_and_not_on_clean_traffic() -> None:
    _, findings = run(
        [SQLI],
        [
            http_event("/products", query="id=1+UNION+SELECT+password+FROM+users", at=1),
            http_event("/index.html", at=2),
            http_event("/search", query="q=reuniao+select+committee", at=3),
        ],
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "KALLYEL-TST-001"
    assert f.severity is Severity.MEDIUM
    assert f.client_ip == "203.0.113.10"
    assert f.count == 1
    assert f.evidence[0].line_no == 1


def test_pattern_matches_url_encoded_and_double_encoded_payloads() -> None:
    _, findings = run(
        [SQLI],
        [
            http_event("/a", query="id=1%20UNION%20SELECT%201", ip="203.0.113.1"),
            http_event("/a", query="id=1%2520UNION%2520SELECT%25201", ip="203.0.113.2"),
        ],
    )
    assert {f.client_ip for f in findings} == {"203.0.113.1", "203.0.113.2"}


def test_pattern_is_case_insensitive_when_rule_says_so() -> None:
    _, findings = run([SQLI], [http_event("/a", query="x=uNiOn+SeLeCt")])
    assert len(findings) == 1


def test_source_filter_is_respected() -> None:
    laravel_only = rule_from_yaml(
        "id: KALLYEL-TST-002\ntitle: x\nmatch:\n  field: http_path_query\n  any_regex: ['evil']\n",
        sources="laravel",
    )
    _, findings = run([laravel_only], [http_event("/evil")])
    assert findings == []


def test_where_filter_narrows_pattern() -> None:
    rule = rule_from_yaml(
        """
id: KALLYEL-TST-003
title: x
where: {http_status: [200]}
match:
  field: http_path
  any_regex: ['/admin']
"""
    )
    _, findings = run(
        [rule], [http_event("/admin", status=404), http_event("/admin", status=200, at=1)]
    )
    assert len(findings) == 1
    assert findings[0].count == 1


def test_one_finding_per_ip_with_bounded_evidence() -> None:
    events = [http_event("/p", query="a=union select", at=i, line_no=i + 1) for i in range(20)]
    events += [http_event("/p", query="a=union select", ip="203.0.113.99", at=30)]
    _, findings = run([SQLI], events)
    by_ip = {f.client_ip: f for f in findings}
    assert by_ip["203.0.113.10"].count == 20
    assert len(by_ip["203.0.113.10"].evidence) == 5
    assert by_ip["203.0.113.99"].count == 1
    assert by_ip["203.0.113.10"].first_seen < by_ip["203.0.113.10"].last_seen  # type: ignore[operator]


def test_payload_hidden_beyond_4kb_is_still_seen() -> None:
    padded = "A" * 5000 + "+union+select+1"
    _, findings = run([SQLI], [http_event("/a", query=padded)])
    assert len(findings) == 1


def test_event_without_field_value_is_ignored() -> None:
    ev = http_event("/a")
    ev.http_path = None
    _, findings = run([SQLI], [ev])
    assert findings == []


# --------------------------------------------------------------------- rate
RATE = rule_from_yaml(
    """
id: KALLYEL-TST-010
title: Pico de 404
type: rate
where: {http_status: [404]}
rate: {threshold: 5, window: 10s}
"""
)


def test_rate_fires_at_threshold_inside_window() -> None:
    _, findings = run([RATE], [http_event(f"/x{i}", status=404, at=i) for i in range(5)])
    assert len(findings) == 1
    assert findings[0].count == 5
    assert "5 ou mais eventos em até 10s" in findings[0].detail


def test_rate_does_not_fire_below_threshold_or_outside_window() -> None:
    few = [http_event("/x", status=404, at=i) for i in range(4)]
    slow = [http_event("/x", status=404, at=i * 5, ip="203.0.113.77") for i in range(10)]
    _, findings = run([RATE], few + slow)
    assert findings == []


def test_rate_ignores_other_statuses_and_separates_ips() -> None:
    events = [http_event("/x", status=404, at=i, ip=f"203.0.113.{i}") for i in range(5)]
    events += [http_event("/ok", status=200, at=i) for i in range(20)]
    _, findings = run([RATE], events)
    assert findings == []


def test_rate_extends_burst_and_counts_second_burst() -> None:
    first = [http_event("/x", status=404, at=i) for i in range(7)]  # 7 eventos
    second = [http_event("/x", status=404, at=1000 + i) for i in range(5)]  # nova rajada
    _, findings = run([RATE], first + second)
    assert len(findings) == 1
    assert findings[0].count == 12


def test_rate_tolerates_slightly_out_of_order_events() -> None:
    order = [0, 2, 1, 4, 3]
    _, findings = run([RATE], [http_event("/x", status=404, at=t) for t in order])
    assert len(findings) == 1


# ----------------------------------------------------------------- sequence
SEQ = rule_from_yaml(
    """
id: KALLYEL-TST-020
title: Força bruta seguida de sucesso
type: sequence
severity: critical
window: 5m
steps:
  - {name: falhas, where: {action: [auth.failure]}, min_count: 3}
  - {name: sucesso, where: {action: [auth.success]}}
""",
    sources="authlog",
)


def test_sequence_fires_on_failures_then_success() -> None:
    events = [auth_event("auth.failure", at=i) for i in range(3)] + [
        auth_event("auth.success", at=10)
    ]
    _, findings = run([SEQ], events)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "KALLYEL-TST-020"
    assert f.client_ip == "198.51.100.5"
    assert "falhas → sucesso" in f.detail
    assert [e.raw.split()[1] for e in f.evidence] == ["auth.failure"] * 3 + ["auth.success"]


def test_sequence_not_fired_without_enough_failures_or_wrong_order() -> None:
    too_few = [auth_event("auth.failure", at=i) for i in range(2)] + [
        auth_event("auth.success", at=5)
    ]
    wrong_order = [auth_event("auth.success", at=0, ip="198.51.100.6")] + [
        auth_event("auth.failure", at=i + 1, ip="198.51.100.6") for i in range(5)
    ]
    _, findings = run([SEQ], too_few + wrong_order)
    assert findings == []


def test_sequence_is_grouped_by_ip() -> None:
    events = [auth_event("auth.failure", at=i, ip="198.51.100.1") for i in range(3)]
    events.append(auth_event("auth.success", at=10, ip="198.51.100.2"))  # outro IP
    _, findings = run([SEQ], events)
    assert findings == []


def test_sequence_respects_window() -> None:
    events = [auth_event("auth.failure", at=i) for i in range(3)] + [
        auth_event("auth.success", at=400)
    ]
    _, findings = run([SEQ], events)
    assert findings == []


def test_sequence_failures_must_be_within_window_of_each_other() -> None:
    events = [auth_event("auth.failure", at=t) for t in (0, 200, 400)] + [
        auth_event("auth.success", at=410)
    ]
    _, findings = run([SEQ], events)
    assert findings == []  # as 3 falhas não cabem em 5 min


def test_sequence_counts_repeated_completions_in_one_finding() -> None:
    events: list[Event] = []
    for base in (0, 1000):
        events += [auth_event("auth.failure", at=base + i) for i in range(3)]
        events.append(auth_event("auth.success", at=base + 10))
    _, findings = run([SEQ], events)
    assert len(findings) == 1
    assert findings[0].count == 2


# -------------------------------------------------------------------- misc
def test_findings_sorted_by_severity() -> None:
    _, findings = run(
        [SQLI, RATE],
        [http_event("/a", query="x=union select", at=100)]
        + [http_event("/x", status=404, at=i, ip="203.0.113.50") for i in range(5)],
    )
    assert [f.severity for f in findings] == sorted((f.severity for f in findings), reverse=True)


def test_events_without_ip_are_skipped_by_stateful_rules() -> None:
    ev = http_event("/x", status=404)
    ev.client_ip = None
    _, findings = run([RATE], [ev] * 10)
    assert findings == []


# ------------------------------------------------- limites de memória (exaustão)
def test_state_eviction_is_bounded_and_warns() -> None:
    from kallyel.rules import engine as engine_mod

    limit = engine_mod.MAX_STATE_KEYS
    eng = Engine([RATE_RULE_FOR_LIMITS])
    for i in range(limit + 5):
        ip = f"2001:db8::{i:x}"
        eng.feed(http_event("/x", status=404, ip=ip, at=0))
    assert len(eng._rate[RATE_RULE_FOR_LIMITS.id]) <= limit
    assert any("IPs distintos" in w for w in eng.warnings)
    assert sum("IPs distintos" in w for w in eng.warnings) == 1  # avisa uma vez só


def test_findings_cap_per_rule_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    from kallyel.rules import engine as engine_mod

    monkeypatch.setattr(engine_mod, "MAX_FINDINGS_PER_RULE", 3)
    eng = Engine([SQLI])
    for i in range(10):
        eng.feed(http_event("/p", query="a=union select 1", ip=f"203.0.113.{i}"))
    assert len(eng.finish()) == 3
    assert any("limite" in w for w in eng.warnings)


RATE_RULE_FOR_LIMITS = rule_from_yaml(
    """
id: KALLYEL-TST-090
title: limite
type: rate
where: {http_status: [404]}
rate: {threshold: 5, window: 10s}
"""
)
