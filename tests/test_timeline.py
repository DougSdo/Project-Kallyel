from kallyel.correlate import build_ip_report, build_timeline
from kallyel.model import Event
from kallyel.rules import Engine, load_builtin_rules
from tests.helpers import auth_event, http_event

IP = "203.0.113.50"
RULES = load_builtin_rules()
BY_ID = {r.id: r for r in RULES}


def scenario() -> list[Event]:
    """Varredura -> tentativas de login -> força bruta SSH -> sucesso, do mesmo IP."""
    events: list[Event] = []
    for i in range(40):  # reconhecimento: scanner gerando 404
        events.append(
            http_event(
                f"/x{i}", status=404, ua="Mozilla/5.0 (Nikto/2.1.6)", at=i, ip=IP, line_no=i + 1
            )
        )
    events += [
        http_event("/", at=60 + i, ip=IP, line_no=100 + i) for i in range(3)
    ]  # tráfego normal
    events += [
        http_event("/login", status=401, at=100 + i, ip=IP, line_no=200 + i) for i in range(20)
    ]
    events += [auth_event("auth.failure", at=200 + i, ip=IP, line_no=300 + i) for i in range(6)]
    events.append(auth_event("auth.success", at=210, ip=IP, line_no=400))
    return events


def run(events: list[Event]):  # type: ignore[no-untyped-def]
    engine = Engine(RULES)
    engine.feed_all(events)
    findings = engine.finish()
    return findings, build_timeline(IP, events, findings, BY_ID)


def test_timeline_shows_scan_then_bruteforce_then_success() -> None:
    findings, tl = run(scenario())
    phases = [e.phase for e in tl.entries if e.phase is not None]
    # ordem cronológica das fases: reconhecimento -> tentativa -> sucesso
    deduped = [p for i, p in enumerate(phases) if i == 0 or p != phases[i - 1]]
    assert deduped == ["recon", "attempt", "success"]

    timestamps = [e.timestamp for e in tl.entries if e.timestamp]
    assert timestamps == sorted(timestamps)

    report = build_ip_report(IP, findings)
    assert [s.phase for s in report.phases] == ["recon", "attempt", "success"]
    assert report.score.band in {"alto", "crítico"}


def test_timeline_collapses_runs_and_summarises_quiet_traffic() -> None:
    _, tl = run(scenario())
    recon = tl.entries[0]
    assert recon.phase == "recon"
    assert recon.count == 40
    assert {"KALLYEL-WEB-005", "KALLYEL-WEB-007"} <= set(recon.rule_ids)
    quiet = [e for e in tl.entries if e.phase is None]
    assert [q.count for q in quiet] == [3]
    assert "sem achado" in quiet[0].description
    assert len(tl.entries) < 10  # 70 eventos viram poucas linhas
    assert tl.total_events == 70


def test_failures_before_success_are_attempts_not_success() -> None:
    _, tl = run(scenario())
    auth_entries = [e for e in tl.entries if e.source_file == "auth.log"]
    assert [e.phase for e in auth_entries] == ["attempt", "success"]
    assert "KALLYEL-AUTH-001" in auth_entries[0].rule_ids
    assert auth_entries[1].rule_ids == ("KALLYEL-AUTH-002",)


def test_ip_without_findings_still_lists_logins_and_quiet_traffic() -> None:
    events = [http_event("/", at=i, ip=IP) for i in range(5)] + [
        auth_event("auth.success", at=10, ip=IP)
    ]
    _, tl = run(events)
    assert [e.phase for e in tl.entries] == [None, "success"]


def test_timeline_ignores_other_ips_findings() -> None:
    other = http_event("/p", query="a=union select 1", ip="203.0.113.99")
    own = http_event("/", ip=IP, at=5)
    engine = Engine(RULES)
    engine.feed_all([other, own])
    tl = build_timeline(IP, [own], engine.finish(), BY_ID)
    assert [e.phase for e in tl.entries] == [None]


def test_timeline_is_capped() -> None:
    # Alterna 404 de scanner e tráfego normal para impedir o agrupamento de entradas
    events: list[Event] = []
    for i in range(700):
        events.append(http_event(f"/a{i}", status=404, ua="sqlmap/1.7", at=i * 2, ip=IP))
        events.append(http_event("/", status=200, at=i * 2 + 1, ip=IP))
    _, tl = run(events)
    assert tl.truncated
    assert len(tl.entries) == 500
