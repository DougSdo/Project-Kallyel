from datetime import timedelta

import pytest

from kallyel.correlate import build_ip_reports, score_findings
from kallyel.correlate.score import (
    SCORE_CAP,
    SEVERITY_WEIGHT,
    band_for,
    phases_in_order,
)
from kallyel.model import Finding, Severity
from tests.helpers import T0


def finding(
    rule_id: str,
    severity: Severity,
    *,
    attack: tuple[str, ...] = ("T1190",),
    phase: str = "attempt",
    at: float = 0.0,
    ip: str | None = "203.0.113.50",
) -> Finding:
    first = T0 + timedelta(seconds=at)
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        client_ip=ip,
        attack=attack,
        phase=phase,
        first_seen=first,
        last_seen=first + timedelta(seconds=10),
        count=1,
    )


def test_no_findings_is_zero_and_low() -> None:
    score = score_findings([])
    assert (score.total, score.raw, score.band) == (0, 0, "baixo")
    assert score.components == []


def test_single_high_finding_is_explained() -> None:
    score = score_findings([finding("KALLYEL-WEB-001", Severity.HIGH)])
    assert score.total == SEVERITY_WEIGHT[Severity.HIGH] == 20
    (comp,) = score.components
    assert comp.label == "Gravidade alta"
    assert "KALLYEL-WEB-001" in comp.detail and "20" in comp.detail


def test_scanner_noise_in_one_phase_stays_moderate() -> None:
    findings = [
        finding("KALLYEL-WEB-005", Severity.MEDIUM, attack=("T1595.002",), phase="recon"),
        finding("KALLYEL-WEB-007", Severity.MEDIUM, attack=("T1595.003",), phase="recon", at=5),
        finding(
            "KALLYEL-WEB-004", Severity.MEDIUM, attack=("T1190", "T1552.001"), phase="recon", at=9
        ),
    ]
    score = score_findings(findings)
    # 3 × 8 de gravidade + 2 técnicas extras (T1595, T1190, T1552 = 3 técnicas -> +8); uma só fase
    assert score.raw == 24 + 8
    assert score.band == "médio"
    assert not any(c.label == "Progressão entre fases" for c in score.components)


def test_bruteforce_then_success_is_rated_by_progression() -> None:
    findings = [
        finding("KALLYEL-AUTH-001", Severity.HIGH, attack=("T1110",), phase="attempt", at=0),
        finding(
            "KALLYEL-AUTH-002", Severity.CRITICAL, attack=("T1110", "T1078"), phase="success", at=60
        ),
    ]
    score = score_findings(findings)
    labels = {c.label: c.points for c in score.components}
    assert labels["Gravidade alta"] == 20
    assert labels["Gravidade crítica"] == 45
    assert labels["Diversidade de técnicas"] == 4  # T1110 e T1078
    assert labels["Progressão entre fases"] == 10
    assert score.total == 79
    assert score.band == "crítico"
    progression = next(c for c in score.components if c.label == "Progressão entre fases")
    assert "tentativa → sucesso" in progression.detail


def test_adding_recon_phase_raises_the_score() -> None:
    base = [
        finding("KALLYEL-AUTH-001", Severity.HIGH, attack=("T1110",), at=100),
        finding(
            "KALLYEL-AUTH-002",
            Severity.CRITICAL,
            attack=("T1110", "T1078"),
            phase="success",
            at=160,
        ),
    ]
    recon = finding("KALLYEL-WEB-007", Severity.MEDIUM, attack=("T1595.003",), phase="recon", at=0)
    assert score_findings([*base, recon]).total > score_findings(base).total


def test_subtechniques_count_as_their_parent() -> None:
    findings = [
        finding("KALLYEL-X-001", Severity.LOW, attack=("T1110.001",)),
        finding("KALLYEL-X-002", Severity.LOW, attack=("T1110.003",)),
    ]
    score = score_findings(findings)
    assert not any(c.label == "Diversidade de técnicas" for c in score.components)


def test_score_is_capped_and_says_so() -> None:
    findings = [finding(f"KALLYEL-X-{i:03d}", Severity.CRITICAL) for i in range(5)]
    score = score_findings(findings)
    assert score.total == SCORE_CAP
    assert score.raw == 5 * 45
    assert score.capped


def test_every_point_is_justified() -> None:
    findings = [
        finding("KALLYEL-WEB-005", Severity.MEDIUM, attack=("T1595.002",), phase="recon"),
        finding("KALLYEL-WEB-001", Severity.HIGH, attack=("T1190",), at=30),
        finding("KALLYEL-AUTH-002", Severity.CRITICAL, attack=("T1078",), phase="success", at=90),
    ]
    score = score_findings(findings)
    assert sum(c.points for c in score.components) == score.raw
    assert all(c.detail.strip() and c.label.strip() and c.points > 0 for c in score.components)


@pytest.mark.parametrize(
    ("total", "band"),
    [
        (0, "baixo"),
        (19, "baixo"),
        (20, "médio"),
        (44, "médio"),
        (45, "alto"),
        (74, "alto"),
        (75, "crítico"),
        (100, "crítico"),
    ],
)
def test_band_boundaries(total: int, band: str) -> None:
    assert band_for(total) == band


def test_phases_in_order_is_chronological_not_canonical() -> None:
    findings = [
        finding("A", Severity.LOW, phase="success", at=0),
        finding("B", Severity.LOW, phase="recon", at=50),
    ]
    assert phases_in_order(findings) == ["success", "recon"]


def test_ip_reports_sorted_by_risk_and_skip_findings_without_ip() -> None:
    findings = [
        finding("KALLYEL-WEB-001", Severity.HIGH, ip="203.0.113.1"),
        finding("KALLYEL-WEB-006", Severity.CRITICAL, ip="203.0.113.2"),
        finding("KALLYEL-APP-001", Severity.HIGH, ip=None),
    ]
    reports = build_ip_reports(findings)
    assert [r.ip for r in reports] == ["203.0.113.2", "203.0.113.1"]
    assert reports[0].duration == timedelta(seconds=10)
