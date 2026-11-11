"""Pontuação de risco por IP. Todo ponto tem uma justificativa em texto.

A pontuação é uma heurística de triagem para ordenar IPs, não uma probabilidade de
ataque. Os pesos abaixo são constantes simples e podem ser ajustados.

Componentes:

1. **Gravidade**: cada regra que disparou para o IP conta uma vez, pelo peso da sua gravidade.
2. **Diversidade de técnicas**: +4 por técnica ATT&CK distinta além da primeira (máx. 20).
   Sub-técnicas contam como a técnica pai (T1110.001 e T1110.003 são uma só).
3. **Progressão entre fases**: +10 por fase além da primeira (máx. 30); reconhecimento seguido
   de tentativa e de sucesso é mais grave do que a mesma quantidade de ruído em uma só fase.

O total é limitado a 100.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from kallyel.model import PHASE_LABELS, PHASES, Finding, Severity

SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 20,
    Severity.CRITICAL: 45,
}
TECHNIQUE_BONUS = 4
TECHNIQUE_BONUS_CAP = 20
PHASE_BONUS = 10
PHASE_BONUS_CAP = 30
SCORE_CAP = 100

# (limite inferior, rótulo)
BANDS: tuple[tuple[int, str], ...] = ((75, "crítico"), (45, "alto"), (20, "médio"), (0, "baixo"))

_SEVERITY_LABEL = {
    Severity.LOW: "baixa",
    Severity.MEDIUM: "média",
    Severity.HIGH: "alta",
    Severity.CRITICAL: "crítica",
}


@dataclass(frozen=True, slots=True)
class ScoreComponent:
    label: str
    points: int
    detail: str


@dataclass(slots=True)
class RiskScore:
    total: int  # já limitado a SCORE_CAP
    raw: int  # soma dos componentes, antes do limite
    band: str
    components: list[ScoreComponent] = field(default_factory=list)

    @property
    def capped(self) -> bool:
        return self.raw > self.total


def band_for(total: int) -> str:
    for floor, label in BANDS:
        if total >= floor:
            return label
    return BANDS[-1][1]


def parent_technique(technique: str) -> str:
    return technique.split(".", 1)[0]


def phases_in_order(findings: Iterable[Finding]) -> list[str]:
    """Fases presentes, na ordem cronológica da primeira ocorrência (empate: ordem canônica)."""
    epoch = datetime.max.replace(tzinfo=timezone.utc)
    first: dict[str, datetime] = {}
    for f in findings:
        when = f.first_seen or epoch
        if f.phase not in first or when < first[f.phase]:
            first[f.phase] = when
    return sorted(first, key=lambda p: (first[p], PHASES.index(p) if p in PHASES else len(PHASES)))


def score_findings(findings: Iterable[Finding]) -> RiskScore:
    items = list(findings)
    components: list[ScoreComponent] = []

    for severity in sorted(SEVERITY_WEIGHT, reverse=True):
        group = sorted(f.rule_id for f in items if f.severity is severity)
        if not group:
            continue
        weight = SEVERITY_WEIGHT[severity]
        components.append(
            ScoreComponent(
                label=f"Gravidade {_SEVERITY_LABEL[severity]}",
                points=weight * len(group),
                detail=f"{len(group)} regra(s) × {weight} pontos ({', '.join(group)})",
            )
        )

    techniques = sorted({parent_technique(t) for f in items for t in f.attack})
    if len(techniques) >= 2:
        points = min(TECHNIQUE_BONUS_CAP, TECHNIQUE_BONUS * (len(techniques) - 1))
        components.append(
            ScoreComponent(
                label="Diversidade de técnicas",
                points=points,
                detail=(
                    f"{len(techniques)} técnicas ATT&CK distintas ({', '.join(techniques)}): "
                    f"+{TECHNIQUE_BONUS} por técnica além da primeira (máx. {TECHNIQUE_BONUS_CAP})"
                ),
            )
        )

    phases = phases_in_order(items)
    if len(phases) >= 2:
        points = min(PHASE_BONUS_CAP, PHASE_BONUS * (len(phases) - 1))
        chain = " → ".join(PHASE_LABELS.get(p, p) for p in phases)
        components.append(
            ScoreComponent(
                label="Progressão entre fases",
                points=points,
                detail=(
                    f"{chain}: +{PHASE_BONUS} por fase além da primeira (máx. {PHASE_BONUS_CAP})"
                ),
            )
        )

    raw = sum(c.points for c in components)
    total = min(SCORE_CAP, raw)
    return RiskScore(total=total, raw=raw, band=band_for(total), components=components)
