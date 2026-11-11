"""Motor de regras em fluxo: um evento por vez, memória limitada.

Premissa de ordem: regras ``rate`` e ``sequence`` assumem eventos aproximadamente
cronológicos. Ao analisar arquivos rotacionados, passe-os do mais antigo para o mais
novo. ``rate`` tolera pequenas inversões; ``sequence`` não.
"""

from __future__ import annotations

import bisect
import re
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from kallyel.model import Event, Evidence, Finding, truncate
from kallyel.rules.model import PatternRule, RateRule, Rule, SequenceRule

EVIDENCE_LIMIT = 5
EVIDENCE_PER_STEP = 3
EVIDENCE_RAW_MAX = 512
MAX_STATE_KEYS = 20_000  # IPs rastreados por regra de taxa/sequência
MAX_FINDINGS_PER_RULE = 100_000


def _evidence(event: Event) -> Evidence:
    return Evidence(
        event.source_file, event.line_no, event.timestamp, truncate(event.raw, EVIDENCE_RAW_MAX)
    )


def _from_epoch(value: float) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc)


def candidate_values(value: str, url_decode: bool) -> Iterator[str]:
    """Texto original e, se pedido, suas versões decodificadas (até duas camadas de %xx)."""
    yield value
    if not url_decode:
        return
    current = value
    for _ in range(2):
        decoded = unquote_plus(current)
        if decoded == current:
            return
        yield decoded
        current = decoded


Candidates = dict[tuple[str, bool], list[str]]


def find_match(
    rule: PatternRule, event: Event, cache: Candidates | None = None
) -> tuple[str, re.Match[str]] | None:
    """Primeira regex que casa: devolve o texto examinado e o casamento, ou None.

    ``cache`` guarda, por evento, as versões decodificadas de cada campo, para que várias
    regras sobre o mesmo campo não decodifiquem a mesma URL de novo.
    """
    if not rule.where.matches(event):
        return None
    value = getattr(event, rule.field)
    if not isinstance(value, str) or not value:
        return None
    if cache is None:
        candidates: Iterable[str] = candidate_values(value, rule.url_decode)
    else:
        key = (rule.field, rule.url_decode)
        candidates = cache.get(key) or cache.setdefault(
            key, list(candidate_values(value, rule.url_decode))
        )
    for candidate in candidates:
        for rx in rule.regexes:
            found = rx.search(candidate)
            if found:
                return candidate, found
    return None


def pattern_matches(rule: PatternRule, event: Event) -> bool:
    """Verdadeiro se o evento satisfaz o filtro ``where`` e alguma regex da regra."""
    return find_match(rule, event) is not None


SNIPPET_CONTEXT = 150


def _line_start(text: str, pos: int) -> int:
    return text.rfind("\n", 0, pos) + 1


def _line_end(text: str, pos: int) -> int:
    end = text.find("\n", pos)
    return len(text) if end == -1 else end


def match_snippet(text: str, found: re.Match[str]) -> str:
    """Trecho do texto em volta do casamento, sem cortar tokens.

    Em texto de várias linhas (stack trace), parte das linhas do casamento mais uma linha de
    contexto de cada lado. Depois limita a ``SNIPPET_CONTEXT`` caracteres de cada lado,
    avançando as bordas até o espaço mais próximo: cortar no meio de um token (ex.: um JWT)
    deixaria sobrar um pedaço que o mascaramento não reconhece.
    """
    lo = _line_start(text, found.start())
    if lo > 0:
        lo = _line_start(text, lo - 1)
    hi = _line_end(text, found.end())
    if hi < len(text):
        hi = _line_end(text, hi + 1)
    region, base = text[lo:hi], lo

    start = max(0, found.start() - base - SNIPPET_CONTEXT)
    end = min(len(region), found.end() - base + SNIPPET_CONTEXT)
    if start > 0:
        cut = max(region.rfind(" ", 0, start), region.rfind("\n", 0, start))
        start = cut + 1 if cut != -1 else 0
    if end < len(region):
        space = [i for i in (region.find(" ", end), region.find("\n", end)) if i != -1]
        end = min(space) if space else len(region)
    cut_left = lo > 0 or start > 0
    cut_right = hi < len(text) or end < len(region)
    return ("…" if cut_left else "") + region[start:end] + ("…" if cut_right else "")


def event_phase_for_rule(rule: Rule, event: Event) -> str | None:
    """Fase do ataque que este evento representa para a regra, ou None se não se relaciona.

    Usado na linha do tempo. Em regras de sequência, só a etapa final tem a fase da regra;
    as etapas anteriores são a preparação (tentativa).
    """
    if isinstance(rule, PatternRule):
        return rule.phase if pattern_matches(rule, event) else None
    if isinstance(rule, RateRule):
        return rule.phase if rule.where.matches(event) else None
    if isinstance(rule, SequenceRule):
        if rule.steps[-1].where.matches(event):
            return rule.phase
        if any(step.where.matches(event) for step in rule.steps[:-1]):
            return "attempt" if rule.phase in {"success", "action"} else rule.phase
    return None


@dataclass(slots=True)
class _RateState:
    times: list[float] = field(default_factory=list)
    armed: bool = False


@dataclass(slots=True)
class _SeqState:
    stage: int = 0
    recent: deque[tuple[float, Evidence]] = field(default_factory=deque)
    start: float = 0.0
    seen: int = 0
    evidence: list[Evidence] = field(default_factory=list)


class Engine:
    """Aplica regras a eventos. Use ``feed`` por evento e ``finish`` ao final."""

    def __init__(self, rules: Iterable[Rule], *, evidence_limit: int = EVIDENCE_LIMIT) -> None:
        self._rules = list(rules)
        self._evidence_limit = evidence_limit
        self._by_source: dict[str, list[Rule]] = {}
        self._findings: dict[tuple[str, str | None], Finding] = {}
        self._findings_per_rule: defaultdict[str, int] = defaultdict(int)
        self._rate: defaultdict[str, dict[str, _RateState]] = defaultdict(dict)
        self._seq: defaultdict[str, dict[str, _SeqState]] = defaultdict(dict)
        self.warnings: list[str] = []
        self._warned: set[str] = set()

    # ------------------------------------------------------------------ API
    def feed(self, event: Event) -> None:
        cache: Candidates = {}  # decodificações do evento, compartilhadas entre regras
        for rule in self._rules_for(event.source_type):
            if isinstance(rule, PatternRule):
                self._feed_pattern(rule, event, cache)
            elif isinstance(rule, RateRule):
                self._feed_rate(rule, event)
            elif isinstance(rule, SequenceRule):
                self._feed_sequence(rule, event)

    def feed_all(self, events: Iterable[Event]) -> None:
        for event in events:
            self.feed(event)

    def finish(self) -> list[Finding]:
        """Achados ordenados por gravidade (maior primeiro), depois por data e regra."""
        epoch = datetime.min.replace(tzinfo=timezone.utc)
        return sorted(
            self._findings.values(),
            key=lambda f: (-int(f.severity), f.first_seen or epoch, f.rule_id, f.client_ip or ""),
        )

    # ------------------------------------------------------------- internos
    def _rules_for(self, source_type: str) -> list[Rule]:
        cached = self._by_source.get(source_type)
        if cached is None:
            cached = [r for r in self._rules if source_type in r.sources]
            self._by_source[source_type] = cached
        return cached

    def _warn_once(self, key: str, message: str) -> None:
        if key not in self._warned:
            self._warned.add(key)
            self.warnings.append(message)

    def _finding(self, rule: Rule, ip: str | None, event: Event) -> Finding | None:
        key = (rule.id, ip)
        finding = self._findings.get(key)
        if finding is not None:
            return finding
        if self._findings_per_rule[rule.id] >= MAX_FINDINGS_PER_RULE:
            self._warn_once(
                f"findings:{rule.id}",
                f"{rule.id}: limite de {MAX_FINDINGS_PER_RULE} achados atingido; os demais foram ignorados",
            )
            return None
        self._findings_per_rule[rule.id] += 1
        finding = Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            client_ip=ip,
            explain=rule.explain,
            false_positives=rule.false_positives,
            mitigation=rule.mitigation,
            attack=rule.attack,
            cwe=rule.cwe,
            owasp=rule.owasp,
            phase=rule.phase,
        )
        self._findings[key] = finding
        return finding

    @staticmethod
    def _stretch(finding: Finding, first: datetime | None, last: datetime | None) -> None:
        if first is not None and (finding.first_seen is None or first < finding.first_seen):
            finding.first_seen = first
        if last is not None and (finding.last_seen is None or last > finding.last_seen):
            finding.last_seen = last

    def _add_evidence(self, finding: Finding, evidence: Evidence) -> None:
        if len(finding.evidence) < self._evidence_limit:
            finding.evidence.append(evidence)

    # -------------------------------------------------------------- pattern
    def _feed_pattern(self, rule: PatternRule, event: Event, cache: Candidates) -> None:
        match = find_match(rule, event, cache)
        if match is None:
            return
        finding = self._finding(rule, event.client_ip, event)
        if finding is None:
            return
        finding.count += 1
        self._stretch(finding, event.timestamp, event.timestamp)
        if len(finding.evidence) < self._evidence_limit:
            evidence = _evidence(event)
            if rule.field == "message":
                # Em registros longos (stack trace) o que casou pode estar além do começo.
                text, found = match
                evidence.raw = truncate(match_snippet(text, found), EVIDENCE_RAW_MAX)
            finding.evidence.append(evidence)

    # ----------------------------------------------------------------- rate
    def _feed_rate(self, rule: RateRule, event: Event) -> None:
        ip, ts = event.client_ip, event.timestamp
        if ip is None or ts is None or not rule.where.matches(event):
            return
        states = self._rate[rule.id]
        state = states.get(ip)
        if state is None:
            if len(states) >= MAX_STATE_KEYS:
                states.pop(next(iter(states)))
                self._warn_once(
                    f"state:{rule.id}",
                    f"{rule.id}: mais de {MAX_STATE_KEYS} IPs distintos; os mais antigos deixaram de ser rastreados",
                )
            state = states[ip] = _RateState()

        bisect.insort(state.times, ts.timestamp())
        if len(state.times) > rule.threshold:
            del state.times[0]

        in_burst = (
            len(state.times) == rule.threshold and state.times[-1] - state.times[0] <= rule.window_s
        )
        if not in_burst:
            state.armed = False
            return
        finding = self._finding(rule, ip, event)
        if finding is None:
            return
        finding.count += 1 if state.armed else rule.threshold
        state.armed = True
        self._stretch(finding, _from_epoch(state.times[0]), ts)
        finding.detail = f"{rule.threshold} ou mais eventos em até {rule.window_s}s"
        self._add_evidence(finding, _evidence(event))

    # ------------------------------------------------------------- sequence
    def _feed_sequence(self, rule: SequenceRule, event: Event) -> None:
        ip, dt = event.client_ip, event.timestamp
        if ip is None or dt is None:
            return
        ts = dt.timestamp()
        states = self._seq[rule.id]
        state = states.get(ip)
        if state is None:
            if len(states) >= MAX_STATE_KEYS:
                states.pop(next(iter(states)))
                self._warn_once(
                    f"state:{rule.id}",
                    f"{rule.id}: mais de {MAX_STATE_KEYS} IPs distintos; os mais antigos deixaram de ser rastreados",
                )
            state = states[ip] = _SeqState()

        if state.stage > 0 and ts - state.start > rule.window_s:
            self._reset(state)

        step = rule.steps[state.stage]
        if not step.where.matches(event):
            return
        evidence = _evidence(event)

        if state.stage == 0:
            state.recent.append((ts, evidence))
            while state.recent and ts - state.recent[0][0] > rule.window_s:
                state.recent.popleft()
            while len(state.recent) > step.min_count:
                state.recent.popleft()
            if len(state.recent) < step.min_count:
                return
            state.start = state.recent[0][0]
            state.evidence = [ev for _, ev in state.recent][-EVIDENCE_PER_STEP:]
            state.recent.clear()
            state.stage, state.seen = 1, 0
            return

        state.seen += 1
        if state.seen <= EVIDENCE_PER_STEP:
            state.evidence.append(evidence)
        if state.seen < step.min_count:
            return
        state.stage += 1
        state.seen = 0
        if state.stage < len(rule.steps):
            return

        finding = self._finding(rule, ip, event)
        if finding is not None:
            finding.count += 1
            if not finding.evidence:
                finding.evidence.extend(state.evidence)
                finding.detail = (
                    " → ".join(s.name for s in rule.steps) + f" em até {rule.window_s}s"
                )
            self._stretch(finding, _from_epoch(state.start), dt)
        self._reset(state)

    @staticmethod
    def _reset(state: _SeqState) -> None:
        state.stage = 0
        state.seen = 0
        state.recent.clear()
        state.evidence = []
