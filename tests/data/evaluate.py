"""Avaliação sintética das regras do Kallyel: detecções, falsos positivos e lacunas verificadas.

Gera os dados com ``generate.py`` (gabarito independente do Kallyel), roda a análise e
produz a tabela de ``docs/avaliacao.md``. Os números do documento são reproduzíveis: um teste
regenera o bloco e falha se o arquivo estiver desatualizado.

    python tests/data/evaluate.py                 # imprime o bloco em Markdown
    python tests/data/evaluate.py --update-docs   # reescreve o bloco em docs/avaliacao.md

Limite importante: tudo aqui é sintético. A taxa de falso positivo medida vale para o tráfego
que ``generate.py`` produz, não para o de uma empresa real.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:  # permite rodar como script
    sys.path.insert(0, str(ROOT))

from kallyel.analysis import analyze  # noqa: E402
from kallyel.rules import load_builtin_rules  # noqa: E402
from tests.data import generate as gen  # noqa: E402

DOC_PATH = ROOT / "docs" / "avaliacao.md"
BEGIN = "<!-- BEGIN GENERATED -->"
END = "<!-- END GENERATED -->"

SEEDS = (1, 2, 3, 4, 5)
CLEAN = {"nginx": 60_000, "auth": 6_000, "laravel": 2_000}
SCEN_BACKGROUND = {"nginx": 10_000, "auth": 1_000, "laravel": 500}

# Lacunas que não dá para exercitar com uma linha de log, ou que valem para a regra inteira.
KNOWN_GAPS: dict[str, str] = {
    "KALLYEL-WEB-001": "Não vê corpo de POST (o log não o traz); só decodifica 2 camadas de %xx; não trata ofuscação por comentário SQL nem injeção numérica sem aspas.",
    "KALLYEL-WEB-002": "Só olha a URL; XSS armazenado, DOM XSS e payload em corpo ficam de fora; lista curta de manipuladores de evento.",
    "KALLYEL-WEB-003": "2 camadas de decodificação; não trata variantes como `..;/`; wrappers de stream fora da lista.",
    "KALLYEL-WEB-004": "Lista fixa de nomes; 404 e 200 geram o mesmo achado (o status está nas evidências, não na gravidade).",
    "KALLYEL-WEB-005": "Só pega scanner que se identifica; trocar o User-Agent desliga a regra.",
    "KALLYEL-WEB-006": "Lista curta de comandos e de metacaracteres; não trata quebra de linha (`%0a`) como separador.",
    "KALLYEL-WEB-007": "Um IP por vez: varredura lenta (abaixo de 30/min) ou distribuída entre muitos IPs passa.",
    "KALLYEL-WEB-008": "Idem: abaixo de 15 respostas 401/403 por minuto, ou espalhado por IPs, não dispara.",
    "KALLYEL-WEB-009": "Não distingue falha real da aplicação de fuzzing; não cobre 502/503.",
    "KALLYEL-AUTH-001": "Só conta 'Failed ...'; servidor só com chave pública vê apenas 'Invalid user'; 'message repeated N times' conta uma vez; ataque lento ou distribuído passa.",
    "KALLYEL-AUTH-002": "Agrupa por IP: falhas de um IP e sucesso de outro não se ligam.",
    "KALLYEL-AUTH-003": "Lista de comandos, não comparação com o comportamento habitual; `sudo bash` de rotina é falso positivo; outros binários que abrem shell passam.",
    "KALLYEL-APP-001": "Só padrões conhecidos de segredo (nomes de variável, Bearer, base64:, AKIA, chave privada); nomes personalizados passam.",
}


@dataclass
class RuleStats:
    rule_id: str
    title: str
    severity: str
    expected: int = 0
    detected: int = 0
    unexpected: int = 0


@dataclass
class Probe:
    rule_id: str
    title: str
    filename: str
    text: str
    expect_detected: bool  # True = controle (deve ser detectado); False = lacuna suspeita
    detected: bool = False


@dataclass
class Evaluation:
    rules: list[RuleStats]
    probes: list[Probe]
    clean_lines: int
    scenario_runs: int
    scenario_lines: int
    clean_findings: int = 0
    scenario_findings_unexpected: int = 0
    extra: dict[str, int] = field(default_factory=dict)


# ----------------------------------------------------------------- sondas
ATT = "203.0.113.230"
T0 = gen.START.timestamp() + 1000.0


def _web(
    target: str, *, t: float = T0, ip: str = ATT, status: int = 200, ua: str = gen.CHROME
) -> str:
    return gen.nginx_line(ip, t, "GET", target, status, 100, ua)


def _single(
    rule: str, title: str, target: str, *, control: bool = False, ua: str = gen.CHROME
) -> Probe:
    return Probe(rule, title, "access.log", _web(target, ua=ua) + "\n", control)


def _ssh_fail(t: float, ip: str, user: str = "root") -> str:
    return gen.auth_line(t, "sshd", 99, f"Failed password for {user} from {ip} port 4444 ssh2")


def build_probes() -> list[Probe]:
    probes: list[Probe] = [
        # controles: devem ser detectados (mostram que a decodificação funciona)
        _single(
            "KALLYEL-WEB-001",
            "SQLi com dupla codificação (%2520)",
            "/p?id=1%2520UNION%2520SELECT%25201",
            control=True,
        ),
        _single(
            "KALLYEL-WEB-003",
            "Traversal com dupla codificação (%252e%252e%252f)",
            "/d?f=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            control=True,
        ),
        # lacunas: ofuscações que o Kallyel NÃO vê
        _single(
            "KALLYEL-WEB-001",
            "SQLi ofuscada com comentário SQL (UN/**/ION SEL/**/ECT)",
            "/p?id=1+UN/**/ION+SEL/**/ECT+1",
        ),
        _single("KALLYEL-WEB-001", "SQLi numérica sem aspas (`or 1=1`)", "/p?id=1+or+1=1"),
        _single(
            "KALLYEL-WEB-001",
            "SQLi com 4 camadas de codificação",
            "/p?id=1%25252520UNION%25252520SELECT",
        ),
        _single(
            "KALLYEL-WEB-002",
            "XSS com manipulador fora da lista (`ontoggle`)",
            "/s?q=<details/open/ontoggle=alert(1)>",
        ),
        _single(
            "KALLYEL-WEB-003",
            "Traversal com 3 camadas (%25252e)",
            "/d?f=%25252e%25252e%25252fetc%25252fpasswd",
        ),
        _single("KALLYEL-WEB-003", "Traversal com `..;/`", "/files/..;/secret"),
        _single(
            "KALLYEL-WEB-004",
            "Arquivo sensível fora da lista (`/config/secrets.yml`)",
            "/config/secrets.yml",
        ),
        _single("KALLYEL-WEB-004", "Backup do .env com til (`/.env.local~`)", "/.env.local~"),
        _single(
            "KALLYEL-WEB-006", "Injeção por quebra de linha (`%0a`)", "/ping?host=127.0.0.1%0aid"
        ),
    ]
    disguised = "".join(_web(f"/x{i}", t=T0 + i, status=404) + "\n" for i in range(40))
    probes.append(
        Probe(
            "KALLYEL-WEB-005",
            "Varredura com User-Agent de navegador (WEB-007 pega pelo volume; WEB-005 não)",
            "access.log",
            disguised,
            False,
        )
    )
    slow = "".join(_web(f"/x{i}", t=T0 + i * 5, status=404) + "\n" for i in range(60))
    probes.append(
        Probe(
            "KALLYEL-WEB-007",
            "Varredura lenta (1 resposta 404 a cada 5 s, 60 no total)",
            "access.log",
            slow,
            False,
        )
    )
    spread = "".join(
        _web(f"/x{j}", t=T0 + j, status=404, ip=f"203.0.113.{231 + i}") + "\n"
        for i in range(40)
        for j in range(3)
    )
    probes.append(
        Probe(
            "KALLYEL-WEB-007",
            "Varredura distribuída (40 IPs x 3 respostas 404)",
            "access.log",
            spread,
            False,
        )
    )
    spray = "".join(_web("/login", t=T0 + i * 10, status=401) + "\n" for i in range(30))
    probes.append(
        Probe(
            "KALLYEL-WEB-008",
            "Tentativas lentas de login (1 resposta 401 a cada 10 s)",
            "access.log",
            spray,
            False,
        )
    )

    ssh_slow = "".join(_ssh_fail(T0 + i * 60, ATT) + "\n" for i in range(10))
    probes.append(
        Probe(
            "KALLYEL-AUTH-001",
            "Força bruta lenta de SSH (1 falha por minuto)",
            "auth.log",
            ssh_slow,
            False,
        )
    )
    ssh_dist = "".join(
        _ssh_fail(T0 + j, f"203.0.113.{231 + i}") + "\n" for i in range(20) for j in range(2)
    )
    probes.append(
        Probe(
            "KALLYEL-AUTH-001",
            "Spray distribuído de SSH (20 IPs x 2 falhas)",
            "auth.log",
            ssh_dist,
            False,
        )
    )
    key_only = "".join(
        gen.auth_line(T0 + i, "sshd", 99, f"Invalid user admin{i} from {ATT} port {5000 + i}")
        + "\n"
        for i in range(10)
    )
    probes.append(
        Probe(
            "KALLYEL-AUTH-001",
            "Servidor só com chave: apenas 'Invalid user' no log",
            "auth.log",
            key_only,
            False,
        )
    )
    split = "".join(_ssh_fail(T0 + i, "203.0.113.240") + "\n" for i in range(6))
    split += (
        gen.auth_line(
            T0 + 20, "sshd", 99, "Accepted password for root from 203.0.113.241 port 4444 ssh2"
        )
        + "\n"
    )
    probes.append(
        Probe(
            "KALLYEL-AUTH-002",
            "Falhas de um IP e sucesso de outro (mesma conta)",
            "auth.log",
            split,
            False,
        )
    )
    pty = gen.auth_line(
        T0,
        "sudo",
        99,
        "  mallory : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",
    )
    probes.append(
        Probe(
            "KALLYEL-AUTH-003",
            "sudo python que abre shell (binário fora da lista)",
            "auth.log",
            pty + "\n",
            False,
        )
    )
    probes.append(
        Probe(
            "KALLYEL-APP-001",
            "Segredo com nome personalizado (`STRIPE_KEY=sk_live_...`)",
            "laravel.log",
            gen.laravel_record(
                T0, "ERROR", "Payment failed STRIPE_KEY=sk_live_FAKEFAKEFAKEFAKEFAKE00"
            )
            + "\n",
            False,
        )
    )
    return probes


# ---------------------------------------------------------------- execução
def _files(manifest: dict[str, object], base: Path) -> list[Path]:
    files = manifest["files"]
    assert isinstance(files, dict)
    return [base / name for name in files]


def run_evaluation(work: Path) -> Evaluation:
    rules = load_builtin_rules()
    stats = {r.id: RuleStats(r.id, r.title, r.severity.label) for r in rules}

    clean_dir = work / "clean"
    manifest = gen.write_dataset(
        clean_dir,
        nginx_lines=CLEAN["nginx"],
        auth_lines=CLEAN["auth"],
        laravel_lines=CLEAN["laravel"],
        seed=SEEDS[0],
    )
    result = analyze(_files(manifest, clean_dir), rules)
    for f in result.findings:
        stats[f.rule_id].unexpected += 1
    ev = Evaluation(
        rules=[],
        probes=[],
        clean_lines=result.stats.lines,
        scenario_runs=len(SEEDS),
        scenario_lines=0,
        clean_findings=len(result.findings),
    )

    for seed in SEEDS:
        d = work / f"scen{seed}"
        manifest = gen.write_dataset(
            d,
            nginx_lines=SCEN_BACKGROUND["nginx"],
            auth_lines=SCEN_BACKGROUND["auth"],
            laravel_lines=SCEN_BACKGROUND["laravel"],
            scenarios=list(gen.SCENARIOS),
            seed=seed,
        )
        result = analyze(_files(manifest, d), rules)
        ev.scenario_lines += result.stats.lines
        expected = {(e[0], e[1] or None) for s in manifest["scenarios"] for e in s["expected"]}
        found = {(f.rule_id, f.client_ip) for f in result.findings}
        for rule_id, _ip in expected:
            stats[rule_id].expected += 1
        for rule_id, _ip in expected & found:
            stats[rule_id].detected += 1
        for rule_id, _ip in found - expected:
            stats[rule_id].unexpected += 1
            ev.scenario_findings_unexpected += 1

    probe_dir = work / "probes"
    for i, probe in enumerate(build_probes()):
        d = probe_dir / str(i)
        d.mkdir(parents=True)
        (d / probe.filename).write_text(probe.text, encoding="utf-8")
        result = analyze([d / probe.filename], rules)
        probe.detected = probe.rule_id in {f.rule_id for f in result.findings}
        ev.probes.append(probe)

    ev.rules = [stats[r.id] for r in rules]
    return ev


# --------------------------------------------------------------- Markdown
def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def render_block(ev: Evaluation) -> str:
    out: list[str] = [BEGIN, ""]
    out.append("### Parâmetros desta medição")
    out.append("")
    out.append(
        f"- Semente(s) de cenário: {', '.join(map(str, SEEDS))} ({ev.scenario_runs} execuções, {ev.scenario_lines} linhas no total, com os 8 cenários de ataque em cada uma)."
    )
    out.append(
        f"- Tráfego limpo (sem ataque): {CLEAN['nginx']} linhas nginx, {CLEAN['auth']} de auth.log e "
        f"{CLEAN['laravel']} de Laravel ({ev.clean_lines} linhas lidas), semente {SEEDS[0]}."
    )
    out.append(
        "- Gerado por `python tests/data/evaluate.py --update-docs`; um teste confere que este bloco está atualizado."
    )
    out.append("")
    out.append("### Resultado por regra")
    out.append("")
    out.append(
        "| Regra | Gravidade | Detectado / esperado | Achados inesperados | Lacunas conhecidas |"
    )
    out.append("|---|---|---|---|---|")
    total_exp = total_det = total_unexp = 0
    for r in ev.rules:
        total_exp += r.expected
        total_det += r.detected
        total_unexp += r.unexpected
        out.append(
            f"| `{r.rule_id}` {_cell(r.title)} | {r.severity} | {r.detected}/{r.expected} | "
            f"{r.unexpected} | {_cell(KNOWN_GAPS.get(r.rule_id, '-'))} |"
        )
    out.append(f"| **Total** | | **{total_det}/{total_exp}** | **{total_unexp}** | |")
    out.append("")
    out.append(
        '"Achados inesperados" são achados (regra, IP) que não estão no gabarito do gerador: '
        f"{ev.clean_findings} vieram do tráfego limpo e {ev.scenario_findings_unexpected} do fundo "
        "normal das execuções com cenários. Todos seriam falsos positivos nesta base sintética."
    )
    out.append("")
    out.append("### Variações verificadas (lacunas e controles)")
    out.append("")
    out.append(
        'Cada linha é um pequeno log executado de verdade. "Não detectado" é uma lacuna conhecida; '
        '"controle" mostra que uma variação parecida é detectada.'
    )
    out.append("")
    out.append("| Regra | Variação | Tipo | Resultado |")
    out.append("|---|---|---|---|")
    for p in ev.probes:
        kind = "controle" if p.expect_detected else "lacuna suspeita"
        result = "detectado" if p.detected else "**não detectado**"
        out.append(f"| `{p.rule_id}` | {_cell(p.title)} | {kind} | {result} |")
    out.append("")
    out.append(END)
    return "\n".join(out) + "\n"


def current_block(work: Path | None = None) -> str:
    if work is not None:
        return render_block(run_evaluation(work))
    with tempfile.TemporaryDirectory() as tmp:
        return render_block(run_evaluation(Path(tmp)))


def update_docs(path: Path = DOC_PATH) -> None:
    text = path.read_text(encoding="utf-8")
    start, end = text.index(BEGIN), text.index(END) + len(END)
    new = text[:start] + current_block().rstrip("\n") + text[end:]
    path.write_text(new, encoding="utf-8", newline="\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--update-docs", action="store_true", help="reescreve o bloco em docs/avaliacao.md"
    )
    args = parser.parse_args(argv)
    if args.update_docs:
        update_docs()
        print(f"atualizado: {DOC_PATH}")
    else:
        sys.stdout.buffer.write(current_block().encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
