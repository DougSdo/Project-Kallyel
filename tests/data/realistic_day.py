"""Uma "jornada" sintética mais realista: tráfego normal e vários atacantes ao longo do dia.

Diferenças em relação aos cenários isolados de ``generate.py``:

- **Vários atacantes** por tipo de ataque, em horários e com IPs diferentes (IPv4 e IPv6).
- **Ferramentas variadas:** scanner que se identifica (Nikto, gobuster), SQLi com sqlmap e
  SQLi com User-Agent de navegador, varredura disfarçada de navegador.
- **Ataques que o Kallyel NÃO detecta** (varredura lenta, força bruta de SSH lenta), marcados no
  gabarito como lacunas conhecidas, porque a realidade também tem isso.
- O gabarito (``gabarito.json`` e ``gabarito.md``) fica **fora** da pasta dos logs, para a
  análise da pasta não tropeçar nele.

100% sintético: IPs de documentação, nenhum dado de terceiros, nenhum código de ataque (as
"ações" são só linhas de log).

    python tests/data/realistic_day.py --out logs/realista
    kallyel analyze logs/realista
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from random import Random

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:  # permite rodar como script
    sys.path.insert(0, str(ROOT))

from tests.data import generate as gen  # noqa: E402

NIKTO_UA = "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)"
SQLMAP_UA = "sqlmap/1.7.11#stable (https://sqlmap.org)"
GOBUSTER_UA = "gobuster/3.6"
SCANNER_RULE = "KALLYEL-WEB-005"


@dataclass(frozen=True)
class Episode:
    """Um ataque reaproveitando um cenário base, com outro IP, horário e ferramenta."""

    base: str
    ip: str
    at: float  # fração do dia (0 a 1)
    title: str
    ua: str | None = None  # troca o User-Agent do cenário base
    expected_change: tuple[tuple[str, bool], ...] = ()  # (regra, True=acrescenta / False=remove)


# O IP original de cada cenário base (em generate.py) é trocado pelo IP do episódio.
BASE_IP = {
    "scanner_sweep": "203.0.113.201",
    "sqli": "203.0.113.202",
    "ssh_bruteforce_success": "203.0.113.203",
    "login_spray": "203.0.113.204",
    "xss": "203.0.113.205",
    "traversal": "203.0.113.206",
    "rce": "203.0.113.207",
}
BASE_UA = {"scanner_sweep": NIKTO_UA, "sqli": gen.CHROME}

EPISODES: tuple[Episode, ...] = (
    Episode("scanner_sweep", "203.0.113.211", 0.06, "Varredura com Nikto (identifica-se)"),
    Episode("sqli", "203.0.113.212", 0.14, "SQLi com sqlmap (User-Agent de ferramenta)", SQLMAP_UA, (("KALLYEL-WEB-005", True),)),
    Episode("ssh_bruteforce_success", "203.0.113.213", 0.19, "Força bruta de SSH e login com sucesso (1º atacante)"),
    Episode("xss", "203.0.113.214", 0.27, "XSS refletido"),
    Episode("scanner_sweep", "203.0.113.215", 0.34, "Varredura com gobuster", GOBUSTER_UA),
    Episode("login_spray", "203.0.113.216", 0.41, "Tentativas repetidas de login web"),
    Episode("traversal", "203.0.113.217", 0.48, "Path traversal e LFI"),
    Episode("sqli", "203.0.113.218", 0.55, "SQLi com User-Agent de navegador (disfarçado)"),
    Episode("rce", "203.0.113.219", 0.62, "Injeção de comando e log4shell"),
    Episode("scanner_sweep", "203.0.113.220", 0.69, "Varredura DISFARÇADA de navegador (a regra de scanner não vê; a de volume vê)", gen.CHROME, (("KALLYEL-WEB-005", False),)),
    Episode("ssh_bruteforce_success", "203.0.113.221", 0.76, "Força bruta de SSH e login com sucesso (2º atacante)"),
    Episode("rce", "2001:db8:bad:1::7", 0.83, "Injeção de comando a partir de IPv6"),
    Episode("login_spray", "203.0.113.222", 0.9, "Tentativas repetidas de login web (2º atacante)"),
    Episode("laravel_leak", "", 0.5, "Vazamento de senha do banco em um stack trace do Laravel (sem IP)"),
)  # fmt: skip


def remap(base: gen.Scenario, ep: Episode) -> gen.Scenario:
    """Copia o cenário base trocando IP e User-Agent, e ajusta o gabarito."""
    old_ip, new_ip = BASE_IP.get(ep.base, base.ip or ""), ep.ip

    def fix(lines: tuple[gen.Line, ...]) -> tuple[gen.Line, ...]:
        out = []
        for t, text in lines:
            if old_ip and new_ip:  # episódios sem IP (log de aplicação) não trocam nada
                text = text.replace(old_ip, new_ip)
            if ep.ua and ep.base in BASE_UA:
                text = text.replace(BASE_UA[ep.base], ep.ua)
            out.append((t, text))
        return tuple(out)

    expected: list[gen.Expected] = [(r, new_ip if ip == old_ip else ip) for r, ip in base.expected]
    for rule, add in ep.expected_change:
        if add:
            expected.append((rule, new_ip))
        else:
            expected = [(r, ip) for r, ip in expected if not (r == rule and ip == new_ip)]
    return replace(
        base,
        name=ep.base,
        description=ep.title,
        ip=new_ip or None,
        nginx=fix(base.nginx),
        auth=fix(base.auth),
        laravel=fix(base.laravel),
        expected=tuple(expected),
    )


def known_gap_episodes(
    day_start: float,
    span: float,
    *,
    slow_ip: str = "203.0.113.230",
    ssh_ip: str = "203.0.113.231",
    slow_at: float = 0.3,
    ssh_at: float = 0.45,
) -> list[gen.Scenario]:
    """Ataques lentos que o Kallyel hoje NÃO detecta (lacunas documentadas em avaliacao.md)."""
    rng = Random("gaps")
    t0 = day_start + span * slow_at
    paths = gen.SWEEP_PATHS + [f"/{w}" for w in gen.WORDLIST]
    rng.shuffle(paths)
    slow = tuple(
        (t0 + i * 6, gen.nginx_line(slow_ip, t0 + i * 6, "GET", p, 404, 162, gen.CHROME))
        for i, p in enumerate(paths[:30])
    )
    t1 = day_start + span * ssh_at
    ssh = tuple(
        (
            t1 + i * 60,
            gen.auth_line(t1 + i * 60, "sshd", 7000 + i, f"Failed password for root from {ssh_ip} port {51000 + i} ssh2"),
        )
        for i in range(10)
    )  # fmt: skip
    return [
        gen.Scenario(
            name="slow_scan",
            description=(
                "Varredura LENTA (1 requisição a cada 6 s): a regra de volume (WEB-007) NÃO "
                "dispara, lacuna conhecida; a de arquivo sensível (WEB-004) dispara pelos caminhos"
            ),
            ip=slow_ip,
            nginx=slow,
            expected=(("KALLYEL-WEB-004", slow_ip),),
        ),
        gen.Scenario(
            name="slow_ssh",
            description="Força bruta de SSH LENTA (1 falha por minuto): lacuna conhecida, NÃO deve ser detectada",
            ip=ssh_ip,
            auth=ssh,
        ),
    ]


def build_episodes(span: float) -> list[gen.Scenario]:
    day_start = gen.START.timestamp()
    built: list[gen.Scenario] = []
    for i, ep in enumerate(EPISODES):
        base = gen.SCENARIOS[ep.base](day_start + span * ep.at, Random(f"day:{i}"))
        built.append(remap(base, ep))
    built.extend(known_gap_episodes(day_start, span))
    return built


def _first_time(s: gen.Scenario) -> float:
    return min(t for t, _ in (*s.nginx, *s.auth, *s.laravel))


def render_gabarito(scenarios: Sequence[gen.Scenario], files: dict[str, int]) -> str:
    rows = sorted(scenarios, key=_first_time)
    out = [
        "# Gabarito da jornada sintética",
        "",
        "Dados 100% sintéticos (IPs de documentação).",
        "",
    ]
    out.append("Linhas por arquivo: " + ", ".join(f"`{k}` {v}" for k, v in files.items()) + ".")
    out += ["", "| Hora (UTC) | IP | O que acontece | Regras esperadas |", "|---|---|---|---|"]
    for s in rows:
        when = datetime.fromtimestamp(_first_time(s), tz=timezone.utc).strftime("%H:%M:%S")
        expected = ", ".join(sorted({r for r, _ in s.expected})) or "**nenhuma (lacuna conhecida)**"
        out.append(f"| {when} | `{s.ip or '-'}` | {s.description} | {expected} |")
    out += [
        "",
        "Rode `kallyel analyze` na pasta dos logs e compare: cada linha da tabela com regras",
        "esperadas deve aparecer como achado para aquele IP; as marcadas como lacuna, não.",
        "",
    ]
    return "\n".join(out)


def build_blind_episodes(span: float, seed: int) -> list[gen.Scenario]:
    """Prova às cegas: sorteia quais ataques entram, os IPs e os horários.

    Nada aqui é impresso nem descrito; o gabarito só é lido por ``--check``, depois que a
    pessoa analisou os logs por conta própria.
    """
    rng = Random(f"blind:{seed}")
    day_start = gen.START.timestamp()
    free_ips = [f"203.0.113.{n}" for n in range(200, 255) if n not in (230, 231)]
    rng.shuffle(free_ips)

    chosen = rng.sample(list(EPISODES), rng.randint(8, len(EPISODES)))
    times = sorted(rng.uniform(0.04, 0.96) for _ in chosen)
    rng.shuffle(chosen)  # o tipo de ataque não segue a ordem do relógio
    built: list[gen.Scenario] = []
    for i, (ep, at) in enumerate(zip(chosen, times, strict=True)):
        ip = ep.ip if (":" in ep.ip or not ep.ip) else free_ips.pop()
        base = gen.SCENARIOS[ep.base](day_start + span * at, Random(f"blind:{seed}:{i}"))
        built.append(remap(base, replace(ep, ip=ip, at=at)))

    gaps = known_gap_episodes(
        day_start,
        span,
        slow_ip=free_ips.pop(),
        ssh_ip=free_ips.pop(),
        slow_at=rng.uniform(0.04, 0.96),
        ssh_at=rng.uniform(0.04, 0.96),
    )
    built.extend(g for g in gaps if rng.random() < 0.6)
    return built


def build(
    out: Path,
    *,
    nginx_lines: int = 150_000,
    auth_lines: int = 6_000,
    laravel_lines: int = 1_500,
    seed: int = 42,
    blind: bool = False,
) -> dict[str, object]:
    """Gera os logs em ``out`` e o gabarito em ``<out>-gabarito`` (ao lado).

    Em modo cego (``blind=True``) só se grava ``gabarito.json`` (sem a versão legível em
    Markdown), e os episódios são sorteados a partir da semente.
    """
    span = max(nginx_lines * gen.MEAN_GAP_SECONDS, 3600.0)
    scenarios = build_blind_episodes(span, seed) if blind else build_episodes(span)
    gabarito_dir = out.with_name(out.name + "-gabarito")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        manifest = gen.write_dataset(
            work, nginx_lines=nginx_lines, auth_lines=auth_lines, laravel_lines=laravel_lines,
            seed=seed, custom=scenarios,
        )  # fmt: skip
        out.mkdir(parents=True, exist_ok=True)
        gabarito_dir.mkdir(parents=True, exist_ok=True)
        for name in manifest["files"]:
            shutil.move(str(work / name), str(out / name))
        (gabarito_dir / "gabarito.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if not blind:
            (gabarito_dir / "gabarito.md").write_text(
                render_gabarito(scenarios, manifest["files"]), encoding="utf-8"
            )
    manifest["gabarito_dir"] = str(gabarito_dir)
    return manifest


def check(result_json: Path, gabarito_json: Path) -> dict[str, object]:
    """Compara o resultado de ``kallyel analyze -f json`` com o gabarito."""
    result = json.loads(result_json.read_text(encoding="utf-8"))
    truth = json.loads(gabarito_json.read_text(encoding="utf-8"))
    found = {(f["rule_id"], f["client_ip"] or "") for f in result["findings"]}
    expected = {(rule, ip) for rule, ip in truth["expected"]}
    descriptions: dict[str, str] = {s["ip"] or "": s["description"] for s in truth["scenarios"]}
    return {
        "expected": len(expected),
        "found_correct": len(expected & found),
        "missed": sorted(expected - found),
        "extra": sorted(found - expected),
        "descriptions": descriptions,
        "exact": found == expected,
    }


def render_check(c: dict[str, object]) -> str:
    missed = c["missed"]
    extra = c["extra"]
    descriptions: dict[str, str] = c["descriptions"]  # type: ignore[assignment]
    lines = [f"Acertos: {c['found_correct']} de {c['expected']} achados esperados."]
    if not missed and not extra:
        lines.append("Correspondência exata com o gabarito.")
    for rule, ip in missed:  # type: ignore[attr-defined]
        what = descriptions.get(ip, "?")
        lines.append(f"FALTOU: {rule} para {ip or '(sem IP)'}: {what}")
    for rule, ip in extra:  # type: ignore[attr-defined]
        lines.append(
            f"A MAIS: {rule} para {ip or '(sem IP)'}: não está no gabarito "
            "(pode ser falso positivo ou uma limitação do gabarito)"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gera uma jornada sintética realista de logs.")
    parser.add_argument(
        "--out", type=Path, help="pasta dos logs (o gabarito vai em <out>-gabarito)"
    )
    parser.add_argument("--nginx-lines", type=int, default=150_000)
    parser.add_argument("--auth-lines", type=int, default=6_000)
    parser.add_argument("--laravel-lines", type=int, default=1_500)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument(
        "--blind",
        action="store_true",
        help="prova às cegas: sorteia ataques, IPs e horários; o gabarito só é lido por --check",
    )
    parser.add_argument(
        "--check",
        type=Path,
        metavar="RESULTADO.json",
        help="compara o resultado de 'kallyel analyze -f json' com o gabarito",
    )
    parser.add_argument(
        "--gabarito",
        type=Path,
        help="gabarito.json (com --check); padrão: <out>-gabarito/gabarito.json",
    )
    args = parser.parse_args(argv)

    if args.check:
        gabarito = args.gabarito or (
            args.out.with_name(args.out.name + "-gabarito") / "gabarito.json" if args.out else None
        )
        if gabarito is None:
            parser.error("--check precisa de --gabarito ou de --out")
        outcome = check(args.check, gabarito)
        sys.stdout.buffer.write((render_check(outcome) + "\n").encode("utf-8"))
        return 0 if outcome["exact"] else 1

    if args.out is None:
        parser.error("--out é obrigatório para gerar os logs")
    seed = (
        args.seed if args.seed is not None else (Random().randrange(1, 10**6) if args.blind else 42)
    )
    manifest = build(
        args.out,
        nginx_lines=args.nginx_lines,
        auth_lines=args.auth_lines,
        laravel_lines=args.laravel_lines,
        seed=seed,
        blind=args.blind,
    )
    if args.blind:
        message = {
            "logs": str(args.out),
            "linhas": manifest["files"],
            "semente": seed,
            "aviso": "Gabarito guardado; NAO abra antes de analisar. Depois: --check RESULTADO.json",
        }
    else:
        message = {
            "logs": str(args.out),
            "gabarito": manifest["gabarito_dir"],
            "linhas": manifest["files"],
        }
    print(json.dumps(message, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
