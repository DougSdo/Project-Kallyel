"""Modelo de dados comum: Event, Finding e Severity."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

RAW_MAX_CHARS = 1024


def truncate(text: str, limit: int = RAW_MAX_CHARS) -> str:
    """Trunca texto e sinaliza o corte, sem nunca devolver mais que ``limit`` + marcador."""
    if len(text) <= limit:
        return text
    return text[:limit] + "…[truncado]"


PHASES = ("recon", "attempt", "success", "action")
PHASE_LABELS = {
    "recon": "reconhecimento",
    "attempt": "tentativa",
    "success": "sucesso",
    "action": "ação",
}


class Severity(IntEnum):
    """Gravidade de um achado. A ordem numérica permite comparar com ``>=``."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"gravidade inválida: {value!r} (use: {valid})") from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(slots=True)
class Event:
    """Evento normalizado. Todo parser devolve este tipo, reconhecido ou não.

    Convenção de ``action`` que as regras embutidas esperam (os parsers devem seguir):

    - ``http.request``: linha de access log (nginx, apache).
    - ``auth.failure`` / ``auth.success``: login SSH (``source_type="authlog"``);
      falhas de ``sudo`` NÃO usam estas ações.
    - ``auth.invalid_user`` / ``auth.max_attempts``: avisos do sshd que acompanham as falhas;
      informativos, não entram na contagem de falhas (evita contar a mesma tentativa duas vezes).
    - ``user.created``: criação de conta local; ``message`` começa com ``new user:``.
    - ``sudo.command``: comando executado via sudo; ``message`` é só a linha de comando.
    - ``sudo.failure``: senha errada, usuário fora do sudoers etc.
    - ``log.other``: linha com envelope syslog válido, mas de um programa ou mensagem que o
      Kallyel não interpreta. Conta como reconhecida; só "não reconhecida" é o que nem
      o envelope (data, host, programa) casou.
    - ``app.error``: registro de nível ERROR ou superior do Laravel, com o stack trace
      de várias linhas dentro de ``message``. ``app.warning`` e ``app.info`` para os demais.

    ``line_count`` é quantas linhas físicas o evento ocupa (registros multilinha do Laravel).
    """

    source_type: str
    source_file: str
    line_no: int
    raw: str
    parse_ok: bool = True
    timestamp: datetime | None = None  # sempre em UTC, com tzinfo
    client_ip: str | None = None
    user: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_query: str | None = None
    http_status: int | None = None
    http_bytes: int | None = None
    user_agent: str | None = None
    referrer: str | None = None
    action: str = "unparsed"
    message: str | None = None
    line_count: int = 1

    @property
    def http_path_query(self) -> str | None:
        """Caminho e query juntos, como aparecem na requisição."""
        if self.http_path is None:
            return None
        if self.http_query:
            return f"{self.http_path}?{self.http_query}"
        return self.http_path


@dataclass(slots=True)
class Evidence:
    """Referência a uma linha de log que sustenta um achado."""

    source_file: str
    line_no: int
    timestamp: datetime | None
    raw: str


@dataclass(slots=True)
class Finding:
    """Achado produzido por uma regra, com tudo que o analista precisa para decidir."""

    rule_id: str
    title: str
    severity: Severity
    client_ip: str | None
    evidence: list[Evidence] = field(default_factory=list)
    explain: str = ""
    false_positives: str = ""
    mitigation: str = ""
    attack: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    owasp: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 0  # eventos que sustentam o achado (pode ser maior que len(evidence))
    detail: str = ""  # contexto da regra (ex.: limiar e janela de uma regra de taxa)
    phase: str = "attempt"  # uma das PHASES
