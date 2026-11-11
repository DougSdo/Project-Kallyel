"""Parser de ``auth.log`` / ``secure`` (syslog) para sshd, sudo e useradd.

Pontos de atenção:

- **Entrada hostil.** O nome de usuário que aparece em ``Failed password for <usuário> from
  <ip>`` é escolhido por quem ataca e pode conter " from 10.0.0.1 port 22". Por isso o IP é
  ancorado pela direita (a regex é gananciosa no usuário) e só se aceita o sufixo que o
  próprio sshd escreve.
- **Ano.** O syslog tradicional não traz ano. Usa-se o ano da data de modificação do arquivo
  como referência (uma entrada nunca está no futuro em relação a ele), o que também resolve a
  virada de ano (dezembro em arquivo modificado em janeiro vira o ano anterior).
- **Fuso.** Horário sem fuso é tratado como ``UTC + utc_offset`` (padrão UTC). Se o servidor
  usa outro fuso, informe ``--log-utc-offset``, senão a correlação com logs que trazem fuso
  (nginx) fica deslocada.
- Linha com envelope syslog válido de programa que não interpretamos vira ``log.other``
  (reconhecida). Só o que não casa nem o envelope é "não reconhecido".
"""

from __future__ import annotations

import contextlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

from kallyel.ingest import RawLine
from kallyel.model import Event, truncate
from kallyel.netutil import parse_ip
from kallyel.parsers.base import LineParser, ParserOptions, naive_to_utc, unparsed_event

_PROG = r"(?P<prog>[^\s:\[\]]{1,64})(?:\[(?P<pid>\d{1,10})\])?"
_TRADITIONAL = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) "
    rf"(?P<host>\S{{1,255}}) {_PROG}: (?P<msg>.*)$"
)
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) "
    rf"(?P<host>\S{{1,255}}) {_PROG}: (?P<msg>.*)$"
)
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

# sshd. O sufixo permitido é exatamente o que o sshd escreve (ssh2 e, no publickey, tipo + impressão).
_SSH_TAIL = r"(?: ssh2(?:: [A-Za-z0-9._-]{1,40} \S{1,200})?)?$"
_FAILED = re.compile(
    r"^Failed (?P<method>[\w/-]{1,40}) for (?:invalid user )?(?P<user>.+) "
    rf"from (?P<ip>\S+) port (?P<port>\d{{1,5}}){_SSH_TAIL}"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>[\w/-]{1,40}) for (?P<user>.+) "
    rf"from (?P<ip>\S+) port (?P<port>\d{{1,5}}){_SSH_TAIL}"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port \d{1,5})?$")
_MAX_ATTEMPTS = re.compile(
    r"^(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(?P<user>.+) "
    r"from (?P<ip>\S+) port \d{1,5} ssh2(?: \[preauth\])?$"
)
_REPEATED = re.compile(r"^message repeated \d{1,6} times: \[ ?(?P<inner>.*)\]$")

# sudo
_SUDO_COMMAND = re.compile(r"^\s*(?P<user>\S+) : .*?COMMAND=(?P<cmd>.*)$")
_SUDO_FAILURE = re.compile(
    r"^\s*(?P<user>\S+) : (?:\d{1,4} incorrect password attempts?|user NOT in sudoers|command not allowed)"
)
_PAM_SUDO_FAILURE = re.compile(
    r"^pam_unix\(sudo:auth\): authentication failure;.*?\buser=(?P<user>\S+)"
)

# useradd
_NEW_USER = re.compile(r"^new user: name=(?P<name>[^,]{1,64}),")


def infer_year_datetime(
    month: int, day: int, hour: int, minute: int, second: int, reference: datetime
) -> datetime | None:
    """Escolhe o ano mais recente em que a data não fica no futuro em relação à referência."""
    limit = reference + timedelta(days=1)
    for year in range(reference.year, reference.year - 5, -1):
        try:
            candidate = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError:  # 29 de fevereiro em ano não bissexto
            continue
        if candidate <= limit:
            return candidate
    return None


class AuthLogParser(LineParser):
    name: ClassVar[str] = "authlog"
    source_types: ClassVar[tuple[str, ...]] = ("authlog",)
    description: ClassVar[str] = "auth.log / secure (syslog): sshd, sudo e useradd"

    def __init__(self, options: ParserOptions | None = None) -> None:
        self._options = options or ParserOptions()
        self._references: dict[str, datetime] = {}

    # --------------------------------------------------------------- horário
    def _reference(self, source_file: str) -> datetime:
        if self._options.reference_time is not None:
            return self._options.reference_time
        cached = self._references.get(source_file)
        if cached is not None:
            return cached
        ref = datetime.now(timezone.utc)
        if not source_file.startswith("<"):
            with contextlib.suppress(OSError, ValueError, OverflowError):
                ref = datetime.fromtimestamp(Path(source_file).stat().st_mtime, tz=timezone.utc)
        self._references[source_file] = ref
        return ref

    def _timestamp(self, m: re.Match[str], source_file: str) -> datetime | None:
        if "ts" in m.groupdict() and m["ts"]:
            text = m["ts"].replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(text).astimezone(timezone.utc)
            except ValueError:
                return None
        month = _MONTHS.get(m["mon"])
        if month is None:
            return None
        local = infer_year_datetime(
            month,
            int(m["day"]),
            int(m["h"]),
            int(m["m"]),
            int(m["s"]),
            self._reference(source_file) + self._options.utc_offset,
        )
        if local is None:
            return None
        return naive_to_utc(local.replace(tzinfo=None), self._options.utc_offset)

    # ---------------------------------------------------------------- linhas
    def parse_line(self, line: RawLine, source_type: str) -> Event:
        m = _TRADITIONAL.match(line.text) or _ISO.match(line.text)
        if not m:
            return unparsed_event(line, source_type)
        timestamp = self._timestamp(m, line.source_file)
        if timestamp is None:
            return unparsed_event(line, source_type)

        message = m["msg"]
        repeated = _REPEATED.match(message)
        if repeated:  # "message repeated N times": interpreta a mensagem interna uma vez
            message = repeated["inner"].strip()
        action, user, ip, text = self._classify(m["prog"].lower(), message)
        return Event(
            source_type=source_type,
            source_file=line.source_file,
            line_no=line.line_no,
            raw=truncate(line.text),
            parse_ok=True,
            timestamp=timestamp,
            client_ip=ip,
            user=user,
            action=action,
            message=text,
        )

    @staticmethod
    def _valid_ip(value: str) -> str | None:
        return value if parse_ip(value) is not None else None

    def _classify(self, prog: str, msg: str) -> tuple[str, str | None, str | None, str]:
        """Devolve (ação, usuário, ip, mensagem normalizada)."""
        if prog in {"sshd", "sshd-session"}:  # OpenSSH 9.8+ registra como sshd-session
            for regex, action in (
                (_FAILED, "auth.failure"),
                (_ACCEPTED, "auth.success"),
                (_MAX_ATTEMPTS, "auth.max_attempts"),
                (_INVALID_USER, "auth.invalid_user"),
            ):
                found = regex.match(msg)
                if found:
                    return action, found["user"] or None, self._valid_ip(found["ip"]), msg
        elif prog == "sudo":
            # Falhas também trazem "COMMAND=", mas o comando NÃO foi executado: testar antes.
            found = _SUDO_FAILURE.match(msg)
            if found:
                return "sudo.failure", found["user"], None, msg.strip()
            found = _SUDO_COMMAND.match(msg)
            if found:
                return "sudo.command", found["user"], None, found["cmd"]
            found = _PAM_SUDO_FAILURE.match(msg)
            if found:
                return "sudo.failure", found["user"], None, msg
        elif prog == "useradd":
            found = _NEW_USER.match(msg)
            if found:
                return "user.created", found["name"], None, msg
        return "log.other", None, None, msg
