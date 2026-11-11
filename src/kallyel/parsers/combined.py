"""Parser do formato *combined* (nginx e Apache).

As regexes usam apenas classes de caracteres disjuntas e quantificadores sem
aninhamento, para ter tempo linear mesmo com linhas hostis.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import ClassVar
from urllib.parse import urlsplit

from kallyel.ingest import RawLine
from kallyel.model import Event, truncate
from kallyel.parsers.base import LineParser, unparsed_event

_QUOTED = r'(?:[^"\\]|\\.)*'

_COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) "
    r"\[(?P<ts>[^\]]{1,64})\] "
    rf'"(?P<req>{_QUOTED})" '
    r"(?P<status>\d{3}) (?P<bytes>\d+|-)"
    rf'(?: "(?P<ref>{_QUOTED})" "(?P<ua>{_QUOTED})")?'
)

_TS = re.compile(
    r"^(?P<d>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):"
    r"(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2}) (?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2})$"
)
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1
    )
}
_HTTP_VERSION = re.compile(r"^HTTP/\d(?:\.\d)?$")


def parse_clf_timestamp(value: str) -> datetime | None:
    """Converte ``10/Oct/2023:13:55:36 -0300`` para UTC, sem depender de locale."""
    m = _TS.match(value)
    if not m:
        return None
    month = _MONTHS.get(m["mon"].lower())
    if month is None:
        return None
    offset = timedelta(hours=int(m["oh"]), minutes=int(m["om"]))
    if m["sign"] == "-":
        offset = -offset
    try:
        local = datetime(
            int(m["y"]), month, int(m["d"]), int(m["H"]), int(m["M"]), int(m["S"]),
            tzinfo=timezone(offset),
        )  # fmt: skip
    except ValueError:
        return None
    return local.astimezone(timezone.utc)


def _unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _split_request(req: str) -> tuple[str | None, str | None, str | None]:
    """Separa ``METHOD alvo HTTP/x`` em método, caminho e query.

    Requisições malformadas (bytes binários, TLS em porta HTTP) mantêm o texto
    cru como caminho, para que as regras ainda possam examiná-lo.
    """
    parts = req.split(" ")
    if len(parts) >= 3 and _HTTP_VERSION.match(parts[-1]) and parts[0].isalpha():
        method = parts[0].upper()
        target = " ".join(parts[1:-1])
    elif len(parts) == 2 and parts[0].isalpha():
        method, target = parts[0].upper(), parts[1]
    else:
        return None, (req or None), None
    if "://" in target[:12]:  # forma absoluta (proxy): GET http://host/x
        split = urlsplit(target)
        target = (split.path or "/") + (f"?{split.query}" if split.query else "")
    path, _, query = target.partition("?")
    return method, path or None, query or None


class CombinedParser(LineParser):
    name: ClassVar[str] = "combined"
    source_types: ClassVar[tuple[str, ...]] = ("nginx", "apache")
    description: ClassVar[str] = "Access log nginx e Apache no formato combined"

    def default_source_type(self, source_file: str) -> str:
        lowered = source_file.lower()
        if "apache" in lowered or "httpd" in lowered:
            return "apache"
        return "nginx"

    def parse_line(self, line: RawLine, source_type: str) -> Event:
        m = _COMBINED.match(line.text)
        if not m:
            return unparsed_event(line, source_type)
        timestamp = parse_clf_timestamp(m["ts"])
        if timestamp is None:
            return unparsed_event(line, source_type)
        method, path, query = _split_request(_unescape(m["req"]))
        user = m["user"]
        ref = m["ref"]
        ua = m["ua"]
        return Event(
            source_type=source_type,
            source_file=line.source_file,
            line_no=line.line_no,
            raw=truncate(line.text),
            parse_ok=True,
            timestamp=timestamp,
            client_ip=m["ip"],
            user=None if user == "-" else user,
            http_method=method,
            http_path=path,
            http_query=query,
            http_status=int(m["status"]),
            http_bytes=None if m["bytes"] == "-" else int(m["bytes"]),
            user_agent=None if ua is None or ua == "-" else _unescape(ua),
            referrer=None if ref is None or ref == "-" else _unescape(ref),
            action="http.request",
        )
