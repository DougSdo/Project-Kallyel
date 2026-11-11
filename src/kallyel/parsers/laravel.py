"""Parser de ``laravel.log`` (Monolog), com registros de várias linhas (stack traces).

Um registro começa em uma linha ``[2024-01-05 12:00:01] production.ERROR: mensagem`` e vai
até a próxima linha que comece com ``[data]``. As linhas seguintes (``[stacktrace]``,
``#0 ...``) entram na ``message`` do mesmo evento.

Limites contra entrada hostil: um registro guarda no máximo ``MAX_RECORD_LINES`` linhas e
``MAX_RECORD_CHARS`` caracteres; o excedente é contado em ``line_count`` mas não fica na
memória.

Horário sem fuso é tratado como ``UTC + utc_offset`` (``app.timezone`` do Laravel; padrão UTC).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timezone
from typing import ClassVar

from kallyel.ingest import RawLine
from kallyel.model import Event, truncate
from kallyel.parsers.base import Parser, ParserOptions, naive_to_utc, unparsed_event

MAX_RECORD_LINES = 1000
MAX_RECORD_CHARS = 64 * 1024

_HEADER = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)\] "
    r"(?P<env>[\w-]{1,40})\.(?P<level>[A-Za-z]{3,9}): (?P<msg>.*)$"
)
_ERROR_LEVELS = {"ERROR", "CRITICAL", "ALERT", "EMERGENCY"}


def _action_for(level: str) -> str:
    up = level.upper()
    if up in _ERROR_LEVELS:
        return "app.error"
    if up == "WARNING":
        return "app.warning"
    return "app.info"


class _Record:
    """Registro em construção: primeira linha + continuações, com tetos de tamanho."""

    __slots__ = ("chars", "first", "level", "line_count", "msg_parts", "timestamp", "truncated")

    def __init__(self, first: RawLine, timestamp: datetime, level: str, message: str) -> None:
        self.first = first
        self.timestamp = timestamp
        self.level = level
        self.msg_parts: list[str] = [message[:MAX_RECORD_CHARS]]
        self.chars = len(self.msg_parts[0])
        self.line_count = 1
        self.truncated = len(message) > MAX_RECORD_CHARS or first.truncated

    def add(self, line: RawLine) -> None:
        self.line_count += 1
        if line.truncated:
            self.truncated = True
        if self.line_count > MAX_RECORD_LINES or self.chars >= MAX_RECORD_CHARS:
            self.truncated = True
            return
        room = MAX_RECORD_CHARS - self.chars
        text = line.text[:room]
        if len(text) < len(line.text):
            self.truncated = True
        self.msg_parts.append(text)
        self.chars += len(text) + 1

    def to_event(self, source_type: str) -> Event:
        message = "\n".join(self.msg_parts)
        if self.truncated:
            message += "\n…[truncado]"
        return Event(
            source_type=source_type,
            source_file=self.first.source_file,
            line_no=self.first.line_no,
            raw=truncate(message),
            parse_ok=True,
            timestamp=self.timestamp,
            action=_action_for(self.level),
            message=message,
            line_count=self.line_count,
        )


class LaravelParser(Parser):
    name: ClassVar[str] = "laravel"
    source_types: ClassVar[tuple[str, ...]] = ("laravel",)
    description: ClassVar[str] = "laravel.log (Monolog), com stack traces de várias linhas"

    def __init__(self, options: ParserOptions | None = None) -> None:
        self._options = options or ParserOptions()

    def _timestamp(self, text: str) -> datetime | None:
        value = text.replace(" ", "T", 1).replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return naive_to_utc(parsed, self._options.utc_offset)
        return parsed.astimezone(timezone.utc)

    def parse_stream(
        self, lines: Iterable[RawLine], source_type: str | None = None
    ) -> Iterator[Event]:
        st = source_type or self.source_types[0]
        current: _Record | None = None
        for line in lines:
            header = _HEADER.match(line.text)
            if header:
                timestamp = self._timestamp(header["ts"])
                if current is not None:
                    yield current.to_event(st)
                    current = None
                if timestamp is None:  # cabeçalho com data impossível: não reconhecido
                    yield unparsed_event(line, st)
                    continue
                current = _Record(line, timestamp, header["level"], header["msg"])
                continue
            if current is not None:
                current.add(line)
            elif line.text.strip():  # continuação sem cabeçalho (arquivo cortado)
                yield unparsed_event(line, st)
        if current is not None:
            yield current.to_event(st)

    def sniff(self, sample: Sequence[str]) -> float:
        texts = [t for t in sample if t.strip()]
        if not texts:
            return 0.0
        if _HEADER.match(texts[0]):
            return 1.0
        # Arquivo rotacionado pode começar no meio de um stack trace.
        return 0.5 if any(_HEADER.match(t) for t in texts) else 0.0
