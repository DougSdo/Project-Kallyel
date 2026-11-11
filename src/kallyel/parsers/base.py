"""Interface comum dos parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import ClassVar

from kallyel.ingest import RawLine
from kallyel.model import Event, truncate


@dataclass(frozen=True, slots=True)
class ParserOptions:
    """Ajustes para formatos cujo horário não traz fuso (auth.log tradicional, Laravel)."""

    # Horário local do servidor = UTC + utc_offset.
    utc_offset: timedelta = timedelta(0)
    reference_time: datetime | None = None  # para deduzir o ano do syslog; None = data do arquivo


def naive_to_utc(local: datetime, offset: timedelta) -> datetime:
    """Interpreta um horário sem fuso como ``UTC + offset`` e converte para UTC."""
    return local.replace(tzinfo=timezone(offset)).astimezone(timezone.utc)


class Parser(ABC):
    """Um parser transforma linhas brutas em eventos normalizados.

    Linhas não reconhecidas viram ``Event(parse_ok=False)``: nunca são descartadas
    em silêncio.
    """

    name: ClassVar[str]
    source_types: ClassVar[tuple[str, ...]]
    description: ClassVar[str]

    @abstractmethod
    def parse_stream(
        self, lines: Iterable[RawLine], source_type: str | None = None
    ) -> Iterator[Event]:
        """Consome linhas de um arquivo e produz eventos."""

    @abstractmethod
    def sniff(self, sample: Sequence[str]) -> float:
        """Fração (0 a 1) das linhas de amostra que este parser reconhece."""

    def default_source_type(self, source_file: str) -> str:
        return self.source_types[0]


class LineParser(Parser):
    """Parser em que cada linha é um evento independente."""

    @abstractmethod
    def parse_line(self, line: RawLine, source_type: str) -> Event:
        """Interpreta uma linha; devolve ``parse_ok=False`` se não reconhecer."""

    def parse_stream(
        self, lines: Iterable[RawLine], source_type: str | None = None
    ) -> Iterator[Event]:
        for line in lines:
            if not line.text.strip():
                continue
            st = source_type or self.default_source_type(line.source_file)
            yield self.parse_line(line, st)

    def sniff(self, sample: Sequence[str]) -> float:
        texts = [t for t in sample if t.strip()]
        if not texts:
            return 0.0
        ok = sum(
            1
            for i, text in enumerate(texts, start=1)
            if self.parse_line(RawLine("<sniff>", i, text), self.source_types[0]).parse_ok
        )
        return ok / len(texts)


def unparsed_event(line: RawLine, source_type: str) -> Event:
    return Event(
        source_type=source_type,
        source_file=line.source_file,
        line_no=line.line_no,
        raw=truncate(line.text),
        parse_ok=False,
        action="unparsed",
    )
