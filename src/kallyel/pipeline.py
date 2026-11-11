"""Liga leitura e parsers: arquivos entram, eventos saem, com contabilidade."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from itertools import chain, islice
from pathlib import Path

from kallyel.ingest import RawLine, iter_input_files, read_file_lines, read_stdin_lines
from kallyel.model import Event
from kallyel.parsers import PARSERS, Parser, detect_parser

SNIFF_LINES = 50
UNPARSED_SAMPLE_LIMIT = 20


@dataclass(slots=True)
class IngestStats:
    files: int = 0
    lines: int = 0
    parsed: int = 0
    unparsed: int = 0
    truncated_lines: int = 0
    skipped_files: list[str] = field(default_factory=list)  # sem parser reconhecido
    unparsed_samples: list[Event] = field(default_factory=list)


def iter_events(
    paths: Iterable[Path],
    stats: IngestStats,
    *,
    use_stdin: bool = False,
    follow_symlinks: bool = False,
    parsers: Sequence[Parser] | None = None,
) -> Iterator[Event]:
    """Lê e normaliza tudo. Só eventos reconhecidos são produzidos; o resto vira estatística."""
    available = PARSERS if parsers is None else tuple(parsers)
    if use_stdin:
        yield from _parse_one(read_stdin_lines(), "<stdin>", stats, available)
    for path in iter_input_files(paths, follow_symlinks=follow_symlinks):
        yield from _parse_one(read_file_lines(path), str(path), stats, available)


def _parse_one(
    lines: Iterator[RawLine], name: str, stats: IngestStats, parsers: Sequence[Parser]
) -> Iterator[Event]:
    stats.files += 1
    head = list(islice(lines, SNIFF_LINES))
    parser = detect_parser([ln.text for ln in head], parsers)
    if parser is None:
        stats.skipped_files.append(name)
        # Conta as linhas mesmo assim, para o resumo ser honesto sobre o que não foi lido.
        stats.lines += len(head) + sum(1 for _ in lines)
        return

    def counted() -> Iterator[RawLine]:
        for ln in chain(head, lines):
            stats.lines += 1
            if ln.truncated:
                stats.truncated_lines += 1
            yield ln

    for event in parser.parse_stream(counted()):
        if event.parse_ok:
            stats.parsed += event.line_count
            yield event
        else:
            stats.unparsed += event.line_count
            if len(stats.unparsed_samples) < UNPARSED_SAMPLE_LIMIT:
                stats.unparsed_samples.append(event)
