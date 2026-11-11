"""Leitura em fluxo de arquivos, pastas, stdin e .gz, com memória limitada.

Logs são entrada controlada por atacante: uma única linha gigante não pode estourar
a memória, então cada linha é lida em pedaços de no máximo ``MAX_LINE_BYTES``.
"""

from __future__ import annotations

import gzip
import os
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

MAX_LINE_BYTES = 8 * 1024
GZIP_MAGIC = b"\x1f\x8b"


class InputError(Exception):
    """Erro de entrada do usuário (caminho inexistente, sem permissão etc.)."""


@dataclass(slots=True)
class RawLine:
    source_file: str
    line_no: int
    text: str
    truncated: bool = False


def iter_input_files(paths: Iterable[Path], *, follow_symlinks: bool = False) -> Iterator[Path]:
    """Expande arquivos e pastas (recursivo) em uma lista ordenada de arquivos regulares.

    Dentro de pastas, links simbólicos e arquivos especiais (FIFO, dispositivos) são
    ignorados, a menos que ``follow_symlinks`` seja verdadeiro. Um arquivo passado
    explicitamente pelo usuário é sempre aceito, se for regular.
    """
    for path in paths:
        if not path.exists():
            raise InputError(f"caminho não encontrado: {path}")
        if path.is_dir():
            yield from _walk_dir(path, follow_symlinks=follow_symlinks)
        elif path.is_file():
            yield path
        else:
            raise InputError(f"não é um arquivo regular nem uma pasta: {path}")


def _walk_dir(root: Path, *, follow_symlinks: bool) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        dirnames.sort()
        if not follow_symlinks:
            dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in sorted(filenames):
            candidate = Path(dirpath) / name
            if candidate.is_symlink() and not follow_symlinks:
                continue
            if candidate.is_file():
                yield candidate


def read_file_lines(path: Path) -> Iterator[RawLine]:
    """Lê um arquivo (texto ou gzip, detectado pelo conteúdo) linha a linha."""
    try:
        with path.open("rb") as raw_fh:
            head = raw_fh.read(2)
            raw_fh.seek(0)
            if head == GZIP_MAGIC:
                with gzip.GzipFile(fileobj=raw_fh) as gz:
                    yield from _iter_lines(gz, str(path))
            else:
                yield from _iter_lines(raw_fh, str(path))
    except PermissionError as exc:
        raise InputError(f"sem permissão para ler: {path}") from exc
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise InputError(f"erro ao ler {path}: {exc}") from exc


def read_stdin_lines(stream: BinaryIO | None = None) -> Iterator[RawLine]:
    """Lê de stdin (texto ou gzip, detectado pelo conteúdo) linha a linha."""
    fh = stream if stream is not None else sys.stdin.buffer
    try:
        peek = getattr(fh, "peek", None)  # BufferedReader permite espiar sem consumir
        if peek is not None and peek(2)[:2] == GZIP_MAGIC:
            with gzip.GzipFile(fileobj=fh) as gz:
                yield from _iter_lines(gz, "<stdin>")
            return
        yield from _iter_lines(fh, "<stdin>")
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise InputError(f"erro ao ler a entrada padrão: {exc}") from exc


def _iter_lines(fh: BinaryIO | gzip.GzipFile, source: str) -> Iterator[RawLine]:
    line_no = 0
    while True:
        chunk = fh.readline(MAX_LINE_BYTES + 1)
        if not chunk:
            return
        line_no += 1
        truncated = False
        if len(chunk) > MAX_LINE_BYTES and not chunk.endswith(b"\n"):
            truncated = True
            # Descarta o resto da linha em pedaços, sem acumular memória.
            while True:
                rest = fh.readline(MAX_LINE_BYTES)
                if not rest or rest.endswith(b"\n"):
                    break
            chunk = chunk[:MAX_LINE_BYTES]
        text = chunk.rstrip(b"\r\n").decode("utf-8", errors="replace")
        yield RawLine(source_file=source, line_no=line_no, text=text, truncated=truncated)
