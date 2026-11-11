"""Neutraliza texto vindo de logs ou regras antes de imprimir no terminal.

Sequências ANSI e caracteres de controle em um log podem reescrever a tela do
analista (esconder linhas, mudar o título da janela). Aqui eles viram texto visível.
"""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def _visible(match: re.Match[str]) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def neutralize(text: str, *, keep_newlines: bool = False) -> str:
    """Troca controles (incluindo ESC e override bidi) por escapes visíveis."""
    if keep_newlines:
        return "\n".join(
            _CONTROL.sub(_visible, part.replace("\r", "")) for part in text.split("\n")
        )
    return _CONTROL.sub(_visible, text.replace("\n", "\\n").replace("\r", "\\r"))
