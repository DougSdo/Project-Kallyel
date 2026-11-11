"""Mascaramento de dados sensíveis na saída (LGPD). Ligado por padrão.

Cobre e-mails, CPF/CNPJ, cabeçalhos ``Authorization``/``Cookie``, tokens (Bearer, JWT,
chaves de aplicação, chaves AWS, chaves privadas) e valores de parâmetros sensíveis
(``password``, ``token``, ``senha`` etc.).

Limites honestos: é uma lista de padrões conhecidos. Dados pessoais em formatos que não
estão aqui (nomes, endereços, telefones) NÃO são mascarados. Endereços IP não são
mascarados, porque são o objeto central da análise.

As regex usam âncoras literais e quantificadores sem aninhamento (tempo linear).
"""

from __future__ import annotations

import re
from collections.abc import Callable

MASK = "[REDACTED]"

SENSITIVE_PARAMS = (
    "password",
    "passwd",
    "pwd",
    "pass",
    "senha",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "csrf_token",
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "session",
    "sessionid",
    "session_id",
    "phpsessid",
    "jsessionid",
    "laravel_session",
    "xsrf-token",
    "authorization",
    "cookie",
    "db_password",
    "app_key",
)

_PARAM_ALT = "|".join(re.escape(p) for p in SENSITIVE_PARAMS)

# Cabeçalhos: mascara tudo até o fim da linha.
_HEADER = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)"
    r"(\s*[:=]\s*)[^\r\n]+"
)
# Parâmetros em query/texto: ?token=abc, 'password' => 'abc', password: abc
_PARAM = re.compile(
    rf"(?i)((?:^|[?&;,\s'\"({{]))({_PARAM_ALT})([\"']?\s*(?:=>|[:=])\s*[\"']?)"
    r"([^&\s\"';,)]+)"
)
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*")
_BASE64_KEY = re.compile(r"base64:[A-Za-z0-9+/=]{16,}")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----[A-Za-z0-9+/=\s]*")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")

_CPF_FORMATTED = re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)")
_CNPJ_FORMATTED = re.compile(r"(?<!\d)\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}(?!\d)")
_DIGITS_11 = re.compile(r"(?<!\d)\d{11}(?!\d)")
_DIGITS_14 = re.compile(r"(?<!\d)\d{14}(?!\d)")


def _cpf_valid(digits: str) -> bool:
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for length in (9, 10):
        total = sum(
            int(d) * w for d, w in zip(digits[:length], range(length + 1, 1, -1), strict=True)
        )
        check = (total * 10) % 11 % 10
        if check != int(digits[length]):
            return False
    return True


def _cnpj_valid(digits: str) -> bool:
    if len(digits) != 14 or len(set(digits)) == 1:
        return False
    weights = ([5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2], [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])
    for i, w in enumerate(weights):
        total = sum(int(d) * wt for d, wt in zip(digits[: len(w)], w, strict=True))
        rest = total % 11
        check = 0 if rest < 2 else 11 - rest
        if check != int(digits[12 + i]):
            return False
    return True


def _sub_digits(
    pattern: re.Pattern[str], text: str, validator: Callable[[str], bool], label: str
) -> str:
    def repl(m: re.Match[str]) -> str:
        digits = m.group()
        return label if validator(digits) else digits

    return pattern.sub(repl, text)


def redact(text: str) -> str:
    """Devolve ``text`` com dados sensíveis substituídos por marcadores."""
    if not text:
        return text
    text = _PRIVATE_KEY.sub("-----BEGIN PRIVATE KEY----- " + MASK, text)
    text = _HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {MASK}", text)
    text = _JWT.sub(MASK, text)
    text = _BASE64_KEY.sub(f"base64:{MASK}", text)
    text = _AWS_KEY.sub(MASK, text)
    text = _PARAM.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{MASK}", text)
    text = _EMAIL.sub("[EMAIL]", text)
    text = _CPF_FORMATTED.sub("[CPF]", text)
    text = _CNPJ_FORMATTED.sub("[CNPJ]", text)
    text = _sub_digits(_DIGITS_14, text, _cnpj_valid, "[CNPJ]")
    text = _sub_digits(_DIGITS_11, text, _cpf_valid, "[CPF]")
    return text


class Redactor:
    """Aplica ``redact`` quando habilitado; caso contrário, devolve o texto como está."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def __call__(self, text: str | None) -> str:
        if text is None:
            return ""
        return redact(text) if self.enabled else text
