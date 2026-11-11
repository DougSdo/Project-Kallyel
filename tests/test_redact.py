import time

import pytest

from kallyel.redact import MASK, Redactor, redact


@pytest.mark.parametrize(
    ("raw", "must_not_contain"),
    [
        ("contato: maria.silva@example.test enviou", "maria.silva@example.test"),
        ("GET /u?email=joao@example.test HTTP/1.1", "joao@example.test"),
        ("cliente CPF 529.982.247-25 cadastrado", "529.982.247-25"),
        ("cliente 52998224725 cadastrado", "52998224725"),
        ("empresa CNPJ 11.222.333/0001-81", "11.222.333/0001-81"),
        ("empresa 11222333000181 ativa", "11222333000181"),
        ("Authorization: Bearer abc123def456ghi789", "abc123def456ghi789"),
        ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
        ("Cookie: laravel_session=eyJ0eXAi; XSRF-TOKEN=abc", "eyJ0eXAi"),
        ("Set-Cookie: sid=topsecretvalue; Path=/", "topsecretvalue"),
        ("GET /login?user=x&password=hunter2&next=/ HTTP/1.1", "hunter2"),
        ("GET /api?token=abcdef123456", "abcdef123456"),
        ("GET /entrar?senha=minhaSenha123", "minhaSenha123"),
        ("'password' => 'hunter2hunter2'", "hunter2hunter2"),
        ("DB_PASSWORD=Sup3rS3cretValue", "Sup3rS3cretValue"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl fim", "eyJzdWIiOiIxIn0"),
        ("key base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAAAA"),
        ("chave AKIAIOSFODNN7EXAMPLE usada", "AKIAIOSFODNN7EXAMPLE"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END", "MIIBOgIBAAJBAK"),
    ],
)
def test_sensitive_data_is_masked(raw: str, must_not_contain: str) -> None:
    assert must_not_contain not in redact(raw)


@pytest.mark.parametrize(
    "text",
    [
        "GET /index.php?page=2&sort=price HTTP/1.1",
        "Failed password for root from 203.0.113.7 port 22 ssh2",
        "pedido 12345678901 sem CPF válido",  # 11 dígitos com dígitos verificadores inválidos
        "id=11111111111",
        "status code: 404",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "https://example.test/blog/senhas-fortes",
        "a@b",
    ],
)
def test_benign_text_is_unchanged(text: str) -> None:
    assert redact(text) == text


def test_keys_are_kept_and_values_masked() -> None:
    out = redact("GET /login?user=ana&password=hunter2&next=/home")
    assert "password=" + MASK in out
    assert "user=ana" in out and "next=/home" in out


def test_ip_addresses_are_not_masked() -> None:
    assert "203.0.113.7" in redact("from 203.0.113.7 user maria@example.test")


def test_redaction_is_idempotent() -> None:
    once = redact("password=hunter2 maria@example.test")
    assert redact(once) == once


def test_redactor_can_be_disabled_only_explicitly() -> None:
    assert Redactor(enabled=False)("password=hunter2") == "password=hunter2"
    assert "hunter2" not in Redactor()("password=hunter2")
    assert Redactor()(None) == ""


@pytest.mark.parametrize(
    "payload",
    [
        "a" * 8000,
        "password=" * 900,
        "Authorization: " * 500,
        "@" * 8000,
        "a@" * 4000,
        "a." * 4000 + "@",
        "1" * 8000,
        "-----BEGIN " * 700,
        "eyJ" + "a" * 8000,
        "Bearer " * 1000,
        "%20" * 3000,
        "'" * 8000,
    ],
)
def test_redaction_is_fast_on_pathological_input(payload: str) -> None:
    start = time.perf_counter()
    redact(payload)
    assert time.perf_counter() - start < 0.5
