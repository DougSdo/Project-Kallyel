from datetime import datetime, timezone
from pathlib import Path

import pytest

from kallyel.config import Config, ConfigError, data_dir, load_config
from kallyel.netutil import InvalidNetworkError, in_networks, is_private, parse_networks
from kallyel.timeutil import TimeParseError, parse_user_time


# ----------------------------------------------------------------- netutil
@pytest.mark.parametrize(
    "ip",
    [
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:10.0.0.1",
        "100.64.0.1",
    ],
)
def test_private_addresses(ip: str) -> None:
    assert is_private(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "172.32.0.1",
        "203.0.113.7",
        "198.51.100.5",
        "192.0.2.1",
        "2001:db8::1",
        "not-an-ip",
        "",
    ],
)
def test_public_and_documentation_addresses_are_not_private(ip: str) -> None:
    # Faixas de documentação NÃO são privadas aqui: os dados sintéticos as usam.
    assert not is_private(ip)


def test_extra_networks() -> None:
    nets = parse_networks(["203.0.113.0/24", "2001:db8::/32"])
    assert in_networks("203.0.113.9", nets)
    assert in_networks("2001:db8::5", nets)
    assert not in_networks("198.51.100.1", nets)
    assert not in_networks("garbage", nets)
    with pytest.raises(InvalidNetworkError):
        parse_networks(["nao-e-rede"])


# ---------------------------------------------------------------- timeutil
def test_parse_user_time_variants() -> None:
    assert parse_user_time("2024-01-31") == datetime(2024, 1, 31, tzinfo=timezone.utc)
    assert parse_user_time("2024-01-31T14:30") == datetime(2024, 1, 31, 14, 30, tzinfo=timezone.utc)
    assert parse_user_time("2024-01-31T14:30:00Z") == datetime(
        2024, 1, 31, 14, 30, tzinfo=timezone.utc
    )
    assert parse_user_time("2024-01-31T14:30:00-03:00") == datetime(
        2024, 1, 31, 17, 30, tzinfo=timezone.utc
    )


@pytest.mark.parametrize("bad", ["ontem", "31/01/2024", "", "2024-13-01"])
def test_parse_user_time_rejects_garbage(bad: str) -> None:
    with pytest.raises(TimeParseError):
        parse_user_time(bad)


# ------------------------------------------------------------------ config
def test_defaults_when_nothing_is_configured(tmp_path: Path) -> None:
    env = {"LOCALAPPDATA": str(tmp_path), "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
    assert load_config(env=env) == Config()


def test_config_file_and_env_precedence(tmp_path: Path) -> None:
    f = tmp_path / "kallyel.toml"
    f.write_text('ignore_private = false\nignore_networks = ["203.0.113.0/24"]\n', encoding="utf-8")
    cfg = load_config(f, env={})
    assert cfg.ignore_private is False
    assert cfg.ignore_networks == ("203.0.113.0/24",)
    cfg = load_config(f, env={"KALLYEL_IGNORE_PRIVATE": "true"})
    assert cfg.ignore_private is True  # ambiente vence o arquivo


def test_config_path_from_env(tmp_path: Path) -> None:
    f = tmp_path / "x.toml"
    f.write_text("ignore_private = false\n", encoding="utf-8")
    assert load_config(env={"KALLYEL_CONFIG": str(f)}).ignore_private is False


@pytest.mark.parametrize(
    "content",
    [
        "redact = false\n",  # mascaramento não é configurável
        "ignore_private = 'talvez'\n",
        "ignore_networks = 'x'\n",
        'ignore_networks = ["xyz"]\n',
        "rules_dir = 5\n",
        "isto nao e toml [",
    ],
)
def test_invalid_config_is_rejected(tmp_path: Path, content: str) -> None:
    f = tmp_path / "kallyel.toml"
    f.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(f, env={})


def test_missing_explicit_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="não encontrado"):
        load_config(tmp_path / "nao-existe.toml", env={})


def test_cwd_config_is_not_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "kallyel.toml").write_text("ignore_private = false\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    env = {"LOCALAPPDATA": str(tmp_path / "vazio"), "HOME": str(tmp_path / "vazio")}
    assert load_config(env=env).ignore_private is True


def test_bad_env_value_is_rejected() -> None:
    with pytest.raises(ConfigError):
        load_config(env={"KALLYEL_IGNORE_PRIVATE": "quem-sabe", "LOCALAPPDATA": "x"})


def test_data_dir_is_user_scoped() -> None:
    assert "kallyel" in str(data_dir({"LOCALAPPDATA": "C:/x"})).lower()


# ----------------------------------------------------------- fuso dos logs
@pytest.mark.parametrize(
    ("text", "hours"),
    [
        ("-03:00", -3),
        ("-0300", -3),
        ("+5", 5),
        ("+05:30", 5.5),
        ("Z", 0),
        ("UTC", 0),
        ("utc", 0),
        ("+14:00", 14),
        ("-12", -12),
    ],
)
def test_parse_utc_offset(text: str, hours: float) -> None:
    from datetime import timedelta

    from kallyel.timeutil import parse_utc_offset

    assert parse_utc_offset(text) == timedelta(hours=hours)


@pytest.mark.parametrize("bad", ["", "tres", "+15:00", "-03:99", "3", "+", "UTC+3"])
def test_parse_utc_offset_rejects_garbage(bad: str) -> None:
    from kallyel.timeutil import parse_utc_offset

    with pytest.raises(TimeParseError):
        parse_utc_offset(bad)


def test_log_utc_offset_in_config_and_env(tmp_path: Path) -> None:
    f = tmp_path / "kallyel.toml"
    f.write_text('log_utc_offset = "-03:00"\n', encoding="utf-8")
    assert load_config(f, env={}).log_utc_offset == "-03:00"
    assert load_config(f, env={"KALLYEL_LOG_UTC_OFFSET": "+01:00"}).log_utc_offset == "+01:00"
    assert (
        load_config(
            env={
                "KALLYEL_LOG_UTC_OFFSET": "UTC",
                "LOCALAPPDATA": str(tmp_path / "v"),
                "HOME": str(tmp_path / "v"),
            }
        ).log_utc_offset
        == "UTC"
    )


@pytest.mark.parametrize(
    "content", ['log_utc_offset = "tres"\n', "log_utc_offset = 3\n", 'log_utc_offset = "+99:00"\n']
)
def test_invalid_log_utc_offset_in_config(tmp_path: Path, content: str) -> None:
    f = tmp_path / "kallyel.toml"
    f.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(f, env={})
