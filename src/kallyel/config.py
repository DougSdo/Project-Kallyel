"""Configuração: ``kallyel.toml`` e variáveis de ambiente ``KALLYEL_*``.

Precedência: opção de linha de comando > variável de ambiente > arquivo > padrão.

Decisões de segurança:

- O arquivo NÃO é procurado no diretório atual (ele pode vir junto de logs ou de projetos
  não confiáveis). Só é lido o caminho passado em ``--config``/``KALLYEL_CONFIG`` ou o
  ``kallyel.toml`` na pasta de dados do usuário.
- O mascaramento de dados pessoais não pode ser desligado por arquivo nem por ambiente,
  apenas por ``--no-redact`` no comando.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from kallyel.netutil import InvalidNetworkError, parse_networks
from kallyel.timeutil import TimeParseError, parse_utc_offset

CONFIG_FILENAME = "kallyel.toml"
_KNOWN_KEYS = {"ignore_private", "ignore_networks", "rules_dir", "log_utc_offset"}
_TRUE = {"1", "true", "yes", "sim", "on"}
_FALSE = {"0", "false", "no", "nao", "não", "off"}


class ConfigError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Config:
    ignore_private: bool = True
    ignore_networks: tuple[str, ...] = ()  # CIDRs extras a ignorar (ex.: monitoramento próprio)
    rules_dir: Path | None = None
    # Fuso dos logs sem fuso (auth.log tradicional e Laravel), ex.: "-03:00". None = UTC.
    log_utc_offset: str | None = None


def data_dir(env: Mapping[str, str] | None = None) -> Path:
    """Pasta de dados do usuário: ``%LOCALAPPDATA%\\Kallyel`` ou ``~/.local/share/kallyel``."""
    env = os.environ if env is None else env
    if sys.platform == "win32":
        base = env.get("LOCALAPPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Local") / "Kallyel"
    return Path.home() / ".local" / "share" / "kallyel"


def _as_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
    raise ConfigError(f"'{name}' deve ser verdadeiro ou falso")


def _from_mapping(data: Mapping[str, Any], origin: str) -> dict[str, Any]:
    unknown = sorted(set(data) - _KNOWN_KEYS)
    if unknown:
        raise ConfigError(f"{origin}: chave(s) desconhecida(s): {', '.join(unknown)}")
    out: dict[str, Any] = {}
    try:
        if "ignore_private" in data:
            out["ignore_private"] = _as_bool(data["ignore_private"], "ignore_private")
        if "ignore_networks" in data:
            nets = data["ignore_networks"]
            if not isinstance(nets, list) or not all(isinstance(n, str) for n in nets):
                raise ConfigError("'ignore_networks' deve ser uma lista de textos (CIDR)")
            parse_networks(nets)  # valida
            out["ignore_networks"] = tuple(nets)
        if "rules_dir" in data:
            if not isinstance(data["rules_dir"], str) or not data["rules_dir"]:
                raise ConfigError("'rules_dir' deve ser um caminho em texto")
            out["rules_dir"] = Path(data["rules_dir"])
        if "log_utc_offset" in data:
            offset = data["log_utc_offset"]
            if not isinstance(offset, str):
                raise ConfigError("'log_utc_offset' deve ser um texto, ex.: \"-03:00\"")
            parse_utc_offset(offset)  # valida
            out["log_utc_offset"] = offset
    except (ConfigError, InvalidNetworkError, TimeParseError) as exc:
        raise ConfigError(f"{origin}: {exc}") from exc
    return out


def load_config(explicit: Path | None = None, env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    values: dict[str, Any] = {}

    path = explicit
    if path is None and env.get("KALLYEL_CONFIG"):
        path = Path(env["KALLYEL_CONFIG"])
    required = path is not None
    if path is None:
        path = data_dir(env) / CONFIG_FILENAME
    if path.is_file():
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"{path}: não foi possível ler a configuração: {exc}") from exc
        values.update(_from_mapping(data, str(path)))
    elif required:
        raise ConfigError(f"arquivo de configuração não encontrado: {path}")

    env_map: dict[str, Any] = {}
    if "KALLYEL_IGNORE_PRIVATE" in env:
        env_map["ignore_private"] = env["KALLYEL_IGNORE_PRIVATE"]
    if env.get("KALLYEL_RULES_DIR"):
        env_map["rules_dir"] = env["KALLYEL_RULES_DIR"]
    if env.get("KALLYEL_LOG_UTC_OFFSET"):
        env_map["log_utc_offset"] = env["KALLYEL_LOG_UTC_OFFSET"]
    if env.get("KALLYEL_IGNORE_NETWORKS"):
        env_map["ignore_networks"] = [
            n.strip() for n in env["KALLYEL_IGNORE_NETWORKS"].split(",") if n.strip()
        ]
    values.update(_from_mapping(env_map, "variáveis KALLYEL_*"))
    return Config(**values)
