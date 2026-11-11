"""Utilidades de rede: quais IPs ignorar por padrão."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from functools import lru_cache

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Lista explícita em vez de ``ipaddress.is_private``: esta inclui as faixas de documentação
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), que os dados sintéticos usam.
PRIVATE_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",  # CGNAT
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


class InvalidNetworkError(ValueError):
    pass


def parse_networks(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    result: list[IPNetwork] = []
    for value in values:
        try:
            result.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise InvalidNetworkError(f"rede inválida: {value!r}") from exc
    return tuple(result)


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


@lru_cache(maxsize=200_000)  # o mesmo IP aparece milhares de vezes num log
def is_private(ip: str) -> bool:
    addr = parse_ip(ip)
    if addr is None:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in net for net in PRIVATE_NETWORKS if net.version == addr.version)


def in_networks(ip: str, networks: Iterable[IPNetwork]) -> bool:
    addr = parse_ip(ip)
    if addr is None:
        return False
    return any(addr in net for net in networks if net.version == addr.version)
