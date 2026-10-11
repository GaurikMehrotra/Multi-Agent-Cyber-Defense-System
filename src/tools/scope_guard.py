"""Immutable authorization policy; DNS and CIDR targets are never accepted."""

from ipaddress import IPv4Address, IPv4Network

LAB = IPv4Network("172.30.0.0/24")
ASSETS = frozenset({IPv4Address("172.30.0.10"), IPv4Address("172.30.0.11")})


def target(value: str) -> str:
    if not isinstance(value, str) or not value.isascii() or value != value.strip():
        raise ValueError("canonical IPv4 literal required")
    try:
        address = IPv4Address(value)
    except ValueError as exc:
        raise ValueError("hostnames, IPv6, CIDRs and encodings forbidden") from exc
    if str(address) != value or address not in LAB or address not in ASSETS:
        raise ValueError("target is not an authorized lab asset")
    return str(address)
