from __future__ import annotations

import ipaddress

ANY = "any"

# Explicit list of rejected networks. We use this instead of ipaddress properties
# (is_private, is_reserved, etc.) because their meaning has changed between Python
# versions: is_private classifies RFC 5737 documentation ranges as private, and
# some versions do not include 100.64/10 (CGNAT/Tailscale). Pinning the ranges here
# makes rejection behaviour version-independent.
_REJECTED_NETWORKS = (
    ipaddress.IPv4Network("0.0.0.0/8"),        # unspecified / "this network"
    ipaddress.IPv4Network("10.0.0.0/8"),       # RFC1918
    ipaddress.IPv4Network("100.64.0.0/10"),    # CGNAT — also the Tailscale range
    ipaddress.IPv4Network("127.0.0.0/8"),      # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local
    ipaddress.IPv4Network("172.16.0.0/12"),    # RFC1918
    ipaddress.IPv4Network("192.168.0.0/16"),   # RFC1918
    ipaddress.IPv4Network("224.0.0.0/4"),      # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # reserved
)


class InvalidSource(ValueError):
    """The operator's source argument is not an acceptable public IPv4 host."""


def parse_source(raw: str) -> str:
    """Normalise an operator-supplied source argument.

    Returns "any" or a single-host CIDR. Callers must use this return value and
    must never pass `raw` onward — it is attacker-influenced text.
    """
    candidate = raw.strip()
    if candidate == ANY:
        return ANY
    try:
        address = ipaddress.IPv4Address(candidate)
    except ipaddress.AddressValueError as exc:
        raise InvalidSource(f"not an IPv4 address: {raw!r}") from exc
    if any(address in net for net in _REJECTED_NETWORKS):
        raise InvalidSource(f"not a routable public address: {address}")
    return f"{address}/32"
