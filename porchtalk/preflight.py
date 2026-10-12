"""Gate B4a: static two-PC IPv4 lab preflight; never creates a socket.

Validating a suggested address is NOT confirming actual local interface
ownership, router exposure, firewall configuration, or network security.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Any

from .identity import IdentityDenied

_ALLOWED_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)


def _address(raw: Any, field: str) -> IPv4Address:
    if type(raw) is not str or not raw or raw != raw.strip():
        raise IdentityDenied(f"{field} must be a literal IPv4 address")
    try:
        address = IPv4Address(raw)
    except ValueError as exc:
        raise IdentityDenied(f"{field} must be a literal IPv4 address") from exc
    if str(address) != raw or not any(address in subnet for subnet in _ALLOWED_NETWORKS):
        raise IdentityDenied(f"{field} must be canonical RFC1918 private IPv4")
    return address


def preflight_two_pc_lab(
    *,
    local_ipv4: str,
    peer_ipv4: str,
    port: int,
    local_device_id: str,
    peer_device_id: str,
    operator_approved: bool = False,
) -> dict[str, Any]:
    """Static conservative same-/24 check before planning any transport.

    The /24 check intentionally limits the first proof-of-concept to simple,
    directly addressed home LANs. It is not a general network-routing rule.
    """
    if operator_approved is not True:
        raise IdentityDenied("operator approval required for LAN planning")
    local = _address(local_ipv4, "local_ipv4")
    remote = _address(peer_ipv4, "peer_ipv4")
    if local == remote:
        raise IdentityDenied("both devices cannot have the same IPv4 address")
    if (int(local) & 0xFFFFFF00) != (int(remote) & 0xFFFFFF00):
        raise IdentityDenied("first lab requires devices in the same /24")
    if int(local) & 0xFF in (0, 255) or int(remote) & 0xFF in (0, 255):
        raise IdentityDenied("network/broadcast-like address denied for first lab")
    if type(port) is not int or not 49152 <= port <= 65535:
        raise IdentityDenied("test port must be in 49152-65535")
    if type(local_device_id) is not str or type(peer_device_id) is not str:
        raise IdentityDenied("invalid device IDs")
    import re
    pattern = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
    if (not pattern.fullmatch(local_device_id) or not pattern.fullmatch(peer_device_id)
            or local_device_id == peer_device_id):
        raise IdentityDenied("invalid or repeated device IDs")
    return {
        "status": "PLAN_REVIEW_ONLY",
        "network_scope": "RFC1918_SAME_24",
        "local_ipv4": str(local),
        "peer_ipv4": str(remote),
        "port": port,
        "local_device_id": local_device_id,
        "peer_device_id": peer_device_id,
        "sockets_created": False,
        "execution_authorized": False,
        "requires_before_lan_test": [
            "INDEPENDENT_FINGERPRINT_CONFIRMATION",
            "PROTECTED_PRIVATE_KEY_PERSISTENCE",
            "MANUAL_LOCAL_INTERFACE_AND_FIREWALL_INSPECTION",
            "EXPLICIT_SINGLE_SESSION_OPERATOR_CONFIRMATION",
            "TRANSPORT_NEGATIVE_CONTROLS_AND_SECURITY_REVIEW",
        ],
    }
