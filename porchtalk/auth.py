"""Offline PorchTalk authenticated grant envelope research (Gate B1).

This module does NOT implement peer discovery, secure transport, key exchange,
remote compute, or live resource authorizations. HMAC is symmetric authentication,
not a public-key signature. Replay tracking is volatile and process-local.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any

_ALLOWED_CLASSES = frozenset({"PUBLIC", "SYNTHETIC"})
_CLAIM_FIELDS = frozenset({
    "protocol", "kind", "grant_id", "owner_id", "grantee_id", "node_id",
    "model_id", "request_id", "data_class", "max_cost_units",
    "issued_at", "expires_at", "nonce",
})
_ENVELOPE_FIELDS = frozenset({"claims", "mac_hex"})
_MAX_GRANT_LIFETIME_SECONDS = 300
_CLOCK_SKEW_SECONDS = 30


class AuthorizationDenied(ValueError):
    """Fail-closed result; avoid reporting secrets in errors."""


def _name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or not value.isascii() or not value.strip():
        raise AuthorizationDenied(f"invalid {field}")
    return value


def _int(value: Any, field: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise AuthorizationDenied(f"invalid {field}")
    return value


def _key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) < 32:
        raise AuthorizationDenied("invalid shared key")
    return key


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _validated_claims(raw: Any) -> dict[str, Any]:
    if type(raw) is not dict or set(raw) != _CLAIM_FIELDS:
        raise AuthorizationDenied("grant claim fields mismatch")
    claims = dict(raw)
    if claims["protocol"] != "PORCHTALK_AUTH_V1" or claims["kind"] != "SINGLE_USE_GRANT":
        raise AuthorizationDenied("unsupported protocol or kind")
    for field in ("grant_id", "owner_id", "grantee_id", "node_id", "model_id", "request_id"):
        _name(claims[field], field)
    if type(claims["data_class"]) is not str or claims["data_class"] not in _ALLOWED_CLASSES:
        raise AuthorizationDenied("invalid data class")
    _int(claims["max_cost_units"], "max_cost_units")
    issued = _int(claims["issued_at"], "issued_at", 1)
    expires = _int(claims["expires_at"], "expires_at", 1)
    if expires <= issued or expires - issued > _MAX_GRANT_LIFETIME_SECONDS:
        raise AuthorizationDenied("invalid grant lifetime")
    nonce = claims["nonce"]
    if not isinstance(nonce, str) or len(nonce) != 32:
        raise AuthorizationDenied("invalid nonce")
    try:
        bytes.fromhex(nonce)
    except ValueError as exc:
        raise AuthorizationDenied("invalid nonce") from exc
    return claims


def issue_grant(
    *, key: bytes, grant_id: str, owner_id: str, grantee_id: str,
    node_id: str, model_id: str, request_id: str, data_class: str,
    max_cost_units: int, now: int | None = None, lifetime_seconds: int = 60,
) -> dict[str, Any]:
    """Make a test envelope. An actual owner must independently approve it."""
    _key(key)
    issued = int(time.time()) if now is None else _int(now, "now", 1)
    lifetime = _int(lifetime_seconds, "lifetime_seconds", 1)
    if lifetime > _MAX_GRANT_LIFETIME_SECONDS:
        raise AuthorizationDenied("grant lifetime too long")
    claims = _validated_claims({
        "protocol": "PORCHTALK_AUTH_V1", "kind": "SINGLE_USE_GRANT",
        "grant_id": grant_id, "owner_id": owner_id, "grantee_id": grantee_id,
        "node_id": node_id, "model_id": model_id, "request_id": request_id,
        "data_class": data_class, "max_cost_units": max_cost_units,
        "issued_at": issued, "expires_at": issued + lifetime,
        "nonce": secrets.token_hex(16),
    })
    return {"claims": claims, "mac_hex": hmac.new(key, _canonical(claims), hashlib.sha256).hexdigest()}


class SessionReplayGuard:
    """Volatile replay guard: not safe after process restart or across hosts."""

    def __init__(self) -> None:
        self._used: set[tuple[str, str, str]] = set()

    def consume(self, identity: tuple[str, str, str]) -> None:
        if identity in self._used:
            raise AuthorizationDenied("replayed grant")
        self._used.add(identity)


def verify_grant(
    envelope: Any, *, key: bytes, expected_owner_id: str,
    expected_grantee_id: str, expected_node_id: str, expected_model_id: str,
    expected_request_id: str, expected_data_class: str,
    proposed_cost_units: int, revoked_grant_ids: set[str],
    replay_guard: SessionReplayGuard, now: int | None = None,
) -> dict[str, Any]:
    """Verify one scoped grant and consume it; never starts a workload."""
    secret = _key(key)
    if type(envelope) is not dict or set(envelope) != _ENVELOPE_FIELDS:
        raise AuthorizationDenied("invalid envelope")
    claims = _validated_claims(envelope["claims"])
    mac = envelope["mac_hex"]
    if not isinstance(mac, str) or len(mac) != 64:
        raise AuthorizationDenied("invalid mac")
    try:
        raw_mac = bytes.fromhex(mac)
    except ValueError as exc:
        raise AuthorizationDenied("invalid mac") from exc
    actual = hmac.new(secret, _canonical(claims), hashlib.sha256).digest()
    if not hmac.compare_digest(actual, raw_mac):
        raise AuthorizationDenied("authentication failed")
    for field, expected in (
        ("owner_id", expected_owner_id), ("grantee_id", expected_grantee_id),
        ("node_id", expected_node_id), ("model_id", expected_model_id),
        ("request_id", expected_request_id), ("data_class", expected_data_class),
    ):
        if claims[field] != _name(expected, field):
            raise AuthorizationDenied(f"{field} not authorized")
    if claims["data_class"] not in _ALLOWED_CLASSES:
        raise AuthorizationDenied("private data cannot be shared")
    cost = _int(proposed_cost_units, "proposed_cost_units")
    if cost > claims["max_cost_units"]:
        raise AuthorizationDenied("cost exceeds grant")
    if type(revoked_grant_ids) is not set or type(replay_guard) is not SessionReplayGuard:
        raise AuthorizationDenied("missing revocation or replay state")
    if claims["grant_id"] in revoked_grant_ids:
        raise AuthorizationDenied("grant revoked")
    clock = int(time.time()) if now is None else _int(now, "now", 1)
    if clock < claims["issued_at"] - _CLOCK_SKEW_SECONDS or clock >= claims["expires_at"]:
        raise AuthorizationDenied("grant outside validity window")
    replay_guard.consume((claims["owner_id"], claims["grant_id"], claims["nonce"]))
    return {"authenticated": True, "scope": {
        "grant_id": claims["grant_id"], "owner_id": claims["owner_id"],
        "grantee_id": claims["grantee_id"], "node_id": claims["node_id"],
        "model_id": claims["model_id"], "request_id": claims["request_id"],
        "data_class": claims["data_class"], "max_cost_units": claims["max_cost_units"],
        "expires_at": claims["expires_at"],
    }, "warning": "OFFLINE_HMAC_ONLY_NOT_NETWORK_AUTHORIZATION"}
