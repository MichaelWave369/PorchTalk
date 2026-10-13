"""Gate B2: offline pinned Ed25519 device identity and challenge/response.

No sockets, live peer enrollment, compute execution, transport encryption, or
binding to Gate A/B1 grants. This is a research protocol, not production security.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTO = "PORCHTALK_DEVICE_IDENTITY_V1"
TTL_MAX = 120
SKEW_SECONDS = 15
_CHALLENGE_FIELDS = frozenset({"protocol", "kind", "sender_id", "recipient_id", "nonce", "issued_at", "expires_at"})
_RESPONSE_FIELDS = _CHALLENGE_FIELDS | {"challenge_sha256"}
_ENVELOPE_FIELDS = frozenset({"claims", "signature_b64"})


class IdentityDenied(ValueError):
    """Protocol denied. Never include private key material in an error."""


def _ident(value: Any, field: str) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 80
            or not value.isascii() or any(not (c.isalnum() or c in "._-") for c in value)):
        raise IdentityDenied(f"invalid {field}")
    return value


def _epoch(value: Any, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise IdentityDenied(f"invalid {field}")
    return value


def _nonce(value: Any) -> str:
    if type(value) is not str or len(value) != 32:
        raise IdentityDenied("invalid nonce")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise IdentityDenied("invalid nonce") from exc
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or len(value) != 64:
        raise IdentityDenied("invalid challenge digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise IdentityDenied("invalid challenge digest") from exc
    return value


def _now(now: int | None) -> int:
    return int(time.time()) if now is None else _epoch(now, "now")


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _decode(value: Any, length: int, field: str) -> bytes:
    if type(value) is not str:
        raise IdentityDenied(f"invalid {field}")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise IdentityDenied(f"invalid {field}") from exc
    if len(raw) != length:
        raise IdentityDenied(f"invalid {field} length")
    return raw


def _public_bytes(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def public_fingerprint(public: Ed25519PublicKey) -> str:
    """SHA256 public-key fingerprint; operator MUST verify via trusted channel."""
    return hashlib.sha256(_public_bytes(public)).hexdigest()


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate_ephemeral(cls, device_id: str) -> DeviceIdentity:
        """Generate an in-memory key for testing. Never silently save it to disk."""
        return cls(_ident(device_id, "device_id"), Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def fingerprint(self) -> str:
        return public_fingerprint(self.public_key)


def _claims(raw: Any, kind: str, now: int) -> dict[str, Any]:
    if type(raw) is not dict or set(raw) != (_CHALLENGE_FIELDS if kind == "CHALLENGE" else _RESPONSE_FIELDS):
        raise IdentityDenied("invalid claim shape")
    if raw["protocol"] != PROTO or raw["kind"] != kind:
        raise IdentityDenied("invalid protocol or kind")
    _ident(raw["sender_id"], "sender_id")
    _ident(raw["recipient_id"], "recipient_id")
    if raw["sender_id"] == raw["recipient_id"]:
        raise IdentityDenied("self-directed handshake denied")
    _nonce(raw["nonce"])
    start = _epoch(raw["issued_at"], "issued_at")
    expiry = _epoch(raw["expires_at"], "expires_at")
    if expiry <= start or expiry - start > TTL_MAX or now < start - SKEW_SECONDS or now >= expiry:
        raise IdentityDenied("handshake expired, premature, or overly long")
    if kind == "RESPONSE":
        _digest(raw["challenge_sha256"])
    return dict(raw)


def _sign(identity: DeviceIdentity, claims: dict[str, Any]) -> dict[str, Any]:
    if claims["sender_id"] != identity.device_id:
        raise IdentityDenied("signer identity mismatch")
    return {"claims": claims, "signature_b64": base64.b64encode(identity.private_key.sign(_json(claims))).decode("ascii")}


def _verify(message: Any, expected_kind: str, key: Ed25519PublicKey, now: int) -> dict[str, Any]:
    if type(message) is not dict or set(message) != _ENVELOPE_FIELDS:
        raise IdentityDenied("invalid signed envelope")
    claims = _claims(message["claims"], expected_kind, now)
    signature = _decode(message["signature_b64"], 64, "signature")
    try:
        key.verify(signature, _json(claims))
    except InvalidSignature as exc:
        raise IdentityDenied("signature verification failed") from exc
    return claims


class PinnedPeers:
    """Explicitly approved, local sqlite trust records and atomic replay history.

    The caller owns the DB path and must protect its integrity and permissions.
    A tampered DB or compromised endpoint is OUTSIDE the threat model.
    """

    def __init__(self, db_path: str | Path):
        self.db = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                device_id TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )""")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS replay (
                direction TEXT NOT NULL,
                peer_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                PRIMARY KEY (direction, peer_id, nonce)
            )""")

    def close(self) -> None:
        self.db.close()

    def enroll(self, device_id: str, public_key: Ed25519PublicKey, *, operator_approved: bool = False) -> str:
        """Enroll exactly one pinned key, only after out-of-band operator approval."""
        peer = _ident(device_id, "device_id")
        if operator_approved is not True:
            raise IdentityDenied("explicit operator approval required")
        if not isinstance(public_key, Ed25519PublicKey):
            raise IdentityDenied("invalid public key")
        encoded = _public_bytes(public_key)
        try:
            self.db.execute("INSERT INTO peers(device_id, public_key) VALUES (?, ?)", (peer, encoded))
        except sqlite3.IntegrityError as exc:
            raise IdentityDenied("device already enrolled; rotation needs a separate approval workflow") from exc
        return hashlib.sha256(encoded).hexdigest()

    def revoke(self, device_id: str) -> None:
        peer = _ident(device_id, "device_id")
        cursor = self.db.execute("UPDATE peers SET revoked=1 WHERE device_id=? AND revoked=0", (peer,))
        if cursor.rowcount != 1:
            raise IdentityDenied("device not enrolled or already revoked")

    def approved_key(self, device_id: str) -> Ed25519PublicKey:
        peer = _ident(device_id, "device_id")
        record = self.db.execute("SELECT public_key, revoked FROM peers WHERE device_id=?", (peer,)).fetchone()
        if record is None or record[1] != 0:
            raise IdentityDenied("peer not approved or revoked")
        try:
            return Ed25519PublicKey.from_public_bytes(record[0])
        except ValueError as exc:
            raise IdentityDenied("invalid enrolled key") from exc

    def consume_once(self, direction: str, peer_id: str, nonce: str) -> None:
        if direction not in ("challenge_responded", "response_verified", "lan_client_hello", "lan_server_reply"):
            raise IdentityDenied("invalid replay direction")
        peer = _ident(peer_id, "peer_id")
        token = _nonce(nonce)
        try:
            # SQLite primary-key insert is atomic, including across processes.
            self.db.execute(
                "INSERT INTO replay(direction, peer_id, nonce) VALUES (?, ?, ?)",
                (direction, peer, token),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityDenied("replayed handshake") from exc


def create_challenge(
    challenger: DeviceIdentity, responder_id: str, *,
    now: int | None = None, ttl_seconds: int = 60,
) -> dict[str, Any]:
    instant = _now(now)
    ttl = _epoch(ttl_seconds, "ttl_seconds")
    if ttl > TTL_MAX:
        raise IdentityDenied("challenge lifetime too long")
    fields = {
        "protocol": PROTO, "kind": "CHALLENGE",
        "sender_id": challenger.device_id, "recipient_id": _ident(responder_id, "responder_id"),
        "nonce": secrets.token_hex(16), "issued_at": instant, "expires_at": instant + ttl,
    }
    _claims(fields, "CHALLENGE", instant)
    return _sign(challenger, fields)


def respond_to_challenge(
    responder: DeviceIdentity, challenge: Any, trusted: PinnedPeers, *,
    now: int | None = None,
) -> dict[str, Any]:
    instant = _now(now)
    if type(challenge) is not dict or type(challenge.get("claims")) is not dict:
        raise IdentityDenied("invalid challenge")
    claimed_sender = _ident(challenge["claims"].get("sender_id"), "sender_id")
    challenger_key = trusted.approved_key(claimed_sender)
    claims = _verify(challenge, "CHALLENGE", challenger_key, instant)
    if claims["recipient_id"] != responder.device_id:
        raise IdentityDenied("wrong recipient")
    # Consumed only after all challenge validation. Restarting does NOT allow reuse.
    trusted.consume_once("challenge_responded", claimed_sender, claims["nonce"])
    response_claims = {
        "protocol": PROTO, "kind": "RESPONSE",
        "sender_id": responder.device_id, "recipient_id": claimed_sender,
        "nonce": secrets.token_hex(16), "issued_at": instant,
        "expires_at": min(claims["expires_at"], instant + 60),
        "challenge_sha256": hashlib.sha256(_json(challenge)).hexdigest(),
    }
    _claims(response_claims, "RESPONSE", instant)
    return _sign(responder, response_claims)


def verify_response(
    challenger: DeviceIdentity, challenge: Any, response: Any,
    trusted: PinnedPeers, *, now: int | None = None,
) -> dict[str, Any]:
    instant = _now(now)
    challenge_claims = _verify(challenge, "CHALLENGE", challenger.public_key, instant)
    if challenge_claims["sender_id"] != challenger.device_id:
        raise IdentityDenied("challenger identity mismatch")
    responder_id = challenge_claims["recipient_id"]
    remote_key = trusted.approved_key(responder_id)
    reply = _verify(response, "RESPONSE", remote_key, instant)
    if reply["sender_id"] != responder_id or reply["recipient_id"] != challenger.device_id:
        raise IdentityDenied("response peer mismatch")
    if reply["challenge_sha256"] != hashlib.sha256(_json(challenge)).hexdigest():
        raise IdentityDenied("challenge transcript mismatch")
    if reply["issued_at"] < challenge_claims["issued_at"] - SKEW_SECONDS or reply["expires_at"] > challenge_claims["expires_at"]:
        raise IdentityDenied("response outside challenge window")
    trusted.consume_once("response_verified", responder_id, challenge_claims["nonce"])
    return {
        "status": "AUTHENTICATED_OFFLINE_PROOF_ONLY",
        "peer_id": responder_id, "peer_fingerprint": public_fingerprint(remote_key),
        "challenge_nonce": challenge_claims["nonce"],
        "warning": "NO_NETWORK_SESSION_NO_COMPUTE_AUTHORIZATION",
    }
