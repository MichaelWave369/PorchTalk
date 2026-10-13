"""Gate B4d: opt-in one-shot private IPv4 authenticated encrypted knock.

Experimental custom protocol using vetted Ed25519/X25519/HKDF/AESGCM primitives.
NOT TLS, NOT audited, NOT production secure transport, NO arbitrary payloads,
NO model weights, NO command execution, NO GPU/CPU sharing, NO public listener.
The interactive CLI is the only intended real-device entrypoint.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import time
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .identity import DeviceIdentity, IdentityDenied, PinnedPeers, public_fingerprint
from .loopback import _read_frame, _write_frame
from .pair_cli import checked_trust_db_path
from .preflight import preflight_two_pc_lab

PROTOCOL = "PORCHTALK_LAN_KNOCK_V1"
_TIMEOUT_MIN = 0.5
_TIMEOUT_MAX = 10
_TTL = 45
_SKEW = 10
_MAX_FRAME = 4096
_SIGNED_FIELDS = frozenset({"protocol", "kind", "sender_id", "recipient_id", "nonce",
                            "ephemeral_x25519_b64", "issued_at", "expires_at", "in_reply_to_sha256"})
_ENVELOPE_FIELDS = frozenset({"claims", "signature_b64"})
_ENCRYPTED_FIELDS = frozenset({"kind", "ciphertext_b64"})


class LanDenied(ValueError):
    """A private LAN research exchange was rejected."""


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(value: Any, length: int, label: str) -> bytes:
    if type(value) is not str or len(value) > 256:
        raise LanDenied(f"invalid {label}")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise LanDenied(f"invalid {label}") from exc
    if len(raw) != length:
        raise LanDenied(f"invalid {label} length")
    return raw


def _identifier(value: Any) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 80
            or not value.isascii()
            or any(not (c.isalnum() or c in "._-") for c in value)):
        raise LanDenied("invalid device ID")
    return value


def _hex(value: Any, length: int) -> str:
    if type(value) is not str or len(value) != length:
        raise LanDenied("invalid challenge identifier")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise LanDenied("invalid challenge identifier") from exc
    return value


def _epoch(value: Any) -> int:
    if type(value) is not int or value <= 0:
        raise LanDenied("invalid timestamp")
    return value


def _sign(
    identity: DeviceIdentity, ephemeral: X25519PrivateKey, kind: str,
    recipient_id: str, reply_hash: str | None, *, now: int | None = None,
) -> dict[str, Any]:
    instant = int(time.time()) if now is None else _epoch(now)
    if kind not in ("HELLO", "REPLY") or (kind == "HELLO" and reply_hash is not None):
        raise LanDenied("unexpected message kind")
    if kind == "REPLY":
        _hex(reply_hash, 64)
    public = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    claims = {
        "protocol": PROTOCOL, "kind": kind,
        "sender_id": _identifier(identity.device_id),
        "recipient_id": _identifier(recipient_id),
        "nonce": secrets.token_hex(16),
        "ephemeral_x25519_b64": _b64(public),
        "issued_at": instant,
        "expires_at": instant + _TTL,
        "in_reply_to_sha256": reply_hash,
    }
    if claims["sender_id"] == claims["recipient_id"]:
        raise LanDenied("self-directed connection")
    signature = identity.private_key.sign(_json(claims))
    return {"claims": claims, "signature_b64": _b64(signature)}


def _verify_signed(
    envelope: Any, *, expected_kind: str, expected_sender: str,
    expected_recipient: str, trusted: PinnedPeers, now: int | None = None,
) -> tuple[dict[str, Any], X25519PublicKey]:
    if type(envelope) is not dict or set(envelope) != _ENVELOPE_FIELDS:
        raise LanDenied("signed frame shape rejected")
    claims = envelope["claims"]
    if type(claims) is not dict or set(claims) != _SIGNED_FIELDS:
        raise LanDenied("signed claim fields rejected")
    if claims["protocol"] != PROTOCOL or claims["kind"] != expected_kind:
        raise LanDenied("unexpected protocol or message kind")
    if (claims["sender_id"] != _identifier(expected_sender)
            or claims["recipient_id"] != _identifier(expected_recipient)):
        raise LanDenied("peer ID or intended recipient mismatch")
    _hex(claims["nonce"], 32)
    issued, expires = _epoch(claims["issued_at"]), _epoch(claims["expires_at"])
    instant = int(time.time()) if now is None else _epoch(now)
    if expires <= issued or expires - issued > _TTL or instant < issued - _SKEW or instant >= expires:
        raise LanDenied("handshake timestamp invalid or expired")
    if expected_kind == "HELLO":
        if claims["in_reply_to_sha256"] is not None:
            raise LanDenied("unexpected reply hash in HELLO")
    else:
        _hex(claims["in_reply_to_sha256"], 64)
    public = _decode(claims["ephemeral_x25519_b64"], 32, "session public key")
    signature = _decode(envelope["signature_b64"], 64, "signature")
    try:
        trusted.approved_key(expected_sender).verify(signature, _json(claims))
    except (IdentityDenied, InvalidSignature) as exc:
        raise LanDenied("unknown, revoked or unauthenticated peer") from exc
    return claims, X25519PublicKey.from_public_bytes(public)


def _keys(ephemeral: X25519PrivateKey, peer_public: X25519PublicKey, transcript: bytes) -> tuple[bytes, bytes]:
    transcript_hash = hashlib.sha256(transcript).digest()
    key_material = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=transcript_hash,
        info=PROTOCOL.encode("ascii") + b"|one-shot-confirmation",
    ).derive(ephemeral.exchange(peer_public))
    return key_material[:32], key_material[32:]


def _seal(key: bytes, kind: str, proof: dict[str, Any], transcript: bytes, nonce: bytes) -> dict[str, str]:
    payload = _json({"kind": kind, "proof": proof})
    return {"kind": kind, "ciphertext_b64": _b64(AESGCM(key).encrypt(nonce, payload, hashlib.sha256(transcript).digest()))}


def _open(frame: Any, key: bytes, kind: str, transcript: bytes, nonce: bytes) -> dict[str, Any]:
    if type(frame) is not dict or set(frame) != _ENCRYPTED_FIELDS or frame["kind"] != kind:
        raise LanDenied("unexpected encrypted frame")
    ciphertext_b64 = frame["ciphertext_b64"]
    if type(ciphertext_b64) is not str or len(ciphertext_b64) > 1024:
        raise LanDenied("invalid encrypted payload")
    try:
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        payload = AESGCM(key).decrypt(nonce, ciphertext, hashlib.sha256(transcript).digest())
        result = json.loads(payload.decode("ascii"))
    except (InvalidTag, ValueError, UnicodeError, base64.binascii.Error) as exc:
        raise LanDenied("encrypted proof could not be verified") from exc
    if (type(result) is not dict or set(result) != {"kind", "proof"}
            or result["kind"] != kind or type(result["proof"]) is not dict):
        raise LanDenied("encrypted proof format rejected")
    return result["proof"]


def _preflight(
    *, local_id: str, peer_id: str, local_ipv4: str, peer_ipv4: str,
    port: int, trust_db_path: str | Path, operator_approved: bool,
) -> PinnedPeers:
    try:
        preflight_two_pc_lab(
            local_ipv4=local_ipv4, peer_ipv4=peer_ipv4, port=port,
            local_device_id=local_id, peer_device_id=peer_id, operator_approved=operator_approved,
        )
        path = checked_trust_db_path(Path(trust_db_path))
        if not path.exists():
            raise LanDenied("local peer trust database does not exist")
        peers = PinnedPeers(path)
        try:
            peers.approved_key(peer_id)
        except BaseException:
            peers.close()
            raise
        return peers
    except IdentityDenied as exc:
        raise LanDenied("private LAN preflight or trust rejected") from exc


def _receipt(identity: DeviceIdentity, peer_id: str, remote_fp: str, transcript: bytes) -> dict[str, Any]:
    return {
        "status": "LAN_ONE_SHOT_ENCRYPTED_KNOCK_PASS",
        "protocol": PROTOCOL,
        "local_device_id": identity.device_id,
        "local_fingerprint_sha256": identity.fingerprint,
        "peer_device_id": peer_id,
        "peer_fingerprint_sha256": remote_fp,
        "transcript_sha256": hashlib.sha256(transcript).hexdigest(),
        "proof_messages_encrypted": True,
        "handshake_identity_metadata_visible": True,
        "transport_type": "EXPERIMENTAL_ED25519_X25519_AESGCM_NOT_TLS",
        "route_authorized": False,
        "compute_authorized": False,
        "warnings": ["NOT_SECURITY_AUDITED", "ONE_SHOT_ONLY", "NO_COMMAND_OR_MODEL_PAYLOAD"],
    }


def _timeout(value: float) -> float:
    if type(value) not in (int, float) or not _TIMEOUT_MIN <= value <= _TIMEOUT_MAX:
        raise LanDenied("invalid one-shot timeout")
    return float(value)


def serve_one_knock(
    *, identity: DeviceIdentity, peer_device_id: str,
    trust_db_path: str | Path, local_ipv4: str, peer_ipv4: str,
    port: int, operator_approved: bool = False, timeout_seconds: float = 5,
) -> dict[str, Any]:
    """Opt-in **one incoming connection** on a precise RFC1918 address; exits.

    Does not execute remote commands, infer, accept free-form content or
    allocate remote resources. Never use on an untrusted network.
    """
    timeout = _timeout(timeout_seconds)
    trusted = _preflight(
        local_id=identity.device_id, peer_id=peer_device_id, local_ipv4=local_ipv4,
        peer_ipv4=peer_ipv4, port=port, trust_db_path=trust_db_path,
        operator_approved=operator_approved,
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.settimeout(timeout)
            listener.bind((local_ipv4, port))  # NEVER 0.0.0.0
            listener.listen(1)
            connection, remote = listener.accept()
            with connection:
                connection.settimeout(timeout)
                if remote[0] != peer_ipv4:
                    raise LanDenied("unexpected source IP")
                hello = _read_frame(connection)
                hello_claims, peer_ephemeral = _verify_signed(
                    hello, expected_kind="HELLO", expected_sender=peer_device_id,
                    expected_recipient=identity.device_id, trusted=trusted,
                )
                trusted.consume_once("lan_client_hello", peer_device_id, hello_claims["nonce"])
                local_ephemeral = X25519PrivateKey.generate()
                reply = _sign(identity, local_ephemeral, "REPLY", peer_device_id,
                              hashlib.sha256(_json(hello)).hexdigest())
                _write_frame(connection, reply)
                transcript = _json(hello) + b"\n" + _json(reply)
                c2s, s2c = _keys(local_ephemeral, peer_ephemeral, transcript)
                proof = _open(_read_frame(connection), c2s, "FINISHED", transcript, b"\0" * 11 + b"\x01")
                if proof != {"transcript_sha256": hashlib.sha256(transcript).hexdigest(),
                              "role": "client", "accepted_peer": identity.device_id}:
                    raise LanDenied("client confirmation mismatch")
                _write_frame(connection, _seal(
                    s2c, "ACK", {"transcript_sha256": hashlib.sha256(transcript).hexdigest(),
                                 "role": "server", "accepted_peer": peer_device_id},
                    transcript, b"\0" * 11 + b"\x02",
                ))
                return _receipt(identity, peer_device_id,
                                public_fingerprint(trusted.approved_key(peer_device_id)), transcript)
    except (OSError, IdentityDenied, ValueError) as exc:
        raise LanDenied("one-shot listener denied or failed") from exc
    finally:
        trusted.close()


def knock_once(
    *, identity: DeviceIdentity, peer_device_id: str,
    trust_db_path: str | Path, local_ipv4: str, peer_ipv4: str,
    port: int, operator_approved: bool = False, timeout_seconds: float = 5,
) -> dict[str, Any]:
    """Opt-in one-time encrypted signed challenge; no persistent session."""
    timeout = _timeout(timeout_seconds)
    trusted = _preflight(
        local_id=identity.device_id, peer_id=peer_device_id, local_ipv4=local_ipv4,
        peer_ipv4=peer_ipv4, port=port, trust_db_path=trust_db_path,
        operator_approved=operator_approved,
    )
    try:
        with socket.create_connection((peer_ipv4, port), timeout=timeout, source_address=(local_ipv4, 0)) as sock:
            sock.settimeout(timeout)
            local_ephemeral = X25519PrivateKey.generate()
            hello = _sign(identity, local_ephemeral, "HELLO", peer_device_id, None)
            _write_frame(sock, hello)
            reply = _read_frame(sock)
            reply_claims, peer_ephemeral = _verify_signed(
                reply, expected_kind="REPLY", expected_sender=peer_device_id,
                expected_recipient=identity.device_id, trusted=trusted,
            )
            if reply_claims["in_reply_to_sha256"] != hashlib.sha256(_json(hello)).hexdigest():
                raise LanDenied("reply does not bind offered challenge")
            trusted.consume_once("lan_server_reply", peer_device_id, reply_claims["nonce"])
            transcript = _json(hello) + b"\n" + _json(reply)
            c2s, s2c = _keys(local_ephemeral, peer_ephemeral, transcript)
            _write_frame(sock, _seal(
                c2s, "FINISHED", {"transcript_sha256": hashlib.sha256(transcript).hexdigest(),
                                  "role": "client", "accepted_peer": peer_device_id},
                transcript, b"\0" * 11 + b"\x01",
            ))
            proof = _open(_read_frame(sock), s2c, "ACK", transcript, b"\0" * 11 + b"\x02")
            if proof != {"transcript_sha256": hashlib.sha256(transcript).hexdigest(),
                          "role": "server", "accepted_peer": identity.device_id}:
                raise LanDenied("server confirmation mismatch")
            return _receipt(identity, peer_device_id,
                            public_fingerprint(trusted.approved_key(peer_device_id)), transcript)
    except (OSError, IdentityDenied, ValueError) as exc:
        raise LanDenied("one-shot client handshake denied or failed") from exc
    finally:
        trusted.close()
