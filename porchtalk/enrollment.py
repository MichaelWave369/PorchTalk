"""Gate B4a: offline portable *public-only* device enrollment cards.

Cards prove possession of the matching private key at creation, NOT the real
human/operator identity behind the device. Human-verified full SHA256 fingerprint
comparison via an independent channel is mandatory for trust enrollment.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity import DeviceIdentity, IdentityDenied, PinnedPeers, public_fingerprint

PROTOCOL = "PORCHTALK_ENROLLMENT_CARD_V1"
_CLAIM_KEYS = frozenset({"protocol", "device_id", "key_type", "public_key_b64", "fingerprint_sha256"})
_CARD_KEYS = frozenset({"claims", "self_signature_b64"})


def _valid_id(value: Any) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 80
            or not value.isascii()
            or any(not (c.isalnum() or c in "._-") for c in value)):
        raise IdentityDenied("invalid device id")
    return value


def _decode(value: Any, size: int, field: str) -> bytes:
    if type(value) is not str:
        raise IdentityDenied(f"invalid {field}")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise IdentityDenied(f"invalid {field}") from exc
    if len(raw) != size:
        raise IdentityDenied(f"invalid {field} length")
    return raw


def _canonical(claims: dict[str, Any]) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def export_public_card(identity: DeviceIdentity) -> dict[str, Any]:
    """Produce a shareable PUBLIC identity card. Never exports private bytes."""
    if not isinstance(identity, DeviceIdentity):
        raise IdentityDenied("device identity required")
    pub = identity.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    claims = {
        "protocol": PROTOCOL, "device_id": _valid_id(identity.device_id),
        "key_type": "Ed25519", "public_key_b64": base64.b64encode(pub).decode("ascii"),
        "fingerprint_sha256": hashlib.sha256(pub).hexdigest(),
    }
    signature = identity.private_key.sign(_canonical(claims))
    return {"claims": claims, "self_signature_b64": base64.b64encode(signature).decode("ascii")}


def verify_public_card(raw: Any) -> tuple[str, Ed25519PublicKey, str]:
    """Validate the self-signature/fingerprint; does NOT establish human identity."""
    if type(raw) is not dict or set(raw) != _CARD_KEYS:
        raise IdentityDenied("invalid enrollment card shape")
    claims = raw["claims"]
    if type(claims) is not dict or set(claims) != _CLAIM_KEYS:
        raise IdentityDenied("invalid enrollment claims")
    if claims["protocol"] != PROTOCOL or claims["key_type"] != "Ed25519":
        raise IdentityDenied("unsupported identity card")
    device_id = _valid_id(claims["device_id"])
    pub = Ed25519PublicKey.from_public_bytes(_decode(claims["public_key_b64"], 32, "public key"))
    fingerprint = public_fingerprint(pub)
    if type(claims["fingerprint_sha256"]) is not str or claims["fingerprint_sha256"] != fingerprint:
        raise IdentityDenied("fingerprint mismatch")
    signature = _decode(raw["self_signature_b64"], 64, "signature")
    try:
        pub.verify(signature, _canonical(claims))
    except InvalidSignature as exc:
        raise IdentityDenied("invalid enrollment card signature") from exc
    return device_id, pub, fingerprint


def approve_public_card(
    trust: PinnedPeers,
    raw: Any,
    *,
    expected_device_id: str,
    fingerprint_verified_out_of_band: str,
    operator_approved: bool = False,
) -> str:
    """Pin only after *full* operator-confirmed fingerprint and named peer match."""
    if not isinstance(trust, PinnedPeers) or operator_approved is not True:
        raise IdentityDenied("explicit operator approval required")
    device_id, key, fingerprint = verify_public_card(raw)
    if device_id != _valid_id(expected_device_id):
        raise IdentityDenied("unexpected device identity")
    if (type(fingerprint_verified_out_of_band) is not str
            or fingerprint_verified_out_of_band != fingerprint):
        raise IdentityDenied("out-of-band full fingerprint mismatch")
    return trust.enroll(device_id, key, operator_approved=True)
