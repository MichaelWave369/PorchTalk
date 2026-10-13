"""Gate B4e: conservative offline reconciliation of two claimed knock receipts.

This proves consistency of two user-supplied JSON files, NOT independent
attestation, signature validation, real PC hardware, or transport security.
The two input files may have been fabricated or altered after generation.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .lan_knock import PROTOCOL

_MAX_BYTES = 8192
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9._-]{1,80}\Z")
_REQUIRED = frozenset({
    "status", "protocol", "local_device_id", "local_fingerprint_sha256",
    "peer_device_id", "peer_fingerprint_sha256", "transcript_sha256",
    "proof_messages_encrypted", "handshake_identity_metadata_visible",
    "transport_type", "route_authorized", "compute_authorized", "warnings",
})


class EvidenceDenied(ValueError):
    """Unverifiable or inconsistent local evidence."""


def _valid_fingerprint(value: Any) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise EvidenceDenied("invalid SHA256 fingerprint or transcript")
    return value


def _ident(value: Any) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise EvidenceDenied("invalid device identity")
    return value


def _exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceDenied("duplicate JSON property")
        result[key] = value
    return result


def inspect_receipt(raw: Any) -> dict[str, Any]:
    if type(raw) is not dict or set(raw) != _REQUIRED:
        raise EvidenceDenied("unknown or missing receipt fields")
    if (raw["status"] != "LAN_ONE_SHOT_ENCRYPTED_KNOCK_PASS"
            or raw["protocol"] != PROTOCOL
            or raw["transport_type"] != "EXPERIMENTAL_ED25519_X25519_AESGCM_NOT_TLS"):
        raise EvidenceDenied("unrecognized or non-successful experimental proof")
    local_id, peer_id = _ident(raw["local_device_id"]), _ident(raw["peer_device_id"])
    if local_id == peer_id:
        raise EvidenceDenied("receipt points to itself")
    for key in ("local_fingerprint_sha256", "peer_fingerprint_sha256", "transcript_sha256"):
        _valid_fingerprint(raw[key])
    if (raw["proof_messages_encrypted"] is not True
            or raw["handshake_identity_metadata_visible"] is not True
            or raw["route_authorized"] is not False
            or raw["compute_authorized"] is not False):
        raise EvidenceDenied("security boundary claim mismatch")
    warnings = raw["warnings"]
    if (type(warnings) is not list or len(warnings) != 3
            or any(type(x) is not str for x in warnings)
            or set(warnings) != {"NOT_SECURITY_AUDITED", "ONE_SHOT_ONLY", "NO_COMMAND_OR_MODEL_PAYLOAD"}):
        raise EvidenceDenied("critical caveat missing from receipt")
    return dict(raw)


def compare_two_receipts(left: Any, right: Any) -> dict[str, Any]:
    a = inspect_receipt(left)
    b = inspect_receipt(right)
    if (a["local_device_id"] != b["peer_device_id"]
            or a["peer_device_id"] != b["local_device_id"]):
        raise EvidenceDenied("device directions are not mirrored")
    if (a["local_fingerprint_sha256"] != b["peer_fingerprint_sha256"]
            or a["peer_fingerprint_sha256"] != b["local_fingerprint_sha256"]):
        raise EvidenceDenied("public-key fingerprints do not cross-match")
    if a["transcript_sha256"] != b["transcript_sha256"]:
        raise EvidenceDenied("independent transcript digests differ")
    return {
        "status": "SELF_REPORTED_RECEIPTS_CONSISTENT",
        "devices": sorted([a["local_device_id"], b["local_device_id"]]),
        "transcript_sha256": a["transcript_sha256"],
        "session_authorized_for_compute": False,
        "independently_attested": False,
        "real_hardware_verified": False,
        "warnings": [
            "UNSIGNED_SELF_REPORTED_RECEIPTS",
            "SAME_TRANSCRIPT_ONLY_NOT_SECURITY_AUDIT",
            "MANUAL_REAL_HARDWARE_VALIDATION_REQUIRED",
        ],
    }


def read_receipt(path: str | Path) -> dict[str, Any]:
    src = Path(path)
    if src.is_symlink() or not src.is_file() or src.stat().st_size > _MAX_BYTES:
        raise EvidenceDenied("missing, linked or oversized receipt file")
    try:
        with src.open("rb") as stream:
            data = stream.read(_MAX_BYTES + 1)
        if len(data) > _MAX_BYTES:
            raise EvidenceDenied("oversized receipt")
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_exact_object)
    except EvidenceDenied:
        raise
    except (ValueError, UnicodeError, OSError) as exc:
        raise EvidenceDenied("invalid receipt JSON") from exc
    return inspect_receipt(doc)
