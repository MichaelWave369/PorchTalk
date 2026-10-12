"""Gate B4c: explicit human public-key pairing, offline only.

The signed card is UNTRUSTED until an operator personally compares its entire
fingerprint against a separate trusted view of the intended physical device.
This CLI does not attest that the verification occurred, and a compromised
host can manipulate input. There is no LAN transport or compute authorization.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from typing import Any

from .enrollment import approve_public_card, verify_public_card
from .identity import IdentityDenied, PinnedPeers, public_fingerprint

_MAX_CARD = 8192
_PEER_ID = re.compile(r"[A-Za-z0-9._-]{1,80}\Z")


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise IdentityDenied("duplicate JSON key in public card")
        result[name] = value
    return result


def _validated_peer_id(value: str) -> str:
    if type(value) is not str or not _PEER_ID.fullmatch(value):
        raise IdentityDenied("invalid device ID")
    return value


def read_public_card(path: Path) -> tuple[dict[str, Any], str, str]:
    """Validate a bounded public-only card, rejecting duplicate JSON keys."""
    if path.is_symlink() or not path.is_file():
        raise IdentityDenied("public card must be a regular non-symlink file")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_CARD:
        raise IdentityDenied("public card invalid or oversized")
    try:
        data = path.read_bytes()
        if len(data) > _MAX_CARD:
            raise IdentityDenied("public card oversized")
        card = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except IdentityDenied:
        raise
    except (UnicodeError, ValueError, OSError) as exc:
        raise IdentityDenied("invalid public card JSON") from exc
    peer_id, _, fingerprint = verify_public_card(card)
    return card, peer_id, fingerprint


def checked_trust_db_path(path: Path) -> Path:
    """Require preexisting private folder and reject obvious DB path hazards.

    On Windows, this cannot validate or enforce owner-only ACLs. Caller must
    choose an OS-protected directory and inspect its security independently.
    """
    raw = Path(path)
    if ".." in raw.parts or not raw.name or raw.is_symlink():
        raise IdentityDenied("unsafe trust database path")
    root = raw.absolute()
    if not root.parent.is_dir():
        raise IdentityDenied("trust directory does not exist")
    ancestor = root.parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise IdentityDenied("symlinked trust directory denied")
        ancestor = ancestor.parent
    if os.name == "posix":
        mode = root.parent.stat().st_mode
        if mode & 0o077:
            raise IdentityDenied("trust directory must be private (0700)")
    if root.exists():
        info = root.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise IdentityDenied("invalid trust database file")
        if os.name == "posix" and info.st_mode & 0o077:
            raise IdentityDenied("trust database file must be private (0600)")
    return root


def _open_trust(path: Path) -> PinnedPeers:
    """Make a new trust DB with owner-only POSIX mode; no auto-enrollment."""
    final = checked_trust_db_path(path)
    if not final.exists():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(final, flags, 0o600)
        except FileExistsError as exc:
            raise IdentityDenied("trust database appeared during creation") from exc
        except OSError as exc:
            raise IdentityDenied("trust database cannot be created") from exc
        else:
            os.close(fd)
    # A dedicated private directory is mandatory even for an existing DB.
    checked_trust_db_path(final)
    return PinnedPeers(final)


def _prompt_interactive(prompt: str) -> str:
    # No --yes, --fingerprint or pipe-to-approve option: a physical terminal is
    # required. This does not guarantee an independent trusted channel.
    if not sys.stdin.isatty():
        raise IdentityDenied("pairing requires an interactive terminal")
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt) as exc:
        raise IdentityDenied("pairing cancelled") from exc


def enroll_interactively(*, card_path: Path, trust_db_path: Path, expected_device_id: str) -> dict[str, Any]:
    card, claimed_device, fingerprint = read_public_card(card_path)
    expected = _validated_peer_id(expected_device_id)
    if claimed_device != expected:
        raise IdentityDenied("unexpected device ID")
    # Path preflight must happen before input but must not create a DB.
    checked_trust_db_path(trust_db_path)
    print(f"UNTRUSTED PUBLIC CARD for: {claimed_device}")
    print(f"UNTRUSTED CARD SHA256 PUBLIC KEY: {fingerprint}")
    print("On the OTHER physical Porch, separately read its local vault public-key fingerprint.")
    print("Do NOT copy the fingerprint from this received card or message.")
    entered = _prompt_interactive("Type all 64 fingerprint characters observed on that other device: ")
    if entered != fingerprint:
        raise IdentityDenied("independently supplied fingerprint mismatch")
    confirmation = _prompt_interactive(f"Type exactly 'ENROLL {expected}' to pin this identity: ")
    if confirmation != f"ENROLL {expected}":
        raise IdentityDenied("explicit device approval not received")
    # Open the DB only after the operator's two separate confirmations.
    trusted = _open_trust(trust_db_path)
    try:
        pinned = approve_public_card(
            trusted, card, expected_device_id=expected,
            fingerprint_verified_out_of_band=entered,
            operator_approved=True,
        )
    finally:
        trusted.close()
    return {
        "status": "PUBLIC_KEY_PINNED_LOCAL_ONLY",
        "device_id": expected, "public_fingerprint_sha256": pinned,
        "peer_authenticated_over_network": False,
        "compute_authorized": False,
        "warning": "HUMAN_CONFIRMATION_IS_NOT_INDEPENDENTLY_ATTESTED",
    }


def revoke_interactively(*, trust_db_path: Path, device_id: str) -> dict[str, Any]:
    peer = _validated_peer_id(device_id)
    # Never create new database as a side effect of attempting revocation.
    path = checked_trust_db_path(trust_db_path)
    if not path.exists():
        raise IdentityDenied("trust database not found")
    confirmation = _prompt_interactive(f"Type exactly 'REVOKE {peer}' to block this pinned key: ")
    if confirmation != f"REVOKE {peer}":
        raise IdentityDenied("explicit revocation confirmation not received")
    trust = _open_trust(path)
    try:
        trust.revoke(peer)
    finally:
        trust.close()
    return {"status": "LOCAL_TRUST_REVOKED", "device_id": peer, "compute_authorized": False}


def inspect_trust(*, trust_db_path: Path) -> dict[str, Any]:
    path = checked_trust_db_path(trust_db_path)
    if not path.exists():
        raise IdentityDenied("trust database not found")
    trust = _open_trust(path)
    try:
        records = trust.db.execute(
            "SELECT device_id, public_key, revoked FROM peers ORDER BY device_id LIMIT 257"
        ).fetchall()
        if len(records) > 256:
            raise IdentityDenied("trust store too large for bounded inspection")
        peers = [
            {
                "device_id": name,
                "fingerprint_sha256": __fingerprint_from_raw(key),
                "revoked": bool(revoked),
            }
            for name, key, revoked in records
        ]
    finally:
        trust.close()
    return {"status": "LOCAL_TRUST_INSPECTION_ONLY", "peers": peers, "compute_authorized": False}


def __fingerprint_from_raw(raw: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return public_fingerprint(Ed25519PublicKey.from_public_bytes(raw))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline, manually confirmed Porch public-key pairing. NO LAN or compute.")
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_card = commands.add_parser("inspect-card", help="Verify signed PUBLIC card, without trusting it")
    inspect_card.add_argument("--card", required=True, type=Path)
    enroll = commands.add_parser("enroll", help="Interactive, separately confirmed peer fingerprint enrollment")
    enroll.add_argument("--card", required=True, type=Path)
    enroll.add_argument("--trust-db", required=True, type=Path)
    enroll.add_argument("--expected-id", required=True)
    revoke = commands.add_parser("revoke", help="Interactively revoke a previously enrolled peer")
    revoke.add_argument("--trust-db", required=True, type=Path)
    revoke.add_argument("--device-id", required=True)
    show = commands.add_parser("list", help="Read enrolled public-key fingerprints and revoked status")
    show.add_argument("--trust-db", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect-card":
            _, name, fingerprint = read_public_card(args.card)
            result = {
                "status": "UNTRUSTED_PUBLIC_CARD_VALID",
                "claimed_device_id": name, "public_fingerprint_sha256": fingerprint,
                "peer_authenticated_over_network": False,
            }
        elif args.command == "enroll":
            result = enroll_interactively(card_path=args.card, trust_db_path=args.trust_db, expected_device_id=args.expected_id)
        elif args.command == "revoke":
            result = revoke_interactively(trust_db_path=args.trust_db, device_id=args.device_id)
        else:
            result = inspect_trust(trust_db_path=args.trust_db)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (IdentityDenied, OSError, ValueError, sqlite3.DatabaseError) as exc:
        # Don't show source paths or object repr from invalid untrusted files.
        reason = str(exc) if isinstance(exc, IdentityDenied) else "pairing IO or validation failure"
        print(f"DENIED: {reason}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
