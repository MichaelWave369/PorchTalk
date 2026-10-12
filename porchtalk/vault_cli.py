"""Operator-run encrypted Porch identity vault CLI. No network access.

Passwords are prompted, never accepted as command-line arguments or logged.
CAUTION: This experimental vault is NOT OS-backed hardware key protection.
"""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sys

from .enrollment import export_public_card, verify_public_card
from .identity import DeviceIdentity, IdentityDenied
from .vault import create_encrypted_vault, unlock_encrypted_vault


def _public_card_write(path: Path, card: dict) -> None:
    payload = json.dumps(card, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if len(payload) > 8192:
        raise IdentityDenied("public card unexpectedly large")
    try:
        with path.open("x", encoding="utf-8") as file:
            file.write(payload)
    except OSError as exc:
        raise IdentityDenied("public card write failed or already exists") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PorchTalk encrypted test identity vault. No networking or compute execution."
    )
    operations = parser.add_subparsers(dest="operation", required=True)
    new = operations.add_parser("init", help="Create an encrypted identity vault; never overwrite")
    new.add_argument("--device-id", required=True)
    new.add_argument("--vault", required=True, type=Path)
    export = operations.add_parser("export-card", help="Unlock identity and write a PUBLIC-only signed card")
    export.add_argument("--vault", required=True, type=Path)
    export.add_argument("--out", required=True, type=Path)
    check = operations.add_parser("verify-card", help="Inspect a PUBLIC card, not an ownership verification")
    check.add_argument("--card", required=True, type=Path)

    args = parser.parse_args(argv)
    try:
        if args.operation == "init":
            if args.vault.exists() or args.vault.is_symlink():
                raise IdentityDenied("vault already exists; never overwrite")
            first = getpass.getpass("New encrypted vault passphrase (min 14 characters): ")
            confirmation = getpass.getpass("Confirm new passphrase: ")
            if first != confirmation:
                raise IdentityDenied("passphrases do not match")
            identity = DeviceIdentity.generate_ephemeral(args.device_id)
            fingerprint = create_encrypted_vault(args.vault, identity, passphrase=first)
            print(f"ENCRYPTED_VAULT_CREATED device_id={identity.device_id}")
            print(f"PUBLIC_KEY_SHA256={fingerprint}")
            print("WARNING: losing the passphrase makes this identity unrecoverable without a backup.")
        elif args.operation == "export-card":
            password = getpass.getpass("Unlock existing encrypted vault: ")
            identity = unlock_encrypted_vault(args.vault, passphrase=password)
            card = export_public_card(identity)
            _public_card_write(args.out, card)
            print(f"PUBLIC_CARD_EXPORTED={args.out}")
            print(f"PUBLIC_KEY_SHA256={identity.fingerprint}")
            print("PUBLIC CARD ONLY. A matching fingerprint requires independent human verification.")
        elif args.operation == "verify-card":
            if args.card.stat().st_size > 8192:
                raise IdentityDenied("public card too large")
            card = json.loads(args.card.read_text(encoding="utf-8"))
            device_id, _, fp = verify_public_card(card)
            print(f"UNTRUSTED_CARD_CLAIM_DEVICE_ID={device_id}")
            print(f"PUBLIC_KEY_SHA256={fp}")
            print("NOT ENROLLED. Check the full fingerprint with the owner over an independent channel.")
        return 0
    except (IdentityDenied, OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
        # Avoid printing exception objects from unsafe input paths or internals.
        if isinstance(exc, IdentityDenied):
            print(f"DENIED: {exc}", file=sys.stderr)
        else:
            print("DENIED: vault operation failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
