"""Gate B4d: explicit one-shot private LAN knock CLI.

The CLI never starts a listener until an operator enters a precise confirmation
in a local interactive terminal. Its connection protocol does NOT use TLS and
is not security-audited. Suitable for controlled private laboratory tests only.
"""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import sqlite3
import sys

from .identity import IdentityDenied
from .lan_knock import LanDenied, knock_once, serve_one_knock
from .preflight import preflight_two_pc_lab
from .vault import unlock_encrypted_vault


def _prompt(prompt: str) -> str:
    if not sys.stdin.isatty():
        raise LanDenied("interactive local operator terminal required")
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt) as exc:
        raise LanDenied("operator cancelled session") from exc


def _passphrase() -> str:
    if not sys.stdin.isatty():
        raise LanDenied("interactive local operator terminal required")
    try:
        return getpass.getpass("Unlock local encrypted Porch identity: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise LanDenied("operator cancelled vault unlock") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PorchTalk lab: ONE opt-in private LAN proof, NO remote execution, experimental protocol."
    )
    modes = parser.add_subparsers(dest="mode", required=True)
    for name in ("serve", "knock"):
        sub = modes.add_parser(name, help=("Accept" if name == "serve" else "Initiate") + " one encrypted peer proof")
        sub.add_argument("--vault", required=True, type=Path, help="This machine's encrypted signing key")
        sub.add_argument("--trust-db", required=True, type=Path, help="Previously human-enrolled peer public keys")
        sub.add_argument("--local-ip", required=True, help="Exact RFC1918 IPv4 on this PC")
        sub.add_argument("--peer-ip", required=True, help="Exact RFC1918 IPv4 on the other PC")
        sub.add_argument("--peer-id", required=True, help="Previously pinned device ID")
        sub.add_argument("--port", required=True, type=int, help="49152..65535, same on both PCs")
        sub.add_argument("--timeout", default=5, type=float, help="Single session timeout: 0.5..10 s")
    args = parser.parse_args(argv)
    try:
        # Human approval always occurs BEFORE the vault is decrypted or any socket opened.
        action = "LISTEN" if args.mode == "serve" else "CONNECT"
        intended = args.local_ip if args.mode == "serve" else args.peer_ip
        print("EXPERIMENTAL PRIVATE-LAN KEY PROOF ONLY. NOT TLS. NOT PRODUCTION.")
        print("No remote code execution, AI inference, model weights or resource grants.")
        print("Inspect local Windows Firewall and router port-forwarding before using.")
        expected = f"{action} {intended}:{args.port} PEER {args.peer_id}"
        print(f"Approval requires typing EXACTLY: {expected}")
        if _prompt("> ") != expected:
            raise LanDenied("explicit one-shot operator approval denied")
        secret = _passphrase()
        identity = unlock_encrypted_vault(args.vault, passphrase=secret)
        # Inputs must describe exact private same-/24 endpoints and distinct IDs.
        preflight_two_pc_lab(
            local_ipv4=args.local_ip, peer_ipv4=args.peer_ip,
            port=args.port, local_device_id=identity.device_id,
            peer_device_id=args.peer_id, operator_approved=True,
        )
        action_fn = serve_one_knock if args.mode == "serve" else knock_once
        receipt = action_fn(
            identity=identity, peer_device_id=args.peer_id, trust_db_path=args.trust_db,
            local_ipv4=args.local_ip, peer_ipv4=args.peer_ip,
            port=args.port, timeout_seconds=args.timeout, operator_approved=True,
        )
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (LanDenied, IdentityDenied, OSError, ValueError, sqlite3.DatabaseError) as exc:
        print("DENIED: no authorized peer session completed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
