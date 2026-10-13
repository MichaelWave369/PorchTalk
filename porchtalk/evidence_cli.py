"""Offline PorchTalk signed-transcript receipt comparison CLI.

Accepts JSON receipt files saved from two independently observed consoles.
Does not verify digital signatures or claim real hardware was reached.
"""

import argparse
import json
import sys

from .evidence import EvidenceDenied, compare_two_receipts, read_receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two PorchTalk B4d receipts offline (consistency, not proof of hardware)."
    )
    parser.add_argument("left", help="First JSON receipt")
    parser.add_argument("right", help="Second JSON receipt")
    args = parser.parse_args(argv)
    try:
        result = compare_two_receipts(read_receipt(args.left), read_receipt(args.right))
    except (EvidenceDenied, OSError, ValueError) as exc:
        print("DENIED: receipts cannot be reconciled", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
