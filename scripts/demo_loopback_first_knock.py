"""PorchTalk Gate B3: local loopback-only First Knock proof.

This demo opens a temporary 127.0.0.1 socket ONLY and tests mutual TLS 1.3
authentication. No device discovery, LAN binding, remote execution, model
weights, shared compute, or permanent private keys.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from porchtalk.identity import DeviceIdentity, PinnedPeers
from porchtalk.loopback import run_loopback_first_knock


def main() -> None:
    alice = DeviceIdentity.generate_ephemeral("alice-laptop")
    bob = DeviceIdentity.generate_ephemeral("bob-desktop")
    with TemporaryDirectory(prefix="porchtalk-first-knock-") as directory:
        alice_db = Path(directory) / "alice.sqlite3"
        bob_db = Path(directory) / "bob.sqlite3"
        alice_trust = PinnedPeers(alice_db)
        bob_trust = PinnedPeers(bob_db)
        try:
            # Demonstration-only implicit approval of IN-MEMORY locally generated
            # test peers. NEVER use this bootstrap for real people/devices.
            alice_trust.enroll(bob.device_id, bob.public_key, operator_approved=True)
            bob_trust.enroll(alice.device_id, alice.public_key, operator_approved=True)
        finally:
            alice_trust.close()
            bob_trust.close()
        result = run_loopback_first_knock(
            alice=alice, bob=bob,
            alice_trust_path=alice_db, bob_trust_path=bob_db,
        )
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
