"""Temporary, offline demonstration of two manually pinned Porch identities."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from porchtalk.identity import DeviceIdentity, PinnedPeers, create_challenge, respond_to_challenge, verify_response


def main() -> None:
    alice = DeviceIdentity.generate_ephemeral("alice-laptop")
    bob = DeviceIdentity.generate_ephemeral("bob-desktop")
    with TemporaryDirectory(prefix="porchtalk-id-demo-") as folder:
        alice_trust = PinnedPeers(Path(folder) / "alice.sqlite3")
        bob_trust = PinnedPeers(Path(folder) / "bob.sqlite3")
        try:
            # Concept demonstration: real operators MUST independently confirm fingerprints.
            alice_trust.enroll(bob.device_id, bob.public_key, operator_approved=True)
            bob_trust.enroll(alice.device_id, alice.public_key, operator_approved=True)
            challenge = create_challenge(alice, bob.device_id)
            response = respond_to_challenge(bob, challenge, bob_trust)
            result = verify_response(alice, challenge, response, alice_trust)
            print(json.dumps({
                "simulation": "OFFLINE_ONLY",
                "alice_public_fingerprint": alice.fingerprint,
                "bob_public_fingerprint": bob.fingerprint,
                "identity_result": result,
                "network_connected": False,
                "compute_authorized": False,
            }, indent=2, sort_keys=True))
        finally:
            alice_trust.close()
            bob_trust.close()


if __name__ == "__main__":
    main()
