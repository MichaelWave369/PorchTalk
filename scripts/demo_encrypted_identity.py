"""Offline synthetic identity continuity demo. NO real devices, NO network.

The sample passphrase below is PUBLIC and must NEVER be reused for real keys.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from porchtalk.enrollment import export_public_card, verify_public_card
from porchtalk.identity import DeviceIdentity
from porchtalk.vault import create_encrypted_vault, unlock_encrypted_vault

DEMO_ONLY_PASSWORD = "demo-only-lanterns-at-the-porch-12345"


def main() -> None:
    identity = DeviceIdentity.generate_ephemeral("synthetic-main-pc")
    with TemporaryDirectory(prefix="porchtalk-b4b-") as folder:
        vault = Path(folder) / "synthetic.porchkey"
        expected = create_encrypted_vault(
            vault, identity, passphrase=DEMO_ONLY_PASSWORD,
        )
        # Simulates application restart by reconstructing from encrypted bytes.
        restored = unlock_encrypted_vault(vault, passphrase=DEMO_ONLY_PASSWORD)
        card = export_public_card(restored)
        _, _, verified_fingerprint = verify_public_card(card)
        print(json.dumps({
            "status": "OFFLINE_ENCRYPTED_IDENTITY_ROUNDTRIP",
            "device_id": restored.device_id,
            "fingerprint_consistent": expected == restored.fingerprint == verified_fingerprint,
            "vault_persisted_temporarily": True,
            "private_key_exported": False,
            "network_connected": False,
            "compute_authorized": False,
        }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
