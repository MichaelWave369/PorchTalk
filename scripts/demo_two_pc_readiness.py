"""Synthetic public-card enrollment and private-address planning. NO NETWORK."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from porchtalk.enrollment import approve_public_card, export_public_card, verify_public_card
from porchtalk.identity import DeviceIdentity, PinnedPeers
from porchtalk.preflight import preflight_two_pc_lab


def main() -> None:
    a = DeviceIdentity.generate_ephemeral("main-pc")
    b = DeviceIdentity.generate_ephemeral("storage-node-1")
    card_a = export_public_card(a)
    card_b = export_public_card(b)
    # Demo ONLY: Here both disposable public keys are created inside the same
    # process. Real operators must compare full fingerprints out-of-band.
    verify_public_card(card_a)
    verify_public_card(card_b)
    with TemporaryDirectory(prefix="porchtalk-preflight-") as folder:
        db_a = PinnedPeers(Path(folder) / "main.sqlite3")
        db_b = PinnedPeers(Path(folder) / "storage.sqlite3")
        try:
            approve_public_card(db_a, card_b,
                                expected_device_id="storage-node-1",
                                fingerprint_verified_out_of_band=b.fingerprint,
                                operator_approved=True)
            approve_public_card(db_b, card_a,
                                expected_device_id="main-pc",
                                fingerprint_verified_out_of_band=a.fingerprint,
                                operator_approved=True)
            plan = preflight_two_pc_lab(
                local_ipv4="192.168.10.15",
                peer_ipv4="192.168.10.20",
                port=54321,
                local_device_id="main-pc",
                peer_device_id="storage-node-1",
                operator_approved=True,
            )
            print(json.dumps({
                "mode": "OFFLINE_SYNTHETIC_ONLY",
                "main_public_fingerprint": a.fingerprint,
                "storage_public_fingerprint": b.fingerprint,
                "plan": plan,
                "lan_connected": False,
                "resource_grant": False,
            }, indent=2))
        finally:
            db_a.close()
            db_b.close()


if __name__ == "__main__":
    main()
