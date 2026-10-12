"""Gate B4a public card and RFC1918 LAN-preflight fail-closed tests."""

import copy
from pathlib import Path
import tempfile
import unittest

from porchtalk.identity import DeviceIdentity, IdentityDenied, PinnedPeers
from porchtalk.enrollment import export_public_card, verify_public_card, approve_public_card
from porchtalk.preflight import preflight_two_pc_lab


class PublicCardTests(unittest.TestCase):
    def setUp(self):
        self.identity = DeviceIdentity.generate_ephemeral("storage-node-1")
        self.card = export_public_card(self.identity)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.trust = PinnedPeers(Path(self.temp.name) / "trust.sqlite3")
        self.addCleanup(self.trust.close)

    def test_public_card_valid_signature_and_fingerprint(self):
        ident, key, fingerprint = verify_public_card(self.card)
        self.assertEqual(ident, self.identity.device_id)
        self.assertEqual(fingerprint, self.identity.fingerprint)

    def test_card_does_not_contain_private_key(self):
        self.assertNotIn("private", repr(self.card).lower())
        self.assertEqual(set(self.card), {"claims", "self_signature_b64"})

    def test_manual_pin_success(self):
        fp = approve_public_card(
            self.trust, self.card,
            expected_device_id="storage-node-1",
            fingerprint_verified_out_of_band=self.identity.fingerprint,
            operator_approved=True,
        )
        self.assertEqual(fp, self.identity.fingerprint)
        self.assertEqual(
            self.trust.approved_key("storage-node-1").public_bytes_raw(),
            self.identity.public_key.public_bytes_raw(),
        )

    def test_operator_approval_is_mandatory(self):
        with self.assertRaisesRegex(IdentityDenied, "approval"):
            approve_public_card(self.trust, self.card,
                                expected_device_id="storage-node-1",
                                fingerprint_verified_out_of_band=self.identity.fingerprint)

    def test_wrong_full_fingerprint_denied(self):
        with self.assertRaisesRegex(IdentityDenied, "fingerprint"):
            approve_public_card(self.trust, self.card,
                                expected_device_id="storage-node-1",
                                fingerprint_verified_out_of_band="0" * 64,
                                operator_approved=True)

    def test_expected_identity_must_match(self):
        with self.assertRaisesRegex(IdentityDenied, "unexpected"):
            approve_public_card(self.trust, self.card,
                                expected_device_id="wrong-name",
                                fingerprint_verified_out_of_band=self.identity.fingerprint,
                                operator_approved=True)

    def test_tampered_device_id_fails_signature(self):
        card = copy.deepcopy(self.card)
        card["claims"]["device_id"] = "attacker-node"
        with self.assertRaises(IdentityDenied):
            verify_public_card(card)

    def test_tampered_public_key_rejected(self):
        impostor = DeviceIdentity.generate_ephemeral("storage-node-1")
        card = copy.deepcopy(self.card)
        card["claims"]["public_key_b64"] = export_public_card(impostor)["claims"]["public_key_b64"]
        with self.assertRaises(IdentityDenied):
            verify_public_card(card)

    def test_tampered_fingerprint_rejected(self):
        card = copy.deepcopy(self.card)
        card["claims"]["fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(IdentityDenied, "fingerprint"):
            verify_public_card(card)

    def test_extra_field_denied(self):
        card = copy.deepcopy(self.card)
        card["claims"]["command"] = "execute"
        with self.assertRaisesRegex(IdentityDenied, "claims"):
            verify_public_card(card)

    def test_wrong_protocol_denied(self):
        card = copy.deepcopy(self.card)
        card["claims"]["protocol"] = "SOMETHING_ELSE"
        with self.assertRaisesRegex(IdentityDenied, "unsupported"):
            verify_public_card(card)

    def test_card_signature_corrupted(self):
        card = copy.deepcopy(self.card)
        card["self_signature_b64"] = "!not-base64"
        with self.assertRaises(IdentityDenied):
            verify_public_card(card)

    def test_card_cannot_replace_pinned_key(self):
        approve_public_card(self.trust, self.card,
                            expected_device_id="storage-node-1",
                            fingerprint_verified_out_of_band=self.identity.fingerprint,
                            operator_approved=True)
        replacement = DeviceIdentity.generate_ephemeral("storage-node-1")
        with self.assertRaisesRegex(IdentityDenied, "rotation"):
            approve_public_card(self.trust, export_public_card(replacement),
                                expected_device_id="storage-node-1",
                                fingerprint_verified_out_of_band=replacement.fingerprint,
                                operator_approved=True)

    def test_card_cannot_reenroll_revoked_identity(self):
        approve_public_card(self.trust, self.card,
                            expected_device_id="storage-node-1",
                            fingerprint_verified_out_of_band=self.identity.fingerprint,
                            operator_approved=True)
        self.trust.revoke("storage-node-1")
        with self.assertRaises(IdentityDenied):
            approve_public_card(self.trust, self.card,
                                expected_device_id="storage-node-1",
                                fingerprint_verified_out_of_band=self.identity.fingerprint,
                                operator_approved=True)


class LANPlanTests(unittest.TestCase):
    def setUp(self):
        self.args = dict(
            local_ipv4="192.168.10.15", peer_ipv4="192.168.10.20",
            port=54321, local_device_id="porch-a", peer_device_id="porch-b",
            operator_approved=True)

    def plan(self, **kwargs):
        payload = dict(self.args, **kwargs)
        return preflight_two_pc_lab(**payload)

    def test_valid_1918_plan_never_opens_socket(self):
        result = self.plan()
        self.assertEqual(result["status"], "PLAN_REVIEW_ONLY")
        self.assertFalse(result["sockets_created"])
        self.assertFalse(result["execution_authorized"])

    def test_optin_required(self):
        with self.assertRaisesRegex(IdentityDenied, "approval"):
            self.plan(operator_approved=False)

    def test_public_ipv4_denied(self):
        for address in ("8.8.8.8", "1.1.1.1", "100.64.0.1"):
            with self.subTest(address=address), self.assertRaises(IdentityDenied):
                self.plan(peer_ipv4=address)

    def test_loopback_linklocal_multicast_unspecified_denied(self):
        for address in ("127.0.0.1", "169.254.1.20", "224.0.0.1", "0.0.0.0"):
            with self.subTest(address=address), self.assertRaises(IdentityDenied):
                self.plan(peer_ipv4=address)

    def test_dns_names_are_forbidden(self):
        for address in ("my-router.local", "localhost", "192.168.10.20 ", "::1"):
            with self.subTest(address=address), self.assertRaises(IdentityDenied):
                self.plan(peer_ipv4=address)

    def test_other_subnet_denied_for_first_lab(self):
        with self.assertRaisesRegex(IdentityDenied, "same /24"):
            self.plan(peer_ipv4="192.168.11.20")

    def test_same_address_denied(self):
        with self.assertRaisesRegex(IdentityDenied, "same"):
            self.plan(peer_ipv4="192.168.10.15")

    def test_last_octet_zero_or_255_denied(self):
        for address in ("192.168.10.0", "192.168.10.255"):
            with self.subTest(address=address), self.assertRaises(IdentityDenied):
                self.plan(peer_ipv4=address)

    def test_ports_are_restricted(self):
        for port in (0, 80, 443, 49151, 65536, True, "54321"):
            with self.subTest(port=port), self.assertRaises(IdentityDenied):
                self.plan(port=port)

    def test_duplicate_or_malformed_peer_ids_rejected(self):
        for device_id in ("porch-a", "../secret", "", "name space"):
            with self.subTest(device_id=device_id), self.assertRaises(IdentityDenied):
                self.plan(peer_device_id=device_id)

    def test_172_and_10_private_ranges_allowed(self):
        self.assertEqual(self.plan(local_ipv4="10.1.2.3", peer_ipv4="10.1.2.4")["status"], "PLAN_REVIEW_ONLY")
        self.assertEqual(self.plan(local_ipv4="172.20.4.3", peer_ipv4="172.20.4.4")["status"], "PLAN_REVIEW_ONLY")

    def test_noncanonical_ipv4_denied(self):
        for address in ("192.168.010.20", "0xc0a80a14", "3232238100"):
            with self.subTest(address=address), self.assertRaises(IdentityDenied):
                self.plan(peer_ipv4=address)


if __name__ == "__main__":
    unittest.main()
