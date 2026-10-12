"""Gate B2 negative controls: offline-only pinned public-key identity."""

import copy
import tempfile
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from porchtalk.identity import (
    DeviceIdentity, IdentityDenied, PinnedPeers, create_challenge,
    respond_to_challenge, verify_response,
)

T = 1800000000


class OfflinePeerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.alice = DeviceIdentity.generate_ephemeral("alice-laptop")
        self.bob = DeviceIdentity.generate_ephemeral("bob-desktop")
        self.alice_db = Path(self.tmp.name) / "alice.sqlite3"
        self.bob_db = Path(self.tmp.name) / "bob.sqlite3"
        self.alice_trust = PinnedPeers(self.alice_db)
        self.bob_trust = PinnedPeers(self.bob_db)
        self.addCleanup(self.alice_trust.close)
        self.addCleanup(self.bob_trust.close)
        self.alice_trust.enroll("bob-desktop", self.bob.public_key, operator_approved=True)
        self.bob_trust.enroll("alice-laptop", self.alice.public_key, operator_approved=True)

    def exchange(self, *, time=T):
        challenge = create_challenge(self.alice, "bob-desktop", now=time)
        response = respond_to_challenge(self.bob, challenge, self.bob_trust, now=time + 1)
        result = verify_response(self.alice, challenge, response, self.alice_trust, now=time + 2)
        return challenge, response, result

    def test_two_pinned_peers_can_verify_each_other_offline(self):
        c, r, result = self.exchange()
        self.assertEqual(result["status"], "AUTHENTICATED_OFFLINE_PROOF_ONLY")
        self.assertEqual(result["peer_id"], "bob-desktop")
        self.assertEqual(result["peer_fingerprint"], self.bob.fingerprint)
        self.assertEqual(result["challenge_nonce"], c["claims"]["nonce"])
        self.assertEqual(r["claims"]["recipient_id"], self.alice.device_id)

    def test_enrollment_never_happens_by_default(self):
        other = DeviceIdentity.generate_ephemeral("eve")
        with self.assertRaisesRegex(IdentityDenied, "approval"):
            self.alice_trust.enroll("eve", other.public_key)
        with self.assertRaisesRegex(IdentityDenied, "not approved"):
            self.alice_trust.approved_key("eve")

    def test_cannot_replace_pinned_key_implicitly(self):
        attacker = DeviceIdentity.generate_ephemeral("bob-desktop")
        with self.assertRaisesRegex(IdentityDenied, "rotation"):
            self.alice_trust.enroll("bob-desktop", attacker.public_key, operator_approved=True)

    def test_fingerprint_is_stable(self):
        self.assertEqual(self.bob.fingerprint, self.alice_trust.enroll(
            "new-bob", self.bob.public_key, operator_approved=True
        ))

    def test_untrusted_challenger_denied(self):
        self.bob_trust.revoke("alice-laptop")
        challenge = create_challenge(self.alice, "bob-desktop", now=T)
        with self.assertRaises(IdentityDenied):
            respond_to_challenge(self.bob, challenge, self.bob_trust, now=T + 1)

    def test_revoked_responder_denied(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        r = respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)
        self.alice_trust.revoke("bob-desktop")
        with self.assertRaises(IdentityDenied):
            verify_response(self.alice, c, r, self.alice_trust, now=T + 2)

    def test_replay_responder_does_not_sign_twice(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)
        with self.assertRaisesRegex(IdentityDenied, "replayed"):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 2)

    def test_replay_initiator_cannot_accept_twice(self):
        c, r, _ = self.exchange()
        with self.assertRaisesRegex(IdentityDenied, "replayed"):
            verify_response(self.alice, c, r, self.alice_trust, now=T + 3)

    def test_replay_persists_after_process_reopen(self):
        c, r, _ = self.exchange()
        self.bob_trust.close()
        self.alice_trust.close()
        self.bob_trust = PinnedPeers(self.bob_db)
        self.alice_trust = PinnedPeers(self.alice_db)
        with self.assertRaisesRegex(IdentityDenied, "replayed"):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 4)
        with self.assertRaisesRegex(IdentityDenied, "replayed"):
            verify_response(self.alice, c, r, self.alice_trust, now=T + 4)

    def test_challenge_tampering_denied(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        c["claims"]["recipient_id"] = "eve"
        with self.assertRaises(IdentityDenied):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)

    def test_wrong_target_denied(self):
        c = create_challenge(self.alice, "someone-else", now=T)
        with self.assertRaisesRegex(IdentityDenied, "wrong recipient"):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)

    def test_fake_challenger_key_denied(self):
        eve = DeviceIdentity.generate_ephemeral("alice-laptop")
        c = create_challenge(eve, "bob-desktop", now=T)
        with self.assertRaisesRegex(IdentityDenied, "signature"):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)

    def test_fake_responder_key_denied(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        eve = DeviceIdentity.generate_ephemeral("bob-desktop")
        # The response is signed by a different key, not the pinned Bob key.
        r = respond_to_challenge(eve, c, self.bob_trust, now=T + 1)
        with self.assertRaisesRegex(IdentityDenied, "signature"):
            verify_response(self.alice, c, r, self.alice_trust, now=T + 2)

    def test_response_tampering_denied(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        r = respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)
        r["claims"]["recipient_id"] = "eve"
        with self.assertRaises(IdentityDenied):
            verify_response(self.alice, c, r, self.alice_trust, now=T + 2)

    def test_response_must_bind_exact_challenge(self):
        c1 = create_challenge(self.alice, "bob-desktop", now=T)
        c2 = create_challenge(self.alice, "bob-desktop", now=T)
        r = respond_to_challenge(self.bob, c1, self.bob_trust, now=T + 1)
        with self.assertRaisesRegex(IdentityDenied, "transcript"):
            verify_response(self.alice, c2, r, self.alice_trust, now=T + 2)

    def test_expired_challenge_denied(self):
        c = create_challenge(self.alice, "bob-desktop", now=T, ttl_seconds=3)
        with self.assertRaisesRegex(IdentityDenied, "expired"):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 3)

    def test_future_challenge_denied(self):
        c = create_challenge(self.alice, "bob-desktop", now=T + 100)
        with self.assertRaisesRegex(IdentityDenied, "premature"):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T)

    def test_lifetime_bound(self):
        with self.assertRaisesRegex(IdentityDenied, "lifetime"):
            create_challenge(self.alice, "bob-desktop", now=T, ttl_seconds=121)

    def test_extra_fields_denied(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        c["claims"]["run_shell"] = True
        with self.assertRaisesRegex(IdentityDenied, "shape"):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)

    def test_bad_signature_encoding_denied(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        c["signature_b64"] = "???"
        with self.assertRaisesRegex(IdentityDenied, "signature"):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)

    def test_signer_does_not_get_to_change_its_identity(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        c["claims"]["sender_id"] = "eve"
        with self.assertRaises(IdentityDenied):
            respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)

    def test_self_handshake_is_invalid(self):
        with self.assertRaisesRegex(IdentityDenied, "self-directed"):
            create_challenge(self.alice, "alice-laptop", now=T)

    def test_revocation_cannot_silently_unrevoke(self):
        self.alice_trust.revoke("bob-desktop")
        with self.assertRaises(IdentityDenied):
            self.alice_trust.enroll("bob-desktop", self.bob.public_key, operator_approved=True)

    def test_missing_peer_cannot_approve_handshake(self):
        isolated = PinnedPeers(Path(self.tmp.name) / "empty.sqlite3")
        self.addCleanup(isolated.close)
        c = create_challenge(self.alice, "bob-desktop", now=T)
        r = respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)
        with self.assertRaises(IdentityDenied):
            verify_response(self.alice, c, r, isolated, now=T + 2)

    def test_failed_verification_does_not_consume_valid_challenge(self):
        c = create_challenge(self.alice, "bob-desktop", now=T)
        r = respond_to_challenge(self.bob, c, self.bob_trust, now=T + 1)
        bad = copy.deepcopy(r)
        bad["signature_b64"] = "bad"
        with self.assertRaises(IdentityDenied):
            verify_response(self.alice, c, bad, self.alice_trust, now=T + 2)
        self.assertEqual(verify_response(self.alice, c, r, self.alice_trust, now=T + 3)["peer_id"], "bob-desktop")


if __name__ == "__main__":
    unittest.main()
