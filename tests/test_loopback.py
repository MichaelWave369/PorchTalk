"""Real TCP/TLS 1.3 loopback-only handshake tests. Never binds to LAN."""

import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from porchtalk.identity import DeviceIdentity, PinnedPeers
from porchtalk.loopback import FirstKnockDenied, _HOST, _read_frame, _write_frame, run_loopback_first_knock


class LoopbackFirstKnockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.alice = DeviceIdentity.generate_ephemeral("alice-laptop")
        self.bob = DeviceIdentity.generate_ephemeral("bob-desktop")
        self.alice_db = Path(self.temp.name) / "alice.sqlite3"
        self.bob_db = Path(self.temp.name) / "bob.sqlite3"
        self.enroll(self.alice_db, self.bob)
        self.enroll(self.bob_db, self.alice)

    def enroll(self, path, identity):
        peers = PinnedPeers(path)
        try:
            peers.enroll(identity.device_id, identity.public_key, operator_approved=True)
        finally:
            peers.close()

    def knock(self, **changes):
        args = dict(alice=self.alice, bob=self.bob,
                    alice_trust_path=self.alice_db, bob_trust_path=self.bob_db)
        args.update(changes)
        return run_loopback_first_knock(**args)

    def test_first_knock_mutual_tls_loopback_only(self):
        receipt = self.knock()
        self.assertEqual(receipt["status"], "LOOPBACK_FIRST_KNOCK_PASS")
        self.assertEqual(receipt["tls_version"], "TLSv1.3")
        self.assertEqual(receipt["peer_id"], "bob-desktop")
        self.assertEqual(receipt["peer_fingerprint"], self.bob.fingerprint)
        self.assertTrue(receipt["verified_challenge"])
        self.assertFalse(receipt["route_authorized"])
        self.assertFalse(receipt["compute_authorized"])
        self.assertEqual(receipt["network_scope"], "127.0.0.1_ONLY")

    def test_repeat_runs_use_fresh_challenges(self):
        self.knock()
        self.knock()

    def test_revoked_bob_denied(self):
        db = PinnedPeers(self.alice_db)
        try:
            db.revoke("bob-desktop")
        finally:
            db.close()
        with self.assertRaises(FirstKnockDenied):
            self.knock()

    def test_revoked_alice_denied(self):
        db = PinnedPeers(self.bob_db)
        try:
            db.revoke("alice-laptop")
        finally:
            db.close()
        with self.assertRaises(FirstKnockDenied):
            self.knock()

    def test_unapproved_server_denied(self):
        missing = Path(self.temp.name) / "missing.sqlite3"
        with self.assertRaises(FirstKnockDenied):
            self.knock(alice_trust_path=missing)

    def test_unapproved_client_denied(self):
        missing = Path(self.temp.name) / "missing.sqlite3"
        with self.assertRaises(FirstKnockDenied):
            self.knock(bob_trust_path=missing)

    def test_wrong_server_key_denied(self):
        impostor = DeviceIdentity.generate_ephemeral("bob-desktop")
        with self.assertRaises(FirstKnockDenied):
            self.knock(bob=impostor)

    def test_wrong_client_key_denied(self):
        impostor = DeviceIdentity.generate_ephemeral("alice-laptop")
        with self.assertRaises(FirstKnockDenied):
            self.knock(alice=impostor)

    def test_reject_same_identity(self):
        with self.assertRaises(FirstKnockDenied):
            self.knock(bob=self.alice)

    def test_timeout_bounds(self):
        for value in (0, -2, 11, True, "5"):
            with self.subTest(value=value), self.assertRaises(FirstKnockDenied):
                self.knock(timeout_seconds=value)

    def test_loopback_address_hardcoded(self):
        self.assertEqual(_HOST, "127.0.0.1")

    def test_fragmented_length_frame_round_trip(self):
        left, right = socket.socketpair()
        try:
            _write_frame(left, {"hello": "porch"})
            self.assertEqual(_read_frame(right), {"hello": "porch"})
        finally:
            left.close()
            right.close()

    def test_oversized_length_denied_before_body(self):
        left, right = socket.socketpair()
        try:
            left.sendall(struct.pack("!I", 4097))
            with self.assertRaisesRegex(FirstKnockDenied, "limit"):
                _read_frame(right)
        finally:
            left.close()
            right.close()

    def test_empty_frame_denied(self):
        left, right = socket.socketpair()
        try:
            left.sendall(struct.pack("!I", 0))
            with self.assertRaisesRegex(FirstKnockDenied, "empty"):
                _read_frame(right)
        finally:
            left.close()
            right.close()

    def test_malformed_json_denied(self):
        left, right = socket.socketpair()
        try:
            left.sendall(struct.pack("!I", 3) + b"bad")
            with self.assertRaisesRegex(FirstKnockDenied, "malformed"):
                _read_frame(right)
        finally:
            left.close()
            right.close()

    def test_non_object_frame_denied(self):
        left, right = socket.socketpair()
        try:
            payload = json.dumps(["NOT_A_HANDSHAKE"]).encode()
            left.sendall(struct.pack("!I", len(payload)) + payload)
            with self.assertRaisesRegex(FirstKnockDenied, "object"):
                _read_frame(right)
        finally:
            left.close()
            right.close()

    def test_truncated_frame_denied(self):
        left, right = socket.socketpair()
        try:
            left.sendall(struct.pack("!I", 8) + b"tiny")
            left.close()
            with self.assertRaisesRegex(FirstKnockDenied, "closed"):
                _read_frame(right)
        finally:
            right.close()

    def test_outbound_limit_denied(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaises(FirstKnockDenied):
                _write_frame(left, {"payload": "x" * 5000})
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
