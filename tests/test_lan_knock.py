"""Gate B4d protocol negative controls and local-only integration fixture.

Loopback integration patches ONLY the RFC1918 address preflight for synthetic
127.0.0.1/127.0.0.2 test connections. Production code never permits 127/8.
"""

from __future__ import annotations

from contextlib import ExitStack
import copy
import hashlib
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from porchtalk.identity import DeviceIdentity, IdentityDenied, PinnedPeers
from porchtalk.lan_knock import (
    LanDenied, _json, _keys, _open, _seal, _sign, _verify_signed,
    knock_once, serve_one_knock,
)

FIXTURE_LOCAL = "127.0.0.1"
FIXTURE_PEER = "127.0.0.2"


class SignedSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="porchtalk-b4d-test-")
        self.addCleanup(self.temp.cleanup)
        self.alice = DeviceIdentity.generate_ephemeral("alice")
        self.bob = DeviceIdentity.generate_ephemeral("bob")
        self.trust_path = Path(self.temp.name) / "approved.sqlite3"
        self.trust = PinnedPeers(self.trust_path)
        self.addCleanup(self.trust.close)
        self.trust.enroll("bob", self.bob.public_key, operator_approved=True)

    def hello(self):
        return _sign(self.bob, X25519PrivateKey.generate(), "HELLO", "alice", None, now=1800000000)

    def verify(self, msg, now=1800000001):
        return _verify_signed(msg, expected_kind="HELLO", expected_sender="bob",
                              expected_recipient="alice", trusted=self.trust, now=now)

    def test_signed_hello_has_pinned_identity(self):
        claims, public = self.verify(self.hello())
        self.assertEqual(claims["sender_id"], "bob")
        self.assertIsNotNone(public)

    def test_modified_name_denied(self):
        msg = self.hello()
        msg["claims"]["sender_id"] = "alice"
        with self.assertRaises(LanDenied):
            self.verify(msg)

    def test_changed_session_public_key_denied(self):
        msg = self.hello()
        msg["claims"]["ephemeral_x25519_b64"] = _sign(
            self.alice, X25519PrivateKey.generate(), "HELLO", "bob", None, now=1800000000
        )["claims"]["ephemeral_x25519_b64"]
        with self.assertRaises(LanDenied):
            self.verify(msg)

    def test_expired_hello_denied(self):
        with self.assertRaisesRegex(LanDenied, "timestamp"):
            self.verify(self.hello(), now=1800000100)

    def test_future_hello_denied(self):
        with self.assertRaisesRegex(LanDenied, "timestamp"):
            self.verify(self.hello(), now=1799999989)

    def test_wrong_pinned_key_denied(self):
        stranger = DeviceIdentity.generate_ephemeral("bob")
        msg = _sign(stranger, X25519PrivateKey.generate(), "HELLO", "alice", None, now=1800000000)
        with self.assertRaisesRegex(LanDenied, "unauthenticated"):
            self.verify(msg)

    def test_added_field_denied(self):
        msg = self.hello()
        msg["claims"]["execute"] = "rm -rf"
        with self.assertRaisesRegex(LanDenied, "claim fields"):
            self.verify(msg)

    def test_hello_cannot_contain_reply_digest(self):
        msg = self.hello()
        msg["claims"]["in_reply_to_sha256"] = "0" * 64
        with self.assertRaises(LanDenied):
            self.verify(msg)

    def test_reply_must_be_to_exact_challenge(self):
        ch = self.hello()
        reply = _sign(self.bob, X25519PrivateKey.generate(), "REPLY", "alice",
                      hashlib.sha256(_json(ch)).hexdigest(), now=1800000000)
        # Swapping an unrelated challenge must fail application transcript binding.
        unrelated = self.hello()
        self.assertNotEqual(reply["claims"]["in_reply_to_sha256"], hashlib.sha256(_json(unrelated)).hexdigest())

    def test_ephemeral_keys_match_and_encrypted_proofs_authenticate(self):
        alice_eph, bob_eph = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        transcript = b"HELLO + REPLY"
        c2s, s2c = _keys(alice_eph, bob_eph.public_key(), transcript)
        other_c2s, other_s2c = _keys(bob_eph, alice_eph.public_key(), transcript)
        self.assertEqual((c2s, s2c), (other_c2s, other_s2c))
        frame = _seal(c2s, "FINISHED", {"role": "client"}, transcript, b"\0" * 11 + b"\x01")
        self.assertEqual(_open(frame, other_c2s, "FINISHED", transcript, b"\0" * 11 + b"\x01"), {"role": "client"})
        with self.assertRaises(LanDenied):
            _open(frame, other_c2s, "FINISHED", b"swapped transcript", b"\0" * 11 + b"\x01")

    def test_ciphertext_tamper_denied(self):
        c2s, _ = _keys(X25519PrivateKey.generate(), X25519PrivateKey.generate().public_key(), b"fixture")
        frame = _seal(c2s, "FINISHED", {"role": "client"}, b"fixture", b"\0" * 11 + b"\x01")
        frame["ciphertext_b64"] = frame["ciphertext_b64"][:-2] + "AA"
        with self.assertRaises(LanDenied):
            _open(frame, c2s, "FINISHED", b"fixture", b"\0" * 11 + b"\x01")

    def test_refuse_wrong_encrypted_message_kind(self):
        c2s, _ = _keys(X25519PrivateKey.generate(), X25519PrivateKey.generate().public_key(), b"fixture")
        frame = _seal(c2s, "FINISHED", {"role": "client"}, b"fixture", b"\0" * 11 + b"\x01")
        with self.assertRaisesRegex(LanDenied, "unexpected encrypted"):
            _open(frame, c2s, "ACK", b"fixture", b"\0" * 11 + b"\x01")

    def test_caller_auth_is_mandatory_and_no_sockets_opened(self):
        with patch("porchtalk.lan_knock.socket.socket", side_effect=AssertionError("socket created")):
            with self.assertRaises(LanDenied):
                serve_one_knock(identity=self.alice, peer_device_id="bob",
                               trust_db_path=self.trust_path, local_ipv4="192.168.1.10",
                               peer_ipv4="192.168.1.20", port=54321)
        with patch("porchtalk.lan_knock.socket.create_connection", side_effect=AssertionError("socket created")):
            with self.assertRaises(LanDenied):
                knock_once(identity=self.alice, peer_device_id="bob",
                           trust_db_path=self.trust_path, local_ipv4="192.168.1.10",
                           peer_ipv4="192.168.1.20", port=54321)

    def test_invalid_public_destination_denied_before_connect(self):
        with patch("porchtalk.lan_knock.socket.create_connection", side_effect=AssertionError("network attempted")):
            with self.assertRaises(LanDenied):
                knock_once(identity=self.alice, peer_device_id="bob",
                           trust_db_path=self.trust_path, local_ipv4="192.168.1.10",
                           peer_ipv4="8.8.8.8", port=54321, operator_approved=True)

    def test_revoked_key_denied_before_connect(self):
        self.trust.revoke("bob")
        with patch("porchtalk.lan_knock.socket.create_connection", side_effect=AssertionError("network attempted")):
            with self.assertRaises(LanDenied):
                knock_once(identity=self.alice, peer_device_id="bob",
                           trust_db_path=self.trust_path, local_ipv4="192.168.1.10",
                           peer_ipv4="192.168.1.20", port=54321, operator_approved=True)


class LoopbackIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="porchtalk-lanloop-")
        self.addCleanup(self.temp.cleanup)
        self.alice = DeviceIdentity.generate_ephemeral("alice")
        self.bob = DeviceIdentity.generate_ephemeral("bob")
        self.a_db = Path(self.temp.name) / "a.sqlite3"
        self.b_db = Path(self.temp.name) / "b.sqlite3"
        for path, friend in [(self.a_db, self.bob), (self.b_db, self.alice)]:
            t = PinnedPeers(path)
            try:
                t.enroll(friend.device_id, friend.public_key, operator_approved=True)
            finally:
                t.close()
            # B4c pairing creates owner-only SQLite trust files. Reproduce
            # its permissions here rather than weakening production checks.
            if os.name == "posix":
                os.chmod(path, 0o600)

    def port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((FIXTURE_PEER, 0))
            return sock.getsockname()[1]

    def run_exchange(self, *, server_identity=None, client_identity=None):
        server_id = self.bob if server_identity is None else server_identity
        client_id = self.alice if client_identity is None else client_identity
        port = self.port()
        output = {}
        errors = []
        ready = threading.Event()
        # Deliberate *test-only* exception: preflight disallows 127/8 in production.
        with patch("porchtalk.lan_knock.preflight_two_pc_lab"):
            def server():
                ready.set()
                try:
                    output["server"] = serve_one_knock(
                        identity=server_id, peer_device_id="alice", trust_db_path=self.b_db,
                        local_ipv4=FIXTURE_PEER, peer_ipv4=FIXTURE_LOCAL, port=port,
                        timeout_seconds=2, operator_approved=True)
                except BaseException as exc:
                    errors.append(exc)

            worker = threading.Thread(target=server, daemon=True)
            worker.start()
            ready.wait(1)
            # A bound listener is usually ready quickly, but retry once if not.
            # The client timeout remains short; this is not a general network probe.
            time.sleep(0.05)
            try:
                output["client"] = knock_once(
                    identity=client_id, peer_device_id="bob", trust_db_path=self.a_db,
                    local_ipv4=FIXTURE_LOCAL, peer_ipv4=FIXTURE_PEER, port=port,
                    timeout_seconds=2, operator_approved=True)
            except BaseException as exc:
                errors.append(exc)
            worker.join(3)
            if worker.is_alive():
                raise AssertionError("one-shot server should have terminated")
        return output, errors

    @unittest.skipUnless(os.name == "posix", "Linux loopback fixture uses 127.0.0.2")
    def test_mutually_pinned_peers_complete_one_encrypted_knock(self):
        result, errors = self.run_exchange()
        self.assertEqual(errors, [])
        self.assertEqual(result["server"]["transcript_sha256"], result["client"]["transcript_sha256"])
        for receipt in result.values():
            self.assertEqual(receipt["status"], "LAN_ONE_SHOT_ENCRYPTED_KNOCK_PASS")
            self.assertTrue(receipt["channel_encrypted"])
            self.assertFalse(receipt["compute_authorized"])
            self.assertFalse(receipt["route_authorized"])

    @unittest.skipUnless(os.name == "posix", "Linux loopback fixture uses 127.0.0.2")
    def test_wrong_client_key_cannot_complete(self):
        impostor = DeviceIdentity.generate_ephemeral("alice")
        result, errors = self.run_exchange(client_identity=impostor)
        self.assertNotIn("client", result)
        self.assertNotIn("server", result)
        self.assertTrue(errors)

    @unittest.skipUnless(os.name == "posix", "Linux loopback fixture uses 127.0.0.2")
    def test_wrong_server_key_cannot_complete(self):
        impostor = DeviceIdentity.generate_ephemeral("bob")
        result, errors = self.run_exchange(server_identity=impostor)
        self.assertNotIn("client", result)
        self.assertNotIn("server", result)
        self.assertTrue(errors)

    @unittest.skipUnless(os.name == "posix", "Linux loopback fixture uses 127.0.0.2")
    def test_revoked_peer_cannot_complete(self):
        trust = PinnedPeers(self.b_db)
        trust.revoke("alice")
        trust.close()
        result, errors = self.run_exchange()
        self.assertNotIn("client", result)
        self.assertNotIn("server", result)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
