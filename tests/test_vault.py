"""Offline identity vault negative controls. No LAN sockets, no remote tasks."""

import base64
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from porchtalk.enrollment import export_public_card, verify_public_card
from porchtalk.identity import (
    DeviceIdentity, IdentityDenied, PinnedPeers, create_challenge,
    respond_to_challenge, verify_response,
)
from porchtalk.vault import create_encrypted_vault, unlock_encrypted_vault

PASSWORD = "correct horse stable porch lantern!"


class EncryptedIdentityVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="porchtalk-vault-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vault = self.root / "identity.porchkey"
        self.identity = DeviceIdentity.generate_ephemeral("main-pc")

    def create(self):
        return create_encrypted_vault(self.vault, self.identity, passphrase=PASSWORD)

    def unlock(self, password=PASSWORD):
        return unlock_encrypted_vault(self.vault, passphrase=password)

    def test_saved_vault_roundtrip_preserves_public_identity(self):
        expected = self.identity.fingerprint
        self.assertEqual(self.create(), expected)
        restored = self.unlock()
        self.assertEqual(restored.device_id, "main-pc")
        self.assertEqual(restored.fingerprint, expected)

    def test_private_seed_is_never_written_in_plaintext(self):
        self.create()
        blob = self.vault.read_bytes()
        self.assertNotIn(b"BEGIN PRIVATE KEY", blob)
        self.assertNotIn(b"PRIVATE KEY", blob)
        self.assertNotIn(PASSWORD.encode(), blob)
        self.assertIn(b"AES-256-GCM", blob)
        self.assertIn(b"scrypt", blob)

    @unittest.skipUnless(os.name == "posix", "POSIX file mode test")
    def test_owner_only_permissions(self):
        self.create()
        self.assertEqual(stat.S_IMODE(self.vault.stat().st_mode), 0o600)

    def test_create_refuses_overwrite(self):
        self.create()
        original = self.vault.read_bytes()
        with self.assertRaisesRegex(IdentityDenied, "already exists"):
            self.create()
        self.assertEqual(self.vault.read_bytes(), original)

    def test_wrong_password_does_not_unlock(self):
        self.create()
        with self.assertRaisesRegex(IdentityDenied, "unlock denied"):
            self.unlock("wrong stable horse lantern porch!")

    def test_short_password_denied(self):
        with self.assertRaisesRegex(IdentityDenied, "14 characters"):
            create_encrypted_vault(self.vault, self.identity, passphrase="123")
        self.assertFalse(self.vault.exists())

    def test_nonstring_password_denied(self):
        with self.assertRaises(IdentityDenied):
            create_encrypted_vault(self.vault, self.identity, passphrase=None)

    def _alter(self, action):
        document = json.loads(self.vault.read_text(encoding="ascii"))
        action(document)
        self.vault.write_text(json.dumps(document), encoding="ascii")

    def test_ciphertext_tampering_denied(self):
        self.create()
        def modify(d):
            raw = bytearray(base64.b64decode(d["ciphertext_b64"]))
            raw[0] ^= 1
            d["ciphertext_b64"] = base64.b64encode(raw).decode("ascii")
        self._alter(modify)
        with self.assertRaises(IdentityDenied):
            self.unlock()

    def test_public_key_tampering_denied(self):
        self.create()
        other = DeviceIdentity.generate_ephemeral("main-pc")
        pub = export_public_card(other)["claims"]["public_key_b64"]
        self._alter(lambda d: d["metadata"].update(public_key_b64=pub))
        with self.assertRaises(IdentityDenied):
            self.unlock()

    def test_device_name_tampering_denied(self):
        self.create()
        self._alter(lambda d: d["metadata"].update(device_id="attacker"))
        with self.assertRaises(IdentityDenied):
            self.unlock()

    def test_kdf_downgrade_denied_before_work(self):
        self.create()
        self._alter(lambda d: d["metadata"]["kdf"].update(n=2))
        with self.assertRaisesRegex(IdentityDenied, "KDF"):
            self.unlock()

    def test_additional_format_fields_denied(self):
        self.create()
        self._alter(lambda d: d.update(run_shell=True))
        with self.assertRaisesRegex(IdentityDenied, "envelope"):
            self.unlock()

    def test_duplicate_json_key_denied(self):
        self.create()
        self.vault.write_bytes(b'{"metadata":{},"metadata":{},"ciphertext_b64":"fake"}')
        with self.assertRaisesRegex(IdentityDenied, "duplicate"):
            self.unlock()

    def test_oversized_file_denied_before_parsing(self):
        self.create()
        self.vault.write_bytes(b"z" * 9000)
        with self.assertRaisesRegex(IdentityDenied, "filesystem metadata"):
            self.unlock()

    @unittest.skipUnless(os.name == "posix", "POSIX permission check")
    def test_world_readable_vault_denied(self):
        self.create()
        os.chmod(self.vault, 0o644)
        with self.assertRaisesRegex(IdentityDenied, "permissions"):
            self.unlock()

    def test_symlink_as_key_path_denied(self):
        self.create()
        link = self.root / "link.porchkey"
        try:
            link.symlink_to(self.vault)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")
        with self.assertRaisesRegex(IdentityDenied, "unsafe"):
            unlock_encrypted_vault(link, passphrase=PASSWORD)

    def test_directory_does_not_exist_denied(self):
        with self.assertRaisesRegex(IdentityDenied, "does not exist"):
            create_encrypted_vault(self.root / "missing" / "a.porchkey", self.identity, passphrase=PASSWORD)

    def test_two_persisted_keys_can_mutually_prove_identity_offline(self):
        bob = DeviceIdentity.generate_ephemeral("storage-pc")
        bob_vault = self.root / "bob.porchkey"
        create_encrypted_vault(self.vault, self.identity, passphrase=PASSWORD)
        create_encrypted_vault(bob_vault, bob, passphrase=PASSWORD)
        # Intentionally drop the generated objects; reload both encrypted vaults.
        alice_loaded = self.unlock()
        bob_loaded = unlock_encrypted_vault(bob_vault, passphrase=PASSWORD)
        a_db = PinnedPeers(self.root / "a.sqlite3")
        b_db = PinnedPeers(self.root / "b.sqlite3")
        try:
            a_db.enroll(bob_loaded.device_id, bob_loaded.public_key, operator_approved=True)
            b_db.enroll(alice_loaded.device_id, alice_loaded.public_key, operator_approved=True)
            challenge = create_challenge(alice_loaded, bob_loaded.device_id)
            answer = respond_to_challenge(bob_loaded, challenge, b_db)
            receipt = verify_response(alice_loaded, challenge, answer, a_db)
            self.assertEqual(receipt["peer_id"], "storage-pc")
            self.assertEqual(verify_public_card(export_public_card(alice_loaded))[2], alice_loaded.fingerprint)
        finally:
            a_db.close()
            b_db.close()

    def test_key_file_not_written_for_public_card(self):
        self.create()
        loaded = self.unlock()
        before = set(self.root.iterdir())
        card = export_public_card(loaded)
        self.assertEqual(verify_public_card(card)[2], loaded.fingerprint)
        self.assertEqual(set(self.root.iterdir()), before)


if __name__ == "__main__":
    unittest.main()
