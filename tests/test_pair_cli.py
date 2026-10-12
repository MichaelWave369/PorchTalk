"""Offline public-card pairing ceremony tests, including negative controls."""

from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from porchtalk.enrollment import export_public_card
from porchtalk.identity import DeviceIdentity, IdentityDenied, PinnedPeers
from porchtalk.pair_cli import (
    checked_trust_db_path, enroll_interactively, inspect_trust, main,
    read_public_card, revoke_interactively,
)


class PairingCeremonyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="porchtalk-pair-test-")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.private = self.root / "private-trust"
        self.private.mkdir(mode=0o700)
        self.card_path = self.root / "peer-public.json"
        self.db_path = self.private / "approved.sqlite3"
        self.bob = DeviceIdentity.generate_ephemeral("storage-pc")
        self.card = export_public_card(self.bob)
        self.card_path.write_text(json.dumps(self.card), encoding="utf-8")

    def run_interactive(self, function, answers, **kwargs):
        with patch("porchtalk.pair_cli.sys.stdin") as stream, patch("builtins.input", side_effect=answers):
            stream.isatty.return_value = True
            return function(**kwargs)

    def approve(self, answers=None):
        return self.run_interactive(
            enroll_interactively,
            [self.bob.fingerprint, "ENROLL storage-pc"] if answers is None else answers,
            card_path=self.card_path, trust_db_path=self.db_path, expected_device_id="storage-pc",
        )

    def test_successful_pairing_pins_exact_public_key(self):
        receipt = self.approve()
        self.assertEqual(receipt["status"], "PUBLIC_KEY_PINNED_LOCAL_ONLY")
        self.assertFalse(receipt["compute_authorized"])
        db = PinnedPeers(self.db_path)
        try:
            self.assertEqual(db.approved_key("storage-pc").public_bytes_raw(), self.bob.public_key.public_bytes_raw())
        finally:
            db.close()

    def test_wrong_out_of_band_fingerprint_refuses_db_creation(self):
        with self.assertRaisesRegex(IdentityDenied, "fingerprint mismatch"):
            self.approve(["0" * 64, "ENROLL storage-pc"])
        self.assertFalse(self.db_path.exists())

    def test_wrong_confirmation_refuses_db_creation(self):
        with self.assertRaisesRegex(IdentityDenied, "approval"):
            self.approve([self.bob.fingerprint, "ENROLL another-pc"])
        self.assertFalse(self.db_path.exists())

    def test_wrong_expected_id_refuses_without_prompts(self):
        with patch("builtins.input") as prompt:
            with self.assertRaisesRegex(IdentityDenied, "unexpected device"):
                self.run_interactive(
                    enroll_interactively, [], card_path=self.card_path,
                    trust_db_path=self.db_path, expected_device_id="impostor",
                )
            prompt.assert_not_called()
        self.assertFalse(self.db_path.exists())

    def test_noninteractive_input_denied_and_no_db(self):
        with patch("porchtalk.pair_cli.sys.stdin") as stream:
            stream.isatty.return_value = False
            with self.assertRaisesRegex(IdentityDenied, "interactive terminal"):
                enroll_interactively(card_path=self.card_path, trust_db_path=self.db_path, expected_device_id="storage-pc")
        self.assertFalse(self.db_path.exists())

    def test_duplicate_card_json_keys_denied(self):
        text = json.dumps(self.card)
        self.card_path.write_text(text[:-1] + ', "claims": {} }', encoding="utf-8")
        with self.assertRaisesRegex(IdentityDenied, "duplicate"):
            read_public_card(self.card_path)

    def test_untrusted_tampered_card_refused(self):
        self.card["claims"]["device_id"] = "impostor"
        self.card_path.write_text(json.dumps(self.card), encoding="utf-8")
        with self.assertRaises(IdentityDenied):
            read_public_card(self.card_path)

    def test_untrusted_card_with_extra_fields_denied(self):
        self.card["dangerous"] = "run"
        self.card_path.write_text(json.dumps(self.card), encoding="utf-8")
        with self.assertRaises(IdentityDenied):
            read_public_card(self.card_path)

    def test_oversized_card_denied(self):
        self.card_path.write_bytes(b"a" * 9000)
        with self.assertRaisesRegex(IdentityDenied, "oversized"):
            read_public_card(self.card_path)

    def test_card_symlink_denied(self):
        link = self.root / "link.json"
        try:
            link.symlink_to(self.card_path)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(IdentityDenied, "non-symlink"):
            read_public_card(link)

    def test_repeat_pairing_cannot_silently_replace_key(self):
        self.approve()
        with self.assertRaisesRegex(IdentityDenied, "rotation"):
            self.approve()

    def test_local_inspection_exposes_only_public_fingerprints(self):
        self.approve()
        inspected = inspect_trust(trust_db_path=self.db_path)
        self.assertEqual(len(inspected["peers"]), 1)
        self.assertEqual(inspected["peers"][0]["fingerprint_sha256"], self.bob.fingerprint)
        self.assertNotIn("private_key", json.dumps(inspected))

    def test_revocation_requires_exact_human_confirmation(self):
        self.approve()
        with self.assertRaisesRegex(IdentityDenied, "confirmation"):
            self.run_interactive(revoke_interactively, ["NO"], trust_db_path=self.db_path, device_id="storage-pc")
        db = PinnedPeers(self.db_path)
        try:
            self.assertIsNotNone(db.approved_key("storage-pc"))
        finally:
            db.close()
        result = self.run_interactive(revoke_interactively, ["REVOKE storage-pc"],
                                      trust_db_path=self.db_path, device_id="storage-pc")
        self.assertEqual(result["status"], "LOCAL_TRUST_REVOKED")
        db = PinnedPeers(self.db_path)
        try:
            with self.assertRaises(IdentityDenied):
                db.approved_key("storage-pc")
        finally:
            db.close()

    def test_revoke_does_not_create_missing_db(self):
        with self.assertRaisesRegex(IdentityDenied, "not found"):
            self.run_interactive(revoke_interactively, ["REVOKE storage-pc"],
                                  trust_db_path=self.db_path, device_id="storage-pc")
        self.assertFalse(self.db_path.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX directory permission policy")
    def test_world_readable_trust_directory_denied(self):
        self.private.chmod(0o755)
        with self.assertRaisesRegex(IdentityDenied, "private"):
            checked_trust_db_path(self.db_path)

    @unittest.skipUnless(os.name == "posix", "POSIX file permission policy")
    def test_trust_db_permissions_are_0600(self):
        self.approve()
        self.assertEqual(stat.S_IMODE(self.db_path.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX file permission policy")
    def test_world_readable_trust_db_denied(self):
        self.approve()
        self.db_path.chmod(0o644)
        with self.assertRaisesRegex(IdentityDenied, "trust database file must be private"):
            checked_trust_db_path(self.db_path)

    def test_symlinked_trust_file_denied(self):
        target = self.private / "other.sqlite3"
        target.write_bytes(b"")
        link = self.private / "symlink.sqlite3"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(IdentityDenied):
            checked_trust_db_path(link)

    def test_symlinked_trust_directory_denied(self):
        link = self.root / "symlink-private"
        try:
            link.symlink_to(self.private, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(IdentityDenied):
            checked_trust_db_path(link / "trust.sqlite3")

    def test_revoke_requires_tty(self):
        self.approve()
        with patch("porchtalk.pair_cli.sys.stdin") as stream:
            stream.isatty.return_value = False
            with self.assertRaisesRegex(IdentityDenied, "interactive terminal"):
                revoke_interactively(trust_db_path=self.db_path, device_id="storage-pc")

    def test_cli_read_only_inspect(self):
        out = StringIO()
        with redirect_stdout(out):
            status = main(["inspect-card", "--card", str(self.card_path)])
        self.assertEqual(status, 0)
        self.assertIn("UNTRUSTED_PUBLIC_CARD_VALID", out.getvalue())
        self.assertFalse(self.db_path.exists())

    def test_cli_rejects_yes_bypass(self):
        with self.assertRaises(SystemExit):
            main(["enroll", "--card", str(self.card_path), "--trust-db", str(self.db_path),
                  "--expected-id", "storage-pc", "--yes"])

    def test_cli_enroll_and_list(self):
        out = StringIO()
        with redirect_stdout(out):
            with patch("porchtalk.pair_cli.sys.stdin") as stream, patch(
                    "builtins.input", side_effect=[self.bob.fingerprint, "ENROLL storage-pc"]):
                stream.isatty.return_value = True
                status = main(["enroll", "--card", str(self.card_path), "--trust-db", str(self.db_path),
                               "--expected-id", "storage-pc"])
        self.assertEqual(status, 0)
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["list", "--trust-db", str(self.db_path)]), 0)
        self.assertIn(self.bob.fingerprint, output.getvalue())

    def test_corrupted_local_database_is_denied_cleanly(self):
        self.db_path.write_bytes(b"not a sqlite database")
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["list", "--trust-db", str(self.db_path)])
        self.assertEqual(code, 2)
        self.assertIn("DENIED", stderr.getvalue())

    def test_trust_inspection_creates_no_network_session(self):
        self.approve()
        with patch("socket.create_connection", side_effect=AssertionError("No network allowed")):
            result = inspect_trust(trust_db_path=self.db_path)
        self.assertEqual(result["status"], "LOCAL_TRUST_INSPECTION_ONLY")

    def test_missing_directory_fails_closed(self):
        missing = self.root / "not-created" / "peers.sqlite3"
        with self.assertRaisesRegex(IdentityDenied, "does not exist"):
            checked_trust_db_path(missing)


if __name__ == "__main__":
    unittest.main()
