"""No-argument-secret CLI regression: prompts only, public card output only."""

import contextlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from porchtalk.vault_cli import main

PASSWORD = "rainbow porch windows latticework!"


class CLIIdentityVaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="porchtalk-cli-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.vault = self.root / "device.porchkey"
        self.card = self.root / "public-card.json"

    def run_cli(self, args, prompts=()):
        out, err = StringIO(), StringIO()
        with patch("porchtalk.vault_cli.getpass.getpass", side_effect=prompts), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_init_export_and_verify_public_card(self):
        code, output, _ = self.run_cli(
            ["init", "--device-id", "main-pc", "--vault", str(self.vault)],
            prompts=[PASSWORD, PASSWORD],
        )
        self.assertEqual(code, 0)
        self.assertTrue(self.vault.exists())
        self.assertIn("ENCRYPTED_VAULT_CREATED", output)
        self.assertNotIn(PASSWORD, output)
        code, output, _ = self.run_cli(
            ["export-card", "--vault", str(self.vault), "--out", str(self.card)],
            prompts=[PASSWORD],
        )
        self.assertEqual(code, 0)
        self.assertTrue(self.card.exists())
        self.assertNotIn("PRIVATE", self.card.read_text(encoding="utf-8"))
        self.assertNotIn(PASSWORD, self.card.read_text(encoding="utf-8"))
        code, output, _ = self.run_cli(["verify-card", "--card", str(self.card)])
        self.assertEqual(code, 0)
        self.assertIn("UNTRUSTED_CARD_CLAIM", output)

    def test_mismatching_password_confirmation_refused(self):
        code, _, error = self.run_cli(
            ["init", "--device-id", "main-pc", "--vault", str(self.vault)],
            prompts=[PASSWORD, "mismatching-porch-passphrase!!"],
        )
        self.assertEqual(code, 2)
        self.assertFalse(self.vault.exists())
        self.assertIn("DENIED", error)

    def test_password_never_passed_in_command_flags(self):
        with self.assertRaises(SystemExit):
            main(["init", "--device-id", "main-pc", "--vault", str(self.vault), "--password", PASSWORD])

    def test_init_cannot_replace_existing_vault(self):
        self.run_cli(["init", "--device-id", "main-pc", "--vault", str(self.vault)],
                     prompts=[PASSWORD, PASSWORD])
        before = self.vault.read_bytes()
        code, _, error = self.run_cli(["init", "--device-id", "main-pc", "--vault", str(self.vault)])
        self.assertEqual(code, 2)
        self.assertEqual(self.vault.read_bytes(), before)
        self.assertIn("already exists", error)

    def test_failed_unlock_cannot_export_public_card(self):
        self.run_cli(["init", "--device-id", "main-pc", "--vault", str(self.vault)],
                     prompts=[PASSWORD, PASSWORD])
        code, _, err = self.run_cli(["export-card", "--vault", str(self.vault), "--out", str(self.card)],
                                    prompts=["incorrect porch passphrase very"])
        self.assertEqual(code, 2)
        self.assertFalse(self.card.exists())
        self.assertIn("DENIED", err)

    def test_public_card_cannot_be_overwritten(self):
        self.run_cli(["init", "--device-id", "main-pc", "--vault", str(self.vault)],
                     prompts=[PASSWORD, PASSWORD])
        self.run_cli(["export-card", "--vault", str(self.vault), "--out", str(self.card)],
                     prompts=[PASSWORD])
        original = self.card.read_bytes()
        code, _, error = self.run_cli(["export-card", "--vault", str(self.vault), "--out", str(self.card)],
                                      prompts=[PASSWORD])
        self.assertEqual(code, 2)
        self.assertEqual(self.card.read_bytes(), original)
        self.assertIn("DENIED", error)

    def test_corrupted_card_denied(self):
        self.card.write_text(json.dumps({"claims": {"fake": True}}), encoding="utf-8")
        code, _, error = self.run_cli(["verify-card", "--card", str(self.card)])
        self.assertEqual(code, 2)
        self.assertIn("DENIED", error)


if __name__ == "__main__":
    unittest.main()
