"""Gate B4d interactive LAN operator CLI tests; no external network traffic."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import patch

from porchtalk.lan_cli import main


class LANCLISafetyTests(unittest.TestCase):
    def setUp(self):
        self.args = [
            "serve", "--vault", "nonexistent.porchkey",
            "--trust-db", "nonexistent.sqlite3",
            "--local-ip", "192.168.1.10",
            "--peer-ip", "192.168.1.20",
            "--peer-id", "neighbor", "--port", "54321",
        ]

    def run_cli(self, answers=(), tty=True, arguments=None):
        out, err = StringIO(), StringIO()
        with patch("porchtalk.lan_cli.sys.stdin") as stdin, \
             patch("builtins.input", side_effect=answers), \
             patch("porchtalk.lan_cli.getpass.getpass", return_value="should-never-need-password"), \
             redirect_stdout(out), redirect_stderr(err):
            stdin.isatty.return_value = tty
            code = main(self.args if arguments is None else arguments)
        return code, out.getvalue(), err.getvalue()

    def test_help_is_not_a_listener(self):
        with patch("porchtalk.lan_cli.serve_one_knock", side_effect=AssertionError("server called")):
            with self.assertRaises(SystemExit) as caught:
                main(["serve", "--help"])
            self.assertEqual(caught.exception.code, 0)

    def test_noninteractive_mode_denied(self):
        with patch("porchtalk.lan_cli.serve_one_knock", side_effect=AssertionError("listener called")):
            code, _, err = self.run_cli(tty=False)
        self.assertEqual(code, 2)
        self.assertIn("DENIED", err)

    def test_wrong_exact_listener_phrase_denied(self):
        with patch("porchtalk.lan_cli.serve_one_knock", side_effect=AssertionError("listener called")):
            code, _, err = self.run_cli(answers=["YES"])
        self.assertEqual(code, 2)
        self.assertIn("DENIED", err)

    def test_correct_approval_only_then_requests_passphrase(self):
        phrase = "LISTEN 192.168.1.10:54321 PEER neighbor"
        with patch("porchtalk.lan_cli.unlock_encrypted_vault",
                   side_effect=ValueError("synthetic vault unlock refused")) as unlock, \
             patch("porchtalk.lan_cli.serve_one_knock", side_effect=AssertionError("listener called")):
            code, _, err = self.run_cli(answers=[phrase])
        self.assertEqual(code, 2)
        self.assertEqual(unlock.call_count, 1)
        self.assertIn("DENIED", err)

    def test_invalid_ip_not_allowed_by_cli_after_approval(self):
        phrase = "CONNECT 8.8.8.8:54321 PEER neighbor"
        client_args = [
            "knock", "--vault", "no.porchkey", "--trust-db", "no.sqlite3",
            "--local-ip", "192.168.1.10", "--peer-ip", "8.8.8.8",
            "--peer-id", "neighbor", "--port", "54321",
        ]
        with patch("porchtalk.lan_cli.unlock_encrypted_vault") as unlock, \
             patch("porchtalk.lan_cli.knock_once", side_effect=AssertionError("network called")):
            from porchtalk.identity import DeviceIdentity
            unlock.return_value = DeviceIdentity.generate_ephemeral("my-pc")
            code, _, error = self.run_cli(answers=[phrase], arguments=client_args)
        self.assertEqual(code, 2)
        self.assertIn("DENIED", error)

    def test_no_automatic_approval_switch(self):
        with self.assertRaises(SystemExit):
            main(self.args + ["--yes"])

    def test_no_private_key_or_passphrase_arg(self):
        with self.assertRaises(SystemExit):
            main(self.args + ["--password", "do-not-record-secrets"])

    def test_missing_parameter_does_not_start_network(self):
        with self.assertRaises(SystemExit):
            main(["serve", "--local-ip", "192.168.1.10"])


if __name__ == "__main__":
    unittest.main()
