"""Offline B4e evidence reconciliation. Does not require any network."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from porchtalk.evidence import EvidenceDenied, compare_two_receipts, inspect_receipt, read_receipt
from porchtalk.evidence_cli import main
from porchtalk.identity import DeviceIdentity
from porchtalk.lan_knock import _receipt


class EvidenceReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="porchtalk-evidence-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.a = DeviceIdentity.generate_ephemeral("main-pc")
        self.b = DeviceIdentity.generate_ephemeral("storage-pc")
        transcript = b"synthetic test transcript, NOT independently observed"
        self.left = _receipt(self.a, self.b.device_id, self.b.fingerprint, transcript)
        self.right = _receipt(self.b, self.a.device_id, self.a.fingerprint, transcript)

    def compare(self):
        return compare_two_receipts(self.left, self.right)

    def test_matching_two_receipts_consistent_but_not_attested(self):
        result = self.compare()
        self.assertEqual(result["status"], "SELF_REPORTED_RECEIPTS_CONSISTENT")
        self.assertFalse(result["real_hardware_verified"])
        self.assertFalse(result["independently_attested"])
        self.assertFalse(result["session_authorized_for_compute"])

    def test_swapped_inputs_still_compare(self):
        self.assertEqual(compare_two_receipts(self.right, self.left)["status"], "SELF_REPORTED_RECEIPTS_CONSISTENT")

    def test_transcript_mismatch_denied(self):
        self.right["transcript_sha256"] = "0" * 64
        with self.assertRaisesRegex(EvidenceDenied, "transcript"):
            self.compare()

    def test_wrong_peer_key_denied(self):
        self.right["peer_fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(EvidenceDenied, "fingerprints"):
            self.compare()

    def test_wrong_device_name_denied(self):
        self.right["local_device_id"] = "other"
        with self.assertRaisesRegex(EvidenceDenied, "directions"):
            self.compare()

    def test_compute_authorized_is_never_accepted(self):
        self.left["compute_authorized"] = True
        with self.assertRaises(EvidenceDenied):
            self.compare()

    def test_private_identity_metadata_flag_required(self):
        self.left["handshake_identity_metadata_visible"] = False
        with self.assertRaises(EvidenceDenied):
            self.compare()

    def test_full_critical_warnings_required(self):
        self.left["warnings"] = ["NOT_SECURITY_AUDITED"]
        with self.assertRaises(EvidenceDenied):
            self.compare()

    def test_invalid_extra_request_field_denied(self):
        self.right["remote_command"] = "something"
        with self.assertRaisesRegex(EvidenceDenied, "fields"):
            self.compare()

    def test_forged_status_denied(self):
        self.left["status"] = "PRODUCTION_READY"
        with self.assertRaises(EvidenceDenied):
            self.compare()

    def test_read_two_valid_json_receipts(self):
        a_file = self.root / "a.json"
        b_file = self.root / "b.json"
        a_file.write_text(json.dumps(self.left), encoding="utf-8")
        b_file.write_text(json.dumps(self.right), encoding="utf-8")
        self.assertEqual(compare_two_receipts(read_receipt(a_file), read_receipt(b_file))["status"],
                         "SELF_REPORTED_RECEIPTS_CONSISTENT")
        self.assertEqual(main([str(a_file), str(b_file)]), 0)

    def test_duplicate_json_property_is_denied(self):
        file = self.root / "duplicate.json"
        file.write_text('{"status":"one","status":"two"}', encoding="utf-8")
        with self.assertRaisesRegex(EvidenceDenied, "duplicate"):
            read_receipt(file)

    def test_oversized_json_is_denied(self):
        file = self.root / "oversized.json"
        file.write_bytes(b"x" * 10000)
        with self.assertRaisesRegex(EvidenceDenied, "oversized"):
            read_receipt(file)

    def test_symlink_receipt_is_denied(self):
        base = self.root / "base.json"
        base.write_text(json.dumps(self.left), encoding="utf-8")
        link = self.root / "alias.json"
        try:
            link.symlink_to(base)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unsupported")
        with self.assertRaisesRegex(EvidenceDenied, "linked"):
            read_receipt(link)

    def test_boolean_not_valid_as_fingerprint(self):
        self.left["transcript_sha256"] = True
        with self.assertRaises(EvidenceDenied):
            self.compare()

    def test_unhashable_warning_is_denied_not_crash(self):
        self.left["warnings"] = [[], "ONE_SHOT_ONLY", "NO_COMMAND_OR_MODEL_PAYLOAD"]
        with self.assertRaises(EvidenceDenied):
            self.compare()


if __name__ == "__main__":
    unittest.main()
