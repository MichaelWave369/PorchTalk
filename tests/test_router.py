"""Fail-closed route selection tests; no sockets, checkpoints or external services."""

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from porchtalk.router import ScenarioError, evaluate

FIXED_NOW = datetime(2026, 10, 12, 18, 0, tzinfo=timezone.utc)
FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "two_porches.json"


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.scenario = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def decide(self):
        return evaluate(self.scenario, now=FIXED_NOW)

    def test_remote_fallback_with_specific_grant(self):
        d = self.decide()["decision"]
        self.assertEqual((d["status"], d["mode"], d["node_id"]), ("ROUTED", "REMOTE", "bob-desktop"))
        self.assertEqual(d["grant_id"], "demo-grant-bob-to-alice")

    def test_local_first_even_when_remote_cheaper(self):
        self.scenario["offers"][0]["quality_tier"] = 2
        self.scenario["offers"][0]["est_cost_units"] = 10
        self.assertEqual(self.decide()["decision"]["node_id"], "alice-laptop")

    def test_deny_without_requester_remote_optin(self):
        self.scenario["request"]["allow_remote"] = False
        d = self.decide()
        self.assertEqual(d["decision"]["status"], "DENIED")
        self.assertEqual(d["rejected_offers"]["bob-desktop/medium-peer"], "REMOTE_DISABLED")

    def test_deny_without_matching_grant(self):
        self.scenario["grants"] = []
        self.assertEqual(self.decide()["rejected_offers"]["bob-desktop/medium-peer"], "NO_VALID_GRANT")

    def test_deny_revoked_and_expired_grants(self):
        self.scenario["grants"][0]["revoked"] = True
        self.assertEqual(self.decide()["decision"]["status"], "DENIED")
        self.scenario["grants"][0]["revoked"] = False
        self.scenario["grants"][0]["expires_at"] = "2026-01-01T00:00:00Z"
        self.assertEqual(self.decide()["decision"]["status"], "DENIED")

    def test_private_data_never_leaves_local_porch(self):
        self.scenario["request"]["data_class"] = "PRIVATE"
        self.assertEqual(self.decide()["rejected_offers"]["bob-desktop/medium-peer"], "PRIVATE_DATA_LOCAL_ONLY")

    def test_deny_when_memory_insufficient(self):
        self.scenario["offers"][1]["free_memory_mib"] = 100
        self.assertEqual(self.decide()["rejected_offers"]["bob-desktop/medium-peer"], "INSUFFICIENT_MEMORY")

    def test_cost_cap_applies_before_grant(self):
        self.scenario["request"]["max_cost_units"] = 2
        self.assertEqual(self.decide()["rejected_offers"]["bob-desktop/medium-peer"], "ESTIMATED_BUDGET_EXCEEDED")

    def test_wrong_grantee_and_owner_deny(self):
        self.scenario["grants"][0]["grantee_id"] = "porch-charlie"
        self.assertEqual(self.decide()["decision"]["status"], "DENIED")
        self.scenario["grants"][0]["grantee_id"] = "porch-alice"
        self.scenario["grants"][0]["owner_id"] = "porch-charlie"
        self.assertEqual(self.decide()["decision"]["status"], "DENIED")

    def test_selection_is_order_independent(self):
        baseline = self.decide()
        self.scenario["offers"].reverse()
        self.scenario["grants"].reverse()
        self.assertEqual(baseline, self.decide())

    def test_reject_ambiguous_and_malformed_metadata(self):
        self.scenario["offers"].append(copy.deepcopy(self.scenario["offers"][0]))
        with self.assertRaises(ScenarioError):
            self.decide()
        self.scenario["offers"].pop()
        self.scenario["request"]["allow_remote"] = 1
        with self.assertRaises(ScenarioError):
            self.decide()

    def test_reject_naive_expiry(self):
        self.scenario["grants"][0]["expires_at"] = "2030-01-01T00:00:00"
        with self.assertRaises(ScenarioError):
            self.decide()

    def test_receipt_checksum_present(self):
        receipt = self.decide()
        self.assertEqual(len(receipt["receipt_sha256"]), 64)
        self.assertIn("SHA256_IS_NOT_A_SIGNATURE", receipt["warnings"])


if __name__ == "__main__":
    unittest.main()
