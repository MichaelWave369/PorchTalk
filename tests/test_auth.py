"""Offline negative controls for authenticated peer-grant envelopes."""

import copy
import unittest

from porchtalk.auth import AuthorizationDenied, SessionReplayGuard, issue_grant, verify_grant

KEY = b"test-secret-key-porchtalk-b1-32-bytes"  # deterministic TEST ONLY: never provision this key
T = 1800000000


class OfflineAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.msg = issue_grant(key=KEY, grant_id="g1", owner_id="bob", grantee_id="alice", node_id="bob-pc", model_id="tiny", request_id="r1", data_class="SYNTHETIC", max_cost_units=3, now=T)
        self.guard = SessionReplayGuard()
        self.revoked = set()

    def verify(self, **changes):
        kw = dict(envelope=self.msg, key=KEY, expected_owner_id="bob", expected_grantee_id="alice", expected_node_id="bob-pc", expected_model_id="tiny", expected_request_id="r1", expected_data_class="SYNTHETIC", proposed_cost_units=2, revoked_grant_ids=self.revoked, replay_guard=self.guard, now=T + 5)
        kw.update(changes)
        return verify_grant(**kw)

    def test_valid_grant(self):
        self.assertTrue(self.verify()["authenticated"])

    def test_replay_is_denied(self):
        self.verify()
        with self.assertRaisesRegex(AuthorizationDenied, "replayed"):
            self.verify()

    def test_tampering_denied(self):
        msg = copy.deepcopy(self.msg)
        msg["claims"]["model_id"] = "more-expensive"
        with self.assertRaisesRegex(AuthorizationDenied, "authentication failed"):
            self.verify(envelope=msg)

    def test_wrong_secret_denied(self):
        with self.assertRaisesRegex(AuthorizationDenied, "authentication failed"):
            self.verify(key=b"another-test-key-porchtalk-32bytes!")

    def test_wrong_principal_denied(self):
        with self.assertRaises(AuthorizationDenied):
            self.verify(expected_grantee_id="charlie")
        with self.assertRaises(AuthorizationDenied):
            self.verify(expected_owner_id="eve")

    def test_scope_mismatch_denied(self):
        for key, value in (("expected_node_id", "other-pc"), ("expected_model_id", "other-model"), ("expected_request_id", "r2"), ("expected_data_class", "PUBLIC")):
            with self.subTest(key=key), self.assertRaises(AuthorizationDenied):
                self.verify(**{key: value})

    def test_revocation_denied(self):
        self.revoked.add("g1")
        with self.assertRaisesRegex(AuthorizationDenied, "revoked"):
            self.verify()

    def test_expired_denied(self):
        with self.assertRaisesRegex(AuthorizationDenied, "validity"):
            self.verify(now=T + 60)

    def test_not_yet_valid_denied(self):
        with self.assertRaisesRegex(AuthorizationDenied, "validity"):
            self.verify(now=T - 31)

    def test_budget_denied(self):
        with self.assertRaisesRegex(AuthorizationDenied, "cost"):
            self.verify(proposed_cost_units=4)

    def test_private_data_not_issuable(self):
        with self.assertRaisesRegex(AuthorizationDenied, "data class"):
            issue_grant(key=KEY, grant_id="g2", owner_id="bob", grantee_id="alice", node_id="bob-pc", model_id="tiny", request_id="r1", data_class="PRIVATE", max_cost_units=3, now=T)

    def test_max_lifetime(self):
        with self.assertRaisesRegex(AuthorizationDenied, "too long"):
            issue_grant(key=KEY, grant_id="g2", owner_id="bob", grantee_id="alice", node_id="bob-pc", model_id="tiny", request_id="r1", data_class="PUBLIC", max_cost_units=3, now=T, lifetime_seconds=301)

    def test_bad_key_rejected(self):
        with self.assertRaisesRegex(AuthorizationDenied, "shared key"):
            self.verify(key=b"short")

    def test_extra_claim_field_rejected(self):
        msg = copy.deepcopy(self.msg)
        msg["claims"]["execute_code"] = True
        with self.assertRaisesRegex(AuthorizationDenied, "fields mismatch"):
            self.verify(envelope=msg)

    def test_unhashable_data_class_denied_cleanly(self):
        msg = copy.deepcopy(self.msg)
        msg["claims"]["data_class"] = []
        with self.assertRaises(AuthorizationDenied):
            self.verify(envelope=msg)

    def test_bad_mac_rejected(self):
        msg = copy.deepcopy(self.msg)
        msg["mac_hex"] = "garbage"
        with self.assertRaisesRegex(AuthorizationDenied, "invalid mac"):
            self.verify(envelope=msg)

    def test_bool_is_not_cost(self):
        with self.assertRaisesRegex(AuthorizationDenied, "proposed_cost_units"):
            self.verify(proposed_cost_units=True)

    def test_missing_replay_guard_denied(self):
        with self.assertRaisesRegex(AuthorizationDenied, "replay state"):
            self.verify(replay_guard=None)

    def test_missing_revocation_registry_denied(self):
        with self.assertRaisesRegex(AuthorizationDenied, "replay state"):
            self.verify(revoked_grant_ids=None)


if __name__ == "__main__":
    unittest.main()
