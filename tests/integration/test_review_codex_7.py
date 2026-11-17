"""Regression tests for the round-seven Codex review (REVIEW_CODEX_7.md, 2026-11-10).

Each test reproduces one round-seven finding through the L1 world and must fail on 7195bac.
"""
import os
import stat
import unittest
from unittest import mock

from jamf_dp_sync import ownership, preflight
from tests.integration.world import World


def nm(v):
    return "jds-NudgeSuite-%s.pkg" % v


class Review7(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        os.chmod(self.w.dp, 0o755)
        self.w.close()

    def ok(self, *a, **kw):
        code, out, log = self.w.run(*a, **kw)
        self.assertEqual(code, 0, log[-2500:])
        return out, log

    # r7 #1: recovery never deletes files in staging just because their names look like scratch.
    def test_r7_01_foreign_lookalikes_untouched(self):
        s = self.w.staging
        with open(os.path.join(s, "nudge-rollback.pkg"), "wb") as f:
            f.write(b"an admin's saved pkg")
        for d in ("arm-backups", "extract-reports"):
            os.makedirs(os.path.join(s, d))
            with open(os.path.join(s, d, "valuable.txt"), "w") as f:
                f.write("keep")
        with mock.patch.object(preflight, "MIN_FREE", 1 << 62):    # even when preflight then refuses
            self.w.run(only=["chrome"])
        self.ok(only=["chrome"])
        self.assertTrue(os.path.exists(os.path.join(s, "nudge-rollback.pkg")))
        self.assertTrue(os.path.exists(os.path.join(s, "arm-backups", "valuable.txt")))
        self.assertTrue(os.path.exists(os.path.join(s, "extract-reports", "valuable.txt")))

    # r7 #2: an inaccessible Packages/ is not "file absent": the sweep keeps the ownership proof.
    def test_r7_02_sweep_keeps_proof_when_packages_inaccessible(self):
        real = ownership.OwnershipStore.settle
        calls = []

        def crash_once(self_, name, *a):
            calls.append(name)
            if len(calls) == 1:
                raise SystemExit("simulated crash after the link, before settle")
            return real(self_, name, *a)
        with mock.patch.object(ownership.OwnershipStore, "settle", crash_once):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
            self.assertIn(nm("2.1.4.81863"), os.listdir(self.w.dp))
            os.chmod(self.w.dp, stat.S_IRUSR | stat.S_IWUSR)        # maintenance: no search access
            code, out, log = self.w.run(only=["nudge"])
            self.assertEqual(code, 1)                                 # preflight refuses
            os.chmod(self.w.dp, 0o755)
            self.ok(only=["nudge"])
        self.assertIn(nm("2.1.4.81863"), [n for _, n, _ in self.w.policy_packages("nudge")])


if __name__ == "__main__":
    unittest.main()
