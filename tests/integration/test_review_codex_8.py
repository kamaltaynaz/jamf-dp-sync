"""Regression tests for the round-eight Codex review (REVIEW_CODEX_8.md, 2026-11-10).

Each test reproduces one round-eight finding through the L1 world and must fail on 289d5b7.
"""
import os
import unittest
from unittest import mock

from jamf_dp_sync import ownership
from tests.integration.world import World


def nm(v):
    return "jds-NudgeSuite-%s.pkg" % v


class Review8(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        for d, _, _ in os.walk(os.path.join(self.w.staging, ".jds-owned")):
            os.chmod(d, 0o700)
        self.w.close()

    def ok(self, *a, **kw):
        code, out, log = self.w.run(*a, **kw)
        self.assertEqual(code, 0, log[-2500:])
        return out, log

    def symlinked_scratch(self):
        os.symlink(self.w.dp, os.path.join(self.w.staging, ".jds-scratch"))
        foreign = os.path.join(self.w.dp, "nudge-admin-saved.pkg")
        with open(foreign, "wb") as f:
            f.write(b"an admin's pkg")
        return foreign, sorted(os.listdir(self.w.dp))

    # r8 #1: a symlinked scratch folder is refused before anything is written through it (dry run).
    def test_r8_01_symlinked_scratch_refused_in_dry_run(self):
        foreign, before = self.symlinked_scratch()
        code, out, log = self.w.run(faults="wrong_team", only=["nudge"], dry_run=True)
        self.assertEqual(code, 1)
        self.assertTrue(os.path.exists(foreign))
        self.assertEqual(sorted(os.listdir(self.w.dp)), before)
        self.assertIn(".jds-scratch", log)

    # r8 #1: ...and in a real run.
    def test_r8_01_symlinked_scratch_refused_in_real_run(self):
        foreign, before = self.symlinked_scratch()
        code, out, log = self.w.run(faults="wrong_team", only=["nudge"])
        self.assertEqual(code, 1)
        self.assertTrue(os.path.exists(foreign))
        self.assertEqual(sorted(os.listdir(self.w.dp)), before)

    # r8 #2: an unreadable anchor folder is "unknown", not "not ours": the entry survives.
    def test_r8_02_unreadable_anchor_keeps_entry(self):
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
            root = os.path.join(self.w.staging, ".jds-owned")
            store_dirs = [os.path.join(root, d) for d in os.listdir(root)]
            for d in store_dirs:
                os.chmod(d, 0o600)                                    # no search permission
            self.w.run(only=["nudge"])
            for d in store_dirs:
                os.chmod(d, 0o700)
            self.ok(only=["nudge"])
        self.assertIn(nm("2.1.4.81863"), [n for _, n, _ in self.w.policy_packages("nudge")])


if __name__ == "__main__":
    unittest.main()
