"""Regression tests for the round-nine Codex review (REVIEW_CODEX_9.md, 2026-11-11).

Each test reproduces one round-nine finding through the L1 world and must fail on 21b57c4.
"""
import os
import shutil
import unittest
from unittest import mock

from jamf_dp_sync.jamf.client import JamfClient
from tests.integration.world import World


def nm(v):
    return "jds-NudgeSuite-%s.pkg" % v


class Review9(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        for d, _, _ in os.walk(os.path.join(self.w.staging, ".jds-owned")):
            if not os.path.islink(d):
                os.chmod(d, 0o700)
        self.w.close()

    def ok(self, *a, **kw):
        code, out, log = self.w.run(*a, **kw)
        self.assertEqual(code, 0, log[-2500:])
        return out, log

    def publish_version(self, v, **kw):
        self.w.set_upstream("nudge", v)
        self.w.set_title("nudge", v)
        self.ok(only=["nudge"], **kw)

    def store_dirs(self):
        root = os.path.join(self.w.staging, ".jds-owned")
        return [os.path.join(root, d) for d in os.listdir(root)]

    # r9 #1: an anchor folder replaced by a symlink is refused; nothing is collected through it.
    def test_r9_01_symlinked_anchor_dir_refused(self):
        self.publish_version("2.1.4.81863")
        before = sorted(os.listdir(self.w.dp))
        for d in self.store_dirs():
            shutil.move(d, d + ".moved")
            os.symlink(self.w.dp, d)
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(sorted(os.listdir(self.w.dp)), before)
        self.assertEqual(code, 1)
        self.assertIn(".jds-owned", log)

    # r9 #2: interrupted-prune recovery keeps the entry while identity is unknown.
    def test_r9_02_prune_recovery_keeps_entry_on_unknown(self):
        self.publish_version("2.1.4.81863")
        self.publish_version("2.1.5.1")
        real = JamfClient.delete_package

        def crash_after_delete(self_, pid):
            real(self_, pid)
            raise SystemExit("simulated crash after record delete, before unlink")
        self.w.set_upstream("nudge", "2.1.6.1")
        self.w.set_title("nudge", "2.1.6.1")
        with mock.patch.object(JamfClient, "delete_package", crash_after_delete):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
        dirs = self.store_dirs()
        for d in dirs:
            os.chmod(d, 0o600)                                 # anchors unsearchable for one run
        self.w.run(only=["nudge"])
        for d in dirs:
            os.chmod(d, 0o700)
        self.ok(only=["nudge"])                                # recovery finishes the prune
        self.assertNotIn(nm("2.1.4.81863"), os.listdir(self.w.dp))
        self.publish_version("2.1.7.1")                        # and later updates are not blocked


if __name__ == "__main__":
    unittest.main()
