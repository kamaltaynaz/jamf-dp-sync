"""Regression tests for the round-six Codex review (REVIEW_CODEX_6.md, 2026-11-10).

Each test reproduces the round-six finding through the L1 world and must fail on 12d7eb2.
"""
import os
import unittest
from unittest import mock

from jamf_dp_sync import preflight, publish
from tests.integration.world import World


class Review6(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    # Scratch lives in <staging>/.jds-scratch since round seven #1.
    def scratch(self):
        d = os.path.join(self.w.staging, ".jds-scratch")
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    def plant(self):
        """What interrupted runs leave in scratch: downloads and extraction/manifest folders."""
        d = os.path.join(self.w.staging, ".jds-scratch")
        os.makedirs(d, 0o700, exist_ok=True)   # as the agent makes it (RHEL umask is 0002)
        os.chmod(d, 0o700)
        for n in ("nudge-abc123.pkg", "googledrive-x1.dmg"):
            with open(os.path.join(d, n), "wb") as f:
                f.write(b"partial")
        for x in ("arm-q9", "extract-z1"):
            os.makedirs(os.path.join(d, x, "inner"))

    # r6 #1: a download stranded by an interrupted publish is reclaimed by the next run.
    def test_r6_01_interrupted_download_reclaimed(self):
        def crash(*a, **kw):
            raise SystemExit("simulated crash after verify, before the link")
        with mock.patch.object(publish, "publish", crash):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
        self.assertTrue(self.scratch())
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 0, log[-2000:])
        self.assertEqual(self.scratch(), [])

    # r6 #1: reclaimed before the free-space preflight, so it can make room for the run.
    def test_r6_01_reclaimed_before_free_space_check(self):
        self.plant()
        with mock.patch.object(preflight, "MIN_FREE", 1 << 62):
            code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertEqual(self.scratch(), [])

    # A dry run reclaims nothing (A12) and nothing but agent scratch is ever removed.
    def test_r6_01_dry_run_and_foreign_files_untouched(self):
        self.plant()
        self.w.run(only=["nudge"], dry_run=True)
        self.assertEqual(len(self.scratch()), 4)
        with open(os.path.join(self.w.staging, "notes.txt"), "w") as f:
            f.write("an admin's file")
        os.symlink("/", os.path.join(self.w.staging, "nudge-link.pkg"))
        self.w.run(only=["nudge"])
        self.assertEqual(self.scratch(), [])
        self.assertEqual(sorted(n for n in os.listdir(self.w.staging) if not n.startswith(".jds-")),
                         ["notes.txt", "nudge-link.pkg"])


if __name__ == "__main__":
    unittest.main()
