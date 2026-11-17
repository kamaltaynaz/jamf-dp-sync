"""Regression tests for the round-five Codex review (REVIEW_CODEX_5.md, 2026-11-10).

Each test reproduces one round-five finding through the L1 world and must fail on 6444fad.
"""
import json
import os
import unittest
from unittest import mock

from jamf_dp_sync import publish
from tests.integration.world import World

OWN = os.path.join(".local", "share", "jamf-dp-sync", "ownership.json")


def nm(v):
    return "jds-NudgeSuite-%s.pkg" % v


def chrome(v):
    return "jds-GoogleChrome-%s.pkg" % v


class Review5(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    def ok(self, *a, **kw):
        code, out, log = self.w.run(*a, **kw)
        self.assertEqual(code, 0, log[-2500:])
        return out, log

    def entries(self):
        p = os.path.join(self.w.home, OWN)
        if not os.path.exists(p):
            return {}
        with open(p) as f:
            return json.load(f)["entries"]

    def anchors(self):
        root = os.path.join(self.w.staging, ".jds-owned")
        out = set()
        for d, _, files in os.walk(root):
            out.update(files)
        return out

    def assert_no_leak(self):
        """Every anchor belongs to an entry, and there are no stale intents or unpublished entries."""
        ents = self.entries()
        wanted = set("%d-%d" % (e["dev"], e["ino"]) for e in ents.values())
        self.assertEqual(self.anchors(), wanted)
        for n, e in ents.items():
            self.assertNotIn("intent", e, n)
            self.assertNotEqual(e["state"], "pending", n)

    def crash_before_link(self):
        def crash(*a, **kw):
            raise SystemExit("simulated crash after begin(), before the link")
        return mock.patch.object(publish, "publish", crash)

    # r5 #1: an interrupted re-publish of a name we already own keeps the earlier ownership.
    def test_r5_01_interrupted_reuse_keeps_ownership(self):
        for v in ("142.0.7444.60", "142.0.7444.61"):
            self.w.set_upstream("chrome", v)
            self.w.set_title("chrome", v)
            self.ok(only=["chrome"], no_prune=True)
        self.w.edit_app("chrome", pin="142.0.7444.60")
        self.ok(only=["chrome"])
        self.assertIn(chrome("142.0.7444.60"), [n for _, n, _ in self.w.policy_packages("chrome")])
        self.w.edit_app("chrome", pin=None)
        with self.crash_before_link():
            with self.assertRaises(SystemExit):
                self.w.run(only=["chrome"])
        self.ok(only=["chrome"])
        self.assertIn(chrome("142.0.7444.61"), [n for _, n, _ in self.w.policy_packages("chrome")])

    # r5 #2a: re-downloading a lost retained file leaves no superseded anchor behind.
    def test_r5_02_redownload_frees_old_anchor(self):
        self.w.set_upstream("nudge", "2.1.4.81863")
        self.ok(only=["nudge"], no_prune=True)
        self.w.set_upstream("nudge", "2.1.5.1")
        self.w.set_title("nudge", "2.1.5.1")
        self.ok(only=["nudge"], no_prune=True)
        os.unlink(os.path.join(self.w.dp, nm("2.1.4.81863")))   # lost; its release is still upstream
        self.w.edit_app("nudge", pin="2.1.4.81863")
        self.ok(only=["nudge"], no_prune=True)
        self.ok(only=["nudge"], no_prune=True)
        self.assert_no_leak()

    # r5 #2b: a publish that never happened leaves no pending entry or anchor once a later run is done.
    def test_r5_02_abandoned_pending_is_swept(self):
        with self.crash_before_link():
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
        self.assertTrue(self.anchors())
        self.w.set_upstream("nudge", "2.1.5.1")
        self.w.set_title("nudge", "2.1.5.1")
        self.ok(only=["nudge"])
        self.assert_no_leak()
        self.assertNotIn(nm("2.1.4.81863"), self.entries())

    # r5 #2c: an anchor made just before a crash (no entry saved) is swept by the next run.
    def test_r5_02_orphan_anchor_is_swept(self):
        from jamf_dp_sync import ownership
        real = ownership.OwnershipStore._save
        calls = []

        def crash_on_first_save(self_, entries, *a, **kw):
            if self.anchors() and not calls:      # the save right after begin() made the anchor
                calls.append(1)
                raise SystemExit("simulated crash after the anchor link, before the entry is saved")
            return real(self_, entries, *a, **kw)
        with mock.patch.object(ownership.OwnershipStore, "_save", crash_on_first_save):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
        self.assertTrue(self.anchors())
        self.ok(only=["nudge"])
        self.assert_no_leak()


if __name__ == "__main__":
    unittest.main()
