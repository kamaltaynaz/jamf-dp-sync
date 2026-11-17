"""Unit regressions for the round-five Codex review (REVIEW_CODEX_5.md): #1, #3 and #4."""
import os
import shutil
import sys
import tempfile
import unittest

from jamf_dp_sync import ownership

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "test", "env"))

import live  # noqa: E402
from tests.unit.test_live_harness import ISOLATED  # noqa: E402


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.staging = os.path.join(self.dir, "staging")
        os.makedirs(self.staging)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def file(self, name, data=b"pkg"):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def store(self, name):
        path = os.path.join(self.dir, name, "ownership.json")
        return ownership.OwnershipStore(path, anchor_dir=ownership.anchor_dir_for(self.staging, path))

    def publish(self, store, name, data=b"pkg"):
        staged = self.file("staged-" + name, data)
        store.begin(name, "x", ownership.sha512_of(staged), staged)
        final = os.path.join(self.dir, name)
        os.link(staged, final)
        os.unlink(staged)
        store.settle(name, final)
        return final


class BeginKeepsPrior(Tmp):
    """r5 #1: begin() over an owned name never replaces its identity until the outcome is known."""
    def test_crash_after_begin_keeps_prior(self):
        s = self.store("a")
        final = self.publish(s, "jds-X-1.pkg")
        s.begin("jds-X-1.pkg", "x", "ab" * 64, self.file("staged-again"))   # ...then a crash
        self.assertTrue(s.owns("jds-X-1.pkg", final))
        self.assertEqual(s.get("jds-X-1.pkg")["state"], ownership.PUBLISHED)


class AnchorNamespaces(Tmp):
    """r5 #3: two ownership stores sharing a staging directory never collect each other's anchors."""
    def test_other_store_anchor_survives(self):
        persistent, smoke = self.store("persistent"), self.store("smoke")
        mine = self.publish(persistent, "TEST-jds-X-1.pkg")
        theirs = self.publish(smoke, "jds-X-1.pkg", b"other")
        smoke.remove("jds-X-1.pkg")
        os.unlink(theirs)
        self.assertTrue(persistent.owns("TEST-jds-X-1.pkg", mine))
        self.assertNotEqual(persistent.anchor_dir, smoke.anchor_dir)


class EffectiveCategory(unittest.TestCase):
    """r5 #4: every app's effective category must be the test category before any write."""
    class J(object):
        def get_policy_xml(self, pid):
            return ISOLATED.encode("utf-8")

    def cfg(self, **app_extra):
        app = dict({"label": "nudge", "name_prefix": "TEST-jds-NudgeSuite", "policy_ids": [133]}, **app_extra)
        return {"dp_packages_dir": live.VM_DP, "category_id": 86, "apps": [app]}

    def test_app_override_refused(self):
        with self.assertRaises(live.Refuse):
            live.validate_config(self.cfg(category_id=99), self.J())

    def test_matching_category_passes(self):
        live.validate_config(self.cfg(), self.J())
        live.validate_config(self.cfg(category_id=86), self.J())


if __name__ == "__main__":
    unittest.main()
