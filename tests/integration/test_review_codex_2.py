"""Regression tests for the round-two Codex review (REVIEW_CODEX_2.md, 2026-11-10).

Each test reproduces one round-two finding through the L1 world and must fail on commit fd8ce33.
Names carry the round-two finding number (r2_NN).
"""
import datetime
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from jamf_dp_sync import pipeline, publish
from jamf_dp_sync.errors import SyncError
from tests.integration.world import POLICY, ROOT, TITLE, World, policy_xml as make_policy

NUDGE = "jds-NudgeSuite-2.1.4.81863.pkg"
NUDGE_NEW = "jds-NudgeSuite-2.1.5.81902.pkg"


class Review2(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    def ok(self, *a, **kw):
        code, out, log = self.w.run(*a, **kw)
        self.assertEqual(code, 0, log[-2500:])
        return out, log

    def names(self, label, pid=None):
        from jamf_dp_sync.jamf import policy_xml as P
        with self.w.jamf.lock:
            xml = self.w.jamf.policies[str(pid or POLICY[label])]
        return [n for _, n, _ in P.packages(xml)]

    def nudge_versions(self, *versions):
        for v in versions:
            self.w.set_upstream("nudge", v)
            self.w.set_title("nudge", v)
            self.ok(only=["nudge"])

    # r2 #1: policies that disagree must not drag the newer one back down.
    def test_r2_01_divergent_policies_no_downgrade(self):
        with self.w.jamf.lock:
            self.w.jamf.policies["110"] = make_policy(110, "second nudge policy", [])
        self.w.edit_app("nudge", policy_ids=[POLICY["nudge"], 110], add_if_missing=True)
        self.ok(only=["nudge"])                                   # both at 2.1.4
        self.nudge_versions("2.1.5.81902")                        # both at 2.1.5
        with self.w.jamf.lock:                                    # admin puts 110 back on 2.1.4
            pk = self.w.jamf.policies[str(POLICY["nudge"])]
            self.w.jamf.policies["110"] = pk.replace(NUDGE_NEW, NUDGE).replace(
                "<id>%s</id>" % self._id(NUDGE_NEW), "<id>%s</id>" % self._id(NUDGE))
            t = self.w.jamf.titles[str(TITLE["nudge"])]             # catalog withdraws 2.1.5
            t["definitions"] = [d for d in t["definitions"] if d["version"] != "2.1.5.81902"]
            for d in t["definitions"]:
                d["absoluteOrderId"] = str(max(0, int(d["absoluteOrderId"]) - 1))
        self.ok(only=["nudge"])
        self.assertIn(NUDGE_NEW, self.names("nudge"))            # first policy never downgraded
        self.assertIn(NUDGE_NEW, self.names("nudge", 110))       # the other reconciled upward

    def _id(self, name):
        with self.w.jamf.lock:
            return [p["id"] for p in self.w.jamf.packages.values() if p["packageName"] == name][0]

    # r2 #4: a publish that failed must not leave adoption authority behind.
    def test_r2_04_failed_publish_leaves_no_ownership(self):
        saved = os.path.join(self.w.dir, "copy.pkg")

        def fail_publish(staged, packages_dir, name, sha512, dp_group=None):
            shutil.copy(staged, saved)
            raise publish.PublishError("link failed (simulated)")
        with mock.patch.object(publish, "publish", fail_publish):
            code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        shutil.copy(saved, os.path.join(self.w.dp, NUDGE))        # someone uploads identical bytes
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertIn("no marked record", log)
        self.assertNotIn(NUDGE, [r["packageName"] for r in self.w.records()])

    # r2 #7: ownership proof survives deletion of the disposable cache.
    def test_r2_07_ledger_survives_cache_deletion(self):
        from jamf_dp_sync.jamf.client import JamfClient
        real = JamfClient.create_package
        calls = []

        def crash_once(self_, *a, **kw):
            calls.append(1)
            if len(calls) == 1:
                raise SystemExit("simulated crash after publish, before record")
            return real(self_, *a, **kw)
        with mock.patch.object(JamfClient, "create_package", crash_once):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
            shutil.rmtree(os.path.join(self.w.home, ".local", "state", "jamf-dp-sync"), ignore_errors=True)
            self.assertTrue(os.path.exists(os.path.join(self.w.home, ".local", "share", "jamf-dp-sync",
                                                        "ownership.json")))  # durable, not in the cache
            self.ok(only=["nudge"])
        self.assertIn(NUDGE, self.names("nudge"))

    # r2 #8: a retained pkg whose record has no SHA-512 is not reused.
    def test_r2_08_retained_without_record_digest_fails_closed(self):
        self.nudge_versions("2.1.4.81863", "2.1.5.81902")
        with self.w.jamf.lock:
            for p in self.w.jamf.packages.values():
                if p["packageName"] == NUDGE:
                    p["hashType"], p["hashValue"] = None, None
        self.w.edit_app("nudge", pin="2.1.4.81863")
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertIn(NUDGE_NEW, self.names("nudge"))

    # r2 #12: a skipped policy is reported on the Stop path too.
    def test_r2_12_skipped_policy_warned_when_current(self):
        self.ok(only=["acrobat"])
        with self.w.jamf.lock:
            self.w.jamf.policies["110"] = make_policy(110, "second acrobat policy", [])
        self.w.edit_app("acrobat", policy_ids=[POLICY["acrobat"], 110], add_if_missing=False)
        self.ok(only=["acrobat"])
        self.assertIn("policy 110", self.w.messages()[-1]["text"])

    # r2 #13: the Stop path never maps a record the agent does not own.
    def test_r2_13_no_mapping_for_unowned_record(self):
        with self.w.jamf.lock:
            self.w.jamf.packages["300"] = {"id": "300", "packageName": NUDGE, "fileName": NUDGE, "notes": ""}
            self.w.jamf.policies[str(POLICY["nudge"])] = make_policy(POLICY["nudge"], "nudge", [(300, NUDGE)])
        self.w.run(only=["nudge"])
        with self.w.jamf.lock:
            self.assertEqual(self.w.jamf.titles[str(TITLE["nudge"])]["packages"], [])

    # r2 #14: pruning skipped by an interrupted run is completed later.
    def test_r2_14_interrupted_prune_completed(self):
        self.nudge_versions("2.1.4.81863", "2.1.5.1")
        self.w.jamf.faults.append({"match": "PATCH /api/v3/patch-software-title-configurations",
                                   "status": 500, "times": 1})
        self.w.set_upstream("nudge", "2.1.6.1")
        self.w.set_title("nudge", "2.1.6.1")
        code, out, log = self.w.run(only=["nudge"])                # mapping fails before prune
        self.assertEqual(code, 1)
        self.ok(only=["nudge"])
        files = sorted(n for n in os.listdir(self.w.dp) if n.startswith("jds-NudgeSuite"))
        self.assertEqual(files, ["jds-NudgeSuite-2.1.5.1.pkg", "jds-NudgeSuite-2.1.6.1.pkg"])

    # r2 #16: a heartbeat cache failure never suppresses the run's notification.
    def test_r2_16_heartbeat_state_failure_still_notifies(self):
        from jamf_dp_sync import state as state_mod
        real = state_mod.StateStore.update
        self.w.set_upstream("dialog", "3.1.1.5000", team="XYZXYZXYZ1")

        def full(self_, key, **kw):
            if key == "_run":
                raise OSError(28, "No space left on device")
            return real(self_, key, **kw)
        with mock.patch.object(state_mod.StateStore, "update", full):
            code, out, log = self.w.run(only=["dialog"], now=datetime.datetime(2026, 11, 16, 3, 20))
        self.assertEqual(code, 1)
        self.assertIn("*FAIL* dialog", self.w.messages()[-1]["text"])

    # r2 #17: a startup failure during --dry-run posts nothing.
    def test_r2_17_startup_failure_in_dry_run_is_silent(self):
        with open(self.w.cfg_path, "w") as f:
            f.write('{"unknown": 1}')
        p = self.w.cli("run", "--dry-run")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(self.w.messages(), [])

    # r2 #18: the dry-run prune preview includes the record the real run would create.
    def test_r2_18_dry_run_prune_preview_matches(self):
        self.nudge_versions("2.1.4.81863", "2.1.5.1")
        self.w.set_upstream("nudge", "2.1.6.1")
        self.w.set_title("nudge", "2.1.6.1")
        out, log = self.ok(only=["nudge"], dry_run=True)
        self.assertIn("would prune %s" % NUDGE, out)

    # r2 #10: dry-run stdout is redacted too.
    def test_r2_10_stdout_redacted(self):
        def leaky(app, ctx):
            raise SyncError("upstream echoed stub-secret back", step="resolve")
        with mock.patch.object(pipeline, "run_app", leaky):
            code, out, log = self.w.run(only=["nudge"], dry_run=True)
        self.assertNotIn("stub-secret", out)


if __name__ == "__main__":
    unittest.main()
