"""Regression tests for the round-three Codex review (REVIEW_CODEX_3.md, 2026-11-10).

Each test reproduces one round-three finding through the L1 world and must fail on dee2602.
"""
import os
import shutil
import unittest
from unittest import mock

from jamf_dp_sync import ownership, publish
from jamf_dp_sync.jamf.client import AGENT_MARKER, JamfClient
from tests.integration.world import POLICY, TITLE, World, policy_xml as make_policy

PID = str(POLICY["nudge"])


def nm(v):
    return "jds-NudgeSuite-%s.pkg" % v


class Review3(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    def ok(self, *a, **kw):
        code, out, log = self.w.run(*a, **kw)
        self.assertEqual(code, 0, log[-2500:])
        return out, log

    def names(self, pid=PID):
        from jamf_dp_sync.jamf import policy_xml as P
        with self.w.jamf.lock:
            return [n for _, n, _ in P.packages(self.w.jamf.policies[str(pid)])]

    def rec_id(self, name):
        with self.w.jamf.lock:
            for p in self.w.jamf.packages.values():
                if p["packageName"] == name:
                    return p["id"]

    def publish_version(self, v, **kw):
        self.w.set_upstream("nudge", v)
        self.w.set_title("nudge", v)
        self.ok(only=["nudge"], **kw)

    def withdraw(self, *versions):
        with self.w.jamf.lock:
            t = self.w.jamf.titles[str(TITLE["nudge"])]
            t["definitions"] = [d for d in t["definitions"] if d["version"] not in versions]
            t["packages"] = [m for m in t.get("packages", []) if m["version"] not in versions]
            for i, d in enumerate(sorted(t["definitions"], key=lambda d: int(d["absoluteOrderId"]))):
                d["absoluteOrderId"] = str(i)

    def set_policy(self, pid, entries):
        with self.w.jamf.lock:
            self.w.jamf.policies[str(pid)] = make_policy(int(pid), "p", entries)

    def on_guard_read(self, change):
        """Run `change()` right after the planning read of the nudge policy (its 2nd read)."""
        real = JamfClient.get_policy_xml
        reads = []

        def get(self_, pid):
            xml = real(self_, pid)
            if str(pid) == PID:
                reads.append(pid)
                if len(reads) == 2:
                    change()
            return xml
        return mock.patch.object(JamfClient, "get_policy_xml", get)

    # r3 #1: pruning never removes a pkg the no-downgrade guard left in a policy.
    def test_r3_01_prune_keeps_pkg_held_by_another_policy(self):
        self.set_policy(110, [])
        self.w.edit_app("nudge", policy_ids=[POLICY["nudge"], 110], add_if_missing=True)
        self.publish_version("2.1.6.1")                               # oldest record ID: 2.1.6.1
        self.w.edit_app("nudge", policy_ids=[POLICY["nudge"], 110], add_if_missing=True, pin="2.1.5.1")
        self.w.set_upstream("nudge", "2.1.5.1")
        self.ok(only=["nudge"])                                       # newer record ID: 2.1.5.1
        self.w.edit_app("nudge", policy_ids=[POLICY["nudge"], 110], add_if_missing=True, pin=None, retain=1)
        self.w.set_title("nudge", "2.1.5.1")
        self.withdraw("2.1.6.1")
        self.set_policy(110, [(int(self.rec_id(nm("2.1.6.1"))), nm("2.1.6.1"))])   # admin keeps 2.1.6.1 here
        self.ok(only=["nudge"])
        self.assertIn(nm("2.1.6.1"), self.names(110))
        self.assertIn(nm("2.1.6.1"), os.listdir(self.w.dp))

    # r3 #2: re-planning in the Q20 guard keeps the no-downgrade rule.
    def test_r3_02_replan_never_downgrades(self):
        def admin_installs_newer():
            with self.w.jamf.lock:
                self.w.jamf.packages["999"] = {"id": "999", "packageName": nm("2.1.9.1"), "fileName": nm("2.1.9.1"),
                                               "notes": AGENT_MARKER}
            self.set_policy(PID, [(999, nm("2.1.9.1"))])
        with self.on_guard_read(admin_installs_newer):
            code, out, log = self.w.run(only=["nudge"])
        self.assertIn(nm("2.1.9.1"), self.names())
        self.assertNotIn(nm("2.1.4.81863"), self.names())

    # r3 #3: the Q20 comparison covers every writable package field.
    def test_r3_03_fut_change_is_not_overwritten(self):
        def admin_flips_fut():
            with self.w.jamf.lock:
                x = self.w.jamf.policies[PID]
                self.w.jamf.policies[PID] = x.replace(
                    "<name>Org-Branding-1.2.pkg</name><action>Install</action><fut>false</fut>",
                    "<name>Org-Branding-1.2.pkg</name><action>Install</action><fut>true</fut>", 1)
        with self.on_guard_read(admin_flips_fut):
            self.ok(only=["nudge"])
        with self.w.jamf.lock:
            self.assertIn("<name>Org-Branding-1.2.pkg</name><action>Install</action><fut>true</fut>",
                          self.w.jamf.policies[PID])

    # r3 #4: an identical file appearing at the destination is never claimed.
    def test_r3_04_existing_identical_file_not_claimed(self):
        real = publish.publish

        def upload_first(staged, packages_dir, name, sha512, dp_group=None):
            shutil.copy(staged, os.path.join(packages_dir, name))   # someone uploads the same bytes
            return real(staged, packages_dir, name, sha512, dp_group)
        with mock.patch.object(publish, "publish", upload_first):
            code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertNotIn(nm("2.1.4.81863"), [r["packageName"] for r in self.w.records()])
        self.assertIsNone(ownership.OwnershipStore(
            os.path.join(self.w.home, ".local", "share", "jamf-dp-sync", "ownership.json")).get(nm("2.1.4.81863")))

    # r3 #5: the Stop exit writes only to finish recorded unfinished work.
    def test_r3_05_stop_does_not_map_unrecorded(self):
        with self.w.jamf.lock:
            self.w.jamf.packages["300"] = {"id": "300", "packageName": nm("2.1.4.81863"),
                                           "fileName": nm("2.1.4.81863"), "notes": AGENT_MARKER}
        self.set_policy(PID, [(300, nm("2.1.4.81863"))])
        with open(os.path.join(self.w.dp, nm("2.1.4.81863")), "wb") as f:
            f.write(b"not a package")
        self.w.run(only=["nudge"])
        with self.w.jamf.lock:
            self.assertEqual(self.w.jamf.titles[str(TITLE["nudge"])]["packages"], [])

    def test_r3_05_stop_does_not_prune_unrecorded(self):
        for v in ("2.1.4.81863", "2.1.5.1", "2.1.6.1"):
            self.publish_version(v, no_prune=True)
        before = sorted(n for n in os.listdir(self.w.dp) if n.startswith("jds-"))
        self.ok(only=["nudge"])                                       # Stop: nothing unfinished
        self.assertEqual(sorted(n for n in os.listdir(self.w.dp) if n.startswith("jds-")), before)

    # r3 #8: a crash between the link and the ownership commit is recoverable.
    def test_r3_08_crash_after_link_recovers(self):
        real = ownership.OwnershipStore.settle   # the bookkeeping step after the link (r5: was commit)
        calls = []

        def crash_once(self_, name, *a):
            calls.append(name)
            if len(calls) == 1:
                raise SystemExit("simulated crash after link, before the entry is settled")
            return real(self_, name, *a)
        with mock.patch.object(ownership.OwnershipStore, "settle", crash_once):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
            self.assertIn(nm("2.1.4.81863"), os.listdir(self.w.dp))
            self.ok(only=["nudge"])
        self.assertIn(nm("2.1.4.81863"), self.names())

    # r3 #9: a prune interrupted after deleting the record is finished even on the Stop path.
    def test_r3_09_interrupted_prune_finished_on_stop(self):
        self.publish_version("2.1.4.81863")
        self.publish_version("2.1.5.1")
        real = JamfClient.delete_package
        calls = []

        def crash_after_delete(self_, pid):
            real(self_, pid)
            calls.append(pid)
            raise SystemExit("simulated crash after record delete, before unlink")
        self.w.set_upstream("nudge", "2.1.6.1")
        self.w.set_title("nudge", "2.1.6.1")
        with mock.patch.object(JamfClient, "delete_package", crash_after_delete):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
        self.assertIn(nm("2.1.4.81863"), os.listdir(self.w.dp))     # record gone, file left
        self.ok(only=["nudge"])                                       # policies already on 2.1.6.1
        self.assertNotIn(nm("2.1.4.81863"), os.listdir(self.w.dp))

    # r3 #12: a re-plan that ends in "no match" still reports why.
    def test_r3_12_replan_warning_reported(self):
        self.w.edit_app("nudge", add_if_missing=False)

        def admin_removes_legacy():
            self.set_policy(PID, [(11, "Org-Branding-1.2.pkg")])
        with self.on_guard_read(admin_removes_legacy):
            code, out, log = self.w.run(only=["nudge"])
        self.assertIn("policy %s" % PID, self.w.messages()[-1]["text"])
        self.assertIn("add_if_missing", self.w.messages()[-1]["text"])


if __name__ == "__main__":
    unittest.main()
