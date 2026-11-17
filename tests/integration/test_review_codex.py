"""Regression tests for the independent Codex review (REVIEW_CODEX.md, 2026-11-10).

Each test reproduces one finding through the L1 world and must fail on the code as reviewed
(commit 479ee0a). Test names carry the finding number.
"""
import datetime
import json
import os
import unittest
from unittest import mock

from jamf_dp_sync import download, state as state_mod
from tests.integration.world import LEGACY, POLICY, TITLE, World, policy_xml as make_policy

NUDGE = "jds-NudgeSuite-2.1.4.81863.pkg"
NUDGE_NEW = "jds-NudgeSuite-2.1.5.81902.pkg"


class Review(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    def ok(self, *a, **kw):
        code, out, log = self.w.run(*a, **kw)
        self.assertEqual(code, 0, log[-2500:])
        return out, log

    def names(self, label):
        return [n for _, n, _ in self.w.policy_packages(label)]

    def two_nudge_versions(self):
        self.ok(only=["nudge"])
        self.w.set_upstream("nudge", "2.1.5.81902")
        self.w.set_title("nudge", "2.1.5.81902")
        self.ok(only=["nudge"])
        self.assertIn(NUDGE_NEW, self.names("nudge"))

    # 1 (blocker): dry run with a retained pinned version must not write anything.
    def test_f01_dry_run_never_writes_on_retained_path(self):
        self.two_nudge_versions()
        files = sorted(os.listdir(self.w.dp))
        writes = len(self.w.jamf_writes())
        self.w.edit_app("nudge", pin="2.1.4.81863")
        out, log = self.ok(only=["nudge"], dry_run=True)
        self.assertEqual(len(self.w.jamf_writes()), writes)
        self.assertEqual(sorted(os.listdir(self.w.dp)), files)
        self.assertIn(NUDGE_NEW, self.names("nudge"))
        self.assertIn("would", out)

    # 3: a retained file is re-verified before it is attached again.
    def test_f03_retained_file_is_reverified(self):
        self.two_nudge_versions()
        self.w.edit_app("nudge", pin="2.1.4.81863")
        path = os.path.join(self.w.dp, NUDGE)
        with open(path, "rb") as f:
            original = f.read()
        for how, data, text in (("corrupted header", original[:100] + b"TAMPERED" + original[108:], "verify"),
                                ("appended bytes", original + b"extra payload", "SHA-512")):
            with self.subTest(how=how):
                with open(path, "wb") as f:
                    f.write(data)
                code, out, log = self.w.run(only=["nudge"])
                self.assertEqual(code, 1)
                self.assertIn(NUDGE_NEW, self.names("nudge"))       # policy not rolled to a bad file
                self.assertTrue(os.path.exists(path))               # a published file is never deleted here
                self.assertIn(text, self.w.messages()[-1]["text"])

    # 4: the policy is re-read right before its PUT, so concurrent edits survive.
    def test_f04_policy_reread_before_put(self):
        real_fetch = download.fetch

        def fetch_and_admin_edits_policy(*a, **kw):
            got = real_fetch(*a, **kw)
            with self.w.jamf.lock:  # an admin adds a package while the agent downloads
                pid = str(POLICY["nudge"])
                xml = self.w.jamf.policies[pid]
                self.w.jamf.policies[pid] = xml.replace(
                    "</packages>", "<package><id>11</id><name>Admin-Added.pkg</name><action>Cache</action>"
                    "</package></packages>")
            return got
        with mock.patch.object(download, "fetch", side_effect=fetch_and_admin_edits_policy):
            self.ok(only=["nudge"])
        self.assertIn("Admin-Added.pkg", self.names("nudge"))
        self.assertIn(NUDGE, self.names("nudge"))

    # 5: a pin is exact even for latest-only sources.
    def test_f05_pin_is_exact_for_latest_only_source(self):
        self.w.set_upstream("chrome", "143.0.7500.1")          # CDN only serves 143
        self.w.edit_app("chrome", pin="142.0.7444.60")          # pinned to 142, never published
        code, out, log = self.w.run(only=["chrome"])
        self.assertNotIn("jds-GoogleChrome-143.0.7500.1.pkg", os.listdir(self.w.dp))
        self.assertNotIn("jds-GoogleChrome-143.0.7500.1.pkg", self.names("chrome"))

    # 6: no automatic downgrade when the catalog moves backward (only a pin rolls back).
    def test_f06_no_downgrade_when_catalog_moves_back(self):
        self.ok(only=["zoom"])
        self.w.set_upstream("zoom", "7.2.6.91011")
        self.w.set_title("zoom", "7.2.6 (91011)")
        self.ok(only=["zoom"])
        with self.w.jamf.lock:  # the newest definition is withdrawn
            t = self.w.jamf.titles[str(TITLE["zoom"])]
            t["definitions"] = [d for d in t["definitions"] if d["version"] != "7.2.6 (91011)"]
            for d in t["definitions"]:
                d["absoluteOrderId"] = str(int(d["absoluteOrderId"]) - 1)
        writes = len(self.w.jamf_writes())
        self.ok(only=["zoom"])
        self.assertIn("jds-ZoomWorkplace-7.2.6.91011.pkg", self.names("zoom"))
        self.assertEqual(len(self.w.jamf_writes()), writes)

    # 7: staging must be outside the share (and never Packages/ itself).
    def test_f07_staging_inside_share_rejected(self):
        raw = dict(self.w.raw_config)
        for bad in (self.w.dp, os.path.join(self.w.share, "stage")):
            with self.subTest(staging=bad):
                os.makedirs(bad, exist_ok=True)
                raw["staging_dir"] = bad
                self.w.save_config(raw)
                from jamf_dp_sync.errors import ConfigError
                with self.assertRaisesRegex(ConfigError, "inside the share"):
                    self.w.run(only=["nudge"])
                self.assertEqual([n for n in os.listdir(self.w.dp) if n.startswith("jds-")], [])

    # 10: an interrupted publish (file on DP, no record) recovers on the next run.
    def test_f10_interrupted_publish_recovers(self):
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
            self.assertIn(NUDGE, os.listdir(self.w.dp))
            self.ok(only=["nudge"])
        self.assertIn(NUDGE, self.names("nudge"))

    def test_f10_hand_file_with_agent_name_still_blocked(self):
        with open(os.path.join(self.w.dp, NUDGE), "wb") as f:
            f.write(b"not ours")
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertIn("no marked record", log)

    # 11: title mapping missed after the policy swap is completed on a later run.
    def test_f11_missing_title_mapping_is_retried(self):
        self.w.jamf.faults.append({"match": "PATCH /api/v3/patch-software-title-configurations",
                                   "status": 500, "times": 1})
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertIn(NUDGE, self.names("nudge"))
        self.ok(only=["nudge"])
        with self.w.jamf.lock:
            maps = self.w.jamf.titles[str(TITLE["nudge"])]["packages"]
        self.assertEqual([m["version"] for m in maps], ["2.1.4.81863"])

    # 12: add_if_missing counts in the "all policies hold it" check and in the dry-run preview.
    def test_f12_add_if_missing_second_policy(self):
        with self.w.jamf.lock:
            self.w.jamf.policies["110"] = make_policy(110, "second acrobat policy", [])
        self.w.edit_app("acrobat", policy_ids=[POLICY["acrobat"], 110])
        self.ok(only=["acrobat"])
        with self.w.jamf.lock:  # someone empties the second policy
            self.w.jamf.policies["110"] = make_policy(110, "second acrobat policy", [])
        self.ok(only=["acrobat"])
        with self.w.jamf.lock:
            self.assertIn("jds-AdobeAcrobatPro", self.w.jamf.policies["110"])

    def test_f12_dry_run_preview_respects_add_if_missing_false(self):
        self.w.edit_app("acrobat", add_if_missing=False)
        out, log = self.ok(only=["acrobat"], dry_run=True)
        self.assertNotIn("would swap policies %d" % POLICY["acrobat"], out)
        self.assertIn("no matching package", out)

    # 16: a failing state write while recording a failure stays inside the app boundary.
    def test_f16_state_write_failure_keeps_other_apps_running(self):
        self.w.set_upstream("dialog", "3.1.1.5000", team="XYZXYZXYZ1")   # dialog fails verification
        real = state_mod.StateStore.update

        def full_disk(self_, key, **changes):
            if key == "dialog":
                raise OSError(28, "No space left on device")
            return real(self_, key, **changes)
        with mock.patch.object(state_mod.StateStore, "update", full_disk):
            code, out, log = self.w.run(only=["dialog", "nudge"])
        self.assertEqual(code, 1)
        self.assertIn(NUDGE, self.names("nudge"))
        self.assertTrue(self.w.messages())


if __name__ == "__main__":
    unittest.main()
