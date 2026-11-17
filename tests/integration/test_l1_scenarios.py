"""L1: every section 12 acceptance row that L1 covers, and every section 11.3 fault, against the
Jamf Pro, Google Chat and upstream stubs. Names start with the row (test_a01_...).

A15 is L0 (tests/unit/test_versions.py). A16 (monitor-only) is deferred (OPEN_QUESTIONS Q15).
A17-A19 are L2/L3.
"""
import datetime
import hashlib
import os
import unittest

from tests.integration.world import BRANDING, LEGACY, POLICY, START, TITLE, World

SYNC = ["nudge", "dialog", "acrobat", "office", "chrome", "zoom", "googledrive"]
NAMES = {"nudge": "jds-NudgeSuite-2.1.4.81863.pkg", "dialog": "jds-swiftDialog-3.1.1.pkg",
         "acrobat": "jds-AdobeAcrobatPro-26.003.22075.pkg", "office": "jds-Microsoft365-16.114.26110224.pkg",
         "chrome": "jds-GoogleChrome-142.0.7444.60.pkg", "zoom": "jds-ZoomWorkplace-7.2.5.90525.pkg",
         "googledrive": "jds-GoogleDrive-133.0.2.pkg"}


def sha512(path):
    with open(path, "rb") as f:
        return hashlib.sha512(f.read()).hexdigest()



def _staging_leftovers(staging):
    """Files left in staging after a run: anything in the scratch folder, or outside .jds-* folders."""
    out = [n for n in os.listdir(staging) if not n.startswith(".jds-")]
    scratch = os.path.join(staging, ".jds-scratch")
    if os.path.isdir(scratch):
        out += [".jds-scratch/" + n for n in os.listdir(scratch)]
    return sorted(out)


class L1(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    def first_run(self):
        code, out, log = self.w.run()
        self.assertEqual(code, 0, log[-3000:])
        return log

    def pkg_files(self):
        return sorted(n for n in os.listdir(self.w.dp) if n.startswith("jds-"))

    # ------------------------------------------------------------------ A1
    def test_a01_first_run_all_apps(self):
        self.first_run()
        self.assertEqual(self.pkg_files(), sorted(NAMES.values()))
        recs = dict((r["packageName"], r) for r in self.w.records())
        for label, name in NAMES.items():
            with self.subTest(app=label):
                path = os.path.join(self.w.dp, name)
                self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o644))
                self.assertEqual(recs[name]["hashType"], "SHA_512")
                self.assertEqual(recs[name]["hashValue"], sha512(path))
                self.assertEqual(recs[name]["notes"], "created by jamf-dp-sync")
                pk = self.w.policy_packages(label)
                self.assertIn(BRANDING, [(i, n) for i, n, _ in pk])           # other packages untouched
                self.assertIn(name, [n for _, n, _ in pk])
                if label in LEGACY:
                    self.assertNotIn(LEGACY[label][1], [n for _, n, _ in pk])  # legacy replaced
        # Hand-uploaded files and records are never touched.
        for _, name in LEGACY.values():
            self.assertTrue(os.path.exists(os.path.join(self.w.dp, name)))
            self.assertIn(name, recs)
        self.assertEqual(_staging_leftovers(self.w.staging), [])  # anchors stay (r4 #2); scratch folder (r7 #1)
        # D15: mapped to the title version.
        with self.w.jamf.lock:
            t = self.w.jamf.titles[str(TITLE["zoom"])]
        self.assertEqual(t["packages"][0]["version"], "7.2.5 (90525)")

    # ------------------------------------------------------------------ A2
    def test_a02_second_run_nothing_new(self):
        self.first_run()
        downloads = self.w.up.count(method="GET", suffix=".pkg") + self.w.up.count(method="GET", suffix=".dmg")
        writes = len(self.w.jamf_writes())
        messages = len(self.w.messages())
        code, out, log = self.w.run()
        self.assertEqual(code, 0)
        self.assertEqual(self.w.up.count(method="GET", suffix=".pkg") + self.w.up.count(method="GET", suffix=".dmg"),
                         downloads)
        self.assertEqual(len(self.w.jamf_writes()), writes)
        self.assertEqual(len(self.w.messages()), messages)

    # ------------------------------------------------------------------ A3
    def test_a03_patch_title_newer(self):
        self.first_run()
        self.w.set_upstream("nudge", "2.1.5.81902")
        self.w.set_title("nudge", "2.1.5.81902")
        self.w.set_upstream("chrome", "143.0.7500.1")      # latest-only: CDN may be ahead of the title
        self.w.set_title("chrome", "142.0.7444.99")
        code, out, log = self.w.run()
        self.assertEqual(code, 0, log[-2000:])
        self.assertIn("jds-NudgeSuite-2.1.5.81902.pkg", [n for _, n, _ in self.w.policy_packages("nudge")])
        self.assertIn("jds-GoogleChrome-143.0.7500.1.pkg", [n for _, n, _ in self.w.policy_packages("chrome")])
        msg = self.w.messages()[-1]["text"]
        self.assertIn("nudge    2.1.4.81863 → 2.1.5.81902", msg)

    # ------------------------------------------------------------------ A4
    def test_a04_upstream_newer_than_title(self):
        self.first_run()
        self.w.set_upstream("nudge", "2.1.9.99999")
        self.w.set_upstream("chrome", "150.0.1.1")
        writes = len(self.w.jamf_writes())
        code, out, log = self.w.run()
        self.assertEqual(code, 0)
        self.assertEqual(len(self.w.jamf_writes()), writes)
        self.assertNotIn("jds-NudgeSuite-2.1.9.99999.pkg", os.listdir(self.w.dp))

    # ------------------------------------------------------------------ A5
    def test_a05_not_yet_upstream_then_alert(self):
        self.first_run()
        self.w.set_title("nudge", "2.1.6.82000")  # no such GitHub release
        day0 = datetime.datetime(2026, 11, 10, 3, 20)
        code, out, log = self.w.run(now=day0)
        self.assertEqual(code, 0)                  # a skip is not an error
        n = len(self.w.messages())
        self.w.run(now=day0 + datetime.timedelta(days=1))
        self.assertEqual(len(self.w.messages()), n)  # still inside alert_after_days
        self.w.run(now=day0 + datetime.timedelta(days=3))
        self.assertIn("2.1.6.82000", self.w.messages()[-1]["text"])
        self.assertIn("waiting 3 days", self.w.messages()[-1]["text"])
        n = len(self.w.messages())
        self.w.run(now=day0 + datetime.timedelta(days=3, hours=5))
        self.assertEqual(len(self.w.messages()), n)  # once a day
        self.w.run(now=day0 + datetime.timedelta(days=4))
        self.assertEqual(len(self.w.messages()), n + 1)

    def test_a05_fault_patch_ahead_and_template_404(self):
        code, out, log = self.w.run(faults="patch_ahead,template_404", only=["nudge", "zoom"])
        self.assertEqual(code, 0, log[-2000:])
        self.assertEqual(self.pkg_files(), [])
        self.assertIn("nudge: skipped", log)
        self.assertIn("zoom: skipped", log)

    def test_a05_zoom_cloudflare_403_is_not_yet(self):
        self.w.set_title("zoom", "7.2.6 (91011)")  # stub answers 403 for unknown Zoom versions (F2)
        code, out, log = self.w.run(only=["zoom"])
        self.assertEqual(code, 0)
        self.assertIn("HTTP 403", log)

    # ------------------------------------------------------------------ A6
    def test_a06_wrong_team_id(self):
        self.w.set_upstream("nudge", "2.1.4.81863", team="XYZXYZXYZ1")
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertEqual(self.pkg_files(), [])
        self.assertEqual(_staging_leftovers(self.w.staging), [])  # anchors stay (r4 #2); scratch folder (r7 #1)
        self.assertIn("*FAIL* nudge    verify: Team ID mismatch (expected T4SK8ZXCXG", self.w.messages()[-1]["text"])

    def test_a06_fault_wrong_team(self):
        code, out, log = self.w.run(faults="wrong_team", only=["chrome"])
        self.assertEqual(code, 1)
        self.assertEqual(self.pkg_files(), [])

    # ------------------------------------------------------------------ A7
    def test_a07_flipped_byte_hash_mismatch(self):
        code, out, log = self.w.run(faults="flip_byte", only=["nudge", "acrobat"])
        self.assertEqual(code, 1)
        self.assertEqual(self.pkg_files(), [])
        self.assertEqual(_staging_leftovers(self.w.staging), [])  # anchors stay (r4 #2); scratch folder (r7 #1)
        text = self.w.messages()[-1]["text"]
        self.assertIn("nudge    verify: SHA-256 mismatch", text)
        self.assertIn("acrobat  verify: SHA-256 mismatch", text)
        self.assertEqual(self.w.jamf_writes(), [])

    # ------------------------------------------------------------------ A8
    def test_a08_github_rate_limited(self):
        code, out, log = self.w.run(faults="github_403", only=["nudge", "dialog"])
        self.assertEqual(code, 0, log[-2000:])
        self.assertEqual(self.pkg_files(), sorted([NAMES["nudge"], NAMES["dialog"]]))
        self.assertIn("HTML fallback", log)

    # ------------------------------------------------------------------ A9
    def test_a09_pin_rolls_back(self):
        self.first_run()
        self.w.set_upstream("nudge", "2.1.5.81902")
        self.w.set_title("nudge", "2.1.5.81902")
        self.w.run()
        gets = self.w.up.count(method="GET", suffix=".pkg")
        self.w.edit_app("nudge", pin="2.1.4.81863")
        code, out, log = self.w.run()
        self.assertEqual(code, 0, log[-2000:])
        names = [n for _, n, _ in self.w.policy_packages("nudge")]
        self.assertIn(NAMES["nudge"], names)
        self.assertNotIn("jds-NudgeSuite-2.1.5.81902.pkg", names)
        self.assertEqual(self.w.up.count(method="GET", suffix=".pkg"), gets)  # retained: no download

    # ----------------------------------------------------------------- A10
    def test_a10_prune_keeps_retain_newest_plus_current(self):
        self.first_run()
        for v in ("2.1.5.1", "2.1.6.1", "2.1.7.1"):
            self.w.set_upstream("nudge", v)
            self.w.set_title("nudge", v)
            code, out, log = self.w.run(only=["nudge"])
            self.assertEqual(code, 0, log[-2000:])
        files = [n for n in self.pkg_files() if "NudgeSuite" in n]
        self.assertEqual(files, ["jds-NudgeSuite-2.1.6.1.pkg", "jds-NudgeSuite-2.1.7.1.pkg"])
        recs = [r["packageName"] for r in self.w.records()]
        self.assertNotIn(NAMES["nudge"], recs)
        self.assertIn(LEGACY["nudge"][1], recs)                        # never non-agent names
        self.assertTrue(os.path.exists(os.path.join(self.w.dp, LEGACY["nudge"][1])))

    def test_a10_no_prune_flag(self):
        self.first_run()
        for v in ("2.1.5.1", "2.1.6.1"):
            self.w.set_upstream("nudge", v)
            self.w.set_title("nudge", v)
            self.w.run(only=["nudge"], no_prune=True)
        self.assertEqual(len([n for n in self.pkg_files() if "NudgeSuite" in n]), 3)

    # ----------------------------------------------------------------- A11
    def test_a11_concurrent_start(self):
        from jamf_dp_sync.lock import RunLock
        with self.w.environment():
            lock = RunLock(os.path.join(self.w.dir, "state", "run.lock"))
            self.assertTrue(lock.acquire())
            try:
                p = self.w.cli("run")
            finally:
                lock.release()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b"holds", p.stderr)
        self.assertEqual(self.pkg_files(), [])

    def test_a11_fault_lock_held(self):
        code, out, log = self.w.run(faults="lock_held")
        self.assertEqual(code, 0)
        self.assertIn("holds", log)

    # ----------------------------------------------------------------- A12
    def test_a12_dry_run(self):
        state_dir = os.path.join(self.w.home, ".local", "state", "jamf-dp-sync")
        code, out, log = self.w.run(dry_run=True)
        self.assertEqual(code, 0, log[-2000:])
        self.assertEqual(self.pkg_files(), [])
        self.assertEqual(self.w.jamf_writes(), [])
        self.assertEqual(self.w.messages(), [])
        self.assertEqual(_staging_leftovers(self.w.staging), [])  # anchors stay (r4 #2); scratch folder (r7 #1)
        self.assertFalse(os.path.exists(state_dir) and os.listdir(state_dir))
        for name in NAMES.values():
            self.assertIn("would publish %s" % name, out)

    # ----------------------------------------------------------------- A13
    def test_a13_acrobat_manifest(self):
        code, out, log = self.w.run(only=["acrobat"])
        self.assertEqual(code, 0, log[-2000:])
        self.assertEqual(self.pkg_files(), [NAMES["acrobat"]])
        self.assertEqual(self.w.up.count(suffix="_incr.pkg"), 0)  # never the patch item

    # ----------------------------------------------------------------- A14
    def test_a14_google_drive_dmg(self):
        code, out, log = self.w.run(only=["googledrive"])
        self.assertEqual(code, 0, log[-2000:])
        self.assertEqual(self.pkg_files(), [NAMES["googledrive"]])
        with open(os.path.join(self.w.dp, NAMES["googledrive"]), "rb") as f:
            self.assertEqual(f.read(4), b"xar!")

    def test_a14_fault_no_7zz(self):
        code, out, log = self.w.run(faults="no_7zz")
        self.assertEqual(code, 1)
        self.assertIn("7zz not found", log)
        self.assertEqual(self.pkg_files(), [])
        self.assertIn("preflight", self.w.messages()[-1]["text"])

    # ------------------------------------------------------- §11.3 preflight
    def test_preflight_faults_abort_before_any_app(self):
        for fault, text in (("dp_not_writable", "not writable"), ("staging_other_fs", "same filesystem")):
            with self.subTest(fault=fault):
                code, out, log = self.w.run(faults=fault)
                self.assertEqual(code, 1)
                self.assertIn(text, log)
                self.assertEqual(self.w.jamf_writes(), [])
                self.assertIn("*FAIL* preflight", self.w.messages()[-1]["text"])

    # ------------------------------------------------- per-app isolation (§9)
    def test_one_failure_does_not_stop_others(self):
        self.w.set_upstream("dialog", "3.1.1.5000", team="XYZXYZXYZ1")
        code, out, log = self.w.run()
        self.assertEqual(code, 1)
        self.assertEqual(len(self.pkg_files()), 6)
        self.assertNotIn(NAMES["dialog"], self.pkg_files())

    # ----------------------------------------------------------------- A20
    def test_a20_no_sudo_anywhere(self):
        root = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                            "jamf_dp_sync")
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.endswith(".py"):
                    with open(os.path.join(dirpath, f)) as fh:
                        self.assertNotIn("sudo", fh.read(), f)

    # ----------------------------------------------------------------- A21
    def test_a21_notifications(self):
        self.first_run()
        msgs = self.w.messages()
        self.assertEqual(len(msgs), 1)                             # one summary per run
        text = msgs[0]["text"]
        self.assertTrue(text.startswith("[") and "jamf-dp-sync · 2026-11-10 03:20" in text)
        self.assertIn("*OK*   nudge    Nudge_Suite-2.1.2.81856.pkg → 2.1.4.81863   policy %d" % POLICY["nudge"], text)
        self.assertIn("*OK*   acrobat  none → 26.003.22075", text)
        self.assertIsNone(msgs[0]["threadKey"])                   # top-level (2026-11-17)
        self.w.run()                                                # no change: nothing sent
        self.assertEqual(len(self.w.messages()), 1)
        monday = datetime.datetime(2026, 11, 16, 3, 20)
        self.w.run(now=monday)
        hb = self.w.messages()[-1]["text"]
        self.assertIn("*Heartbeat* 7/7 apps current", hb)
        self.assertIn("last publish 2026-11-10", hb)
        self.w.run(now=monday + datetime.timedelta(hours=1))         # first run each Monday only
        self.assertEqual(len(self.w.messages()), 2)

    # ----------------------------------------------------------------- A22
    def test_a22_webhook_down_keeps_exit_code(self):
        code, out, log = self.w.run(faults="webhook_down", only=["nudge"])
        self.assertEqual(code, 0)
        self.assertEqual(self.pkg_files(), [NAMES["nudge"]])
        self.assertIn("Chat notification failed", log)
        for secret in ("KEYL1", "TOKL1", "spaces/L1", "ghp_l1test", "stub-secret"):
            self.assertNotIn(secret, log)

    def test_a22_webhook_429_retried(self):
        self.w.chat.mode, self.w.chat.fail_count = "429-then-ok", 2
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 0)
        self.assertEqual(len(self.w.messages()), 1)
        self.assertEqual(self.w.chat.attempts, 3)

    # ------------------------------------------------------- Q6 collision guard
    def test_collision_guard_refuses_unmarked_agent_name(self):
        with open(os.path.join(self.w.dp, NAMES["zoom"]), "wb") as f:
            f.write(b"hand-made file with an agent-looking name")
        code, out, log = self.w.run(only=["zoom"])
        self.assertEqual(code, 1)
        self.assertIn("no marked record", log)

    def test_l2_regression_title_version_already_mapped_elsewhere(self):
        # dev Jamf: a hand-made package already holds the title version (DECISIONS F8).
        with self.w.jamf.lock:
            self.w.jamf.titles[str(TITLE["nudge"])]["packages"] = [
                {"packageId": "200", "version": "2.1.4.81863", "displayName": LEGACY["nudge"][1]}]
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 0, log[-2000:])
        self.assertIn(NAMES["nudge"], [n for _, n, _ in self.w.policy_packages("nudge")])
        with self.w.jamf.lock:
            maps = self.w.jamf.titles[str(TITLE["nudge"])]["packages"]
        self.assertEqual([m["packageId"] for m in maps], ["200"])     # left alone
        self.assertIn("already mapped", self.w.messages()[-1]["text"])

    def test_l2_regression_stale_cdn_twice(self):
        # dev Jamf: Chrome title ahead of the stable pkg; the second run crashed on the cached version.
        self.w.set_title("chrome", "158.0.8127.18")
        for _ in range(3):
            code, out, log = self.w.run(only=["chrome"])
            self.assertEqual(code, 0, log[-1500:])
        self.assertIn("unchanged since last run (still 142.0.7444.60)", log)
        self.assertNotIn("ValueError", log)

    def test_monitor_apps_deferred(self):
        code, out, log = self.w.run(only=["sensor", "vpnclient"])
        self.assertEqual(code, 0)
        self.assertIn("deferred", log)
        self.assertEqual(self.w.jamf_writes(), [])


if __name__ == "__main__":
    unittest.main()
