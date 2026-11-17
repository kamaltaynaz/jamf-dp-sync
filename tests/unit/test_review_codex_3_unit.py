"""Unit regressions for round-three Codex findings 6, 7, 10, 11 (REVIEW_CODEX_3.md)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from jamf_dp_sync import secrets
from jamf_dp_sync.errors import SecretsError

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "test", "env"))
import live  # noqa: E402
import real_smoke  # noqa: E402


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        secrets._reset_for_tests()
        shutil.rmtree(self.dir)


class SecretDiagnostics(Tmp):          # r3 #10
    def test_parse_errors_never_quote_input(self):
        for text in ("JAMF_URL=x\nSUPERSECRETKEYTEXT=1\n", "JAMF_URL=x\nSUPERSECRETLINE_WITHOUT_EQUALS\n"):
            with self.assertRaises(SecretsError) as cm:
                secrets.parse_env(text)
            self.assertNotIn("SUPERSECRET", str(cm.exception))
            self.assertIn("line 2", str(cm.exception))

    def _home(self, env_text, cfg=None, log_file=None):
        home = os.path.join(self.dir, "home")
        d = os.path.join(home, ".config", "jamf-dp-sync")
        os.makedirs(d)
        with open(os.path.join(d, "env"), "w") as f:
            f.write(env_text)
        os.chmod(os.path.join(d, "env"), 0o600)
        with open(os.path.join(ROOT, "packages.example.json")) as f:
            raw = json.load(f)
        os.makedirs(os.path.join(self.dir, "share", "Packages"))
        os.makedirs(os.path.join(self.dir, "staging"))
        raw.update(dp_packages_dir=os.path.join(self.dir, "share", "Packages"),
                   staging_dir=os.path.join(self.dir, "staging"),
                   log_file=log_file or os.path.join(self.dir, "logs", "jds.log"))
        with open(os.path.join(d, "packages.json"), "w") as f:
            f.write(cfg if cfg is not None else json.dumps(raw))
        return home

    def run_cli(self, home, *argv):
        return subprocess.run([sys.executable, os.path.join(ROOT, "jamf_dp_sync.py")] + list(argv),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                              env=dict(os.environ, HOME=home), timeout=60)

    def test_bad_env_key_not_in_bootstrap_log_or_stderr(self):
        home = self._home("JAMF_URL=https://jamf.invalid\nSUPERSECRETKEYTEXT=1\n")
        p = self.run_cli(home, "run", "--dry-run")
        self.assertEqual(p.returncode, 1)
        with open(os.path.join(home, "logs", "jamf-dp-sync.log")) as f:
            self.assertNotIn("SUPERSECRETKEYTEXT", f.read())
        self.assertNotIn("SUPERSECRETKEYTEXT", p.stderr)

    def test_check_config_redacts_secret_in_config_error(self):
        secret = "TOPSECRETVALUE9876"
        home = self._home("JAMF_URL=https://jamf.invalid\nJAMF_CLIENT_ID=a\nJAMF_CLIENT_SECRET=%s\n" % secret,
                          cfg='{"%s": 1}' % secret)
        p = self.run_cli(home, "check-config")
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn(secret, p.stdout + p.stderr)


class LogSetupFailure(Tmp):            # r3 #11
    def test_unwritable_configured_log_is_reported_in_bootstrap_log(self):
        bad = os.path.join(self.dir, "a-directory")
        os.makedirs(bad)
        home = SecretDiagnostics._home(self, "JAMF_URL=https://jamf.invalid\n", log_file=bad)
        p = SecretDiagnostics.run_cli(self, home, "run", "--dry-run")
        self.assertEqual(p.returncode, 1)
        with open(os.path.join(home, "logs", "jamf-dp-sync.log")) as f:
            self.assertIn("cannot open log file", f.read())


class HarnessOwnership(Tmp):           # r3 #6 and #7
    def entry_for(self, path, sha="ab" * 64):
        st = os.stat(path)
        self.anchors = os.path.join(self.dir, ".jds-owned")       # round four #2: anchored identity
        if not os.path.isdir(self.anchors):
            os.makedirs(self.anchors, 0o700)
            os.chmod(self.anchors, 0o700)   # as the agent makes it (RHEL umask is 0002; round nine #1)
        os.link(path, os.path.join(self.anchors, "%d-%d" % (st.st_dev, st.st_ino)))
        return {"label": "nudge", "sha512": sha, "state": "published", "dev": st.st_dev, "ino": st.st_ino}

    def test_smoke_deletes_only_files_it_published(self):
        mine = os.path.join(self.dir, "jds-NudgeSuite-1.pkg")
        other = os.path.join(self.dir, "Manual-Upload.pkg")
        for p in (mine, other):
            with open(p, "wb") as f:
                f.write(b"x")
        entries = {"jds-NudgeSuite-1.pkg": self.entry_for(mine)}
        self.assertEqual(real_smoke.owned_new_files(["jds-NudgeSuite-1.pkg", "Manual-Upload.pkg"], entries, self.dir,
                                                       self.anchors), ["jds-NudgeSuite-1.pkg"])

    def test_live_selects_only_test_category_and_consistent_names(self):
        from jamf_dp_sync.jamf.client import AGENT_MARKER
        recs = [{"id": "1", "packageName": "TEST-jds-NudgeSuite-1.pkg", "fileName": "TEST-jds-NudgeSuite-1.pkg",
                 "categoryId": "86", "notes": AGENT_MARKER},
                {"id": "2", "packageName": "TEST-jds-NudgeSuite-2.pkg", "fileName": "Different.pkg",
                 "categoryId": "86", "notes": AGENT_MARKER},
                {"id": "3", "packageName": "TEST-jds-NudgeSuite-3.pkg", "fileName": "TEST-jds-NudgeSuite-3.pkg",
                 "categoryId": "99", "notes": AGENT_MARKER}]
        self.assertEqual([r["id"] for r in live.select_owned(recs, ["TEST-jds-NudgeSuite"], 86)], ["1"])

    def test_live_deletes_file_only_with_ownership_proof(self):
        mine = os.path.join(self.dir, "TEST-jds-NudgeSuite-1.pkg")
        manual = os.path.join(self.dir, "TEST-jds-NudgeSuite-2.pkg")
        for p in (mine, manual):
            with open(p, "wb") as f:
                f.write(b"x")
        entries = {"TEST-jds-NudgeSuite-1.pkg": self.entry_for(mine)}
        self.assertEqual(live.deletable_files(["TEST-jds-NudgeSuite-1.pkg", "TEST-jds-NudgeSuite-2.pkg"],
                                              entries, self.dir, self.anchors), ["TEST-jds-NudgeSuite-1.pkg"])


if __name__ == "__main__":
    unittest.main()
