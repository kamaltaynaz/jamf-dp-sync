"""Section 9 preflight, including the §11.3 faults it owns."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from jamf_dp_sync import config, preflight
from tests.unit.test_lock_state_faults import Env

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Preflight(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.dp = os.path.join(self.dir, "share", "Packages")
        self.staging = os.path.join(self.dir, "staging")
        os.makedirs(self.dp)
        os.makedirs(self.staging)
        tools = os.path.join(self.dir, "bin")
        os.makedirs(tools)
        for t in ("openssl", "7zz"):
            p = os.path.join(tools, t)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(p, 0o755)
        with open(os.path.join(ROOT, "packages.example.json")) as f:
            raw = json.load(f)
        with open(os.path.join(ROOT, "tests", "fixtures", "googledrive_app.json")) as f:
            raw["apps"].append(json.load(f))  # a dmg_extract app, as before D12
        raw.update(dp_packages_dir=self.dp, staging_dir=self.staging,
                   tools={"openssl": os.path.join(tools, "openssl"), "7zz": os.path.join(tools, "7zz")})
        self.cfg = config.validate(raw)

    def tearDown(self):
        os.chmod(self.dp, 0o755)
        shutil.rmtree(self.dir)

    def test_ok(self):
        with mock.patch.object(preflight, "MIN_FREE", 1):
            self.assertEqual(preflight.check(self.cfg), [])

    def test_dp_not_writable(self):
        os.chmod(self.dp, 0o555)
        if os.access(self.dp, os.W_OK):
            self.skipTest("running as root")
        self.assertIn("not writable", " ".join(preflight.check(self.cfg)))

    def test_faults(self):
        for fault, text in (("dp_not_writable", "not writable"), ("staging_other_fs", "same filesystem"),
                            ("no_7zz", "7zz not found")):
            with self.subTest(fault=fault), Env(JDS_TEST_FAULTS=fault):
                with mock.patch.object(preflight, "MIN_FREE", 1):
                    self.assertIn(text, " ".join(preflight.check(self.cfg)))

    def test_7zz_only_when_needed(self):
        os.unlink(self.cfg.tool("7zz"))
        with mock.patch.object(preflight, "MIN_FREE", 1):
            self.assertIn("7zz not found", " ".join(preflight.check(self.cfg)))
            no_drive = [a for a in self.cfg.apps if a["label"] != "googledrive"]
            self.assertEqual(preflight.check(self.cfg, apps=no_drive), [])

    def test_missing_dirs_and_openssl(self):
        shutil.rmtree(self.staging)
        os.unlink(self.cfg.tool("openssl"))
        msg = " ".join(preflight.check(self.cfg))
        self.assertIn("staging", msg)
        self.assertIn("openssl not found", msg)

    def test_staging_symlink_into_share_rejected(self):
        # Config validation compares paths as written; preflight follows symlinks (review #7).
        inside = os.path.join(os.path.dirname(self.dp), "stage-real")
        os.makedirs(inside)
        link = os.path.join(self.dir, "staging-link")
        os.symlink(inside, link)
        self.cfg.settings["staging_dir"] = link
        with mock.patch.object(preflight, "MIN_FREE", 1):
            self.assertIn("inside the share", " ".join(preflight.check(self.cfg)))

    def test_free_space(self):
        with mock.patch.object(preflight, "MIN_FREE", 1 << 62):
            self.assertIn("GiB free", " ".join(preflight.check(self.cfg)))


if __name__ == "__main__":
    unittest.main()
