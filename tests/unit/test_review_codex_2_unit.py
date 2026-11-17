"""Unit regressions for round-two Codex findings 2, 3, 5, 9, 10, 11, 15 (REVIEW_CODEX_2.md)."""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from unittest import mock

from jamf_dp_sync import config
from jamf_dp_sync.errors import XarError
from jamf_dp_sync.xar import XarArchive
from tests.xarbuild import build_xar

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "test", "env"))
import live  # noqa: E402


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)


class StagingSymlinkEscape(Tmp):   # r2 #5
    def test_resolved_packages_elsewhere_staging_into_real_share(self):
        share = os.path.join(self.dir, "share")
        storage = os.path.join(self.dir, "storage", "Packages")
        os.makedirs(os.path.join(share, "incoming"))
        os.makedirs(storage)
        os.symlink(storage, os.path.join(share, "Packages"))
        staging = os.path.join(self.dir, "private-staging")
        os.symlink(os.path.join(share, "incoming"), staging)
        self.assertTrue(config.staging_problems(os.path.join(share, "Packages"), staging, resolve=True))


class XarBounds(Tmp):              # r2 #9 and #15
    def _toc_xar(self, toc, compress=zlib.compress, cksum_alg=0):
        c = compress(toc)
        p = os.path.join(self.dir, "t.pkg")
        with open(p, "wb") as f:
            f.write(struct.pack(">4sHHQQI", b"xar!", 28, 1, len(c), len(toc), cksum_alg) + c + b"\0" * 64)
        return p

    def test_negative_member_size_rejected(self):
        toc = (b"<?xml version='1.0'?><xar><toc><file id='1'><name>Distribution</name><type>file</type><data>"
               b"<length>4</length><offset>0</offset><size>-1</size><encoding style='application/x-gzip'/>"
               b"</data></file></toc></xar>")
        with self.assertRaisesRegex(XarError, "negative"):
            XarArchive(self._toc_xar(toc))

    def test_negative_checksum_length_rejected(self):
        toc = (b"<?xml version='1.0'?><xar><toc><checksum style='sha1'><offset>0</offset><size>-1</size>"
               b"</checksum></toc></xar>")
        with self.assertRaisesRegex(XarError, "negative|checksum"):
            XarArchive(self._toc_xar(toc, cksum_alg=1))

    def test_truncated_zlib_stream_rejected(self):
        toc = b"<?xml version='1.0'?><xar><toc></toc></xar>"
        with self.assertRaisesRegex(XarError, "TOC"):
            XarArchive(self._toc_xar(toc, compress=lambda d: zlib.compress(d)[:-4]))  # no adler32 trailer

    def test_member_decompression_is_bounded_not_after_the_fact(self):
        p = os.path.join(self.dir, "m.pkg")
        build_xar(p, [("Distribution", b"<x/>" + b" " * (2 * 1024 * 1024))])
        x = XarArchive(p)
        x.members["Distribution"].size = 10
        x.members["Distribution"].extracted_checksum = None
        with mock.patch("zlib.decompress", side_effect=AssertionError("unbounded zlib.decompress used")):
            with self.assertRaisesRegex(XarError, "larger than|size mismatch"):
                x.read("Distribution", max_size=1024 * 1024)
        x.close()


class StartupLogging(Tmp):         # r2 #10 and #11
    def _home(self, env_text, env_mode=0o600, cfg_text=None):
        home = os.path.join(self.dir, "home")
        d = os.path.join(home, ".config", "jamf-dp-sync")
        os.makedirs(d)
        with open(os.path.join(d, "env"), "w") as f:
            f.write(env_text)
        os.chmod(os.path.join(d, "env"), env_mode)
        with open(os.path.join(ROOT, "packages.example.json")) as f:
            cfg = f.read()
        with open(os.path.join(d, "packages.json"), "w") as f:
            f.write(cfg_text if cfg_text is not None else cfg.replace(
                "/srv/jamf/Packages", os.path.join(self.dir, "share", "Packages")).replace(
                "/srv/jamf-dp-sync-staging", os.path.join(self.dir, "staging")).replace(
                "~/logs/jamf-dp-sync.log", os.path.join(self.dir, "cfglog", "jds.log")))
        return home

    def _run(self, home):
        return subprocess.run([sys.executable, os.path.join(ROOT, "jamf_dp_sync.py"), "run", "--dry-run"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=dict(os.environ, HOME=home), timeout=60).returncode

    def test_secret_in_config_error_is_redacted_in_bootstrap_log(self):
        secret = "TOPSECRETVALUE1234"
        home = self._home("JAMF_URL=https://jamf.invalid\nJAMF_CLIENT_ID=a\nJAMF_CLIENT_SECRET=%s\n" % secret,
                          cfg_text='{"%s": 1}' % secret)
        self.assertEqual(self._run(home), 1)
        with open(os.path.join(home, "logs", "jamf-dp-sync.log")) as f:
            text = f.read()
        self.assertIn("unknown global key", text)
        self.assertNotIn(secret, text)

    def test_bad_secrets_permissions_reach_bootstrap_log(self):
        home = self._home("JAMF_URL=https://jamf.invalid\n", env_mode=0o644)
        self.assertEqual(self._run(home), 1)
        with open(os.path.join(home, "logs", "jamf-dp-sync.log")) as f:
            self.assertIn("chmod 600", f.read())


class LiveHarness(unittest.TestCase):   # r2 #2 and #3
    POLICY = ("<policy><general><category><id>86</id></category>"
              "<trigger_other>test-install-nudge-jsm</trigger_other></general>"
              "<scope><all_computers>false</all_computers></scope>"
              "<self_service><use_for_self_service>false</use_for_self_service></self_service></policy>")

    def test_structural_checks(self):
        self.assertEqual(live.policy_problems(self.POLICY, "nudge", 86), [])
        spaced = self.POLICY.replace("<all_computers>false", "<all_computers> true ")
        ss = self.POLICY.replace("<use_for_self_service>false", "<use_for_self_service>true")
        self.assertTrue(live.policy_problems(spaced, "nudge", 86))
        self.assertTrue(any("Self Service" in p for p in live.policy_problems(ss, "nudge", 86)))

    def test_cleanup_files_only_for_owned_records(self):
        files = ["TEST-jds-NudgeSuite-2.1.4.81863.pkg", "TEST-jds-NudgeSuite-2.1.3.1.pkg", "other.pkg"]
        owned = ["TEST-jds-NudgeSuite-2.1.3.1.pkg"]
        self.assertEqual(live.owned_files(files, owned), ["TEST-jds-NudgeSuite-2.1.3.1.pkg"])

    def test_cleanup_validates_isolation_first(self):
        self.assertIn("validate_config", live.cleanup.__code__.co_names)


if __name__ == "__main__":
    unittest.main()
