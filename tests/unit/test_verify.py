"""Section 7: the ordered verification checks and fail-closed clean-up (A6, A7)."""
import hashlib
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import verify, versions
from jamf_dp_sync.errors import NotUpstreamYet, VerifyError
from tests import xarbuild
from tests.xarbuild import FIXTURES, build_xar, cert

OPENSSL = shutil.which("openssl") or "/usr/bin/openssl"
DOTTED = versions.get_rule("dotted")
REAL_NUDGE = os.path.join(FIXTURES, "real", "Nudge_Suite-2.1.4.81863.pkg")


class Verify(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def make(self, version="2.1.4.81863", certs=("synthetic_installer_T4SK8ZXCXG",)):
        p = os.path.join(self.dir, "staged.pkg")
        build_xar(p, [("Distribution", xarbuild.distribution(product=version))],
                  certs=[cert(c) for c in certs])
        with open(p, "rb") as f:
            data = f.read()
        return p, len(data), hashlib.sha256(data).hexdigest()

    def run_verify(self, path, target="2.1.4.81863", exact=True, team="T4SK8ZXCXG", **kw):
        return verify.verify_pkg(path, team, DOTTED, DOTTED.parse(target), exact, openssl=OPENSSL, **kw)

    def test_pass_with_size_and_hash(self):
        p, size, sha = self.make()
        v = self.run_verify(p, expected_size=size, expected_sha256=sha.upper())
        self.assertEqual(v.version, DOTTED.parse("2.1.4.81863"))
        self.assertEqual(v.sha256, sha)
        self.assertEqual(len(v.sha512), 128)
        self.assertTrue(os.path.exists(p))

    def test_size_mismatch_deletes(self):
        p, size, sha = self.make()
        with self.assertRaisesRegex(VerifyError, "size mismatch"):
            self.run_verify(p, expected_size=size + 1)
        self.assertFalse(os.path.exists(p))

    def test_hash_mismatch_deletes(self):
        p, size, sha = self.make()
        with self.assertRaisesRegex(VerifyError, "SHA-256 mismatch"):
            self.run_verify(p, expected_sha256="0" * 64)
        self.assertFalse(os.path.exists(p))

    def test_flipped_byte_detected_by_hash(self):
        p, size, sha = self.make()
        with open(p, "r+b") as f:
            f.seek(size // 2)
            b = f.read(1)
            f.seek(size // 2)
            f.write(bytes([b[0] ^ 1]))
        with self.assertRaises(VerifyError):
            self.run_verify(p, expected_size=size, expected_sha256=sha)
        self.assertFalse(os.path.exists(p))

    def test_not_a_pkg_deletes(self):
        p = os.path.join(self.dir, "staged.pkg")
        with open(p, "wb") as f:
            f.write(b"<html>rate limited</html>")
        with self.assertRaisesRegex(VerifyError, "not a flat pkg"):
            self.run_verify(p)
        self.assertFalse(os.path.exists(p))

    def test_wrong_team_deletes(self):
        p, _, _ = self.make()
        with self.assertRaisesRegex(VerifyError, "Team ID mismatch \\(expected PWA5E9TQ59"):
            self.run_verify(p, team="PWA5E9TQ59")
        self.assertFalse(os.path.exists(p))

    def test_unsigned_deletes(self):
        p, _, _ = self.make(certs=())
        with self.assertRaises(VerifyError):
            self.run_verify(p)
        self.assertFalse(os.path.exists(p))

    def test_v2_exact_mismatch(self):
        p, _, _ = self.make(version="2.1.5.1")
        with self.assertRaisesRegex(VerifyError, "V2"):
            self.run_verify(p)
        self.assertFalse(os.path.exists(p))

    def test_v3_newer_accepted_and_named_by_pkg(self):
        p, _, _ = self.make(version="2.1.5.1")
        v = self.run_verify(p, exact=False)
        self.assertEqual(str(v.version), "2.1.5.1")

    def test_v3_stale_is_not_upstream_yet(self):
        p, _, _ = self.make(version="2.1.3.1")
        with self.assertRaises(NotUpstreamYet):
            self.run_verify(p, exact=False)
        self.assertFalse(os.path.exists(p))

    @unittest.skipUnless(os.path.exists(REAL_NUDGE), "real Nudge Suite pkg not downloaded")
    def test_real_nudge_with_github_digest(self):
        p = os.path.join(self.dir, "staged.pkg")
        shutil.copy(REAL_NUDGE, p)
        v = self.run_verify(p, expected_size=1537619,
                            expected_sha256="731ee55c43b1fc91bd32f3a5783d439392aec4d602f7d854d89786d712e769cc")
        self.assertEqual(v.version_source, "Distribution product")


if __name__ == "__main__":
    unittest.main()
