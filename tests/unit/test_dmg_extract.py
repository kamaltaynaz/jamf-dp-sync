"""Section 6 dmg_extract with a stand-in `7zz` (the real 7zz test is D12 on the Lima VM).

The listing format is SYNTHETIC, modelled on `7zz l -slt`; replace with a recorded listing of the
real GoogleDrive.dmg when D12 runs.
"""
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import sevenzip
from jamf_dp_sync.dmg_extract import dmg_extract
from jamf_dp_sync.errors import ToolError, VerifyError
from tests.fakes import fake_7zz, slt_listing

REGEX = r"(^|/)GoogleDrive\.pkg$"


class DmgExtract(unittest.TestCase):
    def setUp(self):
        self.tools = tempfile.mkdtemp()
        self.staging = tempfile.mkdtemp()
        self.dmg = os.path.join(self.staging, "googledrive-download.dmg")
        with open(self.dmg, "wb") as f:
            f.write(b"koly-ish")

    def tearDown(self):
        shutil.rmtree(self.tools)
        shutil.rmtree(self.staging)

    def bin(self, entries, members):
        return fake_7zz(self.tools, slt_listing(self.dmg, entries), members)

    def test_extracts_one_member_and_removes_dmg(self):
        b = self.bin([("Install Google Drive", True, 0),
                      ("Install Google Drive/GoogleDrive.pkg", False, 4),
                      ("Install Google Drive/.background/bg.png", False, 1)],
                     {"Install Google Drive/GoogleDrive.pkg": b"xar!"})
        out = dmg_extract(self.dmg, REGEX, self.staging, b)
        self.assertEqual(out, self.dmg[:-4] + ".pkg")
        with open(out, "rb") as f:
            self.assertEqual(f.read(), b"xar!")
        self.assertFalse(os.path.exists(self.dmg))
        self.assertEqual(sorted(os.listdir(self.staging)), ["googledrive-download.pkg"])

    def test_zero_or_two_matches(self):
        for entries in ([("Other.pkg", False, 1)],
                        [("a/GoogleDrive.pkg", False, 1), ("b/GoogleDrive.pkg", False, 1)]):
            with self.subTest(entries=entries):
                with open(self.dmg, "wb") as f:
                    f.write(b"x")
                with self.assertRaisesRegex(VerifyError, "exactly one member"):
                    dmg_extract(self.dmg, REGEX, self.staging, self.bin(entries, {}))
                self.assertFalse(os.path.exists(self.dmg))
                self.assertEqual(os.listdir(self.staging), [])

    def test_folder_named_like_pkg_ignored(self):
        b = self.bin([("GoogleDrive.pkg", True, 0), ("x/GoogleDrive.pkg", False, 1)], {"x/GoogleDrive.pkg": b"p"})
        self.assertTrue(dmg_extract(self.dmg, REGEX, self.staging, b).endswith(".pkg"))

    def test_unsafe_paths_rejected(self):
        for bad in ("/abs/GoogleDrive.pkg", "../GoogleDrive.pkg", "a/../../GoogleDrive.pkg", "C:\\x\\GoogleDrive.pkg"):
            with self.subTest(path=bad):
                with open(self.dmg, "wb") as f:
                    f.write(b"x")
                with self.assertRaisesRegex(VerifyError, "unsafe member path"):
                    dmg_extract(self.dmg, r"GoogleDrive\.pkg$", self.staging, self.bin([(bad, False, 1)], {bad: b"p"}))

    def test_missing_7zz(self):
        with self.assertRaises(ToolError):
            dmg_extract(self.dmg, REGEX, self.staging, os.path.join(self.tools, "nope"))
        self.assertFalse(os.path.exists(self.dmg))

    def test_extract_failure_cleans_up(self):
        b = self.bin([("GoogleDrive.pkg", False, 1)], {})  # listed but extraction fails
        with self.assertRaises(ToolError):
            dmg_extract(self.dmg, REGEX, self.staging, b)
        self.assertEqual(os.listdir(self.staging), [])

    def test_parse_slt_requires_separator(self):
        with self.assertRaises(ToolError):
            sevenzip.parse_slt("Path = x\n")


if __name__ == "__main__":
    unittest.main()
