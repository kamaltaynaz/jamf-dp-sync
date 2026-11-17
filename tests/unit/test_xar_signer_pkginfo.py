"""Section 7 checks 3-5: xar reader, signer identity, pkg version.

Uses synthetic xars (tests/xarbuild.py) everywhere, the real Adobe .arm (committed), and the real
Nudge Suite pkg when it is present in the gitignored tests/fixtures/real/.
"""
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import pkginfo, signer
from jamf_dp_sync.errors import VerifyError, XarError
from jamf_dp_sync.xar import XarArchive, is_xar
from tests import xarbuild
from tests.xarbuild import FIXTURES, build_xar, cert

OPENSSL = shutil.which("openssl") or "/usr/bin/openssl"
REAL_NUDGE = os.path.join(FIXTURES, "real", "Nudge_Suite-2.1.4.81863.pkg")
ARM = os.path.join(FIXTURES, "acrobat", "AcrobatManifest.arm")


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def path(self, name):
        return os.path.join(self.dir, name)


class XarReader(Tmp):
    def test_round_trip_gzip_and_bzip2_and_raw(self):
        for enc in ("application/x-gzip", "application/x-bzip2", "application/octet-stream"):
            with self.subTest(encoding=enc):
                p = build_xar(self.path("a.pkg"), [("Distribution", b"<x/>"), ("a.pkg/PackageInfo", b"<y/>")],
                              encoding=enc)
                with XarArchive(p) as x:
                    self.assertEqual(x.names(), ["Distribution", "a.pkg", "a.pkg/PackageInfo"])
                    self.assertEqual(x.members["a.pkg"].type, "directory")
                    self.assertEqual(x.read("a.pkg/PackageInfo"), b"<y/>")

    def test_not_xar(self):
        p = self.path("x.dmg")
        with open(p, "wb") as f:
            f.write(b"koly" + b"\0" * 100)
        self.assertFalse(is_xar(p))
        with self.assertRaises(XarError):
            XarArchive(p)

    def test_truncated(self):
        p = build_xar(self.path("a.pkg"), [("Distribution", b"<x/>")])
        with open(p, "rb") as f:
            data = f.read()
        with open(p, "wb") as f:
            f.write(data[:40])
        with self.assertRaises(XarError):
            XarArchive(p)

    def test_toc_checksum_mismatch(self):
        p = build_xar(self.path("a.pkg"), [("Distribution", b"<x/>")], corrupt="toc_checksum")
        with self.assertRaisesRegex(XarError, "TOC checksum mismatch"):
            XarArchive(p)

    def test_member_checksum_mismatch(self):
        p = build_xar(self.path("a.pkg"), [("Distribution", b"<x/>")], corrupt="member_checksum")
        with XarArchive(p) as x:
            with self.assertRaisesRegex(XarError, "extracted checksum mismatch"):
                x.read("Distribution")

    def test_flipped_heap_byte(self):
        p = build_xar(self.path("a.pkg"), [("Distribution", b"<x>" + b"a" * 200 + b"</x>")], encoding="application/octet-stream")
        with open(p, "r+b") as f:
            f.seek(-10, 2)
            b = f.read(1)
            f.seek(-10, 2)
            f.write(bytes([b[0] ^ 0xFF]))
        with XarArchive(p) as x:
            with self.assertRaisesRegex(XarError, "archived checksum mismatch"):
                x.read("Distribution")

    def test_member_size_limit(self):
        p = build_xar(self.path("a.pkg"), [("Payload", b"x" * 5000)])
        with XarArchive(p) as x:
            with self.assertRaises(XarError):
                x.read("Payload", max_size=1000)

    def test_doctype_in_toc_rejected(self):
        # A TOC with a DOCTYPE never reaches expat.
        import struct, zlib, hashlib
        toc = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><xar><toc/></xar>'
        c = zlib.compress(toc)
        p = self.path("evil.pkg")
        with open(p, "wb") as f:
            f.write(struct.pack(">4sHHQQI", b"xar!", 28, 1, len(c), len(toc), 0) + c)
        with self.assertRaises(XarError):
            XarArchive(p)

    def test_unsigned_has_no_certs(self):
        p = build_xar(self.path("a.pkg"), [("Distribution", b"<x/>")])
        with XarArchive(p) as x:
            self.assertEqual(x.certificates(), [])

    def test_real_adobe_arm(self):
        with XarArchive(ARM) as x:
            self.assertIn("ASSET/AcrobatManifest.xml", x.members)
            with open(os.path.join(FIXTURES, "acrobat", "AcrobatManifest.xml"), "rb") as f:
                self.assertEqual(x.read("ASSET/AcrobatManifest.xml"), f.read())
            self.assertEqual(len(x.certificates()), 3)


class Signer(Tmp):
    def test_rfc2253_parser(self):
        rdns = signer.parse_rfc2253(
            r"subject=C=US,O=Foo\, Inc.,OU=ABCDE12345,CN=Developer ID Installer: Foo\, Inc. (ABCDE12345)")
        self.assertIn(("CN", "Developer ID Installer: Foo, Inc. (ABCDE12345)"), rdns)
        # OpenSSL 1.0.x prints "subject= " with a space; hex escapes for UTF-8
        rdns = signer.parse_rfc2253(r"subject= CN=Caf\C3\A9,OU=X")
        self.assertEqual(rdns, [("CN", u"Café"), ("OU", "X")])

    def test_real_certs(self):
        self.assertEqual(signer.check_installer_identity(cert("nudge_leaf_T4SK8ZXCXG"), "T4SK8ZXCXG", OPENSSL),
                         "Developer ID Installer: Mac Admins Open Source (T4SK8ZXCXG)")
        signer.check_installer_identity(cert("adobe_leaf_JQ525L2MZD"), "JQ525L2MZD", OPENSSL)

    def test_wrong_team(self):
        with self.assertRaisesRegex(VerifyError, "Team ID mismatch \\(expected PWA5E9TQ59"):
            signer.check_installer_identity(cert("nudge_leaf_T4SK8ZXCXG"), "PWA5E9TQ59", OPENSSL)

    def test_application_cert_rejected(self):
        with self.assertRaisesRegex(VerifyError, "not a Developer ID Installer"):
            signer.check_installer_identity(cert("synthetic_application_T4SK8ZXCXG"), "T4SK8ZXCXG", OPENSSL)

    def test_cn_and_ou_must_agree(self):
        with self.assertRaisesRegex(VerifyError, "Team ID mismatch"):
            signer.check_installer_identity(cert("synthetic_installer_cn_ou_disagree"), "T4SK8ZXCXG", OPENSSL)

    def test_escaped_comma_in_org(self):
        signer.check_installer_identity(cert("synthetic_installer_comma_ABCDE12345"), "ABCDE12345", OPENSSL)

    def test_xar_signer_uses_leaf(self):
        p = build_xar(self.path("a.pkg"), [("Distribution", b"<x/>")],
                      certs=[cert("synthetic_installer_T4SK8ZXCXG"), cert("adobe_leaf_JQ525L2MZD")])
        with XarArchive(p) as x:
            signer.check_xar_signer(x, "T4SK8ZXCXG", OPENSSL)
            with self.assertRaises(VerifyError):
                signer.check_xar_signer(x, "JQ525L2MZD", OPENSSL)

    def test_unsigned(self):
        p = build_xar(self.path("a.pkg"), [("Distribution", b"<x/>")])
        with XarArchive(p) as x:
            with self.assertRaisesRegex(VerifyError, "not signed"):
                signer.check_xar_signer(x, "T4SK8ZXCXG", OPENSSL)

    def test_garbage_cert(self):
        with self.assertRaises(VerifyError):
            signer.check_installer_identity(b"not a certificate", "T4SK8ZXCXG", OPENSSL)

    def test_missing_openssl(self):
        from jamf_dp_sync.errors import ToolError
        with self.assertRaises(ToolError):
            signer.check_installer_identity(cert("nudge_leaf_T4SK8ZXCXG"), "T4SK8ZXCXG", self.path("no-openssl"))


class PkgVersion(Tmp):
    def version_of(self, files):
        p = build_xar(self.path("v.pkg"), files)
        with XarArchive(p) as x:
            return pkginfo.read_version(x)

    def test_product_first(self):
        d = xarbuild.distribution(product="2.0", pkgref="1.0")
        self.assertEqual(self.version_of([("Distribution", d), ("a.pkg/PackageInfo", xarbuild.package_info("0.9"))]),
                         ("2.0", "Distribution product"))

    def test_first_versioned_pkg_ref(self):
        d = xarbuild.distribution(product=None, pkgref="1.5")
        self.assertEqual(self.version_of([("Distribution", d)]), ("1.5", "Distribution pkg-ref"))

    def test_packageinfo_fallback(self):
        self.assertEqual(self.version_of([("PackageInfo", xarbuild.package_info("3.1"))]), ("3.1", "PackageInfo"))
        self.assertEqual(self.version_of([("b.pkg/PackageInfo", xarbuild.package_info("3.2"))]),
                         ("3.2", "b.pkg/PackageInfo"))

    def test_no_version(self):
        with self.assertRaises(VerifyError):
            self.version_of([("Payload", b"x")])

    def test_nudge_fixture_files(self):
        with open(os.path.join(FIXTURES, "nudge", "Distribution"), "rb") as f:
            dist = f.read()
        self.assertEqual(self.version_of([("Distribution", dist)]), ("2.1.4.81863", "Distribution product"))


@unittest.skipUnless(os.path.exists(REAL_NUDGE), "real Nudge Suite pkg not downloaded (tests/fixtures/real/)")
class RealNudgePkg(unittest.TestCase):
    def test_reads_and_identifies(self):
        with XarArchive(REAL_NUDGE) as x:
            with open(os.path.join(FIXTURES, "nudge", "toc.xml"), "rb") as f:
                self.assertEqual(x.toc_xml, f.read())
            self.assertEqual(signer.check_xar_signer(x, "T4SK8ZXCXG", OPENSSL),
                             "Developer ID Installer: Mac Admins Open Source (T4SK8ZXCXG)")
            self.assertEqual(pkginfo.read_version(x), ("2.1.4.81863", "Distribution product"))


if __name__ == "__main__":
    unittest.main()
