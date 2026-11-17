"""Section 6 resolvers with recorded responses (A8 HTML fallback, A13 Acrobat item selection).

Recorded real data: tests/fixtures/github/nudge_* (2026-11-09) and tests/fixtures/acrobat/*.
Synthetic shapes (marked): swiftDialog release JSON, Office final URL, redirect chains.
"""
import json
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import versions
from jamf_dp_sync.errors import NotUpstreamYet, ResolveError
from jamf_dp_sync.resolvers import Context, adobe_arm, github_tag, latest_redirect, url_template
from tests.fakes import FakeHttp, ListLog, fake_7zz, slt_listing
from tests.xarbuild import FIXTURES, build_xar, cert

OPENSSL = shutil.which("openssl") or "/usr/bin/openssl"

NUDGE_JSON = os.path.join(FIXTURES, "github", "nudge_release_v2.1.4.81863.json")
NUDGE_HTML = os.path.join(FIXTURES, "github", "nudge_expanded_assets_v2.1.4.81863.html")
ACROBAT_XML = os.path.join(FIXTURES, "acrobat", "AcrobatManifest.xml")
ACROBAT_ARM = os.path.join(FIXTURES, "acrobat", "AcrobatManifest.arm")

NUDGE = {"label": "nudge", "resolver": "github_tag", "repo": "macadmins/nudge",
         "asset_regex": r"^Nudge_Suite-[0-9.]+\.pkg$", "team_id": "T4SK8ZXCXG"}
DIALOG = {"label": "dialog", "resolver": "github_tag", "repo": "swiftDialog/swiftDialog",
          "asset_regex": r"^dialog-[0-9.]+-[0-9]+\.pkg$", "team_id": "PWA5E9TQ59"}
ACROBAT = {"label": "acrobat", "resolver": "adobe_arm_manifest",
           "manifest_url": "https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/acrobat/AcrobatManifest.arm",
           "item_id": "dld_App_Full", "team_id": "JQ525L2MZD"}
ZOOM = {"label": "zoom", "resolver": "url_template",
        "url_template": "https://cdn.zoom.us/prod/{version}/ZoomInstallerIT.pkg"}

API_NUDGE = "https://api.github.com/repos/macadmins/nudge/releases/tags/v2.1.4.81863"
HTML_NUDGE = "https://github.com/macadmins/nudge/releases/expanded_assets/v2.1.4.81863"
NUDGE_SHA = "731ee55c43b1fc91bd32f3a5783d439392aec4d602f7d854d89786d712e769cc"
NUDGE_URL = "https://github.com/macadmins/nudge/releases/download/v2.1.4.81863/Nudge_Suite-2.1.4.81863.pkg"


def read(path):
    with open(path, "rb") as f:
        return f.read()


def ctx(http, rule, **kw):
    return Context(http, versions.get_rule(rule), **kw)


class GithubTag(unittest.TestCase):
    def setUp(self):
        self.rule = versions.get_rule("dotted")
        self.target = self.rule.parse("2.1.4.81863")

    def test_api_with_digest_and_token(self):
        http = FakeHttp()
        http.add("GET", API_NUDGE, body=read(NUDGE_JSON))
        r = github_tag.resolve(NUDGE, self.target, ctx(http, "dotted", github_token="ghp_test"))
        self.assertEqual(r.url, NUDGE_URL)
        self.assertEqual(r.expected_sha256, NUDGE_SHA)
        self.assertEqual(r.expected_size, 1537619)
        self.assertTrue(r.exact)
        self.assertEqual(http.calls[0][2]["Authorization"], "Bearer ghp_test")

    def test_no_token_still_works(self):
        http = FakeHttp()
        http.add("GET", API_NUDGE, body=read(NUDGE_JSON))
        github_tag.resolve(NUDGE, self.target, ctx(http, "dotted"))
        self.assertNotIn("Authorization", http.calls[0][2])

    def test_a8_rate_limited_falls_back_to_html(self):
        for status in (403, 429, 502):
            with self.subTest(status=status):
                http = FakeHttp()
                http.add("GET", API_NUDGE, status=status, body=b'{"message":"API rate limit exceeded"}')
                http.add("GET", HTML_NUDGE, body=read(NUDGE_HTML))
                log = ListLog()
                r = github_tag.resolve(NUDGE, self.target, ctx(http, "dotted", github_token="ghp_test", log=log))
                self.assertEqual(r.url, NUDGE_URL)
                self.assertIsNone(r.expected_sha256)
                self.assertTrue(r.exact)
                self.assertTrue(r.warnings)
                self.assertNotIn("Authorization", http.calls[1][2])  # never on github.com pages
                self.assertTrue(any("HTML fallback" in m for m in log.records))

    def test_a8_api_unreachable_falls_back(self):
        http = FakeHttp()
        http.fail("GET", API_NUDGE)
        http.add("GET", HTML_NUDGE, body=read(NUDGE_HTML))
        self.assertEqual(github_tag.resolve(NUDGE, self.target, ctx(http, "dotted")).url, NUDGE_URL)

    def test_tag_missing_is_not_upstream_yet(self):
        http = FakeHttp()
        http.add("GET", API_NUDGE, status=404, body=b'{"message":"Not Found"}')
        with self.assertRaises(NotUpstreamYet):
            github_tag.resolve(NUDGE, self.target, ctx(http, "dotted"))
        http = FakeHttp()
        http.add("GET", API_NUDGE, status=403)
        http.add("GET", HTML_NUDGE, status=404)
        with self.assertRaises(NotUpstreamYet):
            github_tag.resolve(NUDGE, self.target, ctx(http, "dotted"))

    def test_both_paths_down(self):
        http = FakeHttp()
        http.add("GET", API_NUDGE, status=403)
        http.fail("GET", HTML_NUDGE)
        with self.assertRaises(ResolveError):
            github_tag.resolve(NUDGE, self.target, ctx(http, "dotted"))

    def test_zero_or_many_assets(self):
        rel = json.loads(read(NUDGE_JSON).decode("utf-8"))
        for regex in (r"^nomatch\.pkg$", r"^Nudge.*\.pkg$"):
            with self.subTest(regex=regex):
                http = FakeHttp()
                http.add("GET", API_NUDGE, body=json.dumps(rel))
                app = dict(NUDGE, asset_regex=regex)
                with self.assertRaisesRegex(ResolveError, "exactly one asset"):
                    github_tag.resolve(app, self.target, ctx(http, "dotted"))
                http = FakeHttp()
                http.add("GET", API_NUDGE, status=429)
                http.add("GET", HTML_NUDGE, body=read(NUDGE_HTML))
                with self.assertRaisesRegex(ResolveError, "exactly one asset"):
                    github_tag.resolve(app, self.target, ctx(http, "dotted"))

    def test_unexpected_download_host_rejected(self):
        rel = json.loads(read(NUDGE_JSON).decode("utf-8"))
        for a in rel["assets"]:
            a["browser_download_url"] = a["browser_download_url"].replace("github.com", "evil.example")
        http = FakeHttp()
        http.add("GET", API_NUDGE, body=json.dumps(rel))
        with self.assertRaisesRegex(ResolveError, "unexpected asset URL"):
            github_tag.resolve(NUDGE, self.target, ctx(http, "dotted"))

    def test_swiftdialog_tag_mapping(self):
        # SYNTHETIC release JSON in the shape of the real API (swiftDialog not downloaded in phase 1).
        sd = versions.get_rule("swiftdialog")
        rel = {"tag_name": "v3.1.1", "draft": False, "assets": [
            {"name": "dialog-3.1.1-5000.pkg", "size": 5000000, "digest": "sha256:" + "ab" * 32,
             "browser_download_url": "https://github.com/swiftDialog/swiftDialog/releases/download/v3.1.1/dialog-3.1.1-5000.pkg"},
            {"name": "dialog-3.1.1-5000.zip", "size": 1, "digest": None,
             "browser_download_url": "https://github.com/swiftDialog/swiftDialog/releases/download/v3.1.1/dialog-3.1.1-5000.zip"}]}
        http = FakeHttp()
        http.add("GET", "https://api.github.com/repos/swiftDialog/swiftDialog/releases/tags/v3.1.1", body=json.dumps(rel))
        r = github_tag.resolve(DIALOG, sd.parse("3.1.1.5000"), ctx(http, "swiftdialog"))
        self.assertTrue(r.url.endswith("/dialog-3.1.1-5000.pkg"))
        self.assertEqual(r.expected_sha256, "ab" * 32)

    def test_latest_version_d10(self):
        http = FakeHttp()
        http.add("GET", "https://api.github.com/repos/macadmins/nudge/releases/latest", body=read(NUDGE_JSON))
        self.assertEqual(github_tag.latest_version(NUDGE, ctx(http, "dotted")), self.target)

    def test_latest_version_html_fallback(self):
        http = FakeHttp()
        http.add("GET", "https://api.github.com/repos/macadmins/nudge/releases/latest", status=403)
        http.add("HEAD", "https://github.com/macadmins/nudge/releases/latest", status=302,
                 headers={"Location": "https://github.com/macadmins/nudge/releases/tag/v2.1.4.81863"})
        self.assertEqual(github_tag.latest_version(NUDGE, ctx(http, "dotted")), self.target)


class UrlTemplate(unittest.TestCase):
    URL = "https://cdn.zoom.us/prod/7.2.5.90525/ZoomInstallerIT.pkg"

    def setUp(self):
        self.rule = versions.get_rule("zoom")
        self.target = self.rule.parse("7.2.5 (90525)")

    def test_200_exact(self):
        http = FakeHttp()
        http.add("HEAD", self.URL)
        r = url_template.resolve(ZOOM, self.target, ctx(http, "zoom"))
        self.assertEqual(r.url, self.URL)
        self.assertTrue(r.exact)
        self.assertIsNone(r.expected_sha256)

    def test_404_and_403_not_upstream_yet(self):
        # Real cdn.zoom.us answered 403 for a non-existent version (DECISIONS F2).
        for status in (404, 403):
            http = FakeHttp()
            http.add("HEAD", self.URL, status=status)
            with self.assertRaisesRegex(NotUpstreamYet, "HTTP %d" % status):
                url_template.resolve(ZOOM, self.target, ctx(http, "zoom"))

    def test_other_status_fails(self):
        http = FakeHttp()
        http.add("HEAD", self.URL, status=500)
        with self.assertRaisesRegex(ResolveError, "500"):
            url_template.resolve(ZOOM, self.target, ctx(http, "zoom"))


class LatestRedirect(unittest.TestCase):
    def test_office_like_versioned_final_url(self):
        # SYNTHETIC final URL; the real Office form is confirmed in D13.
        app = {"label": "office", "url": "https://go.microsoft.com/fwlink/?linkid=525133"}
        final = "https://officecdnmac.microsoft.com/pr/x/MacAutoupdate/Microsoft_365_and_Office_16.103.25110920_Installer.pkg"
        http = FakeHttp()
        http.add("HEAD", app["url"], final_url=final, history=[(302, app["url"])])
        r = latest_redirect.resolve(app, versions.get_rule("office").parse("16.103.25110920"), ctx(http, "office"))
        self.assertEqual(r.url, final)
        self.assertFalse(r.exact)
        self.assertEqual(r.source_version.key, (16, 103, 25110920))

    def test_chrome_unversioned(self):
        app = {"label": "chrome", "url": "https://dl.google.com/dl/chrome/mac/universal/stable/gcem/GoogleChrome.pkg"}
        http = FakeHttp()
        http.add("HEAD", app["url"])
        r = latest_redirect.resolve(app, versions.get_rule("dotted").parse("142.0.7444.60"), ctx(http, "dotted"))
        self.assertIsNone(r.source_version)
        self.assertFalse(r.exact)

    def test_non_200(self):
        app = {"label": "chrome", "url": "https://dl.google.com/x.pkg"}
        http = FakeHttp()
        http.add("HEAD", app["url"], status=500)
        with self.assertRaises(ResolveError):
            latest_redirect.resolve(app, versions.get_rule("dotted").parse("1.0.0"), ctx(http, "dotted"))


class AdobeArm(unittest.TestCase):
    FULL_URL = "https://ardownload3.adobe.com/pub/adobe/acrobat/mac/AcrobatDC/2600322075/AcrobatDC2600322075_MUI.pkg"
    FULL_SHA = "d5eeef2df275570d7e1e1f57dcf1f4c939e579c9993fadb12200ffafca2ba174"

    def setUp(self):
        self.rule = versions.get_rule("acrobat")
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_resolve(self, body, target="26.003.22075", app=ACROBAT, **kw):
        http = FakeHttp()
        http.add("GET", app["manifest_url"], body=body)
        return adobe_arm.resolve(app, self.rule.parse(target), ctx(http, "acrobat", workdir=self.dir, **kw))

    def test_a13_from_xml(self):
        r = self.run_resolve(read(ACROBAT_XML))
        self.assertEqual(r.url, self.FULL_URL)
        self.assertEqual(r.expected_sha256, self.FULL_SHA)
        self.assertEqual(r.expected_size, 1707086778)
        self.assertTrue(r.exact)
        for bad in ("_incr", "Upd", "SCA", "2600121563", "2600222031"):
            self.assertNotIn(bad, r.url)

    def test_a13_from_real_arm_xar(self):
        r = self.run_resolve(read(ACROBAT_ARM), tools={"openssl": OPENSSL})
        self.assertEqual(r.url, self.FULL_URL)
        self.assertEqual(r.expected_sha256, self.FULL_SHA)
        self.assertEqual(r.warnings, [])  # signed xar: nothing to warn about
        self.assertEqual(os.listdir(self.dir), [])  # temp files cleaned up

    def test_arm_signer_must_match_team(self):
        with self.assertRaisesRegex(ResolveError, "manifest signer check failed: Team ID mismatch"):
            self.run_resolve(read(ACROBAT_ARM), app=dict(ACROBAT, team_id="UBF8T346G9"),
                             tools={"openssl": OPENSSL})

    def test_unsigned_or_wrongly_signed_arm_rejected(self):
        for certs, why in (([], "not signed"), ([cert("nudge_leaf_T4SK8ZXCXG")], "Team ID mismatch"),
                           ([cert("synthetic_application_T4SK8ZXCXG")], "not a Developer ID Installer")):
            with self.subTest(why=why):
                p = os.path.join(self.dir, "m.arm")
                build_xar(p, [("ASSET/AcrobatManifest.xml", read(ACROBAT_XML))], certs=certs)
                data = read(p)
                os.unlink(p)
                with self.assertRaisesRegex(ResolveError, why):
                    self.run_resolve(data, tools={"openssl": OPENSSL})

    def test_plain_xml_warns(self):
        r = self.run_resolve(read(ACROBAT_XML))
        self.assertTrue(any("plain XML" in w for w in r.warnings))

    def test_a13_never_selects_other_items(self):
        items = adobe_arm.parse_manifest(read(ACROBAT_XML))
        self.assertEqual(len(items), 9)
        item, version, url, size = adobe_arm.select_item(items, "dld_App_Full", "JQ525L2MZD", self.rule)
        self.assertEqual(item["id"], "dld_App_Full")
        # Patch/SCA items fail the fileName rule even if misconfigured as item_id.
        for other in ("dld_Patch_Incr", "dld_Patch_Cumulative", "dld_Installer_Migration_SCAFull",
                      "dld_Patch_Cumulative_dropOS12", "dld_Installer_Migration_SCAFull_dropOS12",
                      "dld_Penultimate_Patch_Incr", "dld_Penultimate_Patch_Cumulative"):
            with self.subTest(item=other):
                with self.assertRaisesRegex(ResolveError, "fileName"):
                    adobe_arm.select_item(items, other, "JQ525L2MZD", self.rule)

    def test_actionmatrix_version_not_used(self):
        # ActionMatrix lists 26.3.22074; the path code says 26.3.22075. Only the path counts.
        with self.assertRaises(NotUpstreamYet):
            self.run_resolve(read(ACROBAT_XML), target="26.003.22076")
        r = self.run_resolve(read(ACROBAT_XML), target="26.003.22075")
        self.assertEqual(str(r.source_version), "26.003.22075")

    def test_pin_older_uses_template_without_hash(self):
        log = ListLog()
        r = self.run_resolve(read(ACROBAT_XML), target="26.001.21563", log=log)
        self.assertEqual(r.url, "https://ardownload3.adobe.com/pub/adobe/acrobat/mac/AcrobatDC/2600121563/AcrobatDC2600121563_MUI.pkg")
        self.assertIsNone(r.expected_sha256)
        self.assertIsNone(r.expected_size)
        self.assertTrue(r.warnings)
        self.assertTrue(log.records)

    def test_wrong_team(self):
        with self.assertRaisesRegex(ResolveError, "Team ID mismatch"):
            self.run_resolve(read(ACROBAT_XML), app=dict(ACROBAT, team_id="UBF8T346G9"))

    def test_unknown_format_logs_first_16_bytes(self):
        with self.assertRaisesRegex(ResolveError, "first 16 bytes: 3c68746d6c3e"):
            self.run_resolve(b"<html>blocked</html>")

    def test_missing_item(self):
        with self.assertRaisesRegex(ResolveError, "no dItem 'dld_Nope'"):
            self.run_resolve(read(ACROBAT_XML), app=dict(ACROBAT, item_id="dld_Nope"))

    def test_tampered_filename_or_path(self):
        xml = read(ACROBAT_XML).replace(b'fileName="AcrobatDC2600322075_MUI.pkg"', b'fileName="AcrobatDC2600322074_MUI.pkg"')
        with self.assertRaisesRegex(ResolveError, "differs"):
            self.run_resolve(xml)
        xml = read(ACROBAT_XML).replace(b'fileName="AcrobatDC2600322075_MUI.pkg"', b'fileName="evil.pkg"')
        with self.assertRaisesRegex(ResolveError, "fileName"):
            self.run_resolve(xml)

    def test_doctype_rejected(self):
        xml = b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]><ARMProductManifest/>'
        with self.assertRaises(ResolveError):
            self.run_resolve(xml)

    def test_7z_wrapped_manifest_via_7zz(self):
        tools = tempfile.mkdtemp()
        try:
            listing = slt_listing("manifest.arm", [("ASSET", True, 0), ("ASSET/AcrobatManifest.xml", False, 6941)])
            bin7 = fake_7zz(tools, listing, {"ASSET/AcrobatManifest.xml": read(ACROBAT_XML)})
            r = self.run_resolve(adobe_arm.SEVENZ_MAGIC + b"\0" * 32, tools={"7zz": bin7})
            self.assertEqual(r.url, self.FULL_URL)
        finally:
            shutil.rmtree(tools)

    def test_7z_without_7zz(self):
        with self.assertRaisesRegex(ResolveError, "no 7zz"):
            self.run_resolve(adobe_arm.SEVENZ_MAGIC + b"\0" * 32)


if __name__ == "__main__":
    unittest.main()
