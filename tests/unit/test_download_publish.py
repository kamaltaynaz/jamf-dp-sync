"""Section 9 atomic publish; section 6 conditional GET; §11.3 flip_byte."""
import hashlib
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import download, publish
from jamf_dp_sync.httpclient import HttpClient, Response
from tests.fakes import fake_7zz, slt_listing
from tests.unit.test_lock_state_faults import Env

DATA = b"xar!" + b"p" * 5000


class FakeDownloadHttp(object):
    def __init__(self, status=200, etag='"v1"'):
        self.status, self.etag, self.calls = status, etag, []

    def download(self, url, dest, headers=None):
        self.calls.append(dict(headers or {}))
        if headers and headers.get("If-None-Match") == self.etag:
            return Response(304, {}, url)
        if 200 <= self.status < 300:
            with open(dest, "wb") as f:
                f.write(DATA)
        return Response(self.status, {"etag": self.etag, "last-modified": "Mon, 09 Nov 2026 00:00:00 GMT"}, url)


class DmgIntegrity(unittest.TestCase):                # public review round 2 #4
    """The source's size/SHA-256 describe the DMG it serves: checked on the DMG, before extraction."""
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.tools = tempfile.mkdtemp()
        listing = slt_listing("x.dmg", [("App/Inner.pkg", False, 5)])
        self.bin = fake_7zz(self.tools, listing, {"App/Inner.pkg": b"xar!+"})
        self.app = {"label": "app", "post_download": {"type": "dmg_extract", "inner_path_regex": r"(^|/)Inner\.pkg$"}}

    def tearDown(self):
        shutil.rmtree(self.dir)
        shutil.rmtree(self.tools)

    def fetch(self, **kw):
        return download.fetch(self.app, "https://x/a.dmg", self.dir, FakeDownloadHttp(), {"7zz": self.bin}, **kw)

    def test_matching_dmg_digest_then_extracts(self):
        f = self.fetch(expected_size=len(DATA), expected_sha256=hashlib.sha256(DATA).hexdigest().upper())
        self.assertTrue(f.integrity_checked)
        with open(f.path, "rb") as fh:
            self.assertEqual(fh.read(), b"xar!+")          # the pkg, whose own size differs from the DMG's

    def test_mismatch_is_refused_and_nothing_left(self):
        from jamf_dp_sync.errors import VerifyError
        for kw in ({"expected_size": len(DATA) + 1}, {"expected_sha256": "0" * 64}):
            with self.assertRaises(VerifyError):
                self.fetch(**kw)
            self.assertEqual(os.listdir(self.dir), [])

    def test_no_published_digest(self):
        self.assertFalse(self.fetch().integrity_checked)


class Download(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_fetch_and_conditional(self):
        app = {"label": "chrome"}
        http = FakeDownloadHttp()
        f = download.fetch(app, "https://dl.google.com/x.pkg", self.dir, http, {})
        self.assertTrue(f.path.endswith(".pkg") and os.path.basename(f.path).startswith("chrome-"))
        self.assertEqual((f.etag, f.url), ('"v1"', "https://dl.google.com/x.pkg"))
        cache = {"url": f.url, "etag": f.etag, "last_modified": f.last_modified}
        again = download.fetch(app, "https://dl.google.com/x.pkg", self.dir, http, {}, cache)
        self.assertTrue(again.not_modified)
        self.assertEqual(http.calls[1]["If-None-Match"], '"v1"')
        self.assertEqual(os.listdir(self.dir), [os.path.basename(f.path)])
        # a different URL never sends validators
        download.fetch(app, "https://dl.google.com/other.pkg", self.dir, http, {}, cache)
        self.assertEqual(http.calls[2], {})

    def test_http_error_cleans_up(self):
        with self.assertRaisesRegex(download.DownloadError, "HTTP 500"):
            download.fetch({"label": "zoom"}, "https://x/y.pkg", self.dir, FakeDownloadHttp(status=500), {})
        self.assertEqual(os.listdir(self.dir), [])

    def test_flip_byte_fault(self):
        with Env(JDS_TEST_FAULTS="flip_byte"):
            f = download.fetch({"label": "nudge"}, "https://x/y.pkg", self.dir, FakeDownloadHttp(), {})
        with open(f.path, "rb") as fh:
            got = fh.read()
        self.assertEqual(len(got), len(DATA))
        self.assertNotEqual(got, DATA)

    def test_url_map_rewrites_only_what_is_opened(self):
        with Env(JDS_TEST_URL_MAP="https://api.github.com=http://127.0.0.1:9/gh"):
            h = HttpClient()
        self.assertEqual(h._rewrite("https://api.github.com/repos/x"), "http://127.0.0.1:9/gh/repos/x")
        self.assertEqual(h._rewrite("https://api.github.com.evil/x"), "https://api.github.com.evil/x")
        self.assertEqual(h._rewrite("https://github.com/x"), "https://github.com/x")


class Publish(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.dp = os.path.join(self.dir, "Packages")
        os.makedirs(self.dp)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def staged(self, data=DATA):
        fd, p = tempfile.mkstemp(dir=self.dir)
        os.write(fd, data)
        os.close(fd)
        return p, hashlib.sha512(data).hexdigest()

    def test_publish_0644_no_clobber(self):
        p, sha = self.staged()
        final, reused = publish.publish(p, self.dp, "jds-X-1.0.pkg", sha)
        self.assertFalse(reused)
        self.assertEqual(oct(os.stat(final).st_mode & 0o777), oct(0o644))
        self.assertFalse(os.path.exists(p))
        p2, sha2 = self.staged()
        self.assertEqual(publish.publish(p2, self.dp, "jds-X-1.0.pkg", sha2), (final, True))
        self.assertFalse(os.path.exists(p2))
        p3, sha3 = self.staged(b"different")
        with self.assertRaisesRegex(publish.PublishError, "different content"):
            publish.publish(p3, self.dp, "jds-X-1.0.pkg", sha3)
        with open(final, "rb") as f:
            self.assertEqual(f.read(), DATA)

    def test_unsafe_name_and_bad_group(self):
        p, sha = self.staged()
        for bad in ("../x.pkg", ".hidden.pkg", ""):
            with self.assertRaises(publish.PublishError):
                publish.publish(p, self.dp, bad, sha)
        with self.assertRaisesRegex(publish.PublishError, "cannot set group"):
            publish.publish(p, self.dp, "jds-X-1.pkg", sha, dp_group="no-such-group-jds")


if __name__ == "__main__":
    unittest.main()
