"""Unit regressions for the Codex review (REVIEW_CODEX.md): findings 2, 13, 14, 15, 17."""
import http.server
import io
import logging
import os
import shutil
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import zlib

from jamf_dp_sync import logsetup, notify, secrets, xmlsafe
from jamf_dp_sync.errors import XarError
from jamf_dp_sync.httpclient import HttpClient, NetworkError
from jamf_dp_sync.xar import XarArchive
from tests.xarbuild import build_xar, cert, distribution

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        secrets._reset_for_tests()
        shutil.rmtree(self.dir)


# ---------------------------------------------------------------- finding 2
class TruncatedDownload(Tmp):
    def test_xar_rejects_members_past_end_of_file(self):
        p = os.path.join(self.dir, "x.pkg")
        build_xar(p, [("Distribution", distribution(product="1.0")), ("a.pkg/Payload", os.urandom(4000))],
                  certs=[cert("synthetic_installer_T4SK8ZXCXG")], encoding="application/octet-stream")
        with open(p, "rb") as f:
            data = f.read()
        with open(p, "wb") as f:
            f.write(data[:-500])  # the payload's tail never arrived
        with self.assertRaisesRegex(XarError, "past the end of the file"):
            XarArchive(p)

    def test_short_body_against_content_length(self):
        class Short(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"12345")
                self.wfile.flush()
                self.close_connection = True

        class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
        srv = Srv(("127.0.0.1", 0), Short)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            dest = os.path.join(self.dir, "d.pkg")
            with self.assertRaises(NetworkError):
                HttpClient(timeout=5).download("http://127.0.0.1:%d/x" % srv.server_address[1], dest)
            self.assertFalse(os.path.exists(dest))
        finally:
            srv.shutdown()
            srv.server_close()


# ---------------------------------------------------------------- finding 14
class DecompressionBomb(Tmp):
    def _xar_with_toc(self, toc, declared_len):
        c = zlib.compress(toc)
        p = os.path.join(self.dir, "bomb.pkg")
        with open(p, "wb") as f:
            f.write(struct.pack(">4sHHQQI", b"xar!", 28, 1, len(c), declared_len, 0) + c)
        return p

    def test_toc_larger_than_declared_is_stopped(self):
        toc = b"<?xml version='1.0'?><xar><toc>" + b" " * (8 * 1024 * 1024) + b"</toc></xar>"
        with self.assertRaisesRegex(XarError, "TOC"):
            XarArchive(self._xar_with_toc(toc, 64))

    def test_member_larger_than_declared_is_stopped(self):
        p = os.path.join(self.dir, "m.pkg")
        build_xar(p, [("Distribution", b"<x/>" + b" " * (2 * 1024 * 1024))])
        x = XarArchive(p)
        x.members["Distribution"].size = 10  # TOC claims a tiny output
        x.members["Distribution"].extracted_checksum = None
        with self.assertRaisesRegex(XarError, "larger than|size mismatch"):
            x.read("Distribution", max_size=1024 * 1024)
        x.close()


# ---------------------------------------------------------------- finding 13
class EncodedXml(unittest.TestCase):
    def test_utf16_doctype_rejected(self):
        doc = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE a [<!ENTITY x "boom">]><a>&x;</a>'
        for data in (doc.encode("utf-16"), doc.encode("utf-16-le"), doc.encode("utf-16-be")):
            with self.subTest(prefix=data[:4]):
                with self.assertRaises(ValueError):
                    xmlsafe.fromstring(data)

    def test_other_declared_encodings_rejected(self):
        with self.assertRaises(xmlsafe.UnsafeXML):
            xmlsafe.fromstring(b'<?xml version="1.0" encoding="UTF-7"?><a/>')
        xmlsafe.fromstring(b'<?xml version="1.0" encoding="utf-8"?><a/>')
        xmlsafe.fromstring(b"<a/>")


# ---------------------------------------------------------------- finding 15
class Redaction(Tmp):
    def setUp(self):
        Tmp.setUp(self)
        secrets._reset_for_tests({"JAMF_CLIENT_SECRET": "s3cr3t-value-123", "GCHAT_WEBHOOK_URL": ""})

    def test_traceback_is_redacted(self):
        log_file = os.path.join(self.dir, "a.log")
        log = logsetup.setup(log_file, stream=False)
        try:
            raise RuntimeError("boom with s3cr3t-value-123 inside")
        except RuntimeError:
            log.exception("unexpected")
        for h in log.handlers:
            h.flush()
        with open(log_file) as f:
            text = f.read()
        self.assertIn("Traceback", text)
        self.assertNotIn("s3cr3t-value-123", text)

    def test_runtime_bearer_token_redacted(self):
        secrets.add_runtime_secret("eyJhbGciOiJSUzI1NiJ9.token-value")
        self.assertNotIn("token-value", secrets.redact("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.token-value"))

    def test_chat_message_is_redacted(self):
        import datetime
        msg = notify.build_message(["*FAIL* x  jamf: 401 for s3cr3t-value-123"], datetime.datetime(2026, 11, 10), tag="[t]")
        self.assertNotIn("s3cr3t-value-123", msg)


# ---------------------------------------------------------------- finding 17
class StartupErrors(Tmp):
    def test_bad_config_is_logged_to_file_under_cron(self):
        home = os.path.join(self.dir, "home")
        os.makedirs(os.path.join(home, ".config", "jamf-dp-sync"))
        cfg = os.path.join(home, ".config", "jamf-dp-sync", "packages.json")
        with open(cfg, "w") as f:
            f.write('{"unknown_key": 1}')
        env = dict(os.environ, HOME=home)
        log = os.path.join(home, "logs", "jamf-dp-sync.log")

        def run():
            p = subprocess.run([sys.executable, os.path.join(ROOT, "jamf_dp_sync.py"), "run", "--dry-run"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=60)
            self.assertEqual(p.returncode, 1)
            with open(log) as f:
                return f.read()
        # No secrets file: redaction cannot be guaranteed, so only a generic line (round 2 #10).
        self.assertIn("configuration invalid (details withheld", run())
        # With secrets loaded, the details are logged (redacted).
        with open(os.path.join(home, ".config", "jamf-dp-sync", "env"), "w") as f:
            f.write("JAMF_URL=https://jamf.invalid\n")
        os.chmod(os.path.join(home, ".config", "jamf-dp-sync", "env"), 0o600)
        self.assertIn("unknown global key", run())


if __name__ == "__main__":
    unittest.main()
