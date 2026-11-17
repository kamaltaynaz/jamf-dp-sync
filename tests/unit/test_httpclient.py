"""DECISIONS B7: manual redirects keep HEAD, drop Authorization across hosts; streaming download.

Runs two loopback HTTP servers addressed as 127.0.0.1 and localhost so the host changes.
"""
import http.server
import os
import shutil
import socketserver
import tempfile
import threading
import unittest

from jamf_dp_sync.httpclient import HttpClient, NetworkError


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def serve(handler):
    srv = _Server(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever)
    t.daemon = True
    t.start()
    return srv


SEEN = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, body):
        SEEN.append((self.command, self.headers.get("Host"), self.path, self.headers.get("Authorization")))
        p = self.path
        if p.startswith("/redir-other"):
            self.send_response(302)
            self.send_header("Location", "http://localhost:%d/final.pkg" % self.server.other_port)
            self.end_headers()
        elif p.startswith("/redir-same"):
            self.send_response(301)
            self.send_header("Location", "/final.pkg")
            self.end_headers()
        elif p.startswith("/loop"):
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        elif p.startswith("/final.pkg"):
            if self.headers.get("If-None-Match") == '"v1"':
                self.send_response(304)
                self.end_headers()
                return
            data = b"x" * 300000
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("ETag", '"v1"')
            self.end_headers()
            if body:
                self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        self._reply(True)

    def do_HEAD(self):
        self._reply(False)


class HttpClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = serve(Handler)
        cls.b = serve(Handler)
        cls.a.other_port = cls.b.server_address[1]
        cls.b.other_port = cls.a.server_address[1]
        cls.base = "http://127.0.0.1:%d" % cls.a.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.a.shutdown(); cls.a.server_close()
        cls.b.shutdown(); cls.b.server_close()

    def setUp(self):
        del SEEN[:]
        self.http = HttpClient(timeout=5)

    def test_head_stays_head_across_redirects(self):
        r = self.http.head(self.base + "/redir-same")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.url.endswith("/final.pkg"))
        self.assertEqual([s[0] for s in SEEN], ["HEAD", "HEAD"])
        self.assertIsNone(r.body)
        self.assertEqual(r.history[0][0], 301)

    def test_authorization_dropped_on_host_change(self):
        r = self.http.head(self.base + "/redir-other", headers={"Authorization": "Bearer t"})
        self.assertEqual(r.status, 200)
        self.assertEqual(SEEN[0][3], "Bearer t")
        self.assertTrue(SEEN[1][1].startswith("localhost:"))
        self.assertIsNone(SEEN[1][3])

    def test_authorization_kept_same_host(self):
        self.http.get(self.base + "/redir-same", headers={"Authorization": "Bearer t"})
        self.assertEqual([s[3] for s in SEEN], ["Bearer t", "Bearer t"])

    def test_no_follow(self):
        r = self.http.head(self.base + "/redir-same", follow=False)
        self.assertEqual(r.status, 301)
        self.assertEqual(r.header("Location"), "/final.pkg")

    def test_redirect_loop(self):
        with self.assertRaises(NetworkError):
            self.http.get(self.base + "/loop")

    def test_404_returned_not_raised(self):
        self.assertEqual(self.http.get(self.base + "/missing").status, 404)

    def test_download_and_conditional(self):
        d = tempfile.mkdtemp()
        try:
            dest = os.path.join(d, "f.pkg")
            r = self.http.download(self.base + "/redir-other", dest)
            self.assertEqual(r.status, 200)
            self.assertEqual(os.path.getsize(dest), 300000)
            self.assertEqual(r.header("etag"), '"v1"')
            os.unlink(dest)
            r = self.http.download(self.base + "/final.pkg", dest, headers={"If-None-Match": '"v1"'})
            self.assertEqual(r.status, 304)
            self.assertFalse(os.path.exists(dest))
        finally:
            shutil.rmtree(d)

    def test_connection_refused(self):
        s = _Server(("127.0.0.1", 0), Handler)
        port = s.server_address[1]
        s.server_close()
        with self.assertRaises(NetworkError):
            self.http.get("http://127.0.0.1:%d/" % port)


if __name__ == "__main__":
    unittest.main()
