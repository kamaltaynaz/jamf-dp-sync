#!/usr/bin/env python3
"""Upstream stub for L1 (spec section 11.3): one local server standing in for GitHub, Adobe,
Microsoft, Google and Zoom. Standard library only, Python 3.6+.

Routes are keyed by "<public host><path>[?query]", e.g. "api.github.com/repos/macadmins/nudge/...".
The agent reaches them through the test-only JDS_TEST_URL_MAP env, which rewrites
https://<host> to http://127.0.0.1:<port>/<host>; `url_map()` builds that value.

Each route: status, headers, and a body (bytes) or body_file (streamed). GET honours If-None-Match
against the route's ETag. Unknown paths: 403 for cdn.zoom.us (as Cloudflare does, DECISIONS F2),
404 elsewhere. Every request is counted so tests can prove "no downloads" (A2).
"""
import os
import shutil
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HOSTS = ("api.github.com", "github.com", "release-assets.githubusercontent.com", "armmf.adobe.com",
         "ardownload3.adobe.com", "go.microsoft.com", "officecdnmac.microsoft.com", "dl.google.com",
         "zoom.us", "cdn.zoom.us")
FORBIDDEN_WHEN_MISSING = ("cdn.zoom.us",)


class Route(object):
    def __init__(self, status=200, body=None, body_file=None, headers=None):
        self.status = status
        self.body = body
        self.body_file = body_file
        self.headers = dict(headers or {})


class State(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.routes = {}
        self.hits = []  # (method, key, status)

    def count(self, key=None, method=None, suffix=None):
        with self.lock:
            return sum(1 for m, k, s in self.hits
                       if (key is None or k == key) and (method is None or m == method)
                       and (suffix is None or k.split("?")[0].endswith(suffix)))


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _key(self):
            return self.path.lstrip("/")

        def _serve(self, head):
            key = self._key()
            with state.lock:
                route = state.routes.get(key)
            if route is None:
                host = key.split("/", 1)[0]
                route = Route(403 if host in FORBIDDEN_WHEN_MISSING else 404, b"")
            status, headers = route.status, dict(route.headers)
            etag = headers.get("ETag")
            if not head and etag and self.headers.get("If-None-Match") == etag and status == 200:
                status = 304
            with state.lock:
                state.hits.append(("HEAD" if head else "GET", key, status))
            size = None
            if status == 200:
                size = os.path.getsize(route.body_file) if route.body_file else len(route.body or b"")
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(size or 0))
            self.end_headers()
            if head or status != 200:
                return
            if route.body_file:
                with open(route.body_file, "rb") as f:
                    shutil.copyfileobj(f, self.wfile)
            else:
                self.wfile.write(route.body or b"")

        def do_GET(self):
            self._serve(False)

        def do_HEAD(self):
            self._serve(True)

    return Handler


def start(host="127.0.0.1", port=0):
    state = State()
    srv = Server((host, port), make_handler(state))
    t = threading.Thread(target=srv.serve_forever, name="upstream-stub")
    t.daemon = True
    t.start()
    return srv, state, "http://%s:%d" % (host, srv.server_address[1])


def url_map(base):
    return ",".join("https://%s=%s/%s" % (h, base, h) for h in HOSTS)
