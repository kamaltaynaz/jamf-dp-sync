#!/usr/bin/env python3
"""Google Chat incoming-webhook stub for L1 (spec sections 9 and 11.3). Stdlib only, Python 3.6+.

Accepts POST /v1/spaces/{space}/messages?key=..&token=..[&threadKey=..&messageReplyOption=..]
with a JSON body and records it. Behaviour is set by mode:

  ok            200 with a message resource
  429 / 500     that status every time
  429-then-ok   429 for the first N posts (N = fail_count, default 2), then 200
  slow          sleeps `delay` seconds before answering (for timeout tests)

Mode comes from GCHAT_STUB_MODE (e.g. "429-then-ok:2") or POST /__stub/mode {"mode": .., "fail_count": ..}.
GET /__stub/messages returns everything received; POST /__stub/reset clears it.
"Webhook unreachable" is tested by pointing the agent at a closed port, not by this stub.
"""
import argparse
import json
import os
import socketserver
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


class State(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.messages = []
        self.attempts = 0
        mode = os.environ.get("GCHAT_STUB_MODE", "ok")
        name, _, n = mode.partition(":")
        self.mode = name
        self.fail_count = int(n) if n else 2
        self.delay = 15.0


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def _send(self, status, obj=None):
            body = json.dumps(obj).encode("utf-8") if obj is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def do_GET(self):
            if self.path == "/__stub/messages":
                with state.lock:
                    return self._send(200, {"attempts": state.attempts, "messages": state.messages})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            parts = urllib.parse.urlsplit(self.path)
            body = self._body()
            if parts.path == "/__stub/reset":
                with state.lock:
                    state.messages, state.attempts = [], 0
                return self._send(204)
            if parts.path == "/__stub/mode":
                cfg = json.loads(body.decode("utf-8"))
                with state.lock:
                    state.mode = cfg["mode"]
                    state.fail_count = int(cfg.get("fail_count", 2))
                    state.delay = float(cfg.get("delay", 15))
                    state.attempts = 0
                return self._send(204)
            segs = parts.path.strip("/").split("/")
            if not (len(segs) == 4 and segs[0] == "v1" and segs[1] == "spaces" and segs[3] == "messages"):
                return self._send(404, {"error": {"code": 404, "message": "not found"}})
            q = urllib.parse.parse_qs(parts.query)
            if not q.get("key") or not q.get("token"):
                return self._send(401, {"error": {"code": 401, "message": "missing key/token"}})
            with state.lock:
                state.attempts += 1
                attempt, mode, fail_count, delay = state.attempts, state.mode, state.fail_count, state.delay
            if mode == "slow":
                time.sleep(delay)
            if mode in ("429", "500"):
                return self._send(int(mode), {"error": {"code": int(mode), "message": "stub %s" % mode}})
            if mode == "429-then-ok" and attempt <= fail_count:
                return self._send(429, {"error": {"code": 429, "message": "RESOURCE_EXHAUSTED"}})
            try:
                payload = json.loads(body.decode("utf-8"))
            except ValueError:
                return self._send(400, {"error": {"code": 400, "message": "invalid JSON"}})
            if not isinstance(payload, dict) or not isinstance(payload.get("text"), str):
                return self._send(400, {"error": {"code": 400, "message": "text payload required"}})
            thread_key = (q.get("threadKey") or [None])[0]
            rec = {"space": segs[2], "text": payload["text"], "threadKey": thread_key,
                   "messageReplyOption": (q.get("messageReplyOption") or [None])[0],
                   "content_type": self.headers.get("Content-Type")}
            with state.lock:
                state.messages.append(rec)
                n = len(state.messages)
            self._send(200, {"name": "spaces/%s/messages/m%d" % (segs[2], n),
                             "thread": {"name": "spaces/%s/threads/%s" % (segs[2], thread_key or "t%d" % n)},
                             "text": payload["text"]})

    return Handler


def start(port=0, host="127.0.0.1"):
    """Start in a background thread. Returns (server, state, base_url)."""
    state = State()
    srv = Server((host, port), make_handler(state))
    t = threading.Thread(target=srv.serve_forever, name="gchat-stub")
    t.daemon = True
    t.start()
    return srv, state, "http://%s:%d" % (host, srv.server_address[1])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Google Chat webhook stub")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--port-file")
    a = ap.parse_args(argv)
    srv, state, url = start(a.port, a.host)
    if a.port_file:
        with open(a.port_file, "w") as f:
            f.write(str(srv.server_address[1]))
    sys.stderr.write("gchat-stub listening on %s\n" % url)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
