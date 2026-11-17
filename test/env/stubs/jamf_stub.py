#!/usr/bin/env python3
"""Stateful local Jamf Pro stub for L1 (spec section 11.3). Standard library only, Python 3.6+.

Implements the endpoints listed in spec section 8 as this build understands them. Shapes follow the
OpenAPI schema and recorded responses of a test Jamf Pro 11.33.0 (DECISIONS F4,
tests/fixtures/jamf/dev-11.33.0). Behaviour of write calls is still unproven until L2.

  POST   /api/oauth/token                                   client credentials -> bearer token
  POST   /api/v1/auth/invalidate-token
  GET    /api/v1/packages?filter=packageName=="X"           (also fileName=="X", page, page-size)
  GET    /api/v1/packages/{id}
  POST   /api/v1/packages
  DELETE /api/v1/packages/{id}                              also drops it from every policy (as Jamf does)
  GET    /api/v3/patch-software-title-configurations/{id}
  GET    /api/v3/patch-software-title-configurations/{id}/definitions   absoluteOrderId 0 = newest
  PATCH  /api/v3/patch-software-title-configurations/{id}   {"packages":[{"packageId","version"}]}
  GET    /JSSResource/policies/id/{id}                      XML
  PUT    /JSSResource/policies/id/{id}                      replaces <packages> if present

Test control (never part of the agent's API):
  GET  /__stub/state   GET /__stub/log   POST /__stub/reset   POST /__stub/fault {"match","status","times"}

Fault injection by environment (spec 11.3): JAMF_STUB_FAULTS="POST /api/v1/packages=403:1,GET /JSSResource=500"
(match is a "METHOD path-prefix"; ":N" limits how many times it fires).

Run:  python3 jamf_stub.py --seed seed.json [--port 0] [--port-file PATH] [--token-ttl 1200]
"""
import argparse
import copy
import json
import os
import re
import socketserver
import sys
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, HTTPServer

# Required fields of the "Package" schema on Jamf Pro 11.33 (dev server OpenAPI, 2026-11-09).
REQUIRED_PACKAGE_FIELDS = (
    "packageName", "fileName", "categoryId", "priority", "fillUserTemplate", "rebootRequired",
    "osInstall", "suppressUpdates", "suppressFromDock", "suppressEula", "suppressRegistration",
)
PACKAGE_PROPERTIES = set(REQUIRED_PACKAGE_FIELDS) | {
    "id", "info", "notes", "osRequirements", "indexed", "fillExistingUsers", "swu", "selfHealNotify",
    "selfHealingAction", "serialNumber", "parentPackageId", "basePath", "cloudTransferStatus",
    "ignoreConflicts", "installLanguage", "md5", "sha256", "sha3512", "hashType", "hashValue", "size",
    "osInstallerVersion", "manifest", "manifestFileName", "format",
}
PACKAGE_DEFAULTS = {
    "info": "", "notes": "", "hashType": None, "hashValue": None, "size": None, "md5": None,
    "sha256": None, "format": None, "swu": False, "selfHealNotify": False, "indexed": False,
}


class State(object):
    def __init__(self, seed, token_ttl=1200):
        self.lock = threading.RLock()
        self.seed = copy.deepcopy(seed)
        self.token_ttl = token_ttl
        self.faults = parse_fault_env(os.environ.get("JAMF_STUB_FAULTS", ""))
        self.reset()

    def reset(self):
        with self.lock:
            s = copy.deepcopy(self.seed)
            self.clients = s.get("clients", {"stub-client": "stub-secret"})
            self.packages = dict((str(p["id"]), p) for p in s.get("packages", []))
            self.next_id = max([int(i) for i in self.packages] + [999]) + 1
            self.policies = dict((str(k), v) for k, v in s.get("policies", {}).items())
            self.titles = dict((str(t["id"]), t) for t in s.get("patch_titles", []))
            self.tokens = {}
            self.log = []

    def snapshot(self):
        with self.lock:
            return {"packages": list(self.packages.values()), "policies": self.policies,
                    "patch_titles": list(self.titles.values()), "log": self.log}


def parse_fault_env(spec):
    faults = []
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        match, _, rest = part.partition("=")
        status, _, times = rest.partition(":")
        faults.append({"match": match.strip(), "status": int(status), "times": int(times) if times else None})
    return faults


class Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            if os.environ.get("JAMF_STUB_VERBOSE"):
                sys.stderr.write("jamf-stub: " + (fmt % args) + "\n")

        # ------------------------------------------------------------ plumbing
        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _send(self, status, body=b"", ctype="application/json"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode("utf-8")
            elif isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            with state.lock:
                state.log.append({"method": self.command, "path": urllib.parse.urlsplit(self.path).path,
                                  "query": urllib.parse.urlsplit(self.path).query, "status": status,
                                  "auth": bool(self.headers.get("Authorization"))})

        def _error(self, status, msg):
            self._send(status, {"httpStatus": status, "errors": [{"code": "STUB", "description": msg}]})

        def _fault(self, path):
            key = "%s %s" % (self.command, path)
            with state.lock:
                for f in state.faults:
                    if key.startswith(f["match"]) and (f["times"] is None or f["times"] > 0):
                        if f["times"] is not None:
                            f["times"] -= 1
                        return f["status"]
            return None

        def _authed(self):
            h = self.headers.get("Authorization") or ""
            if not h.startswith("Bearer "):
                return False
            with state.lock:
                exp = state.tokens.get(h[7:])
            return exp is not None and exp > time.time()

        def _dispatch(self):
            parts = urllib.parse.urlsplit(self.path)
            path, query = parts.path, urllib.parse.parse_qs(parts.query)
            if path.startswith("/__stub/"):
                return self._control(path)
            status = self._fault(path)
            if status:
                return self._error(status, "injected fault")
            if path == "/api/oauth/token" and self.command == "POST":
                return self._token()
            if not self._authed():
                return self._error(401, "unauthorized")
            for pattern, method, fn in ROUTES:
                m = re.match(pattern + "$", path)
                if m and self.command == method:
                    return fn(self, query, *m.groups())
            return self._error(404, "no route %s %s" % (self.command, path))

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _dispatch

        # ------------------------------------------------------------- control
        def _control(self, path):
            if path == "/__stub/state":
                return self._send(200, state.snapshot())
            if path == "/__stub/log":
                return self._send(200, state.log)
            if path == "/__stub/reset" and self.command == "POST":
                state.reset()
                return self._send(204)
            if path == "/__stub/fault" and self.command == "POST":
                f = json.loads(self._body().decode("utf-8"))
                with state.lock:
                    state.faults.append({"match": f["match"], "status": int(f["status"]), "times": f.get("times")})
                return self._send(204)
            return self._error(404, "no control route")

        # ---------------------------------------------------------------- auth
        def _token(self):
            form = urllib.parse.parse_qs(self._body().decode("utf-8"))
            cid = (form.get("client_id") or [""])[0]
            sec = (form.get("client_secret") or [""])[0]
            if (form.get("grant_type") or [""])[0] != "client_credentials" or state.clients.get(cid) != sec:
                return self._send(401, {"error": "invalid_client"})
            tok = uuid.uuid4().hex
            with state.lock:
                state.tokens[tok] = time.time() + state.token_ttl
            return self._send(200, {"access_token": tok, "scope": "api-role:stub", "token_type": "Bearer",
                                    "expires_in": state.token_ttl})

        def invalidate(self, query):
            with state.lock:
                state.tokens.pop((self.headers.get("Authorization") or "")[7:], None)
            return self._send(204)

        # ------------------------------------------------------------ packages
        def list_packages(self, query):
            flt = (query.get("filter") or [""])[0]
            with state.lock:
                items = sorted(state.packages.values(), key=lambda p: int(p["id"]))
            if flt:
                m = re.match(r'^(packageName|fileName)=="((?:[^"\\]|\\.)*)"$', flt)
                if not m:
                    return self._error(400, "stub supports only packageName==\"x\" / fileName==\"x\"")
                field, value = m.group(1), re.sub(r"\\(.)", r"\1", m.group(2))
                if "*" in value:
                    rx = re.compile("^" + ".*".join(re.escape(x) for x in value.split("*")) + "$")
                    items = [p for p in items if rx.match(p[field])]
                else:
                    items = [p for p in items if p[field] == value]
            page = int((query.get("page") or ["0"])[0])
            size = int((query.get("page-size") or ["100"])[0])
            return self._send(200, {"totalCount": len(items), "results": items[page * size:(page + 1) * size]})

        def get_package(self, query, pid):
            with state.lock:
                p = state.packages.get(pid)
            return self._send(200, p) if p else self._error(404, "package %s not found" % pid)

        def create_package(self, query):
            try:
                body = json.loads(self._body().decode("utf-8"))
            except ValueError:
                return self._error(400, "invalid JSON")
            missing = [f for f in REQUIRED_PACKAGE_FIELDS if f not in body]
            if missing:
                return self._error(400, "missing required fields: %s" % ", ".join(missing))
            unknown = sorted(set(body) - PACKAGE_PROPERTIES)
            if unknown:
                return self._error(400, "unknown fields: %s" % ", ".join(unknown))
            with state.lock:
                for p in state.packages.values():
                    if p["packageName"] == body["packageName"] or p["fileName"] == body["fileName"]:
                        return self._error(400, "DUPLICATE_FIELD packageName/fileName")
                pid = str(state.next_id)
                state.next_id += 1
                rec = dict(PACKAGE_DEFAULTS)
                rec.update(body)
                rec["id"] = pid
                state.packages[pid] = rec
            return self._send(201, {"id": pid, "href": "/api/v1/packages/%s" % pid})

        def delete_package(self, query, pid):
            with state.lock:
                if pid not in state.packages:
                    return self._error(404, "package %s not found" % pid)
                del state.packages[pid]
                for polid, xml in list(state.policies.items()):
                    state.policies[polid] = _drop_package(xml, pid)
                # ASSUMED (confirm in L2): Jamf also drops the package from patch title mappings.
                for t in state.titles.values():
                    t["packages"] = [m for m in t.get("packages", []) if str(m.get("packageId")) != pid]
            return self._send(204)

        # --------------------------------------------------------- patch titles
        def get_title(self, query, tid):
            with state.lock:
                t = state.titles.get(tid)
            if not t:
                return self._error(404, "title %s not found" % tid)
            return self._send(200, dict((k, v) for k, v in t.items() if k != "definitions"))

        def get_definitions(self, query, tid):
            with state.lock:
                t = state.titles.get(tid)
            if not t:
                return self._error(404, "title %s not found" % tid)
            defs = sorted(t.get("definitions", []), key=lambda d: int(d["absoluteOrderId"]))
            sort = (query.get("sort") or ["absoluteOrderId:asc"])[0]
            if sort.endswith(":desc"):
                defs.reverse()
            page = int((query.get("page") or ["0"])[0])
            size = int((query.get("page-size") or ["100"])[0])
            return self._send(200, {"totalCount": len(defs), "results": defs[page * size:(page + 1) * size]})

        def patch_title(self, query, tid):
            if not (self.headers.get("Content-Type") or "").startswith("application/merge-patch+json"):
                return self._error(415, "PATCH needs application/merge-patch+json")
            try:
                body = json.loads(self._body().decode("utf-8"))
            except ValueError:
                return self._error(400, "invalid JSON")
            with state.lock:
                t = state.titles.get(tid)
                if not t:
                    return self._error(404, "title %s not found" % tid)
                for pkg in body.get("packages", []):
                    if str(pkg.get("packageId")) not in state.packages:
                        return self._error(400, "unknown packageId %s" % pkg.get("packageId"))
                    if pkg.get("version") not in [d["version"] for d in t.get("definitions", [])]:
                        return self._error(400, "version %s not in title definitions" % pkg.get("version"))
                if "packages" in body:
                    # merge-patch: the array replaces the old one; displayName is server-filled
                    t["packages"] = [{"packageId": str(p["packageId"]), "version": p["version"],
                                      "displayName": state.packages[str(p["packageId"])]["packageName"]}
                                     for p in body["packages"]]
            return self._send(200, dict((k, v) for k, v in t.items() if k != "definitions"))

        # ------------------------------------------------------------ policies
        def get_policy(self, query, polid):
            with state.lock:
                xml = state.policies.get(polid)
            if xml is None:
                return self._send(404, "<html><body>Not Found</body></html>", "text/html")
            return self._send(200, xml, "application/xml")

        def put_policy(self, query, polid):
            body = self._body()
            with state.lock:
                xml = state.policies.get(polid)
                if xml is None:
                    return self._send(404, "<html><body>Not Found</body></html>", "text/html")
                try:
                    new = ET.fromstring(body)
                except ET.ParseError:
                    return self._send(400, "<html><body>Bad Request</body></html>", "text/html")
                pk = new.find("package_configuration/packages")
                if pk is not None:
                    for p in pk.findall("package"):
                        if (p.findtext("id") or "") not in state.packages:
                            return self._send(409, "<html><body>Conflict: Problem with package</body></html>",
                                              "text/html")
                    state.policies[polid] = _replace_packages(xml, pk)
            return self._send(201, "<policy><id>%s</id></policy>" % polid, "application/xml")

    return Handler


def _replace_packages(xml, new_pk):
    root = ET.fromstring(xml)
    pc = root.find("package_configuration")
    if pc is None:
        pc = ET.SubElement(root, "package_configuration")
    old = pc.find("packages")
    if old is not None:
        idx = list(pc).index(old)
        pc.remove(old)
        pc.insert(idx, new_pk)
    else:
        pc.insert(0, new_pk)
    _fix_size(new_pk)
    return ET.tostring(root, encoding="unicode")


def _drop_package(xml, pid):
    root = ET.fromstring(xml)
    pk = root.find("package_configuration/packages")
    if pk is None:
        return xml
    for p in pk.findall("package"):
        if p.findtext("id") == pid:
            pk.remove(p)
    _fix_size(pk)
    return ET.tostring(root, encoding="unicode")


def _fix_size(pk):
    size = pk.find("size")
    if size is None:
        size = ET.Element("size")
        pk.insert(0, size)
    size.text = str(len(pk.findall("package")))


ROUTES = [
    (r"/api/v1/auth/invalidate-token", "POST", lambda h, q: h.invalidate(q)),
    (r"/api/v1/packages", "GET", lambda h, q: h.list_packages(q)),
    (r"/api/v1/packages", "POST", lambda h, q: h.create_package(q)),
    (r"/api/v1/packages/(\d+)", "GET", lambda h, q, i: h.get_package(q, i)),
    (r"/api/v1/packages/(\d+)", "DELETE", lambda h, q, i: h.delete_package(q, i)),
    (r"/api/v3/patch-software-title-configurations/(\d+)", "GET", lambda h, q, i: h.get_title(q, i)),
    (r"/api/v3/patch-software-title-configurations/(\d+)", "PATCH", lambda h, q, i: h.patch_title(q, i)),
    (r"/api/v3/patch-software-title-configurations/(\d+)/definitions", "GET", lambda h, q, i: h.get_definitions(q, i)),
    (r"/JSSResource/policies/id/(\d+)", "GET", lambda h, q, i: h.get_policy(q, i)),
    (r"/JSSResource/policies/id/(\d+)", "PUT", lambda h, q, i: h.put_policy(q, i)),
]


def start(seed, port=0, host="127.0.0.1", token_ttl=1200):
    """Start in a background thread. Returns (server, state, base_url)."""
    state = State(seed, token_ttl)
    srv = Server((host, port), make_handler(state))
    t = threading.Thread(target=srv.serve_forever, name="jamf-stub")
    t.daemon = True
    t.start()
    return srv, state, "http://%s:%d" % (host, srv.server_address[1])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--port-file")
    ap.add_argument("--token-ttl", type=int, default=1200)
    a = ap.parse_args(argv)
    with open(a.seed) as f:
        seed = json.load(f)
    srv, state, url = start(seed, a.port, a.host, a.token_ttl)
    if a.port_file:
        with open(a.port_file, "w") as f:
            f.write(str(srv.server_address[1]))
    sys.stderr.write("jamf-stub listening on %s\n" % url)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
