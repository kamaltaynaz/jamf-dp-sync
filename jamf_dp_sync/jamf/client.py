"""Jamf Pro API client (spec section 8). One API client, least-privilege role `jamf-dp-sync`.

Endpoints and payloads were checked against the OpenAPI schema of a test Jamf Pro 11.33.0 on
2026-11-09 (DECISIONS F4). Section 8 names the v2 patch-title endpoints; they are deprecated on 11.33,
so this client uses v3 (same shapes). No write call has been made against a real server yet (L2).

Auth: client-credentials token from POST /api/oauth/token, refreshed 30 s before expires_in, one
retry after a 401, invalidated at exit (best effort).
"""
import json
import time
import urllib.parse

from jamf_dp_sync.errors import JamfError
from jamf_dp_sync.httpclient import NetworkError, credential_url_problem

REFRESH_MARGIN = 30

# Written into every package record the agent creates; pruning requires it (DECISIONS, Q6 answer).
AGENT_MARKER = "created by jamf-dp-sync"

# Which role privilege a 403 on each call points at (section 8 "API role"); logged on 403 so the
# build log records which privilege fixed it.
PRIVILEGE_HINTS = [
    ("POST", "/api/v1/packages", "Packages: Create"),
    ("DELETE", "/api/v1/packages", "Packages: Delete"),
    ("GET", "/api/v1/packages", "Packages: Read"),
    ("PUT", "/JSSResource/policies", "Policies: Update"),
    ("GET", "/JSSResource/policies", "Policies: Read"),
    ("PATCH", "/api/v3/patch-software-title-configurations", "Patch Management Software Titles: Update"),
    ("GET", "/api/v3/patch-software-title-configurations", "Patch Management Software Titles: Read"),
]

# Required booleans of POST /api/v1/packages on 11.33 (schema "Package"); all sent as false.
PACKAGE_FLAGS = ("fillUserTemplate", "rebootRequired", "osInstall", "suppressUpdates",
                 "suppressFromDock", "suppressEula", "suppressRegistration")


def privilege_hint(method, path):
    for m, prefix, hint in PRIVILEGE_HINTS:
        if method == m and path.startswith(prefix):
            return hint
    return "unknown privilege"


def rsql_quote(value):
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


class JamfClient(object):
    def __init__(self, base_url, client_id, client_secret, http, clock=time.time, log=None):
        problem = credential_url_problem(base_url, "JAMF_URL")
        if problem:
            raise JamfError(problem)    # never send the client secret over plain http
        self.base = base_url.rstrip("/")
        self._cid = client_id
        self._secret = client_secret
        self.http = http
        self.clock = clock
        self.log = log
        self._token = None
        self._expires = 0.0

    # --------------------------------------------------------------- auth
    def _fetch_token(self):
        form = urllib.parse.urlencode({"client_id": self._cid, "client_secret": self._secret,
                                       "grant_type": "client_credentials"}).encode("ascii")
        try:
            r = self.http.request("POST", self.base + "/api/oauth/token", data=form, follow=False,
                                  headers={"Content-Type": "application/x-www-form-urlencoded",
                                           "Accept": "application/json"})
        except NetworkError as e:
            raise JamfError("token request failed: %s" % e)
        if r.status != 200:
            raise JamfError("token request returned %d (check JAMF_CLIENT_ID/SECRET and the API client)"
                            % r.status, status=r.status)
        body = r.json()
        tok, ttl = body.get("access_token"), body.get("expires_in")
        if not tok or not isinstance(ttl, (int, float)):
            raise JamfError("token response missing access_token/expires_in")
        self._token = tok
        self._expires = self.clock() + ttl
        from jamf_dp_sync import secrets
        secrets.add_runtime_secret(tok)  # never let a bearer token reach a log or message

    def token(self):
        if self._token is None or self.clock() >= self._expires - REFRESH_MARGIN:
            self._fetch_token()
        return self._token

    def invalidate(self):
        if self._token is None:
            return
        try:
            self.http.request("POST", self.base + "/api/v1/auth/invalidate-token", follow=False,
                              headers={"Authorization": "Bearer " + self._token})
        except Exception:  # best effort at exit
            pass
        self._token = None

    # ------------------------------------------------------------ request
    def _call(self, method, path, body=None, ctype="application/json", accept="application/json",
              ok=(200, 201, 204)):
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8") if ctype.endswith("json") else body
        for attempt in (1, 2):
            headers = {"Authorization": "Bearer " + self.token(), "Accept": accept}
            if data is not None:
                headers["Content-Type"] = ctype
            try:
                r = self.http.request(method, self.base + path, data=data, headers=headers, follow=False)
            except NetworkError as e:
                raise JamfError("%s %s: %s" % (method, path.split("?")[0], e))
            if r.status == 401 and attempt == 1:
                self._token = None  # expired early or revoked: refresh once
                continue
            break
        if r.status == 403:
            hint = privilege_hint(method, path)
            if self.log:
                self.log.error("Jamf 403 on %s %s: API role likely needs '%s'", method, path.split("?")[0], hint)
            raise JamfError("403 on %s %s (needs '%s')" % (method, path.split("?")[0], hint), status=403)
        if r.status not in ok:
            raise JamfError("%s %s returned %d" % (method, path.split("?")[0], r.status), status=r.status)
        return r

    def _json(self, method, path, body=None, ok=(200, 201, 204), ctype="application/json"):
        r = self._call(method, path, body, ctype=ctype, ok=ok)
        return r.json() if r.body else None

    # ----------------------------------------------------------- packages
    def find_packages(self, field, value, page_size=200):
        """All package records where `field == value` (value may contain RSQL '*')."""
        out, page = [], 0
        while True:
            q = urllib.parse.urlencode({"page": page, "page-size": page_size,
                                        "filter": "%s==%s" % (field, rsql_quote(value))})
            res = self._json("GET", "/api/v1/packages?" + q)
            out.extend(res.get("results", []))
            if len(out) >= res.get("totalCount", 0) or not res.get("results"):
                return out
            page += 1

    def list_packages(self, page_size=200):
        """Every package record (paged, no filter). Used for pruning and the collision preflight,
        filtered client-side so no RSQL wildcard behaviour is assumed."""
        out, page = [], 0
        while True:
            q = urllib.parse.urlencode({"page": page, "page-size": page_size, "sort": "id:asc"})
            res = self._json("GET", "/api/v1/packages?" + q)
            out.extend(res.get("results", []))
            if len(out) >= res.get("totalCount", 0) or not res.get("results"):
                return out
            page += 1

    def find_package(self, package_name):
        hits = [p for p in self.find_packages("packageName", package_name) if p.get("packageName") == package_name]
        if len(hits) > 1:
            raise JamfError("%d package records named %s" % (len(hits), package_name))
        return hits[0] if hits else None

    def create_package(self, file_name, package_name, category_id, sha512):
        body = {"packageName": package_name, "fileName": file_name, "categoryId": str(category_id),
                "priority": 10, "hashType": "SHA_512", "hashValue": sha512, "notes": AGENT_MARKER}
        for flag in PACKAGE_FLAGS:
            body[flag] = False
        res = self._json("POST", "/api/v1/packages", body, ok=(200, 201))
        pid = res.get("id") if res else None
        if pid is None:
            raise JamfError("package create returned no id")
        return int(pid)

    def delete_package(self, package_id):
        self._call("DELETE", "/api/v1/packages/%d" % int(package_id), ok=(200, 204))

    # ---------------------------------------------------------- policies
    def get_policy_xml(self, policy_id):
        r = self._call("GET", "/JSSResource/policies/id/%d" % int(policy_id), accept="application/xml", ok=(200,))
        return r.body

    def put_policy_xml(self, policy_id, xml_bytes):
        self._call("PUT", "/JSSResource/policies/id/%d" % int(policy_id), xml_bytes,
                   ctype="application/xml", accept="application/xml", ok=(200, 201))

    # ------------------------------------------------------- patch titles
    def patch_title(self, title_id):
        return self._json("GET", "/api/v3/patch-software-title-configurations/%d" % int(title_id))

    def patch_definitions(self, title_id, page_size=200):
        out, page = [], 0
        while True:
            q = urllib.parse.urlencode({"page": page, "page-size": page_size, "sort": "absoluteOrderId:asc"})
            res = self._json("GET", "/api/v3/patch-software-title-configurations/%d/definitions?%s" % (int(title_id), q))
            out.extend(res.get("results", []))
            if len(out) >= res.get("totalCount", 0) or not res.get("results"):
                return out

            page += 1

    def latest_patch_version(self, title_id):
        """Version string of the newest definition: absoluteOrderId 0 (confirmed on 11.33, F4).
        releaseDate is NOT monotonic (Chrome 156.x was dated after 157.x), so never sort by date."""
        q = urllib.parse.urlencode({"page": 0, "page-size": 1, "sort": "absoluteOrderId:asc"})
        res = self._json("GET", "/api/v3/patch-software-title-configurations/%d/definitions?%s" % (int(title_id), q))
        defs = res.get("results", []) if res else []
        if not defs:
            raise JamfError("patch title %s has no definitions" % title_id)
        return min(defs, key=lambda d: int(d.get("absoluteOrderId", 1 << 30)))["version"]

    def map_package_to_title(self, title_id, package_id, version):
        """D15: attach a package to a title version, keeping the other mappings.

        Returns "mapped", "already", or "taken by package N (...)" when another package already
        holds that version (left alone; the caller warns).

        merge-patch replaces arrays whole, so the full list is sent back; displayName is read-only
        and dropped.
        """
        title = self.patch_title(title_id)
        current = title.get("packages") or []
        for p in current:
            if p.get("version") == version:
                if str(p.get("packageId")) == str(package_id):
                    return "already"
                # Never take over another package's mapping (L2 on dev, DECISIONS F8): Jamf refuses
                # it anyway (400), and that package may be the hand-uploaded one in use.
                return "taken by package %s (%s)" % (p.get("packageId"), p.get("displayName") or "?")
        pkgs = [{"packageId": str(p["packageId"]), "version": p["version"]} for p in current]
        pkgs.append({"packageId": str(package_id), "version": version})
        self._json("PATCH", "/api/v3/patch-software-title-configurations/%d" % int(title_id), {"packages": pkgs},
                   ctype="application/merge-patch+json")
        return "mapped"
