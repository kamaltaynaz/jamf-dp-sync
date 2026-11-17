"""Test-only fault injection (spec section 11.3): environment variables, never config.

JDS_TEST_FAULTS is a comma-separated list of switches. Unknown names are rejected so a typo cannot
make a fault test pass vacuously. Every active fault is logged at WARNING on each run.

  github_403        GitHub API answers 403 (HTML fallback path, A8)
  wrong_team        verification expects Team ID ZZZZZZZZZZ (A6)
  flip_byte         one byte of every downloaded file is flipped (A7)
  patch_ahead       the patch-title target is bumped one build ahead of upstream (A5)
  template_404      url_template HEAD answers 404 (A5)
  dp_not_writable   preflight sees Packages/ as not writable
  staging_other_fs  preflight sees staging on another filesystem
  no_7zz            the 7zz tool path does not exist
  lock_held         the run lock is already held (A11)
  webhook_down      notifications go to a closed local port (A22)
"""
import os

KNOWN = frozenset((
    "github_403", "wrong_team", "flip_byte", "patch_ahead", "template_404", "dp_not_writable",
    "staging_other_fs", "no_7zz", "lock_held", "webhook_down",
))
ENV = "JDS_TEST_FAULTS"


def active():
    raw = os.environ.get(ENV, "")
    names = set(n.strip() for n in raw.split(",") if n.strip())
    unknown = names - KNOWN
    if unknown:
        raise ValueError("unknown %s: %s" % (ENV, ", ".join(sorted(unknown))))
    return names


class FaultyHttp(object):
    """Wraps an HttpClient for the HTTP faults: github_403 (GitHub API answers 403) and
    template_404 (HEAD on any url_template app's URL answers 404). Used only when a fault is set."""

    def __init__(self, http, template_prefixes=()):
        self._http = http
        self._prefixes = tuple(template_prefixes)

    def __getattr__(self, name):
        return getattr(self._http, name)

    def _fault_response(self, method, url):
        from jamf_dp_sync.httpclient import Response
        if on("github_403") and url.startswith("https://api.github.com/"):
            return Response(403, {}, url, b'{"message": "API rate limit exceeded (fault)"}')
        if on("template_404") and method == "HEAD" and self._prefixes and url.startswith(self._prefixes):
            return Response(404, {}, url, None)
        return None

    def request(self, method, url, **kw):
        return self._fault_response(method, url) or self._http.request(method, url, **kw)

    def get(self, url, headers=None, **kw):
        return self.request("GET", url, headers=headers, **kw)

    def head(self, url, headers=None, **kw):
        return self.request("HEAD", url, headers=headers, **kw)


def on(name):
    if name not in KNOWN:
        raise ValueError("unknown fault %r" % name)
    return name in active()
