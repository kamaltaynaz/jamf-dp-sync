"""latest_redirect resolver (spec section 6): Office, Chrome, Google Drive.

1. Follow redirects with HEAD and record the final URL. When the final file name carries a version
   (Office is expected to), it becomes `source_version`.
2. exact is False: the version inside the downloaded pkg decides acceptance (V3).
3. The conditional GET (ETag / Last-Modified, cached per app) happens at download time, not here.
"""
import posixpath
import re
import urllib.parse

from jamf_dp_sync.errors import ResolveError
from jamf_dp_sync.resolvers import Resolution

_VERSIONISH = re.compile(r"(?<![\d.])(\d+(?:\.\d+){2,})(?![\d.]*\d)")


def version_from_url(url, rule):
    name = posixpath.basename(urllib.parse.unquote(urllib.parse.urlsplit(url).path))
    for m in _VERSIONISH.finditer(name):
        try:
            return rule.parse(m.group(1))
        except ValueError:
            continue
    return None


def resolve(app, target, ctx):
    resp = ctx.http.head(app["url"])
    if resp.status != 200:
        raise ResolveError("HEAD %s (after %d redirects) returned %d"
                           % (urllib.parse.urlsplit(resp.url).hostname, len(resp.history), resp.status))
    return Resolution(resp.url, exact=False, source_version=version_from_url(resp.url, ctx.rule))
