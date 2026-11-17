"""github_tag resolver (spec section 6): Nudge Suite, swiftDialog.

1. Map the target version to a tag with the app's version_rule.
2. GET api.github.com/repos/{repo}/releases/tags/{tag} with the token. Exactly one asset must match
   asset_regex.
3. The asset `digest` (sha256:...) becomes expected_sha256 when present.
4. API failure or rate limit: fall back to github.com/{repo}/releases/expanded_assets/{tag} and
   parse download links (no digest on this path).
5. The token is never sent on the asset download (the returned URL is fetched without credentials).

Also provides `latest_version` for apps with no patch title (D10).
"""
import html
import re
import urllib.parse

from jamf_dp_sync.errors import NotUpstreamYet, ResolveError
from jamf_dp_sync.httpclient import NetworkError
from jamf_dp_sync.resolvers import Resolution

API = "https://api.github.com"
WEB = "https://github.com"
API_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
_SHA256 = re.compile(r"^sha256:([0-9a-fA-F]{64})$")


def _api_headers(ctx):
    h = dict(API_HEADERS)
    if ctx.github_token:
        h["Authorization"] = "Bearer " + ctx.github_token
    return h


def _api_unavailable(resp):
    """403/429/5xx mean rate limit or outage: use the HTML fallback (rule 4)."""
    return resp.status in (403, 429) or resp.status >= 500


def _warn(ctx, msg):
    if ctx.log:
        ctx.log.warning(msg)


def resolve(app, target, ctx):
    repo = app["repo"]
    tag = ctx.rule.format(target, "tag")
    url = "%s/repos/%s/releases/tags/%s" % (API, repo, urllib.parse.quote(tag, safe=""))
    try:
        resp = ctx.http.get(url, headers=_api_headers(ctx))
    except NetworkError as e:
        _warn(ctx, "%s: GitHub API unreachable (%s); using HTML fallback" % (app["label"], e))
        return _resolve_html(app, tag, target, ctx, "API unreachable")
    if resp.status == 404:
        raise NotUpstreamYet("release %s not found in %s" % (tag, repo))
    if _api_unavailable(resp):
        _warn(ctx, "%s: GitHub API returned %d; using HTML fallback" % (app["label"], resp.status))
        return _resolve_html(app, tag, target, ctx, "API %d" % resp.status)
    if resp.status != 200:
        raise ResolveError("GitHub API returned %d for %s %s" % (resp.status, repo, tag))
    return _from_release_json(app, tag, target, resp.json())


def _from_release_json(app, tag, target, release):
    if release.get("tag_name") != tag:
        raise ResolveError("GitHub returned release %r for tag %r" % (release.get("tag_name"), tag))
    if release.get("draft"):
        raise NotUpstreamYet("release %s is a draft" % tag)
    pat = re.compile(app["asset_regex"])
    assets = [a for a in release.get("assets") or [] if pat.search(a.get("name", ""))]
    if len(assets) != 1:
        raise ResolveError("expected exactly one asset matching %r in %s, found %d"
                           % (app["asset_regex"], tag, len(assets)))
    a = assets[0]
    url = a.get("browser_download_url") or ""
    _check_download_url(url, app["repo"], tag, a.get("name"))
    sha = None
    m = _SHA256.match(a.get("digest") or "")
    if m:
        sha = m.group(1).lower()
    size = a.get("size") if isinstance(a.get("size"), int) and a.get("size") > 0 else None
    return Resolution(url, exact=True, expected_sha256=sha, expected_size=size, source_version=target)


def _check_download_url(url, repo, tag, name):
    expected = "%s/%s/releases/download/%s/%s" % (WEB, repo, urllib.parse.quote(tag), urllib.parse.quote(name or ""))
    if url != expected and urllib.parse.unquote(url) != urllib.parse.unquote(expected):
        raise ResolveError("unexpected asset URL %r (expected %r)" % (url, expected))


_HREF = re.compile(r'href="([^"]+)"')


def _resolve_html(app, tag, target, ctx, why):
    repo = app["repo"]
    url = "%s/%s/releases/expanded_assets/%s" % (WEB, repo, urllib.parse.quote(tag, safe=""))
    try:
        resp = ctx.http.get(url)
    except NetworkError as e:
        raise ResolveError("GitHub %s and HTML fallback failed: %s" % (why, e))
    if resp.status == 404:
        raise NotUpstreamYet("release %s not found in %s (HTML fallback)" % (tag, repo))
    if resp.status != 200:
        raise ResolveError("GitHub %s and HTML fallback returned %d" % (why, resp.status))
    page = (resp.body or b"").decode("utf-8", "replace")
    prefix = "/%s/releases/download/%s/" % (repo, tag)
    pat = re.compile(app["asset_regex"])
    names = []
    for href in _HREF.findall(page):
        href = html.unescape(href)
        path = urllib.parse.unquote(urllib.parse.urlsplit(href).path)
        if path.startswith(prefix):
            name = path[len(prefix):]
            if "/" not in name and pat.search(name) and name not in names:
                names.append(name)
    if len(names) != 1:
        raise ResolveError("HTML fallback: expected exactly one asset matching %r in %s, found %d"
                           % (app["asset_regex"], tag, len(names)))
    dl = "%s%s%s" % (WEB, urllib.parse.quote(prefix), urllib.parse.quote(names[0]))
    return Resolution(dl, exact=True, source_version=target,
                      warnings=["GitHub %s: resolved via HTML fallback, no digest" % why])


def latest_version(app, ctx):
    """D10 fallback version source: the latest release tag, parsed with the app's version_rule."""
    repo = app["repo"]
    tag = None
    try:
        resp = ctx.http.get("%s/repos/%s/releases/latest" % (API, repo), headers=_api_headers(ctx))
        if resp.status == 200:
            tag = resp.json().get("tag_name")
        elif not _api_unavailable(resp):
            raise ResolveError("GitHub API returned %d for %s latest release" % (resp.status, repo))
    except NetworkError:
        tag = None
    if tag is None:
        # HTML fallback: /releases/latest redirects to /releases/tag/{tag}.
        try:
            resp = ctx.http.head("%s/%s/releases/latest" % (WEB, repo), follow=False)
        except NetworkError as e:
            raise ResolveError("cannot find latest release of %s: %s" % (repo, e))
        loc = resp.header("location") or ""
        m = re.search(r"/releases/tag/([^/?#]+)$", loc)
        if resp.status not in (301, 302, 303, 307, 308) or not m:
            raise ResolveError("cannot find latest release of %s (HTML fallback status %d)" % (repo, resp.status))
        tag = urllib.parse.unquote(m.group(1))
    try:
        return ctx.rule.parse(tag)
    except ValueError as e:
        raise ResolveError("latest tag %r of %s does not parse: %s" % (tag, repo, e))
