"""url_template resolver (spec section 6): Zoom.

1. Format url_template with the normalised version (`7.2.5 (90525)` -> `7.2.5.90525`).
2. HEAD the URL. 200 -> exact. 404 or 403 -> not downloadable yet (D6).

Zoom's CDN (Cloudflare) answers 403, not 404, for a version that does not exist (probe of
2026-11-09, DECISIONS F2). Treating 403 as "not yet" keeps D6 working; a real block still surfaces as
the skip-threshold alert after alert_after_days, with the status code in the reason.
"""
from jamf_dp_sync.errors import NotUpstreamYet, ResolveError
from jamf_dp_sync.resolvers import Resolution


def resolve(app, target, ctx):
    url = app["url_template"].format(version=ctx.rule.format(target, "url"))
    resp = ctx.http.head(url)
    if resp.status == 200:
        return Resolution(url, exact=True, source_version=target)
    if resp.status in (403, 404):
        raise NotUpstreamYet("%s not downloadable yet (HTTP %d)" % (target, resp.status))
    raise ResolveError("HEAD %s returned %d" % (url.split("?")[0], resp.status))
