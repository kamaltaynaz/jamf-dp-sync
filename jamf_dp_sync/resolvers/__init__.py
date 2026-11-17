"""Resolvers (spec section 6): target version -> download URL plus any published integrity data.

Every resolver module exposes `resolve(app, target, ctx)` returning a Resolution. Adding a source
means adding a module and one line in RESOLVERS; nothing else changes.
"""
import importlib


class Resolution(object):
    """The section 6 contract.

    url              download URL (fetched without credentials)
    expected_sha256  hex digest the source publishes, or None
    expected_size    byte size the source publishes, or None
    exact            True if `url` is exactly the target version (V2), False for latest-only (V3)
    source_version   version the source claims before download (a Version), or None
    """

    __slots__ = ("url", "expected_sha256", "expected_size", "exact", "source_version", "warnings")

    def __init__(self, url, exact, expected_sha256=None, expected_size=None, source_version=None,
                 warnings=None):
        self.url = url
        self.exact = exact
        self.expected_sha256 = expected_sha256.lower() if expected_sha256 else None
        self.expected_size = expected_size
        self.source_version = source_version
        self.warnings = list(warnings or [])

    def as_dict(self):
        return dict((k, getattr(self, k)) for k in self.__slots__)

    def __repr__(self):
        return "Resolution(%r, exact=%r, sha256=%r, size=%r)" % (
            self.url, self.exact, self.expected_sha256, self.expected_size)


class Context(object):
    """What a resolver may use. `http` is an HttpClient-like object; tests pass a fake."""

    def __init__(self, http, rule, github_token=None, tools=None, workdir=None, log=None):
        self.http = http
        self.rule = rule
        self.github_token = github_token
        self.tools = tools or {}
        self.workdir = workdir
        self.log = log


RESOLVERS = {
    "github_tag": "jamf_dp_sync.resolvers.github_tag",
    "url_template": "jamf_dp_sync.resolvers.url_template",
    "latest_redirect": "jamf_dp_sync.resolvers.latest_redirect",
    "adobe_arm_manifest": "jamf_dp_sync.resolvers.adobe_arm",
}


def get(name):
    return importlib.import_module(RESOLVERS[name])


def resolve(app, target, ctx):
    return get(app["resolver"]).resolve(app, target, ctx)
