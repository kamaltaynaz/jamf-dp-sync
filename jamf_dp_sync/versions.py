"""Version normalisation and comparison rules (spec section 7, V1-V4).

Each app names a `version_rule`. A rule turns any of the forms an app's version appears in (patch
title, release tag, URL path, pkg metadata, published file name) into one comparable `Version`, and
formats a `Version` back into the form a resolver or file name needs. Rules are pure functions.
"""
import re
from functools import total_ordering


@total_ordering
class Version(object):
    """A normalised version. Ordering and equality use `key` only; `build` is informational."""

    __slots__ = ("key", "build", "text")

    def __init__(self, key, text, build=None):
        self.key = tuple(key)
        self.build = build
        self.text = text

    def __eq__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self.key == other.key

    def __lt__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self.key < other.key

    def __hash__(self):
        return hash(self.key)

    def __str__(self):
        return self.text

    def __repr__(self):
        return "Version(%r, build=%r, text=%r)" % (self.key, self.build, self.text)


_DOTTED = re.compile(r"^\d+(\.\d+)*$")


def _ints(parts):
    return tuple(int(p) for p in parts)


def _strip_v(s):
    s = s.strip()
    if s[:1] in ("v", "V") and s[1:2].isdigit():
        return s[1:]
    return s


class Rule(object):
    """Base class. Subclasses implement `parse`; `format` defaults to the canonical text."""

    name = None

    def parse(self, value):
        raise NotImplementedError

    def format(self, version, kind):
        """kind: 'tag' (GitHub release tag), 'url' (url_template), 'name' (published file name)."""
        if kind == "tag":
            return "v" + version.text
        if kind in ("url", "name"):
            return version.text
        raise ValueError("unknown format kind %r" % kind)


class DottedRule(Rule):
    """Plain dotted integers, optional leading 'v'. Nudge `2.1.4.81863`, Chrome `142.0.7444.60`."""

    name = "dotted"

    def parse(self, value):
        s = _strip_v(value)
        if not _DOTTED.match(s):
            raise ValueError("not a dotted version: %r" % value)
        key = _ints(s.split("."))
        return Version(key, ".".join(str(n) for n in key))


class SwiftDialogRule(Rule):
    """swiftDialog: marketing version (3 parts) is the key; the build number is kept separately.

    Accepts `3.1.1`, `v3.1.1`, `3.1.1.5000`, `3.1.1-5000`, `dialog-3.1.1-5000.pkg`.
    Canonical text and the published name are the marketing version only (`3.1.1`); the build is
    kept in `Version.build` for logs (DECISIONS Q3 answer).
    """

    name = "swiftdialog"
    _RE = re.compile(r"^(?:dialog-)?v?(\d+)\.(\d+)\.(\d+)(?:[.-](\d+))?(?:\.pkg)?$")

    def parse(self, value):
        m = self._RE.match(value.strip())
        if not m:
            raise ValueError("not a swiftDialog version: %r" % value)
        key = _ints(m.group(1, 2, 3))
        build = int(m.group(4)) if m.group(4) is not None else None
        return Version(key, "%d.%d.%d" % key, build)

    def format(self, version, kind):
        if kind == "tag":
            return "v%d.%d.%d" % version.key
        return Rule.format(self, version, kind)


class AcrobatRule(Rule):
    """Adobe Acrobat: `26.003.22075`, `26.3.22075` and the 10-digit path code `2600322075`.

    The code is 2 digits major, 3 digits minor, 5 digits build. Canonical text is the patch-title
    form `26.003.22075`. `format(v, 'url')` gives the 10-digit code used in Adobe download paths.
    """

    name = "acrobat"
    _DOTTED = re.compile(r"^(\d{1,2})\.(\d{1,3})\.(\d{1,5})$")
    _CODE = re.compile(r"(?<!\d)(\d{2})(\d{3})(\d{5})(?!\d)")

    def parse(self, value):
        s = value.strip()
        # Dotted form, else a standalone 10-digit code anywhere (bare, URL path or file name).
        m = self._DOTTED.match(s) or self._CODE.search(s)
        if not m:
            raise ValueError("not an Acrobat version: %r" % value)
        key = _ints(m.groups())
        return Version(key, "%d.%03d.%05d" % key)

    def format(self, version, kind):
        if kind == "url":
            return "%02d%03d%05d" % version.key
        if kind == "tag":
            raise ValueError("Acrobat has no release tags")
        return Rule.format(self, version, kind)


class ZoomRule(Rule):
    """Zoom: patch title `7.2.5 (90525)`, URL path `7.2.5.90525`."""

    name = "zoom"
    _TITLE = re.compile(r"^(\d+)\.(\d+)\.(\d+)\s*\((\d+)\)$")
    _URL = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$")

    def parse(self, value):
        s = _strip_v(value)
        m = self._TITLE.match(s) or self._URL.match(s)
        if not m:
            raise ValueError("not a Zoom version: %r" % value)
        key = _ints(m.groups())
        return Version(key, "%d.%d.%d.%d" % key)


class OfficeRule(DottedRule):
    """Microsoft 365 / Office. PROVISIONAL until D13 confirms the pkg vs patch-title forms."""

    name = "office"


RULES = dict((r.name, r) for r in (DottedRule(), SwiftDialogRule(), AcrobatRule(), ZoomRule(), OfficeRule()))


def get_rule(name):
    try:
        return RULES[name]
    except KeyError:
        raise ValueError("unknown version_rule %r" % name)


# ---------------------------------------------------------------- V2 / V3 / V4

def accept_exact(pkg_version, target):
    """V2: an exact source must deliver exactly the target version."""
    return pkg_version == target


def accept_latest(pkg_version, target):
    """V3: a latest-only source is accepted when the pkg is at least the target (else stale CDN)."""
    return pkg_version >= target


def published_name(name_prefix, rule, version):
    """`<name_prefix>-<version>.pkg` (section 5)."""
    return "%s-%s.pkg" % (name_prefix, rule.format(version, "name"))


def version_from_published_name(name, name_prefix, rule):
    """V4: read the version back from an agent-created name. Returns None if it is not one."""
    head = name_prefix + "-"
    if not (name.startswith(head) and name.endswith(".pkg")):
        return None
    try:
        return rule.parse(name[len(head):-len(".pkg")])
    except ValueError:
        return None
