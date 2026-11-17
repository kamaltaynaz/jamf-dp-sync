"""Load and validate packages.json (spec section 5).

The agent refuses to run on unknown keys, missing required keys, duplicate labels, or values of the
wrong type. All problems are collected and reported together.
"""
import json
import os
import re

from jamf_dp_sync import versions
from jamf_dp_sync.errors import ConfigError

DEFAULT_CONFIG = "~/.config/jamf-dp-sync/packages.json"

# key: (types, required, default)
GLOBAL_KEYS = {
    "dp_packages_dir": ((str,), True, None),
    "staging_dir": ((str,), True, None),
    "dp_group": ((str,), False, None),
    "category_id": ((int,), False, -1),
    "retain": ((int,), False, 2),
    "alert_after_days": ((int,), False, 3),
    "log_file": ((str,), False, "~/logs/jamf-dp-sync.log"),
    "lock_file": ((str,), False, "~/.local/state/jamf-dp-sync/run.lock"),
    "tools": ((dict,), False, None),
    "apps": ((list,), True, None),
}

TOOL_KEYS = {"openssl": "/usr/bin/openssl", "7zz": "~/bin/7zz"}

COMMON_APP_KEYS = {
    "label": ((str,), True),
    "mode": ((str,), True),
    "patch_title_id": ((int, type(None)), True),
    "version_rule": ((str,), True),
    "policy_ids": ((list,), True),
    "replace_regex": ((str,), False),
    "retain": ((int,), False),
    "alert_after_days": ((int,), False),
    "category_id": ((int,), False),
}

SYNC_APP_KEYS = {
    "resolver": ((str,), True),
    "name_prefix": ((str,), True),
    "team_id": ((str,), True),
    "post_download": ((dict,), False),
    "add_if_missing": ((bool,), False),
    "pin": ((str,), False),
}

RESOLVER_KEYS = {
    "github_tag": {"repo": (str,), "asset_regex": (str,)},
    "url_template": {"url_template": (str,)},
    "latest_redirect": {"url": (str,)},
    "adobe_arm_manifest": {"manifest_url": (str,), "item_id": (str,)},
}

POST_DOWNLOAD_TYPES = {"dmg_extract": {"inner_path_regex"}}

_LABEL = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_TEAM = re.compile(r"^[A-Z0-9]{10}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class Config(object):
    """Validated configuration. `apps` is a list of dicts with per-app defaults filled in."""

    def __init__(self, path, settings, apps):
        self.path = path
        self.settings = settings
        self.apps = apps

    def __getitem__(self, key):
        return self.settings[key]

    def app(self, label):
        for a in self.apps:
            if a["label"] == label:
                return a
        raise KeyError(label)

    def tool(self, name):
        return self.settings["tools"][name]


def _reject_duplicate_keys(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ConfigError("duplicate JSON key %r" % k)
        seen[k] = v
    return seen


def _type_ok(value, types):
    # bool is a subclass of int; never accept it where an int is meant.
    if isinstance(value, bool) and bool not in types:
        return False
    return isinstance(value, types)


def _type_names(types):
    return " or ".join("null" if t is type(None) else t.__name__ for t in types)


def _expand(path):
    return os.path.expanduser(path)


def _inside(path, root):
    path, root = path.rstrip("/") or "/", root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/")


def staging_problems(dp, staging, resolve=False):
    """Section 5/9: staging must be outside the share. The share root is taken to be the directory
    that holds Packages/ (as on the DP server: /srv/shares/jamf/Packages). With `resolve`, symlinks
    are followed (preflight); config validation compares the paths as written."""
    if not (isinstance(dp, str) and isinstance(staging, str)):
        return []
    dps = [dp]
    stagings = [staging]
    shares = [os.path.dirname(dp.rstrip("/"))]
    if resolve:  # every view of the boundary: configured and resolved (review 2 #5)
        dps.append(os.path.realpath(dp))
        stagings.append(os.path.realpath(staging))
        shares += [os.path.realpath(shares[0]), os.path.dirname(os.path.realpath(dp))]
    for st in stagings:
        for share in shares:
            if _inside(st, share):
                return ["staging_dir %s is inside the share %s; it must be outside the share" % (staging, share)]
        for d in dps:
            if _inside(d, st):
                return ["staging_dir %s contains Packages/ %s; it must be outside the share" % (staging, d)]
    return []


def _check_regex(errors, where, key, value):
    try:
        re.compile(value)
    except re.error as e:
        errors.append("%s: %s is not a valid regex: %s" % (where, key, e))


def _check_https(errors, where, key, value):
    if not value.startswith("https://"):
        errors.append("%s: %s must be an https:// URL" % (where, key))


def load(path=None):
    path = _expand(path or DEFAULT_CONFIG)
    try:
        with open(path, "rb") as f:
            raw = json.loads(f.read().decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (IOError, OSError) as e:
        raise ConfigError("cannot read config %s: %s" % (path, e))
    except ValueError as e:
        raise ConfigError("config %s is not valid JSON: %s" % (path, e))
    return validate(raw, path)


def validate(raw, path="<memory>"):
    errors = []
    if not isinstance(raw, dict):
        raise ConfigError("config must be a JSON object")

    settings = {}
    for key in sorted(set(raw) - set(GLOBAL_KEYS)):
        errors.append("unknown global key %r" % key)
    for key, (types, required, default) in sorted(GLOBAL_KEYS.items()):
        if key not in raw:
            if required:
                errors.append("missing required global key %r" % key)
            settings[key] = default
            continue
        if not _type_ok(raw[key], types):
            errors.append("global key %r must be %s" % (key, _type_names(types)))
        settings[key] = raw[key]

    for key in ("dp_packages_dir", "staging_dir", "log_file", "lock_file"):
        if isinstance(settings.get(key), str):
            settings[key] = _expand(settings[key])
            if not os.path.isabs(settings[key]):
                errors.append("global key %r must be an absolute path" % key)
    for problem in staging_problems(settings.get("dp_packages_dir"), settings.get("staging_dir")):
        errors.append(problem)
    if isinstance(settings.get("retain"), int) and settings["retain"] < 1:
        errors.append("retain must be >= 1")
    if isinstance(settings.get("alert_after_days"), int) and settings["alert_after_days"] < 0:
        errors.append("alert_after_days must be >= 0")
    if isinstance(settings.get("category_id"), int) and settings["category_id"] < -1:
        errors.append("category_id must be -1 (none) or a Jamf category ID")

    tools = dict(TOOL_KEYS)
    if isinstance(settings.get("tools"), dict):
        for k, v in settings["tools"].items():
            if k not in TOOL_KEYS:
                errors.append("unknown tool %r (known: %s)" % (k, ", ".join(sorted(TOOL_KEYS))))
            elif not isinstance(v, str):
                errors.append("tools.%s must be a path string" % k)
            else:
                tools[k] = v
    settings["tools"] = dict((k, _expand(v)) for k, v in tools.items())

    apps = []
    labels = set()
    prefixes = []
    if isinstance(raw.get("apps"), list):
        if not raw["apps"]:
            errors.append("apps must not be empty")
        for i, entry in enumerate(raw["apps"]):
            app = _validate_app(entry, i, settings, errors)
            if app is None:
                continue
            if app["label"] in labels:
                errors.append("duplicate label %r" % app["label"])
            labels.add(app["label"])
            if app.get("name_prefix"):
                prefixes.append((app["label"], app["name_prefix"]))
            apps.append(app)

    for la, pa in prefixes:
        for lb, pb in prefixes:
            if la == lb:
                continue
            if pa == pb:
                if la < lb:
                    errors.append("apps %r and %r share name_prefix %r" % (la, lb, pa))
            elif pb.startswith(pa + "-"):
                errors.append("name_prefix %r of %r is ambiguous with %r of %r (pruning safety)" % (pa, la, pb, lb))

    if errors:
        raise ConfigError("invalid config %s:\n  - %s" % (path, "\n  - ".join(errors)))
    return Config(path, settings, apps)


def _validate_app(entry, i, settings, errors):
    where = "apps[%d]" % i
    if not isinstance(entry, dict):
        errors.append("%s must be an object" % where)
        return None
    if isinstance(entry.get("label"), str):
        where = "app %r" % entry["label"]

    mode = entry.get("mode")
    allowed = dict(COMMON_APP_KEYS)
    if mode == "sync":
        allowed.update(SYNC_APP_KEYS)
        resolver = entry.get("resolver")
        if resolver in RESOLVER_KEYS:
            for k, types in RESOLVER_KEYS[resolver].items():
                allowed[k] = (types, True)
        elif "resolver" in entry:
            errors.append("%s: unknown resolver %r (known: %s)" % (where, resolver, ", ".join(sorted(RESOLVER_KEYS))))
    elif mode == "monitor":
        pass
    elif "mode" in entry:
        errors.append("%s: mode must be 'sync' or 'monitor', not %r" % (where, mode))

    bad = False
    for key in sorted(set(entry) - set(allowed)):
        errors.append("%s: unknown key %r for mode %r" % (where, key, mode))
        bad = True
    for key, (types, required) in sorted(allowed.items()):
        if key not in entry:
            if required:
                errors.append("%s: missing required key %r" % (where, key))
                bad = True
            continue
        if not _type_ok(entry[key], types):
            errors.append("%s: %r must be %s" % (where, key, _type_names(types)))
            bad = True
    if bad:
        return None

    app = dict(entry)
    for key in ("retain", "alert_after_days", "category_id"):
        app.setdefault(key, settings.get(key))
    app.setdefault("add_if_missing", False)

    if not _LABEL.match(app["label"]):
        errors.append("%s: label must match %s" % (where, _LABEL.pattern))
    try:
        rule = versions.get_rule(app["version_rule"])
    except ValueError as e:
        errors.append("%s: %s" % (where, e))
        rule = None

    ids = app["policy_ids"]
    if not ids:
        errors.append("%s: policy_ids must not be empty" % where)
    for pid in ids:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            errors.append("%s: policy_ids must be positive integers, got %r" % (where, pid))
    if len(set(i for i in ids if isinstance(i, int))) != len(ids):
        errors.append("%s: duplicate policy ID in policy_ids" % where)

    pt = app["patch_title_id"]
    if pt is None:
        if app.get("resolver") != "github_tag":
            errors.append("%s: patch_title_id may be null only for github_tag apps (the release tag is then the version source)" % where)
    elif pt <= 0:
        errors.append("%s: patch_title_id must be a positive integer" % where)

    if "replace_regex" in app:
        _check_regex(errors, where, "replace_regex", app["replace_regex"])
    if app["mode"] == "monitor":
        # Hand-uploaded pkgs have free-form names; the version comes from a named group
        # (OPEN_QUESTIONS Q4, answered 2026-11-09).
        rx = app.get("replace_regex")
        if rx is None:
            errors.append("%s: monitor apps need replace_regex with a (?P<version>...) group" % where)
        else:
            try:
                if "version" not in re.compile(rx).groupindex:
                    errors.append("%s: replace_regex must contain a (?P<version>...) group" % where)
            except re.error:
                pass  # already reported
    for key in ("retain", "alert_after_days"):
        if isinstance(app.get(key), int) and app[key] < (1 if key == "retain" else 0):
            errors.append("%s: %s out of range" % (where, key))

    if app["mode"] == "sync":
        if not _PREFIX.match(app["name_prefix"]):
            errors.append("%s: name_prefix must match %s" % (where, _PREFIX.pattern))
        if not _TEAM.match(app["team_id"]):
            errors.append("%s: team_id must be 10 upper-case letters/digits" % where)
        if "pin" in app and rule is not None:
            try:
                rule.parse(app["pin"])
            except ValueError as e:
                errors.append("%s: pin %r does not parse with version_rule %r: %s"
                              % (where, app["pin"], app["version_rule"], e))
        res = app["resolver"]
        if res == "github_tag":
            if not _REPO.match(app["repo"]):
                errors.append("%s: repo must be 'owner/name'" % where)
            _check_regex(errors, where, "asset_regex", app["asset_regex"])
        elif res == "url_template":
            _check_https(errors, where, "url_template", app["url_template"])
            try:
                if app["url_template"].format(version="X") == app["url_template"]:
                    errors.append("%s: url_template must contain {version}" % where)
            except (KeyError, IndexError, ValueError) as e:
                errors.append("%s: url_template may only use {version}: %s" % (where, e))
        elif res == "latest_redirect":
            _check_https(errors, where, "url", app["url"])
        elif res == "adobe_arm_manifest":
            _check_https(errors, where, "manifest_url", app["manifest_url"])
        pd = app.get("post_download")
        if pd is not None:
            t = pd.get("type")
            if t not in POST_DOWNLOAD_TYPES:
                errors.append("%s: post_download.type must be one of %s" % (where, sorted(POST_DOWNLOAD_TYPES)))
            else:
                need = POST_DOWNLOAD_TYPES[t]
                extra = set(pd) - need - {"type"}
                if extra:
                    errors.append("%s: unknown post_download keys %s" % (where, sorted(extra)))
                for k in sorted(need - set(pd)):
                    errors.append("%s: post_download missing %r" % (where, k))
                if isinstance(pd.get("inner_path_regex"), str):
                    _check_regex(errors, where, "post_download.inner_path_regex", pd["inner_path_regex"])
                elif "inner_path_regex" in pd:
                    errors.append("%s: post_download.inner_path_regex must be a string" % where)
    return app
