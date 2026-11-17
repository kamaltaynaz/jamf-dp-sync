"""Surgical edits of a Classic API policy's package list (spec section 8 rules).

Classic `PUT /JSSResource/policies/id/{id}` replaces the whole <packages> list, so the PUT body sends
every existing entry back unchanged except the swapped one, which keeps the old entry's <action>
(and fut/feu/update_autorun). Only <package_configuration><packages> is sent; nothing else in the
policy is touched.

Matching uses `^<name_prefix>-.+\\.pkg$`, plus `replace_regex` for legacy names when set. Multiple matches collapse into
the new entry (at the first match's position). No match: append only if add_if_missing, else warn
and skip.
"""
import copy
import re
import xml.etree.ElementTree as ET

from jamf_dp_sync import xmlsafe
from jamf_dp_sync.errors import PolicyEditError

PASSTHROUGH = ("action", "fut", "feu", "update_autorun")
DEFAULT_ACTION = "Install"


def agent_regex(app):
    return "^%s-.+\\.pkg$" % re.escape(app["name_prefix"])


def match_regex(app):
    """The agent's own names always match; `replace_regex` adds the legacy hand-named pkgs it
    replaces on first run (section 5). Using replace_regex alone would stop matching once the first
    swap has put a `<name_prefix>-<version>.pkg` in the policy."""
    if app.get("replace_regex"):
        return "(?:%s)|(?:%s)" % (app["replace_regex"], agent_regex(app))
    return agent_regex(app)


def _parse(policy_xml):
    try:
        root = xmlsafe.fromstring(policy_xml)
    except ValueError as e:
        raise PolicyEditError("policy XML: %s" % e)
    if root.tag != "policy":
        raise PolicyEditError("expected <policy>, got <%s>" % root.tag)
    return root


def _package_elems(root):
    pkgs = root.find("package_configuration/packages")
    if pkgs is None:
        return []
    return [p for p in pkgs if p.tag == "package"]


def _text(elem, name):
    e = elem.find(name)
    return (e.text or "").strip() if e is not None and e.text else ""


def packages(policy_xml):
    """[(id, name, action)] in policy order."""
    out = []
    for p in _package_elems(_parse(policy_xml)):
        pid = _text(p, "id")
        out.append((int(pid) if pid.isdigit() else None, _text(p, "name"), _text(p, "action")))
    return out


def current_version(policy_xml, app, rule):
    """V4: version of the first agent-named pkg (`<name_prefix>-<version>.pkg`) in the policy, or
    None when the policy holds only legacy/hand-named pkgs or none at all."""
    from jamf_dp_sync.versions import version_from_published_name
    pat = re.compile(match_regex(app))
    for _, name, _ in packages(policy_xml):
        if pat.search(name):
            v = version_from_published_name(name, app["name_prefix"], rule)
            if v is not None:
                return v
    return None


def monitor_version(policy_xml, regex, rule):
    """Monitor-only apps: version from the `version` group of the first matching pkg name, or None."""
    pat = re.compile(regex)
    for _, name, _ in packages(policy_xml):
        m = pat.search(name)
        if m and m.groupdict().get("version"):
            try:
                return rule.parse(m.group("version"))
            except ValueError:
                return None
    return None


def matching_names(policy_xml, regex):
    pat = re.compile(regex)
    return [name for _, name, _ in packages(policy_xml) if pat.search(name)]


class SwapPlan(object):
    def __init__(self, changed, put_xml=None, removed=None, replaced=None, added=False, warning=None):
        self.changed = changed
        self.put_xml = put_xml
        self.removed = removed or []    # names taken out of the policy
        self.replaced = replaced        # name of the entry whose position/action was reused
        self.added = added              # True when appended under add_if_missing
        self.warning = warning

    def __repr__(self):
        return "SwapPlan(changed=%r, removed=%r, added=%r, warning=%r)" % (
            self.changed, self.removed, self.added, self.warning)


def _new_entry(pkg_id, pkg_name, template=None):
    e = ET.Element("package")
    ET.SubElement(e, "id").text = str(pkg_id)
    ET.SubElement(e, "name").text = pkg_name
    for tag in PASSTHROUGH:
        src = template.find(tag) if template is not None else None
        if src is not None:
            ET.SubElement(e, tag).text = src.text
        elif tag == "action":
            ET.SubElement(e, tag).text = DEFAULT_ACTION
        elif template is None:
            ET.SubElement(e, tag).text = "false"
    return e


def plan_swap(policy_xml, regex, new_id, new_name, add_if_missing=False):
    """Work out the PUT body that puts (new_id, new_name) in place of the matching entries."""
    root = _parse(policy_xml)
    entries = _package_elems(root)
    pat = re.compile(regex)
    matches = [p for p in entries if pat.search(_text(p, "name"))]

    if len(matches) == 1 and _text(matches[0], "name") == new_name and _text(matches[0], "id") == str(new_id):
        return SwapPlan(False)
    if not matches and not add_if_missing:
        return SwapPlan(False, warning="no package matching %r in policy; add_if_missing is false" % regex)
    if any(_text(p, "id") == str(new_id) and p not in matches for p in entries):
        raise PolicyEditError("package id %s is already in the policy under another name" % new_id)

    new_list = []
    removed = []
    replaced = None
    for p in entries:
        if p in matches:
            if replaced is None:
                replaced = _text(p, "name")
                new_list.append(_new_entry(new_id, new_name, template=p))
            if _text(p, "name") != new_name:
                removed.append(_text(p, "name"))
        else:
            new_list.append(copy.deepcopy(p))
    added = False
    if not matches:
        new_list.append(_new_entry(new_id, new_name))
        added = True

    put = ET.Element("policy")
    pc = ET.SubElement(put, "package_configuration")
    pk = ET.SubElement(pc, "packages")
    ET.SubElement(pk, "size").text = str(len(new_list))
    for e in new_list:
        pk.append(e)
    body = ET.tostring(put, encoding="utf-8")
    if not body.startswith(b"<?xml"):
        body = b'<?xml version="1.0" encoding="UTF-8"?>' + body
    return SwapPlan(True, body, removed, replaced, added)
