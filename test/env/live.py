#!/usr/bin/env python3
"""L2 on a TEST Jamf Pro (spec section 11.3). Run inside the Lima VM as the service user.

  live.py prep --category-id N     read-only: find the test policies by trigger, write packages.test.json
  live.py run                      the L2 scenarios (WRITES to dev Jamf: TEST-jds-* records, test
                                   policies' package lists, title mappings)
  live.py cleanup                  remove every TEST-jds-* record, file, policy entry and title mapping

Isolation (section 11.3): only `TEST-jds-*` names in category jamf-dp-sync-test; only policies whose
custom trigger is `test-install-<app>-jsm` (created by hand, scoped to no computers); the Lima VM's
Packages/. Secrets come from the service user's 0600 env file (dev JAMF_URL, the jamf-dp-sync-test
client, the test Chat space).
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from jamf_dp_sync import secrets, versions  # noqa: E402
from jamf_dp_sync.httpclient import HttpClient  # noqa: E402
from jamf_dp_sync.jamf import policy_xml  # noqa: E402
from jamf_dp_sync.jamf.client import AGENT_MARKER, JamfClient  # noqa: E402

# The repo is read-only in the VM; the generated test config lives with the service user's config.
TEST_CONFIG = os.path.expanduser("~/.config/jamf-dp-sync/packages.test.json")
DEV_TITLES = {"nudge": 72, "dialog": 54, "acrobat": 47, "office": 51, "chrome": 80, "zoom": 3}  # F4
PREFIX = "TEST-jds-"           # only names this harness's configs produce (review #8)
# The one Jamf Pro this harness may write to; JDS_LIVE_HOST overrides it (public release).
DEV_HOST = os.environ.get("JDS_LIVE_HOST", "jamf-test.example.com").strip().lower()
VM_DP = "/srv/shares/jamf/Packages"


class Refuse(SystemExit):
    pass


def check_origin(url):
    """Review #9: exact https origin, not a substring (jamf-test.example.com.example.org must fail)."""
    import urllib.parse
    u = urllib.parse.urlsplit(url or "")
    if u.scheme != "https" or (u.hostname or "").lower() != DEV_HOST or u.username or u.password:
        raise Refuse("refusing: JAMF_URL must be https://%s[:port] (got host %r)" % (DEV_HOST, u.hostname))


def client():
    secrets.init()
    url = secrets.get_secret("JAMF_URL")
    check_origin(url)
    return JamfClient(url, secrets.get_secret("JAMF_CLIENT_ID"), secrets.get_secret("JAMF_CLIENT_SECRET"),
                      HttpClient(timeout=60))


def policy_problems(xml, label, category_id=None):
    """A test policy must have only its test trigger, no scope, no Self Service, the test category.
    Parsed structurally, so whitespace or attribute variations cannot slip past (review 2 #3)."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml.encode("utf-8") if isinstance(xml, str) else xml)
    except ET.ParseError as e:
        return ["policy XML does not parse: %s" % e]

    def text(path):
        e = root.find(path)
        return (e.text or "").strip().lower() if e is not None and e.text else ""
    problems = []
    if text("general/trigger_other") != ("test-install-%s-jsm" % label):
        problems.append("trigger is not test-install-%s-jsm" % label)
    for t in ("checkin", "enrollment_complete", "login", "logout", "startup", "network_state_changed"):
        if text("general/trigger_%s" % t) == "true":
            problems.append("has trigger %s" % t)
    if text("scope/all_computers") == "true":
        problems.append("scoped to all computers")
    scope = root.find("scope")
    if scope is not None:
        for kind in ("computers/computer", "computer_groups/computer_group", "buildings/building",
                     "departments/department", "limit_to_users/user_groups/user_group"):
            if scope.findall(kind):
                problems.append("has scope targets (%s)" % kind.split("/")[-1])
    if text("self_service/use_for_self_service") == "true":
        problems.append("Self Service enabled")
    if not _real_category(category_id):  # round four #7: no "any category" escape
        problems.append("no test category given (%r)" % (category_id,))
    elif text("general/category/id") != str(category_id):
        problems.append("not in category %s" % category_id)
    return problems


def validate_config(cfg, j):
    """Before any write: every app is a TEST-jds-* app on an isolated test policy, DP is the VM's."""
    problems = []
    if cfg.get("dp_packages_dir") != VM_DP:
        problems.append("dp_packages_dir is not the Lima VM's %s" % VM_DP)
    for app in cfg["apps"]:
        effective = app.get("category_id", cfg.get("category_id"))
        if effective != cfg.get("category_id"):  # round five #4: records land where cleanup looks
            problems.append("%s: category_id %r is not the test category %r"
                            % (app["label"], effective, cfg.get("category_id")))
        if not app["name_prefix"].startswith(PREFIX):
            problems.append("%s: name_prefix %s does not start with %s" % (app["label"], app["name_prefix"], PREFIX))
        for pid in app["policy_ids"]:
            for p in policy_problems(j.get_policy_xml(pid).decode("utf-8"), app["label"], cfg.get("category_id")):
                problems.append("%s: policy %s %s" % (app["label"], pid, p))
    if problems:
        raise Refuse("refusing to write to Jamf:\n  " + "\n  ".join(problems))


def prep(args):
    """Read-only. Find test-install-<app>-jsm policies and write packages.test.json."""
    if not _real_category(args.category_id):
        raise Refuse("refusing: --category-id must be the test category's ID (> 0)")
    j = client()
    try:
        r = j._call("GET", "/JSSResource/policies", accept="application/json", ok=(200,)).json()
        found = {}
        for p in r["policies"]:
            xml = j.get_policy_xml(int(p["id"])).decode("utf-8")
            m = re.search(r"<trigger_other>test-install-([a-z0-9]+)-jsm</trigger_other>", xml)
            if m:
                bad = policy_problems(xml, m.group(1), args.category_id)
                print("policy %s %-28s trigger test-install-%s-jsm%s" % (p["id"], p["name"], m.group(1),
                                                                         "  REFUSED: " + "; ".join(bad) if bad else ""))
                if bad:
                    raise Refuse("test policy %s is not isolated: %s" % (p["id"], "; ".join(bad)))
                found[m.group(1)] = int(p["id"])
    finally:
        j.invalidate()
    with open(os.path.join(ROOT, "packages.example.json")) as f:
        raw = json.load(f)
    apps = []
    for app in raw["apps"]:
        if app["mode"] != "sync" or app["label"] not in found:
            continue
        app = dict(app, name_prefix="TEST-" + app["name_prefix"], policy_ids=[found[app["label"]]],
                   patch_title_id=DEV_TITLES[app["label"]], add_if_missing=True)
        app.pop("replace_regex", None)
        apps.append(app)
    missing = sorted(set(DEV_TITLES) - set(found))
    raw.update(apps=apps, category_id=args.category_id, dp_packages_dir=VM_DP,
               staging_dir="/srv/jamf-dp-sync-staging")
    raw.pop("dp_group", None)
    with open(args.out, "w") as f:
        json.dump(raw, f, indent=2)
        f.write("\n")
    print("wrote %s with %d apps%s" % (args.out, len(apps), "; no test policy for: " + ", ".join(missing) if missing else ""))


def agent(*argv):
    p = subprocess.run([sys.executable, os.path.join(ROOT, "jamf_dp_sync.py"), "--config", TEST_CONFIG] + list(argv),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return p.returncode, p.stdout, p.stderr


def check(ok, what):
    print("%s  %s" % ("PASS" if ok else "FAIL", what))
    return ok


def owned_files(files, owned_names):
    """Review 2 #2: files are deleted only when a marked, harness-prefixed record owns that name."""
    owned = set(owned_names)
    return [f for f in files if f in owned]


def is_harness_name(name, prefixes):
    """A name this harness created: one of the configured TEST-jds-<Name> prefixes, then '-'."""
    return any(name.startswith(p + "-") and name.endswith(".pkg") for p in prefixes)


def _real_category(category_id):
    return isinstance(category_id, int) and not isinstance(category_id, bool) and category_id > 0


def select_owned(records, prefixes, category_id):
    """Rounds one #8, three #7, four #7: marked, harness-prefixed records in the test category (which
    must be a real category ID) whose fileName equals their packageName. Nothing else is touched."""
    if not _real_category(category_id):
        raise Refuse("refusing: the test config has no real test category (%r)" % (category_id,))
    out = []
    for r in records:
        name = r.get("packageName") or ""
        if not (is_harness_name(name, prefixes) and AGENT_MARKER in (r.get("notes") or "")):
            continue
        if r.get("fileName") != name:
            continue
        if str(r.get("categoryId")) != str(category_id):
            continue
        out.append(r)
    return out


def deletable_files(names, entries, dp, anchor_dir):
    """Rounds three #7, four #2: a file is deleted only when the agent's ownership store records
    publishing that very file (anchored inode), not merely because its name matches."""
    from jamf_dp_sync import ownership
    return sorted(n for n in names if (entries.get(n) or {}).get("state") in (ownership.PUBLISHED, ownership.PRUNING)
                  and ownership.matches(entries[n], os.path.join(dp, n), anchor_dir))


def test_records(j, prefixes=None, category_id=None):
    if prefixes is None or category_id is None:
        with open(TEST_CONFIG) as f:
            cfg = json.load(f)
        prefixes = prefixes or [a["name_prefix"] for a in cfg["apps"]]
        category_id = cfg.get("category_id") if category_id is None else category_id
    return select_owned(j.list_packages(), prefixes, category_id)


def _same_version(rule, text, version):
    try:
        return rule.parse(text or "") == version
    except ValueError:
        return False


def run(args):
    with open(TEST_CONFIG) as f:
        cfg = json.load(f)
    apps = [a for a in cfg["apps"] if not args.only or a["label"] in args.only]
    labels = [a["label"] for a in apps]
    j = client()
    results = []
    try:
        validate_config(cfg, j)  # review #9: re-check isolation before the first write
        # A12: dry run changes nothing.
        before = len(test_records(j))
        code, out, err = agent("run", "--dry-run", "--only", *labels)
        results.append(check(code == 0 and "would publish" in out and len(test_records(j)) == before,
                             "A12 dry run: intended actions printed, no Jamf change"))
        # A1: first run publishes, creates records with SHA-512, swaps the test policies.
        code, out, err = agent("run", "--only", *labels)
        results.append(check(code in (0, 1), "A1 first run finished (exit %d)" % code))
        recs = dict((r["packageName"], r) for r in test_records(j))
        for app in apps:
            rule = versions.get_rule(app["version_rule"])
            xml = j.get_policy_xml(app["policy_ids"][0])
            cur = policy_xml.current_version(xml, app, rule)
            name = versions.published_name(app["name_prefix"], rule, cur) if cur else None
            rec = recs.get(name)
            path = os.path.join(cfg["dp_packages_dir"], name or "-")
            ok = (cur is not None and rec is not None and rec.get("hashType") == "SHA_512"
                  and AGENT_MARKER in (rec.get("notes") or "") and os.path.exists(path))
            results.append(check(ok or app["label"] == "chrome",
                                 "A1 %s: policy holds %s, record SHA_512 + marker, file on DP%s"
                                 % (app["label"], name, " (Chrome may skip: OPEN Q19)" if app["label"] == "chrome" else "")))
            if rec is not None:
                title = j.patch_title(app["patch_title_id"])
                mapped = [m for m in title.get("packages") or [] if str(m.get("packageId")) == str(rec["id"])
                          and _same_version(rule, m.get("version"), cur)]
                results.append(check(bool(mapped), "A17 %s: pkg mapped to dev title %s at its own version %s"
                                     % (app["label"], app["patch_title_id"], mapped[0]["version"] if mapped else "-")))
        # A2: second run is a no-op.
        writes_before = [(r["id"], r["packageName"]) for r in test_records(j)]
        code, out, err = agent("run", "--only", *labels)
        results.append(check(code == 0 and [(r["id"], r["packageName"]) for r in test_records(j)] == writes_before,
                             "A2 second run: exit 0, no new records (exit %d)" % code))
        # A9 + A10 on Nudge: pin back, then forward, then prune keeps retain + current.
        if "nudge" in labels:
            results.extend(_pin_and_prune(j, cfg))
    finally:
        j.invalidate()
    print("\n%d/%d checks passed" % (sum(results), len(results)))
    return 0 if all(results) else 1


def _pin_and_prune(j, cfg):
    out = []
    path = TEST_CONFIG
    original = json.load(open(path))

    def set_pin(pin):
        raw = json.load(open(path))
        for a in raw["apps"]:
            if a["label"] == "nudge":
                if pin:
                    a["pin"] = pin
                else:
                    a.pop("pin", None)
        with open(path, "w") as f:
            json.dump(raw, f, indent=2)

    app = [a for a in original["apps"] if a["label"] == "nudge"][0]
    rule = versions.get_rule("dotted")
    try:
        for pin in ("2.1.2.81856", "2.1.3.81860", None):
            set_pin(pin)
            code, _, err = agent("run", "--only", "nudge")
            cur = policy_xml.current_version(j.get_policy_xml(app["policy_ids"][0]), app, rule)
            want = pin or "2.1.4.81863"
            out.append(check(code == 0 and str(cur) == want, "A9 nudge pin %s -> policy holds %s" % (pin, cur)))
        names = sorted(r["packageName"] for r in test_records(j) if r["packageName"].startswith(app["name_prefix"] + "-"))
        out.append(check(len(names) == app.get("retain", original.get("retain", 2)),
                         "A10 prune: %d agent records remain: %s" % (len(names), ", ".join(names))))
        files = sorted(n for n in os.listdir(cfg["dp_packages_dir"]) if n.startswith(app["name_prefix"] + "-"))
        out.append(check(files == names, "A10 prune: files match records"))
    finally:
        with open(path, "w") as f:
            json.dump(original, f, indent=2)
            f.write("\n")
    return out


def _without_owned_packages(xml, owned_ids):
    """PUT body keeping every <package> whose id is not an owned record, exactly as it is (review 2 #2).
    None if there is nothing to drop."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml)
    pk = root.find("package_configuration/packages")
    if pk is None:
        return None
    entries = pk.findall("package")
    keep = [e for e in entries if (e.findtext("id") or "").strip() not in owned_ids]
    if len(keep) == len(entries):
        return None
    out = ET.Element("policy")
    new = ET.SubElement(ET.SubElement(out, "package_configuration"), "packages")
    ET.SubElement(new, "size").text = str(len(keep))
    for e in keep:
        new.append(e)
    return ET.tostring(out, encoding="utf-8")


def cleanup(args):
    with open(TEST_CONFIG) as f:
        cfg = json.load(f)
    prefixes = [a["name_prefix"] for a in cfg["apps"] if a["name_prefix"].startswith(PREFIX)]
    j = client()
    try:
        validate_config(cfg, j)  # review 2 #3: isolation re-checked before cleanup writes too
        recs = test_records(j, prefixes, cfg.get("category_id"))  # owned records only
        ids = set(str(r["id"]) for r in recs)
        names = [r["packageName"] for r in recs]
        for app in cfg["apps"]:
            title = j.patch_title(app["patch_title_id"])
            keep = [{"packageId": str(m["packageId"]), "version": m["version"]} for m in title.get("packages") or []
                    if str(m["packageId"]) not in ids]
            if len(keep) != len(title.get("packages") or []):
                j._json("PATCH", "/api/v3/patch-software-title-configurations/%d" % app["patch_title_id"],
                        {"packages": keep}, ctype="application/merge-patch+json")
                print("unmapped harness pkgs from title %s" % app["patch_title_id"])
            for pid in app["policy_ids"]:
                body = _without_owned_packages(j.get_policy_xml(pid), ids)
                if body is not None:
                    j.put_policy_xml(pid, body)
                    print("cleared harness entries from policy %s" % pid)
        for r in recs:
            j.delete_package(int(r["id"]))
            print("deleted record %s %s" % (r["id"], r["packageName"]))
        if cfg.get("dp_packages_dir") == VM_DP:
            from jamf_dp_sync import ownership
            store = ownership.OwnershipStore(
                anchor_dir=ownership.anchor_dir_for(cfg["staging_dir"], ownership.DEFAULT_PATH))
            for n in deletable_files(owned_files(os.listdir(VM_DP), names), store.load(), VM_DP, store.anchor_dir):
                os.unlink(os.path.join(VM_DP, n))
                store.remove(n)
                print("deleted file %s" % n)
        left = test_records(j, prefixes, cfg.get("category_id"))
        print("remaining harness records: %d" % len(left))
        return 0 if not left else 1
    finally:
        j.invalidate()


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("prep")
    p.add_argument("--category-id", type=int, required=True, help="the jamf-dp-sync-test category ID (> 0)")
    p.add_argument("--out", default=TEST_CONFIG)
    r = sub.add_parser("run")
    r.add_argument("--only", nargs="+")
    sub.add_parser("cleanup")
    a = ap.parse_args()
    if a.cmd == "prep":
        return prep(a)
    if a.cmd == "run":
        return run(a)
    if a.cmd == "cleanup":
        return cleanup(a)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main() or 0)
