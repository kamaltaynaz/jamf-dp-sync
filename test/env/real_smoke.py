#!/usr/bin/env python3
"""L1 real-download smoke (spec section 11.3 L1, "Real downloads"). Run INSIDE the Lima VM as the
service user, e.g.  python3 /opt/jamf-dp-sync/test/env/real_smoke.py --only nudge chrome

Real upstream sources, real Packages/ and staging on the VM's /srv, the pinned ~/bin/7zz; Jamf Pro
and Google Chat are the local stubs (in-process), seeded with patch-title versions taken from the
dev Jamf (DECISIONS F4) unless overridden with --title label=version. Nothing leaves the VM except
the upstream downloads. For each app it reports what the real pkg declares (the section 7 "pkg form"
cells), its signer, size and timing, and settles D12 (Google Drive DMG) and D13 (Office version).
"""
import argparse
import datetime
import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "test", "env", "stubs"))

import gchat_stub  # noqa: E402
import jamf_stub  # noqa: E402

from jamf_dp_sync import config, logsetup, ownership, pkginfo, runner, secrets, signer  # noqa: E402
from jamf_dp_sync.xar import XarArchive  # noqa: E402

# Newest dev patch-title versions on 2026-11-09 (DECISIONS F4).
DEV_TITLES = {"nudge": "2.1.4.81863", "dialog": "3.1.1", "acrobat": "26.003.22075",
              "office": "16.114.26110224", "chrome": "158.0.8127.18", "zoom": "7.2.5 (90525)"}
# Google Drive left the sync list (its APFS DMG cannot be opened with 7-Zip); not in packages.example.json.
POLICY = {"nudge": 101, "dialog": 102, "acrobat": 103, "office": 104, "chrome": 105, "zoom": 106,
          "googledrive": 107, "vpnclient": 108, "sensor": 109}
TITLE = {"nudge": 208, "dialog": 209, "acrobat": 201, "office": 202, "chrome": 203, "zoom": 204,
         "googledrive": 205, "vpnclient": 206, "sensor": 207}


def owned_new_files(names, entries, dp, anchor_dir):
    """Rounds three #6, four #2: delete only files the agent published in this smoke run (ownership
    entry with the same anchored inode), never anything else that appeared in Packages/ meanwhile."""
    return sorted(n for n in names if (entries.get(n) or {}).get("state") == ownership.PUBLISHED
                  and ownership.matches(entries[n], os.path.join(dp, n), anchor_dir))


def seed(titles):
    policies = {}
    for label, pid in POLICY.items():
        policies[str(pid)] = ("<policy><general><id>%d</id><name>smoke %s</name></general><package_configuration>"
                              "<packages><size>0</size></packages></package_configuration></policy>" % (pid, label))
    defs = [{"id": str(TITLE[l]), "displayName": l, "softwareTitleId": str(TITLE[l]), "packages": [],
             "definitions": [{"version": titles.get(l, "1.0"), "absoluteOrderId": "0", "releaseDate": "2026-11-09"}]}
            for l in TITLE]
    return {"clients": {"smoke": "smoke-secret"}, "packages": [], "policies": policies, "patch_titles": defs}


def inspect(path, team, openssl):
    with XarArchive(path) as x:
        raw, source = pkginfo.read_version(x)
        cn = signer.check_xar_signer(x, team, openssl)
        dist = x.read("Distribution").decode("utf-8", "replace") if "Distribution" in x.members else ""
        products = [l.strip() for l in dist.splitlines() if "<product" in l or ("<pkg-ref" in l and "version=" in l)]
    return {"pkg_version_raw": raw, "pkg_version_source": source, "signer": cn, "distribution_lines": products[:4]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="+", default=list(DEV_TITLES))
    ap.add_argument("--title", action="append", default=[], help="label=version override")
    ap.add_argument("--keep", action="store_true", help="keep published pkgs in Packages/ afterwards")
    ap.add_argument("--report", default=None)
    a = ap.parse_args()
    titles = dict(DEV_TITLES)
    for t in a.title:
        k, v = t.split("=", 1)
        titles[k] = v

    tmp = tempfile.mkdtemp(prefix="jds-smoke-")
    jsrv, jstate, jurl = jamf_stub.start(seed(titles))
    csrv, cstate, curl = gchat_stub.start()
    home = os.path.join(tmp, "home")
    os.makedirs(os.path.join(home, ".config", "jamf-dp-sync"))
    envf = os.path.join(home, ".config", "jamf-dp-sync", "env")
    with open(envf, "w") as f:
        f.write("JAMF_URL=%s\nJAMF_CLIENT_ID=smoke\nJAMF_CLIENT_SECRET=smoke-secret\nGITHUB_TOKEN=\n"
                "GCHAT_WEBHOOK_URL=%s/v1/spaces/SMOKE/messages?key=k&token=t\n" % (jurl, curl))
    os.chmod(envf, 0o600)
    with open(os.path.join(ROOT, "packages.example.json")) as f:
        raw = json.load(f)
    raw.update(dp_packages_dir="/srv/shares/jamf/Packages", staging_dir="/srv/jamf-dp-sync-staging",
               log_file=os.path.join(tmp, "smoke.log"), lock_file=os.path.join(tmp, "run.lock"),
               tools={"openssl": "/usr/bin/openssl", "7zz": os.path.expanduser("~/bin/7zz")})
    raw.pop("dp_group", None)
    for app in raw["apps"]:
        app["policy_ids"] = [POLICY[app["label"]]]
        app["patch_title_id"] = TITLE[app["label"]]
        if app["mode"] == "sync":
            app["add_if_missing"] = True     # smoke policies start empty
            app.pop("replace_regex", None)
    cfgp = os.path.join(tmp, "packages.json")
    with open(cfgp, "w") as f:
        json.dump(raw, f)

    os.environ["HOME"] = home
    report = {"date": datetime.datetime.now().isoformat(), "titles": titles, "apps": {}}
    before = set(os.listdir(raw["dp_packages_dir"]))
    try:
        cfg = config.load(cfgp)
        secrets.init()
        log = logsetup.setup(cfg["log_file"], verbose=True, stream=True)
        for label in a.only:
            app = cfg.app(label)
            t0 = time.time()
            args = argparse.Namespace(only=[label], dry_run=False, no_prune=True, verbose=True)
            code = runner.cmd_run(cfg, args, log)
            entry = {"exit": code, "seconds": round(time.time() - t0, 1)}
            new = sorted(set(os.listdir(cfg["dp_packages_dir"])) - before)
            mine = [n for n in new if n.startswith(app["name_prefix"] + "-")]
            if mine:
                path = os.path.join(cfg["dp_packages_dir"], mine[0])
                entry.update(published=mine[0], size=os.path.getsize(path))
                entry.update(inspect(path, app["team_id"], cfg.tool("openssl")))
            with jstate.lock:
                entry["policy"] = jstate.policies[str(POLICY[label])][-300:]
            with open(cfg["log_file"]) as f:
                entry["log_tail"] = [l for l in f.read().splitlines() if label in l][-6:]
            report["apps"][label] = entry
            print(json.dumps({label: entry}, indent=1))
            sys.stdout.flush()
    finally:
        if not a.keep:
            dp = raw["dp_packages_dir"]
            # This run's own store (temp HOME) and its own anchor folder (round five #3).
            store = ownership.OwnershipStore(
                anchor_dir=ownership.anchor_dir_for(raw["staging_dir"], ownership.DEFAULT_PATH))
            for n in owned_new_files(set(os.listdir(dp)) - before, store.load(), dp, store.anchor_dir):
                os.unlink(os.path.join(dp, n))
                store.remove(n)                             # also frees its anchor in staging
            try:
                os.rmdir(store.anchor_dir)
            except OSError:
                pass
        jsrv.shutdown()
        csrv.shutdown()
        out = a.report or os.path.join(tempfile.gettempdir(), "jds-smoke-report.json")
        with open(out, "w") as f:
            json.dump(report, f, indent=1)
        print("report: %s" % out)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
