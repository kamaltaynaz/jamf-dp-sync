"""Run preflight (spec section 9). Any problem aborts the run before any app is touched.

Checks: Packages/ and staging exist and are writable by this user (os.access honours the ACL from
DECISIONS Q16), staging is on the same filesystem as Packages/ (st_dev), openssl is runnable, 7zz is
runnable when an app needs it (dmg_extract), and free space on that filesystem is at least
2 x the largest expected pkg (MIN_FREE). Config validity is checked earlier by config.load().
"""
import os

from jamf_dp_sync import config, faults, scratch

GIB = 1024 ** 3
LARGEST_PKG = 3 * GIB          # Office is about 2.5 GB (spec section 4)
MIN_FREE = 2 * LARGEST_PKG     # spec section 9: free space >= 2 x largest expected pkg


def _runnable(path):
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def needs_7zz(cfg):
    return any((a.get("post_download") or {}).get("type") == "dmg_extract"
               for a in cfg.apps if a["mode"] == "sync")


def check(cfg, apps=None):
    """Return a list of human-readable problems; empty means go."""
    problems = []
    dp, staging = cfg["dp_packages_dir"], cfg["staging_dir"]
    for name, path in (("Packages/", dp), ("staging", staging)):
        if not os.path.isdir(path):
            problems.append("%s %s does not exist" % (name, path))
        elif not os.access(path, os.W_OK | os.X_OK):
            problems.append("%s %s is not writable by this user" % (name, path))
    problems.extend(config.staging_problems(dp, staging, resolve=True))
    sp = scratch.problem(staging, dp)  # round eight #1: never write or clean through an unsafe scratch folder
    if sp:
        problems.append(sp)
    from jamf_dp_sync import ownership  # round nine #1: nor through an unsafe anchor folder
    ap = scratch.anchor_problem(ownership.anchor_dir_for(staging, ownership.DEFAULT_PATH))
    if ap:
        problems.append(ap)
    if faults.on("dp_not_writable"):
        problems.append("Packages/ %s is not writable by this user (fault)" % dp)
    if os.path.isdir(dp) and os.path.isdir(staging):
        same = os.stat(dp).st_dev == os.stat(staging).st_dev
        if not same or faults.on("staging_other_fs"):
            problems.append("staging %s is not on the same filesystem as Packages/ %s" % (staging, dp))
        else:
            st = os.statvfs(staging)
            free = st.f_bavail * st.f_frsize
            if free < MIN_FREE:
                problems.append("only %.1f GiB free on the Packages/ filesystem; need %.0f GiB"
                                % (free / float(GIB), MIN_FREE / float(GIB)))
    if not _runnable(cfg.tool("openssl")):
        problems.append("openssl not found at %s" % cfg.tool("openssl"))
    selected = cfg.apps if apps is None else apps
    if any((a.get("post_download") or {}).get("type") == "dmg_extract" for a in selected if a["mode"] == "sync"):
        if faults.on("no_7zz") or not _runnable(cfg.tool("7zz")):
            problems.append("7zz not found at %s (needed for dmg_extract)" % cfg.tool("7zz"))
    return problems
