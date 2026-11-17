"""The agent's private folders under staging: the scratch folder `<staging_dir>/.jds-scratch/`
(round seven #1, round eight #1) and the ownership anchors `<staging_dir>/.jds-owned/<store-id>/`
(round nine #1). The same rule applies to all of them.

Every download, manifest and extraction is written here, and start-of-run recovery empties it, so it
must be exactly what the agent created: a real directory (never a symlink), owned by the service
user, not writable by group or others, on the same filesystem as Packages/ (so publishing is a hard
link). Anything else is refused before a single byte is written or deleted through it, in dry runs
too; preflight reports it.
"""
import os
import stat

from jamf_dp_sync.errors import SyncError

NAME = ".jds-scratch"


def path_for(staging_dir):
    return os.path.join(staging_dir, NAME)


def dir_problem(d, what, packages_dir=None):
    """Why private folder `d` is unsafe, or None (also None while it does not exist yet): it must be
    a real directory (never a symlink), owned by this user, not writable by group or others, and,
    with `packages_dir`, on the same filesystem as Packages/."""
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        return None
    except OSError as e:
        return "%s %s cannot be checked: %s" % (what, d, e)
    if not stat.S_ISDIR(st.st_mode):
        return "%s %s is not a real directory (a symlink or file); remove it by hand" % (what, d)
    if st.st_uid != os.geteuid():
        return "%s %s is owned by another user" % (what, d)
    if st.st_mode & 0o022:
        return "%s %s is writable by group or others" % (what, d)
    if packages_dir is not None:
        try:
            if os.stat(packages_dir).st_dev != st.st_dev:
                return "%s %s is not on the same filesystem as Packages/" % (what, d)
        except OSError as e:
            return "cannot check Packages/ %s against %s: %s" % (packages_dir, d, e)
    return None


def problem(staging_dir, packages_dir):
    """Why the scratch folder is unsafe, or None."""
    return dir_problem(path_for(staging_dir), "scratch folder", packages_dir)


def anchor_problem(anchor_dir):
    """Why the anchor folders (`.jds-owned` and the store's own folder below it) are unsafe, or None."""
    return (dir_problem(os.path.dirname(anchor_dir), "anchor folder")
            or dir_problem(anchor_dir, "anchor folder"))


def ensure(staging_dir, packages_dir):
    """Create the scratch folder if needed and return it, or raise if it is unsafe."""
    d = path_for(staging_dir)
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    except OSError as e:
        raise SyncError("cannot create scratch folder %s: %s" % (d, e), step="preflight")
    p = problem(staging_dir, packages_dir)
    if p:
        raise SyncError(p, step="preflight")
    return d
