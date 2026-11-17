"""Atomic publish into Packages/ (spec section 9): chmod 0644, optional chgrp, then a no-clobber
move on the same filesystem.

os.link + unlink is used instead of rename: it is just as atomic on one filesystem but fails if the
name already exists, so a published pkg can never be overwritten. If a file with that name is
already there with the same SHA-512 (an earlier run published it), it is reused; a different file
under the same name stops the app.
"""
import grp
import hashlib
import os

from jamf_dp_sync.errors import SyncError


class PublishError(SyncError):
    step = "publish"


def _sha512(path):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def publish(staged, packages_dir, name, sha512, dp_group=None):
    """Return (final_path, reused). Removes `staged` in every outcome except an exception before move."""
    if not name or "/" in name or name.startswith("."):
        raise PublishError("unsafe pkg name %r" % name)
    final = os.path.join(packages_dir, name)
    os.chmod(staged, 0o644)
    if dp_group:
        try:
            os.chown(staged, -1, grp.getgrnam(dp_group).gr_gid)
        except (KeyError, OSError) as e:
            raise PublishError("cannot set group %s: %s" % (dp_group, e))
    with open(staged, "rb") as f:   # the bytes are on disk before the name appears (round three #8)
        os.fsync(f.fileno())
    try:
        os.link(staged, final)
    except FileExistsError:
        if _sha512(final) == sha512:
            _discard(staged)
            return final, True
        raise PublishError("%s already exists in Packages/ with different content" % name)
    except OSError as e:
        raise PublishError("cannot publish %s: %s" % (name, e))
    try:
        dfd = os.open(packages_dir, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass  # best effort on filesystems that refuse directory fsync
    _discard(staged)  # the pkg is published; a leftover staged name is only clutter (round four #4)
    return final, False


def _discard(staged):
    try:
        os.unlink(staged)
    except OSError:
        pass  # removed with the app's staging files at the next failure or run
