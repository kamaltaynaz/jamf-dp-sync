"""`dmg_extract` post-download step (spec section 6), for Google Drive (D12).

1. `7zz l` the DMG; select exactly one member matching `inner_path_regex`.
2. Extract that member only, into a fresh temp directory under staging_dir. Absolute paths and `..`
   are rejected.
3. The extracted pkg replaces the DMG for every later step (the DMG is deleted).
"""
import os
import shutil

from jamf_dp_sync import sevenzip


def dmg_extract(dmg_path, inner_path_regex, staging_dir, sevenzip_bin):
    """Return the path of the extracted pkg, moved next to the DMG; the DMG is removed.

    On any failure the DMG and any temp directory are removed and the error propagates.
    """
    extracted = None
    try:
        members = sevenzip.list_members(sevenzip_bin, dmg_path)
        member = sevenzip.select_one(members, inner_path_regex, "dmg_extract")
        extracted = sevenzip.extract_one(sevenzip_bin, dmg_path, member, staging_dir)
        out = dmg_path[:-4] + ".pkg" if dmg_path.endswith(".dmg") else dmg_path + ".pkg"
        os.rename(extracted, out)
        return out
    finally:
        if extracted is not None:
            shutil.rmtree(sevenzip.extract_root(extracted, staging_dir), ignore_errors=True)
        try:
            os.unlink(dmg_path)
        except OSError:
            pass
