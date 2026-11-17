"""`7zz` helpers (D2): list an archive and extract exactly one member, unprivileged.

Used by `dmg_extract` (D12) and by the Adobe resolver for a 7z-wrapped manifest (D11 fallback).
No mounting, loop devices or root.
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile

from jamf_dp_sync.errors import ToolError, VerifyError

LIST_TIMEOUT = 300
EXTRACT_TIMEOUT = 1800


def _run(args, timeout):
    try:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise ToolError("cannot run %s: %s" % (args[0], e))
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        raise ToolError("%s %s timed out after %ds" % (os.path.basename(args[0]), args[1], timeout))
    if p.returncode != 0:
        msg = err.decode("utf-8", "replace").strip().splitlines()
        raise ToolError("%s %s failed (exit %d): %s" % (os.path.basename(args[0]), args[1], p.returncode,
                                                         msg[-1] if msg else "no message"))
    return out.decode("utf-8", "replace")


def parse_slt(text):
    """Parse `7zz l -slt` output into a list of dicts (one per member, archive header excluded)."""
    if "\n----------\n" not in "\n" + text:
        raise ToolError("unexpected 7zz listing format (no '----------' separator)")
    body = ("\n" + text).split("\n----------\n", 1)[1]
    members = []
    for block in re.split(r"\n\s*\n", body):
        entry = {}
        for line in block.splitlines():
            if " = " in line:
                k, v = line.split(" = ", 1)
                entry[k.strip()] = v
            elif line.endswith(" ="):
                entry[line[:-2].strip()] = ""
        if "Path" in entry:
            members.append(entry)
    return members


def list_members(sevenzip, archive):
    return parse_slt(_run([sevenzip, "l", "-slt", archive], LIST_TIMEOUT))


def is_safe_member(path):
    if not path or path.startswith("/") or path.startswith("\\") or "\0" in path:
        return False
    if re.match(r"^[A-Za-z]:", path):
        return False
    parts = re.split(r"[/\\]", path)
    return ".." not in parts


def select_one(members, regex, what):
    """Exactly one non-folder member whose Path matches `regex` (re.search)."""
    pat = re.compile(regex)
    hits = [m["Path"] for m in members
            if m.get("Folder", "-") != "+" and pat.search(m["Path"])]
    if len(hits) != 1:
        raise VerifyError("%s: expected exactly one member matching %r, found %d%s"
                          % (what, regex, len(hits), (": " + ", ".join(hits[:5])) if hits else ""))
    member = hits[0]
    if not is_safe_member(member):
        raise VerifyError("%s: unsafe member path %r" % (what, member))
    return member


def extract_one(sevenzip, archive, member, parent_dir):
    """Extract `member` into a fresh temp dir under `parent_dir`. Returns the extracted file path.

    The caller owns (and must remove) the returned file's directory: os.path.dirname of the
    returned value's top-level temp dir is given by `extract_root(path)`.
    """
    if not is_safe_member(member):
        raise VerifyError("unsafe member path %r" % member)
    tmp = tempfile.mkdtemp(prefix="extract-", dir=parent_dir)
    try:
        # -spd: treat the member name literally (no wildcards); -y: no prompts.
        _run([sevenzip, "x", "-y", "-spd", "-o" + tmp, archive, member], EXTRACT_TIMEOUT)
        out = os.path.join(tmp, *re.split(r"[/\\]", member))
        real_tmp = os.path.realpath(tmp)
        if not os.path.realpath(out).startswith(real_tmp + os.sep):
            raise VerifyError("extracted member escapes the temp directory")
        if not os.path.lexists(out):
            raise VerifyError("7zz reported success but %r was not extracted" % member)
        st = os.lstat(out)
        if not stat.S_ISREG(st.st_mode):
            raise VerifyError("extracted member %r is not a regular file" % member)
        return out
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def extract_root(extracted_path, parent_dir):
    """The temp dir created by extract_one for `extracted_path`."""
    rel = os.path.relpath(extracted_path, parent_dir)
    return os.path.join(parent_dir, rel.split(os.sep, 1)[0])
