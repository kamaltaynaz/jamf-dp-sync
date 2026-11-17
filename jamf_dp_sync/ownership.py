"""Durable record of which files in Packages/ the agent published (round-two review #4 and #7).

Not a cache: unlike ~/.local/state/jamf-dp-sync (safe to delete), this file is the only proof that a
file without a package record (left by a crash) is the agent's own. It lives at
~/.local/share/jamf-dp-sync/ownership.json and is written atomically with fsync.

Entry states, keyed by published file name:
  pending    written just before the file is hard-linked into Packages/, with the staged file's
             (st_dev, st_ino); a link keeps the inode, so after a crash the file is recognised as
             ours by inode, never by name or bytes alone (round three #4, #8)
  published  the link succeeded; `todo` lists the steps still owed (map, prune) and is the only
             thing the Stop exit may resume (round three #5)
  pruning    written just before a prune deletes the record; the next run deletes the file

Anchors (round four #2). A (st_dev, st_ino) pair names a file only while that inode is alive: once
it is freed, a new file may get the same number. So each entry keeps a private hard link,
`<staging_dir>/.jds-owned/<store-id>/<dev>-<ino>`, created from the staged file before the publish
link and removed only after the entry is gone. `<store-id>` is derived from the ownership file's
path, so stores sharing a staging directory (the smoke harness) never touch each other's anchors
(round five #3). While the anchor exists the inode cannot be reused, so "same
dev and inode as the entry, and its anchor is that inode" proves the file is the one we published.
An entry whose anchor is missing (hand-edited or restored file, deleted anchor) never matches: fail
closed. Contents can still change in place, so steps that act on the bytes also compare the SHA-512.

Re-publishing a name that already has an entry (round five #1): begin() records the attempt as the
entry's `intent` and leaves its identity alone; settle() then promotes the intent if the link
happened, or drops it. A crash in between leaves the earlier, still-valid identity in place.

sweep() runs once at the start of every real run, under the run lock (round five #2): it settles
intents a crash left behind, drops pending entries whose file was never linked, and removes anchors
no entry refers to. Anchors are otherwise collected whenever an entry is dropped or settled.

A missing file means "nothing published yet". A corrupt file stops the affected app (fail closed)
rather than being silently reset.
"""
import errno
import hashlib
import json
import os
import stat as _st
import tempfile

from jamf_dp_sync import scratch
from jamf_dp_sync.errors import SyncError

DEFAULT_PATH = "~/.local/share/jamf-dp-sync/ownership.json"
PENDING, PUBLISHED, PRUNING = "pending", "published", "pruning"


class OwnershipError(SyncError):
    step = "ownership"


class OwnershipStore(object):
    def __init__(self, path=None, read_only=False, anchor_dir=None):
        self.path = os.path.expanduser(path or DEFAULT_PATH)
        self.read_only = read_only
        self.anchor_dir = anchor_dir

    def load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (IOError, OSError) as e:
            if getattr(e, "errno", None) == 2:  # ENOENT: nothing published yet
                return {}
            raise OwnershipError("cannot read %s: %s" % (self.path, e))
        except ValueError as e:
            raise OwnershipError("%s is corrupt (%s); restore it or remove the agent's orphan files by hand"
                                 % (self.path, e))
        entries = data.get("entries") if isinstance(data, dict) else None
        if not isinstance(entries, dict):
            raise OwnershipError("%s has no entries map" % self.path)
        return entries

    def get(self, name):
        return self.load().get(name)

    def _save(self, entries, gc=False):
        if self.read_only:
            return
        d = os.path.dirname(self.path)
        if not os.path.isdir(d):
            os.makedirs(d, 0o700)
        fd, tmp = tempfile.mkstemp(prefix=".ownership.", dir=d)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"entries": entries}, f, indent=1, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp, self.path)
            _fsync_dir(d)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        if gc:  # when an entry or attempt is dropped or settled; never on begin()
            self._gc_anchors(entries)

    def _gc_anchors(self, entries):
        """Remove anchors no entry refers to (after the entry is durably gone, never before)."""
        if not self.anchor_dir or not os.path.isdir(self.anchor_dir):
            return
        if scratch.anchor_problem(self.anchor_dir):
            return  # round nine #1: never list or delete through an unsafe anchor folder
        try:
            present = os.listdir(self.anchor_dir)
        except OSError:
            return  # unreadable now; collected by a later run
        wanted = set()
        for e in entries.values():
            for ident in (e, e.get("intent")):
                if _anchor_name(ident):
                    wanted.add(_anchor_name(ident))
        for n in present:
            if n not in wanted:
                try:
                    os.unlink(os.path.join(self.anchor_dir, n))
                except OSError:
                    pass

    def _set(self, name, **fields):
        entries = self.load()
        entry = dict(entries.get(name) or {})
        entry.update(fields)
        entries[name] = entry
        self._save(entries)

    def begin(self, name, label, sha512, staged):
        """Anchor the staged file, then record it: a new entry in state pending, or the `intent` of
        an existing entry (whose identity stays until settle()). Must precede the publish link."""
        if self.read_only:
            return
        if not self.anchor_dir:
            raise OwnershipError("no anchor directory configured")
        st = os.lstat(staged)
        for d in (os.path.dirname(self.anchor_dir), self.anchor_dir):
            try:
                os.mkdir(d, 0o700)  # each level 0700, whatever the umask
            except FileExistsError:
                pass
            bad = scratch.dir_problem(d, "anchor folder")
            if bad:  # round nine #1: checked before anything is created below it
                raise OwnershipError(bad)
        anchor = os.path.join(self.anchor_dir, "%d-%d" % (st.st_dev, st.st_ino))
        try:
            os.link(staged, anchor)
        except FileExistsError:
            a = os.lstat(anchor)
            if (a.st_dev, a.st_ino) != (st.st_dev, st.st_ino):
                raise OwnershipError("stale anchor %s; remove it by hand" % anchor)
        except OSError as e:
            raise OwnershipError("cannot anchor %s in %s: %s" % (name, self.anchor_dir, e))
        _fsync_dir(self.anchor_dir)
        attempt = {"label": label, "sha512": sha512, "dev": st.st_dev, "ino": st.st_ino}
        entries = self.load()
        if name in entries:
            entries[name] = dict(entries[name], intent=attempt)
        else:
            entries[name] = dict(attempt, state=PENDING, todo=[])
        self._save(entries)

    def settle(self, name, final):
        """After a publish attempt, whatever its outcome. Returns "new" when `final` is the file this
        attempt linked (now published), "prior" when it is the entry's earlier published file, or
        None when it is neither (the attempt is dropped; an unpublished new entry is removed)."""
        if self.read_only:
            return None
        if presence(final) is None:
            return None  # round seven #2: an unreadable path is not proof of absence; keep everything
        entries = self.load()
        entry = entries.get(name)
        if entry is None:
            return None
        intent = entry.get("intent")
        if intent is None and entry.get("state") == PENDING:
            intent, entry = entry, None
        linked = identity(intent, final, self.anchor_dir) if intent is not None else False
        if linked is None:
            return None  # round eight #2: cannot tell (anchor unreadable); keep everything
        outcome = None
        if linked:
            entries[name] = {"label": intent["label"], "sha512": intent["sha512"], "dev": intent["dev"],
                             "ino": intent["ino"], "state": PUBLISHED, "todo": []}
            outcome = "new"
        elif entry is not None:
            entries[name] = dict((k, v) for k, v in entry.items() if k != "intent")
            if entry.get("state") == PUBLISHED and matches(entry, final, self.anchor_dir):
                outcome = "prior"
        else:
            del entries[name]
        self._save(entries, gc=True)
        return outcome

    def sweep(self, packages_dir):
        """Start of a real run, under the run lock: settle what a crash left behind, then collect
        anchors no entry refers to. Pending entries whose file is ours stay for orphan adoption."""
        if self.read_only:
            return
        for name, entry in sorted(self.load().items()):
            final = os.path.join(packages_dir, name)
            if presence(final) is None:
                continue  # cannot tell (permissions, I/O): leave it for a run that can (round seven #2)
            if entry.get("intent") is not None:
                self.settle(name, final)  # promote if the link happened, otherwise drop the attempt
            elif entry.get("state") == PENDING and identity(entry, final, self.anchor_dir) is False:
                self.settle(name, final)  # definitely never linked: drop the entry
            # a pending entry whose file is linked stays: the app's run adopts it (records it)
        self._save(self.load(), gc=True)

    def owns(self, name, path, digest=False, entry=None):
        """True when `path` is the very file entry `name` recorded (anchored inode) and, with
        `digest`, still holds the bytes recorded at publish time."""
        entry = entry if entry is not None else self.get(name)
        if not matches(entry, path, self.anchor_dir):
            return False
        return not digest or sha512_of(path) == entry.get("sha512")

    def identity_of(self, name, path, entry=None):
        """Three-valued ownership (True / False / None = cannot tell) for deleting paths (round nine #2)."""
        entry = entry if entry is not None else self.get(name)
        return identity(entry, path, self.anchor_dir)

    def set_todo(self, name, steps):
        if self.get(name) is not None:
            self._set(name, todo=list(steps))

    def done(self, name, step):
        entry = self.get(name)
        if entry is not None and step in (entry.get("todo") or []):
            self._set(name, todo=[s for s in entry["todo"] if s != step])

    def commit(self, name):
        self._set(name, state=PUBLISHED)

    def pruning(self, name):
        if self.get(name) is not None:
            self._set(name, state=PRUNING)

    def remove(self, name):
        entries = self.load()
        if entries.pop(name, None) is not None:
            self._save(entries, gc=True)

    def abort(self, name):
        """Drop a pending entry after a failed publish; never touches a published one."""
        entry = self.get(name)
        if entry is not None and entry.get("state") == PENDING:
            self.remove(name)


def presence(path):
    """True if something is at `path`, False only on a definite "no such file", None if unknown."""
    try:
        os.lstat(path)
        return True
    except OSError as e:
        if e.errno in (errno.ENOENT, errno.ENOTDIR):
            return False
        return None


def _anchor_name(entry):
    if not isinstance(entry, dict) or entry.get("dev") is None or entry.get("ino") is None:
        return None
    return "%d-%d" % (entry["dev"], entry["ino"])


def identity(entry, path, anchor_dir):
    """Is `path` the very file this entry recorded (same device and inode, and the entry's anchor
    still pins that inode, so the number cannot have been reused; round four #2)?
    True / False, or None when it cannot be told: any error other than "no such file", on the path
    or on the anchor, is unknown, never "not ours" (round eight #2)."""
    name = _anchor_name(entry)
    if not name or not anchor_dir:
        return False
    if os.path.lexists(os.path.dirname(anchor_dir)) and scratch.anchor_problem(anchor_dir):
        return None  # round nine #1: an unsafe anchor folder proves nothing either way
    ident = (entry["dev"], entry["ino"])
    for p in (path, os.path.join(anchor_dir, name)):
        try:
            st = os.lstat(p)
        except OSError as e:
            return False if e.errno in (errno.ENOENT, errno.ENOTDIR) else None
        if not _st.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != ident:
            return False
    return True


def matches(entry, path, anchor_dir):
    """True only when identity() is certain."""
    return identity(entry, path, anchor_dir) is True


def sha512_of(path):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def anchor_dir_for(staging_dir, store_path=None):
    """Anchors live with staging (same filesystem as Packages/, checked by preflight), in a folder
    of their own for each ownership file (round five #3)."""
    p = os.path.abspath(os.path.expanduser(store_path or DEFAULT_PATH))
    return os.path.join(staging_dir, ".jds-owned", hashlib.sha256(p.encode("utf-8")).hexdigest()[:16])


def _fsync_dir(d):
    try:
        dfd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dfd)
    except OSError:
        pass
    finally:
        os.close(dfd)
