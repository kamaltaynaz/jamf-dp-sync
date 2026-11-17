"""Per-app cache (spec section 9): ETags, skip-since dates, last results. Safe to delete.

One JSON file per app plus `_run.json` under ~/.local/state/jamf-dp-sync/. Writes are atomic
(temp file + rename). Jamf Pro and Packages/ hold the real state; losing this cache only costs a
re-download or an earlier/later skip alert.
"""
import json
import os
import re
import tempfile

DEFAULT_DIR = "~/.local/state/jamf-dp-sync"
_SAFE = re.compile(r"^[a-z0-9_-]+$")


class StateStore(object):
    def __init__(self, directory=None, read_only=False):
        self.dir = os.path.expanduser(directory or DEFAULT_DIR)
        self.read_only = read_only  # dry run: never write

    def _path(self, key):
        if not _SAFE.match(key):
            raise ValueError("bad state key %r" % key)
        return os.path.join(self.dir, key + ".json")

    def load(self, key):
        path = self._path(key)  # a bad key is a bug, not a missing cache: let it raise
        try:
            with open(path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (IOError, OSError, ValueError):
            return {}  # missing or corrupt cache is the same as no cache

    def save(self, key, data):
        if self.read_only:
            return
        if not os.path.isdir(self.dir):
            os.makedirs(self.dir, 0o700)
        fd, tmp = tempfile.mkstemp(prefix="." + key + ".", dir=self.dir)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=1, sort_keys=True)
            os.rename(tmp, self._path(key))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def update(self, key, **changes):
        data = self.load(key)
        for k, v in changes.items():
            if v is None:
                data.pop(k, None)
            else:
                data[k] = v
        self.save(key, data)
        return data
