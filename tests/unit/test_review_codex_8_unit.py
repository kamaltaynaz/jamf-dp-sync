"""Unit regressions for the round-eight Codex review: scratch-folder checks (#1), tri-state identity (#2)."""
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import ownership, scratch
from jamf_dp_sync.errors import SyncError


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.staging = os.path.join(self.dir, "staging")
        self.dp = os.path.join(self.dir, "Packages")
        os.makedirs(self.staging)
        os.makedirs(self.dp)

    def tearDown(self):
        for d, _, _ in os.walk(self.dir):
            os.chmod(d, 0o700)
        shutil.rmtree(self.dir)


class Scratch(Tmp):
    def test_created_private(self):
        d = scratch.ensure(self.staging, self.dp)
        self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
        self.assertIsNone(scratch.problem(self.staging, self.dp))

    def test_symlink_refused(self):
        os.symlink(self.dp, scratch.path_for(self.staging))
        self.assertIn("not a real directory", scratch.problem(self.staging, self.dp))
        with self.assertRaises(SyncError):
            scratch.ensure(self.staging, self.dp)

    def test_file_refused(self):
        open(scratch.path_for(self.staging), "w").close()
        self.assertIn("not a real directory", scratch.problem(self.staging, self.dp))

    def test_group_writable_refused(self):
        d = scratch.path_for(self.staging)
        os.mkdir(d)
        os.chmod(d, 0o770)
        self.assertIn("writable by group", scratch.problem(self.staging, self.dp))


class Identity(Tmp):
    def test_unreadable_anchor_is_unknown(self):
        anchors = os.path.join(self.staging, ".jds-owned", "s")
        store = ownership.OwnershipStore(os.path.join(self.dir, "o.json"), anchor_dir=anchors)
        staged = os.path.join(self.staging, "x.pkg")
        with open(staged, "wb") as f:
            f.write(b"pkg")
        store.begin("x.pkg", "x", ownership.sha512_of(staged), staged)
        entry = store.get("x.pkg")
        self.assertIs(ownership.identity(entry, staged, anchors), True)
        os.chmod(anchors, 0o600)
        if os.geteuid() != 0:                     # root ignores directory permissions
            self.assertIsNone(ownership.identity(entry, staged, anchors))
            self.assertIsNone(store.settle("x.pkg", staged))
            os.chmod(anchors, 0o700)
            self.assertEqual(store.get("x.pkg")["state"], ownership.PENDING)   # kept
        os.chmod(anchors, 0o700)
        self.assertIs(ownership.identity(entry, os.path.join(self.dir, "missing.pkg"), anchors), False)


if __name__ == "__main__":
    unittest.main()
