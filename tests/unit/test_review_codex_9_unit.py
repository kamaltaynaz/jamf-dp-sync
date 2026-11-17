"""Unit regressions for the round-nine Codex review: unsafe anchor folders (#1)."""
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import ownership


class AnchorFolders(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.staging = os.path.join(self.dir, "staging")
        self.victim = os.path.join(self.dir, "Packages")
        os.makedirs(self.staging)
        os.makedirs(self.victim)
        with open(os.path.join(self.victim, "someone-elses.pkg"), "wb") as f:
            f.write(b"keep")
        self.path = os.path.join(self.dir, "o.json")
        self.anchors = ownership.anchor_dir_for(self.staging, self.path)
        self.store = ownership.OwnershipStore(self.path, anchor_dir=self.anchors)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def staged(self):
        p = os.path.join(self.staging, "s.pkg")
        with open(p, "wb") as f:
            f.write(b"pkg")
        return p

    def test_levels_created_private(self):
        self.store.begin("x.pkg", "x", "ab" * 64, self.staged())
        for d in (os.path.dirname(self.anchors), self.anchors):
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)

    def test_symlinked_store_folder_refused_and_never_collected(self):
        os.makedirs(os.path.dirname(self.anchors), 0o700)
        os.symlink(self.victim, self.anchors)
        with self.assertRaises(ownership.OwnershipError):
            self.store.begin("x.pkg", "x", "ab" * 64, self.staged())
        self.store._gc_anchors({})
        self.assertEqual(os.listdir(self.victim), ["someone-elses.pkg"])
        entry = {"dev": 1, "ino": 2}
        self.assertIsNone(ownership.identity(entry, os.path.join(self.victim, "someone-elses.pkg"), self.anchors))

    def test_symlinked_parent_refused(self):
        os.symlink(self.victim, os.path.dirname(self.anchors))
        with self.assertRaises(ownership.OwnershipError):
            self.store.begin("x.pkg", "x", "ab" * 64, self.staged())
        self.assertEqual(os.listdir(self.victim), ["someone-elses.pkg"])


if __name__ == "__main__":
    unittest.main()
