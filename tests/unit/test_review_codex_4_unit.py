"""Unit regressions for the round-four Codex review (REVIEW_CODEX_4.md): #2 (inode reuse) and #7."""
import os
import shutil
import sys
import tempfile
import unittest

from jamf_dp_sync import ownership

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "test", "env"))

import live  # noqa: E402
from tests.unit.test_live_harness import ISOLATED  # noqa: E402


class InodeReuse(unittest.TestCase):
    """r4 #2: a stale entry (file deleted, inode number free again) must not match a new file."""
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.anchors = os.path.join(self.dir, "staging", ".jds-owned")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_entry_without_its_anchor_never_matches(self):
        f = os.path.join(self.dir, "a.pkg")
        with open(f, "wb") as fh:
            fh.write(b"x")
        st = os.stat(f)
        # Same (dev, ino) as the file now at that path, as after inode-number reuse, but no anchor.
        entry = {"dev": st.st_dev, "ino": st.st_ino, "sha512": "00" * 64}
        self.assertFalse(ownership.matches(entry, f, self.anchors))

    def test_anchor_pins_the_inode(self):
        staged = os.path.join(self.dir, "staged.pkg")
        with open(staged, "wb") as fh:
            fh.write(b"pkg")
        store = ownership.OwnershipStore(os.path.join(self.dir, "o.json"), anchor_dir=self.anchors)
        store.begin("jds-X-1.pkg", "x", "ab" * 64, staged)
        final = os.path.join(self.dir, "jds-X-1.pkg")
        os.link(staged, final)
        os.unlink(staged)
        self.assertTrue(store.owns("jds-X-1.pkg", final))
        os.unlink(final)                                  # deleted by hand: the anchor keeps the inode
        self.assertEqual(len(os.listdir(self.anchors)), 1)
        store.remove("jds-X-1.pkg")                       # forgetting the entry frees the anchor
        self.assertEqual(os.listdir(self.anchors), [])


class CategoryIsolation(unittest.TestCase):
    """r4 #7: the live harness never runs without a real test category."""
    def test_select_owned_refuses_without_category(self):
        for bad in (None, -1, 0):
            with self.assertRaises(live.Refuse):
                live.select_owned([], ["TEST-jds-NudgeSuite"], bad)

    def test_policy_problems_require_category(self):
        for bad in (None, -1):
            self.assertTrue(live.policy_problems(ISOLATED, "nudge", bad))


if __name__ == "__main__":
    unittest.main()
