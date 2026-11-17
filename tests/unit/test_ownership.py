"""Durable ownership store (round-two review #4, #7; round three #4, #8; round four #2)."""
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import ownership


class Ownership(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "share", "ownership.json")
        self.anchors = os.path.join(self.dir, "staging", ".jds-owned")
        self.o = ownership.OwnershipStore(self.path, anchor_dir=self.anchors)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def staged(self, name, data=b"x"):
        p = os.path.join(self.dir, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_lifecycle(self):
        self.assertEqual(self.o.load(), {})
        self.o.begin("jds-X-1.pkg", "x", "ab" * 64, self.staged("s1"))
        self.assertEqual(self.o.get("jds-X-1.pkg")["state"], "pending")
        self.o.commit("jds-X-1.pkg")
        self.o.abort("jds-X-1.pkg")                       # abort never drops a published entry
        self.assertEqual(self.o.get("jds-X-1.pkg")["state"], "published")
        self.o.pruning("jds-X-1.pkg")
        self.assertEqual(self.o.get("jds-X-1.pkg")["state"], "pruning")
        self.o.remove("jds-X-1.pkg")
        self.assertIsNone(self.o.get("jds-X-1.pkg"))
        self.assertEqual(os.listdir(self.anchors), [])
        self.assertEqual(oct(os.stat(os.path.dirname(self.path)).st_mode & 0o777), oct(0o700))

    def test_abort_drops_pending_and_its_anchor(self):
        self.o.begin("jds-X-2.pkg", "x", "cd" * 64, self.staged("s2"))
        self.assertEqual(len(os.listdir(self.anchors)), 1)
        self.o.abort("jds-X-2.pkg")
        self.assertIsNone(self.o.get("jds-X-2.pkg"))
        self.assertEqual(os.listdir(self.anchors), [])

    def test_corrupt_fails_closed(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write("{oops")
        with self.assertRaisesRegex(ownership.OwnershipError, "corrupt"):
            self.o.load()

    def test_read_only_never_writes(self):
        ro = ownership.OwnershipStore(self.path, read_only=True, anchor_dir=self.anchors)
        ro.begin("jds-X-3.pkg", "x", "ef" * 64, self.staged("s3"))
        self.assertFalse(os.path.exists(self.path))
        self.assertFalse(os.path.exists(self.anchors))

    def test_identity_is_the_anchored_inode(self):
        s = self.staged("s5", b"pkg")
        self.o.begin("a.pkg", "x", ownership.sha512_of(s), s)
        f = os.path.join(self.dir, "a.pkg")
        os.link(s, f)
        os.unlink(s)
        self.assertTrue(self.o.owns("a.pkg", f, digest=True))
        os.unlink(f)
        with open(f, "wb") as fh:          # same name, same bytes, new file: never ours, because the
            fh.write(b"pkg")               # anchor keeps the old inode number allocated
        self.assertFalse(self.o.owns("a.pkg", f))
        self.assertFalse(ownership.matches({"dev": 1}, f, self.anchors))   # no inode recorded: never
        self.assertFalse(self.o.owns("a.pkg", os.path.join(self.dir, "missing.pkg")))

    def test_digest_catches_in_place_change(self):
        s = self.staged("s6", b"pkg")
        self.o.begin("b.pkg", "x", ownership.sha512_of(s), s)
        with open(s, "ab") as fh:
            fh.write(b"tampered")
        self.assertTrue(self.o.owns("b.pkg", s))
        self.assertFalse(self.o.owns("b.pkg", s, digest=True))

    def test_begin_needs_an_anchor_dir(self):
        with self.assertRaises(ownership.OwnershipError):
            ownership.OwnershipStore(self.path).begin("c.pkg", "x", "ab" * 64, self.staged("s7"))

    def test_settle_keeps_the_prior_on_reuse(self):
        s1 = self.staged("p1", b"pkg")
        self.o.begin("d.pkg", "x", ownership.sha512_of(s1), s1)
        self.assertEqual(self.o.settle("d.pkg", s1), "new")
        s2 = self.staged("p2", b"pkg")                    # a second publish of the same name...
        self.o.begin("d.pkg", "x", ownership.sha512_of(s2), s2)
        self.assertTrue(self.o.owns("d.pkg", s1))          # identity untouched until settled
        self.assertEqual(self.o.settle("d.pkg", s1), "prior")   # ...found ours already there
        self.assertTrue(self.o.owns("d.pkg", s1, digest=True))
        self.assertNotIn("intent", self.o.get("d.pkg"))
        self.assertEqual(len(os.listdir(self.anchors)), 1)   # the second staged file's anchor is freed

    def test_todo(self):
        self.o.begin("jds-X-4.pkg", "x", "ab" * 64, self.staged("s4"))
        self.o.set_todo("jds-X-4.pkg", ["map", "prune"])
        self.o.done("jds-X-4.pkg", "map")
        self.assertEqual(self.o.get("jds-X-4.pkg")["todo"], ["prune"])

    def test_not_in_the_disposable_cache(self):
        self.assertIn(".local/share/", ownership.DEFAULT_PATH)
        self.assertNotIn(".local/state/", ownership.DEFAULT_PATH)


if __name__ == "__main__":
    unittest.main()
