"""Section 9 single instance and cache; section 11.3 fault switches."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from jamf_dp_sync import faults
from jamf_dp_sync.lock import RunLock
from jamf_dp_sync.state import StateStore


class Env(object):
    def __init__(self, **kw):
        self.kw = kw

    def __enter__(self):
        self.old = dict((k, os.environ.get(k)) for k in self.kw)
        os.environ.update(self.kw)

    def __exit__(self, *a):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class Lock(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "sub", "run.lock")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_second_holder_refused_across_processes(self):
        with RunLock(self.path) as a:
            self.assertTrue(a.acquire())
            code = ("import sys; sys.path.insert(0, %r); from jamf_dp_sync.lock import RunLock; "
                    "sys.exit(0 if RunLock(%r).acquire() else 3)") % (os.getcwd(), self.path)
            self.assertEqual(subprocess.call([sys.executable, "-c", code]), 3)
        self.assertTrue(RunLock(self.path).acquire())  # released on exit

    def test_fault_lock_held(self):
        with Env(JDS_TEST_FAULTS="lock_held"):
            self.assertFalse(RunLock(self.path).acquire())


class State(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_round_trip_and_update(self):
        s = StateStore(self.dir)
        self.assertEqual(s.load("chrome"), {})
        s.update("chrome", etag='"x"', skip_since="2026-11-09")
        s.update("chrome", skip_since=None)
        self.assertEqual(s.load("chrome"), {"etag": '"x"'})
        self.assertEqual([f for f in os.listdir(self.dir) if f.startswith(".")], [])

    def test_read_only_never_writes(self):
        StateStore(self.dir, read_only=True).update("nudge", a=1)
        self.assertEqual(os.listdir(self.dir), [])

    def test_corrupt_is_empty(self):
        with open(os.path.join(self.dir, "zoom.json"), "w") as f:
            f.write("{not json")
        self.assertEqual(StateStore(self.dir).load("zoom"), {})

    def test_bad_key(self):
        with self.assertRaises(ValueError):
            StateStore(self.dir).load("../etc")


class Faults(unittest.TestCase):
    def test_off_by_default(self):
        with Env(JDS_TEST_FAULTS=""):
            self.assertEqual(faults.active(), set())
            self.assertFalse(faults.on("flip_byte"))

    def test_on(self):
        with Env(JDS_TEST_FAULTS="flip_byte, github_403"):
            self.assertTrue(faults.on("flip_byte"))
            self.assertTrue(faults.on("github_403"))
            self.assertFalse(faults.on("wrong_team"))

    def test_typo_rejected(self):
        with Env(JDS_TEST_FAULTS="flip_bite"):
            with self.assertRaises(ValueError):
                faults.active()
        with self.assertRaises(ValueError):
            faults.on("nope")


if __name__ == "__main__":
    unittest.main()
