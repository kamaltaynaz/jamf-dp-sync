"""Regression tests for the round-four Codex review (REVIEW_CODEX_4.md, 2026-11-10).

Each test reproduces one round-four finding through the L1 world and must fail on 49ab382.
"""
import os
import shutil
import unittest
from unittest import mock

from jamf_dp_sync import publish
from jamf_dp_sync.jamf.client import JamfClient
from tests.integration.world import TEAMS, TITLE, World, team_cert
from tests.xarbuild import build_xar, distribution

NUDGE = "jds-NudgeSuite-%s.pkg"


def nm(v):
    return NUDGE % v


class Review4(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    def ok(self, *a, **kw):
        code, out, log = self.w.run(*a, **kw)
        self.assertEqual(code, 0, log[-2500:])
        return out, log

    def names(self):
        return [n for _, n, _ in self.w.policy_packages("nudge")]

    def publish_version(self, v, **kw):
        self.w.set_upstream("nudge", v)
        self.w.set_title("nudge", v)
        self.ok(only=["nudge"], **kw)

    def dp(self, name):
        return os.path.join(self.w.dp, name)

    def replace_by_rename(self, name, data=None):
        """Someone puts another file under the same name (new inode); same bytes unless `data`."""
        tmp = self.dp(".upload.tmp")
        if data is None:
            shutil.copyfile(self.dp(name), tmp)
        else:
            with open(tmp, "wb") as f:
                f.write(data)
        os.rename(tmp, self.dp(name))

    def mappings(self):
        with self.w.jamf.lock:
            return [m["version"] for m in self.w.jamf.titles[str(TITLE["nudge"])].get("packages") or []]

    # r4 #1a: normal pruning never deletes a file the agent did not publish (replaced by rename).
    def test_r4_01_prune_keeps_replaced_file(self):
        self.publish_version("2.1.4.81863", no_prune=True)
        self.publish_version("2.1.5.1", no_prune=True)
        self.replace_by_rename(nm("2.1.4.81863"), b"an admin's own file")
        self.publish_version("2.1.6.1")                       # retain 2: 2.1.4.81863 is pruned
        self.assertIn(nm("2.1.4.81863"), os.listdir(self.w.dp))
        with open(self.dp(nm("2.1.4.81863")), "rb") as f:
            self.assertEqual(f.read(), b"an admin's own file")
        self.assertIn("not pruned", self.w.messages()[-1]["text"])

    # r4 #1b: a retained file replaced with identical bytes is not reused (ownership is the inode).
    def test_r4_01_retained_replacement_not_reused(self):
        self.publish_version("2.1.4.81863", no_prune=True)
        self.publish_version("2.1.5.1", no_prune=True)
        self.replace_by_rename(nm("2.1.4.81863"))
        self.w.edit_app("nudge", pin="2.1.4.81863")
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertEqual(self.names()[-1:], [nm("2.1.5.1")])

    # r4 #2: Stop-path mapping checks the bytes, not only the inode.
    def test_r4_02_stop_map_checks_digest(self):
        real = JamfClient.map_package_to_title
        calls = []

        def crash_once(self_, *a):
            calls.append(a)
            if len(calls) == 1:
                raise SystemExit("simulated crash before mapping")
            return real(self_, *a)
        with mock.patch.object(JamfClient, "map_package_to_title", crash_once):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
            self.assertIn(nm("2.1.4.81863"), self.names())
            with open(self.dp(nm("2.1.4.81863")), "r+b") as f:   # changed in place: same inode
                f.seek(0, 2)
                f.write(b"tampered")
            code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertEqual(self.mappings(), [])

    # r4 #3: a re-download whose bytes differ from the surviving record is never published under it.
    def test_r4_03_redownload_differs_from_record(self):
        self.publish_version("2.1.4.81863", no_prune=True)
        self.publish_version("2.1.5.1", no_prune=True)
        os.unlink(self.dp(nm("2.1.4.81863")))                    # file lost, record retained
        v = "2.1.4.81863"                                       # vendor republishes other bytes
        path = os.path.join(self.w.files, "Nudge_Suite-%s.pkg" % v)
        build_xar(path, [("Distribution", distribution(product=v)), ("Resources/rebuilt", b"new build")],
                  certs=[team_cert(TEAMS["nudge"], self.w.dir)])
        import hashlib
        with open(path, "rb") as f:
            data = f.read()
        self.w._github("macadmins/nudge", "v" + v, os.path.basename(path), path, len(data),
                       hashlib.sha256(data).hexdigest(), latest=False)
        self.w.edit_app("nudge", pin=v)
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertEqual(self.names()[-1:], [nm("2.1.5.1")])
        self.assertNotIn(nm(v), os.listdir(self.w.dp))

    # r4 #4a: a failure to remove the staged name after the link does not fail the publish.
    def test_r4_04_staged_unlink_failure_tolerated(self):
        real = os.unlink
        hits = []
        scratch = os.path.abspath(os.path.join(self.w.staging, ".jds-scratch"))   # r7 #1: staged here

        def unlink(p, *a, **kw):
            if os.path.dirname(os.path.abspath(p)) == scratch and p.endswith(".pkg"):
                hits.append(p)
                raise PermissionError(13, "simulated", p)
            return real(p, *a, **kw)
        with mock.patch.object(publish.os, "unlink", unlink):
            self.ok(only=["nudge"])
        self.assertTrue(hits)                       # the failure really was injected
        self.assertIn(nm("2.1.4.81863"), self.names())

    # r4 #4b: any exception after the link keeps the ownership evidence; the next run adopts the file.
    def test_r4_04_exception_after_link_recovers(self):
        real = publish.publish

        def link_then_fail(*a, **kw):
            real(*a, **kw)
            raise OSError(5, "simulated failure after the link")
        with mock.patch.object(publish, "publish", link_then_fail):
            code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 1)
        self.assertIn(nm("2.1.4.81863"), os.listdir(self.w.dp))
        self.ok(only=["nudge"])
        self.assertIn(nm("2.1.4.81863"), self.names())

    # r4 #5: a mapping that could not be made yet stays owed until the title catches up.
    def test_r4_05_map_kept_until_title_has_version(self):
        self.w.set_upstream("nudge", "2.1.5.1")
        self.w.edit_app("nudge", pin="2.1.5.1")                 # title still offers 2.1.4.81863 only
        self.ok(only=["nudge"])
        self.assertNotIn("2.1.5.1", self.mappings())
        self.w.edit_app("nudge", pin=None)
        self.w.set_title("nudge", "2.1.5.1")                     # title catches up: Stop path
        self.ok(only=["nudge"])
        self.assertIn("2.1.5.1", self.mappings())

    # r4 #6: --no-prune also leaves an interrupted prune's file alone.
    def test_r4_06_no_prune_skips_recorded_prune(self):
        self.publish_version("2.1.4.81863")
        self.publish_version("2.1.5.1")
        real = JamfClient.delete_package

        def crash_after_delete(self_, pid):
            real(self_, pid)
            raise SystemExit("simulated crash after record delete, before unlink")
        self.w.set_upstream("nudge", "2.1.6.1")
        self.w.set_title("nudge", "2.1.6.1")
        with mock.patch.object(JamfClient, "delete_package", crash_after_delete):
            with self.assertRaises(SystemExit):
                self.w.run(only=["nudge"])
        self.ok(only=["nudge"], no_prune=True)
        self.assertIn(nm("2.1.4.81863"), os.listdir(self.w.dp))
        self.ok(only=["nudge"])                                   # pruning allowed again: finished
        self.assertNotIn(nm("2.1.4.81863"), os.listdir(self.w.dp))


if __name__ == "__main__":
    unittest.main()
