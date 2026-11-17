"""D7 / section 8 pruning with the name + notes-marker rule (A10, Q6 answer)."""
import os
import unittest

from jamf_dp_sync import prune, versions
from jamf_dp_sync.jamf.client import AGENT_MARKER

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(ROOT, "tests", "fixtures", "share_packages_names.txt")) as _f:
    REAL_NAMES = [l.strip() for l in _f if l.strip() and not l.startswith("#")]

APP = {"name_prefix": "jds-GoogleChrome"}
RULE = versions.get_rule("dotted")


def rec(pid, name, marked=True, file_name=None):
    return {"id": str(pid), "packageName": name, "fileName": file_name or name,
            "notes": AGENT_MARKER if marked else ""}


class Prune(unittest.TestCase):
    def test_keeps_retain_newest_by_id_plus_current(self):
        recs = [rec(10, "jds-GoogleChrome-140.0.1.1.pkg"), rec(20, "jds-GoogleChrome-141.0.1.1.pkg"),
                rec(30, "jds-GoogleChrome-142.0.1.1.pkg"), rec(40, "jds-GoogleChrome-143.0.1.1.pkg")]
        out = prune.plan_prune(recs, APP, RULE, "jds-GoogleChrome-143.0.1.1.pkg", retain=2)
        self.assertEqual([r["id"] for r in out], ["20", "10"])

    def test_pinned_current_older_than_retained_is_kept(self):
        recs = [rec(10, "jds-GoogleChrome-140.0.1.1.pkg"), rec(20, "jds-GoogleChrome-141.0.1.1.pkg"),
                rec(30, "jds-GoogleChrome-142.0.1.1.pkg")]
        out = prune.plan_prune(recs, APP, RULE, "jds-GoogleChrome-140.0.1.1.pkg", retain=2)
        self.assertEqual(out, [])

    def test_never_touches_unmarked_or_foreign(self):
        recs = [rec(1, "GoogleChrome-156.0.8078.48.pkg", marked=False),
                rec(2, "jds-GoogleChrome-139.0.1.1.pkg", marked=False),      # right name, no marker
                rec(3, "jds-GoogleChrome-138.0.1.1.pkg", file_name="other.pkg"),  # name/file disagree
                rec(4, "jds-GoogleChrome-latest.pkg"),                      # unparseable version
                rec(5, "jds-GoogleChrome-142.0.1.1.pkg"), rec(6, "jds-GoogleChrome-143.0.1.1.pkg"),
                rec(7, "jds-GoogleChrome-144.0.1.1.pkg")]
        out = prune.plan_prune(recs, APP, RULE, "jds-GoogleChrome-144.0.1.1.pkg", retain=2)
        self.assertEqual([r["id"] for r in out], ["5"])

    def test_retain_must_be_positive(self):
        with self.assertRaises(ValueError):
            prune.plan_prune([], APP, RULE, "x", retain=0)


class CollisionPreflight(unittest.TestCase):
    def test_real_share_has_no_collisions_with_jds_prefix(self):
        for prefix in ("jds-NudgeSuite", "jds-swiftDialog", "jds-GoogleChrome", "jds-GoogleDrive"):
            self.assertEqual(prune.collisions(REAL_NAMES, [], {"name_prefix": prefix}, RULE), [])

    def test_old_prefix_would_collide(self):
        self.assertEqual(prune.collisions(REAL_NAMES, [], {"name_prefix": "GoogleChrome"}, RULE),
                         ["GoogleChrome-156.0.8078.48.pkg"])

    def test_file_without_marked_record_is_a_collision(self):
        files = ["jds-GoogleChrome-142.0.1.1.pkg", "jds-GoogleChrome-143.0.1.1.pkg"]
        recs = [rec(1, "jds-GoogleChrome-142.0.1.1.pkg"), rec(2, "jds-GoogleChrome-143.0.1.1.pkg", marked=False)]
        self.assertEqual(prune.collisions(files, recs, APP, RULE), ["jds-GoogleChrome-143.0.1.1.pkg"])

    def test_record_without_file_and_without_marker_is_a_collision(self):
        self.assertEqual(prune.collisions([], [rec(9, "jds-GoogleChrome-1.0.0.pkg", marked=False)], APP, RULE),
                         ["jds-GoogleChrome-1.0.0.pkg"])


if __name__ == "__main__":
    unittest.main()
