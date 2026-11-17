"""Section 8 rules: surgical Classic policy package swaps (A1 'other policy packages untouched')."""
import os
import unittest
import xml.etree.ElementTree as ET

from jamf_dp_sync import versions
from jamf_dp_sync.errors import PolicyEditError
from jamf_dp_sync.jamf import policy_xml as P
from tests.xarbuild import FIXTURES

with open(os.path.join(FIXTURES, "policies", "policy_101_legacy.xml"), "rb") as _f:
    LEGACY = _f.read()

NUDGE = {"name_prefix": "NudgeSuite", "replace_regex": r"^(Nudge_Suite|NudgeSuite)-.+\.pkg$"}
NUDGE_DEFAULT = {"name_prefix": "NudgeSuite"}


def entries(put_xml):
    root = ET.fromstring(put_xml)
    self_size = int(root.find("package_configuration/packages/size").text)
    pk = [dict((c.tag, c.text) for c in p) for p in root.findall("package_configuration/packages/package")]
    assert self_size == len(pk), (self_size, len(pk))
    return root, pk


def with_packages(names):
    root = ET.fromstring(LEGACY.split(b"-->", 1)[1])
    pk = root.find("package_configuration/packages")
    for p in list(pk.findall("package")):
        pk.remove(p)
    for i, (pid, name, action) in enumerate(names):
        e = ET.SubElement(pk, "package")
        ET.SubElement(e, "id").text = str(pid)
        ET.SubElement(e, "name").text = name
        ET.SubElement(e, "action").text = action
    pk.find("size").text = str(len(names))
    return ET.tostring(root)


class Swap(unittest.TestCase):
    def test_default_regex(self):
        import re
        pat = re.compile(P.match_regex(NUDGE_DEFAULT))  # re.escape output differs 3.6 vs 3.7+
        self.assertTrue(pat.search("NudgeSuite-2.1.4.pkg"))
        for no in ("NudgeSuite-.pkg", "XNudgeSuite-1.pkg", "NudgeSuite-1.pkg.dmg", "Nudge_Suite-1.pkg"):
            self.assertFalse(pat.search(no), no)
        both = re.compile(P.match_regex(NUDGE))
        self.assertTrue(both.search("Nudge_Suite-2.1.2.pkg") and both.search("NudgeSuite-2.1.4.pkg"))

    def test_replace_legacy_keeps_action_and_others(self):
        plan = P.plan_swap(LEGACY, P.match_regex(NUDGE), 900, "NudgeSuite-2.1.4.81863.pkg")
        self.assertTrue(plan.changed)
        self.assertEqual(plan.removed, ["Nudge_Suite-2.1.3.81500.pkg"])
        self.assertEqual(plan.replaced, "Nudge_Suite-2.1.3.81500.pkg")
        root, pk = entries(plan.put_xml)
        # Only package_configuration/packages is sent.
        self.assertEqual([c.tag for c in root], ["package_configuration"])
        self.assertEqual([c.tag for c in root.find("package_configuration")], ["packages"])
        self.assertEqual([p["name"] for p in pk],
                         ["Org-Branding-1.2.pkg", "NudgeSuite-2.1.4.81863.pkg", "Nudge-Profile-Helper.pkg"])
        self.assertEqual(pk[1], {"id": "900", "name": "NudgeSuite-2.1.4.81863.pkg", "action": "Install",
                                 "fut": "false", "feu": "true", "update_autorun": "false"})
        # Untouched entries come back byte-for-byte equivalent.
        self.assertEqual(pk[0], {"id": "11", "name": "Org-Branding-1.2.pkg", "action": "Cache",
                                 "fut": "false", "feu": "false", "update_autorun": "false"})

    def test_action_preserved_when_cache(self):
        xml = with_packages([(42, "NudgeSuite-2.1.3.pkg", "Cache")])
        _, pk = entries(P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 900, "NudgeSuite-2.1.4.pkg").put_xml)
        self.assertEqual(pk[0]["action"], "Cache")

    def test_multiple_matches_collapse(self):
        xml = with_packages([(1, "A.pkg", "Install"), (2, "NudgeSuite-1.pkg", "Install"),
                             (3, "B.pkg", "Install"), (4, "NudgeSuite-2.pkg", "Install")])
        plan = P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 9, "NudgeSuite-3.pkg")
        _, pk = entries(plan.put_xml)
        self.assertEqual([p["name"] for p in pk], ["A.pkg", "NudgeSuite-3.pkg", "B.pkg"])
        self.assertEqual(plan.removed, ["NudgeSuite-1.pkg", "NudgeSuite-2.pkg"])

    def test_no_match_warns_and_skips(self):
        xml = with_packages([(1, "A.pkg", "Install")])
        plan = P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 9, "NudgeSuite-3.pkg")
        self.assertFalse(plan.changed)
        self.assertIsNone(plan.put_xml)
        self.assertIn("add_if_missing is false", plan.warning)

    def test_no_match_add_if_missing(self):
        xml = with_packages([(1, "A.pkg", "Cache")])
        plan = P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 9, "NudgeSuite-3.pkg", add_if_missing=True)
        self.assertTrue(plan.added)
        _, pk = entries(plan.put_xml)
        self.assertEqual(pk[1], {"id": "9", "name": "NudgeSuite-3.pkg", "action": "Install",
                                 "fut": "false", "feu": "false", "update_autorun": "false"})

    def test_empty_policy_add(self):
        xml = with_packages([])
        _, pk = entries(P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 9, "NudgeSuite-3.pkg", add_if_missing=True).put_xml)
        self.assertEqual(len(pk), 1)

    def test_idempotent(self):
        xml = with_packages([(1, "A.pkg", "Install"), (9, "NudgeSuite-3.pkg", "Install")])
        plan = P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 9, "NudgeSuite-3.pkg")
        self.assertFalse(plan.changed)
        self.assertIsNone(plan.warning)

    def test_current_plus_stale_duplicate_collapses(self):
        xml = with_packages([(9, "NudgeSuite-3.pkg", "Install"), (8, "NudgeSuite-2.pkg", "Install")])
        plan = P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 9, "NudgeSuite-3.pkg")
        self.assertTrue(plan.changed)
        self.assertEqual(plan.removed, ["NudgeSuite-2.pkg"])

    def test_pin_rollback_is_a_swap(self):
        xml = with_packages([(9, "NudgeSuite-3.pkg", "Install")])
        plan = P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 8, "NudgeSuite-2.pkg")
        _, pk = entries(plan.put_xml)
        self.assertEqual(pk[0]["name"], "NudgeSuite-2.pkg")

    def test_new_id_already_present_elsewhere(self):
        xml = with_packages([(9, "Other.pkg", "Install"), (2, "NudgeSuite-1.pkg", "Install")])
        with self.assertRaises(PolicyEditError):
            P.plan_swap(xml, P.match_regex(NUDGE_DEFAULT), 9, "NudgeSuite-3.pkg")

    def test_prefix_is_escaped(self):
        app = {"name_prefix": "TEST-Google.Chrome"}
        xml = with_packages([(1, "TEST-GoogleXChrome-1.pkg", "Install")])
        self.assertEqual(P.matching_names(xml, P.match_regex(app)), [])

    def test_bad_xml(self):
        for bad in (b"<notpolicy/>", b"<policy>", b'<!DOCTYPE x [<!ENTITY a "b">]><policy/>'):
            with self.subTest(bad=bad):
                with self.assertRaises(PolicyEditError):
                    P.plan_swap(bad, "^x$", 1, "x.pkg")


class MonitorVersion(unittest.TestCase):
    RX = r"^ExampleSensorMacOS[-_.]?(?P<version>[0-9.]+)\.pkg$"

    def test_reads_named_group(self):
        xml = with_packages([(1, "A.pkg", "Install"), (5, "ExampleSensorMacOS.7.18.19304.pkg", "Install")])
        self.assertEqual(str(P.monitor_version(xml, self.RX, versions.get_rule("dotted"))), "7.18.19304")

    def test_no_match_or_bad_version(self):
        self.assertIsNone(P.monitor_version(with_packages([(1, "A.pkg", "Install")]), self.RX,
                                            versions.get_rule("dotted")))
        self.assertIsNone(P.monitor_version(with_packages([(1, "ExampleSensorMacOS-1..2.pkg", "Install")]),
                                            self.RX, versions.get_rule("dotted")))


class CurrentVersionV4(unittest.TestCase):
    def test_reads_agent_name(self):
        xml = with_packages([(1, "A.pkg", "Install"), (9, "NudgeSuite-2.1.4.81863.pkg", "Install")])
        v = P.current_version(xml, NUDGE_DEFAULT, versions.get_rule("dotted"))
        self.assertEqual(str(v), "2.1.4.81863")

    def test_legacy_only_is_none(self):
        self.assertIsNone(P.current_version(LEGACY, NUDGE, versions.get_rule("dotted")))


if __name__ == "__main__":
    unittest.main()
