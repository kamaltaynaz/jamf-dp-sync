"""Review findings 8 and 9: the dev-Jamf L2 harness only touches what it created, only on the test Jamf Pro."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "test", "env"))
import live  # noqa: E402

ISOLATED = ("<policy><general><id>133</id><category><id>86</id><name>jamf-dp-sync-test</name></category>"
            "<trigger_other>test-install-nudge-jsm</trigger_other><trigger_checkin>false</trigger_checkin>"
            "</general><scope><all_computers>false</all_computers><computers/><computer_groups/></scope>"
            "<package_configuration><packages><size>2</size>"
            "<package><id>5</id><name>TEST-VPN.pkg</name><action>Install</action></package>"
            "<package><id>9</id><name>TEST-jds-NudgeSuite-2.1.4.81863.pkg</name><action>Install</action></package>"
            "</packages></package_configuration></policy>")


class Origin(unittest.TestCase):
    def test_exact_dev_origin_only(self):
        live.check_origin("https://jamf-test.example.com")
        live.check_origin("https://jamf-test.example.com:8443/")
        for bad in ("https://jamf-test.example.com.example.org", "http://jamf-test.example.com",
                    "https://jamf.example.com", "https://evil/?h=jamf-test.example.com",
                    "https://user:pw@jamf-test.example.com", ""):
            with self.subTest(url=bad):
                with self.assertRaises(live.Refuse):
                    live.check_origin(bad)


class Isolation(unittest.TestCase):
    def test_isolated_policy_passes(self):
        self.assertEqual(live.policy_problems(ISOLATED, "nudge", 86), [])

    def test_violations(self):
        cases = [(ISOLATED.replace("<all_computers>false", "<all_computers>true"), "all computers"),
                 (ISOLATED.replace("<computers/>", "<computers><computer><id>7</id></computer></computers>"), "scope targets"),
                 (ISOLATED.replace("<trigger_checkin>false", "<trigger_checkin>true"), "checkin"),
                 (ISOLATED.replace("test-install-nudge-jsm", "install-nudge-jsm"), "trigger"),
                 (ISOLATED.replace("<id>86</id>", "<id>3</id>"), "category")]
        for xml, text in cases:
            with self.subTest(text=text):
                self.assertTrue(any(text in p for p in live.policy_problems(xml, "nudge", 86)))


class CleanupScope(unittest.TestCase):
    def test_only_configured_harness_names(self):
        prefixes = ["TEST-jds-NudgeSuite"]
        self.assertTrue(live.is_harness_name("TEST-jds-NudgeSuite-2.1.4.81863.pkg", prefixes))
        for other in ("TEST-VPN.pkg", "TEST-jds-NudgeSuiteX-1.pkg", "TEST-jds-Other-1.pkg", "TEST-jds-NudgeSuite-1.dmg"):
            self.assertFalse(live.is_harness_name(other, prefixes), other)

    def test_policy_cleanup_keeps_unrelated_test_pkg(self):
        import xml.etree.ElementTree as ET
        body = live._without_owned_packages(ISOLATED.encode(), {"9"})
        names = [e.findtext("name") for e in ET.fromstring(body).iter("package")]
        self.assertEqual(names, ["TEST-VPN.pkg"])


if __name__ == "__main__":
    unittest.main()
