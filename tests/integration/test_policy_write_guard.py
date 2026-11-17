"""Q20 (accepted risk + detection): checks around every policy PUT.

Before the PUT the policy is read again; an edit since the plan is kept by re-planning. After the PUT
it is read back; any difference from what was sent raises a warning in the Chat summary.
"""
import unittest
from unittest import mock

from jamf_dp_sync.jamf.client import JamfClient
from tests.integration.world import POLICY, World

NUDGE = "jds-NudgeSuite-2.1.4.81863.pkg"
ADMIN = "<package><id>11</id><name>Admin-Added.pkg</name><action>Cache</action></package>"


class PolicyWriteGuard(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.pid = str(POLICY["nudge"])

    def tearDown(self):
        self.w.close()

    def names(self):
        from jamf_dp_sync.jamf import policy_xml as P
        with self.w.jamf.lock:
            return [n for _, n, _ in P.packages(self.w.jamf.policies[self.pid])]

    def admin_edit(self):
        with self.w.jamf.lock:
            self.w.jamf.policies[self.pid] = self.w.jamf.policies[self.pid].replace("</packages>", ADMIN + "</packages>")

    def test_edit_between_plan_and_put_is_kept(self):
        real = JamfClient.get_policy_xml
        reads = []

        def get(self_, pid):
            xml = real(self_, pid)
            reads.append(pid)
            if pid == int(self.pid) and len([r for r in reads if r == pid]) == 2:
                self.admin_edit()  # lands right after the planning read
            return xml
        with mock.patch.object(JamfClient, "get_policy_xml", get):
            code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 0, log[-2000:])
        self.assertIn("Admin-Added.pkg", self.names())
        self.assertIn(NUDGE, self.names())

    def test_change_right_after_put_is_reported(self):
        real = JamfClient.put_policy_xml

        def put(self_, pid, body):
            real(self_, pid, body)
            if pid == int(self.pid):
                self.admin_edit()  # someone else writes immediately after us
        with mock.patch.object(JamfClient, "put_policy_xml", put):
            code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 0)
        text = self.w.messages()[-1]["text"]
        self.assertIn("policy %s" % self.pid, text)
        self.assertIn("changed around this update", text)

    def test_quiet_when_nothing_else_changes(self):
        code, out, log = self.w.run(only=["nudge"])
        self.assertEqual(code, 0)
        self.assertNotIn("changed around this update", self.w.messages()[-1]["text"])


if __name__ == "__main__":
    unittest.main()
