"""L1 smoke tests: the Jamf Pro client, policy editor and notifier against the local stubs.

These prove the stubs and the client agree with each other. They do NOT prove the shapes match
the Jamf Pro; that is L2 (OPEN_QUESTIONS Q5).
"""
import datetime
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "test", "env", "stubs"))

import gchat_stub  # noqa: E402
import jamf_stub  # noqa: E402

from jamf_dp_sync import notify  # noqa: E402
from jamf_dp_sync.errors import JamfError  # noqa: E402
from jamf_dp_sync.httpclient import HttpClient  # noqa: E402
from jamf_dp_sync.jamf import policy_xml  # noqa: E402
from jamf_dp_sync.jamf.client import JamfClient  # noqa: E402

with open(os.path.join(ROOT, "tests", "fixtures", "policies", "policy_101_legacy.xml")) as _f:
    POLICY_101 = _f.read().split("-->", 1)[1].strip()

SEED = {
    "clients": {"jamf-dp-sync-test": "stub-secret"},
    "packages": [
        {"id": "11", "packageName": "Org-Branding-1.2.pkg", "fileName": "Org-Branding-1.2.pkg"},
        {"id": "42", "packageName": "Nudge_Suite-2.1.3.81500.pkg", "fileName": "Nudge_Suite-2.1.3.81500.pkg"},
        {"id": "57", "packageName": "Nudge-Profile-Helper.pkg", "fileName": "Nudge-Profile-Helper.pkg"},
    ],
    "policies": {"101": POLICY_101},
    "patch_titles": [{
        "id": "201", "displayName": "Nudge", "softwareTitleId": "9001", "packages": [],
        "definitions": [
            {"version": "2.1.4.81863", "absoluteOrderId": "0", "releaseDate": "2026-10-01T00:00:00Z"},
            {"version": "2.1.3.81500", "absoluteOrderId": "1", "releaseDate": "2026-08-01T00:00:00Z"},
        ]}],
}


class Clock(object):
    def __init__(self):
        self.t = 1000000.0

    def __call__(self):
        return self.t


class JamfStubTest(unittest.TestCase):
    def setUp(self):
        self.srv, self.state, self.url = jamf_stub.start(SEED, token_ttl=300)
        self.clock = Clock()
        self.jamf = JamfClient(self.url, "jamf-dp-sync-test", "stub-secret", HttpClient(timeout=5), clock=self.clock)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def log_paths(self, method=None):
        return [(e["method"], e["path"]) for e in self.state.log if method is None or e["method"] == method]

    def test_token_reuse_and_early_refresh(self):
        self.jamf.find_package("x.pkg")
        self.jamf.find_package("y.pkg")
        self.assertEqual(self.log_paths("POST").count(("POST", "/api/oauth/token")), 1)
        self.clock.t += 300 - 29  # inside the 30 s refresh margin
        self.jamf.find_package("z.pkg")
        self.assertEqual(self.log_paths("POST").count(("POST", "/api/oauth/token")), 2)

    def test_bad_credentials(self):
        bad = JamfClient(self.url, "jamf-dp-sync-test", "wrong", HttpClient(timeout=5))
        with self.assertRaisesRegex(JamfError, "token request returned 401"):
            bad.find_package("x.pkg")

    def test_401_retried_once_with_new_token(self):
        self.jamf.find_package("x.pkg")
        with self.state.lock:
            self.state.tokens.clear()  # server-side revocation
        self.assertIsNone(self.jamf.find_package("x.pkg"))

    def test_package_lifecycle_and_delete_drops_from_policy(self):
        self.assertIsNone(self.jamf.find_package("NudgeSuite-2.1.4.81863.pkg"))
        pid = self.jamf.create_package("NudgeSuite-2.1.4.81863.pkg", "NudgeSuite-2.1.4.81863.pkg", -1, "ab" * 64)
        rec = self.jamf.find_package("NudgeSuite-2.1.4.81863.pkg")
        self.assertEqual(int(rec["id"]), pid)
        self.assertEqual(rec["hashType"], "SHA_512")
        self.assertEqual(rec["hashValue"], "ab" * 64)
        self.assertEqual(rec["notes"], "created by jamf-dp-sync")  # pruning marker (Q6)
        with self.assertRaises(JamfError):
            self.jamf.create_package("NudgeSuite-2.1.4.81863.pkg", "NudgeSuite-2.1.4.81863.pkg", -1, "cd" * 64)
        self.jamf.delete_package(42)
        self.assertNotIn("Nudge_Suite-2.1.3.81500.pkg", self.jamf.get_policy_xml(101).decode())

    def test_policy_swap_round_trip(self):
        pid = self.jamf.create_package("NudgeSuite-2.1.4.81863.pkg", "NudgeSuite-2.1.4.81863.pkg", -1, "ab" * 64)
        before = self.jamf.get_policy_xml(101)
        app = {"name_prefix": "NudgeSuite", "replace_regex": r"^(Nudge_Suite|NudgeSuite)-.+\.pkg$"}
        plan = policy_xml.plan_swap(before, policy_xml.match_regex(app), pid, "NudgeSuite-2.1.4.81863.pkg")
        self.jamf.put_policy_xml(101, plan.put_xml)
        after = self.jamf.get_policy_xml(101)
        self.assertEqual(policy_xml.packages(after),
                         [(11, "Org-Branding-1.2.pkg", "Cache"), (pid, "NudgeSuite-2.1.4.81863.pkg", "Install"),
                          (57, "Nudge-Profile-Helper.pkg", "Install")])
        self.assertIn("<trigger_other>install-nudge-jsm</trigger_other>", after.decode())
        again = policy_xml.plan_swap(after, policy_xml.match_regex(app), pid, "NudgeSuite-2.1.4.81863.pkg")
        self.assertFalse(again.changed)

    def test_put_with_unknown_package_is_rejected(self):
        plan = policy_xml.plan_swap(self.jamf.get_policy_xml(101), r"^Nudge_Suite-", 99999, "Ghost.pkg")
        with self.assertRaisesRegex(JamfError, "409"):
            self.jamf.put_policy_xml(101, plan.put_xml)

    def test_patch_title_latest_and_mapping(self):
        self.assertEqual(self.jamf.latest_patch_version(201), "2.1.4.81863")
        pid = self.jamf.create_package("NudgeSuite-2.1.4.81863.pkg", "NudgeSuite-2.1.4.81863.pkg", -1, "ab" * 64)
        self.jamf.map_package_to_title(201, pid, "2.1.4.81863")
        self.jamf.map_package_to_title(201, 42, "2.1.3.81500")
        self.assertEqual(sorted(p["version"] for p in self.jamf.patch_title(201)["packages"]),
                         ["2.1.3.81500", "2.1.4.81863"])

    def test_403_names_privilege(self):
        os.environ["JAMF_STUB_FAULTS"] = "POST /api/v1/packages=403:1"
        try:
            srv, state, url = jamf_stub.start(SEED)
        finally:
            del os.environ["JAMF_STUB_FAULTS"]
        try:
            buf = io.StringIO()
            log = logging.getLogger("test403")
            log.addHandler(logging.StreamHandler(buf))
            jamf = JamfClient(url, "jamf-dp-sync-test", "stub-secret", HttpClient(timeout=5), log=log)
            with self.assertRaisesRegex(JamfError, "Packages: Create"):
                jamf.create_package("a.pkg", "a.pkg", -1, "ab" * 64)
            self.assertIn("Packages: Create", buf.getvalue())
            jamf.create_package("a.pkg", "a.pkg", -1, "ab" * 64)  # fault fired once only
        finally:
            srv.shutdown()
            srv.server_close()

    def test_invalidate(self):
        self.jamf.find_package("x.pkg")
        self.jamf.invalidate()
        self.assertIn(("POST", "/api/v1/auth/invalidate-token"), self.log_paths())
        self.assertEqual(self.state.tokens, {})

    def test_stub_cli_process(self):
        d = tempfile.mkdtemp()
        try:
            seed = os.path.join(d, "seed.json")
            portf = os.path.join(d, "port")
            with open(seed, "w") as f:
                json.dump(SEED, f)
            p = subprocess.Popen([sys.executable, os.path.join(ROOT, "test", "env", "stubs", "jamf_stub.py"),
                                  "--seed", seed, "--port-file", portf], stderr=subprocess.PIPE)
            try:
                import time
                port = ""
                for _ in range(100):
                    if os.path.exists(portf):
                        with open(portf) as f:
                            port = f.read()
                    if port:
                        break
                    time.sleep(0.05)
                url = "http://127.0.0.1:%s" % port
                jamf = JamfClient(url, "jamf-dp-sync-test", "stub-secret", HttpClient(timeout=5))
                self.assertEqual(jamf.latest_patch_version(201), "2.1.4.81863")
            finally:
                p.terminate()
                p.wait()
                p.stderr.close()
        finally:
            shutil.rmtree(d)


class ChatStubTest(unittest.TestCase):
    def setUp(self):
        self.srv, self.state, self.url = gchat_stub.start()
        self.hook = self.url + "/v1/spaces/TESTSPACE/messages?key=KEYSECRET&token=TOKSECRET"
        self.day = datetime.datetime(2026, 11, 10, 3, 21)
        self.logbuf = io.StringIO()
        self.log = logging.getLogger("chat-test-%d" % id(self))
        self.log.addHandler(logging.StreamHandler(self.logbuf))
        self.log.propagate = False

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def messages(self):
        with urllib.request.urlopen(self.url + "/__stub/messages") as r:
            return json.loads(r.read().decode("utf-8"))

    def test_posts_top_level_message(self):
        text = notify.build_message([notify.ok_line("nudge", "2.1.3", "2.1.4", [101])], self.day, tag="[lima-test]")
        self.assertTrue(notify.send(text, self.hook, HttpClient(), log=self.log))
        m = self.messages()["messages"][0]
        self.assertIsNone(m["threadKey"])                       # top-level (2026-11-17)
        self.assertIsNone(m.get("messageReplyOption"))
        self.assertTrue(m["text"].startswith("[lima-test] jamf-dp-sync · 2026-11-10 03:21"))
        self.assertTrue(m["content_type"].startswith("application/json"))

    def test_a22_429_retried(self):
        self.state.mode, self.state.fail_count = "429-then-ok", 2
        sleeps = []
        self.assertTrue(notify.send("x", self.hook, HttpClient(), log=self.log, sleep=sleeps.append))
        self.assertEqual(self.messages()["attempts"], 3)
        self.assertEqual(sleeps, [2, 4])

    def test_a22_persistent_500_logged_without_url(self):
        self.state.mode = "500"
        self.assertFalse(notify.send("x", self.hook, HttpClient(), log=self.log, sleep=lambda s: None))
        out = self.logbuf.getvalue()
        self.assertIn("HTTP 500", out)
        for secret in ("KEYSECRET", "TOKSECRET", "TESTSPACE", self.url):
            self.assertNotIn(secret, out)

    def test_a22_unreachable(self):
        port = self.srv.server_address[1]
        self.srv.shutdown()
        self.srv.server_close()
        hook = "http://127.0.0.1:%d/v1/spaces/S/messages?key=KEYSECRET&token=TOKSECRET" % port
        self.assertFalse(notify.send("x", hook, HttpClient(timeout=2), log=self.log, sleep=lambda s: None))
        self.assertNotIn("KEYSECRET", self.logbuf.getvalue())
        self.srv, self.state, self.url = gchat_stub.start()  # for tearDown


class NotifyTestCommand(unittest.TestCase):
    """`jamf-dp-sync notify-test` end to end with a temp HOME (no real secrets involved)."""

    def test_notify_test_posts(self):
        srv, state, url = gchat_stub.start()
        home = tempfile.mkdtemp()
        try:
            cfgdir = os.path.join(home, ".config", "jamf-dp-sync")
            os.makedirs(cfgdir)
            env_file = os.path.join(cfgdir, "env")
            with open(env_file, "w") as f:
                f.write("JAMF_URL=http://127.0.0.1:9\nJAMF_CLIENT_ID=x\nJAMF_CLIENT_SECRET=y\nGITHUB_TOKEN=\n"
                        "GCHAT_WEBHOOK_URL=%s/v1/spaces/S/messages?key=KEYSECRET&token=TOKSECRET\n" % url)
            os.chmod(env_file, 0o600)
            env = dict(os.environ, HOME=home)
            p = subprocess.run([sys.executable, os.path.join(ROOT, "jamf_dp_sync.py"), "notify-test"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr.decode())
            self.assertIn(b"sent", p.stdout)
            self.assertNotIn(b"KEYSECRET", p.stdout + p.stderr)
            self.assertEqual(len(state.messages), 1)
            self.assertIn("notify-test", state.messages[0]["text"])

            os.chmod(env_file, 0o644)
            p = subprocess.run([sys.executable, os.path.join(ROOT, "jamf_dp_sync.py"), "notify-test"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60)
            self.assertEqual(p.returncode, 1)
            self.assertIn(b"chmod 600", p.stderr)
            self.assertEqual(len(state.messages), 1)

            os.chmod(env_file, 0o600)
            p = subprocess.run([sys.executable, os.path.join(ROOT, "jamf_dp_sync.py"),
                                "--config", os.path.join(ROOT, "packages.example.json"), "check-config"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr.decode())
            self.assertIn(b"monitor: vpnclient, sensor", p.stdout)
        finally:
            srv.shutdown()
            srv.server_close()
            shutil.rmtree(home)


if __name__ == "__main__":
    unittest.main()
