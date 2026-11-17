"""scripts/leak_check.py finds secret-shaped values and denied terms, and ignores the tests' fakes."""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "scripts", "leak_check.py")


class LeakCheck(unittest.TestCase):
    def run_on(self, files, deny=None):
        d = tempfile.mkdtemp()
        for name, text in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        cmd = [sys.executable, SCRIPT, d]
        if deny is not None:
            p = os.path.join(d, "..", os.path.basename(d) + ".deny")
            with open(p, "w") as f:
                f.write(deny)
            cmd += ["--deny-file", p]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return r.returncode, r.stdout.decode()

    def test_fakes_pass(self):
        rc, out = self.run_on({"a.py": 'HOOK = "https://chat.googleapis.com/v1/spaces/AAA/messages?key=KEY123&token=TOK"\n'
                                        'GITHUB_TOKEN=ghp_l1test\n'})
        self.assertEqual(rc, 0, out)

    def test_real_shapes_fail_without_printing_them(self):
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        rc, out = self.run_on({"a.txt": "token=%s\n" % token})
        self.assertEqual(rc, 1)
        self.assertIn("GitHub token", out)
        self.assertNotIn(token, out)

    def test_chat_webhook_any_order_and_filled_secret(self):    # public review #5
        key = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
        tok = "Ab" * 22
        hook = "https://chat.googleapis.com/v1/spaces/AAAAbbbb/messages?token=%s&key=%s" % (tok, key)
        rc, out = self.run_on({"a.txt": hook + "\n"})
        self.assertEqual(rc, 1)
        self.assertNotIn(tok, out)
        rc, out = self.run_on({"env": "JAMF_CLIENT_SECRET=" + "q8Zr" * 12 + "\n"})
        self.assertEqual(rc, 1)
        self.assertIn("filled-in secret", out)
        rc, out = self.run_on({"env.example": "JAMF_CLIENT_SECRET=\nJAMF_CLIENT_ID=<client id>\n"
                                              "JAMF_CLIENT_SECRET=smoke-secret\n"})
        self.assertEqual(rc, 0, out)

    def test_quoted_keys_and_short_secrets(self):              # public review round 2 #5
        real = "q8Zr" * 12
        for text in ('{"JAMF_CLIENT_SECRET": "%s"}' % real, "JAMF_CLIENT_SECRET='%s'" % real,
                     "JAMF_CLIENT_SECRET=" + "Kx7pQ2vL" + "9mN4wR8t",
                     "  JAMF_CLIENT_ID: " + "6f1c2a90-77b3-4d1e" + "-9a1f-2c3d4e5f6a7b"):
            rc, out = self.run_on({"cfg.txt": text + "\n"})
            self.assertEqual(rc, 1, text)
            self.assertNotIn(real, out)
        fakes = ('{"JAMF_CLIENT_SECRET": "s3cr3t-value-123"}', "JAMF_CLIENT_SECRET=stub-secret-longer",
                 "JAMF_CLIENT_ID=client-id-test-value", "JAMF_CLIENT_SECRET=%s\\n", "JAMF_CLIENT_SECRET=<client secret>")
        rc, out = self.run_on({"cfg.txt": "\n".join(fakes) + "\n"})
        self.assertEqual(rc, 0, out)

    def test_fake_words_must_be_whole_words(self):              # public review round 3 #5
        rc, out = self.run_on({"cfg.txt": "JAMF_CLIENT_SECRET=" + "8N3qvQdTeSt9" + "aYp6K2rB4mF7\n"})
        self.assertEqual(rc, 1, out)

    def test_expressions_and_placeholders_pass(self):           # public review round 3 #6
        rc, out = self.run_on({"a.py": 'JAMF_CLIENT_SECRET = os.environ.get("JAMF_CLIENT_SECRET")\n'
                                       "GITHUB_TOKEN=YOUR_GITHUB_TOKEN\nGITHUB_TOKEN=xxxxxxxxxxxxxxxx\n"
                                       "JAMF_CLIENT_ID=your-client-id-here\n"})
        self.assertEqual(rc, 0, out)

    def test_json_escapes_and_code(self):                       # public review round 4 #5, #6
        rc, out = self.run_on({"a.json": '{"JAMF_CLIENT_SECRET":"' + "Kx7pQ2vL9mN4" + 'wR8t\\/pQ9xL"}\n'})
        self.assertEqual(rc, 1, out)
        rc, out = self.run_on({"a.py": "JAMF_CLIENT_ID = settings.jamf_client_id\nGITHUB_TOKEN = args.github_token\n"
                                       'JAMF_CLIENT_SECRET = os.environ.get ("JAMF_CLIENT_SECRET")\n'})
        self.assertEqual(rc, 0, out)

    def test_file_names_never_printed_raw(self):                  # public review #6
        token = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
        rc, out = self.run_on({token + ".txt": "nothing\n", "notes-internal.example.md": "dp.internal.example\n"},
                              deny="internal.example\n")
        self.assertEqual(rc, 1)
        self.assertNotIn(token, out)
        self.assertNotIn("internal.example", out)
        self.assertIn("in file name", out)

    def test_deny_file(self):
        rc, out = self.run_on({"notes.md": "server is dp.internal.example\n"}, deny="# mine\ninternal.example\n")
        self.assertEqual(rc, 1)
        self.assertIn("denied term", out)


if __name__ == "__main__":
    unittest.main()
