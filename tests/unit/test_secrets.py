"""Section 5: secrets file, mode 0600, single read path."""
import os
import shutil
import tempfile
import unittest

from jamf_dp_sync import secrets
from jamf_dp_sync.errors import SecretsError

FAKE = (
    "# test values only\n"
    "JAMF_URL=https://jamf.invalid\n"
    "JAMF_CLIENT_ID=client-id-test\n"
    "JAMF_CLIENT_SECRET='s3cret-test-value'\n"
    "GITHUB_TOKEN=\n"
    "GCHAT_WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/T/messages?key=k-test&token=t-test\n"
)


class SecretsFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "env")
        with open(self.path, "w") as f:
            f.write(FAKE)
        os.chmod(self.path, 0o600)

    def tearDown(self):
        secrets._reset_for_tests()
        shutil.rmtree(self.dir)

    def test_loads_0600(self):
        secrets.init(self.path)
        self.assertEqual(secrets.get_secret("JAMF_URL"), "https://jamf.invalid")
        self.assertEqual(secrets.get_secret("JAMF_CLIENT_SECRET"), "s3cret-test-value")

    def test_rejects_group_or_other_readable(self):
        for mode in (0o640, 0o604, 0o660, 0o644, 0o620):
            os.chmod(self.path, mode)
            with self.subTest(mode=oct(mode)):
                with self.assertRaises(SecretsError) as cm:
                    secrets.init(self.path)
                self.assertIn("chmod 600", str(cm.exception))

    def test_missing_file(self):
        with self.assertRaises(SecretsError):
            secrets.init(os.path.join(self.dir, "nope"))

    def test_directory_rejected(self):
        d = os.path.join(self.dir, "envdir")
        os.mkdir(d, 0o700)
        with self.assertRaises(SecretsError):
            secrets.init(d)

    def test_optional_empty_secret(self):
        secrets.init(self.path)
        self.assertIsNone(secrets.get_secret("GITHUB_TOKEN", required=False))
        with self.assertRaises(SecretsError):
            secrets.get_secret("GITHUB_TOKEN")

    def test_unknown_key_in_file(self):
        with open(self.path, "a") as f:
            f.write("JAMF_PASSWORD=x\n")
        with self.assertRaises(SecretsError):
            secrets.init(self.path)

    def test_unknown_secret_name(self):
        secrets.init(self.path)
        with self.assertRaises(SecretsError):
            secrets.get_secret("AWS_KEY")

    def test_not_initialised(self):
        secrets._reset_for_tests()
        with self.assertRaises(SecretsError):
            secrets.get_secret("JAMF_URL")

    def test_redact(self):
        secrets.init(self.path)
        url = secrets.get_secret("GCHAT_WEBHOOK_URL")
        line = "POST %s failed; secret s3cret-test-value" % url
        out = secrets.redact(line)
        self.assertNotIn("k-test", out)
        self.assertNotIn("s3cret-test-value", out)
        self.assertIn("***", out)

    def test_webhook_prefers_new_name_and_kind_not_redacted(self):
        secrets._reset_for_tests({"GCHAT_WEBHOOK_URL": "https://old/hook", "WEBHOOK_KIND": "slack"})
        self.assertEqual(secrets.webhook(), ("https://old/hook", "slack"))
        self.assertEqual(secrets.redact("sent to slack via https://old/hook"), "sent to slack via ***")
        secrets._reset_for_tests({"WEBHOOK_URL": "https://new/hook", "GCHAT_WEBHOOK_URL": "https://old/hook"})
        self.assertEqual(secrets.webhook(), ("https://new/hook", None))
        secrets._reset_for_tests(None)

    def test_env_example_has_only_empty_values(self):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        with open(os.path.join(root, "env.example")) as f:
            values = secrets.parse_env(f.read())
        self.assertEqual(sorted(values), sorted(secrets.KNOWN_KEYS))
        self.assertTrue(all(v == "" for v in values.values()))


if __name__ == "__main__":
    unittest.main()
