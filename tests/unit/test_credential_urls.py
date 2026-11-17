"""Public review #4: credentials (Jamf client secret, webhook key) never go over plain http."""
import unittest

from jamf_dp_sync.httpclient import credential_url_problem
from jamf_dp_sync.jamf.client import JamfClient, JamfError


class CredentialUrls(unittest.TestCase):
    def test_rules(self):
        ok = ("https://jamf.example.com", "https://yourorg.jamfcloud.com", "https://jamf.example.com:8443/",
              "http://127.0.0.1:8080", "http://localhost:9")
        for url in ok:
            self.assertIsNone(credential_url_problem(url, "JAMF_URL"), url)
        bad = {"http://jamf.example.com": "must use https", "ftp://jamf.example.com": "must use https",
               "https://[oops": "could not be parsed", "https://x:99999": "could not be parsed",
               "": "no host", "https://u:p@jamf.example.com": "user name or password"}
        for url, why in bad.items():
            self.assertIn(why, credential_url_problem(url, "JAMF_URL"), url)

    def test_jamf_client_refuses_http_before_any_request(self):
        class NoHttp(object):
            def request(self, *a, **k):
                raise AssertionError("no request may be made")
        with self.assertRaises(JamfError) as cm:
            JamfClient("http://jamf.example.com", "id", "s3cret-value", NoHttp())
        self.assertNotIn("s3cret", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
