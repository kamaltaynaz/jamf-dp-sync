"""Jamf client against responses recorded on a test Jamf Pro 11.33.0 (DECISIONS F4)."""
import json
import os
import unittest

from jamf_dp_sync import versions
from jamf_dp_sync.jamf.client import JamfClient
from tests.fakes import FakeHttp

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REC = os.path.join(ROOT, "tests", "fixtures", "jamf", "dev-11.33.0")
BASE = "https://jamf.invalid"
DEFS_Q = "?page=0&page-size=1&sort=absoluteOrderId%3Aasc"


def load(name):
    with open(os.path.join(REC, name)) as f:
        return json.load(f)


DEFS = load("patch_definitions_top3.json")
TITLES = dict((int(t["id"]), t) for t in load("patch_titles.json")["results"])

# label -> (title id, version_rule, expected newest version on 2026-11-09)
EXPECTED = {
    "nudge": (72, "dotted", "2.1.4.81863"),
    "dialog": (54, "swiftdialog", "3.1.1"),
    "acrobat": (47, "acrobat", "26.003.22075"),
    "office": (51, "office", "16.114.26110224"),
    "chrome": (80, "dotted", "158.0.8127.18"),
    "zoom": (3, "zoom", "7.2.5 (90525)"),
    "googledrive": (32, "dotted", "133.0.2"),
}


def client(http):
    http.add("POST", BASE + "/api/oauth/token", body=json.dumps({"access_token": "t", "expires_in": 1200}))
    return JamfClient(BASE, "id", "secret", http)


class RecordedDev(unittest.TestCase):
    def test_latest_is_absolute_order_zero(self):
        for label, (tid, rule, want) in sorted(EXPECTED.items()):
            with self.subTest(label=label):
                http = FakeHttp()
                http.add("GET", BASE + "/api/v3/patch-software-title-configurations/%d/definitions%s" % (tid, DEFS_Q),
                         body=json.dumps(DEFS[str(tid)]))
                got = client(http).latest_patch_version(tid)
                self.assertEqual(got, want)
                versions.get_rule(rule).parse(got)  # every real title form parses with its rule

    def test_release_date_is_not_monotonic(self):
        # Why "latest" must come from absoluteOrderId, not releaseDate.
        res = DEFS["80"]["results"]
        self.assertEqual(res[0]["absoluteOrderId"], "0")
        self.assertGreater(res[2]["releaseDate"], res[1]["releaseDate"])

    def test_mapping_patch_keeps_others_and_drops_display_name(self):
        http = FakeHttp()
        url = BASE + "/api/v3/patch-software-title-configurations/72"
        http.add("GET", url, body=json.dumps(TITLES[72]))
        sent = {}

        def patch(headers):
            from jamf_dp_sync.httpclient import Response
            return Response(200, {}, url, b"{}")
        http.routes[("PATCH", url)] = patch
        orig = http.request

        def spy(method, u, headers=None, data=None, **kw):
            if method == "PATCH":
                sent["headers"], sent["body"] = headers, json.loads(data.decode())
            return orig(method, u, headers=headers, data=data, **kw)
        http.request = spy
        client(http).map_package_to_title(72, 901, "2.1.4.81863")
        self.assertEqual(sent["headers"]["Content-Type"], "application/merge-patch+json")
        self.assertEqual(sent["body"], {"packages": [{"packageId": "200", "version": "2.1.2.81856"},
                                                     {"packageId": "901", "version": "2.1.4.81863"}]})

    def test_hand_made_records_have_no_marker(self):
        from jamf_dp_sync import prune
        for r in load("packages_nudge.json")["results"]:
            self.assertFalse(prune.is_agent_record(r, {"name_prefix": "jds-NudgeSuite"}, versions.get_rule("dotted")))
            self.assertNotIn("created by jamf-dp-sync", r.get("notes") or "")


if __name__ == "__main__":
    unittest.main()
