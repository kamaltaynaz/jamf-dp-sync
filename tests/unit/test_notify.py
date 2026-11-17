"""Section 9 message rules: format, 4,000-character cap, threading, retry policy, no URL leaks."""
import datetime
import unittest

from jamf_dp_sync import notify
from jamf_dp_sync.httpclient import NetworkError, Response
from tests.fakes import ListLog

WHEN = datetime.datetime(2026, 11, 10, 3, 21)
HOOK = "https://chat.googleapis.com/v1/spaces/AAA/messages?key=KEY123&token=TOK456"


class Format(unittest.TestCase):
    def test_example_message(self):
        lines = [notify.ok_line("nudge", "2.1.4.81863", "2.1.5.81902", [101]),
                 notify.fail_line("office", "verify", "Team ID mismatch (expected UBF8T346G9)"),
                 notify.warn_line("sensor", "policy 7.18 behind patch title 7.19 (monitor-only)")]
        msg = notify.build_message(lines, WHEN, tag="[dp01]")
        self.assertEqual(msg.splitlines()[0], "[dp01] jamf-dp-sync · 2026-11-10 03:21")
        self.assertEqual(msg.splitlines()[1], "*OK*   nudge    2.1.4.81863 → 2.1.5.81902   policy 101")
        self.assertEqual(msg.splitlines()[2], "*FAIL* office   verify: Team ID mismatch (expected UBF8T346G9)")

    def test_cap_and_overflow(self):
        lines = ["*OK*   app%03d %s" % (i, "x" * 80) for i in range(200)]
        msg = notify.build_message(lines, WHEN, tag="[lima-test]")
        self.assertLessEqual(len(msg), 4000)
        self.assertRegex(msg.splitlines()[-1], r"^…and \d+ more, see log$")
        shown = len(msg.splitlines()) - 2
        self.assertEqual(int(msg.splitlines()[-1].split()[1]), 200 - shown)

    def test_no_overflow_when_fits(self):
        msg = notify.build_message(["a", "b"], WHEN, tag="[x]")
        self.assertNotIn("more, see log", msg)

    def test_host_tag(self):
        self.assertEqual(notify.host_tag("dp01.example.com"), "[dp01]")
        self.assertEqual(notify.host_tag("lima-test"), "[lima-test]")

    def test_post_url_is_top_level(self):          # 2026-11-17: no thread replies
        u = notify.post_url(HOOK)
        self.assertIn("key=KEY123", u)
        self.assertNotIn("threadKey", u)
        self.assertNotIn("messageReplyOption", u)
        threaded = HOOK + "&threadKey=x&messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
        self.assertEqual(notify.post_url(threaded), u)


class Kinds(unittest.TestCase):                      # Slack and Teams (public release, 2026-11-17)
    def test_detect(self):
        self.assertEqual(notify.detect_kind(HOOK), "gchat")
        self.assertEqual(notify.detect_kind("https://hooks.slack.com/services/T/B/X"), "slack")
        self.assertEqual(notify.detect_kind(
            "https://prod-01.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=s"), "teams")
        self.assertEqual(notify.detect_kind("https://x.environment.api.powerplatform.com/powerautomate/a"), "teams")
        self.assertEqual(notify.detect_kind("http://127.0.0.1:8080/v1/spaces/S/messages"), "gchat")  # stubs
        self.assertEqual(notify.detect_kind(HOOK, "Slack"), "slack")
        with self.assertRaises(ValueError):
            notify.detect_kind(HOOK, "discord")

    def test_slack_payload_escapes(self):
        self.assertEqual(notify.payload("slack", "*OK* a < b & c > d"), {"text": "*OK* a &lt; b &amp; c &gt; d"})

    def test_teams_payload(self):
        p = notify.payload("teams", "[x] jamf-dp-sync · 2026-11-10 03:21\n*OK*   nudge  1 → 2\n\n*FAIL* zoom")
        card = p["attachments"][0]
        self.assertEqual(card["contentType"], "application/vnd.microsoft.card.adaptive")
        blocks = [b["text"] for b in card["content"]["body"]]
        self.assertEqual(blocks, ["[x] jamf-dp-sync · 2026-11-10 03:21", "**OK**   nudge  1 → 2", " ", "**FAIL** zoom"])

    def test_gchat_payload_unchanged(self):
        self.assertEqual(notify.payload("gchat", "*OK* x"), {"text": "*OK* x"})


class SeqHttp(object):
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def request(self, method, url, data=None, headers=None, follow=True, timeout=None):
        self.calls.append((method, url, data, timeout))
        o = self.outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return Response(o, {}, url, b"{}")


class Delivery(unittest.TestCase):
    def setUp(self):
        self.sleeps = []
        self.log = ListLog()

    def send(self, outcomes):
        http = SeqHttp(outcomes)
        ok = notify.send("hello", HOOK, http, log=self.log, sleep=self.sleeps.append)
        return ok, http

    def test_success(self):
        ok, http = self.send([200])
        self.assertTrue(ok)
        self.assertEqual(http.calls[0][0], "POST")
        self.assertEqual(http.calls[0][2], b'{"text": "hello"}')
        self.assertEqual(http.calls[0][3], 10)

    def test_retries_on_429_then_ok(self):
        ok, http = self.send([429, 503, 200])
        self.assertTrue(ok)
        self.assertEqual(len(http.calls), 3)
        self.assertEqual(self.sleeps, [2, 4])

    def test_gives_up_after_three_retries(self):
        ok, http = self.send([500, 500, 500, 500])
        self.assertFalse(ok)
        self.assertEqual(len(http.calls), 4)
        self.assertTrue(self.log.records)

    def test_no_retry_on_400(self):
        ok, http = self.send([400])
        self.assertFalse(ok)
        self.assertEqual(len(http.calls), 1)

    def test_unreachable_never_raises_or_leaks(self):
        ok, http = self.send([NetworkError("POST chat.googleapis.com: refused")] * 4)
        self.assertFalse(ok)
        joined = " ".join(self.log.records)
        self.assertNotIn("KEY123", joined)
        self.assertNotIn("TOK456", joined)
        self.assertNotIn("spaces/AAA", joined)

    def test_slack_url_untouched_and_body(self):
        http = SeqHttp([200])
        url = "https://hooks.slack.com/services/T/B/X?threadKey=keep"
        self.assertTrue(notify.send("a<b", url, http, log=self.log, sleep=self.sleeps.append))
        self.assertEqual(http.calls[0][1], url)
        self.assertEqual(http.calls[0][2], b'{"text": "a&lt;b"}')

    def test_teams_202_is_success(self):
        http = SeqHttp([202])
        self.assertTrue(notify.send("x", "https://a.logic.azure.com/workflows/1", http, log=self.log))

    def test_bad_kind_never_raises(self):
        self.assertFalse(notify.send("x", HOOK, SeqHttp([]), log=self.log, kind="pager"))

    def test_malformed_or_plain_http_url_never_raises_or_leaks(self):   # public review #3, #4
        for url in ("https://[broken/KEYFRAG", "http://chat.example.com/hook?key=KEYFRAG", "ftp://x/KEYFRAG",
                    "https://user:KEYFRAG@hooks.slack.com/services/x"):
            log = ListLog()
            self.assertFalse(notify.send("x", url, SeqHttp([]), log=log, kind="gchat"))
            self.assertNotIn("KEYFRAG", " ".join(log.records))
        self.assertTrue(notify.send("x", "http://127.0.0.1:8080/v1/spaces/S/messages", SeqHttp([200]), log=self.log))

    def test_no_webhook(self):
        self.assertFalse(notify.send("x", None, SeqHttp([]), log=self.log))


if __name__ == "__main__":
    unittest.main()
