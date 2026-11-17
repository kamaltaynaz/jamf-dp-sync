"""Webhook notifications (spec section 9): Google Chat, Slack or Microsoft Teams (Workflows).

The kind comes from WEBHOOK_KIND when set, else from the webhook URL's host; an unknown host is
treated as Google Chat (the original and default). One plain-text message per run, capped at 4,000 characters, prefixed with the host tag, posted as a
new top-level message (2026-11-17: thread replies were easy to miss). Delivery: POST JSON, 10 s timeout, up to 3 retries with backoff on 429/5xx/network errors, then
log and continue. A notification failure never raises and never changes the run's exit code. The
webhook URL embeds a key and token: it is never logged, echoed, or put in a message.
"""
import json
import re
import socket
import time
import urllib.parse

from jamf_dp_sync import secrets
from jamf_dp_sync.httpclient import NetworkError, credential_url_problem

CAP = 4000
TIMEOUT = 10
RETRIES = 3
BACKOFF = (2, 4, 8)


def host_tag(hostname=None):
    name = (hostname or socket.gethostname()).split(".")[0]
    return "[%s]" % name


def ok_line(label, old, new, policy_ids):
    return "*OK*   %-8s %s → %s   policy %s" % (label, old or "none", new, ", ".join(str(p) for p in policy_ids))


def fail_line(label, step, reason):
    return "*FAIL* %-8s %s: %s" % (label, step, reason)


def warn_line(label, text):
    return "*WARN* %-8s %s" % (label, text)


def build_message(lines, when, tag=None, title="jamf-dp-sync", cap=CAP):
    """Header plus lines; overflow is replaced by '…and N more, see log' within `cap` characters."""
    lines = [secrets.redact(l) for l in lines]  # never a secret in a Chat message (review #15)
    head = "%s %s · %s" % (tag or host_tag(), title, when.strftime("%Y-%m-%d %H:%M"))
    out = [head]
    used = len(head)
    for i, line in enumerate(lines):
        remaining = len(lines) - i
        tail = "\n…and %d more, see log" % remaining
        if used + 1 + len(line) + (len(tail) if remaining > 1 else 0) > cap:
            out.append(tail.lstrip("\n"))
            break
        out.append(line)
        used += 1 + len(line)
    return "\n".join(out)[:cap]


KINDS = ("gchat", "slack", "teams")
NAMES = {"gchat": "Google Chat", "slack": "Slack", "teams": "Teams"}


def detect_kind(webhook_url, override=None):
    """'gchat', 'slack' or 'teams'. `override` (WEBHOOK_KIND) wins; else the URL's host decides."""
    if override:
        kind = override.strip().lower()
        if kind not in KINDS:
            raise ValueError("WEBHOOK_KIND must be one of %s" % ", ".join(KINDS))
        return kind
    host = (urllib.parse.urlsplit(webhook_url).hostname or "").lower()
    if host == "hooks.slack.com":
        return "slack"
    if (host.endswith(".logic.azure.com") or host.endswith(".powerplatform.com")
            or host.endswith(".webhook.office.com")):
        return "teams"
    return "gchat"


def post_url(webhook_url):
    """The webhook URL with any threadKey/messageReplyOption removed, so each message starts a new
    top-level thread in the space (DECISIONS: Chat top-level messages)."""
    parts = urllib.parse.urlsplit(webhook_url)
    q = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
         if k not in ("threadKey", "messageReplyOption")]
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(q), ""))


_BOLD = re.compile(r"\*([^*\n]+)\*")


def payload(kind, text):
    """The JSON body for `kind`. Messages use Chat's *bold*; Slack's mrkdwn reads the same, Teams'
    Adaptive Card markdown needs **bold** and one TextBlock per line."""
    if kind == "slack":
        esc = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return {"text": esc}
    if kind == "teams":
        body = [{"type": "TextBlock", "text": _BOLD.sub(r"**\1**", line) or " ", "wrap": True,
                 "fontType": "Monospace" if i else "Default", "weight": "Bolder" if i == 0 else "Default"}
                for i, line in enumerate(text.splitlines())]
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4", "body": body}}]}
    return {"text": text}


def send(text, webhook_url, http, log=None, sleep=time.sleep, kind=None):
    """Post `text`. Returns True on success, False after retries are exhausted. Never raises."""
    if not webhook_url:
        if log:
            log.warning("notification skipped: no webhook configured")
        return False
    try:
        if kind and kind.strip().lower() not in KINDS:
            raise ValueError("WEBHOOK_KIND must be one of %s" % ", ".join(KINDS))
        problem = credential_url_problem(webhook_url, "webhook URL")
        if problem:
            raise ValueError(problem)
        kind = detect_kind(webhook_url, kind)
        url = post_url(webhook_url) if kind == "gchat" else webhook_url
        body = json.dumps(payload(kind, text)).encode("utf-8")
    except ValueError as e:
        # Only fixed texts reach the log: a parser message could quote part of the URL.
        if log:
            log.error("notification skipped: %s", e if str(e).startswith(("WEBHOOK_KIND", "webhook URL"))
                      else "webhook URL could not be parsed")
        return False
    headers = {"Content-Type": "application/json; charset=UTF-8"}
    last = None
    for attempt in range(RETRIES + 1):
        try:
            r = http.request("POST", url, data=body, headers=headers, follow=False, timeout=TIMEOUT)
            if 200 <= r.status < 300:
                return True
            last = "HTTP %d" % r.status
            retry = r.status == 429 or r.status >= 500
        except NetworkError as e:
            last = "network error (%s)" % _strip_url(str(e))
            retry = True
        except Exception as e:  # never let notification break a run
            last = "unexpected error (%s)" % type(e).__name__
            retry = False
        if not retry or attempt == RETRIES:
            break
        sleep(BACKOFF[min(attempt, len(BACKOFF) - 1)])
    if log:
        log.error("%s notification failed after %d attempt(s): %s", NAMES[kind], attempt + 1, last)
    return False


def _strip_url(msg):
    # NetworkError messages carry only the host, but be defensive about query strings.
    return msg.split("?")[0]
