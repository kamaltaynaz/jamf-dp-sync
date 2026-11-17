# Notifications

The agent posts to one incoming webhook: Google Chat, Slack, or Microsoft Teams through a Workflows
webhook. Everything is also written to the log file, so notifications are optional: with no
`WEBHOOK_URL` the agent runs normally and logs that it skipped the message.

## When a message is sent

One message per run, and only when there is something to say:

| Line | Sent when |
| --- | --- |
| `*OK*` | An app published a new pkg or changed a policy: old → new version and the policies changed |
| `*FAIL*` | An app failed: the step and a one-line reason |
| `*WARN*` | A version has not been downloadable for `alert_after_days` (repeated at most daily); a policy was skipped because nothing matched and `add_if_missing` is false; a policy's package list changed around an update; a title mapping was taken by another package; and similar warnings |
| `*Heartbeat*` | The first run on a Monday: apps current and each app's last publish date |
| `*FAIL* preflight` / `*FAIL* startup` | The run stopped before any app (config, secrets, folders, tools, disk space) |

A night with no changes, failures or due alerts sends nothing (except the Monday heartbeat). Dry
runs never send anything.

## Format

```
[dp] jamf-dp-sync · 2026-11-10 03:21
*OK*   nudge    2.1.4.81863 → 2.1.5.81902   policy 101
*OK*   zoom     7.2.5.90525 → 7.2.6.91011   policy 104
*FAIL* office   verify: Team ID mismatch (expected UBF8T346G9, certificate OU ABCDE12345)
*WARN* acrobat  target 26.003.22080 not fetchable: manifest offers 26.003.22075, target 26.003.22080 not published yet (waiting 3 days)
```

- The first line starts with the server's short host name in brackets, so messages from a test
  server are easy to tell apart.
- At most 4,000 characters; extra lines are replaced by "…and N more, see log".
- Plain text with `*bold*` markers. Slack reads them as bold; for Teams they are converted.
- Secret values (tokens, client secret, the webhook URL) are removed from every line before sending.

## Google Chat

1. In the Chat space, open **Apps & integrations > Webhooks** and add an incoming webhook. If the
   option is missing, a Google Workspace administrator must allow users to add incoming webhooks.
2. Put the URL in the secrets file as `WEBHOOK_URL`.

Each run's message is posted as a new top-level message: any `threadKey` or `messageReplyOption`
parameter on the URL is removed before posting. The older secrets key `GCHAT_WEBHOOK_URL` is still
read when `WEBHOOK_URL` is empty.

## Slack

1. Create a Slack app with **Incoming Webhooks** enabled and add a webhook for the channel (the URL
   starts with `https://hooks.slack.com/`).
2. Put the URL in the secrets file as `WEBHOOK_URL`.

The message is sent as `{"text": ...}` with `&`, `<` and `>` escaped.

## Microsoft Teams (Workflows)

1. In Teams, create a workflow from the template **"Post to a channel when a webhook request is
   received"** and choose the team and channel.
2. Copy the HTTP POST URL the workflow shows and put it in the secrets file as `WEBHOOK_URL`.

The message is sent as an Adaptive Card (version 1.4), one text block per line, with the header in
bold and the app lines in a monospaced font.

## Choosing the kind

The kind is detected from the webhook URL's host:

| Host | Kind |
| --- | --- |
| `hooks.slack.com` | `slack` |
| ends with `.logic.azure.com`, `.powerplatform.com` or `.webhook.office.com` | `teams` |
| anything else | `gchat` |

If your URL does not match (for example a proxy in front of the webhook), set `WEBHOOK_KIND` to
`gchat`, `slack` or `teams` in the secrets file. Any other value is an error. `check-config` prints
the kind it will use.

## Delivery

Each message is a JSON `POST` with a 10-second timeout, retried up to 3 times with increasing
back-off (2, 4, 8 seconds) on HTTP 429, 5xx or a network error. Redirects are not followed. If it
still fails, the agent logs the failure (with the HTTP status, never the URL) and carries on: a
notification failure never changes the run's exit code.

The webhook URL contains a key or signature that lets anyone post to your channel, so treat it as a
secret. The agent never logs it, prints it or puts it in a message.

## Testing

```
jamf-dp-sync notify-test
```

Sends "notify-test: if you can read this, the webhook works." and prints `sent` or `FAILED (see log)`.
Use a separate channel and webhook for a test server.
