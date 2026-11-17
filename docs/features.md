# Features and requirements

## Features

- Jamf Patch Management titles as the version source, with a per-app `pin` for rollback.
- Resolvers: `github_tag`, `url_template`, `latest_redirect`, `adobe_arm_manifest`, plus a
  `dmg_extract` post-download step for a pkg inside a DMG.
- Verification before anything is published; fails closed.
- Atomic, no-overwrite publish into `Packages/`.
- Surgical Classic API policy edits: only the matching package entry changes.
- Package records carry a marker in their notes; only files with the agent's name prefix **and** a
  marked record are ever pruned. Hand-uploaded packages are never touched.
- Skip-then-alert when Jamf's catalog announces a version before the vendor serves it.
- Recovery from interrupted runs (a crash between publishing a file and creating its record, or in
  the middle of a prune).
- Notifications to Google Chat, Slack or Microsoft Teams (Workflows): one message per run, nothing
  on quiet nights, and a Monday heartbeat.
- `--dry-run` that writes nothing to the distribution point, Jamf or the local cache.
- `label-import` drafts config entries from Installomator labels.

## Requirements

- A Linux server that hosts a Jamf **file share distribution point** (the agent writes to its
  `Packages/` folder directly). Tested on RHEL 8-family Linux.
- Python 3.6 or later. Standard library only: no pip, no virtualenv.
- `openssl` (used to read the signing certificate).
- Optional: the official 7-Zip for Linux (`7zz`), pinned to a version and SHA-256 you have checked,
  only if an app ships its pkg inside a DMG.
- A Jamf Pro API client with a small role (see [Install](install.md#5-jamf-pro-api-role-and-client)).
- Outbound HTTPS from the server to Jamf Pro, the vendors' download hosts, GitHub (for GitHub-hosted
  apps) and your webhook.
