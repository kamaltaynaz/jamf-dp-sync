# Changelog

## 1.0.0 — 2026-11-17

First public release.

- `run`: per-app sync from Jamf Patch Management titles to a Linux file share distribution point,
  with a run lock, preflight checks, per-app isolation and exit code 1 when any app fails.
- Resolvers: `github_tag` (with API digest and a web-page fallback when the API is rate-limited),
  `url_template`, `latest_redirect` (with conditional requests) and `adobe_arm_manifest`; a
  `dmg_extract` post-download step using 7-Zip, with no mounting and no root.
- Verification before publish: size and SHA-256 where published, flat pkg structure and table of
  contents checksum, Developer ID Installer certificate fields (Team ID), and pkg version rules
  (`dotted`, `swiftdialog`, `acrobat`, `zoom`, `office`).
- Atomic, no-overwrite publish into `Packages/` via a hard link from staging on the same filesystem.
- Jamf Pro integration in a fixed order: package record with SHA-512 and an ownership marker,
  surgical Classic API policy swaps with re-read and read-back checks, and patch title mapping.
- Pinning for rollback, with re-verification of retained pkgs.
- Pruning limited to files with the agent's name prefix and a marked package record.
- Skip-then-alert when the catalog is ahead of the vendor.
- Recovery from interrupted runs through a durable ownership record with inode anchors.
- Notifications to Google Chat, Slack and Microsoft Teams (Workflows): one message per run, nothing
  on quiet nights, Monday heartbeat; `notify-test`.
- `run --dry-run`, `run --no-prune`, `check-config` and `status` commands.
- `label-import`: drafts config entries from Installomator labels, without executing them.
- Monitor-mode config entries are validated and reported by `status`; alerting from `run` is not
  built yet.
- Python 3.6+ standard library only; secrets file checked for `0600` and redacted from logs and
  messages.
