# jamf-dp-sync

A small unattended agent that runs from cron on a Linux Jamf **file share distribution point** and
turns it into a **local cache for Mac builds**.

Each night it reads the Jamf Pro Patch Management title for each app you list, downloads the
vendor's signed installer pkg once, verifies it, publishes it into the distribution point's
`Packages/` folder, and swaps it into the Jamf policy your enrollment workflow calls. New Macs then
install those apps from the local network instead of each one downloading them from the internet
during the build.

It is written in Python 3.6+ using only the standard library, and runs as an ordinary service user.
It never needs root.

## Why it exists

Many enrollment workflows (for example [Jamf Setup Manager](https://github.com/jamf/setup-manager))
install apps with [Installomator](https://github.com/Installomator/Installomator) labels. That works
well for most fleets. Two things go wrong when many Macs are built at the same time behind one public
IP address:

- **GitHub's API limit.** Some labels ask the GitHub API which release is newest. Anonymous GitHub
  API calls are limited to 60 requests per hour per public IP. Every Mac behind the same NAT shares
  that limit, so during a mass build the GitHub-backed labels start failing part-way through.
- **Repeated large downloads.** Every Mac downloads every installer from the internet, every build.
  Some are several gigabytes each (Microsoft 365 and Adobe Acrobat, for example).

Installomator did nothing wrong here. Downloading the latest version at install time is the right
design for most fleets, and the rate limit belongs to GitHub. jamf-dp-sync complements Installomator:
it moves the download for the handful of apps every new Mac needs from "every Mac, at build time" to
"one server, once a night". It can also draft its configuration from Installomator labels (see
[`label-import`](docs/installomator-labels.md)).

## How it works

For each app, on each run:

1. Read the target version from the app's Jamf Patch Management title (or a `pin` in the config, or
   the latest GitHub release for apps with no patch title).
2. Read the version currently in the app's Jamf policy. If the policy already holds the target, stop:
   no download, no writes. Most nights every app stops here.
3. Find the download URL with one of four small resolvers (GitHub release asset, a URL template with
   the version in it, a "latest" URL that redirects, or Adobe's update manifest).
4. Download into a staging folder on the same filesystem as `Packages/`. A pkg inside a DMG can be
   pulled out with 7-Zip, without mounting anything.
5. Verify: size and SHA-256 where the vendor publishes them, a valid flat pkg, a "Developer ID
   Installer" signing certificate from the expected Apple Team ID, and the version inside the pkg.
6. Publish atomically into `Packages/` as `<name_prefix>-<version>.pkg`.
7. Create the Jamf package record (with a SHA-512 checksum), swap the new pkg into each policy while
   leaving everything else in the policy as it was, and map the pkg to its version in the patch title.
8. Prune older copies the agent created, keeping the current one plus one for rollback by default.
9. Post one summary message to a chat webhook if anything changed or failed.

Any failed check stops that app before the distribution point or Jamf is touched; the other apps
carry on. See [How it works](docs/how-it-works.md) for the detail.

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
- A Jamf Pro API client with a small role (see [Install](docs/install.md#5-jamf-pro-api-role-and-client)).
- Outbound HTTPS from the server to Jamf Pro, the vendors' download hosts, GitHub (for GitHub-hosted
  apps) and your webhook.

## Quick start

1. Follow [docs/install.md](docs/install.md): service user, write access to `Packages/`, staging
   folder, code, secrets, config, Jamf API client and one policy per app.
2. Describe your apps in `packages.json` ([docs/configuration.md](docs/configuration.md)), or draft
   entries from Installomator labels ([docs/installomator-labels.md](docs/installomator-labels.md)).
3. Check and try it, as the service user:

   ```
   python3 /opt/jamf-dp-sync/jamf_dp_sync.py check-config
   python3 /opt/jamf-dp-sync/jamf_dp_sync.py notify-test
   python3 /opt/jamf-dp-sync/jamf_dp_sync.py run --dry-run
   python3 /opt/jamf-dp-sync/jamf_dp_sync.py run
   ```

4. Add the daily cron line, then point your enrollment workflow at the policies
   ([docs/setup-manager.md](docs/setup-manager.md)).

## Commands

In the docs, `jamf-dp-sync` is short for `python3 /opt/jamf-dp-sync/jamf_dp_sync.py` (or
`python3 -m jamf_dp_sync` from the code folder).

```
jamf-dp-sync [--config PATH] run [--only LABEL ...] [--dry-run] [--no-prune] [-v]
jamf-dp-sync [--config PATH] check-config
jamf-dp-sync [--config PATH] status [--only LABEL ...]
jamf-dp-sync [--config PATH] notify-test
jamf-dp-sync label-import --installomator PATH LABEL [LABEL ...]
```

| Command | What it does |
| --- | --- |
| `run` | Sync every app (or only the labels given). Exit 0 when no app failed, 1 when any app failed or preflight failed. A second run while one is already running exits 0. |
| `run --dry-run` | Resolve, download and verify, then print what would change. Writes nothing to `Packages/`, Jamf or the state cache, and sends no notification. |
| `run --no-prune` | Skip pruning for this run. |
| `check-config` | Validate `packages.json` and the secrets file. Does not contact Jamf. |
| `status` | Per app: version in the policy, latest patch title version, last result. Read-only. |
| `notify-test` | Post a test message to the configured webhook. |
| `label-import` | Print draft `packages.json` entries for Installomator labels. Needs no secrets or config. |

`--config` defaults to `~/.config/jamf-dp-sync/packages.json`.

## Compatibility

- **Jamf Pro on-premises:** tested in production.
- **Jamf Cloud:** expected to work, not yet tested; reports welcome. Nothing in the agent assumes an
  on-premises server: it uses only the Jamf Pro API and Classic API over HTTPS with an OAuth API
  client. Jamf Pro supports file share distribution points alongside the Jamf Cloud distribution
  point, chosen per network segment, so a cloud-hosted Jamf Pro with an on-site Linux file share
  distribution point is the same design.

  **Limitation:** the packages exist only on the local file share distribution point. A Mac whose
  network segment points at the cloud distribution point will not find them, and the policy will
  fail for that Mac. The cache is for on-site builds: make sure build Macs are on a network segment
  that uses the local distribution point. Uploading to the cloud distribution point as well is a
  possible future option.

## Known limits

- **The signature check reads certificate fields; it is not cryptographic.** The agent takes the
  leaf certificate from the pkg's xar table of contents and uses `openssl` to check that it is a
  "Developer ID Installer" certificate whose subject OU equals the app's expected Team ID. That
  catches a wrong or unexpected vendor pkg, but it does **not** verify the table of contents
  signature or the chain to Apple's root the way `pkgutil --check-signature` does on macOS: a forged
  self-signed certificate with the same fields would pass. Authenticity comes from HTTPS to the
  vendor's own host plus the vendor's SHA-256 and size where the source publishes them (GitHub
  release asset digests, Adobe's manifest). For sources that publish no hash (`latest_redirect`,
  `url_template`), it rests on HTTPS alone; the certificate fields and version check guard against
  mistakes, not attacks. macOS's installer still checks the real signature when a Mac installs the pkg.
- **Policy edits are last-writer-wins.** The Classic API has no conditional update. The agent re-reads
  each policy just before it writes (keeping any edit made since it planned) and reads it back just
  after, warning in the run summary if the package list changed around the update. An admin edit made
  in the instant between that re-read and the write can still be lost; schedule runs for a quiet hour.
- **Signed vendor pkgs only.** The agent publishes a pkg the vendor built and signed, either directly
  or inside a DMG. It never repackages an `.app` bundle from a DMG or ZIP.
- **Some DMGs cannot be opened on Linux.** 7-Zip cannot read every APFS disk image; a dry run tells you.
- **Local distribution point only** (see Compatibility).
- **Monitor mode is not finished.** `monitor` entries are validated and `status` reports their
  policy and patch title versions, but `run` skips them and sends no alerts yet.
- **The Adobe `.arm` manifest** is accepted on HTTPS plus the certificate-field check of its xar
  wrapper; any other signature around it is not verified.

## How it compares

jamf-dp-sync does one narrow job. The tools below do far more; this is about fit, not merit.

| | jamf-dp-sync | Installomator | AutoPkg / AutoPkgr | Munki |
| --- | --- | --- | --- | --- |
| Where it runs | Linux server hosting the file share DP | On each Mac, at install time | A Mac (AutoPkgr is a GUI for AutoPkg) | Client agent on each Mac plus a web repo |
| Download | Once per version, on the server | Every Mac, every install | Once, on the AutoPkg Mac | Once into the repo; Macs fetch from the repo |
| What it handles | Signed vendor pkgs (pkg, pkg in a DMG) | Hundreds of labels: pkg, dmg, zip, app bundles | Thousands of community recipes; can build pkgs from apps | Full software management, updates, self service |
| Version source | Jamf Patch Management titles | The vendor's latest | Recipes | Your repo catalogs |
| Setup | Service user, ACL, config file, cron | A script or a Setup Manager action | A Mac, recipes, overrides, uploader setup | Server repo, client install, manifests |

Choose AutoPkg or Munki when you need broad app coverage, repackaging or ongoing patching. Choose
jamf-dp-sync when you already have a Linux file share distribution point and want the few apps your
builds install to come from it, kept current automatically.

## Documentation

- [Install](docs/install.md)
- [Configuration reference](docs/configuration.md)
- [How it works](docs/how-it-works.md)
- [Using Installomator labels](docs/installomator-labels.md)
- [Notifications](docs/notifications.md)
- [Jamf Setup Manager and other workflows](docs/setup-manager.md)
- [Testing](docs/testing.md)
- [References in code comments](docs/code-references.md) (spec sections and review findings)

## Credits

Designed by Kamal Taynaz. Built with Claude Code (Anthropic) as the developer, with independent code
review rounds by OpenAI Codex.

Thanks to [Installomator](https://github.com/Installomator/Installomator), whose labels record the
vendor download sources and Team IDs this project builds on, and to
[Jamf Setup Manager](https://github.com/jamf/setup-manager).

## Licence

MIT. See [LICENSE](LICENSE).
