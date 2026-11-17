# Configuration reference

The agent reads two files, both in the service user's home:

- `~/.config/jamf-dp-sync/packages.json`: what to sync (this page). Another path can be given with
  `--config PATH` before the command, for example `jamf-dp-sync --config /path/test.json run`.
- `~/.config/jamf-dp-sync/env`: secrets ([below](#secrets)).

The config is validated on every start. The agent refuses to run, and lists every problem at once, on:
unknown keys, missing required keys, values of the wrong type (`true` is never accepted where a
number is meant), duplicate JSON keys, duplicate labels, invalid regular expressions, non-`https://`
URLs and the other rules below. Run `jamf-dp-sync check-config` after every change.

## Global keys

| Key | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `dp_packages_dir` | string (path) | yes | | The distribution point's `Packages/` folder. |
| `staging_dir` | string (path) | yes | | Staging folder: same filesystem as `Packages/`, outside the share (the folder holding `Packages/`). |
| `dp_group` | string | no | none | Group to set on published files (`chgrp`). The service user must be a member. |
| `category_id` | integer | no | `-1` | Jamf category ID for new package records; `-1` means none. |
| `retain` | integer ≥ 1 | no | `2` | Agent-created versions to keep per app (see [pruning](#retention-and-pruning)). |
| `alert_after_days` | integer ≥ 0 | no | `3` | Days an app may wait for a version before alerting (see [skip-then-alert](#skip-then-alert)). |
| `log_file` | string (path) | no | `~/logs/jamf-dp-sync.log` | Log file, rotated at 5 MB with 9 older files kept. |
| `lock_file` | string (path) | no | `~/.local/state/jamf-dp-sync/run.lock` | Lock that keeps runs from overlapping. |
| `tools` | object | no | see below | Paths of external tools. |
| `apps` | array | yes | | One object per app; must not be empty. |

Paths may start with `~/` and must be absolute after that is expanded.

`tools` accepts only these keys:

| Key | Default | Needed |
| --- | --- | --- |
| `openssl` | `/usr/bin/openssl` | Always |
| `7zz` | `~/bin/7zz` | Only when an app uses `dmg_extract` (or an Adobe manifest arrives 7z-wrapped) |

## Per-app keys

Every app has a `mode`: `sync` (the agent publishes it) or `monitor` (see [monitor mode](#monitor-mode)).

### Keys for every app

| Key | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `label` | string | yes | | Unique ID used in logs, messages, the cache and `--only`. Lower-case letters, digits, `_` and `-`; up to 64 characters; starts with a letter or digit. |
| `mode` | string | yes | | `sync` or `monitor`. |
| `patch_title_id` | integer or `null` | yes | | Jamf Patch Management software title ID. `null` is allowed only for `github_tag` apps (see [version sources](#version-sources)). |
| `version_rule` | string | yes | | How versions are compared: `dotted`, `swiftdialog`, `acrobat`, `zoom` or `office` ([version rules](#version-rules)). |
| `policy_ids` | array of integers | yes | | Jamf policies to update. Positive, no duplicates, at least one. The **first** policy is where the current version is read from. |
| `replace_regex` | string (regex) | no | | Matches hand-named pkgs in those policies that the agent should replace (sync), or extracts the version (monitor, required there). |
| `retain` | integer ≥ 1 | no | global `retain` | Per-app override. |
| `alert_after_days` | integer ≥ 0 | no | global value | Per-app override. |
| `category_id` | integer | no | global value | Per-app override. |

### Extra keys for sync apps

| Key | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `resolver` | string | yes | | `github_tag`, `url_template`, `latest_redirect` or `adobe_arm_manifest`, plus that resolver's keys ([resolvers](#resolvers)). |
| `name_prefix` | string | yes | | Published files are named `<name_prefix>-<version>.pkg`. Letters, digits, `.`, `_`, `-`; up to 100 characters. Use a prefix such as `jds-` that no hand-uploaded pkg uses. |
| `team_id` | string | yes | | The vendor's Apple Developer Team ID (10 upper-case letters or digits). The pkg must be signed by a "Developer ID Installer" certificate with this Team ID. |
| `post_download` | object | no | | `{"type": "dmg_extract", "inner_path_regex": "..."}` ([below](#post_download-dmg_extract)). |
| `add_if_missing` | boolean | no | `false` | Add the pkg to a policy that has no matching package. With `false`, such a policy is left alone and a warning is reported on every run. |
| `pin` | string | no | | Hold this exact version instead of following the patch title ([pinning](#pinning-and-rollback)). Must parse with the app's `version_rule`. |

Two apps may not share a `name_prefix`, and one prefix may not be another's prefix followed by `-`
(for example `jds-Zoom` and `jds-Zoom-IT`), because pruning would not be able to tell their files
apart.

### Which package in a policy is replaced

In each policy the agent replaces the package entries whose name matches `^<name_prefix>-.+\.pkg$`
or `replace_regex`. Several matches are collapsed into the one new entry, which keeps the first
match's install action. Every other package in the policy is sent back unchanged. If nothing matches,
the pkg is added only when `add_if_missing` is `true`.

`replace_regex` is how you migrate a policy that already holds a hand-uploaded pkg: for example
`"^Nudge_Suite-.+\\.pkg$"` replaces `Nudge_Suite-2.1.4.81863.pkg` on the first run. The hand-uploaded
package record and file stay in Jamf and on the distribution point; the agent never deletes them.

## Resolvers

A resolver turns the target version into a download URL and any integrity data the vendor publishes.
All URLs must be `https://`. Downloads never carry credentials, and a redirect from HTTPS to HTTP is
refused.

### `github_tag`

For apps released as GitHub release assets.

| Key | Meaning |
| --- | --- |
| `repo` | `owner/name`, for example `macadmins/nudge`. |
| `asset_regex` | Matches exactly one asset name in the release, for example `^Nudge_Suite-[0-9.]+\.pkg$`. Zero or several matches is an error. |

The target version is turned into a tag with the version rule: `v<version>` for `dotted`,
`v<major>.<minor>.<patch>` for `swiftdialog`. The repository must therefore tag releases in that form.
The agent reads `GET /repos/{repo}/releases/tags/{tag}` from the GitHub API (with `GITHUB_TOKEN` when
set) and uses the asset's published SHA-256 digest and size when present. If the API is rate-limited
or down (403, 429, 5xx or unreachable), it falls back to the release's web page, which has no digest.
A missing tag or a draft release means "not published yet" ([skip-then-alert](#skip-then-alert)).

Use it for: Nudge, swiftDialog and other apps whose signed pkg is a GitHub release asset.

### `url_template`

For vendors with a versioned download URL.

| Key | Meaning |
| --- | --- |
| `url_template` | HTTPS URL containing `{version}` and no other placeholder, for example `https://cdn.zoom.us/prod/{version}/ZoomInstallerIT.pkg`. |

`{version}` is filled with the version in the rule's URL form (for example `7.2.5.90525` for `zoom`,
the 10-digit code for `acrobat`). The agent sends a `HEAD`: 200 means the version exists; 404 or 403
means it is not downloadable yet (some CDNs answer 403 for a path that does not exist). The URL is
exact, so the pkg must contain exactly the target version.

### `latest_redirect`

For vendors that publish only a "latest" URL.

| Key | Meaning |
| --- | --- |
| `url` | HTTPS URL that serves, or redirects to, the current pkg (or DMG). |

The agent follows the redirects and downloads the file. The version inside the pkg decides: if it is
at least the target, it is accepted and named by the pkg's own version; if it is older (the vendor's
CDN has not caught up with Jamf's catalog yet), the app is skipped. A conditional request
(ETag / Last-Modified, cached per app) avoids downloading an unchanged file again.

Use it for: Microsoft 365 (`https://go.microsoft.com/fwlink/?linkid=525133`), Google Chrome's
enterprise pkg (`https://dl.google.com/dl/chrome/mac/universal/stable/gcem/GoogleChrome.pkg`), and
most labels imported from Installomator. Because only the latest is served, a `pin` to an older
version works only while that version is still retained on the distribution point.

### `adobe_arm_manifest`

For Adobe Acrobat, from Adobe's update manifest.

| Key | Meaning |
| --- | --- |
| `manifest_url` | HTTPS URL of the `.arm` manifest, for example `https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/acrobat/AcrobatManifest.arm`. |
| `item_id` | The manifest item to use: `dld_App_Full` (the full installer, never the incremental or other items). |

The manifest may be a signed xar archive (its signer must be a Developer ID Installer certificate for
the app's `team_id`), a 7z archive (needs `7zz`) or plain XML. The selected item gives the URL, the
SHA-256 and the size. Before downloading, the agent checks the item's signing entity Team ID, its
file name (`AcrobatDC<10 digits>_MUI.pkg`) and that its version equals the target. A target newer than
the manifest is "not yet"; a pinned target older than the manifest uses Adobe's versioned download URL
without a hash, with a warning.

## `post_download: dmg_extract`

For a vendor pkg shipped inside a DMG:

```json
"post_download": {"type": "dmg_extract", "inner_path_regex": "(^|/)ExampleApp\\.pkg$"}
```

After download, `7zz` lists the DMG and exactly one member must match `inner_path_regex`. Only that
member is extracted, into a fresh folder under staging; absolute paths and `..` are refused. Nothing
is mounted and no root is needed. The extracted pkg then goes through every verification check as
usual. 7-Zip cannot open every APFS disk image; a dry run shows whether yours works.

## Version sources

The target version for a sync app comes from, in order:

1. `pin`, if set;
2. the patch title's newest definition (`patch_title_id`), as ordered by Jamf (not by release date,
   which is not always in order);
3. for a `github_tag` app with `patch_title_id: null`, the repository's latest release tag (set
   `GITHUB_TOKEN`).

The current version is read from the agent-named pkg in the app's first policy. There is no local
version database. If that policy already holds a version newer than the target, the agent keeps it
and never downgrades without a pin.

## Version rules

Each app names a `version_rule` that turns every form its version appears in (patch title, tag, URL,
pkg, file name) into one comparable value.

| Rule | Accepts | File-name / URL form | Example |
| --- | --- | --- | --- |
| `dotted` | Dotted integers, optional leading `v` | Same dotted form, leading zeros dropped | `142.0.7444.60`, tag `v2.1.4.81863` |
| `swiftdialog` | `3.1.1`, `v3.1.1`, `3.1.1.5000`, `3.1.1-5000`, `dialog-3.1.1-5000.pkg` | Marketing version only (`3.1.1`); the build number is ignored when comparing | tag `v3.1.1` |
| `acrobat` | `26.003.22075`, `26.3.22075`, or the 10-digit code `2600322075` anywhere in a string | Name `26.003.22075`; URL form `2600322075` | |
| `zoom` | `7.2.5 (90525)` (patch title) or `7.2.5.90525` | `7.2.5.90525` | |
| `office` | Same as `dotted` | Same as `dotted` | Compare the Microsoft 365 suite pkg with the **Microsoft Word** patch title, whose versions match the suite pkg's |

For a new app, check that the patch title's version strings and the pkg's own version parse with the
rule you choose; `run --dry-run` reports a version that does not parse. A patch title whose versions
have fewer parts than the pkg's (for example `8.11` against `8.11.20503`) will not compare correctly
with `dotted`.

## Pinning and rollback

Set `pin` to an exact version to hold an app there:

```json
"pin": "2.1.4.81863"
```

On the next run every policy of that app is swapped to the pinned version, even if that is a
downgrade. If the pinned pkg is still retained on the distribution point (with its record), it is
re-verified (signer, version, SHA-512 against its record) and reused without downloading. Otherwise
it is downloaded, which needs a source that can serve old versions (`github_tag`, `url_template`,
`adobe_arm_manifest`); `latest_redirect` cannot. Remove `pin` to follow the patch title again.

## Retention and pruning

After a successful update the agent deletes old copies of the pkgs it created, keeping:

- the current version;
- the `retain` newest agent-created records (by Jamf record ID), so `retain: 2` keeps the current
  version plus one rollback;
- anything one of the app's policies still references.

A package counts as agent-created only when **both** its name is `<name_prefix>-<version>.pkg` with a
version the rule parses **and** its Jamf package record's notes contain `created by jamf-dp-sync`,
which the agent writes when it creates the record. It must also be the very file the agent published
(checked by inode and checksum). Anything else is never deleted.

The record is deleted first, then the file, because Jamf does not delete files from file share
distribution points. Deleting a record removes it from every policy that uses it, which is why only
agent-created records are touched.

If a file or record in `Packages/` looks like the agent's (matches `<name_prefix>-<version>.pkg`) but
has no marked record, the app stops with an error rather than guess. Rename the file or change the
prefix.

`run --no-prune` skips pruning for one run.

## Skip-then-alert

Jamf's patch catalog sometimes announces a version before the vendor's download serves it. When the
target is not downloadable yet (missing release, 403/404 on a template URL, an older pkg on a "latest"
URL, a manifest that has not caught up), the app is skipped without error and the first-skipped date
is recorded in the cache. Once the app has waited `alert_after_days` days, the run summary includes a
warning, at most once a day, until the version arrives or the target changes.

## Monitor mode

```json
{
  "label": "examplevpn",
  "mode": "monitor",
  "patch_title_id": 205,
  "version_rule": "dotted",
  "policy_ids": [105],
  "replace_regex": "^ExampleVPN-(?P<version>[0-9.]+)\\.pkg$"
}
```

For apps you still upload by hand. A monitor entry takes only the keys for every app (no resolver,
prefix or Team ID), needs a `patch_title_id`, and its `replace_regex` must contain a
`(?P<version>...)` group that extracts the version from the pkg name in the policy.

Current state: monitor entries are validated, and `status` shows the policy's version next to the
patch title's. `run` skips them with one log line; it does not download them and does not alert yet.

## Secrets

`~/.config/jamf-dp-sync/env`, one `KEY=value` per line. Lines starting with `#` are comments, values
may be quoted, and an `export ` prefix is accepted. Any other key is refused. The file must be a
regular file owned by the service user with no group or other permissions (`chmod 600`).

| Key | Required | Meaning |
| --- | --- | --- |
| `JAMF_URL` | yes | Jamf Pro base URL, for example `https://yourorg.jamfcloud.com` or `https://jamf.example.com:8443`. |
| `JAMF_CLIENT_ID` | yes | API client ID. |
| `JAMF_CLIENT_SECRET` | yes | API client secret. |
| `GITHUB_TOKEN` | no | Read-only fine-grained token for the GitHub API. Recommended for `github_tag` apps. |
| `WEBHOOK_URL` | no | Incoming webhook for Google Chat, Slack or Microsoft Teams (Workflows). Empty means no notifications. |
| `WEBHOOK_KIND` | no | `gchat`, `slack` or `teams`. Empty means detect from the URL's host. |
| `GCHAT_WEBHOOK_URL` | no | Older name for `WEBHOOK_URL`; read only when `WEBHOOK_URL` is empty. |

Secret values are redacted from every log line and message, including Jamf bearer tokens obtained
at run time.

## Full example

```json
{
  "dp_packages_dir": "/srv/jamf/Packages",
  "staging_dir": "/srv/jamf-dp-sync-staging",
  "category_id": -1,
  "retain": 2,
  "alert_after_days": 3,
  "tools": {"openssl": "/usr/bin/openssl", "7zz": "~/bin/7zz"},
  "apps": [
    {
      "label": "nudge",
      "mode": "sync",
      "resolver": "github_tag",
      "repo": "macadmins/nudge",
      "asset_regex": "^Nudge_Suite-[0-9.]+\\.pkg$",
      "name_prefix": "jds-NudgeSuite",
      "team_id": "T4SK8ZXCXG",
      "patch_title_id": 201,
      "version_rule": "dotted",
      "policy_ids": [101],
      "replace_regex": "^Nudge_Suite-.+\\.pkg$"
    },
    {
      "label": "acrobat",
      "mode": "sync",
      "resolver": "adobe_arm_manifest",
      "manifest_url": "https://armmf.adobe.com/arm-manifests/mac/AcrobatDC/acrobat/AcrobatManifest.arm",
      "item_id": "dld_App_Full",
      "name_prefix": "jds-AdobeAcrobatPro",
      "team_id": "JQ525L2MZD",
      "patch_title_id": 202,
      "version_rule": "acrobat",
      "policy_ids": [102],
      "add_if_missing": true
    },
    {
      "label": "office",
      "mode": "sync",
      "resolver": "latest_redirect",
      "url": "https://go.microsoft.com/fwlink/?linkid=525133",
      "name_prefix": "jds-Microsoft365",
      "team_id": "UBF8T346G9",
      "patch_title_id": 203,
      "version_rule": "office",
      "policy_ids": [103],
      "add_if_missing": true
    },
    {
      "label": "zoom",
      "mode": "sync",
      "resolver": "url_template",
      "url_template": "https://cdn.zoom.us/prod/{version}/ZoomInstallerIT.pkg",
      "name_prefix": "jds-ZoomWorkplace",
      "team_id": "BJ4HAAB9B3",
      "patch_title_id": 204,
      "version_rule": "zoom",
      "policy_ids": [104],
      "add_if_missing": true
    },
    {
      "label": "exampleapp",
      "mode": "sync",
      "resolver": "latest_redirect",
      "url": "https://downloads.example.com/ExampleApp.dmg",
      "post_download": {"type": "dmg_extract", "inner_path_regex": "(^|/)ExampleApp\\.pkg$"},
      "name_prefix": "jds-ExampleApp",
      "team_id": "ABCDE12345",
      "patch_title_id": 206,
      "version_rule": "dotted",
      "policy_ids": [106],
      "add_if_missing": true
    }
  ]
}
```

The IDs (101, 201 and so on), the `exampleapp` entry and its Team ID are placeholders. The Team IDs
of the real vendors shown are the ones their pkgs are signed with; check them against a pkg you trust
if in doubt, since a wrong value only blocks the publish.
