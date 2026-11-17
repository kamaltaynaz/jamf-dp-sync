# Using Installomator labels

[Installomator](https://github.com/Installomator/Installomator) labels already record, for hundreds
of apps, where the vendor publishes the installer and which Apple Team ID signs it. `label-import`
reads those facts from a copy of `Installomator.sh` and drafts `packages.json` entries from them, so
you do not have to research each app from scratch.

## Usage

```
jamf-dp-sync label-import --installomator /path/to/Installomator.sh nudgesuite firefoxpkg
```

- The draft entries are printed to standard output as a JSON array, ready to paste into the `apps`
  list of `packages.json`.
- For each label, a status (`draft`, `manual`, `unsupported` or `missing`) and notes about what to
  check are printed to standard error.
- The exit code is 1 if any label could not be drafted.
- It needs no secrets, no config and no network access. It can run on any machine with Python 3.6+,
  including a Mac.

## Getting Installomator.sh

The agent never downloads it; point it at a copy you already trust:

- the `Installomator.sh` from a release on the
  [Installomator GitHub releases page](https://github.com/Installomator/Installomator/releases), or
- the copy bundled inside Jamf Setup Manager, in `Setup Manager.app/Contents/Resources/`.

Use the same version your fleet uses, so the drafts match the labels you already rely on.

## What it reads, and how it maps

Only static assignments in the label's block are read: `type`, `downloadURL`, `expectedTeamID`,
`pkgName`, `archiveName` and `name`. **Nothing in the label is executed.**

| In the label | In the draft entry |
| --- | --- |
| `type="pkg"` | A sync entry |
| `type="pkgInDmg"` | A sync entry with `post_download: dmg_extract` |
| `downloadURL="https://..."` (a literal URL) | `resolver: latest_redirect` with that `url` |
| `downloadURL=$(downloadURLFromGit owner repo)` | `resolver: github_tag` with `repo: owner/repo` |
| `archiveName` (a glob, GitHub labels) | `asset_regex`, the glob turned into an anchored regex |
| `pkgName` (pkgInDmg labels) | `inner_path_regex` matching that pkg name |
| `expectedTeamID` | `team_id` |
| `name` | `name_prefix`: `jds-` plus the name's letters and digits |

Every draft also gets `label` (from the Installomator label), `mode: sync`, `version_rule: dotted`,
`patch_title_id: null`, `policy_ids: []` and `add_if_missing: true`.

## What it refuses

It never guesses. A label is reported instead of drafted when:

- **The download URL is computed by shell code** (for example from a `curl` call, a variable or a
  command substitution other than `downloadURLFromGit`), or is not HTTPS. Status `manual`: find the
  vendor URL yourself and write the entry by hand.
- **The label contains anything other than plain `name=value` lines.** Any `if`, `case` or loop,
  a function (Installomator calls some itself, such as `appCustomVersion`), a subshell, a heredoc,
  `read`, `export`, an `&&` / `||` chain, or an assignment hidden in an expansion. Status `manual`,
  even when that code looks harmless: the importer does not try to work out what shell code does.
  Values may contain `$(...)`: that runs in a subshell and cannot change the label's variables.
  In a current Installomator this refuses 16 of the 191 labels that would otherwise draft (mostly
  `appCustomVersion` functions and `if` blocks); a value used by the
  draft that is set more than once is refused too.
- **`type` or `expectedTeamID` is missing or computed, or `pkgName` / `archiveName` is present but
  computed.** Status `manual`; the Team ID is required for verification, and a computed inner name is
  never replaced by a "match anything" pattern.
- **The label installs an app bundle** (`dmg`, `zip`, `tbz`, `appInDmgInZip` and so on). Status
  `unsupported`: jamf-dp-sync publishes signed vendor pkgs only and never repackages an `.app`.
- **The label is not in the file.** Status `missing`.

## What you still fill in

- **`policy_ids`**: the Jamf policy for the app ([install, step 7](install.md#7-one-jamf-policy-per-app)).
  The draft has an empty list, which `check-config` rejects until you fill it in.
- **`patch_title_id`**: the app's Patch Management title. Required for `latest_redirect` entries.
  A `github_tag` entry may keep `null`, in which case the latest GitHub release is the version source
  (set `GITHUB_TOKEN`).
- **`version_rule`**: `dotted` is assumed. Check that the patch title's version strings and the pkg's
  version both parse and compare correctly with it.
- **For `github_tag` entries:** the agent looks up the release tag `v<version>`, so check that the
  repository tags releases that way. If `archiveName` was missing, the draft's `asset_regex` matches
  any `.pkg` (or `.dmg`) asset and the release must have exactly one.
- **For `pkgInDmg` entries:** install `7zz` and run a dry run; some APFS disk images cannot be opened
  by 7-Zip. Without `pkgName` the draft matches any pkg in the DMG, and there must be exactly one.
- **For `latest_redirect` entries:** if the vendor also offers a versioned URL, a `url_template` entry
  is more exact (it can fetch a pinned older version).

Then run `check-config` and `run --dry-run --only <label>`.

## Prefer tested entries where they exist

`packages.example.json` holds entries that have been tested in production, for some apps with a
better resolver or version rule than a draft can give (for example Adobe's manifest for Acrobat, a
versioned template for Zoom, and the `swiftdialog`, `acrobat`, `zoom` and `office` version rules).
When you import one of those labels, `label-import` says so in its notes; use the tested entry and
change only the IDs.

## Example

Run against the copy bundled with Setup Manager, with one label of each outcome (notes go to stderr,
the JSON to stdout, exit status 1 because not every label was drafted):

```
$ jamf-dp-sync label-import --installomator "/Applications/Utilities/Setup Manager.app/Contents/Resources/Installomator.sh" nudgesuite firefoxpkg microsoftoffice365 googlechrome
nudgesuite: draft
  - packages.example.json has a tested entry for this app (label 'nudge') with a better resolver or version rule; prefer it to this draft
  - fill in: policy_ids (the Jamf policy for this app)
  - github_tag looks up the tag 'v<version>'; check the repo tags its releases that way
  - patch_title_id may stay null for a GitHub app: the release tag is then the version source (set a GITHUB_TOKEN)
  - version_rule 'dotted' assumed; check the patch title's version format
firefoxpkg: draft
  - fill in: policy_ids (the Jamf policy for this app) and patch_title_id (its Patch Management title)
  - latest_redirect: the version is read from the downloaded pkg; if the vendor has a versioned URL, a url_template entry is more exact
  - version_rule 'dotted' assumed; check the patch title's version format
microsoftoffice365: manual
  - the label has a command it does not model ('if'); only labels made of plain name=value lines are drafted, so write the entry by hand
  - packages.example.json has a tested entry for this app (label 'office'); use it
googlechrome: unsupported
  - type 'dmg': jamf-dp-sync publishes signed pkgs only (pkg, pkgInDmg); an app bundle in a dmg would need repackaging
[
  {
    "label": "nudgesuite",
    "mode": "sync",
    "resolver": "github_tag",
    "repo": "macadmins/Nudge",
    "asset_regex": "^Nudge_Suite-[0-9.].*\\.pkg$",
    "name_prefix": "jds-NudgeSuite",
    "team_id": "T4SK8ZXCXG",
    "patch_title_id": null,
    "version_rule": "dotted",
    "policy_ids": [],
    "add_if_missing": true
  },
  {
    "label": "firefoxpkg",
    "mode": "sync",
    "resolver": "latest_redirect",
    "url": "https://download.mozilla.org/?product=firefox-pkg-latest-ssl&os=osx&lang=en-US",
    "name_prefix": "jds-Firefox",
    "team_id": "43AQ936H96",
    "patch_title_id": null,
    "version_rule": "dotted",
    "policy_ids": [],
    "add_if_missing": true
  }
]
```

The exit code here is 1, because `googlechrome` (an app in a DMG) could not be drafted; the
`googlechromepkg` label is the pkg variant. The exact output depends on your copy of Installomator.
Before using the `firefoxpkg` draft you would fill in `policy_ids` and `patch_title_id`.
