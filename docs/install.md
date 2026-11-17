# Install

This guide sets up jamf-dp-sync on the Linux server that hosts your Jamf file share distribution
point. An administrator with root does steps 1 to 4 once. After that the agent runs as an ordinary
service user and never uses `sudo`.

Example values used throughout (replace them with yours):

| Example | Meaning |
| --- | --- |
| `dp.example.com` | The Linux server hosting the file share distribution point |
| `/srv/jamf/Packages` | The distribution point's `Packages/` folder |
| `/srv/jamf-dp-sync-staging` | Staging folder: same filesystem as `Packages/`, outside the share |
| `jamfsync` | The service user |
| `/opt/jamf-dp-sync` | The code |
| `https://yourorg.jamfcloud.com` or `https://jamf.example.com:8443` | Your Jamf Pro URL |

Before you start, the file share distribution point must already exist in Jamf Pro and Macs must be
able to download from it. The agent does not create or configure distribution points.

## 1. Service user

Create an unprivileged user with a home directory. It needs no login shell and no `sudo`.

```
useradd --create-home --shell /sbin/nologin jamfsync
```

Make sure the user may use cron (check `/etc/cron.allow` and `/etc/cron.deny` if your system uses
them). To work as the user later:

```
sudo -u jamfsync -H bash
```

The agent keeps everything else under this user's home:

| Path | What |
| --- | --- |
| `~/.config/jamf-dp-sync/packages.json` | Config |
| `~/.config/jamf-dp-sync/env` | Secrets, mode `0600` |
| `~/bin/7zz` | Optional 7-Zip binary |
| `~/logs/jamf-dp-sync.log` | Log, rotated at 5 MB, 10 files |
| `~/.local/state/jamf-dp-sync/` | Cache (ETags, skip dates, last results) and the run lock. Safe to delete. |
| `~/.local/share/jamf-dp-sync/ownership.json` | Record of the files the agent published. **Not** a cache: keep it. |

## 2. Write access to Packages/

Give the service user write access to `Packages/` with a POSIX ACL, so the share's existing owner,
group and mode stay as they are:

```
setfacl -m u:jamfsync:rwx /srv/jamf/Packages
getfacl /srv/jamf/Packages
```

No default ACL is needed. The agent publishes each pkg with mode `0644`, so Samba (and a web server,
if your distribution point also serves HTTP or HTTPS) can read it through the "other" permission.

## 3. Staging folder

The agent downloads and verifies in a staging folder, then publishes with a hard link, which only
works within one filesystem. The staging folder must therefore be:

- on the **same filesystem** as `Packages/` (the agent compares device numbers before every run);
- **outside the share**. The share root is taken to be the folder that holds `Packages/`
  (`/srv/jamf` here), so staging must not be inside it;
- owned by the service user and not writable by group or others.

```
mkdir /srv/jamf-dp-sync-staging
chown jamfsync: /srv/jamf-dp-sync-staging
chmod 0750 /srv/jamf-dp-sync-staging
```

Free space: preflight requires at least 6 GiB free on that filesystem (twice the largest expected
pkg). Allow about 20 GB if you sync large apps such as Microsoft 365 and Adobe Acrobat and keep a
rollback copy of each.

The agent creates two private folders inside staging: `.jds-scratch/` (downloads in progress,
emptied at the start of each run) and `.jds-owned/` (hard-link anchors that prove which files in
`Packages/` it published). Leave both alone.

**SELinux.** A hard link keeps the staged file's security label. If SELinux is enforcing, give the
staging folder the same context as the share (for example `samba_share_t`, plus whatever your web
server needs if the distribution point is served over HTTP/HTTPS), or published files will not be
readable by Macs:

```
semanage fcontext -a -t samba_share_t '/srv/jamf-dp-sync-staging(/.*)?'
restorecon -Rv /srv/jamf-dp-sync-staging
```

## 4. Code

Put the code in a root-owned folder that the service user can read but not change:

```
git clone https://github.com/kamaltaynaz/jamf-dp-sync.git /opt/jamf-dp-sync
chown -R root:root /opt/jamf-dp-sync
chmod -R u=rwX,go=rX /opt/jamf-dp-sync
```

Check the Python version (3.6 or later) and `openssl`:

```
python3 --version
command -v openssl
```

Nothing is installed with pip. The entry point is `/opt/jamf-dp-sync/jamf_dp_sync.py`.

### Optional: 7-Zip for pkgs inside DMGs

Only needed if an app uses `post_download: dmg_extract`. Use the official 7-Zip for Linux (`7zz`)
from [7-zip.org](https://www.7-zip.org/download.html), pin one version, and check the archive's
SHA-256 against a value you have verified before installing it. 7-Zip 26.05 is the version this
project was tested with.

```
# as jamfsync
mkdir -p ~/bin
sha256sum 7z2605-linux-x64.tar.xz        # compare with the checksum you recorded
tar -xf 7z2605-linux-x64.tar.xz -C ~/bin 7zz
~/bin/7zz | head -2
```

The default path is `~/bin/7zz`; set `tools.7zz` in the config to use another. 7-Zip cannot open
every APFS disk image, so try a dry run before relying on it for a new app.

## 5. Jamf Pro API role and client

In Jamf Pro, **Settings > System > API roles and clients**:

1. Create an API role (for example `jamf-dp-sync`) with exactly these privileges:

   | Privilege | Used for |
   | --- | --- |
   | Read Packages | Finding package records, pruning and recovery checks (`GET /api/v1/packages`) |
   | Create Packages | Creating the record for each published pkg (`POST /api/v1/packages`) |
   | Delete Packages | Pruning old records the agent created (`DELETE /api/v1/packages/{id}`) |
   | Read Policies | Reading each app's policy (`GET /JSSResource/policies/id/{id}`) |
   | Update Policies | Swapping the package in the policy (`PUT /JSSResource/policies/id/{id}`) |
   | Read Patch Management Software Titles | Target version and title mappings (`GET /api/v3/patch-software-title-configurations/...`) |
   | Update Patch Management Software Titles | Mapping the pkg to its title version (`PATCH /api/v3/patch-software-title-configurations/{id}`) |

   The agent never updates an existing package record, so Update Packages is not needed. It does not
   look up categories either: with `category_id` left at `-1` no Categories privilege is needed. If a
   call is refused, the log names the privilege it expected, for example
   `Jamf 403 on POST /api/v1/packages: API role likely needs 'Packages: Create'`.

2. Create an API client with that role, enable it, and generate a client secret. The agent gets
   short-lived tokens with the client-credentials flow (`POST /api/oauth/token`), refreshes them
   before they expire, and invalidates its token when it exits.

## 6. Patch titles

For each app, make sure a Patch Management software title exists in Jamf Pro
(**Computers > Patch Management**) and note its ID (the number in the title's URL). The agent uses the
title's newest definition as the target version, and attaches each published pkg to its version in
the title.

An app hosted on GitHub may have no patch title; it then uses the repository's latest release as its
version source (`patch_title_id: null`, see [configuration](configuration.md#version-sources)).

## 7. One Jamf policy per app

Create one policy for each app the agent syncs:

- **Trigger:** Custom, for example `install-nudge-jsm`. Custom trigger names are case-sensitive.
- **Execution frequency:** Ongoing.
- **Packages:** none yet. Set `add_if_missing: true` for the app so the first run adds its pkg.
  (If the policy already holds a hand-uploaded pkg, set `replace_regex` instead so it is replaced.)
- **Scope:** the computers or group your enrollment workflow builds.
- **Self Service:** off.
- **Distribution point:** each computer's default (decided by network segment, next step).

Note the policy ID (the number in the policy's URL). The agent uses only policy IDs; your enrollment
workflow uses the trigger.

Policy names must be unique. If Jamf answers a save with HTTP 409 "Duplicate name", the save was
refused, even if a read shortly afterwards seems to show your change; Jamf reads can lag behind.

## 8. Network segments

Build Macs must download from this distribution point. In **Settings > Network > Network segments**,
set the default distribution point to the file share distribution point on `dp.example.com` for the
address ranges your build Macs use. A Mac on a segment that points elsewhere (including the Jamf
Cloud distribution point) will not find the agent's packages.

## 9. Secrets file

As the service user, create `~/.config/jamf-dp-sync/env` and restrict it:

```
mkdir -p ~/.config/jamf-dp-sync
cp /opt/jamf-dp-sync/env.example ~/.config/jamf-dp-sync/env
chmod 600 ~/.config/jamf-dp-sync/env
```

```
JAMF_URL=https://yourorg.jamfcloud.com
JAMF_CLIENT_ID=<client id>
JAMF_CLIENT_SECRET=<client secret>
GITHUB_TOKEN=<read-only fine-grained token>
WEBHOOK_URL=<incoming webhook URL>
WEBHOOK_KIND=
```

The agent refuses to start if the file is readable or writable by group or others, is not owned by
the service user, or contains a key it does not know. `GITHUB_TOKEN` is optional but recommended for
GitHub-hosted apps: a fine-grained token with read-only access to public repositories lifts the
server's own GitHub API limit. Without it the agent uses GitHub's web pages as a fallback. See
[configuration](configuration.md#secrets) for every key and [notifications](notifications.md) for the
webhook.

## 10. Config file

As the service user, write `~/.config/jamf-dp-sync/packages.json`. Start from `packages.example.json`
or from [`label-import`](installomator-labels.md), and fill in your paths and IDs:

```json
{
  "dp_packages_dir": "/srv/jamf/Packages",
  "staging_dir": "/srv/jamf-dp-sync-staging",
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
      "add_if_missing": true
    }
  ]
}
```

Every key is described in [configuration.md](configuration.md).

## 11. Check, test, run

All as the service user.

```
python3 /opt/jamf-dp-sync/jamf_dp_sync.py check-config
```

Validates the config and the secrets file and prints which apps are in sync and monitor mode, and
which webhook kind it detected. It does not contact Jamf.

```
python3 /opt/jamf-dp-sync/jamf_dp_sync.py status
```

A read-only call to Jamf: for each app, the version in its policy, the patch title's latest version
and the last result. This confirms the API client and IDs.

```
python3 /opt/jamf-dp-sync/jamf_dp_sync.py notify-test
```

Posts a test message to the webhook.

```
python3 /opt/jamf-dp-sync/jamf_dp_sync.py run --dry-run
```

Runs preflight, resolves, downloads and verifies each app, then prints what it would do (`would
publish ...`, `would swap policy ...`, `would map ...`, `would prune ...`). It writes nothing to
`Packages/`, Jamf or the state cache and sends no notification. Review the output.

```
python3 /opt/jamf-dp-sync/jamf_dp_sync.py run
```

The first real run. You can start with one app (`run --only nudge`) and add the others once you have
tested an install. Then test on a Mac on a build network segment, for example
`sudo jamf policy -event install-nudge-jsm -verbose`, and confirm in `/var/log/jamf.log` that the
download came from your distribution point.

## 12. Cron

Install a daily run in the service user's crontab (`crontab -e` as `jamfsync`). Pick a time after
Jamf has refreshed its patch catalog overnight and outside build hours, for example 03:20:

```
20 3 * * * /usr/bin/python3 /opt/jamf-dp-sync/jamf_dp_sync.py run >/dev/null 2>&1
```

Output is discarded because everything goes to `~/logs/jamf-dp-sync.log` and the webhook. Errors
that happen before the config is read (for example a bad secrets file) are written to the same log
path. A second run that starts while one is still going exits quietly.

## Updating and rollback

To update the code, pull a new release into `/opt/jamf-dp-sync` as root and run `check-config` and
`run --dry-run` as the service user.

To stop using the agent, remove the cron line. The policies keep working with the last published
pkgs; nothing else depends on the agent. To roll an app back to an earlier version, set `pin` (see
[configuration](configuration.md#pinning-and-rollback)).

Jamf does not delete files from file share distribution points: deleting a package record in Jamf
leaves the file in `Packages/`. The agent deletes both for the packages it created; clean up anything
else by hand.
