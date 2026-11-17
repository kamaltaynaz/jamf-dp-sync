# How it works

## A run

`jamf-dp-sync run` does the following:

1. **Lock.** Takes a non-blocking lock on `lock_file`. If another run holds it, logs one line and
   exits 0.
2. **Recover** (real runs only). Empties the scratch folder `<staging_dir>/.jds-scratch/` left by an
   interrupted run and tidies the ownership record (see [crash recovery](#crash-recovery-and-ownership)).
3. **Preflight.** `Packages/` and staging exist and are writable by the service user; staging is on
   the same filesystem as `Packages/` and outside the share; the agent's private folders are real
   directories owned by the service user; at least 6 GiB is free; `openssl` is runnable; `7zz` is
   runnable if an app needs it. Any problem stops the whole run before any app is touched, and is
   reported to the webhook.
4. **Each app in turn**, in config order. One app's failure never stops the others.
5. **Notify.** One message for the whole run, if there is anything to say.

The exit code is 1 if preflight failed or any app failed, otherwise 0.

## One app

For a `sync` app:

1. **Target version.** `pin` if set; otherwise the newest definition of the app's Patch Management
   title; otherwise (GitHub apps with no title) the latest release tag.
2. **Current version.** Read from the name of the agent's pkg in the app's first policy (rule V4).
   If every policy already holds the target, **stop**: no download and no writes, apart from finishing
   steps an earlier interrupted run still owes (title mapping, pruning). Most nights every app ends
   here.
3. **Ownership checks.** Finish anything an interrupted run left (below). If a file or record looks
   like the agent's but has no marked record, stop the app with an error.
4. **Reuse.** If the exact target is already published and retained (a rollback with `pin`, or an
   earlier partial run), re-verify it (signer, version, SHA-512 against its record) and go to step 8.
5. **Resolve** the download URL with the app's resolver.
6. **Download** into the scratch folder, without credentials. For `latest_redirect` apps a
   conditional request skips an unchanged file. A DMG is replaced by the pkg extracted from it.
7. **Verify** (below). Any failure deletes the staged file and stops the app.
8. **Publish** the file into `Packages/` atomically.
9. **Create the package record** in Jamf.
10. **Swap** the pkg into each policy.
11. **Map** the pkg to its version in the patch title.
12. **Prune** old agent-created copies.

The policy swap is the only step that changes what enrolling Macs receive.

## Verification checks

Nothing reaches `Packages/` unless every check passes, in this order:

1. **Size** equals the size the source publishes, when it publishes one.
2. **SHA-256** equals the digest the source publishes, when it publishes one (GitHub release asset
   digests, Adobe's manifest). The SHA-512 is computed in the same pass for the Jamf record.
3. **Flat pkg:** the file starts with the xar magic bytes, its table of contents parses, and the
   table of contents checksum matches.
4. **Signing certificate fields:** the leaf certificate in the table of contents is read with
   `openssl`; its common name must start with "Developer ID Installer:" and end with the expected
   Team ID in brackets, and its organisational unit (OU) must equal the app's `team_id`. This catches
   a wrong or unexpected vendor pkg, but it only reads the certificate's fields: it does not verify
   the signature or the chain to Apple's root, so a forged self-signed certificate with copied
   fields would pass. Authenticity rests on HTTPS from the vendor's host and, where published, the
   vendor's SHA-256 (see the README's known limits).
5. **Version:** read from the pkg (`Distribution` product version, else the first `pkg-ref` with a
   version, else `PackageInfo`) and compared with rule V2 or V3.

XML from vendors and from Jamf is parsed with the standard library; any document containing a
DOCTYPE or entity declaration is rejected before parsing.

## Version rules V1 to V4

- **V1, normalise.** Each app's `version_rule` turns patch title, tag, URL, pkg and file-name forms
  into one comparable value (see [configuration](configuration.md#version-rules)).
- **V2, exact sources** (`github_tag`, `url_template`, `adobe_arm_manifest`, and any pinned app): the
  pkg's version must equal the target.
- **V3, latest-only sources** (`latest_redirect`): a pkg at or above the target is accepted and named
  by its own version; an older pkg means the vendor's CDN has not caught up, so the app is skipped and
  [skip-then-alert](configuration.md#skip-then-alert) applies.
- **V4, current version** comes from the name of the agent's pkg in the app's first policy. No local
  version database is kept.

Without a pin the agent never moves a policy to an older version, even if Jamf's catalog goes
backwards.

## Atomic publish

The staged file is set to mode `0644` (and to `dp_group`, if set), flushed to disk, then hard-linked
into `Packages/` under its final name and the staged name removed. Because staging is on the same
filesystem, the link is atomic: a Mac never sees a half-written file. A link also refuses to replace
an existing name, so a published pkg is never overwritten. If a file of that name already exists with
the same SHA-512 (an earlier run published it), it is reused; a different file under that name stops
the app.

## Jamf write order

The order is fixed: **file in `Packages/` → package record → policy update → title mapping**. A
record is never created for a file that is not on disk.

- **Package record:** `POST /api/v1/packages` with the file name, SHA-512 checksum, category and a
  notes marker (`created by jamf-dp-sync`) that pruning later requires.
- **Policy update:** the Classic API replaces a policy's whole package list, so the agent sends every
  existing entry back unchanged except the swapped one, which keeps its install action. It re-reads
  the policy just before writing and re-plans if someone changed its packages since, then reads it
  back afterwards and warns if the list differs from what it sent.
- **Title mapping:** the pkg is attached to its version in the patch title, keeping existing
  mappings. If another package is already mapped to that version, it is left alone with a warning. If
  the title does not list the version yet, the mapping is retried on later runs.

## Crash recovery and ownership

The agent keeps a durable record of the files it publishes in
`~/.local/share/jamf-dp-sync/ownership.json`, with a hard-link "anchor" for each in
`<staging_dir>/.jds-owned/`. The anchor keeps the file's inode number from being reused, so the agent
can prove a file in `Packages/` is the very one it published, not merely one with the same name. The
anchors use no extra disk space while the pkg is in `Packages/`.

With that record, a later run can safely finish what an interrupted run left:

- a file published but with no package record yet: the record is created;
- a prune that deleted the record but not the file: the file is deleted;
- a title mapping or prune still owed: it is done on the next run, even if nothing else changed.

A file the agent cannot prove it published is never adopted, reused, mapped or deleted; the app
stops or warns and asks you to check by hand. Deleting `ownership.json` or the `.jds-owned/` folder
does not cause damage, but the agent then no longer recognises its earlier files and will refuse to
prune or reuse them.

The cache in `~/.local/state/jamf-dp-sync/` (ETags, skip dates, last results, heartbeat week) is
different: it is safe to delete, at the cost of a re-download or a skip alert sent earlier or later.

## Notifications

- **One message per run**, combining successes, failures and warnings, capped at 4,000 characters
  (overflow ends with "…and N more, see log").
- **Nothing on a quiet night.** A run where no app changed or failed and no alert is due sends nothing.
- **Monday heartbeat.** The first run on a Monday adds a heartbeat: how many apps are current and
  each app's last publish date. If no heartbeat arrives on a Monday, the agent has stopped running.
- **Preflight and startup failures** are sent as their own message.
- Delivery failures are logged and never change the run's exit code.

See [notifications](notifications.md) for formats and setup.

## Dry run

`run --dry-run` takes the lock, runs preflight, resolves, downloads and verifies every app that needs
an update, then deletes the download and prints what it would do:

```
nudge        dry-run
    would publish jds-NudgeSuite-2.1.5.81902.pkg (31.2 MB, SHA-256 3f9a0c1b2d4e)
    would create package record jds-NudgeSuite-2.1.5.81902.pkg
    would swap policy 101: replace jds-NudgeSuite-2.1.4.81863.pkg with jds-NudgeSuite-2.1.5.81902.pkg
    would map jds-NudgeSuite-2.1.5.81902.pkg to patch title 201 version 2.1.5.81902
    would prune jds-NudgeSuite-2.1.3.81850.pkg (record and file)
zoom         current
```

It writes nothing to `Packages/`, Jamf, the state cache or the ownership record, skips start-of-run
recovery and sends no notification. It does use the scratch folder in staging for the download. The
exit code is 1 if any app failed.
