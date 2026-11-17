# Testing

The tests use only the standard library's `unittest`; `pytest` can run them too but is not needed.
Nothing in the test suites contacts Jamf Pro, a vendor or a webhook.

## Unit tests

```
make test-unit
```

(or `python3 -m unittest discover -s tests/unit -t . -v`)

Version rules, resolvers against recorded responses, xar and pkg parsing, the signer check, Adobe
manifest parsing, policy XML edits, config and secrets validation, notification formats,
`label-import`, pruning selection, ownership records and more. A few tests are skipped unless a real
vendor pkg has been downloaded into `tests/fixtures/real/`.

## Integration tests

```
make test-int
```

(or `python3 -m unittest discover -s tests/integration -t . -v`)

These run the whole agent against local stand-ins, all standard-library HTTP servers on
`127.0.0.1`:

- a stateful **Jamf Pro stub** (OAuth tokens, packages, Classic API policies, patch titles);
- a **webhook stub** that records the messages;
- an **upstream stub** that serves synthetic signed pkgs in the shapes the real sources use (GitHub
  API and release pages, Adobe's manifest, redirecting "latest" URLs, a versioned URL template, a DMG).

Each test builds a temporary home with a `0600` secrets file, `Packages/` and staging on the same
filesystem, and signing certificates generated with `openssl` for each Team ID. Scenarios cover first
runs, no-change runs, new patch versions, a catalog ahead of the vendor, wrong Team IDs, corrupted
downloads, GitHub rate limiting, pins, pruning, concurrent runs, dry runs, interrupted runs and an
unreachable webhook. `openssl` must be on the `PATH`.

Two environment variables exist only for these tests and must never be set on a real server:

- `JDS_TEST_URL_MAP` redirects the vendors' HTTPS hosts to the local upstream stub.
- `JDS_TEST_FAULTS` switches on injected faults, for example `github_403`, `wrong_team`,
  `flip_byte`, `patch_ahead`, `template_404`, `dp_not_writable`, `staging_other_fs`, `no_7zz`,
  `lock_held` and `webhook_down`. Unknown names are rejected, and any active fault is logged as a
  warning on every run.

## Python 3.6

The agent must run on Python 3.6 with the standard library only, because that is the platform
Python of RHEL 8-family servers. A unit test checks this statically on any Python: it rejects
syntax and standard-library features newer than 3.6 and any import outside the standard library.

To prove it for real, run both suites on Python 3.6 itself. One way is a small Linux VM, for example
with [Lima](https://lima-vm.io) on a Mac:

- Rocky Linux 8 or another RHEL 8 rebuild, which ships Python 3.6;
- the repository mounted read-only;
- an unprivileged user with no `sudo`, as on the real server, with `Packages/` and staging on one
  filesystem and an ACL giving that user write access to `Packages/`;
- optionally Samba and SELinux set up as on your distribution point, to check that a published file
  is readable over SMB.

Then, as that user:

```
cd /path/to/jamf-dp-sync
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/unit -t .
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/integration -t .
```

`PYTHONDONTWRITEBYTECODE` keeps Python from trying to write into the read-only mount.

## Before production

Never point a first run at production. A safe order:

1. Unit and integration tests pass, on Python 3.6 if your server has it.
2. If you have a test Jamf Pro instance, run the agent against it with test-only objects: a separate
   API client, a test category, `name_prefix` values starting with something like `TEST-jds-`, and
   test policies scoped to a test Mac only. Use a separate config file (`--config`) and a separate
   webhook channel.
3. On the real server, `check-config`, `status`, `notify-test`, then `run --dry-run`, and read the
   output.
4. A real run for one app (`run --only <label>`), then an install test on a spare Mac on the build
   network.
5. The remaining apps, then the cron line, then the enrollment workflow change.

`run --dry-run` is safe to repeat at any time: it writes nothing to `Packages/`, Jamf or the cache
and sends no notification.
