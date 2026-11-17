# Commands

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
