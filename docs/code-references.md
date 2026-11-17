# References in code comments

The code was built from a design spec and checked through several rounds of independent code
review. Comments and test names still cite them. The spec and review notes held details of the
environment the agent was first built for, so they are not published; this page maps the
references to the public docs.

| Comment says | Meaning | Read |
| --- | --- | --- |
| spec section 3, §3 | The per-app run flow (9 steps, 2 exits) | [How it works](how-it-works.md) |
| section 4 | The app catalogue (sources, Team IDs, triggers) | [`packages.example.json`](../packages.example.json) |
| section 5 | Configuration and secrets | [Configuration](configuration.md) |
| section 6 | Resolvers and `dmg_extract` | [Configuration](configuration.md), [How it works](how-it-works.md) |
| section 7, V1–V4 | Verification checks 1–5 and version rules | [How it works](how-it-works.md) |
| section 8 | Jamf Pro API calls, write order, policy edits, pruning | [How it works](how-it-works.md), [Install](install.md) (API role) |
| section 9 | Runtime: layout, CLI, lock, preflight, dry run, notifications | [Install](install.md), [Notifications](notifications.md) |
| section 10 | Setup Manager `policy` actions | [Setup Manager](setup-manager.md) |
| section 11, L0–L3 | Test levels: unit, local stubs, test Jamf Pro, production | [Testing](testing.md) |
| A1–A22 | Acceptance criteria; each has a named integration test in `tests/integration/test_l1_scenarios.py` | the tests themselves |
| D1–D16 | Design decisions (e.g. D1 standard library only, D6 skip-then-alert, D7 retention) | [How it works](how-it-works.md) |
| DECISIONS F…, Q…, OPEN_QUESTIONS Q… | Findings and answered questions recorded during the build | the comment itself states the rule |
| review #N, round N #M, `test_review_codex_*` | A finding from an independent review round; the test reproduces it | the test's docstring |
