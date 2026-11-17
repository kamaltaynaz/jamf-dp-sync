"""Pruning selection and the name-collision preflight (spec D7, section 8 "Pruning risk").

Tightened at the owner's request (OPEN_QUESTIONS Q6, answered 2026-11-09): a package counts as
agent-created only when BOTH
  * its name is `<name_prefix>-<version>.pkg` with a version the app's rule parses, and
  * its Jamf package record's `notes` carry AGENT_MARKER, written when the agent created it.
Pruning keeps the current version plus the `retain` newest agent records by record ID, deletes the
record first and then the file (Jamf does not delete files from file share DPs), and never looks at
anything else. The preflight refuses to run an app if a file on the DP matches its name pattern
without a marked record, so a hand-uploaded pkg can never be mistaken for the agent's.

Pure functions: the caller supplies the records (from the Jamf API) and the file names (from the DP).
"""
from jamf_dp_sync.jamf.client import AGENT_MARKER
from jamf_dp_sync.versions import version_from_published_name


def _is_agent_name(name, app, rule):
    return version_from_published_name(name, app["name_prefix"], rule) is not None


def is_agent_record(record, app, rule):
    name = record.get("packageName") or ""
    return (_is_agent_name(name, app, rule)
            and record.get("fileName") == name
            and AGENT_MARKER in (record.get("notes") or ""))


def collisions(file_names, records, app, rule):
    """Names on the DP (or in Jamf) that look agent-made but have no marked record. Must be empty."""
    marked = set(r["packageName"] for r in records if is_agent_record(r, app, rule))
    seen = set(n for n in file_names if _is_agent_name(n, app, rule))
    seen.update(r.get("packageName") or "" for r in records if _is_agent_name(r.get("packageName") or "", app, rule))
    return sorted(seen - marked)


def plan_prune(records, app, rule, current_name, retain, protected_ids=()):
    """Return the agent records to delete (newest-by-ID first is kept), never the current one and
    never one a target policy still references (round three #1)."""
    if retain < 1:
        raise ValueError("retain must be >= 1")
    protected = set(str(i) for i in protected_ids)
    mine = [r for r in records if is_agent_record(r, app, rule)]
    mine.sort(key=lambda r: int(r["id"]), reverse=True)
    keep = set(r["packageName"] for r in mine[:retain])
    keep.add(current_name)
    return [r for r in mine if r["packageName"] not in keep and str(r["id"]) not in protected]
