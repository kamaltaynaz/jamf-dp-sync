"""The per-app run (spec section 3: 9 steps, 2 exits) and the run as a whole (section 9).

Exits: **Stop** (every policy already on the target: no download, no API writes) and **Fail closed**
(any check fails before the DP or Jamf is touched: alert, delete staged file). The fixed order of
section 8 is kept: file in Packages/ -> package record -> policy update -> title mapping.

One app's failure never stops the others. Monitor-only apps are deferred (OPEN_QUESTIONS Q15,
DECISIONS): `run` skips them with one log line.
"""
import datetime
import os
import re
import shutil
import tempfile

from jamf_dp_sync import (config, download, faults, ownership, prune, publish, resolvers, scratch,
                          verify, versions)
from jamf_dp_sync.errors import NotUpstreamYet, SyncError
from jamf_dp_sync.jamf import policy_xml
from jamf_dp_sync.jamf.client import AGENT_MARKER
from jamf_dp_sync.resolvers import github_tag

WRONG_TEAM = "ZZZZZZZZZZ"


class AppResult(object):
    """status: published | swapped | current | skipped | failed | dry-run | monitor-deferred"""

    def __init__(self, label, status, old=None, new=None, pkg=None, policies=None, step=None,
                 reason=None, alert=False, warnings=None, actions=None):
        self.label = label
        self.status = status
        self.old = old
        self.new = new
        self.pkg = pkg
        self.policies = policies or []
        self.step = step
        self.reason = reason
        self.alert = alert            # send a notification line for this result
        self.warnings = warnings or []
        self.actions = actions or []  # dry run: what would have happened

    @property
    def changed(self):
        return self.status in ("published", "swapped")

    def __repr__(self):
        return "AppResult(%s %s %s->%s %s)" % (self.label, self.status, self.old, self.new, self.reason or "")


class RunContext(object):
    def __init__(self, cfg, jamf, http, state, log, now=None, dry_run=False, no_prune=False,
                 github_token=None, owners=None):
        self.cfg = cfg
        self.jamf = jamf
        self.http = http
        self.state = state
        self.log = log
        self.now = now or datetime.datetime.now()
        self.dry_run = dry_run
        self.no_prune = no_prune
        self.github_token = github_token
        self.owners = owners or ownership.OwnershipStore(
            read_only=dry_run, anchor_dir=ownership.anchor_dir_for(cfg["staging_dir"], ownership.DEFAULT_PATH))


# ------------------------------------------------------------------ helpers

def bump(text):
    """patch_ahead fault: raise the last number in a version string by one (any rule's form)."""
    nums = list(re.finditer(r"\d+", text))
    if not nums:
        return text
    m = nums[-1]
    return text[:m.start()] + str(int(m.group()) + 1) + text[m.end():]


def _target(app, rule, ctx):
    """Section 3 step 2. Returns (Version, raw title text or None, source)."""
    if app.get("pin"):
        return rule.parse(app["pin"]), None, "pin"
    if app.get("patch_title_id") is not None:
        raw = ctx.jamf.latest_patch_version(app["patch_title_id"])
        if faults.on("patch_ahead"):
            raw = bump(raw)
        return rule.parse(raw), raw, "patch title"
    rctx = resolvers.Context(ctx.http, rule, github_token=ctx.github_token, log=ctx.log)
    v = github_tag.latest_version(app, rctx)
    return v, None, "release tag (no patch title)"


def _policy_state(app, rule, ctx):
    """[(policy_id, xml)] and the V4 current version from the first policy."""
    xmls = [(pid, ctx.jamf.get_policy_xml(pid)) for pid in app["policy_ids"]]
    current = policy_xml.current_version(xmls[0][1], app, rule)
    return xmls, current


def _on_target(current, target, pinned):
    """Section 3: a run writes only when the target is newer than what the policy holds. Only a pin
    asks for an exact version (rollback, D5); a catalog that moves backward never downgrades."""
    if current is None:
        return False
    return current == target if pinned else current >= target


def _all_policies_hold(xmls, regex, pkg_id, pkg_name, add_if_missing):
    return _hold(xmls, regex, pkg_id, pkg_name, add_if_missing)[0]


def _hold(xmls, regex, pkg_id, pkg_name, add_if_missing):
    """(every policy already holds the pkg, warnings for policies skipped by add_if_missing=false)."""
    holds, warnings = True, []
    for pid, x in xmls:
        plan = policy_xml.plan_swap(x, regex, pkg_id, pkg_name, add_if_missing)
        if plan.changed:
            holds = False
        if plan.warning:
            warnings.append("policy %s: %s" % (pid, plan.warning))
    return holds, warnings


def _skip(app, target, ctx, reason):
    """D6: skip, alert once older than alert_after_days, then once a day."""
    key = app["label"]
    st = ctx.state.load(key)
    today = ctx.now.date()
    if st.get("skip_target") != str(target) or not st.get("skip_since"):
        st["skip_target"], st["skip_since"] = str(target), today.isoformat()
    since = datetime.datetime.strptime(st["skip_since"], "%Y-%m-%d").date()
    days = (today - since).days
    alert = days >= app["alert_after_days"] and st.get("last_alert") != today.isoformat()
    if alert:
        st["last_alert"] = today.isoformat()
    st["last_result"] = "skipped: %s" % reason
    try:
        ctx.state.save(key, st)
    except (IOError, OSError) as e:
        ctx.log.warning("%s: could not update state cache: %s", key, e)
    return AppResult(key, "skipped", new=str(target), reason="%s (waiting %d day%s)" % (reason, days, "" if days == 1 else "s"),
                     alert=alert, step="resolve")


def _title_version_text(app, version, raw_target, target, ctx):
    """The definition string to map a pkg to (D15), or None when the title has no such version."""
    if raw_target is not None and version == target:
        return raw_target
    rule = versions.get_rule(app["version_rule"])
    for d in ctx.jamf.patch_definitions(app["patch_title_id"]):
        try:
            if rule.parse(d["version"]) == version:
                return d["version"]
        except ValueError:
            continue
    return None


# ------------------------------------------------------------------ one app

def run_app(app, ctx):
    label = app["label"]
    if app["mode"] == "monitor":
        ctx.log.info("%s: monitor-only apps are deferred (OPEN_QUESTIONS Q15); skipped", label)
        return AppResult(label, "monitor-deferred")

    cfg = ctx.cfg
    rule = versions.get_rule(app["version_rule"])
    regex = policy_xml.match_regex(app)
    prefix = app["name_prefix"]
    pinned = bool(app.get("pin"))

    # 1-2. target and "policy on target?"
    target, raw_target, source = _target(app, rule, ctx)
    xmls, current = _policy_state(app, rule, ctx)
    if current is not None:
        old = str(current)
    else:  # first run: name the legacy pkg being replaced, if any
        legacy = policy_xml.matching_names(xmls[0][1], regex)
        old = legacy[0] if legacy else None
    if not pinned and current is not None and current > target:
        # The first policy is ahead of the catalog: hold that version and bring the other policies to
        # it; never drag anything down without a pin (round-two review #1).
        target, raw_target, source = current, None, "policy ahead of %s" % source
    early = _finish_pruning(app, ctx)  # recorded unfinished prunes, on every path (round three #9)
    if _on_target(current, target, pinned):
        cur_id, cur_name = _current_entry(xmls[0][1], app, rule, current)
        holds, skipped = (_hold(xmls, regex, cur_id, cur_name, app["add_if_missing"])
                          if cur_id is not None else (False, []))
        if holds:
            # Stop exit. The only writes are steps an earlier run of ours recorded as still owed in
            # the ownership store (round three #5): title mapping and pruning.
            actions, warnings = _resume_todo(app, ctx, rule, cur_id, cur_name, current, raw_target, target)
            actions = early + actions
            warnings = skipped + warnings  # skipped policies are reported every run (round two #12)
            if not actions and not warnings:
                ctx.log.info("%s: on target %s (%s); nothing to do", label, target, source)
            status = "dry-run" if ctx.dry_run and actions else "current"
            return _done(app, ctx, AppResult(label, status, old=old, new=old, actions=actions,
                                             warnings=warnings, alert=bool(warnings)))

    # Ownership: recover interrupted publishes/prunes, then refuse unexplained agent-like names.
    records = ctx.jamf.list_packages()
    pre_actions = _reconcile_orphans(app, ctx, rule, records)
    if pre_actions and not ctx.dry_run:
        records = ctx.jamf.list_packages()
    clash = [n for n in prune.collisions(os.listdir(cfg["dp_packages_dir"]), records, app, rule)
             if not (ctx.dry_run and any(n in a for a in pre_actions))]
    if clash:
        raise SyncError("names look agent-made but have no marked record: %s" % ", ".join(clash[:3]),
                        step="preflight")

    # 3. already have the target (pin rollback, earlier partial run)? Re-verify before reuse.
    exact_source = pinned or app["resolver"] != "latest_redirect" or (current is not None and target == current)
    if exact_source:
        name = versions.published_name(prefix, rule, target)
        rec = _marked(records, name)
        path = os.path.join(cfg["dp_packages_dir"], name)
        here = ownership.presence(path)
        if here is None:
            raise SyncError("cannot check %s in Packages/" % name, step="preflight")
        if rec is not None and here:
            entry = ctx.owners.get(name)
            if not (entry and entry.get("state") == ownership.PUBLISHED and ctx.owners.owns(name, path, entry=entry)
                    and entry.get("sha512") == (rec.get("hashValue") or "").lower()):
                # Round four #1: a marked record is not proof the file is still ours.
                raise SyncError("retained %s in Packages/ is not the file this agent published; not reused, "
                                "check it by hand" % name, step="verify")
            _reverify_retained(app, ctx, rule, path, rec, target)
            ctx.log.info("%s: %s already published and re-verified; swapping policies only", label, name)
            return _finish(app, ctx, rule, regex, int(rec["id"]), name, target, raw_target, target, old,
                           published=False, actions=pre_actions)

    # 4. resolve
    rctx = resolvers.Context(ctx.http, rule, github_token=ctx.github_token, tools=cfg["tools"],
                             workdir=scratch_dir(cfg), log=ctx.log)
    try:
        res = resolvers.resolve(app, target, rctx)
    except NotUpstreamYet as e:
        return _skip(app, target, ctx, str(e))
    warnings = list(res.warnings)

    # 5. download + verify (a pin is always exact, whatever the source: review #5)
    cache = ctx.state.load(label) if app["resolver"] == "latest_redirect" else None
    fetched = download.fetch(app, res.url, scratch_dir(cfg), ctx.http, cfg["tools"], cache,
                             expected_size=res.expected_size, expected_sha256=res.expected_sha256)
    if fetched.not_modified:
        last = cache.get("pkg_version")
        try:
            last_v = rule.parse(last) if last else None
        except ValueError:  # a bad cache entry only costs a re-download (cache is safe to delete)
            last_v = None
        if last_v is not None and last_v < target and not pinned:
            return _skip(app, target, ctx, "upstream file unchanged since last run (still %s)" % last)
        fetched = download.fetch(app, res.url, scratch_dir(cfg), ctx.http, cfg["tools"], None,
                                 expected_size=res.expected_size, expected_sha256=res.expected_sha256)
    team = WRONG_TEAM if faults.on("wrong_team") else app["team_id"]
    try:
        on_pkg = not fetched.integrity_checked   # a DMG's size/hash were checked before extraction
        v = verify.verify_pkg(fetched.path, team, rule, target, res.exact or pinned,
                              expected_size=res.expected_size if on_pkg else None,
                              expected_sha256=res.expected_sha256 if on_pkg else None,
                              openssl=cfg.tool("openssl"))
    except NotUpstreamYet as e:
        if cache is not None:
            _state(ctx, label, url=fetched.url, etag=fetched.etag, last_modified=fetched.last_modified,
                   pkg_version=_stale_version(e))
        return _skip(app, target, ctx, str(e))
    if cache is not None:
        _state(ctx, label, url=fetched.url, etag=fetched.etag, last_modified=fetched.last_modified,
               pkg_version=str(v.version))
    name = versions.published_name(prefix, rule, v.version)

    # Latest-only source handed us what the policies already hold.
    rec = _marked(records, name)
    if (current is not None and v.version == current and rec is not None
            and _all_policies_hold(xmls, regex, int(rec["id"]), name, app["add_if_missing"])):
        os.unlink(v.path)
        return _done(app, ctx, AppResult(label, "current", old=old, new=old))

    if rec is not None and (rec.get("hashValue") or "").lower() != v.sha512:
        # Round four #3: never put new bytes under a record that carries another file's checksum.
        raise SyncError("%s: downloaded bytes differ from the SHA-512 in its existing package record "
                        "(the vendor rebuilt this version?); not published, check it by hand" % name,
                        step="verify")

    if ctx.dry_run:
        os.unlink(v.path)
        actions = pre_actions + ["publish %s (%s, SHA-256 %s)" % (name, _mb(v.size), v.sha256[:12])]
        if rec is None:
            actions.append("create package record %s" % name)
        return _finish(app, ctx, rule, regex, int(rec["id"]) if rec else None, name, v.version, raw_target,
                       target, old, published=True, actions=actions, warnings=warnings,
                       prospective=None if rec else name)

    # 6. publish. Ownership is "pending" (with the staged inode) until the link succeeds and
    # "published" after; an existing file is never claimed (rounds two #4, three #4/#8).
    # begin() records this attempt beside any existing entry and settle() resolves it, so a crash in
    # between never loses the earlier identity (round five #1).
    ctx.owners.begin(name, label, v.sha512, v.path)
    final = os.path.join(cfg["dp_packages_dir"], name)
    try:
        final, reused = publish.publish(v.path, cfg["dp_packages_dir"], name, v.sha512, cfg["dp_group"])
    except Exception:
        ctx.owners.settle(name, final)  # linked before the failure: kept, and adopted next run (r4 #4)
        raise
    outcome = ctx.owners.settle(name, final)
    if outcome != ("prior" if reused else "new"):
        raise SyncError("%s already exists in Packages/ and was not published by this agent; not claimed"
                        % name, step="publish")
    ctx.log.info("%s: %s %s", label, "reused" if reused else "published", final)
    # 7. record (never before the file is on disk)
    if rec is None:
        if any(r.get("packageName") == name for r in records):
            raise SyncError("a package record named %s exists without the agent marker" % name, step="record")
        pkg_id = ctx.jamf.create_package(name, name, app["category_id"], v.sha512)
    else:
        pkg_id = int(rec["id"])
    return _finish(app, ctx, rule, regex, pkg_id, name, v.version, raw_target, target, old,
                   published=not reused, warnings=warnings)


def _reverify_retained(app, ctx, rule, path, rec, target):
    """Review #3: a retained pkg is checked again (signer, version, digest vs its record) before reuse."""
    team = WRONG_TEAM if faults.on("wrong_team") else app["team_id"]
    want = (rec.get("hashValue") or "").lower()
    if (rec.get("hashType") or "").upper() != "SHA_512" or len(want) != 128:
        # Round two #8: without the digest recorded at publish time there is nothing to compare.
        raise SyncError("retained %s: its package record has no SHA-512; not reused"
                        % os.path.basename(path), step="verify")
    v = verify.verify_pkg(path, team, rule, target, True, openssl=ctx.cfg.tool("openssl"), discard=False)
    if want != v.sha512:
        raise SyncError("retained %s: SHA-512 differs from its package record; not reused"
                        % os.path.basename(path), step="verify")
    return v


def _reconcile_mapping(app, ctx, pkg_id, name, version, raw_target, target):
    """Review #11: when the policies already hold the pkg, make sure the title mapping exists too.
    Returns (dry-run actions, warnings, settled). `settled` is False only while the title has no
    such version yet, so the owed step is kept (round four #5). Reads only, unless mapping."""
    if app.get("patch_title_id") is None:
        return [], [], True
    text = _title_version_text(app, version, raw_target, target, ctx)
    if text is None:
        ctx.log.info("%s: patch title %s has no version %s yet; mapping still owed",
                     app["label"], app["patch_title_id"], version)
        return [], [], False
    title = ctx.jamf.patch_title(app["patch_title_id"])
    for m in title.get("packages") or []:
        if m.get("version") == text:
            return [], [], True  # mapped (to us, or left alone because another package holds it)
    # Round two #13: only for a pkg we own (marked record) whose file is on the DP.
    rec = ctx.jamf.find_package(name)
    path = os.path.join(ctx.cfg["dp_packages_dir"], name)
    if (rec is None or AGENT_MARKER not in (rec.get("notes") or "") or int(rec["id"]) != int(pkg_id)
            or not os.path.exists(path)):
        return [], ["%s: not mapped to patch title %s: its package record is not the agent's" % (name, app["patch_title_id"])], True
    # Round four #2: the bytes must still be the ones verified and recorded at publish time.
    if not ctx.owners.owns(name, path, digest=True) or (rec.get("hashValue") or "").lower() != ctx.owners.get(name).get("sha512"):
        raise SyncError("%s in Packages/ no longer matches what this agent published; not mapped, "
                        "check it by hand" % name, step="title-map")
    if ctx.dry_run:
        return ["map %s to patch title %s version %s (missing)" % (name, app["patch_title_id"], text)], [], True
    ctx.jamf.map_package_to_title(app["patch_title_id"], pkg_id, text)
    return [], ["patch title %s version %s mapping was missing; restored" % (app["patch_title_id"], text)], True


def _reconcile_orphans(app, ctx, rule, records):
    """A file in Packages/ with this app's agent name but no marked record is finished off only when
    the durable ownership store says so and its SHA-512 still matches (rounds one #10, two #4/#7):
      published -> create its record (a run stopped between the move and the record)
      pruning   -> delete the file (a run stopped between deleting the record and the file)
    pending entries and unknown files are left for the collision check to refuse."""
    marked = set(r["packageName"] for r in records if prune.is_agent_record(r, app, rule))
    entries = ctx.owners.load()
    done = []
    for n in sorted(os.listdir(ctx.cfg["dp_packages_dir"])):
        if n in marked or versions.version_from_published_name(n, app["name_prefix"], rule) is None:
            continue
        entry = entries.get(n)
        if not entry or entry.get("label") != app["label"] or entry.get("state") not in (
                ownership.PUBLISHED, ownership.PENDING):
            continue
        if any(r.get("packageName") == n for r in records):
            continue  # an unmarked record with that name: never adopt, let the collision check refuse
        path = os.path.join(ctx.cfg["dp_packages_dir"], n)
        # The very file we linked (inode recorded before the link) with the bytes we verified: a crash
        # between link and record, or between link and commit (round three #8). A same-named upload
        # has another inode and is never adopted (round three #4).
        if not ctx.owners.owns(n, path, digest=True, entry=entry):
            continue
        sha = entry["sha512"]
        if ctx.dry_run:
            done.append("adopt %s (published by an interrupted run): create its package record" % n)
            continue
        if entry["state"] == ownership.PENDING:
            ctx.owners.commit(n)
        ctx.jamf.create_package(n, n, app["category_id"], sha)
        ctx.owners.set_todo(n, ["map", "prune"])
        ctx.log.warning("%s: adopted %s left by an interrupted run", app["label"], n)
        done.append("adopted %s" % n)
    return done


def _current_entry(xml, app, rule, current):
    """(id, name) of the agent pkg in this policy whose version is `current`."""
    for pid, name, _ in policy_xml.packages(xml):
        if versions.version_from_published_name(name, app["name_prefix"], rule) == current:
            return pid, name
    return None, None


def _marked(records, name):
    for r in records:
        if r.get("packageName") == name and AGENT_MARKER in (r.get("notes") or ""):
            return r
    return None


def _stale_version(err):
    m = re.search(r"pkg is ([^\s,]+)", str(err))
    return m.group(1) if m else None


def _mb(n):
    return "%.1f MB" % (n / 1e6)


def _finish(app, ctx, rule, regex, pkg_id, name, version, raw_target, target, old, published,
            actions=None, warnings=None, prospective=None):
    """Steps 8-9: swap every policy (re-read just before its PUT: review #4), map to the title,
    prune, record state. In a dry run nothing is written and the same plans become actions."""
    label = app["label"]
    dry = ctx.dry_run
    actions = list(actions or [])
    warnings = list(warnings or [])
    changed = []
    pinned = bool(app.get("pin"))
    if not dry:  # what this transaction still owes, so an interruption can be resumed (round three #5)
        ctx.owners.set_todo(name, (["map"] if app.get("patch_title_id") is not None else [])
                            + ([] if ctx.no_prune else ["prune"]))
    for pid in app["policy_ids"]:
        xml = ctx.jamf.get_policy_xml(pid)
        held = policy_xml.current_version(xml, app, rule)
        if not pinned and held is not None and held > version:
            warnings.append("policy %s holds %s, newer than %s; not downgraded without a pin" % (pid, held, version))
            continue  # round two #1: never downgrade a policy without a pin
        plan = policy_xml.plan_swap(xml, regex, pkg_id if pkg_id is not None else 0, name, app["add_if_missing"])
        if plan.warning:
            warnings.append("policy %s: %s" % (pid, plan.warning))
            if dry:
                actions.append("leave policy %s: no matching package and add_if_missing is false" % pid)
        if plan.changed:
            if dry:
                what = ("add %s" % name) if plan.added else ("replace %s with %s" % (", ".join(plan.removed) or plan.replaced, name))
                actions.append("swap policy %s: %s" % (pid, what))
            else:
                plan, notes = _guarded_put(ctx, app, rule, regex, pid, xml, plan, pkg_id, name, version)
                warnings.extend(notes)
                if plan is not None:
                    changed.append(pid)
    if app.get("patch_title_id") is not None:
        text = _title_version_text(app, version, raw_target, target, ctx)
        if text is None:
            warnings.append("patch title %s has no version %s yet; not mapped (kept as owed)"
                            % (app["patch_title_id"], version))
        elif dry:
            actions.append("map %s to patch title %s version %s" % (name, app["patch_title_id"], text))
        else:
            try:
                outcome = ctx.jamf.map_package_to_title(app["patch_title_id"], pkg_id, text)
            except SyncError as e:
                raise SyncError("title mapping failed: %s" % e, step="title-map")
            if outcome.startswith("taken"):
                warnings.append("patch title %s version %s is already mapped, %s; left as is"
                                % (app["patch_title_id"], text, outcome))
        if not dry and text is not None:
            ctx.owners.done(name, "map")
    if not ctx.no_prune:
        a, w = _prune(app, ctx, rule, name, prospective=prospective)
        actions.extend(a)
        warnings.extend(w)
        if not dry:
            ctx.owners.done(name, "prune")
    if dry:
        return AppResult(label, "dry-run", old=old, new=str(version), pkg=name, policies=app["policy_ids"],
                         actions=actions, warnings=warnings)
    status = "published" if published else ("swapped" if changed else "current")
    st = {"last_result": status, "skip_since": None, "skip_target": None, "last_alert": None}
    if published:
        st["last_publish"] = ctx.now.date().isoformat()
    _state(ctx, label, **st)
    return AppResult(label, status, old=old, new=str(version), pkg=name, policies=changed or app["policy_ids"],
                     warnings=warnings, alert=bool(changed) or published)


def _pkg_signature(xml):
    """Every field of every <package> entry the PUT sends back (round three #3), in order."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml)
    pk = root.find("package_configuration/packages")
    if pk is None:
        return []
    return [tuple((c.tag, (c.text or "").strip()) for c in p) for p in pk.findall("package")]


def _guarded_put(ctx, app, rule, regex, pid, planned_from, plan, pkg_id, name, version):
    """Q20 (accepted risk + detection). The Classic API has no conditional PUT, so:
    1. re-read just before the PUT; if any package entry changed since the plan, re-plan from the
       fresh copy (keeping that edit), applying the same no-downgrade rule (round three #2) and
       reporting its warnings (round three #12);
    2. read back just after the PUT; if the entries differ from what was sent, someone was editing at
       the same moment and an edit may have been lost: warn in the Chat summary.
    Returns (plan actually sent or None, warnings)."""
    notes = []
    fresh = ctx.jamf.get_policy_xml(pid)
    if _pkg_signature(fresh) != _pkg_signature(planned_from):
        ctx.log.warning("%s: policy %s changed since it was read; re-planning", app["label"], pid)
        held = policy_xml.current_version(fresh, app, rule)
        if not app.get("pin") and held is not None and held > version:
            return None, ["policy %s holds %s, newer than %s; not downgraded without a pin" % (pid, held, version)]
        plan = policy_xml.plan_swap(fresh, regex, pkg_id, name, app["add_if_missing"])
        if plan.warning:
            notes.append("policy %s: %s" % (pid, plan.warning))
        if not plan.changed:
            return None, notes
    ctx.jamf.put_policy_xml(pid, plan.put_xml)
    after = ctx.jamf.get_policy_xml(pid)
    if _pkg_signature(after) != _pkg_signature(plan.put_xml):
        notes.append("policy %s: package list changed around this update (sent %s, now %s); "
                     "check it for a lost edit" % (pid, [n for _, n, _ in policy_xml.packages(plan.put_xml)],
                                                   [n for _, n, _ in policy_xml.packages(after)]))
    return plan, notes


def _referenced_ids(app, ctx):
    ids = set()
    for pid in app["policy_ids"]:
        ids.update(str(i) for i, _, _ in policy_xml.packages(ctx.jamf.get_policy_xml(pid)))
    return ids


def _finish_pruning(app, ctx):
    """Round three #9: finish prunes an earlier run recorded ("pruning") but did not complete. The file
    is deleted only if it is the very file recorded (inode), and only once its record is gone."""
    actions = []
    if ctx.no_prune:  # round four #6: the flag covers recorded prunes too; they stay owed
        return actions
    for n, entry in sorted(ctx.owners.load().items()):
        if entry.get("label") != app["label"] or entry.get("state") != ownership.PRUNING:
            continue
        if ctx.jamf.find_package(n) is not None:
            continue  # record not deleted yet: the next prune handles it in order
        path = os.path.join(ctx.cfg["dp_packages_dir"], n)
        if ctx.dry_run:
            actions.append("finish pruning %s" % n)
            continue
        ident = ctx.owners.identity_of(n, path, entry=entry)
        if ident is None:  # round nine #2: cannot tell now; keep the entry and finish on a later run
            ctx.log.warning("%s: cannot check %s now; pruning finished on a later run", app["label"], n)
            continue
        if ident:
            os.unlink(path)
        elif ownership.presence(path):
            ctx.log.warning("%s: %s is not the file this agent published; left in place", app["label"], n)
        ctx.owners.remove(n)
        ctx.log.warning("%s: finished pruning %s left by an interrupted run", app["label"], n)
    return actions


def _resume_todo(app, ctx, rule, pkg_id, name, version, raw_target, target):
    """Round three #5: on the Stop exit, resume only steps the ownership store records as owed for
    the pkg the policies hold, and only if that file is still the one we published (inode)."""
    entry = ctx.owners.get(name)
    todo = list((entry or {}).get("todo") or [])
    if not todo or entry.get("state") != ownership.PUBLISHED or not ctx.owners.owns(
            name, os.path.join(ctx.cfg["dp_packages_dir"], name), entry=entry):
        return [], []
    actions, warnings = [], []
    if "map" in todo:
        a, w, settled = _reconcile_mapping(app, ctx, pkg_id, name, version, raw_target, target)
        actions += a
        warnings += w
        if settled and not ctx.dry_run:
            ctx.owners.done(name, "map")
    if "prune" in todo and not ctx.no_prune:
        a, w = _prune(app, ctx, rule, name)
        actions += a
        warnings += w
        if not ctx.dry_run:
            ctx.owners.done(name, "prune")
    return actions, warnings


def _prune(app, ctx, rule, current_name, prospective=None):
    """Delete record first (Jamf removes it from every policy), then the file. The ownership entry is
    marked "pruning" before, so an interruption is finished by the next run (round two #14).
    `prospective`: in a dry run, the record the real run would create (round two #18)."""
    records = ctx.jamf.list_packages()
    if prospective:
        top = max([int(r["id"]) for r in records] + [0]) + 1
        records = records + [{"id": str(top), "packageName": prospective, "fileName": prospective,
                              "notes": AGENT_MARKER}]
    actions, warnings = [], []
    protected = _referenced_ids(app, ctx)  # never prune what a target policy still holds (round three #1)
    for rec in prune.plan_prune(records, app, rule, current_name, app["retain"], protected):
        n = rec["packageName"]
        path = os.path.join(ctx.cfg["dp_packages_dir"], n)
        entry = ctx.owners.get(n)
        here = ownership.presence(path)
        if here is None or (here and ctx.owners.identity_of(n, path, entry=entry) is not True):
            # Round four #1: the file under that name is not the one we published (replaced, or
            # never recorded). Leave record and file alone and say so.
            warnings.append("not pruned %s: the file in Packages/ is not provably the one this agent published "
                            "(or could not be checked); "
                            "check it by hand" % n)
            continue
        if ctx.dry_run:
            actions.append("prune %s (record and file)" % n)
            continue
        ctx.owners.pruning(n)
        ctx.jamf.delete_package(int(rec["id"]))
        ident = ctx.owners.identity_of(n, path)   # re-checked just before the unlink
        if ident is None:  # round nine #2: keep the "pruning" entry; a later run finishes it
            warnings.append("pruned record %s; its file could not be checked and is left for a later run" % n)
            continue
        if ident:
            os.unlink(path)
        elif ownership.presence(path):
            warnings.append("pruned record %s but left its file: it changed during the prune" % n)
        ctx.owners.remove(n)
        ctx.log.info("%s: pruned %s", app["label"], n)
    return actions, warnings


def _state(ctx, key, **changes):
    """The cache is safe to lose; a failed write must never escape the per-app boundary (review #16)."""
    try:
        ctx.state.update(key, **changes)
    except (IOError, OSError) as e:
        ctx.log.warning("%s: could not update state cache: %s", key, e)


def _done(app, ctx, result):
    if result.status != "dry-run":
        _state(ctx, app["label"], last_result=result.status, skip_since=None, skip_target=None)
    return result


# ------------------------------------------------------------------ the run

SCRATCH = scratch.NAME


def scratch_dir(cfg):
    """Every download, manifest and extraction goes into `<staging_dir>/.jds-scratch/` (round seven
    #1), validated before every use (round eight #1): see jamf_dp_sync/scratch.py."""
    return scratch.ensure(cfg["staging_dir"], cfg["dp_packages_dir"])


def recover(cfg, log, owners=None):
    """Start of every real run, under the run lock and before the free-space check (so reclaimed
    space counts). Dry runs skip it.
    1. Empty `<staging>/.jds-scratch/` (round six #1, seven #1): only if it is a real directory owned
       by this user, and only when staging is outside the share. Nothing else in staging is touched.
    2. Ownership sweep (round five #2), only when Packages/ is a readable, searchable directory; the
       sweep itself treats any error other than "no such file" as unknown and keeps the evidence
       (round seven #2).
    Failures are logged and never stop the run; preflight and the apps report real problems."""
    staging, dp = cfg["staging_dir"], cfg["dp_packages_dir"]
    sdir = scratch.path_for(staging)
    try:
        if (os.path.lexists(sdir) and not scratch.problem(staging, dp)
                and not config.staging_problems(dp, staging, resolve=True)):
            for n in sorted(os.listdir(sdir)):
                p = os.path.join(sdir, n)
                if os.path.isdir(p) and not os.path.islink(p):
                    shutil.rmtree(p)
                else:
                    os.unlink(p)
                log.warning("removed %s left in staging by an interrupted run", n)
    except (IOError, OSError) as e:
        log.error("staging recovery failed: %s", e)
    try:
        owners = owners or ownership.OwnershipStore(
            anchor_dir=ownership.anchor_dir_for(staging, ownership.DEFAULT_PATH))
        if os.path.isdir(dp) and os.access(dp, os.R_OK | os.X_OK):
            owners.sweep(dp)
        else:
            log.warning("ownership sweep skipped: %s is not accessible", dp)
    except Exception as e:  # each app meets the same store and reports it
        log.error("ownership sweep failed: %s", e)


def run_apps(apps, ctx):
    results = []
    for app in apps:
        try:
            results.append(run_app(app, ctx))
        except SyncError as e:
            ctx.log.error("%s: %s failed: %s", app["label"], e.step, e)
            _cleanup_staging(app, ctx)
            _state(ctx, app["label"], last_result="failed: %s: %s" % (e.step, e))
            results.append(AppResult(app["label"], "failed", step=e.step, reason=str(e), alert=True))
        except Exception as e:  # per-app isolation: a bug in one app never stops the others
            ctx.log.exception("%s: unexpected error", app["label"])
            _cleanup_staging(app, ctx)
            results.append(AppResult(app["label"], "failed", step="internal",
                                     reason="%s: %s" % (type(e).__name__, e), alert=True))
    return results


def _cleanup_staging(app, ctx):
    d = scratch.path_for(ctx.cfg["staging_dir"])
    if scratch.problem(ctx.cfg["staging_dir"], ctx.cfg["dp_packages_dir"]):
        return  # round eight #1: never clean through an unsafe scratch folder
    try:
        for n in os.listdir(d):
            if n.startswith(app["label"] + "-"):
                p = os.path.join(d, n)
                shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.unlink(p)
    except OSError:
        pass
