"""`jamf-dp-sync run` and `status` (spec section 9): lock, preflight, per-app pipeline, one Chat
message per run, the Monday heartbeat, and the exit code (1 if any app failed)."""
import datetime
import sys

from jamf_dp_sync import faults, notify, pipeline, preflight, secrets, versions
from jamf_dp_sync.httpclient import HttpClient
from jamf_dp_sync.jamf import policy_xml
from jamf_dp_sync.jamf.client import JamfClient
from jamf_dp_sync.lock import RunLock
from jamf_dp_sync.state import StateStore

CLOSED_PORT_WEBHOOK = "http://127.0.0.1:9/v1/spaces/FAULT/messages?key=x&token=y"


def _select(cfg, only):
    if not only:
        return list(cfg.apps)
    unknown = sorted(set(only) - set(a["label"] for a in cfg.apps))
    if unknown:
        raise ValueError("unknown label(s) for --only: %s" % ", ".join(unknown))
    return [a for a in cfg.apps if a["label"] in only]


def _webhook():
    """(url, kind) for notify.send."""
    if faults.on("webhook_down"):
        return CLOSED_PORT_WEBHOOK, None
    return secrets.webhook()


def _lines(results):
    lines = []
    for r in results:
        if r.status in ("published", "swapped"):
            lines.append(notify.ok_line(r.label, r.old, r.new, r.policies))
        elif r.status == "failed":
            lines.append(notify.fail_line(r.label, r.step, r.reason))
        elif r.status == "skipped" and r.alert:
            lines.append(notify.warn_line(r.label, "%s %s not fetchable: %s" % ("target", r.new, r.reason)))
        if r.changed or (r.alert and r.status == "current"):
            lines.extend(notify.warn_line(r.label, w) for w in r.warnings)
    return lines


def _heartbeat(cfg, results, store, now):
    """First run each Monday (ISO week): apps current and last publish date per app."""
    if now.weekday() != 0:
        return []
    week = "%d-W%02d" % now.isocalendar()[:2]
    run = store.load("_run")
    if run.get("heartbeat_week") == week:
        return []
    try:  # the cache is disposable; never let it suppress the run's notification (review 2 #16)
        store.update("_run", heartbeat_week=week)
    except (IOError, OSError):
        pass
    ok = [r.label for r in results if r.status in ("current", "published", "swapped")]
    sync = [a["label"] for a in cfg.apps if a["mode"] == "sync"]
    out = ["*Heartbeat* %d/%d apps current" % (len(ok), len(sync))]
    for label in sync:
        out.append("       %-8s last publish %s" % (label, store.load(label).get("last_publish", "never")))
    return out


def cmd_run(cfg, args, log, now=None, out=None):
    now = now or datetime.datetime.now()
    out = out or sys.stdout
    active = sorted(faults.active())
    if active:
        log.warning("TEST FAULTS ACTIVE: %s", ", ".join(active))
    lock = RunLock(cfg["lock_file"])
    if not lock.acquire():
        log.info("another jamf-dp-sync run holds %s; exiting", cfg["lock_file"])
        return 0
    http = HttpClient()
    if active:
        prefixes = [a["url_template"].split("{version}")[0] for a in cfg.apps if a.get("resolver") == "url_template"]
        http = faults.FaultyHttp(http, prefixes)
    try:
        apps = _select(cfg, args.only)
        if not args.dry_run:
            pipeline.recover(cfg, log)  # rounds five #2, six #1: leftovers of interrupted runs first
        problems = preflight.check(cfg, apps)
        if problems:
            for p in problems:
                log.error("preflight: %s", p)
            if not args.dry_run:
                text = notify.build_message(["*FAIL* preflight: %s" % "; ".join(problems)], now)
                url, kind = _webhook()
                notify.send(text, url, http, log=log, kind=kind)
            return 1
        store = StateStore(read_only=args.dry_run)
        jamf = JamfClient(secrets.get_secret("JAMF_URL"), secrets.get_secret("JAMF_CLIENT_ID"),
                          secrets.get_secret("JAMF_CLIENT_SECRET"), http, log=log)
        ctx = pipeline.RunContext(cfg, jamf, http, store, log, now=now, dry_run=args.dry_run,
                                  no_prune=args.no_prune,
                                  github_token=secrets.get_secret("GITHUB_TOKEN", required=False))
        try:
            results = pipeline.run_apps(apps, ctx)
        finally:
            jamf.invalidate()
        for r in results:
            log.info("%s: %s %s", r.label, r.status, r.reason or "")
        if args.dry_run:
            for r in results:
                out.write(secrets.redact("%-12s %-16s %s\n" % (r.label, r.status, r.reason or "")))
                for a in r.actions:
                    out.write(secrets.redact("    would %s\n" % a))
                for w in r.warnings:
                    out.write(secrets.redact("    warning: %s\n" % w))
            return 1 if any(r.status == "failed" for r in results) else 0
        lines = _lines(results) + _heartbeat(cfg, results, store, now)
        if lines:
            url, kind = _webhook()
            notify.send(notify.build_message(lines, now), url, http, log=log, kind=kind)
        return 1 if any(r.status == "failed" for r in results) else 0
    finally:
        lock.release()


def cmd_status(cfg, args, log, out=None):
    """Per app: policy version, patch version, last result."""
    out = out or sys.stdout
    http = HttpClient()
    jamf = JamfClient(secrets.get_secret("JAMF_URL"), secrets.get_secret("JAMF_CLIENT_ID"),
                      secrets.get_secret("JAMF_CLIENT_SECRET"), http, log=log)
    store = StateStore(read_only=True)
    out.write("%-12s %-8s %-22s %-22s %s\n" % ("app", "mode", "policy version", "patch version", "last result"))
    try:
        for app in _select(cfg, args.only):
            rule = versions.get_rule(app["version_rule"])
            try:
                xml = jamf.get_policy_xml(app["policy_ids"][0])
                if app["mode"] == "sync":
                    pv = policy_xml.current_version(xml, app, rule)
                else:
                    pv = policy_xml.monitor_version(xml, app["replace_regex"], rule)
                patch = jamf.latest_patch_version(app["patch_title_id"]) if app.get("patch_title_id") else "n/a (no patch title)"
            except Exception as e:  # status is read-only and best effort per app
                pv, patch = "error", type(e).__name__
            out.write(secrets.redact("%-12s %-8s %-22s %-22s %s\n" % (
                app["label"], app["mode"], pv or "legacy/none", patch,
                store.load(app["label"]).get("last_result", "-"))))
    finally:
        jamf.invalidate()
    return 0
