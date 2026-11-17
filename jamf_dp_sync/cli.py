"""Command line interface (spec section 9).

    jamf-dp-sync [--config PATH] run [--only LABEL ...] [--dry-run] [--no-prune] [-v]
    jamf-dp-sync [--config PATH] check-config
    jamf-dp-sync [--config PATH] status [--only LABEL ...]
    jamf-dp-sync [--config PATH] notify-test
    jamf-dp-sync label-import --installomator PATH LABEL [LABEL ...]
"""
import argparse
import datetime
import sys

from jamf_dp_sync import config, logsetup, notify, runner, secrets
from jamf_dp_sync.errors import SyncError
from jamf_dp_sync.httpclient import HttpClient


def build_parser():
    ap = argparse.ArgumentParser(prog="jamf-dp-sync")
    ap.add_argument("--config", default=None, help="packages.json (default %s)" % config.DEFAULT_CONFIG)
    sub = ap.add_subparsers(dest="command")
    run = sub.add_parser("run", help="sync all apps")
    run.add_argument("--only", nargs="+", metavar="LABEL")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--no-prune", action="store_true")
    run.add_argument("-v", "--verbose", action="store_true")
    sub.add_parser("check-config", help="validate packages.json and the secrets file")
    st = sub.add_parser("status", help="per app: policy version, patch version, last result")
    st.add_argument("--only", nargs="+", metavar="LABEL")
    li = sub.add_parser("label-import", help="draft packages.json entries from Installomator labels")
    li.add_argument("--installomator", required=True, metavar="PATH", help="a local Installomator.sh")
    li.add_argument("labels", nargs="+", metavar="LABEL")
    sub.add_parser("notify-test", help="post a test message to the configured webhook (Google Chat, Slack or Teams)")
    return ap


def cmd_check_config(args, log):
    secrets.init()                  # first, so a config error naming a secret is redacted (round three #10)
    cfg = config.load(args.config)
    for key in ("JAMF_URL", "JAMF_CLIENT_ID", "JAMF_CLIENT_SECRET"):
        secrets.get_secret(key)
    from jamf_dp_sync.httpclient import credential_url_problem
    from jamf_dp_sync.errors import SecretsError
    problem = credential_url_problem(secrets.get_secret("JAMF_URL"), "JAMF_URL")
    if problem:
        raise SecretsError(problem)
    if not secrets.get_secret("GITHUB_TOKEN", required=False):
        log.warning("GITHUB_TOKEN is empty")
    url, kind = secrets.webhook()
    if not url:
        log.warning("WEBHOOK_URL is empty: no notifications")
    else:
        from jamf_dp_sync.errors import SecretsError
        from jamf_dp_sync.httpclient import credential_url_problem
        problem = credential_url_problem(url, "WEBHOOK_URL")
        if problem:
            raise SecretsError(problem)
        try:
            print("notifications: %s" % notify.detect_kind(url, kind))
        except ValueError as e:
            raise SecretsError(str(e))
    sync = [a["label"] for a in cfg.apps if a["mode"] == "sync"]
    mon = [a["label"] for a in cfg.apps if a["mode"] == "monitor"]
    print("config OK: %s" % cfg.path)
    print("  sync:    %s" % ", ".join(sync))
    print("  monitor: %s" % (", ".join(mon) or "none"))
    return 0


def cmd_notify_test(args, log):
    secrets.init()
    url, kind = secrets.webhook()
    if not url:
        print("notify-test: no WEBHOOK_URL in the secrets file")
        return 1
    now = datetime.datetime.now()
    text = notify.build_message(["notify-test: if you can read this, the webhook works."], now)
    ok = notify.send(text, url, HttpClient(), log=log, kind=kind)
    print("notify-test: %s" % ("sent" if ok else "FAILED (see log)"))
    return 0 if ok else 1


def cmd_label_import(args, out=None, err=None):
    """Print the drafted entries as JSON (stdout) and what to check per label (stderr). Needs no
    secrets or config. Exit 1 if any label could not be drafted."""
    import json
    from jamf_dp_sync import label_import
    out, err = out or sys.stdout, err or sys.stderr
    with open(args.installomator, "rb") as f:
        text = f.read().decode("utf-8", "replace")
    entries, ok = [], True
    for label in args.labels:
        try:
            d = label_import.draft(text, label)
        except label_import.LabelError as e:
            d = {"status": "missing", "entry": None, "notes": [str(e)]}
        err.write("%s: %s\n" % (label, d["status"]))
        for n in d["notes"]:
            err.write("  - %s\n" % n)
        if d["entry"]:
            entries.append(d["entry"])
        else:
            ok = False
    json.dump(entries, out, indent=2)
    out.write("\n")
    return 0 if ok else 1


BOOTSTRAP_LOG = "~/logs/jamf-dp-sync.log"


def _startup_failure(args, err, log, secrets_ok):
    """Review #17 and round 2 #10/#11/#17: under cron stdout/stderr go to /dev/null, so a startup
    error goes to the bootstrap log file. Details are logged only when the secrets are loaded (so
    redaction knows them); a dry run never posts to Chat."""
    from jamf_dp_sync.errors import SecretsError
    if secrets_ok or isinstance(err, SecretsError):
        log.error("startup: %s", err)
    else:
        log.error("startup: configuration invalid (details withheld: secrets unavailable for redaction; "
                  "run 'jamf-dp-sync check-config' interactively)")
    if args.dry_run or not secrets_ok:
        return 1
    try:
        now = datetime.datetime.now()
        text = notify.build_message(["*FAIL* startup: %s" % str(err).splitlines()[0]], now)
        url, kind = secrets.webhook()
        notify.send(text, url, HttpClient(), log=log, kind=kind)
    except SyncError as e2:
        log.error("startup: could not notify: %s", e2)
    return 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    log = logsetup.setup(verbose=getattr(args, "verbose", False))
    if args.command is None:
        build_parser().print_help()
        return 2
    try:
        if args.command == "label-import":
            return cmd_label_import(args)
        if args.command == "check-config":
            return cmd_check_config(args, log)
        if args.command == "notify-test":
            return cmd_notify_test(args, log)
        if args.command == "run":
            import os
            log = logsetup.setup(os.path.expanduser(BOOTSTRAP_LOG), verbose=args.verbose)
            secrets_err = None
            try:
                secrets.init()          # first, so every later log line can be redacted
            except SyncError as e:
                secrets_err = e
            try:
                cfg = config.load(args.config)
            except SyncError as e:
                return _startup_failure(args, e, log, secrets_err is None)
            if secrets_err is not None:
                return _startup_failure(args, secrets_err, log, False)
            try:
                log = logsetup.setup(cfg["log_file"], verbose=args.verbose)
            except (IOError, OSError) as e:  # bootstrap handlers are still in place (round three #11)
                log.error("startup: cannot open log file %s: %s", cfg["log_file"], e.strerror or e)
                return 1
            return runner.cmd_run(cfg, args, log)
        secrets.init()
        cfg = config.load(args.config)
        if args.command == "status":
            return runner.cmd_status(cfg, args, log)
        return 2
    except SyncError as e:
        log.error("%s: %s", e.step, e)
        return 1
    except ValueError as e:  # e.g. an unknown --only label or JDS_TEST_FAULTS name
        log.error("%s", e)
        return 2
