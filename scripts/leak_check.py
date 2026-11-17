#!/usr/bin/env python3
"""Fail if the repository contains something that looks like a real secret.

    python3 scripts/leak_check.py [--deny-file FILE] [PATH]

Scans every file under PATH (default: the repository root), skipping .git. Finds private keys,
GitHub and Slack tokens, filled-in Google Chat / Slack / Teams webhook URLs, and AWS access keys.
The test suite's fake values (short, obviously fake) do not match. With --deny-file, also fails on
any line of FILE found in a file (case-insensitive; '#' lines are comments): use it to keep your own
host names and organisation names out of a fork. Exit 1 and list the hits when anything matches.
"""
import argparse
import os
import re
import sys

PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("Slack token", re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{20,}")),
    ("Slack webhook", re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Google Chat webhook", re.compile(r"chat\.googleapis\.com/v1/spaces/\S*?[?&](?:key|token)=[A-Za-z0-9_%-]{30,}")),
    # A filled-in credential: KEY=value, "KEY": "value", KEY: value. Placeholders (<...>, %s, $VAR)
    # and values that say they are fake (see FAKE) are skipped.
    ("filled-in secret", re.compile(r"\b(?:JAMF_CLIENT_SECRET|JAMF_CLIENT_ID|GITHUB_TOKEN)[\"']?"
                                    r"\s*[=:]\s*[\"']?(?P<v>(?![<%$])(?:\\[/\\]|[^\s\"'<>\\,}(){}\[\]]){12,})"
                                    r"(?=[\s\"',}]|\\n|$)")),
    ("Teams webhook", re.compile(r"(?:logic\.azure\.com|powerplatform\.com|webhook\.office\.com)[^\s\"']*(?:sig=|/IncomingWebhook/)[A-Za-z0-9%_-]{30,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]
# A value is a test fake or placeholder when one of its words (split on - _ . :) is one of these;
# a random credential that merely contains such letters (…dTeSt9…) is not exempt.
FAKE_WORDS = {"test", "tests", "fake", "stub", "smoke", "example", "dummy", "placeholder", "changeme",
              "s3cr3t", "secret", "redacted", "your", "here", "xxx", "xxxx", "sample", "l1", "l1test"}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}
MAX_BYTES = 5 * 1024 * 1024


_EXPR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")


def _fake(match):
    """True for values that are not credentials: placeholders, fakes, and code expressions such as
    settings.jamf_client_id or os.environ.get (...)."""
    v = match.groupdict().get("v")
    if not v:
        return False
    if _EXPR.fullmatch(v):
        return True
    words = [w.lower() for w in re.split(r"[-_.:]+", v) if w]
    return any(w in FAKE_WORDS for w in words) or bool(re.fullmatch(r"x+", v.lower()))


def load_deny(path):
    with open(path) as f:
        return [l.strip().lower() for l in f if l.strip() and not l.lstrip().startswith("#")]


def shown(rel, deny):
    """The path as printed: secret-shaped parts and denied terms replaced, so the report itself
    never repeats what it found."""
    for _, rx in PATTERNS:
        rel = rx.sub("<redacted>", rel)
    for term in deny:
        rel = re.sub(re.escape(term), "<redacted>", rel, flags=re.I)
    return rel


def scan(root, deny=()):
    hits = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            for what, rx in PATTERNS:
                if rx.search(rel):
                    hits.append((shown(rel, deny), 0, what + " in file name"))
            for term in deny:
                if term in rel.lower():
                    hits.append((shown(rel, deny), 0, "denied term in file name"))
            rel = shown(rel, deny)
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    continue
                with open(path, "rb") as f:
                    text = f.read().decode("utf-8", "replace")
            except (IOError, OSError):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                for what, rx in PATTERNS:
                    if any(not _fake(m) for m in rx.finditer(line)):
                        hits.append((rel, n, what))
                low = line.lower()
                for term in deny:
                    if term in low:
                        hits.append((rel, n, "denied term"))
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--deny-file")
    args = ap.parse_args(argv)
    deny = load_deny(args.deny_file) if args.deny_file else []
    hits = scan(args.path, deny)
    for rel, n, what in hits:
        # Never print the matching text: it may be the secret.
        print("%s:%d: %s" % (rel, n, what))
    print("leak check: %s (%d finding%s)" % ("FAILED" if hits else "clean", len(hits), "" if len(hits) == 1 else "s"))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
