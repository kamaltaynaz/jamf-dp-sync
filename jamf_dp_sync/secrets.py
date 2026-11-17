"""Secrets (spec section 5).

Every secret is read through `get_secret`. Swapping the env file for a 1Password service account
(`op read ...`) later means changing `_load_source` only.

The env file must be a regular file owned by the current user and not readable or writable by group
or others; the agent refuses to start otherwise.
"""
import os
import stat

from jamf_dp_sync.errors import SecretsError

DEFAULT_ENV_FILE = "~/.config/jamf-dp-sync/env"
KNOWN_KEYS = ("JAMF_URL", "JAMF_CLIENT_ID", "JAMF_CLIENT_SECRET", "GITHUB_TOKEN", "WEBHOOK_URL", "WEBHOOK_KIND",
              "GCHAT_WEBHOOK_URL")   # GCHAT_WEBHOOK_URL: older name for WEBHOOK_URL, still read
NOT_SECRET = ("WEBHOOK_KIND",)   # a setting kept here so startup-failure alerts need no config; never redacted

_values = None
_runtime = set()  # values learned at run time (bearer tokens) that must be redacted too


def check_permissions(path):
    try:
        st = os.stat(path)
    except OSError as e:
        raise SecretsError("secrets file %s: %s" % (path, e.strerror))
    if not stat.S_ISREG(st.st_mode):
        raise SecretsError("secrets file %s is not a regular file" % path)
    if st.st_mode & 0o077:
        raise SecretsError("secrets file %s is mode %04o; it must not be readable by group or others (chmod 600)"
                           % (path, stat.S_IMODE(st.st_mode)))
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise SecretsError("secrets file %s is not owned by the current user" % path)


def parse_env(text):
    values = {}
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SecretsError("secrets file line %d is not KEY=VALUE" % n)
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key not in KNOWN_KEYS:
            # Never quote the input: a mistyped line may itself be a secret (round three #10).
            raise SecretsError("secrets file line %d: unknown key (expected one of %s)" % (n, ", ".join(KNOWN_KEYS)))
        values[key] = value
    return values


def _load_source(path):
    check_permissions(path)
    with open(path, "rb") as f:
        return parse_env(f.read().decode("utf-8"))


def init(path=None):
    """Load secrets once at start-up. Raises SecretsError on any problem."""
    global _values
    _values = _load_source(os.path.expanduser(path or DEFAULT_ENV_FILE))


def get_secret(name, required=True):
    """The only way the agent reads a secret."""
    if name not in KNOWN_KEYS:
        raise SecretsError("unknown secret %r" % name)
    if _values is None:
        raise SecretsError("secrets not initialised")
    value = _values.get(name, "")
    if required and not value:
        raise SecretsError("secret %s is empty or missing" % name)
    return value or None


def add_runtime_secret(value):
    """Register a secret obtained at run time (e.g. a Jamf bearer token) for redaction."""
    if value and len(value) >= 8:
        _runtime.add(value)


def redact(text):
    """Replace every loaded or runtime secret value in `text` with '***' (for logs and messages)."""
    if not text:
        return text
    values = set(v for k, v in (_values or {}).items() if v and len(v) >= 4 and k not in NOT_SECRET) | _runtime
    for value in sorted(values, key=len, reverse=True):
        text = text.replace(value, "***")
    return text


def _reset_for_tests(values=None):
    global _values
    _values = values
    _runtime.clear()


def webhook():
    """(url, kind) for notifications: WEBHOOK_URL, else the older GCHAT_WEBHOOK_URL; kind from
    WEBHOOK_KIND (None = detect from the URL). Either may be None."""
    url = get_secret("WEBHOOK_URL", required=False) or get_secret("GCHAT_WEBHOOK_URL", required=False)
    return url, get_secret("WEBHOOK_KIND", required=False)
