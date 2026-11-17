"""Error types. Each carries the run step it failed in, for the Chat summary (spec section 9)."""


class SyncError(Exception):
    """An app-level failure. `step` names the pipeline step for notifications."""

    step = "error"

    def __init__(self, message, step=None):
        Exception.__init__(self, message)
        if step is not None:
            self.step = step


class ConfigError(SyncError):
    step = "config"


class SecretsError(SyncError):
    step = "secrets"


class ResolveError(SyncError):
    step = "resolve"


class NotUpstreamYet(ResolveError):
    """The target version is not downloadable yet. Not a failure: D6 skip-then-alert applies."""

    step = "resolve"


class VerifyError(SyncError):
    step = "verify"


class XarError(VerifyError):
    pass


class ToolError(SyncError):
    step = "tool"


class JamfError(SyncError):
    step = "jamf"

    def __init__(self, message, status=None, step=None):
        SyncError.__init__(self, message, step)
        self.status = status


class PolicyEditError(SyncError):
    step = "policy"
