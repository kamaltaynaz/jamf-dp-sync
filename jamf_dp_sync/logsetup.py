"""Logging (spec section 9): rotating file 10 x 5 MB, secrets redacted from every formatted record."""
import logging
import logging.handlers
import os

from jamf_dp_sync import secrets

LOGGER = "jamf_dp_sync"


class RedactingFormatter(logging.Formatter):
    """Redacts the fully formatted record, traceback included (review #15)."""

    def format(self, record):
        return secrets.redact(logging.Formatter.format(self, record))


def setup(log_file=None, verbose=False, stream=True):
    """Build the new handlers first and swap them in only on success, so a log file that cannot be
    opened leaves the previous (bootstrap) handlers in place to report it (round three #11)."""
    log = logging.getLogger(LOGGER)
    fmt = RedactingFormatter("%(asctime)s %(levelname)s %(message)s")
    handlers = []
    if log_file:
        d = os.path.dirname(log_file)
        if d and not os.path.isdir(d):
            os.makedirs(d, 0o700)
        fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=9)
        fh.setFormatter(fmt)
        handlers.append(fh)
    if stream:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        handlers.append(sh)
    for h in log.handlers:
        h.close()
    log.handlers = handlers
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.propagate = False
    return log
