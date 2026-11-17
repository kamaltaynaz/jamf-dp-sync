"""Single instance (spec section 9): a non-blocking flock on lock_file.

A second run finds the lock held, logs one line and exits 0 (A11).
"""
import errno
import fcntl
import os

from jamf_dp_sync import faults


class RunLock(object):
    def __init__(self, path):
        self.path = path
        self._fd = None

    def acquire(self):
        """True if this process now holds the lock, False if another run holds it."""
        if faults.on("lock_held"):
            return False
        d = os.path.dirname(self.path)
        if d and not os.path.isdir(d):
            os.makedirs(d, 0o700)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError) as e:
            os.close(fd)
            if e.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                return False
            raise
        os.ftruncate(fd, 0)
        os.write(fd, ("%d\n" % os.getpid()).encode("ascii"))
        self._fd = fd
        return True

    def release(self):
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()
