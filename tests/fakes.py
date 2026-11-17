"""Test doubles: a recorded-response HTTP client and a fake `7zz` executable."""
import os
import stat
import sys
import textwrap

from jamf_dp_sync.httpclient import NetworkError, Response


class FakeHttp(object):
    """Maps (METHOD, url) to a Response, an Exception, or a callable(headers) -> Response.

    Records every call as (method, url, headers) so tests can assert on credentials.
    """

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    def add(self, method, url, status=200, body=b"", headers=None, final_url=None, history=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.routes[(method, url)] = Response(status, dict((k.lower(), v) for k, v in (headers or {}).items()),
                                              final_url or url, body if method != "HEAD" else None, history)

    def fail(self, method, url, message="connection refused"):
        self.routes[(method, url)] = NetworkError(message)

    def request(self, method, url, headers=None, data=None, follow=True, timeout=None):
        self.calls.append((method, url, dict(headers or {})))
        r = self.routes.get((method, url))
        if r is None:
            raise AssertionError("unexpected %s %s" % (method, url))
        if isinstance(r, Exception):
            raise r
        if callable(r):
            return r(headers or {})
        return r

    def get(self, url, headers=None, **kw):
        return self.request("GET", url, headers=headers, **kw)

    def head(self, url, headers=None, **kw):
        return self.request("HEAD", url, headers=headers, **kw)


class ListLog(object):
    def __init__(self):
        self.records = []

    def warning(self, msg, *args):
        self.records.append(msg % args if args else msg)

    info = debug = error = warning


def fake_7zz(directory, listing, members):
    """Write an executable `7zz` stand-in into `directory`.

    `listing` is printed for `l -slt`; `x -o<dir> archive member` writes members[member] bytes.
    Returns its path. Uses the running Python so it works on the Mac and the VM.
    """
    data_path = os.path.join(directory, "7zz-data.py")
    with open(data_path, "w") as f:
        f.write("LISTING = %r\nMEMBERS = %r\n" % (listing, members))
    script = os.path.join(directory, "7zz")
    with open(script, "w") as f:
        f.write("#!%s\n" % sys.executable)
        f.write(textwrap.dedent("""
            import os, sys
            sys.path.insert(0, %r)
            exec(open(%r).read())
            args = sys.argv[1:]
            if args[0] == "l":
                sys.stdout.write(LISTING)
                sys.exit(0)
            if args[0] == "x":
                out = [a[2:] for a in args if a.startswith("-o")][0]
                member = args[-1]
                if member not in MEMBERS:
                    sys.stderr.write("ERROR: No files to process\\n")
                    sys.exit(2)
                dest = os.path.join(out, *member.split("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(MEMBERS[member])
                sys.exit(0)
            sys.exit(7)
        """ % (directory, data_path)))
    os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR)
    return script


SLT_HEADER = """
7-Zip (z) 24.09 (arm64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit arm_v:8-A locale=C.UTF-8 Threads:4 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 300000000 bytes (287 MiB)

Listing archive: {archive}

--
Path = {archive}
Type = Dmg
Physical Size = 300000000

----------
"""


def slt_listing(archive, entries):
    """Build a `7zz l -slt` style listing. entries: list of (path, is_folder, size)."""
    blocks = []
    for path, folder, size in entries:
        blocks.append("Path = %s\nSize = %d\nPacked Size = %d\nModified = 2026-11-01 10:00:00\n"
                      "Attributes = %s\nFolder = %s\n" % (path, size, size, "D" if folder else "A",
                                                         "+" if folder else "-"))
    return SLT_HEADER.format(archive=archive) + "\n".join(blocks)
