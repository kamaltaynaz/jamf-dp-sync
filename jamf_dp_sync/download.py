"""Download to staging (spec section 3 step 5, section 6 latest_redirect rule 3).

The file goes into staging_dir (same filesystem as Packages/, outside the share) under a unique
temporary name. No credentials are ever sent. For latest_redirect apps a conditional GET uses the
ETag / Last-Modified cached per app, so an unchanged file is not fetched again. A DMG is replaced by
its extracted pkg (dmg_extract). The source's published size and SHA-256 describe the file it
serves, so for a DMG they are checked here, on the DMG, before extraction (public review round 2 #4);
the pkg inside is then verified by its structure, certificate fields and version only.
Any failure removes what was staged.
"""
import os
import tempfile

from jamf_dp_sync import faults
from jamf_dp_sync.dmg_extract import dmg_extract
from jamf_dp_sync.errors import SyncError


class DownloadError(SyncError):
    step = "download"


class Fetched(object):
    def __init__(self, path=None, not_modified=False, etag=None, last_modified=None, url=None,
                 integrity_checked=False):
        self.path = path
        self.integrity_checked = integrity_checked   # size/SHA-256 already matched (on the DMG)
        self.not_modified = not_modified
        self.etag = etag
        self.last_modified = last_modified
        self.url = url


def _flip_middle_byte(path):
    size = os.path.getsize(path)
    if not size:
        return
    with open(path, "r+b") as f:
        f.seek(size // 2)
        b = f.read(1)
        f.seek(size // 2)
        f.write(bytes([b[0] ^ 0xFF]))


def _check_container(path, expected_size, expected_sha256):
    from jamf_dp_sync.verify import VerifyError, file_digests
    size, sha256, _ = file_digests(path)
    if expected_size is not None and size != expected_size:
        raise VerifyError("DMG size mismatch (expected %d, got %d)" % (expected_size, size))
    if expected_sha256 is not None and sha256 != expected_sha256.lower():
        raise VerifyError("DMG SHA-256 mismatch (expected %s, got %s)" % (expected_sha256.lower(), sha256))


def fetch(app, url, staging_dir, http, tools, cache=None, expected_size=None, expected_sha256=None):
    """Download `url` for `app`. `cache` is the app's state dict (for the conditional GET) or None.
    For a DMG, `expected_size` / `expected_sha256` are checked on the DMG before extraction."""
    is_dmg = (app.get("post_download") or {}).get("type") == "dmg_extract"
    fd, path = tempfile.mkstemp(prefix="%s-" % app["label"], suffix=".dmg" if is_dmg else ".pkg",
                                dir=staging_dir)
    os.close(fd)
    headers = {}
    if cache and cache.get("url") == url:
        if cache.get("etag"):
            headers["If-None-Match"] = cache["etag"]
        if cache.get("last_modified"):
            headers["If-Modified-Since"] = cache["last_modified"]
    try:
        resp = http.download(url, path, headers=headers)
        if resp.status == 304 and headers:
            os.unlink(path)
            return Fetched(not_modified=True, url=url)
        if not (200 <= resp.status < 300):
            raise DownloadError("download returned HTTP %d" % resp.status)
        if faults.on("flip_byte"):
            _flip_middle_byte(path)
        checked = False
        if is_dmg:
            if expected_size is not None or expected_sha256 is not None:
                _check_container(path, expected_size, expected_sha256)
                checked = True
            path = dmg_extract(path, app["post_download"]["inner_path_regex"], staging_dir,
                               "/nonexistent/7zz" if faults.on("no_7zz") else tools.get("7zz"))
        return Fetched(path, etag=resp.header("etag"), last_modified=resp.header("last-modified"), url=url,
                       integrity_checked=checked)
    except Exception:
        if path and os.path.exists(path):
            os.unlink(path)
        raise
