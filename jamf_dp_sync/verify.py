"""Verification of a staged pkg (spec section 7). Nothing reaches Packages/ unless all checks pass.

Checks, in order:
  1. size equals expected_size (when the resolver supplied one)
  2. SHA-256 equals expected_sha256 (when supplied)
  3. flat pkg: xar magic and a parseable TOC with a valid TOC checksum
  4. leaf certificate is "Developer ID Installer" with OU == team_id
  5. pkg version passes V2 (exact sources) or V3 (latest-only sources)

Any failure deletes the staged file and raises VerifyError (or NotUpstreamYet for a stale CDN under
V3, which section 7 routes to D6 rather than to a failure).
"""
import hashlib
import os

from jamf_dp_sync import pkginfo, signer, versions
from jamf_dp_sync.errors import NotUpstreamYet, SyncError, VerifyError, XarError
from jamf_dp_sync.xar import XarArchive

CHUNK = 1024 * 1024


def file_digests(path):
    """(size, sha256 hex, sha512 hex) in one pass. SHA-512 is what the Jamf package record needs."""
    s256 = hashlib.sha256()
    s512 = hashlib.sha512()
    size = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            size += len(block)
            s256.update(block)
            s512.update(block)
    return size, s256.hexdigest(), s512.hexdigest()


class Verified(object):
    def __init__(self, path, version, version_source, size, sha256, sha512, signer_cn):
        self.path = path
        self.version = version
        self.version_source = version_source
        self.size = size
        self.sha256 = sha256
        self.sha512 = sha512
        self.signer_cn = signer_cn


def verify_pkg(path, team_id, rule, target, exact, expected_size=None, expected_sha256=None,
               openssl="openssl", discard=True):
    """Run checks 1-5. On failure the file is deleted when `discard` (a staged download); a file
    already in Packages/ (re-verification of a retained pkg) is never deleted here."""
    try:
        return _verify(path, team_id, rule, target, exact, expected_size, expected_sha256, openssl)
    except SyncError:
        if discard:
            _discard(path)
        raise
    except Exception as e:  # never leave an unverified file behind, whatever went wrong
        if discard:
            _discard(path)
        raise VerifyError("unexpected error verifying %s: %s" % (os.path.basename(path), e))


def _verify(path, team_id, rule, target, exact, expected_size, expected_sha256, openssl):
    size = os.path.getsize(path)
    # 1. size
    if expected_size is not None and size != expected_size:
        raise VerifyError("size mismatch (expected %d, got %d)" % (expected_size, size), step="verify")
    # 2. SHA-256 (digests computed in one pass; SHA-512 kept for the package record)
    size, sha256, sha512 = file_digests(path)
    if expected_sha256 is not None and sha256 != expected_sha256.lower():
        raise VerifyError("SHA-256 mismatch (expected %s, got %s)" % (expected_sha256.lower(), sha256))
    # 3. flat pkg
    try:
        archive = XarArchive(path)
    except XarError as e:
        raise VerifyError("not a flat pkg: %s" % e)
    with archive:
        # 4. signer identity
        cn = signer.check_xar_signer(archive, team_id, openssl)
        # 5. version
        raw_version, source = pkginfo.read_version(archive)
    try:
        pkg_version = rule.parse(raw_version)
    except ValueError as e:
        raise VerifyError("pkg version %r (%s) does not parse: %s" % (raw_version, source, e))
    if exact:
        if not versions.accept_exact(pkg_version, target):
            raise VerifyError("version mismatch: pkg is %s, expected exactly %s (V2)" % (pkg_version, target))
    elif not versions.accept_latest(pkg_version, target):
        raise NotUpstreamYet("stale CDN: pkg is %s, older than target %s (V3)" % (pkg_version, target))
    return Verified(path, pkg_version, source, size, sha256, sha512, cn)


def _discard(path):
    try:
        os.unlink(path)
    except OSError:
        pass
