"""Signer identity check (spec section 7, check 4).

Takes the leaf certificate from the xar TOC and asks `openssl` for its subject. Passes only when the
subject CN is a "Developer ID Installer" certificate and its OU equals the expected Team ID.

This confirms who signed the pkg. It does NOT verify the TOC signature cryptographically or the
chain to Apple's root (see README "Known limits").
"""
import subprocess

from jamf_dp_sync.errors import ToolError, VerifyError

INSTALLER_PREFIX = "Developer ID Installer: "


def parse_rfc2253(line):
    """Parse `subject=...` output of `openssl x509 -nameopt RFC2253` into [(attr, value), ...].

    Handles the OpenSSL 1.0.x form (`subject= X=..`) and 1.1+/3.x (`subject=X=..`), escaped commas,
    plus signs and `\\XX` hex escapes of UTF-8 bytes.
    """
    line = line.strip()
    if "=" in line and line.split("=", 1)[0].strip().lower() == "subject":
        line = line.split("=", 1)[1]
    line = line.strip()
    rdns = []
    buf = bytearray()
    i = 0
    raw = line.encode("utf-8")
    parts = []
    while i < len(raw):
        c = raw[i:i + 1]
        if c == b"\\" and i + 1 < len(raw):
            nxt = raw[i + 1:i + 3]
            if len(nxt) == 2 and all(ch in b"0123456789abcdefABCDEF" for ch in nxt):
                buf.append(int(nxt, 16))
                i += 3
                continue
            buf += raw[i + 1:i + 2]
            i += 2
            continue
        if c in (b",", b"+"):
            parts.append(bytes(buf))
            buf = bytearray()
            i += 1
            continue
        buf += c
        i += 1
    parts.append(bytes(buf))
    for p in parts:
        if not p:
            continue
        if b"=" not in p:
            raise VerifyError("cannot parse certificate subject component %r" % p)
        k, v = p.split(b"=", 1)
        rdns.append((k.decode("ascii", "replace").strip(), v.decode("utf-8", "replace").strip()))
    return rdns


def certificate_subject(der, openssl="openssl"):
    try:
        p = subprocess.Popen([openssl, "x509", "-inform", "DER", "-noout", "-subject", "-nameopt", "RFC2253"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise ToolError("cannot run openssl (%s): %s" % (openssl, e))
    out, err = p.communicate(der, timeout=30)
    if p.returncode != 0:
        raise VerifyError("openssl could not read the signing certificate: %s"
                          % err.decode("utf-8", "replace").strip()[:200])
    return parse_rfc2253(out.decode("utf-8", "replace"))


def check_installer_identity(der, team_id, openssl="openssl"):
    """Raise VerifyError unless `der` is a Developer ID Installer cert for `team_id`.

    Returns the certificate CN on success.
    """
    rdns = certificate_subject(der, openssl)
    cns = [v for k, v in rdns if k.upper() == "CN"]
    ous = [v for k, v in rdns if k.upper() == "OU"]
    if len(cns) != 1:
        raise VerifyError("signing certificate has %d CN values" % len(cns))
    cn = cns[0]
    if not cn.startswith(INSTALLER_PREFIX):
        raise VerifyError("signed with %r, not a Developer ID Installer certificate" % cn)
    if ous != [team_id]:
        raise VerifyError("Team ID mismatch (expected %s, certificate OU %s)"
                          % (team_id, ",".join(ous) or "none"))
    if not cn.endswith("(%s)" % team_id):
        raise VerifyError("Team ID mismatch (expected %s, certificate CN %r)" % (team_id, cn))
    return cn


def check_xar_signer(archive, team_id, openssl="openssl"):
    certs = archive.certificates()
    if not certs:
        raise VerifyError("pkg is not signed (no certificate in the xar TOC)")
    return check_installer_identity(certs[0], team_id, openssl)
