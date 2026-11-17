"""adobe_arm_manifest resolver (spec section 6): Adobe Acrobat Pro.

1. Download manifest_url and detect its format by magic bytes: `xar!` -> stdlib xar reader,
   `7z\\xBC\\xAF\\x27\\x1C` -> 7zz, `<?xml` -> as-is, anything else -> fail, logging the first 16 bytes.
2. Parse ARMProductManifest; select the dItem whose id equals item_id (dld_App_Full).
3. URL = httpURLBase + "/" + URL + "/" + fileName; hashValue -> expected_sha256; size -> expected_size.
4. Pre-download checks: Team ID in signingEntity == team_id; fileName matches
   ^AcrobatDC\\d{10}_MUI\\.pkg$; version decoded from the path equals the target.
5. A target older than the manifest (a pin) falls back to the ardownload3 template with no hash,
   with a warning.
6. Extra check (2026-11-09, beyond spec rule 6): a xar `.arm` must carry a
   "Developer ID Installer" leaf certificate for the app's team_id, checked like a pkg (section 7
   check 4: identity only, not cryptographic). Plain XML or 7z manifests carry no such certificate;
   they are accepted on HTTPS alone, as rule 6 says, with a warning.
"""
import binascii
import os
import re
import shutil
import tempfile

from jamf_dp_sync import sevenzip, signer, xmlsafe
from jamf_dp_sync.errors import NotUpstreamYet, ResolveError, VerifyError, XarError
from jamf_dp_sync.resolvers import Resolution
from jamf_dp_sync.xar import XarArchive

XAR_MAGIC = b"xar!"
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
FILENAME_RE = re.compile(r"^AcrobatDC\d{10}_MUI\.pkg$")
FALLBACK_TEMPLATE = "https://ardownload3.adobe.com/pub/adobe/acrobat/mac/AcrobatDC/{vercode}/AcrobatDC{vercode}_MUI.pkg"
MANIFEST_MEMBER_RE = r"(^|/)[^/]+\.xml$"
_SIGNING_ENTITY = re.compile(r"^Developer ID Installer: .+ \(([A-Z0-9]{10})\)$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def detect_format(data):
    if data.startswith(XAR_MAGIC):
        return "xar"
    if data.startswith(SEVENZ_MAGIC):
        return "7z"
    if data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"<?xml"):
        return "xml"
    return None


def extract_manifest_xml(data, workdir=None, sevenzip_bin=None, team_id=None, openssl="openssl"):
    """Return (manifest XML bytes, warnings) from a .arm payload in any of the three formats.

    A xar payload must be signed with a Developer ID Installer certificate for `team_id`.
    """
    fmt = detect_format(data)
    if fmt == "xml":
        return data, ["manifest is plain XML: no signer to check, trusted on HTTPS alone"]
    if fmt is None:
        raise ResolveError("unknown manifest format; first 16 bytes: %s"
                           % binascii.hexlify(data[:16]).decode("ascii"))
    tmpdir = tempfile.mkdtemp(prefix="arm-", dir=workdir)
    try:
        path = os.path.join(tmpdir, "manifest.arm")
        with open(path, "wb") as f:
            f.write(data)
        if fmt == "xar":
            try:
                with XarArchive(path) as x:
                    if team_id is not None:
                        try:
                            signer.check_xar_signer(x, team_id, openssl)
                        except VerifyError as e:
                            raise ResolveError("manifest signer check failed: %s" % e)
                    names = [n for n, m in x.members.items()
                             if m.type == "file" and re.search(MANIFEST_MEMBER_RE, n)]
                    if len(names) != 1:
                        raise ResolveError("manifest xar: expected one .xml member, found %r" % sorted(names))
                    return x.read(names[0]), []
            except XarError as e:
                raise ResolveError("manifest xar unreadable: %s" % e)
        if not sevenzip_bin:
            raise ResolveError("manifest is 7z but no 7zz configured")
        members = sevenzip.list_members(sevenzip_bin, path)
        member = sevenzip.select_one(members, MANIFEST_MEMBER_RE, "manifest 7z")
        out = sevenzip.extract_one(sevenzip_bin, path, member, tmpdir)
        with open(out, "rb") as f:
            return f.read(), ["manifest is 7z: no signer to check, trusted on HTTPS alone"]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_manifest(xml_bytes):
    """Return {dItem id: attribute dict} from an ARMProductManifest."""
    try:
        root = xmlsafe.fromstring(xml_bytes)
    except ValueError as e:
        raise ResolveError("manifest XML: %s" % e)
    if xmlsafe.local(root.tag) != "ARMProductManifest":
        raise ResolveError("manifest root is <%s>, not <ARMProductManifest>" % xmlsafe.local(root.tag))
    items = {}
    for e in root.iter():
        if xmlsafe.local(e.tag) == "dItem":
            i = e.get("id")
            if i in items:
                raise ResolveError("manifest has duplicate dItem id %r" % i)
            items[i] = dict(e.attrib)
    return items


def select_item(items, item_id, team_id, rule):
    """Section 6 rules 2-4 (minus the target comparison). Returns (item, item_version, url, size)."""
    item = items.get(item_id)
    if item is None:
        raise ResolveError("manifest has no dItem %r (has: %s)" % (item_id, ", ".join(sorted(items))))
    for k in ("httpURLBase", "URL", "fileName", "signingEntity", "hashValue", "size"):
        if not item.get(k):
            raise ResolveError("dItem %s is missing %s" % (item_id, k))
    m = _SIGNING_ENTITY.match(item["signingEntity"].strip())
    if not m:
        raise ResolveError("dItem %s signingEntity %r is not a Developer ID Installer" % (item_id, item["signingEntity"]))
    if m.group(1) != team_id:
        raise ResolveError("Team ID mismatch in manifest (expected %s, signingEntity %s)" % (team_id, m.group(1)))
    name = item["fileName"]
    if not FILENAME_RE.match(name):
        raise ResolveError("dItem %s fileName %r does not match %s" % (item_id, name, FILENAME_RE.pattern))
    if not item["httpURLBase"].startswith("https://"):
        raise ResolveError("dItem %s httpURLBase is not https" % item_id)
    try:
        path_version = rule.parse(item["URL"].rstrip("/").rsplit("/", 1)[-1])
        name_version = rule.parse(name)
    except ValueError as e:
        raise ResolveError("dItem %s: cannot decode version: %s" % (item_id, e))
    if path_version != name_version:
        raise ResolveError("dItem %s: path version %s differs from file name version %s"
                           % (item_id, path_version, name_version))
    if not _HEX64.match(item["hashValue"]):
        raise ResolveError("dItem %s hashValue is not a SHA-256 hex digest" % item_id)
    try:
        size = int(item["size"])
    except ValueError:
        raise ResolveError("dItem %s size %r is not an integer" % (item_id, item["size"]))
    url = "%s/%s/%s" % (item["httpURLBase"].rstrip("/"), item["URL"].strip("/"), name)
    return item, path_version, url, size


def resolve(app, target, ctx):
    resp = ctx.http.get(app["manifest_url"])
    if resp.status != 200:
        raise ResolveError("manifest download returned %d" % resp.status)
    xml_bytes, warnings = extract_manifest_xml(resp.body or b"", ctx.workdir, ctx.tools.get("7zz"),
                                               app["team_id"], ctx.tools.get("openssl", "openssl"))
    for w in warnings:
        if ctx.log:
            ctx.log.warning("%s: %s", app["label"], w)
    items = parse_manifest(xml_bytes)
    item, item_version, url, size = select_item(items, app["item_id"], app["team_id"], ctx.rule)

    if target == item_version:
        return Resolution(url, exact=True, expected_sha256=item["hashValue"], expected_size=size,
                          source_version=item_version, warnings=warnings)
    if target > item_version:
        raise NotUpstreamYet("manifest offers %s, target %s not published yet" % (item_version, target))
    # Rule 5: pinned to an older version than the manifest carries.
    vercode = ctx.rule.format(target, "url")
    fallback = FALLBACK_TEMPLATE.format(vercode=vercode)
    msg = ("target %s is older than manifest %s; using template URL with no hash or size"
           % (target, item_version))
    if ctx.log:
        ctx.log.warning("%s: %s", app["label"], msg)
    return Resolution(fallback, exact=True, source_version=target, warnings=warnings + [msg])
