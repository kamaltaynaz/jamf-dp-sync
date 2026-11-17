"""Read the version a flat pkg declares (spec section 7, check 5).

Order: Distribution <product version>, else the first <pkg-ref> carrying a version attribute, else
PackageInfo <pkg-info version> (top-level for component pkgs, else the first nested component).
"""
from jamf_dp_sync import xmlsafe
from jamf_dp_sync.errors import VerifyError, XarError


def read_version(archive):
    """Return (version_string, source) where source names the field used."""
    names = archive.members
    if "Distribution" in names:
        root = _parse(archive, "Distribution")
        for e in root.iter():
            if xmlsafe.local(e.tag) == "product" and e.get("version"):
                return e.get("version").strip(), "Distribution product"
        for e in root.iter():
            if xmlsafe.local(e.tag) == "pkg-ref" and e.get("version"):
                return e.get("version").strip(), "Distribution pkg-ref"
    candidates = []
    if "PackageInfo" in names:
        candidates.append("PackageInfo")
    candidates.extend(sorted(n for n in names if n.count("/") == 1 and n.endswith(".pkg/PackageInfo")))
    for n in candidates:
        root = _parse(archive, n)
        if xmlsafe.local(root.tag) == "pkg-info" and root.get("version"):
            return root.get("version").strip(), n
    raise VerifyError("pkg declares no version (no Distribution product/pkg-ref or PackageInfo version)")


def _parse(archive, name):
    try:
        return xmlsafe.fromstring(archive.read(name))
    except (ValueError, XarError) as e:
        raise VerifyError("cannot parse %s: %s" % (name, e))
