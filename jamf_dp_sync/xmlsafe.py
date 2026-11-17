"""Minimal hardening for stdlib XML parsing of upstream and Jamf documents.

Python 3.6's expat may predate the billion-laughs mitigations, so documents with a DOCTYPE or entity
declarations are refused before they reach the parser. None of the documents this agent reads
(xar TOCs, Distribution, PackageInfo, the Adobe manifest, Classic API policies) need one.
"""
import re
import xml.etree.ElementTree as ET

_FORBIDDEN = re.compile(br"<!DOCTYPE|<!ENTITY", re.I)
_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")
_DECL_ENCODING = re.compile(br"^\s*<\?xml[^>]*\bencoding\s*=\s*[\"']([A-Za-z0-9._-]+)[\"']")
_ALLOWED_ENCODINGS = ("utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin-1", "latin1")


class UnsafeXML(ValueError):
    pass


def fromstring(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    # The DOCTYPE/ENTITY scan only works on ASCII-compatible bytes, so anything else is refused
    # outright: UTF-16/32 (BOM or NUL bytes) and declared encodings other than UTF-8/ASCII/Latin-1
    # (review #13). None of the documents this agent reads use them.
    if data.startswith(_BOMS) or b"\x00" in data:
        raise UnsafeXML("XML is not UTF-8/ASCII (UTF-16/32 or NUL bytes)")
    m = _DECL_ENCODING.match(data.lstrip(b"\xef\xbb\xbf"))
    if m and m.group(1).decode("ascii").lower() not in _ALLOWED_ENCODINGS:
        raise UnsafeXML("XML declares unsupported encoding %s" % m.group(1).decode("ascii"))
    if _FORBIDDEN.search(data):
        raise UnsafeXML("XML contains a DOCTYPE or ENTITY declaration")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError("XML parse error: %s" % e)


def local(tag):
    """Tag name without its {namespace}."""
    return tag.rsplit("}", 1)[-1]


def find_local(elem, name):
    """First descendant (any namespace) whose local name is `name`."""
    for e in elem.iter():
        if local(e.tag) == name:
            return e
    return None
