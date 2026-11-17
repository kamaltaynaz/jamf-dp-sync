"""Test helper: build small synthetic xar archives (flat pkgs) in pure Python.

Produces the same layout as `xar`/`pkgbuild`: 28-byte header, zlib TOC, heap starting with the
SHA-1 TOC checksum and a 256-byte signature slot. The signature bytes are random (the agent does not
verify them; README "Known limits"), the certificates are real DER.
"""
import base64
import hashlib
import os
import struct
import zlib
from xml.sax.saxutils import escape

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def cert(name):
    with open(os.path.join(FIXTURES, "certs", name + ".der"), "rb") as f:
        return f.read()


def build_xar(path, files, certs=None, encoding="application/x-gzip", corrupt=None):
    """files: list of (path, bytes). Directories are created for nested paths.

    corrupt: None | 'toc_checksum' | 'member_checksum' — produce a damaged archive for tests.
    """
    heap = bytearray(b"\0" * 20)  # TOC checksum slot (sha1)
    sig_offset = None
    if certs:
        sig_offset = len(heap)
        heap += os.urandom(256)

    tree = {}
    for p, data in files:
        node = tree
        parts = p.split("/")
        for d in parts[:-1]:
            node = node.setdefault(d, {})
        node[parts[-1]] = data

    counter = [0]

    def emit(name, value):
        counter[0] += 1
        fid = counter[0]
        if isinstance(value, dict):
            inner = "".join(emit(n, v) for n, v in sorted(value.items()))
            return ('<file id="%d"><name>%s</name><type>directory</type>%s</file>'
                    % (fid, escape(name), inner))
        if encoding == "application/x-gzip":
            archived = zlib.compress(value)
        elif encoding == "application/x-bzip2":
            import bz2
            archived = bz2.compress(value)
        else:
            archived = value
        offset = len(heap)
        heap.extend(archived)
        a_sum = hashlib.sha1(archived).hexdigest()
        e_sum = hashlib.sha1(value).hexdigest()
        if corrupt == "member_checksum":
            e_sum = "0" * 40
        return ('<file id="%d"><name>%s</name><type>file</type><data>'
                '<length>%d</length><offset>%d</offset><size>%d</size>'
                '<encoding style="%s"/>'
                '<archived-checksum style="sha1">%s</archived-checksum>'
                '<extracted-checksum style="sha1">%s</extracted-checksum>'
                '</data></file>' % (fid, escape(name), len(archived), offset, len(value), encoding, a_sum, e_sum))

    body = "".join(emit(n, v) for n, v in sorted(tree.items()))
    sig = ""
    if certs:
        x509 = "".join("<X509Certificate>%s</X509Certificate>" % base64.b64encode(c).decode("ascii")
                       for c in certs)
        sig = ('<signature style="RSA"><offset>%d</offset><size>256</size>'
               '<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>%s</X509Data></KeyInfo>'
               '</signature>' % (sig_offset, x509))
    toc = ('<?xml version="1.0" encoding="UTF-8"?><xar><toc>'
           '<creation-time>2026-11-09T00:00:00</creation-time>'
           '<checksum style="sha1"><offset>0</offset><size>20</size></checksum>'
           '%s%s</toc></xar>' % (sig, body)).encode("utf-8")
    ctoc = zlib.compress(toc)
    digest = hashlib.sha1(ctoc).digest()
    if corrupt == "toc_checksum":
        digest = b"\x01" * 20
    heap[0:20] = digest
    header = struct.pack(">4sHHQQI", b"xar!", 28, 1, len(ctoc), len(toc), 1)
    with open(path, "wb") as f:
        f.write(header + ctoc + bytes(heap))
    return path


DISTRIBUTION = """<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <pkg-ref id="com.example.app"/>
    <pkg-ref id="com.example.app" version="{pkgref}">#app.pkg</pkg-ref>
    {product}
</installer-gui-script>
"""


def distribution(product=None, pkgref="1.0"):
    p = '<product id="com.example.app" version="%s"/>' % product if product else ""
    return DISTRIBUTION.format(product=p, pkgref=pkgref).encode("utf-8")


def package_info(version):
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<pkg-info identifier="com.example.app" version="%s" format-version="2"/>' % version).encode("utf-8")
