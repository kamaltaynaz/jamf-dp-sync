"""Read-only xar reader (flat pkgs and Adobe .arm manifests), standard library only.

Format: a 28-byte big-endian header ('xar!', header size, version, compressed and uncompressed TOC
lengths, checksum algorithm), a zlib-compressed XML table of contents, then the heap. The TOC
checksum stored in the heap is verified, which is what "parseable table of contents" means in
spec section 7 check 3. Members are read with seek, so multi-GB pkgs are never loaded whole.
"""
import base64
import bz2
import hashlib
import struct
import zlib

from jamf_dp_sync import xmlsafe
from jamf_dp_sync.errors import XarError

MAGIC = b"xar!"
_HEADER = struct.Struct(">4sHHQQI")
_CKSUM_ALGS = {0: None, 1: "sha1", 2: "md5"}
MAX_TOC = 64 * 1024 * 1024
DEFAULT_MAX_MEMBER = 16 * 1024 * 1024


def is_xar(path):
    with open(path, "rb") as f:
        return f.read(4) == MAGIC


class Member(object):
    __slots__ = ("path", "type", "offset", "length", "size", "encoding", "archived_checksum",
                 "extracted_checksum")

    def __init__(self, path, type_):
        self.path = path
        self.type = type_
        self.offset = self.length = self.size = None
        self.encoding = "application/octet-stream"
        self.archived_checksum = self.extracted_checksum = None  # (alg, hexdigest)

    def __repr__(self):
        return "Member(%r, %s, size=%r)" % (self.path, self.type, self.size)


def _int_text(elem, name):
    e = xmlsafe.find_local(elem, name) if elem is not None else None
    if e is None or e.text is None:
        return None
    try:
        return int(e.text.strip())
    except ValueError:
        raise XarError("xar TOC: <%s> is not an integer" % name)


def _checksum(elem):
    if elem is None:
        return None
    alg = (elem.get("style") or "").lower()
    return (alg, (elem.text or "").strip().lower())


class XarArchive(object):
    def __init__(self, path):
        self.path = path
        self._f = open(path, "rb")
        try:
            self._read_header_and_toc()
        except Exception:
            self._f.close()
            raise

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------- header / TOC
    def _read_header_and_toc(self):
        head = self._f.read(_HEADER.size)
        if len(head) < _HEADER.size:
            raise XarError("file too short for a xar header")
        magic, hsize, version, clen, ulen, alg = _HEADER.unpack(head)
        if magic != MAGIC:
            raise XarError("not a xar archive (magic %r)" % magic)
        if hsize < _HEADER.size:
            raise XarError("bad xar header size %d" % hsize)
        if version != 1:
            raise XarError("unsupported xar version %d" % version)
        if clen <= 0 or clen > MAX_TOC or ulen > MAX_TOC:
            raise XarError("implausible xar TOC length")
        if alg in _CKSUM_ALGS:
            alg_name = _CKSUM_ALGS[alg]
        elif alg == 3:
            head_rest = self._f.read(hsize - _HEADER.size)
            alg_name = head_rest.split(b"\0", 1)[0].decode("ascii", "replace").lower()
        else:
            raise XarError("unknown xar checksum algorithm %d" % alg)
        self._f.seek(hsize)
        ctoc = self._f.read(clen)
        if len(ctoc) != clen:
            raise XarError("truncated xar TOC")
        try:
            d = zlib.decompressobj()
            toc = d.decompress(ctoc, ulen + 1)  # bounded by the declared length (review #14)
        except zlib.error as e:
            raise XarError("xar TOC does not decompress: %s" % e)
        if len(toc) != ulen or d.unconsumed_tail:
            raise XarError("xar TOC length mismatch (larger or smaller than declared)")
        if not d.eof:  # the whole stream, trailer included, must be there (review 2 #15)
            raise XarError("xar TOC zlib stream is incomplete")
        self.heap_offset = hsize + clen
        try:
            self.toc_root = xmlsafe.fromstring(toc)
        except ValueError as e:
            raise XarError("xar TOC is not valid XML: %s" % e)
        self.toc_xml = toc
        self.toc = xmlsafe.find_local(self.toc_root, "toc")
        if self.toc is None:
            raise XarError("xar TOC has no <toc>")
        self._verify_toc_checksum(ctoc, alg_name)
        self.members = {}
        for f in self.toc:
            if xmlsafe.local(f.tag) == "file":
                self._walk(f, "")
        self._check_bounds()

    def _check_bounds(self):
        """Every heap range the TOC declares must lie inside the file. A download that stopped early
        but kept the TOC and metadata intact fails here (review #2)."""
        self._f.seek(0, 2)
        heap_size = self._f.tell() - self.heap_offset
        for m in self.members.values():
            if m.offset is None or m.length is None:
                continue
            if m.offset < 0 or m.length < 0 or m.offset + m.length > heap_size:
                raise XarError("xar member %s extends past the end of the file (truncated download?)" % m.path)

    def _verify_toc_checksum(self, ctoc, alg_name):
        ck = None
        for e in self.toc:
            if xmlsafe.local(e.tag) == "checksum":
                ck = e
        if alg_name is None:
            return
        if ck is None:
            raise XarError("xar header names checksum %s but TOC has no <checksum>" % alg_name)
        off, size = _int_text(ck, "offset"), _int_text(ck, "size")
        if off is None or size is None:
            raise XarError("xar TOC checksum has no offset/size")
        if off < 0 or size < 0 or size > 64:
            raise XarError("xar TOC checksum has a negative or implausible offset/size")
        try:
            h = hashlib.new(alg_name)
        except ValueError:
            raise XarError("unsupported xar checksum %s" % alg_name)
        h.update(ctoc)
        stored = self._read_heap(off, size)
        if stored != h.digest():
            raise XarError("xar TOC checksum mismatch")

    def _walk(self, elem, prefix):
        name_e = None
        type_e = None
        for c in elem:
            n = xmlsafe.local(c.tag)
            if n == "name":
                name_e = c
            elif n == "type":
                type_e = c
        name = (name_e.text or "") if name_e is not None else ""
        if not name or name in (".", "..") or "/" in name or "\0" in name:
            raise XarError("xar member with unsafe name %r" % name)
        path = prefix + name
        m = Member(path, (type_e.text or "").strip() if type_e is not None else "file")
        data = None
        for c in elem:
            if xmlsafe.local(c.tag) == "data":
                data = c
        if data is not None:
            m.offset = _int_text(data, "offset")
            m.length = _int_text(data, "length")
            m.size = _int_text(data, "size")
            for c in data:
                n = xmlsafe.local(c.tag)
                if n == "encoding":
                    m.encoding = c.get("style") or m.encoding
                elif n == "archived-checksum":
                    m.archived_checksum = _checksum(c)
                elif n == "extracted-checksum":
                    m.extracted_checksum = _checksum(c)
        for field in ("offset", "length", "size"):
            if getattr(m, field) is not None and getattr(m, field) < 0:
                raise XarError("xar member %s has a negative %s" % (path, field))  # review 2 #9
        self.members[path] = m
        for c in elem:
            if xmlsafe.local(c.tag) == "file":
                self._walk(c, path + "/")

    # -------------------------------------------------------------------- heap
    def _read_heap(self, offset, length):
        if offset < 0 or length < 0:
            raise XarError("negative xar heap range")
        self._f.seek(self.heap_offset + offset)
        data = self._f.read(length)
        if len(data) != length:
            raise XarError("xar heap truncated")
        return data

    def names(self):
        return sorted(self.members)

    def read(self, path, max_size=DEFAULT_MAX_MEMBER):
        """Return the decoded bytes of one file member, verifying both checksums."""
        m = self.members.get(path)
        if m is None:
            raise KeyError(path)
        if m.type != "file":
            raise XarError("xar member %s is a %s, not a file" % (path, m.type))
        if m.offset is None or m.length is None:
            return b""
        if m.length > max_size or (m.size or 0) > max_size:
            raise XarError("xar member %s is larger than %d bytes" % (path, max_size))
        raw = self._read_heap(m.offset, m.length)
        _check(raw, m.archived_checksum, path, "archived")
        enc = m.encoding
        limit = min(max_size, m.size if m.size is not None else max_size) + 1
        try:  # decompression is bounded, whatever the TOC declares (review #14)
            dec = None
            if enc == "application/octet-stream":
                out = raw
            elif enc == "application/x-gzip":
                dec = zlib.decompressobj()
            elif enc == "application/x-bzip2":
                dec = bz2.BZ2Decompressor()
            elif enc in ("application/x-lzma", "application/x-xz"):
                import lzma
                dec = lzma.LZMADecompressor()
            else:
                raise XarError("xar member %s has unsupported encoding %s" % (path, enc))
            if dec is not None:
                out = dec.decompress(raw, limit)
                if len(out) > max_size:
                    raise XarError("xar member %s is larger than %d bytes" % (path, max_size))
                if m.size is not None and len(out) > m.size:
                    raise XarError("xar member %s size mismatch (more data than declared)" % path)
                if not dec.eof:  # complete stream only (review 2 #15)
                    raise XarError("xar member %s: compressed stream is incomplete" % path)
        except (zlib.error, IOError, OSError, EOFError, ValueError) as e:
            raise XarError("xar member %s does not decode: %s" % (path, e))
        if len(out) > max_size:
            raise XarError("xar member %s is larger than %d bytes" % (path, max_size))
        if m.size is not None and len(out) != m.size:
            raise XarError("xar member %s size mismatch" % path)
        _check(out, m.extracted_checksum, path, "extracted")
        return out

    # --------------------------------------------------------------- signature
    def certificates(self):
        """DER certificates from the TOC's RSA <signature>, leaf first. Empty list if unsigned."""
        sig = None
        for e in self.toc:
            if xmlsafe.local(e.tag) == "signature":
                sig = e
                break
        if sig is None:
            return []
        certs = []
        for e in sig.iter():
            if xmlsafe.local(e.tag) == "X509Certificate" and e.text:
                try:
                    certs.append(base64.b64decode("".join(e.text.split())))
                except (ValueError, TypeError) as err:
                    raise XarError("xar signature certificate is not base64: %s" % err)
        return certs

    def has_cms_signature(self):
        return any(xmlsafe.local(e.tag) == "x-signature" for e in self.toc)


def _check(data, checksum, path, which):
    if checksum is None or not checksum[0] or not checksum[1]:
        return
    alg, expected = checksum
    try:
        h = hashlib.new(alg)
    except ValueError:
        raise XarError("xar member %s: unsupported %s checksum %s" % (path, which, alg))
    h.update(data)
    if h.hexdigest() != expected:
        raise XarError("xar member %s: %s checksum mismatch" % (path, which))
