"""D1: the agent must run on Python 3.6 with the standard library only.

The dev Mac has no 3.6, so this is a static guard: newest syntax the running parser can still
reject, plus a deny-list of 3.7+ APIs, plus a stdlib-only import check. The real 3.6 run happens on
the Lima VM (OPEN_QUESTIONS Q7).
"""
import ast
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AGENT_FILES = [os.path.join(ROOT, "jamf_dp_sync.py")]
for _dirpath, _dirs, _files in os.walk(os.path.join(ROOT, "jamf_dp_sync")):
    AGENT_FILES.extend(os.path.join(_dirpath, f) for f in _files if f.endswith(".py"))

# APIs added after 3.6 that are easy to reach for by habit.
DENY = [
    (r"capture_output\s*=", "subprocess capture_output (3.7)"),
    (r"\btext\s*=\s*True", "subprocess text= (3.7)"),
    (r"^\s*(from|import)\s+dataclasses", "dataclasses (3.7)"),
    (r"from\s+__future__\s+import\s+annotations", "postponed annotations (3.7)"),
    (r"\.fromisoformat\(", "datetime.fromisoformat (3.7)"),
    (r"\bnullcontext\b", "contextlib.nullcontext (3.7)"),
    (r"\bThreadingHTTPServer\b", "http.server.ThreadingHTTPServer (3.7)"),
    (r"\.removeprefix\(|\.removesuffix\(", "str.removeprefix (3.9)"),
    (r"\bre\.Pattern\b|\bre\.Match\b", "re.Pattern (3.7)"),
    (r"\.isascii\(", "str.isascii (3.7)"),
    (r"\btime_ns\(", "time.time_ns (3.7)"),
    (r"importlib\.resources", "importlib.resources (3.7)"),
    (r"\bbreakpoint\(", "breakpoint (3.7)"),
    (r"\bfunctools\.cached_property|\bcached_property\b", "cached_property (3.8)"),
    (r":=", "walrus (3.8)"),
    (r"\bmath\.(prod|isqrt|dist)\b", "math 3.8 functions"),
]

STDLIB_OK = set("""
argparse ast base64 binascii bz2 calendar codecs collections contextlib datetime email errno fcntl
fnmatch functools getpass glob grp gzip hashlib hmac http io html importlib itertools json logging lzma math os platform
posixpath random re shlex shutil signal socket ssl stat string struct subprocess sys tempfile
textwrap threading time traceback types urllib uuid xml zlib copy
""".split())
# Python 3.10+ knows its own stdlib; the list above covers older dev interpreters.
STDLIB_OK |= set(getattr(sys, "stdlib_module_names", ()))
STDLIB_OK.add("jamf_dp_sync")


def _source(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8")


class Py36Compat(unittest.TestCase):
    def test_syntax(self):
        # On 3.6/3.7 the native parse is the real check. On 3.8+ ask for the oldest grammar the
        # interpreter still offers (3.6 up to 3.12, 3.7 from 3.13 on).
        if sys.version_info < (3, 8):
            kw = {}
        else:
            kw = {"feature_version": (3, 6) if sys.version_info < (3, 13) else (3, 7)}
        for path in AGENT_FILES:
            with self.subTest(path=os.path.relpath(path, ROOT)):
                ast.parse(_source(path), filename=path, **kw)

    def test_no_newer_apis(self):
        for path in AGENT_FILES:
            src = _source(path)
            for pattern, what in DENY:
                for m in re.finditer(pattern, src, re.M):
                    line = src.count("\n", 0, m.start()) + 1
                    self.fail("%s:%d uses %s" % (os.path.relpath(path, ROOT), line, what))

    def test_no_fstring_self_documenting(self):
        for path in AGENT_FILES:
            self.assertIsNone(re.search(r"\{[^{}]*=\}", "".join(
                re.findall(r"f\"[^\"]*\"|f'[^']*'", _source(path)))), path)

    def test_stdlib_only(self):
        for path in AGENT_FILES:
            tree = ast.parse(_source(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module]
                for n in names:
                    with self.subTest(path=os.path.relpath(path, ROOT), module=n):
                        self.assertIn(n.split(".")[0], STDLIB_OK)


if __name__ == "__main__":
    unittest.main()
