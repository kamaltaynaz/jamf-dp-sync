"""Draft a packages.json app entry from an Installomator label (public release, 2026-11-17).

Reads the label's block from an Installomator.sh the admin points to; the agent never downloads it.
Only static facts are used: `type`, `downloadURL`, `expectedTeamID`, `pkgName`, `archiveName`,
`name`. Nothing in the label is executed. Shell-computed values are never guessed: such a label is
reported as needing a manual entry.

Strict by design (public review round 3): a label is drafted only when its block consists of plain
`name=value` assignments (values may use $(...), which runs in a subshell and cannot change the
label's variables) and comments. Any other command - if/case/loops, functions (Installomator calls
some, e.g. appCustomVersion), subshells, heredocs, read/export/local, && / || chains - makes it a
manual entry, because the importer will not try to work out what that shell code does.

Mapping:
  type pkg / pkgInDmg               supported (pkgInDmg adds post_download dmg_extract)
  other types (dmg, zip, ...)       unsupported: the agent publishes signed pkgs only
  downloadURL "literal https URL"   resolver latest_redirect (version read from the pkg, rule V3)
  downloadURL $(downloadURLFromGit owner repo)
                                    resolver github_tag (asset from archiveName, else by file type)
  anything else                     manual entry

The draft still needs the Jamf IDs (patch_title_id, policy_ids) and may need a better version_rule;
`notes` says what to fill in.
"""
import re

SUPPORTED_TYPES = ("pkg", "pkgInDmg")
_HEADER_PART = re.compile(r"^([A-Za-z0-9_.-]+(?:\|[A-Za-z0-9_.-]+)*)\|\\\s*$")
_HEADER_END = re.compile(r"^([A-Za-z0-9_.-]+(?:\|[A-Za-z0-9_.-]+)*)\)\s*(?:#.*)?$")
_DISPATCH = re.compile(r'^\s*case\s+"?\$\{?label\}?"?\s+in\s*(?:#.*)?$')
_END = re.compile(r"^\s*;;\s*(?:#.*)?$")
_GIT = re.compile(r"^\"?\$\(\s*downloadURLFromGit\s+([A-Za-z0-9_.-]+)\s+([A-Za-z0-9_.-]+)\s*\)\"?\s*(?:#.*)?$")


# Labels for which packages.example.json holds a tested entry with a better resolver or version rule.
TESTED = {"nudgesuite": "nudge", "dialog": "dialog", "swiftdialog": "dialog", "adobeacrobatprodc": "acrobat",
          "microsoftoffice365": "office", "googlechromepkg": "chrome", "zoom": "zoom"}
_SPECIAL = set(".^$*+?{}[]\\|()")


def _esc(text):
    """re.escape for regex specials only (Python 3.6's re.escape also escapes spaces and '-')."""
    return "".join("\\" + c if c in _SPECIAL else c for c in text)


class LabelError(ValueError):
    pass


class LabelUnreadable(LabelError):
    """The label's block could not be delimited (unbalanced quotes, a heredoc, ...)."""


def find_label(script_text, label):
    """The lines of `label`'s case block (header excluded). Raises LabelError if absent and
    LabelUnreadable if its end cannot be found reliably. The block ends at a ';;' that stands alone
    on a complete logical line (not inside quotes, $(...), a nested case, or a continued line)."""
    lines = script_text.splitlines()
    start = next((n for n, l in enumerate(lines) if _DISPATCH.match(l)), None)
    if start is None:
        raise LabelError("no 'case $label in' line: is this Installomator.sh?")
    names = []
    i = start + 1
    while i < len(lines):
        line = lines[i]
        m = _HEADER_PART.match(line)
        if m:
            names.extend(m.group(1).split("|"))
            i += 1
            continue
        m = _HEADER_END.match(line)
        if m:
            names.extend(m.group(1).split("|"))
            if label in names:
                body = []
                for text, complete, physical in _logical(lines[i + 1:]):
                    if complete and _END.match(text):
                        return body
                    body.extend(physical)
                raise LabelUnreadable("could not find where label %r ends (unbalanced quotes, a heredoc or an "
                                      "unfinished construct); write the entry by hand" % label)
        names = []
        i += 1
    raise LabelError("label %r not found in this Installomator.sh" % label)


_BARE = re.compile(r"""^[^\s'"$`\\~{}*?\[\]()<>;&|#!]+$""")


def _literal(value):
    """The string bash would assign, if `value` is one plain literal word: bare (no quoting,
    expansion, globbing, tilde or brace syntax) or wholly in single quotes, or wholly in double
    quotes with nothing that expands or escapes inside. Anything else (mixed quoting, $, `,
    backslash, ~, {…}, globs) returns None and the label becomes a manual entry."""
    v = value
    if len(v) >= 2 and v[0] == "'" and v[-1] == "'" and "'" not in v[1:-1]:
        inner = v[1:-1]
    elif len(v) >= 2 and v[0] == '"' and v[-1] == '"' and not any(c in v[1:-1] for c in '"$`\\'):
        inner = v[1:-1]
    elif _BARE.match(v):
        inner = v
    else:
        return None
    if any(c in inner for c in "\n\t"):
        return None
    return inner


USED = ("type", "downloadURL", "expectedTeamID", "pkgName", "archiveName", "name")
_PLAIN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
_WORD_END = " \t\n;&|()<>"


def _word_at(text, i, word):
    """True if `word` starts at text[i] as a whole shell word."""
    if not text.startswith(word, i):
        return False
    before = text[i - 1] if i else " "
    after = text[i + len(word)] if i + len(word) < len(text) else " "
    return (before in _WORD_END or before == "(") and after in _WORD_END


def _scan(text):
    """Split shell text into top-level statements on newline ; & && || | . Quotes, $(...), (...),
    backticks and case...esac blocks (at any level, so a case arm's ')' and ';;' don't end anything)
    are kept whole; double quotes may contain $(...) with its own quotes, as bash allows.
    Returns (list of (statement, after_and_or), complete). `after_and_or` marks a statement that runs
    only if another succeeded or failed; `complete` is False if anything is still open at the end."""
    out, cur, stack, i, cond = [], [], [], 0, False
    n = len(text)
    while i < n:
        c, top = text[i], (stack[-1] if stack else None)
        two = text[i:i + 2]
        if top == "'":
            cur.append(c)
            if c == "'":
                stack.pop()
        elif top == "`":
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1])
                i += 1
            elif c == "`":
                stack.pop()
        elif top == '"':
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1])
                i += 1
            elif two == "$(":
                stack.append("$(")
                cur.append("(")
                i += 1
            elif c == "`":
                stack.append("`")
            elif c == '"':
                stack.pop()
        else:                                   # top level, or inside $( ), ( ) or case
            if c == "\\" and i + 1 < n:
                cur.append(text[i:i + 2])
                i += 1
            elif c in "'\"`":
                stack.append(c)
                cur.append(c)
            elif two == "$(":
                stack.append("$(")
                cur.append("$(")
                i += 1
            elif _word_at(text, i, "case"):
                stack.append("case")
                cur.append("case")
                i += 3
            elif top == "case" and _word_at(text, i, "esac"):
                stack.pop()
                cur.append("esac")
                i += 3
            elif top == "case" and c in "()":
                cur.append(c)                   # a case arm's pattern brackets
            elif c == "(" and top is None and not "".join(cur).strip():
                stack.append("(")               # a subshell at the start of a statement
                cur.append(c)
            elif c == "(" and top in ("$(", "("):
                stack.append("(")
                cur.append(c)
            elif c == ")" and top in ("$(", "("):
                stack.pop()
                cur.append(c)
            elif c == "#" and (not cur or cur[-1][-1:].isspace() or cur[-1] in "(;"):
                while i < n and text[i] != "\n":      # comment to end of line
                    i += 1
                continue
            elif top is None and c in ";&|\n":
                if "".join(cur).strip():
                    out.append(("".join(cur).strip(), cond))
                cur = []
                if two in ("&&", "||"):
                    cond = True
                    i += 1
                elif two == ";;":
                    out.append((";;", False))
                    cond = False
                    i += 1
                elif c in ";\n" or c == "&":
                    cond = False
                    if c == "&":
                        out.append(("&", False))     # a background job: not a plain assignment
            else:
                cur.append(c)
        i += 1
    if "".join(cur).strip():
        out.append(("".join(cur).strip(), cond))
    return out, not stack


def _logical(lines):
    """Yield (text, complete, physical_lines): physical lines joined while a trailing backslash, a
    pending && / || / |, or anything _scan sees as open continues the statement."""
    buf = []
    for line in lines:
        buf.append(line)
        text = "\n".join(buf)
        stripped = re.sub(r"\s+#[^'\"]*$", "", text).rstrip()
        if stripped.endswith("\\") or stripped.endswith(("&&", "||", "|")):
            continue
        if _scan(text)[1]:
            yield text, True, buf
            buf = []
    if buf:
        yield "\n".join(buf), False, buf


def logical_lines(body):
    for text, complete, _ in _logical(body):
        yield text, complete


def _first_word(stmt):
    return stmt.split(None, 1)[0] if stmt.split() else ""


def _words(stmt):
    """Split a statement into shell words on unquoted whitespace (quotes and $(...) kept whole)."""
    words, cur, stack, i = [], [], [], 0
    while i < len(stmt):
        c, top = stmt[i], (stack[-1] if stack else None)
        if top == "'":
            if c == "'":
                stack.pop()
        elif top in ('"', "`"):
            if c == "\\":
                cur.append(c)
                i += 1
                c = stmt[i] if i < len(stmt) else ""
            elif c == top:
                stack.pop()
            elif top == '"' and stmt[i:i + 2] == "$(":
                stack.append("$(")
        elif c == "\\":
            cur.append(c)
            i += 1
            c = stmt[i] if i < len(stmt) else ""
        elif c in "'\"`":
            stack.append(c)
        elif stmt[i:i + 2] == "$(":
            stack.append("$(")
            cur.append(c)
            i += 1
            c = "("
        elif c == "(" and (top in ("$(", "(") or (top is None and cur and cur[-1] == "=")):
            stack.append("(")                   # nested parens, or an array: name=( ... )
        elif c == ")" and top in ("$(", "("):
            stack.pop()
        elif c.isspace() and not stack:
            if cur:
                words.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    if cur:
        words.append("".join(cur))
    return words


def _plain(stmt):
    """True when `stmt` is exactly one `name=value` word: no command, redirection or second word
    (so `IFS= read -r downloadURL` and `v=x downloadURL=...` are not plain)."""
    w = _words(stmt)
    return len(w) == 1 and bool(_PLAIN.match(w[0]))


def strict_problem(body):
    """None if the block is only comments and plain `name=value` assignments, else a short reason.
    The reason names at most the first word of the offending command, never a value."""
    for text, complete in logical_lines(body):
        if not complete:
            return "unbalanced quotes, a heredoc or an unfinished construct"
        stmts = _scan(text)[0]
        if not stmts:
            continue
        if len(stmts) != 1 or stmts[0][1] or not _plain(stmts[0][0]):
            first = next((s for s, c in stmts if not _plain(s) or c), stmts[0][0])
            word = re.sub(r"[^A-Za-z0-9_(){}\[\]-]", "", _first_word(first))[:30] or "compound"
            return "a command it does not model (%r)" % word
    joined = "\n".join(body)
    if re.search(r"\$\(\(|\$\[|(^|[\s;])\(\(", joined):
        return "arithmetic ($((...)), $[...] or ((...)), which can change variables"
    for key in USED:
        if (re.search(r"\$\{\s*%s\s*:?[=?]" % key, joined)
                or re.search(r"\(\(.*\b%s\s*[-+*/%%]?=" % key, joined)):
            return "%s assigned inside an expansion" % key
    return None


def assignments(body):
    """{name: [raw value, ...]} for the plain top-level assignments in the block (best effort; only
    trusted after strict_problem(body) is None)."""
    out = {}
    for text, complete in logical_lines(body):
        if not complete:
            continue
        for stmt, cond in _scan(text)[0]:
            m = _PLAIN.match(stmt)
            if m and not cond:
                out.setdefault(m.group(1), []).append(m.group(2))
    return out


def glob_to_regex(glob):
    """Installomator's archiveName glob (`Nudge_Suite-[0-9.]*.pkg`) as an anchored regex."""
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            j = glob.find("]", i + 2)                     # a ']' right after '[' (or '[!') is literal
            if j == -1:
                out.append(_esc(c))
            else:
                inner = glob[i + 1:j]
                neg = inner[:1] in ("!", "^")
                if neg:
                    inner = inner[1:]
                inner = inner.replace("\\", "\\\\")
                if inner.startswith("^"):
                    inner = "\\" + inner
                out.append("[" + ("^" if neg else "") + inner + "]")
                i = j
        else:
            out.append(_esc(c))
        i += 1
    return "^" + "".join(out) + "$"


def _prefix(name, label):
    base = re.sub(r"[^A-Za-z0-9]", "", name or "") or re.sub(r"[^A-Za-z0-9]", "", label)
    return "jds-" + base[:90]


def draft(script_text, label):
    """{'status': 'draft'|'manual'|'unsupported', 'entry': dict|None, 'notes': [str]}.
    Raises LabelError when the label is not in the file."""
    try:
        d = _draft(script_text, label)
    except LabelUnreadable as e:
        d = {"status": "manual", "entry": None, "notes": [str(e)]}
    if d["status"] != "draft" and label in TESTED:
        d["notes"].append("packages.example.json has a tested entry for this app (label %r); use it" % TESTED[label])
    return d


def _draft(script_text, label):
    body = find_label(script_text, label)
    a = assignments(body)

    notes = []

    def single(key):
        vals = a.get(key, [])
        if len(vals) != 1:
            return None, len(vals)
        return vals[0], 1

    (typ, n) = single("type")
    typ_v = _literal(typ) if typ else None
    if typ_v is None:
        return {"status": "manual", "entry": None,
                "notes": ["'type' is set %d times or computed; write the entry by hand" % n]}
    if typ_v not in SUPPORTED_TYPES:
        return {"status": "unsupported", "entry": None,
                "notes": ["type %r: jamf-dp-sync publishes signed pkgs only (pkg, pkgInDmg); "
                          "an app bundle in a %s would need repackaging" % (typ_v, typ_v)]}
    problem = strict_problem(body)
    if problem:
        return {"status": "manual", "entry": None,
                "notes": ["the label has %s; only labels made of plain name=value lines are drafted, "
                          "so write the entry by hand" % problem]}

    (team, n) = single("expectedTeamID")
    team_v = _literal(team) if team else None
    if not team_v or not re.match(r"^[A-Z0-9]{10}$", team_v):
        return {"status": "manual", "entry": None,
                "notes": ["expectedTeamID missing, repeated or computed; the agent needs the Team ID to verify"]}

    (url, n) = single("downloadURL")
    if url is None:
        return {"status": "manual", "entry": None,
                "notes": ["downloadURL is set %d times (e.g. per CPU architecture or by condition); "
                          "write the entry by hand" % n]}
    name_v = _literal((a.get("name") or [""])[0]) or label
    entry = {"label": re.sub(r"[^a-z0-9_-]", "-", label.lower())[:64], "mode": "sync"}

    git = _GIT.match(url.strip())
    lit = _literal(url)
    if git:
        entry["resolver"] = "github_tag"
        entry["repo"] = "%s/%s" % (git.group(1), git.group(2))
        arch = a.get("archiveName", [])
        arch_v = _literal(arch[0]) if len(arch) == 1 else None
        if arch and not arch_v:
            return {"status": "manual", "entry": None,
                    "notes": ["archiveName is repeated or computed; write asset_regex by hand"]}
        if arch_v:
            entry["asset_regex"] = glob_to_regex(arch_v)
        else:
            ext = "dmg" if typ_v == "pkgInDmg" else "pkg"
            entry["asset_regex"] = r"\.%s$" % ext
            notes.append("asset_regex %r matches any .%s asset; the release must have exactly one" % (
                entry["asset_regex"], ext))
        notes.append("github_tag looks up the tag 'v<version>'; check the repo tags its releases that way")
        notes.append("patch_title_id may stay null for a GitHub app: the release tag is then the version "
                     "source (set a GITHUB_TOKEN)")
    elif lit and lit.startswith("https://") and not re.search(r"[\s<>\"{}|\\^`]", lit):   # RFC 3986: never in a URL
        entry["resolver"] = "latest_redirect"
        entry["url"] = lit
        notes.append("latest_redirect: the version is read from the downloaded pkg; if the vendor has a "
                     "versioned URL, a url_template entry is more exact")
    else:
        return {"status": "manual", "entry": None,
                "notes": ["downloadURL is computed by shell code or not https; never guessed. "
                          "Find the vendor URL and write the entry by hand"]}

    entry["name_prefix"] = _prefix(name_v, label)
    entry["team_id"] = team_v
    entry["patch_title_id"] = None
    entry["version_rule"] = "dotted"
    entry["policy_ids"] = []
    entry["add_if_missing"] = True

    if typ_v == "pkgInDmg":
        pkg = a.get("pkgName", [])
        pkg_v = _literal(pkg[0]) if len(pkg) == 1 else None
        if pkg and not pkg_v:
            return {"status": "manual", "entry": None,
                    "notes": ["pkgName is repeated or computed; write inner_path_regex by hand"]}
        if pkg_v:
            inner = "(^|/)" + _esc(pkg_v.split("/")[-1]) + "$"
        else:
            inner = r"(^|/)[^/]+\.pkg$"
            notes.append("no pkgName in the label: inner_path_regex matches any pkg; the DMG must hold exactly one")
        entry["post_download"] = {"type": "dmg_extract", "inner_path_regex": inner}
        notes.append("pkgInDmg needs 7-Zip (7zz) on the server; some APFS DMGs cannot be opened, "
                     "run a dry run to find out")

    notes.insert(0, "fill in: policy_ids (the Jamf policy for this app)"
                 + ("" if entry["resolver"] == "github_tag" else " and patch_title_id (its Patch Management title)"))
    notes.append("version_rule 'dotted' assumed; check the patch title's version format")
    if label in TESTED:
        notes.insert(0, "packages.example.json has a tested entry for this app (label %r) with a better "
                        "resolver or version rule; prefer it to this draft" % TESTED[label])
    return {"status": "draft", "entry": entry, "notes": notes}
