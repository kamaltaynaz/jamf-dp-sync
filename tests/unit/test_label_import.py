"""label-import: drafting packages.json entries from Installomator labels (public release, 2026-11-17).
The script below is a synthetic Installomator.sh fragment in the real file's shape."""
import io
import json
import os
import re
import tempfile
import unittest

from jamf_dp_sync import cli, label_import

SCRIPT = r'''
downloadURLFromGit() { # $1 git user name, $2 git repo name
    case $type in
        pkg)
            filetype=pkg
            ;;
    esac
}
case $label in
nudgesuite)
    name="Nudge Suite"
    type="pkg"
    archiveName="Nudge_Suite-[0-9.]*.pkg"
    appNewVersion=$(versionFromGit macadmins Nudge )
    downloadURL=$(downloadURLFromGit macadmins Nudge )
    expectedTeamID="T4SK8ZXCXG"
    ;;
dialog|\
swiftdialog)
    name="Dialog"
    type="pkg"
    downloadURL="$(downloadURLFromGit swiftDialog swiftDialog)"
    expectedTeamID="PWA5E9TQ59"
    ;;
examplepkg)
    name="Example App"
    type="pkg"
    downloadURL="https://downloads.example.com/latest/Example.pkg" # vendor latest
    appNewVersion=$(curl -fsIL "$downloadURL" | grep -i location)
    expectedTeamID="ABCDE12345"
    ;;
exampledmgpkg)
    name="Example Suite"
    type="pkgInDmg"
    downloadURL="https://downloads.example.com/latest/Suite.dmg"
    pkgName="Installers/Install Example (Suite).pkg"
    expectedTeamID="ABCDE12345"
    ;;
archapp)
    name="Arch App"
    type="pkg"
    if [[ $(arch) == "arm64" ]]; then
        downloadURL="https://downloads.example.com/arm/App.pkg"
    else
        downloadURL="https://downloads.example.com/intel/App.pkg"
    fi
    expectedTeamID="ABCDE12345"
    ;;
computed)
    name="Computed"
    type="pkg"
    downloadURL=$(curl -fs https://example.com/feed | grep pkg)
    expectedTeamID="ABCDE12345"
    ;;
appindmg)
    name="Some App"
    type="dmg"
    downloadURL="https://downloads.example.com/App.dmg"
    expectedTeamID="ABCDE12345"
    ;;
noteam)
    name="No Team"
    type="pkg"
    downloadURL="https://downloads.example.com/x.pkg"
    ;;
esac
'''


class Draft(unittest.TestCase):
    def d(self, label):
        return label_import.draft(SCRIPT, label)

    def test_github_with_archive_name(self):
        r = self.d("nudgesuite")
        self.assertEqual(r["status"], "draft")
        e = r["entry"]
        self.assertEqual((e["resolver"], e["repo"], e["asset_regex"], e["team_id"]),
                         ("github_tag", "macadmins/Nudge", r"^Nudge_Suite-[0-9.].*\.pkg$", "T4SK8ZXCXG"))
        self.assertIsNone(e["patch_title_id"])
        self.assertEqual(e["name_prefix"], "jds-NudgeSuite")
        self.assertTrue(e["add_if_missing"])
        self.assertIn("tested entry", r["notes"][0])

    def test_multi_name_header(self):
        for label in ("dialog", "swiftdialog"):
            e = self.d(label)["entry"]
            self.assertEqual((e["repo"], e["asset_regex"]), ("swiftDialog/swiftDialog", r"\.pkg$"))

    def test_literal_url_is_latest_redirect(self):
        r = self.d("examplepkg")
        e = r["entry"]
        self.assertEqual((e["resolver"], e["url"]), ("latest_redirect", "https://downloads.example.com/latest/Example.pkg"))
        self.assertNotIn("post_download", e)
        self.assertIn("patch_title_id", r["notes"][0])

    def test_pkg_in_dmg(self):
        e = self.d("exampledmgpkg")["entry"]
        self.assertEqual(e["post_download"], {"type": "dmg_extract",
                                              "inner_path_regex": r"(^|/)Install Example \(Suite\)\.pkg$"})

    def test_never_guesses(self):
        for label in ("archapp", "computed", "noteam"):
            r = self.d(label)
            self.assertEqual(r["status"], "manual", label)
            self.assertIsNone(r["entry"])

    def test_app_bundles_unsupported(self):
        r = self.d("appindmg")
        self.assertEqual(r["status"], "unsupported")
        self.assertIn("repackaging", r["notes"][0])

    def test_function_case_is_not_a_label(self):
        with self.assertRaises(label_import.LabelError):
            label_import.draft(SCRIPT, "pkg")
        with self.assertRaises(label_import.LabelError):
            label_import.draft(SCRIPT, "missing")


def label(body, typ="pkg"):
    return ("case $label in\nx)\n    name=\"X\"\n    type=\"%s\"\n    expectedTeamID=\"ABCDE12345\"\n%s    ;;\nesac\n"
            % (typ, body))


class NeverGuess(unittest.TestCase):                    # public review rounds 1 and 2
    MANUAL = {
        "nested case per arch": "    case $(arch) in\n      arm64)\n        downloadURL=\"https://d.example.com/a.pkg\"\n"
                                "        ;;\n      i386)\n        downloadURL=\"https://d.example.com/i.pkg\"\n        ;;\n"
                                "    esac\n",
        "if with a word 'done'": "    if false; then echo done\n        downloadURL=https://d.example.com/arm.pkg\n    fi\n",
        "appended": "    downloadURL=\"https://d.example.com/\"\n    downloadURL+=\"$arch.pkg\"\n",
        "after &&": "    [[ $(arch) == arm64 ]] && downloadURL=\"https://d.example.com/arm.pkg\"\n",
        "export": "    downloadURL=\"https://d.example.com/a.pkg\"\n    export downloadURL=\"https://x.example.com/b.pkg\"\n",
        "process substitution": "    downloadURL=\"https://d.example.com/<(c).pkg\"\n",
        "split across lines": "    downloadURL=\"https://d.example.com/\\\nother.pkg\"\n",
        "unterminated quote": "    v=\"open\n    downloadURL=\"https://d.example.com/a.pkg\"\n",
        # Strict mode (round 3): any command other than name=value, even a harmless one.
        "closed if before": "    if true; then :; fi; echo ready\n    downloadURL=https://d.example.com/s.pkg\n",
        "loop before": "    for i in 1 2; do echo $i; done\n    downloadURL=\"https://d.example.com/s.pkg\"\n",
        "continued &&": "    [[ \"$arch\" == arm64 ]] && \\\n        downloadURL=https://d.example.com/arm.pkg\n",
        "&& then newline": "    [[ \"$arch\" == arm64 ]] &&\n        downloadURL=https://d.example.com/arm.pkg\n",
        "function": "    chooseURL() {\n        downloadURL=https://d.example.com/s.pkg\n    }\n",
        "subshell": "    (\n        downloadURL=https://d.example.com/s.pkg\n    )\n",
        "heredoc": "    cat <<'END'\n    downloadURL=https://d.example.com/s.pkg\nEND\n",
        "read": "    downloadURL=https://d.example.com/s.pkg\n    read -r downloadURL <<< \"${r:-x}\"\n",
        "default-assign expansion": "    downloadURL=https://d.example.com/s.pkg\n    v=\"${downloadURL:=https://x}\"\n",
        # Round 4: one name=value word per line; literal values only; no arithmetic.
        "IFS= read": "    downloadURL=https://d.example.com/s.pkg\n    IFS= read -r downloadURL <<< https://d.example.com/c.pkg\n",
        "second word": "    downloadURL=https://d.example.com/s.pkg\n    v=x downloadURL=https://d.example.com/c.pkg\n",
        "array then word": "    a=( x ) downloadURL=https://d.example.com/c.pkg\n    downloadURL=https://d.example.com/s.pkg\n",
        "mixed quoting": "    downloadURL=https://d.example.com/\"current.pkg\"\n",
        "tilde": "    downloadURL=~/x.pkg\n",
        "brace": "    downloadURL=https://d.example.com/{a,b}.pkg\n",
        "arithmetic ++": "    downloadURL=https://d.example.com/s.pkg\n    v=$((expectedTeamID++))\n",
        "arithmetic $[ ]": "    downloadURL=https://d.example.com/s.pkg\n    v=$[expectedTeamID=1234567890]\n",
    }

    def test_manual(self):
        for why, body in self.MANUAL.items():
            self.assertEqual(label_import.draft(label(body), "x")["status"], "manual", why)

    def test_computed_inner_names(self):
        dmg = "    downloadURL=\"https://d.example.com/x.dmg\"\n"
        self.assertEqual(label_import.draft(label(dmg + "    pkgName=\"$computed\"\n", "pkgInDmg"), "x")["status"],
                         "manual")
        git = "    downloadURL=$(downloadURLFromGit o r)\n"
        self.assertEqual(label_import.draft(label(git + "    archiveName=\"$(x)\"\n"), "x")["status"], "manual")

    def test_static_labels_still_draft(self):
        ok = {
            "multi-line version command": "    v=$(curl -fs x \\\n      | grep y)\n    downloadURL=\"https://d.example.com/s.pkg\"\n",
            "quotes inside $( ) inside quotes": "    v=\"$(curl -fsL \"https://a.example.com/x\" | cut -d '\"' -f 2)\"\n"
                                                "    downloadURL=\"https://d.example.com/s.pkg\"\n",
            "; inside quotes": "    downloadURL=\"https://d.example.com/s.pkg?a=1;b=2\"\n",
            "single-quoted": "    downloadURL='https://d.example.com/s.pkg'\n",
            "array": "    blockingProcesses=( \"A b\" C )\n    downloadURL=https://d.example.com/s.pkg\n",
        }
        for why, body in ok.items():
            d = label_import.draft(label(body), "x")
            self.assertEqual(d["status"], "draft", why)
            self.assertTrue(d["entry"]["url"].startswith("https://d.example.com/s.pkg"), why)

    def test_case_inside_substitution_does_not_end_the_label(self):     # round 3 #2
        body = ("    downloadURL=https://d.example.com/old.pkg\n    appNewVersion=$(case \"$arch\" in\n"
                "        (arm64)\n            echo 1\n            ;;\n        *)\n            echo 2\n            ;;\n"
                "    esac)\n    downloadURL=https://d.example.com/current.pkg\n")
        self.assertEqual(label_import.draft(label(body), "x")["status"], "manual")   # set twice: never guessed

    def test_quoted_hash_is_not_a_comment(self):                     # round 4 #2
        body = "    downloadURL=https://d.example.com/current.dmg\n    pkgName=\"Install #1.pkg\"\n"
        e = label_import.draft(label(body, "pkgInDmg"), "x")["entry"]
        self.assertEqual(e["post_download"]["inner_path_regex"], r"(^|/)Install #1\.pkg$")

    def test_only_labels_after_the_dispatch_line(self):               # round 4 #4
        doc = "x)\ntype=pkg\nexpectedTeamID=ABCDE12345\ndownloadURL=https://d.example.com/doc.pkg\n;;\n"
        script = "cat <<'END'\n" + doc + "END\n" + label("    downloadURL=https://d.example.com/real.pkg\n")
        self.assertEqual(label_import.draft(script, "x")["entry"]["url"], "https://d.example.com/real.pkg")
        with self.assertRaises(label_import.LabelError):
            label_import.draft(doc, "x")

    def test_glob_classes(self):
        rx = re.compile(label_import.glob_to_regex("App-[!0-9]*.pkg"))
        self.assertEqual([n for n in ("App-arm.pkg", "App-123.pkg") if rx.match(n)], ["App-arm.pkg"])
        self.assertTrue(re.match(label_import.glob_to_regex("a[]]b"), "a]b"))


class Cli(unittest.TestCase):
    def test_json_out_and_exit_code(self):
        fd, path = tempfile.mkstemp(suffix=".sh")
        self.addCleanup(os.remove, path)
        with os.fdopen(fd, "w") as f:
            f.write(SCRIPT)
        args = cli.build_parser().parse_args(["label-import", "--installomator", path, "examplepkg", "appindmg"])
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(cli.cmd_label_import(args, out, err), 1)
        self.assertEqual([e["label"] for e in json.loads(out.getvalue())], ["examplepkg"])
        self.assertIn("appindmg: unsupported", err.getvalue())
        args = cli.build_parser().parse_args(["label-import", "--installomator", path, "examplepkg"])
        self.assertEqual(cli.cmd_label_import(args, io.StringIO(), io.StringIO()), 0)


if __name__ == "__main__":
    unittest.main()
