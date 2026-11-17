"""A15: every row of the section 7 normalisation table.

Cells the spec marks "confirm" are listed in PENDING and reported as skipped until real data
fills them (they become fixtures when confirmed).
"""
import unittest

from jamf_dp_sync import versions as V

# (app, rule, source kind, input, expected key, expected build)
TABLE = [
    # Nudge
    ("nudge", "dotted", "tag", "v2.1.4.81863", (2, 1, 4, 81863), None),
    ("nudge", "dotted", "pkg", "2.1.4.81863", (2, 1, 4, 81863), None),
    # swiftDialog
    ("dialog", "swiftdialog", "patch", "3.1.1", (3, 1, 1), None),
    ("dialog", "swiftdialog", "patch", "3.1.1.5000", (3, 1, 1), 5000),
    ("dialog", "swiftdialog", "tag", "v3.1.1", (3, 1, 1), None),
    ("dialog", "swiftdialog", "asset", "dialog-3.1.1-5000.pkg", (3, 1, 1), 5000),
    # Acrobat
    ("acrobat", "acrobat", "patch", "26.003.22075", (26, 3, 22075), None),
    ("acrobat", "acrobat", "path", "2600322075", (26, 3, 22075), None),
    ("acrobat", "acrobat", "path", "pub/adobe/acrobat/mac/AcrobatDC/2600322075", (26, 3, 22075), None),
    ("acrobat", "acrobat", "file", "AcrobatDC2600322075_MUI.pkg", (26, 3, 22075), None),
    ("acrobat", "acrobat", "actionmatrix", "26.3.22074", (26, 3, 22074), None),
    # Zoom
    ("zoom", "zoom", "url", "7.2.5.90525", (7, 2, 5, 90525), None),
    # Chrome
    ("chrome", "dotted", "patch", "142.0.7444.60", (142, 0, 7444, 60), None),
    # Confirmed from dev Jamf Pro 11.33.0 patch titles, 2026-11-09 (DECISIONS F4)
    ("nudge", "dotted", "patch", "2.1.4.81863", (2, 1, 4, 81863), None),
    ("dialog", "swiftdialog", "patch", "3.1.1", (3, 1, 1), None),
    ("zoom", "zoom", "patch", "7.2.5 (90525)", (7, 2, 5, 90525), None),
    ("chrome", "dotted", "patch", "158.0.8127.18", (158, 0, 8127, 18), None),
    ("googledrive", "dotted", "patch", "133.0.2", (133, 0, 2), None),
    ("office", "office", "patch", "16.114.26110224", (16, 114, 26110224), None),
    # Confirmed from real pkgs downloaded in the Lima VM, 2026-11-09 (DECISIONS F7)
    ("dialog", "swiftdialog", "pkg", "3.1.1", (3, 1, 1), None),
    ("zoom", "zoom", "pkg", "7.2.5.90525", (7, 2, 5, 90525), None),
    ("chrome", "dotted", "pkg", "157.0.8103.39", (157, 0, 8103, 39), None),
    ("acrobat", "acrobat", "pkg", "26.003.22075", (26, 3, 22075), None),
    ("office", "office", "pkg", "16.114.26110224", (16, 114, 26110224), None),
    ("office", "office", "url", "Microsoft_365_and_Office_16.114.26110224_Installer.pkg", None, None),
]

# Cells marked "confirm" in section 7: (app, source kind, reason).
PENDING = [
]


class NormalisationTable(unittest.TestCase):
    def test_rows(self):
        from jamf_dp_sync.resolvers.latest_redirect import version_from_url
        for app, rule, kind, value, key, build in TABLE:
            with self.subTest(app=app, kind=kind, value=value):
                if kind == "url" and key is None:  # versioned final URL (latest_redirect rule 1)
                    v = version_from_url("https://res.public.onecdn.static.microsoft/x/" + value, V.get_rule(rule))
                    self.assertEqual(v.key, (16, 114, 26110224))
                    continue
                v = V.get_rule(rule).parse(value)
                self.assertEqual(v.key, key)
                self.assertEqual(v.build, build)

    def test_zoom_patch_title_form_parses(self):
        # The form is unconfirmed (PENDING) but the rule must accept it as written in section 7.
        self.assertEqual(V.get_rule("zoom").parse("7.2.5 (90525)").key, (7, 2, 5, 90525))
        self.assertEqual(V.get_rule("zoom").parse("7.2.5 (90525)"), V.get_rule("zoom").parse("7.2.5.90525"))


def _make_pending(app, kind, reason):
    @unittest.skip("pending (section 7 'confirm'): %s / %s: %s" % (app, kind, reason))
    def test(self):
        pass
    return test


class PendingCells(unittest.TestCase):
    pass


for _app, _kind, _reason in PENDING:
    setattr(PendingCells, "test_pending_%s_%s" % (_app, _kind), _make_pending(_app, _kind, _reason))


class Formatting(unittest.TestCase):
    def test_tags(self):
        self.assertEqual(V.get_rule("dotted").format(V.get_rule("dotted").parse("2.1.4.81863"), "tag"), "v2.1.4.81863")
        sd = V.get_rule("swiftdialog")
        self.assertEqual(sd.format(sd.parse("3.1.1.5000"), "tag"), "v3.1.1")

    def test_zoom_url(self):
        z = V.get_rule("zoom")
        self.assertEqual(z.format(z.parse("7.2.5 (90525)"), "url"), "7.2.5.90525")

    def test_acrobat_vercode_and_name(self):
        a = V.get_rule("acrobat")
        v = a.parse("26.3.22075")
        self.assertEqual(a.format(v, "url"), "2600322075")
        self.assertEqual(a.format(v, "name"), "26.003.22075")
        with self.assertRaises(ValueError):
            a.format(v, "tag")

    def test_swiftdialog_name_keeps_build(self):
        sd = V.get_rule("swiftdialog")
        self.assertEqual(sd.format(sd.parse("dialog-3.1.1-5000.pkg"), "name"), "3.1.1")
        self.assertEqual(sd.format(sd.parse("3.1.1"), "name"), "3.1.1")


class Rejects(unittest.TestCase):
    def test_garbage(self):
        cases = [("dotted", ""), ("dotted", "2.1.x"), ("dotted", "latest"), ("swiftdialog", "3.1"),
                 ("acrobat", "26.3"), ("acrobat", "123456789"), ("zoom", "7.2.5"), ("zoom", "7.2.5 ()")]
        for rule, value in cases:
            with self.subTest(rule=rule, value=value):
                with self.assertRaises(ValueError):
                    V.get_rule(rule).parse(value)

    def test_unknown_rule(self):
        with self.assertRaises(ValueError):
            V.get_rule("semver")


class Comparison(unittest.TestCase):
    def test_v2_exact(self):
        d = V.get_rule("dotted")
        self.assertTrue(V.accept_exact(d.parse("2.1.4.81863"), d.parse("v2.1.4.81863")))
        self.assertFalse(V.accept_exact(d.parse("2.1.4.81862"), d.parse("2.1.4.81863")))

    def test_v2_swiftdialog_ignores_build(self):
        sd = V.get_rule("swiftdialog")
        self.assertTrue(V.accept_exact(sd.parse("3.1.1.5000"), sd.parse("v3.1.1")))

    def test_v3_latest(self):
        d = V.get_rule("dotted")
        target = d.parse("142.0.7444.60")
        self.assertTrue(V.accept_latest(d.parse("142.0.7444.60"), target))
        self.assertTrue(V.accept_latest(d.parse("142.0.7444.61"), target))
        self.assertFalse(V.accept_latest(d.parse("142.0.7444.59"), target))

    def test_numeric_not_lexical(self):
        d = V.get_rule("dotted")
        self.assertLess(d.parse("2.9"), d.parse("2.10"))

    def test_acrobat_zero_padding_irrelevant(self):
        a = V.get_rule("acrobat")
        self.assertEqual(a.parse("26.003.22075"), a.parse("26.3.22075"))
        self.assertGreater(a.parse("26.003.22075"), a.parse("26.3.22074"))


class PublishedNames(unittest.TestCase):
    def test_round_trip(self):
        for rule, prefix, value in [("dotted", "NudgeSuite", "2.1.4.81863"),
                                    ("swiftdialog", "swiftDialog", "3.1.1.5000"),
                                    ("acrobat", "AdobeAcrobatPro", "26.003.22075"),
                                    ("zoom", "ZoomWorkplace", "7.2.5 (90525)")]:
            with self.subTest(rule=rule):
                r = V.get_rule(rule)
                v = r.parse(value)
                name = V.published_name(prefix, r, v)
                self.assertTrue(name.startswith(prefix + "-") and name.endswith(".pkg"))
                back = V.version_from_published_name(name, prefix, r)
                self.assertEqual(back, v)

    def test_v4_rejects_foreign_names(self):
        d = V.get_rule("dotted")
        self.assertIsNone(V.version_from_published_name("Nudge_Suite-2.1.4.pkg", "NudgeSuite", d))
        self.assertIsNone(V.version_from_published_name("NudgeSuite-latest.pkg", "NudgeSuite", d))
        self.assertIsNone(V.version_from_published_name("NudgeSuite-2.1.4.dmg", "NudgeSuite", d))


if __name__ == "__main__":
    unittest.main()
