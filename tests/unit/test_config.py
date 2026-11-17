"""Section 5: config loading and validation."""
import copy
import json
import os
import tempfile
import unittest

from jamf_dp_sync import config
from jamf_dp_sync.errors import ConfigError

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXAMPLE = os.path.join(ROOT, "packages.example.json")


def example():
    with open(EXAMPLE) as f:
        return json.load(f)


class ExampleConfig(unittest.TestCase):
    def test_example_is_valid(self):
        cfg = config.load(EXAMPLE)
        self.assertEqual(len(cfg.apps), 8)  # Google Drive left the sync list after D12 failed
        self.assertEqual([a["label"] for a in cfg.apps if a["mode"] == "monitor"], ["vpnclient", "sensor"])

    def test_defaults_applied(self):
        cfg = config.load(EXAMPLE)
        nudge = cfg.app("nudge")
        self.assertEqual(nudge["retain"], 2)
        self.assertEqual(nudge["alert_after_days"], 3)
        self.assertTrue(nudge["add_if_missing"])          # the example targets new, empty policies
        raw = example()
        del raw["apps"][0]["add_if_missing"]
        self.assertFalse(config.validate(raw).app("nudge")["add_if_missing"])   # the default
        self.assertTrue(cfg["log_file"].startswith(os.path.expanduser("~")))
        self.assertEqual(cfg.tool("openssl"), "/usr/bin/openssl")
        self.assertEqual(cfg.tool("7zz"), os.path.expanduser("~/bin/7zz"))

    def test_per_app_override(self):
        raw = example()
        raw["apps"][0]["retain"] = 3
        self.assertEqual(config.validate(raw).app("nudge")["retain"], 3)


class Rejections(unittest.TestCase):
    def assertInvalid(self, raw, fragment):
        with self.assertRaises(ConfigError) as cm:
            config.validate(raw)
        self.assertIn(fragment, str(cm.exception))

    def test_unknown_global_key(self):
        raw = example(); raw["dp_packages"] = "/x"
        self.assertInvalid(raw, "unknown global key 'dp_packages'")

    def test_missing_global_key(self):
        raw = example(); del raw["staging_dir"]
        self.assertInvalid(raw, "missing required global key 'staging_dir'")

    def test_unknown_app_key(self):
        raw = example(); raw["apps"][0]["teamid"] = "T4SK8ZXCXG"
        self.assertInvalid(raw, "unknown key 'teamid'")

    def test_resolver_key_on_wrong_resolver(self):
        raw = example(); raw["apps"][2]["repo"] = "a/b"  # acrobat is adobe_arm_manifest
        self.assertInvalid(raw, "unknown key 'repo'")

    def test_missing_app_key(self):
        raw = example(); del raw["apps"][1]["team_id"]
        self.assertInvalid(raw, "missing required key 'team_id'")

    def test_missing_resolver_key(self):
        raw = example(); del raw["apps"][2]["item_id"]
        self.assertInvalid(raw, "missing required key 'item_id'")

    def test_duplicate_label(self):
        raw = example()
        dup = copy.deepcopy(raw["apps"][0]); dup["name_prefix"] = "Other"
        raw["apps"].append(dup)
        self.assertInvalid(raw, "duplicate label 'nudge'")

    def test_duplicate_json_key(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"retain": 2, "retain": 3}')
        try:
            with self.assertRaises(ConfigError) as cm:
                config.load(f.name)
            self.assertIn("duplicate JSON key 'retain'", str(cm.exception))
        finally:
            os.unlink(f.name)

    def test_bad_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{nope")
        try:
            with self.assertRaises(ConfigError):
                config.load(f.name)
        finally:
            os.unlink(f.name)

    def test_unknown_mode_and_resolver(self):
        raw = example(); raw["apps"][0]["mode"] = "mirror"
        self.assertInvalid(raw, "mode must be 'sync' or 'monitor'")
        raw = example(); raw["apps"][0]["resolver"] = "ftp"
        self.assertInvalid(raw, "unknown resolver 'ftp'")

    def test_wrong_types(self):
        raw = example(); raw["apps"][0]["policy_ids"] = "101"
        self.assertInvalid(raw, "'policy_ids' must be list")
        raw = example(); raw["retain"] = True
        self.assertInvalid(raw, "global key 'retain' must be int")
        raw = example(); raw["apps"][0]["policy_ids"] = [True]
        self.assertInvalid(raw, "positive integers")

    def test_null_patch_title_only_for_github(self):
        raw = example(); raw["apps"][2]["patch_title_id"] = None
        self.assertInvalid(raw, "null only for github_tag apps")

    def test_monitor_rejects_sync_keys(self):
        raw = example(); raw["apps"][6]["team_id"] = "ABCDEFGHIJ"
        self.assertInvalid(raw, "unknown key 'team_id' for mode 'monitor'")

    def test_bad_regex_team_and_url(self):
        raw = example(); raw["apps"][0]["asset_regex"] = "("
        self.assertInvalid(raw, "asset_regex is not a valid regex")
        raw = example(); raw["apps"][0]["team_id"] = "t4sk8zxcxg"
        self.assertInvalid(raw, "team_id must be 10")
        raw = example(); raw["apps"][4]["url"] = "http://dl.google.com/x.pkg"
        self.assertInvalid(raw, "must be an https:// URL")
        raw = example(); raw["apps"][5]["url_template"] = "https://cdn.zoom.us/prod/latest.pkg"
        self.assertInvalid(raw, "must contain {version}")
        raw = example(); raw["apps"][5]["url_template"] = "https://cdn.zoom.us/{v}/{version}.pkg"
        self.assertInvalid(raw, "may only use {version}")

    def test_pin_must_parse(self):
        raw = example(); raw["apps"][5]["pin"] = "latest"
        self.assertInvalid(raw, "pin 'latest' does not parse")
        raw = example(); raw["apps"][5]["pin"] = "7.2.5 (90525)"
        self.assertEqual(config.validate(raw).app("zoom")["pin"], "7.2.5 (90525)")

    def test_post_download(self):
        def with_drive():
            raw = example()
            with open(os.path.join(ROOT, "tests", "fixtures", "googledrive_app.json")) as f:
                raw["apps"].append(json.load(f))
            return raw
        config.validate(with_drive())
        raw = with_drive(); raw["apps"][-1]["post_download"] = {"type": "unzip"}
        self.assertInvalid(raw, "post_download.type must be one of")
        raw = with_drive(); raw["apps"][-1]["post_download"] = {"type": "dmg_extract"}
        self.assertInvalid(raw, "post_download missing 'inner_path_regex'")

    def test_name_prefix_collisions(self):
        raw = example(); raw["apps"][1]["name_prefix"] = "jds-NudgeSuite"
        self.assertInvalid(raw, "share name_prefix 'jds-NudgeSuite'")
        raw = example(); raw["apps"][1]["name_prefix"] = "jds-NudgeSuite-Beta"
        self.assertInvalid(raw, "ambiguous")

    def test_test_prefix_allowed(self):
        raw = example()
        for a in raw["apps"]:
            if "name_prefix" in a:
                a["name_prefix"] = "TEST-" + a["name_prefix"]
        config.validate(raw)

    def test_staging_inside_share_rejected(self):
        raw = example(); raw["staging_dir"] = raw["dp_packages_dir"]
        self.assertInvalid(raw, "inside the share")
        raw = example(); raw["staging_dir"] = os.path.dirname(raw["dp_packages_dir"]) + "/staging"
        self.assertInvalid(raw, "inside the share")

    def test_relative_path_rejected(self):
        raw = example(); raw["staging_dir"] = "staging"
        self.assertInvalid(raw, "'staging_dir' must be an absolute path")

    def test_monitor_needs_version_group(self):
        raw = example(); del raw["apps"][6]["replace_regex"]
        self.assertInvalid(raw, "monitor apps need replace_regex")
        raw = example(); raw["apps"][7]["replace_regex"] = r"^Sensor-[0-9.]+\.pkg$"
        self.assertInvalid(raw, "(?P<version>...) group")

    def test_unknown_tool(self):
        raw = example(); raw["tools"]["curl"] = "/usr/bin/curl"
        self.assertInvalid(raw, "unknown tool 'curl'")

    def test_all_errors_reported_together(self):
        raw = example(); raw["bogus"] = 1; del raw["apps"][0]["label"]
        with self.assertRaises(ConfigError) as cm:
            config.validate(raw)
        msg = str(cm.exception)
        self.assertIn("bogus", msg)
        self.assertIn("'label'", msg)


if __name__ == "__main__":
    unittest.main()
