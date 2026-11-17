"""L1 test world: the agent's whole environment, built locally (spec section 11.3).

- upstream stub serving synthetic signed pkgs for all seven sync apps in the shapes the real sources
  use (GitHub release API + expanded_assets + redirect to the asset host, a signed Adobe .arm,
  Microsoft fwlink redirect, Google direct pkg / DMG, Zoom template with Cloudflare-style 403);
- stateful Jamf Pro stub seeded with one policy per app (plus monitor apps), legacy pkgs and patch
  titles; Google Chat stub;
- a temp HOME with a 0600 env file, a config derived from packages.example.json, Packages/ and
  staging on the same filesystem, a stand-in 7zz for the DMG.

Certificates are generated per Team ID with openssl (identity only, as the agent checks).
"""
import argparse
import base64
import contextlib
import copy
import datetime
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "test", "env", "stubs"))

import gchat_stub  # noqa: E402
import jamf_stub  # noqa: E402
import upstream_stub  # noqa: E402

from jamf_dp_sync import config, logsetup, notify, runner, secrets  # noqa: E402
from tests.fakes import fake_7zz, slt_listing  # noqa: E402
from tests.xarbuild import build_xar, distribution  # noqa: E402

TEAMS = {"nudge": "T4SK8ZXCXG", "dialog": "PWA5E9TQ59", "acrobat": "JQ525L2MZD", "office": "UBF8T346G9",
         "chrome": "EQHXZ8M8AV", "zoom": "BJ4HAAB9B3", "googledrive": "EQHXZ8M8AV"}
POLICY = {"nudge": 101, "dialog": 102, "acrobat": 103, "office": 104, "chrome": 105, "zoom": 106,
          "googledrive": 107, "vpnclient": 108, "sensor": 109}
TITLE = {"nudge": 208, "dialog": 209, "acrobat": 201, "office": 202, "chrome": 203, "zoom": 204,
         "googledrive": 205, "vpnclient": 206, "sensor": 207}
# label -> (patch-title text, pkg product version) for the starting world
START = {"nudge": ("2.1.4.81863", "2.1.4.81863"), "dialog": ("3.1.1", "3.1.1.5000"),
         "acrobat": ("26.003.22075", "26.003.22075"), "office": ("16.114.26110224", "16.114.26110224"),
         "chrome": ("142.0.7444.60", "142.0.7444.60"), "zoom": ("7.2.5 (90525)", "7.2.5.90525"),
         "googledrive": ("133.0.2", "133.0.2")}
LEGACY = {"nudge": (200, "Nudge_Suite-2.1.2.81856.pkg"), "dialog": (201, "dialog-3.1.0-4000.pkg"),
          "chrome": (202, "GoogleChrome-141.0.1.1.pkg")}
BRANDING = (11, "Org-Branding-1.2.pkg")
DMG_MEMBER = "Install Google Drive/GoogleDrive.pkg"

_CERTS = {}


def team_cert(team, workdir):
    if team not in _CERTS:
        key, der = os.path.join(workdir, "k.pem"), os.path.join(workdir, "%s.der" % team)
        subprocess.check_call(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-days", "30",
             "-subj", "/UID=%s/CN=Developer ID Installer: L1 Test (%s)/OU=%s/O=L1 Test/C=US" % (team, team, team),
             "-outform", "DER", "-out", der], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(der, "rb") as f:
            _CERTS[team] = f.read()
        os.unlink(key)
    return _CERTS[team]


def policy_xml(pid, name, packages):
    pk = "".join("<package><id>%d</id><name>%s</name><action>Install</action><fut>false</fut>"
                 "<feu>false</feu><update_autorun>false</update_autorun></package>" % p for p in packages)
    return ("<policy><general><id>%d</id><name>%s</name><trigger_other>install-x-jsm</trigger_other></general>"
            "<package_configuration><packages><size>%d</size>%s</packages>"
            "<distribution_point>default</distribution_point></package_configuration></policy>"
            % (pid, name, len(packages), pk))


class World(object):
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="jds-l1-")
        self.home = os.path.join(self.dir, "home")
        self.files = os.path.join(self.dir, "upstream")
        self.share = os.path.join(self.dir, "srv", "shares", "jamf")
        self.dp = os.path.join(self.share, "Packages")
        self.staging = os.path.join(self.dir, "srv", "jamf-dp-sync-staging")
        self.tools = os.path.join(self.dir, "tools")
        for d in (self.home, self.files, self.dp, self.staging, self.tools):
            os.makedirs(d)
        self.upstream_srv, self.up, self.up_url = upstream_stub.start()
        self.chat_srv, self.chat, self.chat_url = gchat_stub.start()
        self.jamf_srv, self.jamf, self.jamf_url = jamf_stub.start(self._seed())
        self.versions = {}
        for label, (title, pkg) in START.items():
            self.set_upstream(label, pkg)
        for pid, name in (LEGACY.values()):
            self._hand_file(name)
        self._hand_file(BRANDING[1])
        self.cfg_path = self._write_config()
        self._write_env()
        self.env = {"HOME": self.home, "JDS_TEST_URL_MAP": upstream_stub.url_map(self.up_url),
                    "JDS_TEST_FAULTS": ""}
        self._old_env = None
        self._old_backoff = notify.BACKOFF

    # ---------------------------------------------------------------- setup
    def _seed(self):
        pkgs = [{"id": str(BRANDING[0]), "packageName": BRANDING[1], "fileName": BRANDING[1], "notes": ""}]
        for pid, name in LEGACY.values():
            pkgs.append({"id": str(pid), "packageName": name, "fileName": name, "notes": ""})
        policies = {}
        for label, pid in POLICY.items():
            entries = [BRANDING]
            if label in LEGACY:
                entries.append(LEGACY[label])
            policies[str(pid)] = policy_xml(pid, "install-%s-jsm" % label, entries)
        titles = []
        for label, tid in TITLE.items():
            text = START[label][0] if label in START else "1.0"
            titles.append({"id": str(tid), "displayName": label, "softwareTitleId": str(tid), "packages": [],
                           "definitions": [{"version": text, "absoluteOrderId": "0",
                                            "releaseDate": "2026-11-01T00:00:00Z"}]})
        return {"clients": {"jamf-dp-sync-test": "stub-secret"}, "packages": pkgs,
                "policies": policies, "patch_titles": titles}

    def _hand_file(self, name):
        with open(os.path.join(self.dp, name), "wb") as f:
            f.write(b"hand-uploaded " + name.encode())

    def _write_config(self):
        with open(os.path.join(ROOT, "packages.example.json")) as f:
            raw = json.load(f)
        raw.update(dp_packages_dir=self.dp, staging_dir=self.staging, category_id=-1,
                   log_file=os.path.join(self.dir, "log", "jamf-dp-sync.log"),
                   lock_file=os.path.join(self.dir, "state", "run.lock"),
                   tools={"openssl": shutil.which("openssl") or "/usr/bin/openssl",
                          "7zz": os.path.join(self.tools, "7zz")})
        raw.pop("dp_group", None)
        # Google Drive left the example config when D12 failed; the dmg_extract path stays tested (A14).
        with open(os.path.join(ROOT, "tests", "fixtures", "googledrive_app.json")) as f:
            raw["apps"].append(json.load(f))
        for app in raw["apps"]:
            app["policy_ids"] = [POLICY[app["label"]]]
            app["patch_title_id"] = TITLE[app["label"]]
            if app["label"] in ("acrobat", "office", "zoom", "googledrive"):
                app["add_if_missing"] = True  # no legacy pkg in their policies
            if app["label"] == "dialog":
                app["replace_regex"] = r"^dialog-.+\.pkg$"
            if app["label"] == "chrome":
                app["replace_regex"] = r"^GoogleChrome-.+\.pkg$"
        self.raw_config = raw
        return self.save_config(raw)

    def save_config(self, raw):
        path = os.path.join(self.dir, "packages.json")
        with open(path, "w") as f:
            json.dump(raw, f, indent=1)
        self.raw_config = raw
        return path

    def edit_app(self, label, **changes):
        raw = copy.deepcopy(self.raw_config)
        for app in raw["apps"]:
            if app["label"] == label:
                for k, v in changes.items():
                    if v is None:
                        app.pop(k, None)
                    else:
                        app[k] = v
        self.save_config(raw)

    def _write_env(self):
        d = os.path.join(self.home, ".config", "jamf-dp-sync")
        os.makedirs(d)
        p = os.path.join(d, "env")
        with open(p, "w") as f:
            f.write("JAMF_URL=%s\nJAMF_CLIENT_ID=jamf-dp-sync-test\nJAMF_CLIENT_SECRET=stub-secret\n"
                    "GITHUB_TOKEN=ghp_l1test\nGCHAT_WEBHOOK_URL=%s/v1/spaces/L1/messages?key=KEYL1&token=TOKL1\n"
                    % (self.jamf_url, self.chat_url))
        os.chmod(p, 0o600)

    # ------------------------------------------------------------- upstream
    def make_pkg(self, label, product, team=None, name=None):
        path = os.path.join(self.files, name or "%s-%s.pkg" % (label, product.replace(" ", "_")))
        build_xar(path, [("Distribution", distribution(product=product))],
                  certs=[team_cert(team or TEAMS[label], self.dir)])
        with open(path, "rb") as f:
            data = f.read()
        return path, len(data), hashlib.sha256(data).hexdigest()

    def route(self, key, status=200, body=None, body_file=None, headers=None):
        with self.up.lock:
            self.up.routes[key] = upstream_stub.Route(status, body, body_file, headers)

    def set_upstream(self, label, pkg_version, team=None):
        """Publish `pkg_version` of `label` upstream, in that source's real shape."""
        self.versions[label] = pkg_version
        getattr(self, "_up_" + label)(pkg_version, team)

    def _github(self, repo, tag, asset, path, size, sha, latest=True):
        api = "api.github.com/repos/%s/releases" % repo
        dl = "https://github.com/%s/releases/download/%s/%s" % (repo, tag, asset)
        rel = {"tag_name": tag, "draft": False, "assets": [
            {"name": asset, "size": size, "digest": "sha256:" + sha, "browser_download_url": dl},
            {"name": "README.md", "size": 1, "digest": None,
             "browser_download_url": "https://github.com/%s/releases/download/%s/README.md" % (repo, tag)}]}
        self.route("%s/tags/%s" % (api, tag), body=json.dumps(rel).encode())
        if latest:
            self.route("%s/latest" % api, body=json.dumps(rel).encode())
        html = ('<ul><li><a href="/%s/releases/download/%s/%s">%s</a></li>'
                '<li><a href="/%s/archive/refs/tags/%s.zip">Source</a></li></ul>' % (repo, tag, asset, asset, repo, tag))
        self.route("github.com/%s/releases/expanded_assets/%s" % (repo, tag), body=html.encode())
        blob = "release-assets.githubusercontent.com/%s" % hashlib.sha1(dl.encode()).hexdigest()
        self.route(dl[len("https://"):], status=302, headers={"Location": "https://" + blob})
        self.route(blob, body_file=path)

    def _up_nudge(self, v, team):
        name = "Nudge_Suite-%s.pkg" % v
        path, size, sha = self.make_pkg("nudge", v, team, name)
        self._github("macadmins/nudge", "v" + v, name, path, size, sha)

    def _up_dialog(self, v, team):
        marketing, build = v.rsplit(".", 1)
        name = "dialog-%s-%s.pkg" % (marketing, build)
        path, size, sha = self.make_pkg("dialog", v, team, name)
        self._github("swiftDialog/swiftDialog", "v" + marketing, name, path, size, sha)

    def _up_acrobat(self, v, team):
        major, minor, build = v.split(".")
        code = "%02d%03d%05d" % (int(major), int(minor), int(build))
        name = "AcrobatDC%s_MUI.pkg" % code
        path, size, sha = self.make_pkg("acrobat", v, team, name)
        decoy, dsize, dsha = self.make_pkg("acrobat", v, team, "AcrobatDCUpd%s_incr.pkg" % code)
        item = ('<dItem id="%s" httpURLBase="https://ardownload3.adobe.com" URL="pub/adobe/acrobat/mac/AcrobatDC/%s" '
                'fileName="%s" signingEntity="Developer ID Installer: Adobe Inc. (JQ525L2MZD)" hashValue="%s" size="%d" />')
        xml = ('<?xml version="1.0" encoding="utf-8"?><ARMProductManifest version="1.1"><DownloadActionItems>%s%s'
               '</DownloadActionItems></ARMProductManifest>'
               % (item % ("dld_Patch_Incr", code, os.path.basename(decoy), dsha, dsize),
                  item % ("dld_App_Full", code, name, sha, size)))
        arm = os.path.join(self.files, "AcrobatManifest-%s.arm" % code)
        build_xar(arm, [("ASSET/AcrobatManifest.xml", xml.encode())], certs=[team_cert("JQ525L2MZD", self.dir)])
        self.route("armmf.adobe.com/arm-manifests/mac/AcrobatDC/acrobat/AcrobatManifest.arm", body_file=arm)
        self.route("ardownload3.adobe.com/pub/adobe/acrobat/mac/AcrobatDC/%s/%s" % (code, name), body_file=path)
        self.route("ardownload3.adobe.com/pub/adobe/acrobat/mac/AcrobatDC/%s/%s" % (code, os.path.basename(decoy)),
                   body_file=decoy)

    def _up_office(self, v, team):
        path, _, _ = self.make_pkg("office", v, team)
        final = "officecdnmac.microsoft.com/pr/C1297A47/MacAutoupdate/Microsoft_365_and_Office_%s_Installer.pkg" % v
        self.route("go.microsoft.com/fwlink/?linkid=525133", status=302, headers={"Location": "https://" + final})
        self.route(final, body_file=path, headers={"ETag": '"office-%s"' % v})

    def _up_chrome(self, v, team):
        path, _, _ = self.make_pkg("chrome", v, team)
        self.route("dl.google.com/dl/chrome/mac/universal/stable/gcem/GoogleChrome.pkg", body_file=path,
                   headers={"ETag": '"chrome-%s"' % v, "Last-Modified": "Mon, 09 Nov 2026 00:00:00 GMT"})

    def _up_zoom(self, v, team):
        path, _, _ = self.make_pkg("zoom", v, team)
        self.route("cdn.zoom.us/prod/%s/ZoomInstallerIT.pkg" % v, body_file=path)

    def _up_googledrive(self, v, team):
        path, _, _ = self.make_pkg("googledrive", v, team)
        with open(path, "rb") as f:
            inner = f.read()
        dmg = os.path.join(self.files, "GoogleDrive-%s.dmg" % v)
        with open(dmg, "wb") as f:
            f.write(b"koly-fake-dmg-" + v.encode())
        fake_7zz(self.tools, slt_listing("GoogleDrive.dmg", [("Install Google Drive", True, 0),
                                                             (DMG_MEMBER, False, len(inner)),
                                                             ("Install Google Drive/.background.png", False, 1)]),
                 {DMG_MEMBER: inner})
        self.route("dl.google.com/drive-file-stream/GoogleDrive.dmg", body_file=dmg,
                   headers={"ETag": '"drive-%s"' % v})

    # ----------------------------------------------------------- jamf side
    def set_title(self, label, text):
        """Make `text` the newest definition (absoluteOrderId 0) of the app's patch title."""
        with self.jamf.lock:
            t = self.jamf.titles[str(TITLE[label])]
            defs = [d for d in t["definitions"] if d["version"] != text]
            for d in defs:
                d["absoluteOrderId"] = str(int(d["absoluteOrderId"]) + 1)
            t["definitions"] = [{"version": text, "absoluteOrderId": "0", "releaseDate": "2026-11-09T00:00:00Z"}] + defs

    def policy_packages(self, label):
        from jamf_dp_sync.jamf import policy_xml as P
        with self.jamf.lock:
            xml = self.jamf.policies[str(POLICY[label])]
        return P.packages(xml)

    def records(self):
        with self.jamf.lock:
            return sorted(self.jamf.packages.values(), key=lambda p: int(p["id"]))

    def jamf_writes(self):
        with self.jamf.lock:
            return [(e["method"], e["path"]) for e in self.jamf.log
                    if e["method"] in ("POST", "PUT", "PATCH", "DELETE") and e["path"] != "/api/oauth/token"
                    and not e["path"].endswith("invalidate-token")]

    def messages(self):
        with self.chat.lock:
            return list(self.chat.messages)

    # --------------------------------------------------------------- run it
    @contextlib.contextmanager
    def environment(self, **extra):
        old = dict((k, os.environ.get(k)) for k in list(self.env) + list(extra))
        os.environ.update(self.env)
        os.environ.update(extra)
        notify.BACKOFF = (0, 0, 0)
        try:
            yield
        finally:
            notify.BACKOFF = self._old_backoff
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def run(self, faults="", now=None, dry_run=False, no_prune=False, only=None):
        """In-process `jamf-dp-sync run`, as cli.main does it. Returns (exit code, stdout, log text)."""
        now = now or datetime.datetime(2026, 11, 10, 3, 20)  # a Tuesday
        with self.environment(JDS_TEST_FAULTS=faults):
            cfg = config.load(self.cfg_path)
            secrets.init()
            buf = io.StringIO()
            log = logsetup.setup(cfg["log_file"], verbose=True, stream=False)
            args = argparse.Namespace(only=only, dry_run=dry_run, no_prune=no_prune, verbose=True)
            code = runner.cmd_run(cfg, args, log, now=now, out=buf)
            secrets._reset_for_tests()
        with open(cfg["log_file"]) as f:
            logtext = f.read()
        return code, buf.getvalue(), logtext

    def cli(self, *argv, **extra):
        """Real subprocess run of jamf_dp_sync.py (exit codes, A11, A20)."""
        env = dict(os.environ, **self.env)
        env.update(extra)
        return subprocess.run([sys.executable, os.path.join(ROOT, "jamf_dp_sync.py"), "--config", self.cfg_path]
                              + list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=600)

    def close(self):
        for srv in (self.upstream_srv, self.chat_srv, self.jamf_srv):
            srv.shutdown()
            srv.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)
