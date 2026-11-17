# How it compares

jamf-dp-sync does one narrow job. The tools below do far more; this is about fit, not merit.

| | jamf-dp-sync | Installomator | AutoPkg / AutoPkgr | Munki |
| --- | --- | --- | --- | --- |
| Where it runs | Linux server hosting the file share DP | On each Mac, at install time | A Mac (AutoPkgr is a GUI for AutoPkg) | Client agent on each Mac plus a web repo |
| Download | Once per version, on the server | Every Mac, every install | Once, on the AutoPkg Mac | Once into the repo; Macs fetch from the repo |
| What it handles | Signed vendor pkgs (pkg, pkg in a DMG) | Hundreds of labels: pkg, dmg, zip, app bundles | Thousands of community recipes; can build pkgs from apps | Full software management, updates, self service |
| Version source | Jamf Patch Management titles | The vendor's latest | Recipes | Your repo catalogs |
| Setup | Service user, ACL, config file, cron | A script or a Setup Manager action | A Mac, recipes, overrides, uploader setup | Server repo, client install, manifests |

Choose AutoPkg or Munki when you need broad app coverage, repackaging or ongoing patching. Choose
jamf-dp-sync when you already have a Linux file share distribution point and want the few apps your
builds install to come from it, kept current automatically.
