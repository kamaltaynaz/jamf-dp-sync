# Known limits and compatibility

The README lists these in brief. This page has the full detail.

## Known limits

- **The signature check reads certificate fields; it is not cryptographic.** The agent takes the
  leaf certificate from the pkg's xar table of contents and uses `openssl` to check that it is a
  "Developer ID Installer" certificate whose subject OU equals the app's expected Team ID. That
  catches a wrong or unexpected vendor pkg, but it does **not** verify the table of contents
  signature or the chain to Apple's root the way `pkgutil --check-signature` does on macOS: a forged
  self-signed certificate with the same fields would pass. Authenticity comes from HTTPS to the
  vendor's own host plus the vendor's SHA-256 and size where the source publishes them (GitHub
  release asset digests, Adobe's manifest). For sources that publish no hash (`latest_redirect`,
  `url_template`), it rests on HTTPS alone; the certificate fields and version check guard against
  mistakes, not attacks. macOS's installer still checks the real signature when a Mac installs the pkg.
- **Policy edits are last-writer-wins.** The Classic API has no conditional update. The agent re-reads
  each policy just before it writes (keeping any edit made since it planned) and reads it back just
  after, warning in the run summary if the package list changed around the update. An admin edit made
  in the instant between that re-read and the write can still be lost; schedule runs for a quiet hour.
- **Signed vendor pkgs only.** The agent publishes a pkg the vendor built and signed, either directly
  or inside a DMG. It never repackages an `.app` bundle from a DMG or ZIP.
- **Some DMGs cannot be opened on Linux.** 7-Zip cannot read every APFS disk image; a dry run tells you.
- **Local distribution point only** (see [Compatibility](#compatibility)).
- **Monitor mode is not finished.** `monitor` entries are validated and `status` reports their
  policy and patch title versions, but `run` skips them and sends no alerts yet.
- **The Adobe `.arm` manifest** is accepted on HTTPS plus the certificate-field check of its xar
  wrapper; any other signature around it is not verified.

## Compatibility

- **Jamf Pro on-premises:** tested in production.
- **Jamf Cloud:** expected to work, not yet tested; reports welcome. Nothing in the agent assumes an
  on-premises server: it uses only the Jamf Pro API and Classic API over HTTPS with an OAuth API
  client. Jamf Pro supports file share distribution points alongside the Jamf Cloud distribution
  point, chosen per network segment, so a cloud-hosted Jamf Pro with an on-site Linux file share
  distribution point is the same design.

  **Limitation:** the packages exist only on the local file share distribution point. A Mac whose
  network segment points at the cloud distribution point will not find them, and the policy will
  fail for that Mac. The cache is for on-site builds: make sure build Macs are on a network segment
  that uses the local distribution point. Uploading to the cloud distribution point as well is a
  possible future option.
