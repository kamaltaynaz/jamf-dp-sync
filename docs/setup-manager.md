# Jamf Setup Manager and other workflows

jamf-dp-sync keeps a Jamf policy pointed at the current pkg. Your enrollment workflow then runs that
policy by its custom trigger. The agent itself never uses triggers, only policy IDs, so any workflow
that can run `jamf policy -event <trigger>` works.

## Jamf Setup Manager

[Jamf Setup Manager](https://github.com/jamf/setup-manager) runs a list of `enrollmentActions` from
its configuration profile. An action can call an Installomator label (`installomator`) or a Jamf
policy trigger (`policy`). To move an app to the local cache, replace the `installomator` key with a
`policy` key naming the app's custom trigger, and keep the `label` and `icon` as they are.

Before:

```xml
<dict>
  <key>icon</key>
  <string>https://assets.example.com/icons/nudge.png</string>
  <key>label</key>
  <string>Installing Nudge</string>
  <key>installomator</key>
  <string>nudgesuite</string>
</dict>
```

After:

```xml
<dict>
  <key>icon</key>
  <string>https://assets.example.com/icons/nudge.png</string>
  <key>label</key>
  <string>Installing Nudge</string>
  <key>policy</key>
  <string>install-nudge-jsm</string>
</dict>
```

Leave the order and every other action unchanged. Apps you do not sync can keep their Installomator
actions; the two work side by side.

Points to check:

- **Custom triggers are case-sensitive.** The string must match the policy's trigger exactly.
- **The policy must be in scope** for the Macs being built, and the Macs must be on a network segment
  whose default distribution point is your file share distribution point. Otherwise the policy runs
  but cannot download the pkg.
- **Change the profile last.** Publish the pkgs, test each trigger on a spare Mac, then switch the
  profile. On a test Mac on the build network:

  ```
  sudo jamf policy -event install-nudge-jsm -verbose
  ```

  and confirm in `/var/log/jamf.log` that the pkg was downloaded from your distribution point.
- **Rollback** is restoring the previous profile. The policies keep working with the last published
  pkgs.

## Other workflows

Any enrollment tool or script can use the same policies, for example a script run by a policy on
the Enrollment Complete trigger:

```
/usr/local/bin/jamf policy -event install-nudge-jsm
```

The same applies to Self Service or other policies that call a trigger. The only requirements are
the ones above: the policy is in scope, and the Mac uses the local distribution point.
