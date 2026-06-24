# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): It will monitor every connection made by each process. Depending on the mode (silent allow connections, silent deny connection and alert) it will **show you an alert** every time a new connection is stablished. It also has a very nice GUI to see all this information.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall. This is a basic firewall that will alert you for suspicious connections (it has a GUI but it isn't as fancy as the one of Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See application that will search in several locations where **malware could be persisting** (it's a one-shot tool, not a monitoring service).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Like KnockKnock by monitoring processes that generate persistence.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See application to find **keyloggers** that install keyboard "event taps"

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Binary authorization and monitoring system for macOS. It uses an **Endpoint Security** client to authorize **`exec`** events before code runs, so it is common in enterprise fleets focused on **allowlisting/denylisting** instead of only post-execution detection.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon-like macOS dynamic analysis tool. It ingests **Endpoint Security telemetry** (process, file, interprocess, login, and XProtect-related events) and is useful to understand what a mature ES-based sensor can actually observe.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lightweight Objective-See tools for **process**, **file**, and **DNS** telemetry. On modern macOS they have extra prerequisites such as **root**, **Terminal Full Disk Access**, or **System/Network Extension approval**. For more instrumentation ideas check [this other page about macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

Most modern macOS security products run as some combination of **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, and applications with **Full Disk Access**. A quick operator checklist:

```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
  [ -f "$db" ] || continue
  echo "== $db =="
  sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```

If `systemextensionsctl list` shows a sensor as **`[activated enabled]`**, it is usually the fastest indicator that the extension is actually live. On **macOS 15 Sequoia and later**, MDM can also mark specific security extensions as **non-removable from the UI**, so "disable it from System Settings" is no longer a safe assumption. For internals, see [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Recent macOS releases made some previously annoying-to-detect user-driven bypasses much noisier for blue teams:

- **macOS 15+**: Endpoint Security clients can receive **`gatekeeper_user_override`** events, so manual Gatekeeper bypasses can be centrally logged.
- **Current macOS Endpoint Security tooling** can also ingest **XProtect malware detection** events, making it easier to confirm what Apple already detected on the endpoint.
- **macOS 15.4+**: Endpoint Security adds **`tcc_modify`**, which finally gives defenders a supported way to monitor **TCC grants/revokes** instead of scraping TCC debug logs.

```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```

This is useful both for defenders and for red teamers doing self-assessment: if the target has a mature ES-based stack, **user-approved Gatekeeper / TCC bypass chains may be much more visible than they used to be**. For background on these protections, see [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) and [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
