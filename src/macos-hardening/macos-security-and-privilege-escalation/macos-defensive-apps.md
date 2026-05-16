# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Itafuatilia kila muunganisho unaofanywa na kila process. Kulingana na mode (silent allow connections, silent deny connection and alert) itakuonyesha **alert** kila wakati muunganisho mpya unapowekwa. Pia ina GUI nzuri sana kuonyesha taarifa hizi zote.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall. Hii ni firewall ya msingi ambayo itakuonyesha alert kwa connections za shaka (ina GUI lakini si ya kupendeza kama ya Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Application ya Objective-See ambayo itatafuta katika maeneo kadhaa ambapo **malware could be persisting** (ni tool ya mara moja, si monitoring service).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Kama KnockKnock kwa kufuatilia processes zinazozalisha persistence.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Application ya Objective-See ya kutafuta **keyloggers** zinazoweka keyboard "event taps"

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Mfumo wa binary authorization na monitoring kwa macOS. Hutumia client wa **Endpoint Security** kuidhinisha matukio ya **`exec`** kabla code haijatekelezwa, kwa hiyo ni ya kawaida katika enterprise fleets inayolenga **allowlisting/denylisting** badala ya detection ya post-execution pekee.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Tool ya dynamic analysis ya macOS inayofanana na Procmon. Hu-ingest **Endpoint Security telemetry** (process, file, interprocess, login, na matukio yanayohusiana na XProtect) na ni muhimu kuelewa sensor yenye msingi wa ES iliyokomaa inaweza kuona nini hasa.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Tools nyepesi za Objective-See kwa **process**, **file**, na **DNS** telemetry. Kwenye macOS za kisasa zina prerequisites za ziada kama **root**, **Terminal Full Disk Access**, au **System/Network Extension approval**. Kwa mawazo zaidi ya instrumentation angalia [this other page about macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

U nyingi za kisasa za usalama wa macOS huendeshwa kama mchanganyiko wa **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, na applications zenye **Full Disk Access**. Orodha ya haraka ya operator:
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
If `systemextensionsctl list` inaonyesha sensor kama **`[activated enabled]`**, kwa kawaida hiyo ndiyo dalili ya haraka zaidi kwamba extension iko hai kweli. Kwenye **macOS 15 Sequoia na baadaye**, MDM pia inaweza kuweka specific security extensions kuwa **non-removable from the UI**, hivyo "disable it from System Settings" si tena dhana salama. Kwa internals, ona [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Toleo za hivi karibuni za macOS zilifanya baadhi ya user-driven bypasses ambazo zamani zilikuwa ngumu kutambua zionekane zaidi kwa blue teams:

- **macOS 15+**: Endpoint Security clients zinaweza kupokea **`gatekeeper_user_override`** events, hivyo manual Gatekeeper bypasses zinaweza kuandikwa centrally kwenye logs.
- **Current macOS Endpoint Security tooling** pia inaweza kusoma **XProtect malware detection** events, jambo linalorahisisha kuthibitisha kile ambacho Apple tayari iligundua kwenye endpoint.
- **macOS 15.4+**: Endpoint Security inaongeza **`tcc_modify`**, ambayo hatimaye inawapa defenders njia supported ya kufuatilia **TCC grants/revokes** badala ya kusoma TCC debug logs.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Hii ni muhimu kwa watetezi na pia kwa red teamers wanaofanya self-assessment: ikiwa lengo lina mature ES-based stack, **user-approved Gatekeeper / TCC bypass chains zinaweza kuonekana zaidi kuliko zilivyokuwa hapo awali**. Kwa background kuhusu protections hizi, tazama [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) na [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
