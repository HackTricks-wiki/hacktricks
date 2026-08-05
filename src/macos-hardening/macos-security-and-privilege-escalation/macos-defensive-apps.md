# Apps za Ulinzi za macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Itafuatilia kila connection inayofanywa na kila process. Kulingana na mode (silent allow connections, silent deny connection and alert), **itakuonyesha alert** kila mara connection mpya inapoanzishwa. Pia ina GUI nzuri sana ya kuona taarifa hizi zote.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall ya Objective-See. Hii ni firewall ya msingi ambayo itakuonyesha alert kuhusu connections zenye mashaka (ina GUI, lakini si ya kuvutia kama ile ya Little Snitch).

## Utambuzi wa persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Application ya Objective-See inayotafuta katika maeneo kadhaa ambako **malware inaweza kuwa ina-persist** (ni one-shot tool, si monitoring service).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Kama KnockKnock, kwa kufuatilia processes zinazozalisha persistence.

## Utambuzi wa keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): Application ya Objective-See ya kutafuta **keyloggers** zinazosakinisha keyboard "event taps"

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Mfumo wa binary authorization na monitoring wa macOS. Unatumia client ya **Endpoint Security** ku-authorize events za **`exec`** kabla code haija-run, hivyo ni wa kawaida katika enterprise fleets zinazolenga **allowlisting/denylisting** badala ya kutegemea tu post-execution detection.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Chombo cha dynamic analysis cha macOS kinachofanana na Procmon. Hupokea **Endpoint Security telemetry** (events za process, file, interprocess, login, na zinazohusiana na XProtect) na ni muhimu kuelewa kile ambacho sensor iliyokomaa inayotumia ES inaweza kweli kuchunguza.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Vifaa vyepesi vya Objective-See kwa **process**, **file**, na **DNS** telemetry. Kwenye macOS za kisasa vina prerequisites za ziada kama **root**, **Terminal Full Disk Access**, au **System/Network Extension approval**. Kwa mawazo zaidi ya instrumentation, angalia [ukurasa huu mwingine kuhusu macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Triage ya haraka ya defensive tooling

Bidhaa nyingi za kisasa za usalama za macOS huendesha kama mchanganyiko wa **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, na applications zilizo na **Full Disk Access**. Checklist ya haraka kwa operator:
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
Ikiwa `systemextensionsctl list` inaonyesha sensor kama **`[activated enabled]`**, kwa kawaida hii ndiyo kiashirio cha haraka zaidi kwamba extension iko hai. Kwenye **macOS 15 Sequoia na matoleo ya baadaye**, MDM pia inaweza kuweka security extensions mahususi kuwa **zisizoweza kuondolewa kwenye UI**, kwa hivyo "kuizima kutoka System Settings" si dhana salama tena. Kwa maelezo ya ndani, angalia [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry ambayo defenders wanaweza kutumia

Matoleo ya hivi karibuni ya macOS yamefanya baadhi ya bypasses zinazoendeshwa na user na ambazo hapo awali zilikuwa vigumu kugundua kuwa na noise nyingi zaidi kwa blue teams:

- **macOS 15+**: Clients za Endpoint Security zinaweza kupokea matukio ya **`gatekeeper_user_override`**, hivyo bypasses za Gatekeeper zinazofanywa manually zinaweza kurekodiwa centrally.
- **Current macOS Endpoint Security tooling** pia inaweza kupokea matukio ya **XProtect malware detection**, hivyo kurahisisha kuthibitisha kile ambacho Apple tayari imegundua kwenye endpoint.
- **macOS 15.4+**: Endpoint Security inaongeza **`tcc_modify`**, ambayo hatimaye huwapa defenders njia inayoungwa mkono ya kufuatilia **TCC grants/revokes** badala ya kuscrape TCC debug logs.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Hii ni muhimu kwa defenders na red teamers wanaofanya self-assessment: ikiwa target ina stack iliyokomaa inayotumia ES, **user-approved Gatekeeper / TCC bypass chains zinaweza kuonekana zaidi kuliko ilivyokuwa awali**. Kwa maelezo ya msingi kuhusu protections hizi, angalia [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) na [TCC](macos-security-protections/macos-tcc/README.md).

## Marejeo

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
