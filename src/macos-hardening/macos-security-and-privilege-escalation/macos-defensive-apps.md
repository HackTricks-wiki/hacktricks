# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Dit sal elke verbinding monitor wat deur elke proses gemaak word. Afhangend van die modus (stilweg verbindings toelaat, verbindings stilweg weier en waarsku) sal dit **vir jou 'n waarskuwing wys** elke keer wanneer 'n nuwe verbinding gevestig word. Dit het ook 'n baie goeie GUI om al hierdie inligting te sien.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See-firewall. Dit is 'n basiese firewall wat jou oor verdagte verbindings sal waarsku (dit het 'n GUI, maar dit is nie so indrukwekkend soos dié van Little Snitch nie).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See-toepassing wat op verskeie plekke sal soek waar **malware persistent kan wees** (dit is 'n eenmalige tool, nie 'n monitoring-diens nie).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Soos KnockKnock, deur prosesse te monitor wat persistence genereer.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See-toepassing om **keyloggers** te vind wat sleutelbord-"event taps" installeer

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Binary authorization- en monitoring-stelsel vir macOS. Dit gebruik 'n **Endpoint Security**-kliënt om **`exec`**-events te authoriseer voordat kode loop, daarom is dit algemeen in enterprise-fleets wat op **allowlisting/denylisting** eerder as slegs post-execution detection fokus.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon-agtige macOS dynamic analysis-tool. Dit neem **Endpoint Security telemetry** in (process-, file-, interprocess-, login- en XProtect-verwante events) en is nuttig om te verstaan wat 'n volwasse ES-gebaseerde sensor werklik kan observeer.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lightweight Objective-See-tools vir **process**, **file** en **DNS** telemetry. Op moderne macOS het hulle addisionele prerequisites soos **root**, **Terminal Full Disk Access**, of **System/Network Extension approval**. Vir meer instrumentation-idees, kyk na [hierdie ander bladsy oor macOS-app-inspeksie/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

Die meeste moderne macOS-securityprodukte loop as 'n kombinasie van **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, en toepassings met **Full Disk Access**. 'n Vinnige operateur-kontrolelys:
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
As `systemextensionsctl list` ’n sensor as **`[activated enabled]`** wys, is dit gewoonlik die vinnigste aanduiding dat die uitbreiding werklik aktief is. Op **macOS 15 Sequoia en later** kan MDM ook spesifieke sekuriteitsuitbreidings as **nie-verwyderbaar uit die UI** merk, dus is “deaktiveer dit vanuit System Settings” nie meer ’n veilige aanname nie. Vir interne besonderhede, sien [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Onlangse native telemetry wat defenders kan gebruik

Onlangse macOS-vrystellings het sommige voorheen moeilik-opspoorbare, gebruiker-geïnisieerde bypasses baie meer sigbaar vir blue teams gemaak:

- **macOS 15+**: Endpoint Security-kliënte kan **`gatekeeper_user_override`**-gebeurtenisse ontvang, sodat handmatige Gatekeeper-bypasses sentraal aangeteken kan word.
- **Huidige macOS Endpoint Security tooling** kan ook **XProtect malware detection**-gebeurtenisse inneem, wat dit makliker maak om te bevestig wat Apple reeds op die endpoint opgespoor het.
- **macOS 15.4+**: Endpoint Security voeg **`tcc_modify`** by, wat defenders uiteindelik ’n ondersteunde manier gee om **TCC grants/revokes** te monitor in plaas daarvan om TCC-debuglogs te skraap.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Dit is nuttig vir defenders sowel as red teamers wat self-evaluering doen: as die teiken 'n volwasse ES-gebaseerde stack het, **kan user-approved Gatekeeper / TCC bypass chains baie sigbaarder wees as voorheen**. Vir agtergrond oor hierdie beskermings, sien [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) en [TCC](macos-security-protections/macos-tcc/README.md).

## Verwysings

- [1] [Objective-See - TCCing is Believing! Apple voeg uiteindelik TCC-events by Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
