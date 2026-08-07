# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Dit sal elke verbinding wat deur elke proses gemaak word, monitor. Afhangend van die modus (verbindings stilweg toelaat, verbindings stilweg weier en waarsku), sal dit **elke keer vir jou 'n waarskuwing wys** wanneer 'n nuwe verbinding tot stand gebring word. Dit het ook 'n baie goeie GUI om al hierdie inligting te sien.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall. Dit is 'n basiese firewall wat jou oor verdagte verbindings sal waarsku (dit het 'n GUI, maar dit is nie so indrukwekkend soos dié van Little Snitch nie).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See-toepassing wat op verskeie plekke sal soek waar **malware kan volhou** (dit is 'n eenmalige hulpmiddel, nie 'n monitoringdiens nie).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Soos KnockKnock, deur prosesse te monitor wat persistence genereer.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See-toepassing om **keyloggers** te vind wat sleutelbord-"event taps" installeer.

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Binary authorization- en monitoringstelsel vir macOS. Dit gebruik 'n **Endpoint Security**-kliënt om **`exec`**-gebeurtenisse te magtig voordat kode uitgevoer word, en is dus algemeen in ondernemingsvlootomgewings wat op **allowlisting/denylisting** eerder as slegs post-execution detection fokus.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): 'n Procmon-agtige macOS-dinamiese-analisehulpmiddel. Dit neem **Endpoint Security telemetry** (process-, file-, interprocess-, login- en XProtect-verwante gebeurtenisse) in en is nuttig om te verstaan wat 'n volwasse ES-gebaseerde sensor werklik kan waarneem.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Liggewig Objective-See-hulpmiddels vir **process**, **file** en **DNS** telemetry. Op moderne macOS het hulle bykomende voorvereistes soos **root**, **Terminal Full Disk Access** of **System/Network Extension approval**. Vir meer idees oor instrumentation, kyk na [hierdie ander bladsy oor macOS-app-inspeksie/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

Die meeste moderne macOS-sekuriteitsprodukte loop as 'n kombinasie van **System Extensions / Endpoint Security clients**, **launchd agents/daemons** en toepassings met **Full Disk Access**. 'n Vinnige operateurkontrolelys:
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
As `systemextensionsctl list` ’n sensor as **`[activated enabled]`** wys, is dit gewoonlik die vinnigste aanduiding dat die extension werklik aktief is. Op **macOS 15 Sequoia en later** kan MDM ook spesifieke security extensions as **nie-verwyderbaar vanaf die UI** merk, dus is “skakel dit vanaf System Settings af” nie meer ’n veilige aanname nie. Sien [macOS System Extensions](mac-os-architecture/macos-system-extensions.md) vir interne besonderhede.

## Onlangse native telemetry wat defenders kan gebruik

Onlangse macOS-vrystellings het sommige user-driven bypasses wat voorheen moeilik was om op te spoor, baie sigbaarder vir blue teams gemaak:

- **macOS 15+**: Endpoint Security-clients kan **`gatekeeper_user_override`**-events ontvang, sodat handmatige Gatekeeper-bypasses sentraal aangeteken kan word.
- **Huidige macOS Endpoint Security-tooling** kan ook **XProtect malware detection**-events inneem, wat dit makliker maak om te bevestig wat Apple reeds op die endpoint opgespoor het.
- **macOS 15.4+**: Endpoint Security voeg **`tcc_modify`** by, wat defenders uiteindelik ’n ondersteunde manier gee om **TCC grants/revokes** te monitor in plaas daarvan om TCC-debuglogs te scrape.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Dit is nuttig vir beide verdedigers en red teamers wat self-assessering doen: indien die teiken ’n volwasse ES-gebaseerde stack het, **kan user-approved Gatekeeper / TCC bypass-kettings baie sigbaarder wees as voorheen**. Vir agtergrond oor hierdie beskermings, sien [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) en [TCC](macos-security-protections/macos-tcc/README.md).

## Verwysings


- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
