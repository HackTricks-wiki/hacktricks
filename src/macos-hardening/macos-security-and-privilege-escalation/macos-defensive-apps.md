# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Dit sal elke verbinding wat deur elke proses gemaak word, monitor. Afhangende van die modus (stil toelaat verbindings, stil weier verbinding en waarsku) sal dit vir jou 'n **waarskuwing wys** elke keer wat 'n nuwe verbinding gevestig word. Dit het ook 'n baie mooi GUI om al hierdie inligting te sien.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall. Dit is 'n basiese firewall wat jou sal waarsku oor verdagte verbindings (dit het 'n GUI maar dit is nie so fancy soos die een van Little Snitch nie).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See toepassing wat op verskeie plekke sal soek waar **malware could be persisting** (dis 'n eenmalige tool, nie 'n monitoring service nie).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Soos KnockKnock deur prosesse te monitor wat persistence genereer.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See toepassing om **keyloggers** te vind wat keyboard "event taps" installeer

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Binary authorization and monitoring system vir macOS. Dit gebruik 'n **Endpoint Security** client om **`exec`** events te authoriseer voordat code loop, so dit is algemeen in enterprise fleets wat fokus op **allowlisting/denylisting** eerder as net post-execution detection.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon-agtige macOS dynamic analysis tool. Dit verbruik **Endpoint Security telemetry** (process, file, interprocess, login, en XProtect-related events) en is nuttig om te verstaan wat 'n mature ES-based sensor werklik kan observeer.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Liggewig Objective-See tools vir **process**, **file**, en **DNS** telemetry. Op moderne macOS het hulle ekstra prerequisites soos **root**, **Terminal Full Disk Access**, of **System/Network Extension approval**. Vir meer instrumentation-idees kyk [this other page about macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

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
If `systemextensionsctl list` wys ’n sensor as **`[activated enabled]`**, is dit gewoonlik die vinnigste aanduiding dat die extension werklik live is. Op **macOS 15 Sequoia and later**, kan MDM ook spesifieke security extensions as **non-removable from the UI** merk, so "disable it from System Settings" is nie meer ’n veilige aanname nie. Vir internals, sien [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Onlangse macOS releases het sommige voorheen irriterende-om-te-detekteer user-driven bypasses baie noisier vir blue teams gemaak:

- **macOS 15+**: Endpoint Security clients kan **`gatekeeper_user_override`** events ontvang, so manual Gatekeeper bypasses kan sentraal gelog word.
- **Current macOS Endpoint Security tooling** kan ook **XProtect malware detection** events ingesluk, wat dit makliker maak om te bevestig wat Apple reeds op die endpoint detected het.
- **macOS 15.4+**: Endpoint Security voeg **`tcc_modify`** by, wat verdedigers uiteindelik ’n supported way gee om **TCC grants/revokes** te monitor in plaas van om TCC debug logs te scrape.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Dit is nuttig vir beide verdedigers en red teamers wat self-assessment doen: as die teiken ’n volwasse ES-based stack het, **user-approved Gatekeeper / TCC bypass chains kan baie meer sigbaar wees as voorheen**. Vir agtergrond oor hierdie beskermings, sien [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) en [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
