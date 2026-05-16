# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Es überwacht jede von jedem Prozess hergestellte Verbindung. Abhängig vom Modus (Verbindungen still erlauben, Verbindung still verweigern und Alarm) **zeigt es dir einen Alarm**, jedes Mal wenn eine neue Verbindung hergestellt wird. Es hat außerdem eine sehr schöne GUI, um all diese Informationen zu sehen.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See-Firewall. Das ist eine einfache Firewall, die dich bei verdächtigen Verbindungen alarmiert (sie hat eine GUI, aber sie ist nicht so schick wie die von Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See-Anwendung, die an mehreren Stellen sucht, an denen **malware sich persistent machen könnte** (es ist ein One-Shot-Tool, kein Monitoring-Dienst).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Wie KnockKnock, indem Prozesse überwacht werden, die Persistence erzeugen.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See-Anwendung, um **keyloggers** zu finden, die Keyboard-„event taps“ installieren

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Binary Authorization- und Monitoring-System für macOS. Es verwendet einen **Endpoint Security**-Client, um **`exec`**-Events vor der Ausführung von Code zu autorisieren, daher ist es in Enterprise-Flotten üblich, die sich auf **allowlisting/denylisting** statt nur auf Post-Execution-Detection konzentrieren.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon-ähnliches macOS-Dynamic-Analysis-Tool. Es verarbeitet **Endpoint Security telemetry** (Prozess-, Datei-, Interprozess-, Login- und XProtect-bezogene Events) und ist nützlich, um zu verstehen, was ein ausgereifter ES-basierter Sensor tatsächlich beobachten kann.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Leichtgewichtige Objective-See-Tools für **process**-, **file**- und **DNS**-Telemetrie. Auf modernem macOS haben sie zusätzliche Voraussetzungen wie **root**, **Terminal Full Disk Access** oder **System/Network Extension approval**. Für weitere Ideen zur Instrumentierung sieh dir [diese andere Seite über macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md) an.

## Quick triage of defensive tooling

Die meisten modernen macOS-Sicherheitsprodukte laufen als irgendeine Kombination aus **System Extensions / Endpoint Security clients**, **launchd agents/daemons** und Anwendungen mit **Full Disk Access**. Eine kurze Operator-Checkliste:
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
Wenn `systemextensionsctl list` einen Sensor als **`[activated enabled]`** anzeigt, ist das normalerweise der schnellste Hinweis darauf, dass die Extension tatsächlich aktiv ist. Auf **macOS 15 Sequoia und neuer** kann MDM außerdem bestimmte Security Extensions als **nicht aus der UI entfernbar** markieren, sodass „in den System Settings deaktivieren“ nicht mehr als sichere Annahme gilt. Für Interna siehe [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Aktuelle native Telemetrie, die Defenders auswerten können

Aktuelle macOS-Releases haben einige bisher schwer zu erkennende, vom Benutzer ausgelöste Bypasses für Blue Teams deutlich lauter gemacht:

- **macOS 15+**: Endpoint Security Clients können **`gatekeeper_user_override`**-Events empfangen, sodass manuelle Gatekeeper-Bypasses zentral protokolliert werden können.
- **Aktuelle macOS Endpoint Security-Tools** können außerdem **XProtect malware detection**-Events aufnehmen, wodurch sich leichter bestätigen lässt, was Apple bereits auf dem Endpoint erkannt hat.
- **macOS 15.4+**: Endpoint Security fügt **`tcc_modify`** hinzu, was Defenders endlich eine unterstützte Möglichkeit gibt, **TCC grants/revokes** zu überwachen, statt TCC-Debug-Logs auszuwerten.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Dies ist sowohl für Verteidiger als auch für Red Teamer, die Self-Assessment durchführen, nützlich: Wenn das Ziel einen ausgereiften ES-basierten Stack hat, können **vom Benutzer genehmigte Gatekeeper / TCC-Bypass-Chains viel sichtbarer sein als früher**. Für Hintergrund zu diesen Schutzmechanismen siehe [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) und [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
