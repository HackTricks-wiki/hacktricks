# Defensive Apps unter macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Überwacht jede von einem Prozess hergestellte Verbindung. Abhängig vom Modus (Verbindungen stillschweigend erlauben, Verbindungen stillschweigend verweigern und alarmieren) wird **jedes Mal eine Warnung angezeigt**, wenn eine neue Verbindung hergestellt wird. Außerdem verfügt es über eine sehr übersichtliche GUI, in der all diese Informationen angezeigt werden.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall von Objective-See. Dies ist eine einfache Firewall, die dich bei verdächtigen Verbindungen alarmiert (sie verfügt über eine GUI, ist aber nicht so aufwendig wie die von Little Snitch).

## Erkennung von Persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Anwendung von Objective-See, die an verschiedenen Orten nach sucht, an denen **Malware Persistence einrichten könnte** (es handelt sich um ein einmaliges Tool, nicht um einen Monitoring-Service).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Ähnlich wie KnockKnock, überwacht jedoch Prozesse, die Persistence erzeugen.

## Erkennung von Keyloggern

- [**ReiKey**](https://objective-see.org/products/reikey.html): Anwendung von Objective-See zum Auffinden von **Keyloggern**, die Tastatur-„Event taps“ installieren.

## Endpoint-Telemetrie / Ausführungskontrolle

- [**Santa**](https://santa.dev/): System zur Binary-Autorisierung und -Überwachung für macOS. Es verwendet einen **Endpoint Security**-Client, um **`exec`**-Ereignisse zu autorisieren, bevor Code ausgeführt wird. Daher ist es in Enterprise-Flotten üblich, die sich auf **Allowlisting/Denylisting** statt ausschließlich auf die Erkennung nach der Ausführung konzentrieren.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Ein Procmon-ähnliches Tool zur dynamischen Analyse von macOS. Es verarbeitet **Endpoint-Security-Telemetrie** (Prozess-, Datei-, Interprozess-, Login- und XProtect-bezogene Ereignisse) und ist nützlich, um zu verstehen, was ein ausgereifter, auf ES basierender Sensor tatsächlich beobachten kann.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Schlanke Objective-See-Tools für **Prozess-, Datei-** und **DNS-Telemetrie**. Unter modernen macOS-Versionen gelten zusätzliche Voraussetzungen wie **root**, **vollständiger Festplattenzugriff für Terminal** oder die Genehmigung einer **System-/Network Extension**. Weitere Ideen zur Instrumentierung findest du auf [dieser anderen Seite über die Inspektion, das Debugging und Fuzzing von macOS-Apps](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Schnelle Triage von Defensive Tooling

Die meisten modernen macOS-Sicherheitsprodukte laufen als Kombination aus **System Extensions / Endpoint-Security-Clients**, **launchd-Agents/Daemons** und Anwendungen mit **vollständigem Festplattenzugriff**. Eine kurze Checkliste für Operatoren:
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
Wenn `systemextensionsctl list` einen Sensor als **`[activated enabled]`** anzeigt, ist das normalerweise der schnellste Hinweis darauf, dass die Extension tatsächlich aktiv ist. Ab **macOS 15 Sequoia** kann MDM bestimmte Security Extensions außerdem als **nicht über die Benutzeroberfläche entfernbar** markieren. Daher ist „in den Systemeinstellungen deaktivieren“ nicht mehr grundsätzlich eine sichere Annahme. Informationen zu den Interna findest du unter [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Aktuelle native Telemetrie, die Defender nutzen können

Aktuelle macOS-Versionen machen einige zuvor nur schwer erkennbaren, benutzergesteuerten Bypasses für Blue Teams deutlich auffälliger:

- **macOS 15+**: Endpoint Security clients können **`gatekeeper_user_override`**-Events empfangen, sodass manuelle Gatekeeper-Bypasses zentral protokolliert werden können.
- **Aktuelle macOS Endpoint Security tooling** kann auch **XProtect malware detection**-Events aufnehmen. Dadurch lässt sich leichter bestätigen, was Apple auf dem Endpoint bereits erkannt hat.
- **macOS 15.4+**: Endpoint Security führt **`tcc_modify`** ein. Damit erhalten Defender endlich eine unterstützte Möglichkeit, **TCC grants/revokes** zu überwachen, anstatt TCC debug logs auszulesen.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Dies ist sowohl für Defender als auch für Red Teamer bei der Selbstbewertung nützlich: Wenn das Ziel über einen ausgereiften ES-basierten Stack verfügt, **können vom Benutzer genehmigte Gatekeeper- / TCC-bypass chains deutlich sichtbarer sein als früher**. Hintergrundinformationen zu diesen Schutzmechanismen finden Sie unter [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) und [TCC](macos-security-protections/macos-tcc/README.md).

## Referenzen

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
