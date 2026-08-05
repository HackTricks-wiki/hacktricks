# macOS-Sicherheit & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlagen von macOS

Wenn du mit macOS nicht vertraut bist, solltest du mit den Grundlagen von macOS beginnen:

- Spezielle macOS-**Dateien & Berechtigungen:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Allgemeine macOS-**Benutzer**


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- Die **Architektur** des K**ernels**


{{#ref}}
mac-os-architecture/
{{#endref}}

- Allgemeine macOS-N**etzwerkdienste & Protokolle**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Open-Source**-macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Um ein `tar.gz` herunterzuladen, ändere eine URL wie [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) zu [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In Unternehmen werden **macOS**-Systeme sehr wahrscheinlich **mit einem MDM verwaltet**. Daher ist es aus der Perspektive eines Angreifers interessant zu wissen, **wie das funktioniert**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS – Untersuchen, Debuggen und Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## macOS-Sicherheitsschutz


{{#ref}}
macos-security-protections/
{{#endref}}

## Angriffsfläche

### Dateiberechtigungen

Wenn ein **als root laufender Prozess** eine Datei schreibt, die von einem Benutzer kontrolliert werden kann, könnte der Benutzer dies zur **Privilege Escalation** missbrauchen.\
Dies kann in den folgenden Situationen auftreten:

- Die verwendete Datei wurde bereits von einem Benutzer erstellt (im Besitz des Benutzers)
- Die verwendete Datei ist aufgrund einer Gruppe für den Benutzer beschreibbar
- Die verwendete Datei befindet sich in einem Verzeichnis, das dem Benutzer gehört (der Benutzer könnte die Datei erstellen)
- Die verwendete Datei befindet sich in einem Verzeichnis, das root gehört, aber der Benutzer hat aufgrund einer Gruppe Schreibzugriff darauf (der Benutzer könnte die Datei erstellen)

Eine **Datei erstellen** zu können, die von **root verwendet** werden soll, ermöglicht es einem Benutzer, deren **Inhalt auszunutzen** oder sogar **symlinks/hardlinks** zu erstellen, um auf einen anderen Ort zu verweisen.

Bei dieser Art von Schwachstellen darfst du nicht vergessen, **verwundbare `.pkg`-Installer zu prüfen**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Handler für Dateierweiterungen und URL-Schemas

Ungewöhnliche, über Dateierweiterungen registrierte Apps könnten missbraucht werden, und verschiedene Anwendungen können so registriert werden, dass sie bestimmte Protokolle öffnen


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

Unter macOS können **Anwendungen und Binaries über Berechtigungen** verfügen, um auf Ordner oder Einstellungen zuzugreifen, wodurch sie privilegierter als andere sind.

Daher muss ein Angreifer, der einen macOS-Rechner erfolgreich kompromittieren möchte, seine **TCC-Berechtigungen eskalieren** (oder je nach Bedarf sogar **SIP umgehen**).

Diese Berechtigungen werden gewöhnlich in Form von **Entitlements** vergeben, mit denen die Anwendung signiert ist. Alternativ kann die Anwendung bestimmte Zugriffe anfordern; nachdem der **Benutzer sie genehmigt hat**, sind sie in den **TCC-Datenbanken** zu finden. Eine weitere Möglichkeit, wie ein Prozess diese Berechtigungen erhalten kann, besteht darin, ein **Kindprozess eines Prozesses** mit diesen **Berechtigungen** zu sein, da sie gewöhnlich **vererbt** werden.

Folge diesen Links, um verschiedene Möglichkeiten zu finden, [**Berechtigungen in TCC zu eskalieren**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**TCC zu umgehen**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) und zu erfahren, wie [**SIP in der Vergangenheit umgangen wurde**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS herkömmliche Privilege Escalation

Aus der Perspektive eines Red Teams solltest du natürlich ebenfalls daran interessiert sein, zu root zu eskalieren. Im folgenden Beitrag findest du einige Hinweise:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS-Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Referenzen

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
