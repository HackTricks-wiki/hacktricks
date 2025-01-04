# macOS Sicherheit & Privilegieneskalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegendes zu MacOS

Wenn Sie mit macOS nicht vertraut sind, sollten Sie die Grundlagen von macOS lernen:

- Besondere macOS **Dateien & Berechtigungen:**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Häufige macOS **Benutzer**

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- Die **Architektur** des k**ernels**

{{#ref}}
mac-os-architecture/
{{#endref}}

- Häufige macOS n**etzwerkdienste & Protokolle**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Open Source** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Um ein `tar.gz` herunterzuladen, ändern Sie eine URL wie [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) zu [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In Unternehmen werden **macOS** Systeme höchstwahrscheinlich **mit einem MDM verwaltet**. Daher ist es aus der Perspektive eines Angreifers interessant zu wissen, **wie das funktioniert**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspektion, Debugging und Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Sicherheitsmaßnahmen

{{#ref}}
macos-security-protections/
{{#endref}}

## Angriffsfläche

### Datei Berechtigungen

Wenn ein **Prozess, der als root läuft,** eine Datei schreibt, die von einem Benutzer kontrolliert werden kann, könnte der Benutzer dies ausnutzen, um **Privilegien zu eskalieren**.\
Dies könnte in den folgenden Situationen auftreten:

- Die verwendete Datei wurde bereits von einem Benutzer erstellt (gehört dem Benutzer)
- Die verwendete Datei ist aufgrund einer Gruppe für den Benutzer beschreibbar
- Die verwendete Datei befindet sich in einem Verzeichnis, das dem Benutzer gehört (der Benutzer könnte die Datei erstellen)
- Die verwendete Datei befindet sich in einem Verzeichnis, das root gehört, aber der Benutzer hat aufgrund einer Gruppe Schreibzugriff darauf (der Benutzer könnte die Datei erstellen)

In der Lage zu sein, eine **Datei zu erstellen**, die von **root verwendet wird**, ermöglicht es einem Benutzer, **von ihrem Inhalt zu profitieren** oder sogar **Symlinks/Hardlinks** zu erstellen, um sie an einen anderen Ort zu verweisen.

Für diese Art von Schwachstellen vergessen Sie nicht, **anfällige `.pkg`-Installer** zu überprüfen:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Dateierweiterung & URL-Schema-App-Handler

Seltsame Apps, die durch Dateierweiterungen registriert sind, könnten missbraucht werden, und verschiedene Anwendungen können registriert werden, um spezifische Protokolle zu öffnen.

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilegieneskalation

In macOS **können Anwendungen und Binärdateien Berechtigungen** haben, um auf Ordner oder Einstellungen zuzugreifen, die sie privilegierter machen als andere.

Daher muss ein Angreifer, der eine macOS-Maschine erfolgreich kompromittieren möchte, seine **TCC-Berechtigungen eskalieren** (oder sogar **SIP umgehen**, je nach seinen Bedürfnissen).

Diese Berechtigungen werden normalerweise in Form von **Entitlements** vergeben, mit denen die Anwendung signiert ist, oder die Anwendung könnte einige Zugriffe angefordert haben, und nachdem der **Benutzer diese genehmigt hat**, können sie in den **TCC-Datenbanken** gefunden werden. Eine andere Möglichkeit, wie ein Prozess diese Berechtigungen erhalten kann, besteht darin, ein **Kind eines Prozesses**
