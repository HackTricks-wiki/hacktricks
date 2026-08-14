# macOS-Dateierweiterungs- und URL-Scheme-App-Handler

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-Datenbank

Dies ist eine Datenbank mit allen installierten Anwendungen in macOS, die abgefragt werden kann, um Informationen zu den einzelnen installierten Anwendungen abzurufen, beispielsweise unterstützte **URL-Schemes**, **Dokumenttypen**, **UTIs** und Standard-Handler.

Diese Datenbank kann mit folgendem Befehl ausgegeben werden:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Oder mit dem Tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ist das Gehirn der Datenbank. Es stellt **mehrere XPC-Dienste** wie `.lsd.installation`, `.lsd.open`, `.lsd.openurl` und weitere bereit. Es **benötigt jedoch auch bestimmte Entitlements** für Anwendungen, damit diese die bereitgestellten XPC-Funktionen verwenden können, beispielsweise `.launchservices.changedefaulthandler` oder `.launchservices.changeurlschemehandler`, um Standardanwendungen für MIME-Typen oder URL-Schemata zu ändern, sowie weitere.

**`/System/Library/CoreServices/launchservicesd`** beansprucht den Dienst `com.apple.coreservices.launchservicesd` und kann abgefragt werden, um Informationen über laufende Anwendungen zu erhalten. Die Abfrage ist mit dem Systemtool **`/usr/bin/lsappinfo`** oder mit [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) möglich.

Aus Sicht eines Operators sollte man beachten, dass es normalerweise **zwei nützliche Ansichten** gibt:

- Die von LaunchServices / `lsd` verwaltete **Registrierungsdatenbank** (gespeichert in `.csstore`-Dateien).
- Die **effektiven benutzerspezifischen Standardwerte**, die in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` innerhalb des Arrays `LSHandlers` gespeichert sind.

Diese Unterscheidung ist wichtig: Eine Anwendung kann als fähig **registriert** sein, einen Typ oder ein Schema zu verarbeiten, während die **aktuelle Standardanwendung** weiterhin eine andere Bundle-ID sein kann.

In aktuellen macOS-Versionen ist die Suche nach Registrierungen nicht auf `/Applications` beschränkt: Anwendungen in anderen über Spotlight sichtbaren und zugänglichen Ordnern sowie auf eingebundenen oder freigegebenen Volumes können in die Registrierung aufgenommen werden. Bewahre daher während der Triage die `path`- und Volume-Informationen aus `lsregister -dump` auf und gehe nicht davon aus, dass die Deregistrierung einer Anwendung dauerhaft ist, solange das Bundle weiterhin auffindbar bleibt.<sup>[[4]](#references)</sup>

## Handler für Dateierweiterungen und URL-Schemata

Die folgende Zeile kann nützlich sein, um die Anwendungen zu finden, die Dateien abhängig von deren Erweiterung öffnen können:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Oder verwenden Sie etwas wie [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Sie können auch die von einer Anwendung unterstützten Erweiterungen überprüfen, indem Sie:
```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
## Effektive Handler auflisten

Die nützlichste Datei für die **Standardanwendungen des aktuellen Benutzers** ist normalerweise:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Um **URL scheme**-Handler daraus zu dumpen:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Zum Auslesen der **content-type / UTI**-Handler:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
So lösen Sie den UTI-Baum einer Beispieldatei auf:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Wenn du eine benutzerfreundlichere CLI zum Abfragen oder Ändern von Defaults möchtest:
```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```
### Datei-spezifische `Open With`-Überschreibungen

Die Handler-Auflösung verfügt außerdem über eine **dateispezifische** Ebene. Bevor auf die UTI der Datei und den globalen Standard des Benutzers zurückgegriffen wird, prüft LaunchServices das Extended Attribute `com.apple.LaunchServices.OpenWith`. Finder erstellt es, wenn für eine Datei **Always Open With** ausgewählt wird; sein Wert ist eine binäre Property List, die einen Anwendungspfad, eine Bundle-ID und einen Versionsselektor enthält.<sup>[[3]](#references)</sup>

Untersuche und dekodiere es, ohne der Dateinamenerweiterung zu vertrauen:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Dies ist nützlich, wenn ein einzelner Köder trotz eines harmlosen globalen Standards, den `duti`, `dutix` oder `LSHandlers` melden, eine unerwartete Anwendung öffnet. In einem kontrollierten Lab kann der exakte opaque value aus einer über den Finder konfigurierten Datei kopiert werden; durch das Löschen wird die normale auf dem Dateityp basierende Auflösung wiederhergestellt:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Interessante Info.plist-Schlüssel

Bei der Triage eines Application Bundles sind diese Schlüssel am wichtigsten:

- **`CFBundleDocumentTypes`**: Dokumentgruppen, die das Bundle öffnen kann.
- **`LSItemContentTypes`**: die **moderne / bevorzugte** Methode, um Dokumenttypen an UTIs zu binden.
- **`LSHandlerRank`**: von LaunchServices verwendete Rangfolge (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: von der App implementierte benutzerdefinierte URI-Schemes.
- **`UTExportedTypeDeclarations`**: UTIs, die der App **gehören**.
- **`UTImportedTypeDeclarations`**: UTIs, die der App nicht gehören, die das System aber erkennen soll.

Ein nützlicher schneller Triage-Befehl ist:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Ein subtiles, aber wichtiges Detail: Wenn **`LSItemContentTypes`** vorhanden ist, sind ältere Schlüssel wie **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** und **`CFBundleTypeOSTypes`** faktisch Legacy-Kompatibilitätsdaten. Für die tatsächliche Handler-Auflösung sollte zuerst der UTI-Pfad berücksichtigt werden.

## Offensive Hinweise

Anwendungen müssen nicht ausgeführt werden, um interessant zu werden. Ein abgelegtes oder geklontes `.app`-Bundle kann **von `lsd` automatisch geparst werden, sobald es auf die Festplatte geschrieben wurde**, und seine deklarierten Dokumenttypen / URL-Schemata können registriert werden, ohne dass der Benutzer das Bundle jemals startet.

Dies ist sowohl für die Forschung zu **Persistence / Hijacking** als auch für **Initial-Access-Ketten** nützlich:

- Eine bösartige Anwendung kann eine **seltene Dateiendung** oder eine **benutzerdefinierte UTI** beanspruchen und darauf warten, dass das Opfer die Köderdatei öffnet.
- Eine bösartige Anwendung kann ein **benutzerdefiniertes URL-Schema** registrieren, das über einen Browser, eine Electron-App, ein Office-Dokument, einen Chat-Client oder eine andere Helper-App erreichbar ist.<sup>[[1]](#references)</sup>
- Um die normale Standardauflösung vom Testen eines bestimmten möglichen Handlers zu trennen, rufe das Schema über LaunchServices mit `open 'targetscheme://host/path?value=test'` auf und sprich anschließend ein bestimmtes registriertes Bundle mit `open -b com.vendor.Target 'targetscheme://host/path?value=test'` an. Dies ist nützlich, um zu prüfen, wie die empfangende Anwendung vom Angreifer kontrollierte URL-Komponenten validiert und dekodiert.<sup>[[1]](#references)</sup>
- Wenn du ein App-Bundle nach dem Erstellen bearbeitest, kannst du LaunchServices mit folgendem Befehl zwingen, es erneut zu parsen:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Beim Testen verdächtiger Bundles solltest du besonders auf Folgendes achten:

- **`LSHandlerRank=Owner`** bei ungewöhnlichen Dateitypen.
- **Breite `CFBundleDocumentTypes`**-Arrays, die viele Erweiterungen beanspruchen.
- **Helper- / Wrapper-Apps**, deren einzig interessantes Verhalten hinter einem Dokument- oder URI-Handler verborgen ist.
- **Shortcut-ähnliche Dateien** (`.webloc`, `.inetloc`, `.fileloc`), die letztendlich an LaunchServices weiterleiten. Für `.fileloc`-artige Tricks und damit verbundene Gatekeeper-Aspekte siehe [diese andere Seite](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Wenn dein Ziel passive Code-Ausführung allein durch das Öffnen eines Ordners oder Auswählen einer Datei ist, solltest du auch die spezielle Seite zu [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) prüfen, da dies eine andere, aber eng verwandte File-Handler-Angriffsfläche ist.



## References

- [1] [Objective-See - Remote Mac-Exploitation über benutzerdefinierte URL-Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Das Gate umgehen: Ein genauerer Blick auf Gatekeeper-Schwachstellen in macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Wie macOS eine Datei in der richtigen App öffnet](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - LaunchServices in macOS Sequoia steuern](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
