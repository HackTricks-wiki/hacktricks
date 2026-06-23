# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-Datenbank

Dies ist eine Datenbank aller in macOS installierten Anwendungen, die abgefragt werden kann, um Informationen zu jeder installierten Anwendung zu erhalten, wie unterstützte **URL schemes**, **document types**, **UTIs** und Standard-Handler.

Es ist möglich, diese Datenbank mit folgendem Befehl zu dumpen:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Oder mit dem Tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ist das Gehirn der Datenbank. Es stellt **mehrere XPC services** bereit, wie `.lsd.installation`, `.lsd.open`, `.lsd.openurl` und mehr. Es **erfordert aber auch einige entitlements** für Anwendungen, um die exponierten XPC-Funktionalitäten nutzen zu können, wie `.launchservices.changedefaulthandler` oder `.launchservices.changeurlschemehandler`, um Standard-Apps für MIME types oder URL schemes und andere zu ändern.

**`/System/Library/CoreServices/launchservicesd`** beansprucht den Service `com.apple.coreservices.launchservicesd` und kann abgefragt werden, um Informationen über laufende Anwendungen zu erhalten. Es kann mit dem Systemtool **`/usr/bin/lsappinfo`** oder mit [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) abgefragt werden.

Aus Operator-Perspektive solltest du beachten, dass es normalerweise **zwei nützliche Ansichten** gibt:

- Die **registration database**, verwaltet von LaunchServices / `lsd` (unterstützt durch `.csstore` Dateien).
- Die **pro Benutzer effektiven Standardwerte**, gespeichert in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` innerhalb des `LSHandlers` Arrays.

Diese Unterscheidung ist wichtig: Eine Anwendung kann **registriert** sein, um einen Typ oder ein Scheme zu verarbeiten, aber der **aktuelle Standard** kann dennoch ein anderes Bundle ID sein.

## File Extension & URL scheme app handlers

Die folgende Zeile kann nützlich sein, um die Anwendungen zu finden, die Dateien abhängig von der Erweiterung öffnen können:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Oder verwende etwas wie [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Du kannst auch die von einer Anwendung unterstützten Erweiterungen prüfen, indem du:
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
## Auflisten effektiver Handler

Die nützlichste Datei für die **Standardeinstellungen des aktuellen Benutzers** ist normalerweise:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Um die **URL scheme**-Handler daraus zu dumpen:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Um **content-type / UTI**-Handler zu dumpen:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Um den UTI-Baum einer Beispieldatei aufzulösen:
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
## Interessante Info.plist-Schlüssel

Beim Triage eines Application-Bundles sind diese Schlüssel am wichtigsten:

- **`CFBundleDocumentTypes`**: Dokumentgruppen, die das Bundle zu öffnen vorgibt.
- **`LSItemContentTypes`**: die **moderne / bevorzugte** Art, Dokumenttypen an UTIs zu binden.
- **`LSHandlerRank`**: Ranking, das von LaunchServices verwendet wird (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: benutzerdefinierte URI-Schemata, die von der App implementiert werden.
- **`UTExportedTypeDeclarations`**: UTIs, die die App **besitzt**.
- **`UTImportedTypeDeclarations`**: UTIs, die die App nicht besitzt, aber vom System erkannt werden sollen.

Ein nützlicher Schnelltriage-Befehl ist:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Ein subtiler, aber wichtiger Detailpunkt: Wenn **`LSItemContentTypes`** vorhanden ist, sind ältere Keys wie **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** und **`CFBundleTypeOSTypes`** effektiv Legacy-Kompatibilitätsdaten. Für die tatsächliche Handler-Auflösung solltest du zuerst den UTI-Pfad betrachten.

## Offensive notes

Applications müssen nicht ausgeführt werden, um interessant zu werden. Ein abgelegtes oder geklontes `.app`-Bundle kann **von `lsd` automatisch geparst werden, sobald es auf die Festplatte geschrieben wird**, und seine deklarierten document types / URL schemes können registriert werden, ohne dass der Benutzer das Bundle jemals startet.

Das ist sowohl für **persistence / hijacking research** als auch für **initial-access chains** nützlich:

- Eine bösartige App kann eine **seltene Erweiterung** oder eine **custom UTI** beanspruchen und warten, bis das Opfer die Lockdatei öffnet.
- Eine bösartige App kann ein **custom URL scheme** registrieren, das über einen Browser, eine Electron App, ein office document, einen chat client oder eine andere helper app erreichbar ist.
- Wenn du ein App-Bundle nach dem Build bearbeitest, kannst du LaunchServices dazu zwingen, es erneut zu parsen mit:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Beim Testen verdächtiger Bundles achte besonders auf:

- **`LSHandlerRank=Owner`** bei unüblichen Typen.
- **Breite `CFBundleDocumentTypes`**-Arrays, die viele Erweiterungen beanspruchen.
- **Helper- / Wrapper-Apps**, deren einzig interessantes Verhalten hinter einem Dokument- oder URI-Handler liegt.
- **Shortcut-ähnliche Dateien** (`.webloc`, `.inetloc`, `.fileloc`), die am Ende in LaunchServices dispatchen. Für `.fileloc`-ähnliche Tricks und verwandte Gatekeeper-Winkel siehe [diese andere Seite](macos-security-protections/macos-fs-tricks/README.md).

Wenn dein Ziel passive Code-Ausführung durch bloßes Browsen zu einem Ordner oder das Auswählen einer Datei ist, prüfe auch die dedizierte Seite zu [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), da dies eine andere, aber eng verwandte File-Handler-Angriffsfläche ist.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
