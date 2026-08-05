# macOS-Dateierweiterungs- und URL-Schema-App-Handler

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-Datenbank

Dies ist eine Datenbank aller installierten Anwendungen in macOS, die abgefragt werden kann, um Informationen über jede installierte Anwendung zu erhalten, beispielsweise unterstützte **URL-Schemata**, **Dokumenttypen**, **UTIs** und standardmäßige Handler.

Diese Datenbank kann mit folgendem Befehl ausgegeben werden:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Oder mit dem Tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ist die zentrale Instanz der Datenbank. Es stellt **mehrere XPC-Services** wie `.lsd.installation`, `.lsd.open`, `.lsd.openurl` und weitere bereit. Es **benötigt jedoch bestimmte Entitlements** für Anwendungen, damit diese die offengelegten XPC-Funktionen nutzen können, beispielsweise `.launchservices.changedefaulthandler` oder `.launchservices.changeurlschemehandler`, um Standard-Apps für MIME-Typen oder URL-Schemata zu ändern, sowie weitere.

**`/System/Library/CoreServices/launchservicesd`** beansprucht den Service `com.apple.coreservices.launchservicesd` und kann abgefragt werden, um Informationen über laufende Anwendungen zu erhalten. Die Abfrage ist mit dem Systemtool **`/usr/bin/lsappinfo`** oder mit [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) möglich.

Aus Sicht eines Operators sollte man bedenken, dass es normalerweise **zwei nützliche Ansichten** gibt:

- Die von LaunchServices / `lsd` verwaltete **Registrierungsdatenbank** (gesichert durch `.csstore`-Dateien).
- Die **effektiven Standardwerte pro Benutzer**, die in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` innerhalb des Arrays `LSHandlers` gespeichert sind.

Diese Unterscheidung ist wichtig: Eine Anwendung kann als fähig **registriert** sein, einen Typ oder ein Schema zu verarbeiten, während die **aktuelle Standardanwendung** weiterhin eine andere Bundle-ID haben kann.

## App-Handler für Dateierweiterungen und URL-Schemata

Die folgende Zeile kann nützlich sein, um die Anwendungen zu finden, die Dateien abhängig von der Erweiterung öffnen können:
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
Sie können auch die von einer Anwendung unterstützten Erweiterungen überprüfen, indem Sie Folgendes ausführen:
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

Die nützlichste Datei für die **Standardanwendungen des aktuellen Benutzers** ist in der Regel:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Um daraus **URL scheme**-Handler zu dumpen:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Zum Dumpen von **content-type / UTI**-Handlern:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
So lösen Sie den UTI-Baum einer Beispieldatei auf:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Wenn du eine benutzerfreundlichere CLI zum Abfragen oder Ändern von Standardeinstellungen möchtest:
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

Bei der Triage eines Application Bundles sind diese Schlüssel am wichtigsten:

- **`CFBundleDocumentTypes`**: Dokumentgruppen, die das Bundle nach eigenen Angaben öffnen kann.
- **`LSItemContentTypes`**: die **moderne / bevorzugte** Methode, um Dokumenttypen an UTIs zu binden.
- **`LSHandlerRank`**: von LaunchServices verwendete Rangfolge (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: vom Application implementierte benutzerdefinierte URI-Schemata.
- **`UTExportedTypeDeclarations`**: UTIs, die das Application **besitzt**.
- **`UTImportedTypeDeclarations`**: UTIs, die das Application nicht besitzt, aber vom System erkannt werden sollen.

Ein nützlicher schneller Triage-Befehl ist:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Ein subtiler, aber wichtiger Hinweis: Wenn **`LSItemContentTypes`** vorhanden ist, sind ältere Schlüssel wie **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** und **`CFBundleTypeOSTypes`** effektiv Legacy-Kompatibilitätsdaten. Für die tatsächliche Handler-Auflösung sollte zuerst der UTI-Pfad berücksichtigt werden.

## Offensive Hinweise

Anwendungen müssen nicht ausgeführt werden, um interessant zu werden. Ein abgelegtes oder geklontes `.app`-Bundle kann **von `lsd` automatisch geparst werden, sobald es auf die Festplatte geschrieben wurde**, und seine deklarierten Dokumenttypen / URL-Schemes können registriert werden, ohne dass der Benutzer das Bundle jemals startet.

Dies ist sowohl für die **Erforschung von Persistence / Hijacking** als auch für **Initial-Access-Ketten** nützlich:

- Eine bösartige Anwendung kann eine **seltene Extension** oder eine **benutzerdefinierte UTI** beanspruchen und darauf warten, dass das Opfer die Köderdatei öffnet.
- Eine bösartige Anwendung kann ein **benutzerdefiniertes URL-Scheme** registrieren, das über einen Browser, eine Electron-App, ein Office-Dokument, einen Chat-Client oder eine andere Helper-App erreichbar ist.<sup>[1]</sup>
- Wenn du ein App-Bundle nach dem Build bearbeitest, kannst du LaunchServices mit folgendem Befehl dazu zwingen, es erneut zu parsen:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Beim Testen verdächtiger Bundles sollte besonders auf Folgendes geachtet werden:

- **`LSHandlerRank=Owner`** bei ungewöhnlichen Typen.
- Breite **`CFBundleDocumentTypes`**-Arrays, die viele Dateiendungen beanspruchen.
- **Helper-/Wrapper-Apps**, deren einzig interessantes Verhalten hinter einem Dokument- oder URI-Handler verborgen ist.
- **Shortcut-ähnliche Dateien** (`.webloc`, `.inetloc`, `.fileloc`), die letztlich an LaunchServices weiterleiten. Für Tricks im Stil von `.fileloc` und verwandte Gatekeeper-Aspekte siehe [diese andere Seite](macos-security-protections/macos-fs-tricks/README.md).<sup>[2]</sup>

Wenn dein Ziel passive Codeausführung allein durch das Öffnen eines Ordners oder Auswählen einer Datei ist, sieh dir auch die spezielle Seite zu [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) an, da dies eine andere, aber eng verwandte File-Handler-Angriffsfläche ist.

## Referenzen

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
