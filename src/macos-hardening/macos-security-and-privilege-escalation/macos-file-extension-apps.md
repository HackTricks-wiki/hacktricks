# macOS-Dateierweiterungs- und URL-Schema-App-Handler

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-Datenbank

Dies ist eine Datenbank aller installierten Anwendungen in macOS, die abgefragt werden kann, um Informationen zu den einzelnen installierten Anwendungen abzurufen, beispielsweise unterstützte **URL-Schemata**, **Dokumenttypen**, **UTIs** und Standard-Handler.

Es ist möglich, diese Datenbank mit folgendem Befehl zu dumpen:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Oder mit dem Tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ist das Gehirn der Datenbank. Es stellt **mehrere XPC services** wie `.lsd.installation`, `.lsd.open`, `.lsd.openurl` und weitere bereit. Es **benötigt jedoch auch bestimmte Entitlements**, damit Anwendungen die bereitgestellten XPC-Funktionalitäten verwenden können, etwa `.launchservices.changedefaulthandler` oder `.launchservices.changeurlschemehandler`, um Standard-Apps für MIME types oder URL schemes zu ändern, sowie weitere.

**`/System/Library/CoreServices/launchservicesd`** beansprucht den Service `com.apple.coreservices.launchservicesd` und kann abgefragt werden, um Informationen über laufende Anwendungen zu erhalten. Die Abfrage ist mit dem Systemtool **`/usr/bin/lsappinfo`** oder mit [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) möglich.

Aus Sicht eines Operators sollte man berücksichtigen, dass es normalerweise **zwei nützliche Ansichten** gibt:

- Die von LaunchServices / `lsd` verwaltete **Registrierungsdatenbank** (gespeichert in `.csstore` files).
- Die **effektiven Standardwerte pro Benutzer**, gespeichert in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` innerhalb des `LSHandlers`-Arrays.

Diese Unterscheidung ist wichtig: Eine Anwendung kann als fähig **registriert** sein, einen type oder ein scheme zu verarbeiten, aber der **aktuelle Standard** kann weiterhin eine andere bundle ID sein.

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
Du kannst auch die von einer Anwendung unterstützten Erweiterungen überprüfen mit:
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

Die nützlichste Datei für die **Standardeinstellungen des aktuellen Benutzers** ist normalerweise:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Um daraus **URL scheme**-Handler zu dumpen:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Zum Dumpen der **content-type / UTI**-Handler:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Um den UTI-Baum einer Beispieldatei aufzulösen:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Wenn du eine benutzerfreundlichere CLI zum Abfragen oder Ändern von Standardwerten möchtest:
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

Bei der Analyse eines Application Bundles sind diese Schlüssel am wichtigsten:

- **`CFBundleDocumentTypes`**: Dokumentgruppen, die das Bundle nach eigenen Angaben öffnen kann.
- **`LSItemContentTypes`**: die **moderne / bevorzugte** Methode, um Dokumenttypen an UTIs zu binden.
- **`LSHandlerRank`**: von LaunchServices verwendete Rangfolge (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: von der App implementierte benutzerdefinierte URI-Schemes.
- **`UTExportedTypeDeclarations`**: UTIs, die die App **besitzt**.
- **`UTImportedTypeDeclarations`**: UTIs, die die App nicht besitzt, die das System aber erkennen soll.

Ein nützlicher schneller Triage-Befehl ist:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Ein subtiles, aber wichtiges Detail: Wenn **`LSItemContentTypes`** vorhanden ist, sind ältere Schlüssel wie **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** und **`CFBundleTypeOSTypes`** effektiv Legacy-Kompatibilitätsdaten. Für die tatsächliche Handler-Auflösung sollte zuerst der UTI-Pfad berücksichtigt werden.

## Offensive Hinweise

Anwendungen müssen nicht ausgeführt werden, um interessant zu werden. Ein abgelegtes oder geklontes `.app`-Bundle kann **von `lsd` automatisch geparst werden, sobald es auf die Festplatte geschrieben wurde**, und seine deklarierten Dokumenttypen bzw. URL-Schemas können registriert werden, ohne dass der Benutzer das Bundle jemals startet.

Dies ist sowohl für die **Persistence- / Hijacking-Forschung** als auch für **Initial-Access-Ketten** nützlich:

- Eine schädliche App kann eine **seltene Erweiterung** oder eine **benutzerdefinierte UTI** beanspruchen und darauf warten, dass das Opfer die Lockdatei öffnet.
- Eine schädliche App kann ein **benutzerdefiniertes URL-Schema** registrieren, das über einen Browser, eine Electron-App, ein Office-Dokument, einen Chat-Client oder eine andere Helper-App erreichbar ist.<sup>[[1]](#references)</sup>
- Wenn du ein App-Bundle nach dem Erstellen bearbeitest, kannst du LaunchServices mit folgendem Befehl zu einem erneuten Parsen zwingen:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Beim Testen verdächtiger Bundles sollte besonders auf Folgendes geachtet werden:

- **`LSHandlerRank=Owner`** bei ungewöhnlichen Dateitypen.
- **Breite `CFBundleDocumentTypes`**-Arrays, die viele Erweiterungen beanspruchen.
- **Helper- / wrapper apps**, deren einzig interessantes Verhalten hinter einem Dokument- oder URI-Handler verborgen ist.
- **Shortcut-ähnliche Dateien** (`.webloc`, `.inetloc`, `.fileloc`), die letztlich in LaunchServices weiterleiten. Für Tricks im Stil von `.fileloc` und verwandte Gatekeeper-Aspekte siehe [diese andere Seite](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Wenn das Ziel passive Codeausführung allein durch das Öffnen eines Ordners oder die Auswahl einer Datei ist, sollte auch die spezielle Seite zu [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) geprüft werden, da dies eine andere, aber eng verwandte File-Handler-Angriffsfläche ist.

## Referenzen


- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
