# macOS Dateierweiterung & URL-Schema-App-Handler

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-Datenbank

Dies ist eine Datenbank aller installierten Anwendungen in macOS, die abgefragt werden kann, um Informationen über jede installierte Anwendung zu erhalten, wie z.B. die unterstützten URL-Schemata und MIME-Typen.

Es ist möglich, diese Datenbank mit folgendem Befehl zu dumpen:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Oder mit dem Tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ist das Gehirn der Datenbank. Es bietet **mehrere XPC-Dienste** wie `.lsd.installation`, `.lsd.open`, `.lsd.openurl` und mehr. Aber es **benötigt auch einige Berechtigungen** für Anwendungen, um die exponierten XPC-Funktionalitäten nutzen zu können, wie `.launchservices.changedefaulthandler` oder `.launchservices.changeurlschemehandler`, um Standardanwendungen für MIME-Typen oder URL-Schemata und andere zu ändern.

**`/System/Library/CoreServices/launchservicesd`** beansprucht den Dienst `com.apple.coreservices.launchservicesd` und kann abgefragt werden, um Informationen über laufende Anwendungen zu erhalten. Es kann mit dem Systemtool /**`usr/bin/lsappinfo`** oder mit [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) abgefragt werden.

## Datei-Erweiterung & URL-Schema-Anwendungs-Handler

Die folgende Zeile kann nützlich sein, um die Anwendungen zu finden, die Dateien je nach Erweiterung öffnen können:
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
```
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
{{#include ../../banners/hacktricks-training.md}}
