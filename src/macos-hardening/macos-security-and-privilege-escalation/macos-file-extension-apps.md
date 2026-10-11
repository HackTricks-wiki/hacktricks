# macOS-App-Handler für Dateierweiterungen und URL-Schemes

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-Datenbank

Dies ist eine Datenbank aller installierten Anwendungen unter macOS. Sie kann abgefragt werden, um Informationen zu den installierten Anwendungen abzurufen, etwa zu unterstützten **URL-Schemes**, **Dokumenttypen**, **UTIs** und Standard-Handlern.

Diese Datenbank lässt sich wie folgt ausgeben:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Oder mithilfe des Tools [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ist das Gehirn der Datenbank. Es stellt **mehrere XPC-Dienste** wie `.lsd.installation`, `.lsd.open`, `.lsd.openurl` und weitere bereit. Es **benötigt jedoch auch bestimmte Entitlements** für Anwendungen, damit diese die bereitgestellten XPC-Funktionen nutzen können, etwa `.launchservices.changedefaulthandler` oder `.launchservices.changeurlschemehandler`, um Standard-Apps für MIME-Typen oder URL-Schemas zu ändern, und weitere.

**`/System/Library/CoreServices/launchservicesd`** beansprucht den Dienst `com.apple.coreservices.launchservicesd` und kann abgefragt werden, um Informationen über laufende Anwendungen zu erhalten. Die Abfrage ist mit dem Systemtool **`/usr/bin/lsappinfo`** oder mit [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) möglich.

Aus Sicht eines Operators sollten Sie bedenken, dass es normalerweise **zwei nützliche Ansichten** gibt:

- Die **Registrierungsdatenbank**, die von LaunchServices / `lsd` verwaltet wird (gespeichert in `.csstore`-Dateien).
- Die **effektiven Standardwerte pro Benutzer**, die in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` im Array `LSHandlers` gespeichert sind.

Dieser Unterschied ist wichtig: Eine Anwendung kann **registriert** sein, um einen Typ oder ein Schema zu verarbeiten, während die **aktuelle Standard-App** weiterhin eine andere Bundle-ID hat.

Bei neueren macOS-Versionen ist die Erkennung registrierter Apps nicht auf `/Applications` beschränkt: Apps in anderen zugänglichen, für Spotlight sichtbaren Ordnern sowie auf eingebundenen oder freigegebenen Volumes können in die Registrierung aufgenommen werden. Bewahren Sie daher bei der Triage die Pfad- und Volume-Informationen aus `lsregister -dump` auf und gehen Sie nicht davon aus, dass die Abmeldung einer App dauerhaft ist, solange das Bundle weiterhin gefunden werden kann.<sup>[[4]](#references)</sup>

## Handler für Dateierweiterungen und URL-Schemas

Die folgende Zeile kann nützlich sein, um Anwendungen zu finden, die Dateien je nach Erweiterung öffnen können:

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

Du kannst auch die von einer Anwendung unterstützten Erweiterungen prüfen, indem du Folgendes ausführst:

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

Die nützlichste Datei für die **Standardhandler des aktuellen Benutzers** ist in der Regel:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Um die **URL-Schema**-Handler daraus auszulesen:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Um **content-type / UTI**-Handler auszulesen:

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

### Dateiweise `Open With`-Überschreibungen

Bei der Handler-Auflösung gibt es außerdem eine **dateispezifische** Ebene. Bevor LaunchServices auf die UTI der Datei und den globalen Standard des Benutzers zurückgreift, prüft es das erweiterte Attribut `com.apple.LaunchServices.OpenWith`. Finder erstellt es, wenn für eine Datei **Immer öffnen mit** ausgewählt wird; sein Wert ist eine binäre Property List mit einem Anwendungspfad, einer Bundle-ID und einem Versionsselektor.<sup>[[3]](#references)</sup>

Untersuche und dekodiere es, ohne der Dateinamenerweiterung zu vertrauen:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Dies ist nützlich, wenn ein einzelner Köder in einer unerwarteten Anwendung geöffnet wird, obwohl `duti`, `dutix` oder `LSHandlers` einen harmlosen globalen Standard melden. Für ein kontrolliertes Lab kann der genaue undurchsichtige Wert aus einer über den Finder konfigurierten Datei kopiert werden; durch Löschen wird die normale typbasierte Auflösung wiederhergestellt:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interessante Info.plist-Schlüssel

Bei der Triage eines App-Bundles sind diese Schlüssel am wichtigsten:

- **`CFBundleDocumentTypes`**: Dokumentgruppen, die das Bundle angeblich öffnen kann.
- **`LSItemContentTypes`**: die **moderne / bevorzugte** Methode, um Dokumenttypen an UTIs zu binden.
- **`LSHandlerRank`**: von LaunchServices verwendete Rangfolge (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: von der App implementierte benutzerdefinierte URI-Schemas.
- **`UTExportedTypeDeclarations`**: UTIs, die der App **gehören**.
- **`UTImportedTypeDeclarations`**: UTIs, die der App nicht gehören, die das System aber erkennen soll.

Ein nützlicher schneller Triage-Befehl ist:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Ein subtiler, aber wichtiger Punkt: Wenn **`LSItemContentTypes`** vorhanden ist, sind ältere Schlüssel wie **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** und **`CFBundleTypeOSTypes`** praktisch nur noch Legacy-Kompatibilitätsdaten. Für die tatsächliche Handler-Auflösung sollte zuerst der UTI-Pfad berücksichtigt werden.

## Offensive Hinweise

Anwendungen müssen nicht ausgeführt werden, um interessant zu sein. Ein abgelegtes oder geklontes `.app`-Bundle kann **automatisch von `lsd` geparst werden, sobald es auf die Festplatte geschrieben wird**. Seine deklarierten Dokumenttypen und URL-Schemes können registriert werden, ohne dass der Benutzer das Bundle jemals startet.

Das ist sowohl für die **Persistence-/Hijacking-Forschung** als auch für **Initial-Access-Ketten** nützlich:

- Eine schädliche App kann eine **seltene Erweiterung** oder eine **benutzerdefinierte UTI** beanspruchen und darauf warten, dass das Opfer die Köderdatei öffnet.
- Eine schädliche App kann ein **benutzerdefiniertes URL-Scheme** registrieren, das über einen Browser, eine Electron-App, ein Office-Dokument, einen Chat-Client oder eine andere Helper-App erreichbar ist.<sup>[[1]](#references)</sup>
- Um die normale Standardauflösung vom Testen eines bestimmten Handler-Kandidaten zu unterscheiden, rufe das Scheme über LaunchServices mit `open 'targetscheme://host/path?value=test'` auf und gib anschließend mit `open -b com.vendor.Target 'targetscheme://host/path?value=test'` ein bestimmtes registriertes Bundle an. Das ist nützlich, um zu prüfen, wie die empfangende App angreifergesteuerte URL-Komponenten validiert und dekodiert.<sup>[[1]](#references)</sup>
- Wenn du ein App-Bundle nach dem Erstellen bearbeitest, kannst du LaunchServices dazu zwingen, es erneut zu parsen:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Beim Testen verdächtiger Bundles solltest du besonders auf Folgendes achten:

- **`LSHandlerRank=Owner`** bei ungewöhnlichen Typen.
- **Breit gefasste `CFBundleDocumentTypes`**-Arrays, die viele Erweiterungen beanspruchen.
- **Helper- / Wrapper-Apps**, deren einzig interessantes Verhalten hinter einem Dokument- oder URI-Handler steckt.
- **Verknüpfungsähnliche Dateien** (`.webloc`, `.inetloc`, `.fileloc`), die schließlich an LaunchServices übergeben werden. Informationen zu Tricks mit Dateien im `.fileloc`-Stil und verwandten Gatekeeper-Angriffspunkten findest du auf [dieser anderen Seite](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Wenn dein Ziel passive Codeausführung allein durch das Aufrufen eines Ordners oder Auswählen einer Datei ist, sieh dir auch die spezielle Seite zu [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) an, da es sich dabei um eine andere, aber eng verwandte Angriffsfläche für Datei-Handler handelt.



## References

- [1] [Objective-See - Remote Mac-Exploitation über benutzerdefinierte URL-Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Das Gate umgehen: Ein genauerer Blick auf Gatekeeper-Schwachstellen in macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Wie macOS eine Datei in der richtigen App öffnet](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - LaunchServices in macOS Sequoia steuern](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
