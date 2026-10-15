# macOS-Dateierweiterungen und App-Handler für URL-Schemes

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices-Datenbank

Dies ist eine Datenbank aller installierten Anwendungen in macOS, die abgefragt werden kann, um Informationen zu jeder installierten Anwendung abzurufen, z. B. unterstützte **URL-Schemes**, **Dokumenttypen**, **UTIs** und Standard-Handler.

Diese Datenbank kann wie folgt ausgegeben werden:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Oder mit dem Tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** ist das Gehirn der Datenbank. Es stellt **mehrere XPC-Dienste** wie `.lsd.installation`, `.lsd.open`, `.lsd.openurl` und weitere bereit. Um die bereitgestellten XPC-Funktionen nutzen zu können, **benötigen Anwendungen jedoch bestimmte Entitlements**, etwa `.launchservices.changedefaulthandler` oder `.launchservices.changeurlschemehandler`, um Standard-Apps für MIME-Typen oder URL-Schemata zu ändern, und weitere.

**`/System/Library/CoreServices/launchservicesd`** beansprucht den Dienst `com.apple.coreservices.launchservicesd` und kann abgefragt werden, um Informationen über laufende Anwendungen zu erhalten. Die Abfrage ist mit dem Systemtool **`/usr/bin/lsappinfo`** oder mit [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) möglich.

Aus Sicht eines Operators solltest du bedenken, dass es üblicherweise **zwei nützliche Ansichten** gibt:

- Die **Registrierungsdatenbank**, die von LaunchServices / `lsd` verwaltet wird und auf `.csstore`-Dateien basiert.
- Die **effektiven benutzerspezifischen Standards**, die in der `LSHandlers`-Array unter `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` gespeichert sind.

Diese Unterscheidung ist wichtig: Eine Anwendung kann für einen Typ oder ein Schema **registriert** sein, aber die **aktuelle Standard-App** kann weiterhin eine andere Bundle-ID haben.

Bei aktuellen macOS-Versionen ist die Suche nach Registrierungen nicht auf `/Applications` beschränkt: Apps in anderen für Spotlight sichtbaren und zugänglichen Ordnern sowie auf eingebundenen oder freigegebenen Volumes können in die Registry aufgenommen werden. Bewahre daher bei der Triage die `path`- und Volume-Informationen aus `lsregister -dump` auf und gehe nicht davon aus, dass die Abmeldung einer App dauerhaft ist, solange das Bundle weiterhin auffindbar ist.<sup>[[4]](#references)</sup>

## Handler für Dateierweiterungen und URL-Schemata

Die folgende Zeile kann hilfreich sein, um Anwendungen zu finden, die Dateien abhängig von ihrer Erweiterung öffnen können:

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

## Aufzählen effektiver Handler

Die nützlichste Datei für die **Standardeinstellungen des aktuellen Benutzers** ist normalerweise:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Um die Handler für **URL scheme** daraus zu dumpen:

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

Wenn du eine benutzerfreundlichere CLI verwenden möchtest, um Standardwerte abzufragen oder zu ändern:

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

### Dateispezifische `Open With`-Überschreibungen

Bei der Handler-Auflösung gibt es außerdem eine **dateispezifische** Ebene. Bevor LaunchServices auf die UTI der Datei und den globalen Standard des Benutzers zurückgreift, prüft es das erweiterte Attribut `com.apple.LaunchServices.OpenWith`. Finder erstellt es, wenn für eine Datei **Immer öffnen mit** ausgewählt wird; sein Wert ist eine binäre Property List mit einem Anwendungspfad, einer Bundle-Kennung und einem Versionsselektor.<sup>[[3]](#references)</sup>

Untersuchen und dekodieren Sie es, ohne der Dateinamenerweiterung zu vertrauen:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Dies ist nützlich, wenn ein einzelner Lure trotz eines harmlosen globalen Standardwerts, den `duti`, `dutix` oder `LSHandlers` melden, mit einer unerwarteten Anwendung geöffnet wird. In einem kontrollierten Lab lässt sich der genaue opake Wert aus einer über den Finder konfigurierten Datei kopieren; durch Löschen wird die normale typbasierte Auflösung wiederhergestellt:

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
- **`LSItemContentTypes`**: die **moderne / bevorzugte** Methode, Dokumenttypen an UTIs zu binden.
- **`LSHandlerRank`**: Rangfolge, die von LaunchServices verwendet wird (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: benutzerdefinierte URI-Schemes, die von der App implementiert werden.
- **`UTExportedTypeDeclarations`**: UTIs, die der App **gehören**.
- **`UTImportedTypeDeclarations`**: UTIs, die der App nicht gehören, die das System aber erkennen soll.

Ein nützlicher Befehl für eine schnelle Triage ist:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Ein subtiles, aber wichtiges Detail: Wenn **`LSItemContentTypes`** vorhanden ist, sind ältere Keys wie **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** und **`CFBundleTypeOSTypes`** effektiv Legacy-Kompatibilitätsdaten. Bei der tatsächlichen Handler-Auflösung sollte zuerst der UTI-Pfad berücksichtigt werden.

## Offensive Hinweise

Anwendungen müssen nicht ausgeführt werden, damit ihre Handler-Registrierungen interessant werden. **Das Schreiben eines `.app`-Bundles allein garantiert jedoch keine sofortige Registrierung.** Finder kann eine App registrieren, wenn es sie entdeckt, auch wenn ein Benutzer ihren Ordner durchsucht; die Registrierung kann auch beim Booten oder Anmelden oder durch einen expliziten Registrierungsaufruf erfolgen. Prüfe `lsregister -dump`, bevor du eine Registrierung testest. Die Registrierung allein startet die App nicht und macht sie auch nicht zum effektiven Standard.<sup>[[5]](#references)</sup> Informationen zu den Voraussetzungen für Persistence findest du unter [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Das ist sowohl für **Persistence- / Hijacking-Forschung** als auch für **Initial-Access-Ketten** nützlich:

- Eine schädliche App kann eine **seltene Dateiendung** oder eine **benutzerdefinierte UTI** beanspruchen und darauf warten, dass das Opfer die Köderdatei öffnet.
- Eine schädliche App kann ein **benutzerdefiniertes URL-Scheme** registrieren, das über einen Browser, eine Electron-App, ein Office-Dokument, einen Chat-Client oder eine andere Helper-App erreichbar ist.<sup>[[1]](#references)</sup>
- Um die normale Standardauflösung von einem Test eines bestimmten möglichen Handlers zu unterscheiden, rufe das Scheme über LaunchServices mit `open 'targetscheme://host/path?value=test'` auf. Anschließend kannst du mit `open -b com.vendor.Target 'targetscheme://host/path?value=test'` ein bestimmtes registriertes Bundle ansprechen. Das ist nützlich, um zu prüfen, wie die empfangende App angreifergesteuerte URL-Komponenten validiert und dekodiert.<sup>[[1]](#references)</sup>
- Wenn du ein App-Bundle nach dem Erstellen bearbeitest, kannst du LaunchServices dazu zwingen, es erneut zu parsen:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Beim Testen verdächtiger Bundles besonders auf Folgendes achten:

- **`LSHandlerRank=Owner`** bei ungewöhnlichen Typen.
- **Breite `CFBundleDocumentTypes`**-Arrays, die viele Dateiendungen beanspruchen.
- **Helper- / Wrapper-Apps**, deren einzig interessantes Verhalten hinter einem Dokument- oder URI-Handler steckt.
- **Shortcut-ähnliche Dateien** (`.webloc`, `.inetloc`, `.fileloc`), die schließlich an LaunchServices weiterleiten. Zu Tricks im Stil von `.fileloc` und verwandten Gatekeeper-Aspekten siehe [diese andere Seite](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### URL-Parameter, die an nachgelagerte Optionen weitergereicht werden

Die Bestätigung des externen Protokolls durch einen Browser genehmigt nur das Öffnen des Handlers; dadurch werden die URL-Parameter nicht vertrauenswürdig. Verfolgen Sie den URL-Parser der empfangenden App bis zu jeder Bibliothek, Media-Engine, jedem Hilfsprozess und jeder Option zum Schreiben von Dateien. Achten Sie auf ein Präfix für Query-Keys, das URL-Felder in nachgelagerte Optionsnamen umwandelt. Testen Sie sowohl wörtliche als auch percent-kodierte Trennzeichen mit einem harmlosen Marker in einem Wegwerf-Account.<sup>[[6]](#references)</sup>

Überprüfen Sie die **endgültige Option, die von der nachgelagerten Komponente akzeptiert wird**, nicht nur die anfängliche Verarbeitung durch die App. Bei einem Handler konnten Query-Keys mit Präfix bis zu mpv-Eingabebefehlen gelangen; selbst das Blockieren dieser Option ließ noch einen Pfad zum Schreiben von Dateien offen. Testen Sie die erreichbare Optionsklasse, nicht nur einen bekannten gefährlichen Key.<sup>[[7]](#references)</sup>

### Integrierter `applescript://`-Handler

Der URL-Handler `applescript://com.apple.scripteditor` akzeptiert `action=new` und einen URL-kodierten `script`-Parameter. Ein Browser-Link kann daher Script Editor mit bereits im Editor befindlichem, vom Angreifer kontrolliertem AppleScript öffnen, sodass kein Einfügen in Terminal erforderlich ist. **Die Ausführung erfolgt nicht automatisch**: Der Browser fragt möglicherweise, ob Script Editor geöffnet werden soll, und der Benutzer muss das Script ausführen.<sup>[[8]](#references)</sup>

Neuere macOS-Versionen können eine Warnung zu Script-Dokumenten anzeigen, während XProtect AppleScript bei der Ausführung scannt.<sup>[[8]](#references)[[9]](#references)</sup>

Verwenden Sie eine harmlose lokale Testdatei, um den Handler und die Abfragen in der zu prüfenden macOS-Version zu überprüfen; sie sollte den Editor nur befüllen, bis auf **Run** geklickt wird.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Wenn dein Ziel passive Codeausführung allein durch das Öffnen eines Ordners oder die Auswahl einer Datei ist, sieh dir auch die spezielle Seite zu [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) an. Dabei handelt es sich um eine andere, aber eng verwandte Dateihandler-Angriffsfläche.



## References

- [1] [Objective-See - Remote-Ausnutzung von Macs über benutzerdefinierte URL-Schemas](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gatekeeper umgehen: Ein genauerer Blick auf Schwachstellen in Gatekeeper unter macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Wie macOS eine Datei mit der passenden App öffnet](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - LaunchServices in macOS Sequoia steuern](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Konzepte zu Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Forschung zur Befehlsausführung über das IINA-URL-Schema](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Unsichere Verarbeitung von mpv-Optionen im URL-Schema](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - Bei der ClickFix-Technik wird statt Terminal der Script Editor verwendet](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Schutzmaßnahmen für Terminal und Skripte](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
