# Gestori di app per estensioni di file macOS e schemi URL

{{#include ../../banners/hacktricks-training.md}}

## Database LaunchServices

Questo è un database di tutte le applicazioni installate in macOS che può essere interrogato per ottenere informazioni su ciascuna applicazione installata, come i schemi URL che supporta e i tipi MIME.

È possibile eseguire il dump di questo database con:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Oppure utilizzando lo strumento [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** è il cervello del database. Fornisce **diversi servizi XPC** come `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e altri. Ma richiede anche **alcuni diritti** per le applicazioni per poter utilizzare le funzionalità XPC esposte, come `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler` per cambiare le app predefinite per i tipi MIME o gli schemi URL e altri.

**`/System/Library/CoreServices/launchservicesd`** rivendica il servizio `com.apple.coreservices.launchservicesd` e può essere interrogato per ottenere informazioni sulle applicazioni in esecuzione. Può essere interrogato con lo strumento di sistema /**`usr/bin/lsappinfo`** o con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Gestori di app per estensioni di file e schemi URL

La seguente riga può essere utile per trovare le applicazioni che possono aprire file a seconda dell'estensione:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
O usa qualcosa come [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Puoi anche controllare le estensioni supportate da un'applicazione eseguendo:
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
