# Gestori di app per estensioni file e URL scheme su macOS

{{#include ../../banners/hacktricks-training.md}}

## Database LaunchServices

Questo è un database di tutte le applicazioni installate in macOS che può essere interrogato per ottenere informazioni su ciascuna applicazione installata, come **URL schemes** supportati, **document types**, **UTIs** e gestori predefiniti.

È possibile estrarre questo database con:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
O usando lo strumento [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** è il cervello del database. Fornisce **diversi servizi XPC** come `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, e altri. Però **richiede anche alcuni entitlements** alle applicazioni per poter usare le funzionalità XPC esposte, come `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler` per cambiare le app predefinite per i tipi MIME o gli URL scheme e altri.

**`/System/Library/CoreServices/launchservicesd`** rivendica il servizio `com.apple.coreservices.launchservicesd` e può essere interrogato per ottenere informazioni sulle applicazioni in esecuzione. Può essere interrogato con lo strumento di sistema **`/usr/bin/lsappinfo`** o con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Dal punto di vista dell'operatore, tieni presente che di solito ci sono **due viste utili**:

- Il **registration database** gestito da LaunchServices / `lsd` (supportato dai file `.csstore`).
- I **default effettivi per utente** archiviati in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` dentro l'array `LSHandlers`.

Questa distinzione è importante: un'applicazione può essere **registrata** come in grado di gestire un tipo o uno scheme, ma il **default attuale** può ancora essere un altro bundle ID.

## File Extension & URL scheme app handlers

La seguente riga può essere utile per trovare le applicazioni che possono aprire file in base all'estensione:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Oppure usa qualcosa come [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Puoi anche controllare le estensioni supportate da un'applicazione facendo:
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
## Enumerare gli handler effettivi

Il file più utile per i **default dell'utente corrente** è di solito:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Per estrarre i gestori **URL scheme** da esso:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Per fare il dump dei handler **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Per risolvere l’albero UTI di un file di esempio:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Se vuoi una CLI più amichevole per interrogare o modificare i default:
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
## Chiavi Info.plist interessanti

Quando si esamina un application bundle, queste chiavi sono le più importanti:

- **`CFBundleDocumentTypes`**: gruppi di documenti che il bundle dichiara di poter aprire.
- **`LSItemContentTypes`**: il modo **moderno / preferito** per associare i tipi di documento alle UTI.
- **`LSHandlerRank`**: ranking usato da LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: schemi URI personalizzati implementati dall'app.
- **`UTExportedTypeDeclarations`**: UTI di cui l'app è **owner**.
- **`UTImportedTypeDeclarations`**: UTI di cui l'app non è owner ma che vuole far riconoscere al sistema.

Un comando utile per una rapida analisi è:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Un dettaglio sottile ma importante: se **`LSItemContentTypes`** è presente, le chiavi più vecchie come **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`** sono di fatto dati di compatibilità legacy. Per la risoluzione effettiva dell’handler, concentra prima l’attenzione sul percorso UTI.

## Offensive notes

Le applicazioni non devono essere eseguite per diventare interessanti. Un bundle `.app` lasciato cadere o clonato può essere **parsato automaticamente da `lsd` non appena viene scritto su disco**, e i suoi tipi di documento / schemi URL dichiarati possono essere registrati senza che l’utente avvii mai il bundle.

Questo è utile sia per la **ricerca su persistence / hijacking** sia per le **initial-access chains**:

- Una app malevola può rivendicare una **estensione rara** o una **UTI personalizzata** e attendere che la vittima apra il file-esca.
- Una app malevola può registrare uno **schema URL personalizzato** raggiungibile da un browser, un’app Electron, un documento office, un client chat o un’altra app helper.
- Se modifichi un bundle di un’app dopo averlo buildato, puoi forzare LaunchServices a riparsarlo con:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Quando testi bundle sospetti, presta particolare attenzione a:

- **`LSHandlerRank=Owner`** su tipi insoliti.
- **Array `CFBundleDocumentTypes`** molto ampi che dichiarano molte estensioni.
- **App helper / wrapper** il cui unico comportamento interessante è nascosto dietro un document o URI handler.
- **File simili a shortcut** (`.webloc`, `.inetloc`, `.fileloc`) che finiscono per essere instradati in LaunchServices. Per trucchi in stile `.fileloc` e angoli correlati di Gatekeeper, controlla [questa altra pagina](macos-security-protections/macos-fs-tricks/README.md).

Se il tuo obiettivo è l'esecuzione passiva di codice semplicemente navigando in una cartella o selezionando un file, controlla anche la pagina dedicata ai [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), poiché si tratta di una superficie file-handler diversa ma strettamente correlata.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
