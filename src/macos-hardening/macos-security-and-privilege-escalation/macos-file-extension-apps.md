# Gestori di estensioni di file e schemi URL in macOS

{{#include ../../banners/hacktricks-training.md}}

## Database di LaunchServices

Questo è un database di tutte le applicazioni installate in macOS, che può essere interrogato per ottenere informazioni su ciascuna applicazione installata, come gli **schemi URL**, i **tipi di documento**, gli **UTI** e i gestori predefiniti.

È possibile eseguire il dump di questo database con:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Oppure usando lo strumento [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** è il cervello del database. Fornisce **diversi servizi XPC** come `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e altri. Tuttavia, **richiede anche alcuni entitlements** alle applicazioni per poter utilizzare le funzionalità XPC esposte, come `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler` per modificare le applicazioni predefinite per i MIME type o gli URL scheme, oltre ad altre.

**`/System/Library/CoreServices/launchservicesd`** registra il servizio `com.apple.coreservices.launchservicesd` e può essere interrogato per ottenere informazioni sulle applicazioni in esecuzione. Può essere interrogato con lo strumento di sistema **`/usr/bin/lsappinfo`** oppure con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Dal punto di vista dell'operatore, tieni presente che di solito esistono **due viste utili**:

- Il **database di registrazione** gestito da LaunchServices / `lsd` (basato sui file `.csstore`).
- Le **impostazioni predefinite effettive per utente** memorizzate in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, all'interno dell'array `LSHandlers`.

Questa distinzione è importante: un'applicazione può essere **registrata** come in grado di gestire un type o uno scheme, ma il **predefinito attuale** potrebbe essere ancora un altro bundle ID.

## Gestori delle applicazioni per estensioni di file e URL scheme

La riga seguente può essere utile per trovare le applicazioni in grado di aprire i file in base all'estensione:
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
Puoi anche verificare le estensioni supportate da un'applicazione eseguendo:
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
## Enumerazione dei gestori effettivi

Il file più utile per le **impostazioni predefinite dell'utente corrente** è solitamente:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Per eseguire il **dump** dei gestori degli **URL scheme** da esso:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Per eseguire il **dump** dei gestori **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Per risolvere l'albero UTI di un file di esempio:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Se vuoi una CLI più intuitiva per interrogare o modificare i valori predefiniti:
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

Durante il triage di un application bundle, queste sono le chiavi più importanti:

- **`CFBundleDocumentTypes`**: gruppi di documenti che il bundle dichiara di poter aprire.
- **`LSItemContentTypes`**: metodo **moderno / preferito** per associare i tipi di documento agli UTI.
- **`LSHandlerRank`**: ranking utilizzato da LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes implementati dall'app.
- **`UTExportedTypeDeclarations`**: UTI di cui l'app è **proprietaria**.
- **`UTImportedTypeDeclarations`**: UTI di cui l'app non è proprietaria, ma che vuole far riconoscere al sistema.

Un comando rapido utile per il triage è:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Un dettaglio sottile ma importante: se è presente **`LSItemContentTypes`**, le chiavi precedenti come **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`** sono di fatto dati legacy per la compatibilità. Per la risoluzione effettiva degli handler, concentrati prima sul percorso UTI.

## Note offensive

Le applicazioni non devono necessariamente essere eseguite per diventare interessanti. Un bundle `.app` copiato o clonato può essere **analizzato automaticamente da `lsd` non appena viene scritto su disco**, e i tipi di documenti / schemi URL dichiarati possono essere registrati senza che l'utente avvii mai il bundle.

Questo è utile sia per la ricerca su **persistence / hijacking** sia per le **initial-access chains**:

- Un'applicazione malevola può rivendicare una **rare extension** o una **custom UTI** e attendere che la vittima apra il file-esca.
- Un'applicazione malevola può registrare un **custom URL scheme** raggiungibile da un browser, un'applicazione Electron, un documento Office, un client di chat o un'altra helper app.<sup>[1]</sup>
- Se modifichi un app bundle dopo averlo creato, puoi forzare LaunchServices ad analizzarlo nuovamente con:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Quando testi bundle sospetti, presta particolare attenzione a:

- **`LSHandlerRank=Owner`** per tipi non comuni.
- Array **`CFBundleDocumentTypes`** ampi che dichiarano molte estensioni.
- App helper / wrapper il cui unico comportamento interessante è accessibile tramite un document o URI handler.
- File simili a collegamenti (`.webloc`, `.inetloc`, `.fileloc`) che finiscono per essere gestiti da LaunchServices. Per i trick in stile `.fileloc` e i relativi aspetti di Gatekeeper, consulta [this other page](macos-security-protections/macos-fs-tricks/README.md).<sup>[2]</sup>

Se il tuo obiettivo è ottenere code-execution passiva semplicemente navigando in una cartella o selezionando un file, consulta anche la pagina dedicata ai [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), poiché si tratta di una superficie di file handler diversa, ma strettamente correlata.

## Riferimenti

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
