# Gestori di app per estensioni di file e schemi URL su macOS

{{#include ../../banners/hacktricks-training.md}}

## Database LaunchServices

Si tratta di un database di tutte le applicazioni installate in macOS, che può essere interrogato per ottenere informazioni su ciascuna applicazione installata, come gli **schemi URL**, i **tipi di documento**, gli **UTI** e i gestori predefiniti.

È possibile scaricare questo database con:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Oppure usando lo strumento [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** è il cervello del database. Fornisce **diversi servizi XPC** come `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e altri. Tuttavia, **richiede anche alcuni entitlements** alle applicazioni per poter utilizzare le funzionalità XPC esposte, come `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler` per modificare le applicazioni predefinite per i tipi MIME o gli schemi URL, oltre ad altri.

**`/System/Library/CoreServices/launchservicesd`** dichiara il servizio `com.apple.coreservices.launchservicesd` e può essere interrogato per ottenere informazioni sulle applicazioni in esecuzione. Può essere interrogato con lo strumento di sistema **`/usr/bin/lsappinfo`** o con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Dal punto di vista dell'operatore, tieni presente che solitamente esistono **due viste utili**:

- Il **database di registrazione** gestito da LaunchServices / `lsd` (supportato dai file `.csstore`).
- Le **impostazioni predefinite effettive per utente** memorizzate in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, all'interno dell'array `LSHandlers`.

Questa distinzione è importante: un'applicazione può essere **registrata** come in grado di gestire un tipo o uno schema, ma l'**impostazione predefinita corrente** può essere ancora un altro bundle ID.

Nelle versioni recenti di macOS, la ricerca delle registrazioni non è limitata a `/Applications`: le applicazioni presenti in altre cartelle visibili a Spotlight e accessibili, così come nei volumi montati o condivisi, possono entrare nel registro. Pertanto, durante il triage, conserva le informazioni relative a `path` e al volume ottenute da `lsregister -dump` e non presumere che la deregistrazione di un'applicazione sia permanente finché il bundle rimane individuabile.<sup>[[4]](#references)</sup>

## Gestori delle applicazioni per estensioni di file e schemi URL

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
Per estrarre i gestori **URL scheme** da esso:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Per eseguire il dump dei gestori di **content-type / UTI**:
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
### Override `Open With` per file

La risoluzione del gestore include anche un livello **specifico per file**. Prima di ricorrere alla UTI del file e al valore predefinito globale dell'utente, LaunchServices verifica l'attributo esteso `com.apple.LaunchServices.OpenWith`. Finder lo crea quando si seleziona **Always Open With** per un file; il suo valore è un property list binario contenente il percorso di un'applicazione, l'identificatore del bundle e un selettore di versione.<sup>[[3]](#references)</sup>

Ispezionalo e decodificalo senza fare affidamento sull'estensione del file:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Questo è utile quando un singolo lure si apre con un'applicazione inattesa, anche se `duti`, `dutix` o `LSHandlers` riportano un'impostazione predefinita globale legittima. In un laboratorio controllato, il valore opaco esatto può essere copiato da un file configurato tramite Finder; eliminarlo ripristina la normale risoluzione basata sul tipo:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Chiavi Info.plist interessanti

Durante il triage di un application bundle, queste sono le chiavi più importanti:

- **`CFBundleDocumentTypes`**: gruppi di documenti che il bundle dichiara di poter aprire.
- **`LSItemContentTypes`**: il metodo **moderno / preferito** per associare i tipi di documento agli UTI.
- **`LSHandlerRank`**: priorità utilizzata da LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes implementati dall'app.
- **`UTExportedTypeDeclarations`**: gli UTI di cui l'app è **proprietaria**.
- **`UTImportedTypeDeclarations`**: UTI di cui l'app non è proprietaria, ma che vuole far riconoscere al sistema.

Un utile comando per un rapido triage è:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Un dettaglio sottile ma importante: se **`LSItemContentTypes`** è presente, le chiavi più vecchie come **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`** sono di fatto dati legacy per la compatibilità. Per l'effettiva risoluzione degli handler, considera prima il percorso UTI.

## Note offensive

Le applicazioni non devono necessariamente essere eseguite per diventare interessanti. Un bundle `.app` copiato o clonato può essere **analizzato automaticamente da `lsd` non appena viene scritto sul disco**, e i tipi di documenti / schemi URL dichiarati possono essere registrati senza che l'utente avvii mai il bundle.

Questo è utile sia per la **ricerca sulla persistence / hijacking** sia per le **initial-access chains**:

- Un'applicazione malevola può rivendicare una **rare extension** o una **custom UTI** e attendere che la vittima apra il file-esca.
- Un'applicazione malevola può registrare una **custom URL scheme** raggiungibile da un browser, un'app Electron, un documento Office, un client di chat o un'altra helper app.<sup>[[1]](#references)</sup>
- Per separare la normale risoluzione predefinita dal test di uno specifico candidate handler, invoca lo schema tramite LaunchServices con `open 'targetscheme://host/path?value=test'`, quindi indirizza una specifica registered bundle con `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Questo è utile per verificare come l'app ricevente valida e decodifica i componenti URL controllati dall'attaccante.<sup>[[1]](#references)</sup>
- Se modifichi un app bundle dopo averlo creato, puoi forzare LaunchServices ad analizzarlo nuovamente con:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Quando testi bundle sospetti, presta particolare attenzione a:

- **`LSHandlerRank=Owner`** su tipi non comuni.
- Array **`CFBundleDocumentTypes`** ampi che dichiarano molte estensioni.
- App **Helper / wrapper** il cui unico comportamento interessante è accessibile tramite un document o URI handler.
- File simili a shortcut (`.webloc`, `.inetloc`, `.fileloc`) che finiscono per essere gestiti da LaunchServices. Per i trick in stile `.fileloc` e i relativi aspetti di Gatekeeper, consulta [questa altra pagina](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Se il tuo obiettivo è l'esecuzione passiva di codice semplicemente visitando una cartella o selezionando un file, consulta anche la pagina dedicata ai [generatori Quick Look](macos-proces-abuse/macos-quicklook-generators.md), poiché si tratta di una superficie di file handler diversa, ma strettamente correlata.



## References

- [1] [Objective-See - Sfruttamento remoto dei Mac tramite schemi URL personalizzati](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: Uno sguardo più approfondito alle vulnerabilità di Gatekeeper su macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Come macOS apre un file nell'app corretta](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Controllare LaunchServices in macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
