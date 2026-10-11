# Gestori delle app per estensioni dei file e schemi URL in macOS

{{#include ../../banners/hacktricks-training.md}}

## Database di LaunchServices

Questo database contiene tutte le applicazioni installate in macOS e può essere interrogato per ottenere informazioni su ciascuna, ad esempio gli **schemi URL**, i **tipi di documenti**, gli **UTI** supportati e i gestori predefiniti.

È possibile effettuare il dump di questo database con:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Oppure usando lo strumento [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** è il cuore del database. Fornisce **diversi servizi XPC** come `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e altri. Tuttavia, per poter usare le funzionalità XPC esposte, richiede anche che le applicazioni dispongano di **alcuni entitlement**, come `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler`, per modificare le app predefinite per i tipi MIME o gli schemi URL, e altri ancora.

**`/System/Library/CoreServices/launchservicesd`** dichiara il servizio `com.apple.coreservices.launchservicesd` e può essere interrogato per ottenere informazioni sulle applicazioni in esecuzione. È possibile interrogarlo con lo strumento di sistema **`/usr/bin/lsappinfo`** oppure con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Dal punto di vista di un operatore, tieni presente che di solito ci sono **due viste utili**:

- Il **database di registrazione** gestito da LaunchServices / `lsd` (basato su file `.csstore`).
- Le **impostazioni predefinite effettive per utente**, memorizzate nell’array `LSHandlers` di `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`.

Questa distinzione è importante: un’applicazione può essere **registrata** come in grado di gestire un tipo o uno schema, ma l’**impostazione predefinita corrente** può comunque essere un altro bundle ID.

Nelle versioni recenti di macOS, la ricerca delle registrazioni non è limitata a `/Applications`: le app presenti in altre cartelle accessibili e visibili a Spotlight, nonché nei volumi montati o condivisi, possono essere aggiunte al registro. Pertanto, durante il triage, conserva le informazioni su `path` e sul volume riportate da `lsregister -dump` e non dare per scontato che la rimozione della registrazione di un’app sia permanente finché il bundle rimane individuabile.<sup>[[4]](#references)</sup>

## Gestori delle app per estensioni di file e schemi URL

La riga seguente può essere utile per trovare le applicazioni in grado di aprire i file in base all’estensione:

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

## Enumerare i gestori effettivi

Il file più utile per le **impostazioni predefinite dell'utente corrente** è solitamente:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Per estrarre i gestori dello **schema URL** da esso:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Per dumpare gli handler di **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Per determinare l'albero UTI di un file di esempio:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Se desideri una CLI più intuitiva per interrogare o modificare i valori predefiniti:

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

La risoluzione del gestore prevede anche un livello **specifico per file**. Prima di ricorrere all'UTI del file e all'impostazione predefinita globale dell'utente, LaunchServices controlla l'attributo esteso `com.apple.LaunchServices.OpenWith`. Finder lo crea quando si seleziona **Always Open With** per un singolo file; il suo valore è una property list binaria contenente il percorso di un'applicazione, l'identificatore del bundle e un selettore di versione.<sup>[[3]](#references)</sup>

Esaminalo e decodificalo senza fidarti dell'estensione del file:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

È utile quando una singola esca si apre con un’applicazione imprevista, anche se `duti`, `dutix` o `LSHandlers` indicano un valore predefinito globale innocuo. In un lab controllato, è possibile copiare il valore opaco esatto da un file configurato tramite Finder; eliminarlo ripristina la normale risoluzione basata sul tipo:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Chiavi Info.plist interessanti

Quando si analizza un bundle di un'applicazione, queste chiavi sono le più importanti:

- **`CFBundleDocumentTypes`**: gruppi di documenti che il bundle dichiara di poter aprire.
- **`LSItemContentTypes`**: metodo **moderno / preferito** per associare i tipi di documento agli UTI.
- **`LSHandlerRank`**: priorità usata da LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: schemi URI personalizzati implementati dall'app.
- **`UTExportedTypeDeclarations`**: UTI di cui l'app è **proprietaria**.
- **`UTImportedTypeDeclarations`**: UTI di cui l'app non è proprietaria, ma che vuole far riconoscere al sistema.

Un comando utile per una rapida analisi iniziale è:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Un dettaglio sottile ma importante: se è presente **`LSItemContentTypes`**, le chiavi più vecchie come **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`** sono di fatto dati legacy per la compatibilità. Per la risoluzione effettiva degli handler, concentrati innanzitutto sul percorso UTI.

## Note offensive

Le applicazioni non devono essere eseguite per diventare interessanti. Un bundle `.app` copiato o clonato può essere **analizzato automaticamente da `lsd` non appena viene scritto sul disco** e i tipi di documento e gli schemi URL dichiarati possono essere registrati senza che l’utente avvii mai il bundle.

Questo è utile sia per la ricerca su **persistence / hijacking** sia per le **catene di initial-access**:

- Un’app malevola può rivendicare un’**estensione rara** o un **UTI personalizzato** e attendere che la vittima apra il file-esca.
- Un’app malevola può registrare uno **schema URL personalizzato** raggiungibile da un browser, un’app Electron, un documento Office, un client di chat o un’altra app helper.<sup>[[1]](#references)</sup>
- Per distinguere la risoluzione predefinita dal test di uno specifico handler candidato, invoca lo schema tramite LaunchServices con `open 'targetscheme://host/path?value=test'`, quindi indirizza un bundle registrato specifico con `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. È utile per verificare come l’app ricevente convalida e decodifica i componenti URL controllati dall’attaccante.<sup>[[1]](#references)</sup>
- Se modifichi un bundle dell’app dopo averlo creato, puoi forzare LaunchServices a rianalizzarlo con:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Quando testi bundle sospetti, presta particolare attenzione a:

- **`LSHandlerRank=Owner`** per tipi non comuni.
- Array **`CFBundleDocumentTypes`** ampi che dichiarano molte estensioni.
- App helper / wrapper il cui unico comportamento interessante è accessibile tramite un handler per documenti o URI.
- File simili a collegamenti (`.webloc`, `.inetloc`, `.fileloc`) che finiscono per avviare LaunchServices. Per i trucchi basati su `.fileloc` e i relativi aspetti di Gatekeeper, consulta [questa altra pagina](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Se il tuo obiettivo è ottenere l'esecuzione passiva di codice semplicemente aprendo una cartella o selezionando un file, consulta anche la pagina dedicata ai [generatori Quick Look](macos-proces-abuse/macos-quicklook-generators.md), poiché si tratta di una superficie di gestione dei file diversa, ma strettamente correlata.



## References

- [1] [Objective-See - Sfruttamento remoto dei Mac tramite schemi URL personalizzati](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassare il gate: uno sguardo più da vicino alle vulnerabilità di Gatekeeper su macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Come macOS apre un file nell'app corretta](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Gestire LaunchServices in macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
