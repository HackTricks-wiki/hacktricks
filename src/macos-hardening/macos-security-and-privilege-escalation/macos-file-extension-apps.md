# Gestori di app per estensioni di file e schemi URL di macOS

{{#include ../../banners/hacktricks-training.md}}

## Database LaunchServices

È un database di tutte le applicazioni installate in macOS, che può essere interrogato per ottenere informazioni su ciascuna applicazione installata, come gli **schemi URL**, i **tipi di documento**, gli **UTI** e i gestori predefiniti.

È possibile scaricare questo database con:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Oppure usando lo strumento [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** è il cervello del database. Fornisce **diversi servizi XPC** come `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e altri. Tuttavia, per poter usare le funzionalità XPC esposte, **richiede anche alcuni entitlements** alle applicazioni, come `.launchservices.changedefaulthandler` o `.launchservices.changeurlschemehandler` per modificare le app predefinite per i tipi MIME o gli schemi URL, e altri ancora.

**`/System/Library/CoreServices/launchservicesd`** rivendica il servizio `com.apple.coreservices.launchservicesd` e può essere interrogato per ottenere informazioni sulle applicazioni in esecuzione. È possibile interrogarlo con lo strumento di sistema **`/usr/bin/lsappinfo`** o con [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Dal punto di vista di un operatore, tieni presente che di solito ci sono **due viste utili**:

- Il **database di registrazione** gestito da LaunchServices / `lsd` (basato su file `.csstore`).
- I **default effettivi per utente** memorizzati in `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` nell'array `LSHandlers`.

Questa distinzione è importante: un'applicazione può essere **registrata** come in grado di gestire un tipo o uno schema, ma il **default attuale** può essere ancora un altro bundle ID.

Nelle versioni recenti di macOS, l'individuazione delle registrazioni non è limitata a `/Applications`: le app presenti in altre cartelle accessibili e visibili a Spotlight, nonché nei volumi montati o condivisi, possono entrare nel registro. Pertanto, durante il triage, conserva le informazioni relative a `path` e ai volumi da `lsregister -dump` e non dare per scontato che la rimozione della registrazione di un'app sia permanente finché il bundle rimane individuabile.<sup>[[4]](#references)</sup>

## Gestori di app per estensioni di file e schemi URL

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

Il file più utile per le **impostazioni predefinite dell'utente corrente** di solito è:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Per eseguire il dump dei gestori dello **schema URL** da esso:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Per eseguire il dump dei gestori **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Per risolvere l’albero UTI di un file di esempio:

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

La risoluzione del gestore prevede anche un livello **specifico per file**. Prima di usare come fallback l'UTI del file e l'impostazione predefinita globale dell'utente, LaunchServices controlla l'attributo esteso `com.apple.LaunchServices.OpenWith`. Finder lo crea quando si seleziona **Always Open With** per un file; il suo valore è un elenco proprietà binario contenente il percorso di un'applicazione, l'identificatore del bundle e un selettore di versione.<sup>[[3]](#references)</sup>

Esaminalo e decodificalo senza fidarti dell'estensione del file:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

È utile quando un singolo lure si apre con un’applicazione inaspettata, anche se `duti`, `dutix` o `LSHandlers` indicano un valore predefinito globale benigno. In un lab controllato, è possibile copiare il valore opaco esatto da un file configurato tramite Finder; eliminarlo ripristina la normale risoluzione basata sul tipo:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Chiavi interessanti di Info.plist

Durante il triage di un bundle applicativo, queste chiavi sono le più importanti:

- **`CFBundleDocumentTypes`**: gruppi di documenti che il bundle dichiara di poter aprire.
- **`LSItemContentTypes`**: il modo **moderno / preferito** per associare i tipi di documento agli UTI.
- **`LSHandlerRank`**: ranking usato da LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: schemi URI personalizzati implementati dall’app.
- **`UTExportedTypeDeclarations`**: UTI di cui l’app è **proprietaria**.
- **`UTImportedTypeDeclarations`**: UTI di cui l’app non è proprietaria, ma che vuole far riconoscere al sistema.

Un comando utile per un rapido triage è:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Un dettaglio sottile ma importante: se è presente **`LSItemContentTypes`**, le chiavi meno recenti come **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`** sono di fatto dati legacy per la compatibilità. Per la risoluzione effettiva degli handler, concentrati prima sul percorso UTI.

## Note offensive

Le applicazioni non devono essere avviate perché le loro dichiarazioni di handler diventino interessanti, ma **la sola creazione di un bundle `.app` non garantisce la registrazione immediata**. Finder può registrare un'app quando la rileva, anche quando un utente esplora la relativa cartella; la registrazione può avvenire anche all'avvio o al login, oppure tramite una chiamata di registrazione esplicita. Prima di verificare una dichiarazione, controlla `lsregister -dump`. La sola registrazione non avvia l'app e non la rende l'handler predefinito effettivo.<sup>[[5]](#references)</sup> Per i prerequisiti di persistence, consulta [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Questo è utile sia per la ricerca su **persistence / hijacking** sia per le **catene di initial access**:

- Un'app malevola può dichiarare un'**estensione rara** o un **UTI personalizzato** e attendere che la vittima apra il file-esca.
- Un'app malevola può registrare uno **schema URL personalizzato** raggiungibile da un browser, un'app Electron, un documento Office, un client di chat o un'altra app helper.<sup>[[1]](#references)</sup>
- Per distinguere la normale risoluzione predefinita dal test di uno specifico handler candidato, richiama lo schema tramite LaunchServices con `open 'targetscheme://host/path?value=test'`, quindi seleziona un bundle registrato specifico con `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Questo è utile per verificare come l'app ricevente convalida e decodifica i componenti dell'URL controllati dall'attaccante.<sup>[[1]](#references)</sup>
- Se modifichi un bundle dell'app dopo averlo creato, puoi forzare LaunchServices a rianalizzarlo con:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Quando testi bundle sospetti, presta particolare attenzione a:

- **`LSHandlerRank=Owner`** su tipi non comuni.
- Array **`CFBundleDocumentTypes`** estesi che dichiarano molte estensioni.
- App helper / wrapper il cui unico comportamento interessante è accessibile tramite un document handler o URI handler.
- File simili a shortcut (`.webloc`, `.inetloc`, `.fileloc`) che finiscono per avviare LaunchServices. Per i trucchi in stile `.fileloc` e i relativi aspetti di Gatekeeper, consulta [questa altra pagina](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### Parametri URL inoltrati alle opzioni successive

La conferma del protocollo esterno di un browser autorizza solo l'apertura dell'handler; non rende affidabili i parametri URL. Segui il parser URL dell'app ricevente fino a qualsiasi libreria, motore multimediale, processo helper o opzione di scrittura su file. Cerca un prefisso per le chiavi di query che trasformi i campi URL in nomi di opzioni successive. Verifica sia i separatori letterali sia quelli codificati in percentuale, usando un marker innocuo in un account usa e getta.<sup>[[6]](#references)</sup>

Verifica l'**opzione finale accettata dal componente successivo**, non solo il parsing iniziale dell'app. Un handler consentiva alle chiavi di query con prefisso di raggiungere i comandi di input di mpv; bloccare quell'opzione lasciava comunque disponibile un percorso di scrittura su file. Verifica la classe di opzioni raggiungibile, non solo una chiave pericolosa già nota.<sup>[[7]](#references)</sup>

### Handler `applescript://` integrato

L'handler URL `applescript://com.apple.scripteditor` accetta `action=new` e un parametro `script` codificato in URL. Un link nel browser può quindi aprire Script Editor con AppleScript controllato dall'attaccante già nell'editor, evitando un passaggio di incolla in Terminal. **Non comporta l'esecuzione automatica**: il browser potrebbe chiedere di aprire Script Editor e l'utente deve eseguire lo script.<sup>[[8]](#references)</sup>

Le versioni recenti di macOS possono mostrare un avviso per i documenti script, mentre XProtect analizza AppleScript durante l'esecuzione.<sup>[[8]](#references)[[9]](#references)</sup>

Usa una sonda locale innocua per verificare l'handler e gli avvisi nella versione di macOS in esame; dovrebbe limitarsi a inserire il contenuto nell'editor finché non si fa clic su **Run**.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Se il tuo obiettivo è ottenere l'esecuzione passiva di codice semplicemente aprendo una cartella o selezionando un file, consulta anche la pagina dedicata ai [generatori Quick Look](macos-proces-abuse/macos-quicklook-generators.md), poiché si tratta di una superficie di gestione dei file diversa, ma strettamente correlata.



## References

- [1] [Objective-See - Sfruttamento remoto dei Mac tramite schemi URL personalizzati](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassare il gate: uno sguardo più da vicino alle vulnerabilità di Gatekeeper su macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Come macOS apre un file con l'app corretta](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Gestire LaunchServices in macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Concetti di Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Ricerca sull'esecuzione di comandi tramite lo schema URL di IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Gestione non sicura delle opzioni mpv nel suo schema URL](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - La tecnica ClickFix usa Script Editor invece di Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Protezioni per Terminal e gli script](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
