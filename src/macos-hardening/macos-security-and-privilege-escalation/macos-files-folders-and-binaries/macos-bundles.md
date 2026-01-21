# Bundle di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I bundle in macOS fungono da contenitori per una varietà di risorse, incluse applicazioni, librerie e altri file necessari, facendo sì che risultino come oggetti singoli in Finder, come i familiari file `*.app`. Il bundle più comunemente incontrato è il bundle `.app`, sebbene siano diffusi anche altri tipi come `.framework`, `.systemextension` e `.kext`.

### Componenti essenziali di un bundle

All'interno di un bundle, in particolare nella directory `<application>.app/Contents/`, sono ospitate varie risorse importanti:

- **\_CodeSignature**: Questa directory memorizza i dettagli di code-signing fondamentali per verificare l'integrità dell'applicazione. Puoi ispezionare le informazioni sul code-signing usando comandi come:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contiene il binario eseguibile dell'applicazione che viene eseguito all'interazione dell'utente.
- **Resources**: Un repository per i componenti dell'interfaccia utente dell'applicazione, incluse immagini, documenti e descrizioni dell'interfaccia (nib/xib files).
- **Info.plist**: Funziona come file di configurazione principale dell'applicazione, cruciale affinché il sistema riconosca e interagisca correttamente con l'applicazione.

#### Chiavi importanti in Info.plist

Il file `Info.plist` è un pilastro per la configurazione dell'applicazione, contenente chiavi come:

- **CFBundleExecutable**: Specifica il nome del file eseguibile principale situato nella directory `Contents/MacOS`.
- **CFBundleIdentifier**: Fornisce un identificatore globale per l'applicazione, utilizzato ampiamente da macOS per la gestione delle applicazioni.
- **LSMinimumSystemVersion**: Indica la versione minima di macOS richiesta per l'esecuzione dell'applicazione.

### Esplorare i bundle

Per esplorare il contenuto di un bundle, come `Safari.app`, si può usare il comando seguente: `bash ls -lR /Applications/Safari.app/Contents`

Questa esplorazione rivela directory come `_CodeSignature`, `MacOS`, `Resources`, e file come `Info.plist`, ciascuno con uno scopo specifico, dalla protezione dell'applicazione alla definizione dell'interfaccia utente e dei parametri operativi.

#### Directory aggiuntive del bundle

Oltre alle directory comuni, i bundle possono includere anche:

- **Frameworks**: Contiene framework bundlati usati dall'applicazione. I framework sono come dylibs con risorse extra.
- **PlugIns**: Una directory per plug-in e estensioni che estendono le capacità dell'applicazione.
- **XPCServices**: Contiene i servizi XPC usati dall'applicazione per la comunicazione out-of-process.

Questa struttura garantisce che tutti i componenti necessari siano incapsulati all'interno del bundle, facilitando un ambiente applicativo modulare e sicuro.

Per informazioni più dettagliate sulle chiavi di `Info.plist` e sul loro significato, la documentazione Apple per sviluppatori fornisce risorse estese: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Note di sicurezza e vettori di abuso

- **Gatekeeper / App Translocation**: Quando un bundle in quarantena viene eseguito per la prima volta, macOS effettua una verifica di firma approfondita e può eseguirlo da un percorso translocato randomizzato. Una volta accettato, i lanci successivi eseguono solo controlli superficiali; i file di risorse in `Resources/`, `PlugIns/`, nibs, ecc., storicamente non venivano controllati. Dalla versione macOS 13 Ventura viene eseguita una verifica profonda al primo avvio e la nuova autorizzazione TCC *App Management* limita ai processi di terze parti la possibilità di modificare altri bundle senza il consenso dell'utente, ma i sistemi più vecchi restano vulnerabili.
- **Bundle Identifier collisions**: Più target embedded (PlugIns, helper tools) che riutilizzano lo stesso `CFBundleIdentifier` possono compromettere la validazione della firma e talvolta abilitare URL‑scheme hijacking/confusion. Enumerare sempre i sub‑bundles e verificare che gli ID siano unici.

## Resource Hijacking (Dirty NIB / NIB Injection)

Prima di Ventura, sostituire risorse UI in un'app firmata poteva bypassare i controlli superficiali della code signing e portare all'esecuzione di codice con gli entitlements dell'app. Ricerche recenti (2024) mostrano che questo funziona ancora su sistemi pre‑Ventura e su build non in quarantena:

1. Copiare l'app target in una posizione scrivibile (es., `/tmp/Victim.app`).
2. Sostituire `Contents/Resources/MainMenu.nib` (o qualsiasi nib dichiarato in `NSMainNibFile`) con uno maligno che istanzia `NSAppleScript`, `NSTask`, ecc.
3. Avviare l'app. Il nib maligno viene eseguito con il bundle ID e gli entitlements della vittima (concessioni TCC, accesso a microfono/camera, ecc.).
4. Ventura+ mitiga effettuando una verifica approfondita del bundle al primo avvio e richiedendo il permesso *App Management* per modifiche successive, quindi la persistenza è più difficile ma gli attacchi al primo avvio sui macOS più vecchi restano applicabili.

Esempio minimo di payload maligno in un nib (compilare xib in nib con `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

Perché le ricerche di `@rpath` preferiscono Frameworks/PlugIns inclusi nel bundle, inserire una libreria dannosa all'interno di `Contents/Frameworks/` o `Contents/PlugIns/` può reindirizzare l'ordine di caricamento quando il binario principale è firmato senza library validation o con un ordinamento `LC_RPATH` debole.

Passaggi tipici per sfruttare un bundle unsigned/ad‑hoc:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- Il runtime hardened con `com.apple.security.cs.disable-library-validation` assente blocca le dylibs di terze parti; verifica prima gli entitlements.
- I servizi XPC sotto `Contents/XPCServices/` spesso caricano sibling frameworks — patcha i loro binari allo stesso modo per percorsi di persistence o privilege escalation.

## Scheda di ispezione rapida
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Riferimenti

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
