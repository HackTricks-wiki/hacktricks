# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di Base

I bundle in macOS fungono da contenitori per una varietà di risorse, tra cui applicazioni, librerie e altri file necessari, facendoli apparire come oggetti singoli nel Finder, come i familiari file `*.app`. Il bundle più comunemente incontrato è il bundle `.app`, sebbene siano prevalenti anche altri tipi come `.framework`, `.systemextension` e `.kext`.

### Componenti Essenziali di un Bundle

All'interno di un bundle, in particolare nella directory `<application>.app/Contents/`, si trovano una varietà di risorse importanti:

- **\_CodeSignature**: Questa directory memorizza i dettagli della firma del codice, vitali per verificare l'integrità dell'applicazione. Puoi ispezionare le informazioni sulla firma del codice utilizzando comandi come: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
- **MacOS**: Contiene il binario eseguibile dell'applicazione che viene eseguito al momento dell'interazione dell'utente.
- **Resources**: Un repository per i componenti dell'interfaccia utente dell'applicazione, inclusi immagini, documenti e descrizioni dell'interfaccia (file nib/xib).
- **Info.plist**: Funziona come il file di configurazione principale dell'applicazione, cruciale per il sistema per riconoscere e interagire correttamente con l'applicazione.

#### Chiavi Importanti in Info.plist

Il file `Info.plist` è un pilastro per la configurazione dell'applicazione, contenente chiavi come:

- **CFBundleExecutable**: Specifica il nome del file eseguibile principale situato nella directory `Contents/MacOS`.
- **CFBundleIdentifier**: Fornisce un identificatore globale per l'applicazione, utilizzato ampiamente da macOS per la gestione delle applicazioni.
- **LSMinimumSystemVersion**: Indica la versione minima di macOS richiesta per l'esecuzione dell'applicazione.

### Esplorare i Bundle

Per esplorare i contenuti di un bundle, come `Safari.app`, può essere utilizzato il seguente comando: `bash ls -lR /Applications/Safari.app/Contents`

Questa esplorazione rivela directory come `_CodeSignature`, `MacOS`, `Resources` e file come `Info.plist`, ognuno con uno scopo unico, dalla sicurezza dell'applicazione alla definizione della sua interfaccia utente e parametri operativi.

#### Directory Aggiuntive del Bundle

Oltre alle directory comuni, i bundle possono includere anche:

- **Frameworks**: Contiene framework inclusi utilizzati dall'applicazione. I framework sono simili ai dylibs con risorse extra.
- **PlugIns**: Una directory per plug-in ed estensioni che migliorano le capacità dell'applicazione.
- **XPCServices**: Contiene servizi XPC utilizzati dall'applicazione per la comunicazione fuori processo.

Questa struttura garantisce che tutti i componenti necessari siano racchiusi all'interno del bundle, facilitando un ambiente applicativo modulare e sicuro.

Per ulteriori informazioni dettagliate sulle chiavi `Info.plist` e i loro significati, la documentazione per sviluppatori di Apple fornisce risorse estensive: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{{#include ../../../banners/hacktricks-training.md}}
