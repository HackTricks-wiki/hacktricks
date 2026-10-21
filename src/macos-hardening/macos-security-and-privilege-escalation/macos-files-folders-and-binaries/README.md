# File, cartelle, binari e memoria di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Struttura gerarchica dei file

Apple documenta il filesystem di macOS come una gerarchia di domini di sistema, locali, di rete e utente. I contenuti esatti variano in base alla versione del sistema operativo e le posizioni di sistema sono sempre più spesso protette o sintetizzate. <sup>[[1]](#references)</sup>

- **/Applications**: Qui dovrebbero trovarsi le app installate. Tutti gli utenti potranno accedervi.
- **/bin**: Binari da riga di comando
- **/cores**: Se esiste, viene usata per archiviare i core dump
- **/dev**: Tutto viene trattato come un file, quindi qui potresti vedere dispositivi hardware.
- **/etc**: File di configurazione
- **/Library**: Qui si trovano molte sottodirectory e file relativi a preferenze, cache e log. Esiste una cartella Library nella root e nella directory di ogni utente.
- **/private**: Non documentata, ma molte delle cartelle menzionate sono collegamenti simbolici alla directory private.
- **/sbin**: Binari essenziali di sistema (relativi all’amministrazione)
- **/System**: File richiesti da macOS; questa gerarchia contiene principalmente componenti forniti da Apple.
- **/tmp**: File temporanei (collegamento simbolico a `/private/tmp`). Le installazioni storiche eliminavano comunemente i vecchi file temporanei secondo una pianificazione periodica, a volte descritta come ogni tre giorni; tuttavia, nelle versioni attuali, i tempi di pulizia dipendono dal sistema e dai criteri adottati. Non fare affidamento sulla persistenza dei dati in questa posizione.
- **/Users**: Directory home degli utenti.
- **/usr**: File di configurazione e binari di sistema
- **/var**: File di log
- **/Volumes**: Qui appaiono i volumi montati.
- **/.vol**: Eseguendo `stat a.txt` si ottiene qualcosa del genere: `16777223 7545753 -rw-r--r-- 1 username wheel ...`; il primo numero è l’ID del volume in cui si trova il file, il secondo è il numero dell’inode. È possibile accedere al contenuto del file tramite `/.vol/` usando queste informazioni ed eseguendo `cat /.vol/16777223/7545753`

### Cartelle delle applicazioni

- Le **applicazioni di sistema** si trovano in `/System/Applications`
- Le applicazioni **installate** si trovano solitamente in `/Applications` o in `~/Applications`
- I **dati delle applicazioni** si trovano in `/Library/Application Support` per le applicazioni eseguite come root e in `~/Library/Application Support` per quelle eseguite come utente.
- I **daemon** di applicazioni di terze parti che **devono essere eseguiti come root** si trovano solitamente in `/Library/PrivilegedHelperTools/`.
- Le app **sandboxed** sono mappate nella cartella `~/Library/Containers`. Ogni app ha una cartella il cui nome corrisponde al bundle ID dell’applicazione (`com.apple.Safari`).
- Il **kernel** si trova in `/System/Library/Kernels/kernel`
- Le **estensioni del kernel di Apple** si trovano in `/System/Library/Extensions`
- Le **estensioni del kernel di terze parti** sono archiviate in `/Library/Extensions`

### File con informazioni sensibili

macOS archivia informazioni sensibili, incluse le credenziali, in varie posizioni:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Installer pkg vulnerabili


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Per la distinzione tra il volume Data scrivibile e il volume System sigillato visibile in questa gerarchia, consulta [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Estensioni specifiche di OS X

- **`.dmg`**: I file Apple Disk Image sono molto comuni per gli installer.
- **`.kext`**: Deve seguire una struttura specifica ed è la versione di OS X di un driver. (è un bundle)
- **`.plist`**: Un property list archivia informazioni strutturate in formato XML o binario.
  - Può essere XML o binario. I file binari possono essere letti con:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Un bundle applicativo che segue la struttura standard delle directory di macOS.
- **`.dylib`**: Librerie dinamiche (come i file DLL di Windows)
- **`.pkg`**: I moderni pacchetti flat di installazione sono archivi XAR, ma `.pkg` è un formato di installer, non un sinonimo di XAR. I vecchi pacchetti di installazione in stile bundle sono directory. Consulta [macOS installers](macos-installers-abuse.md) per la struttura e l’ispezione dei pacchetti. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Questo file si trova in ogni directory e salva gli attributi e le personalizzazioni della directory.
- **`.Spotlight-V100`**: Questa cartella appare nella directory root di ogni volume del sistema.
- **`.metadata_never_index`**: Se questo file si trova nella root di un volume, Spotlight non indicizzerà quel volume.
- **`.noindex`**: I file e le cartelle con questa estensione non verranno indicizzati da Spotlight.
- **`.sdef`**: Un file di definizione degli script che descrive come AppleScript può interagire con un’applicazione.

### Bundle di macOS

Un bundle è una directory con una gerarchia standardizzata che Finder può mostrare come un singolo oggetto; i bundle delle applicazioni usano l’estensione `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Su macOS e iOS, le librerie e i framework di sistema usati comunemente vengono precollegati nella **dyld shared cache**, migliorando le prestazioni di avvio delle applicazioni. Sebbene venga trattata come un’unica cache logica, le versioni attuali potrebbero archiviarla come cache principale più diversi file subcache, anziché letteralmente in un unico file. Il formato e la posizione sono dettagli implementativi che cambiano a seconda della versione del sistema operativo. <sup>[[3]](#references)</sup>

Su macOS si trova in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`; nelle versioni precedenti, la **shared cache** potrebbe trovarsi in **`/System/Library/dyld/`**.\
In iOS è possibile trovarla in **`/System/Library/Caches/com.apple.dyld/`**.

Analogamente alla dyld shared cache, anche il kernel e le estensioni del kernel vengono compilati in una kernel cache, che viene caricata all’avvio.

Le versioni precedenti potevano essere estratte con [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Questa build potrebbe non supportare i formati di cache attuali; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) è un’altra opzione:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Nota che, anche se lo strumento `dyld_shared_cache_util` non funziona, puoi passare il **binario dyld condiviso a Hopper**: Hopper sarà in grado di identificare tutte le librerie e di **selezionare quella** che vuoi esaminare:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Alcuni extractor non funzionano perché i dylib sono precollegati con indirizzi hard-coded e potrebbero quindi saltare a indirizzi sconosciuti.

> [!TIP]
> È anche possibile scaricare la Shared Library Cache di altri dispositivi \*OS in macOS usando un emulatore in Xcode. Verranno scaricate in: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, come:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** usa la syscall **`shared_region_check_np`** per verificare se l'SLC è stato mappato (e ottenere l'indirizzo) e **`shared_region_map_and_slide_np`** per mappare l'SLC.

Nota che, anche se l'SLC viene slid al primo utilizzo, tutti i **processi** usano la **stessa copia**, il che **eliminava la protezione ASLR** se l'attaccante era in grado di eseguire processi nel sistema. Questo è stato effettivamente sfruttato in passato e corretto con lo shared region pager.

I branch pool sono piccoli dylib Mach-O che creano piccoli spazi tra le mappature delle immagini, rendendo impossibile interporre le funzioni.

### Restrizioni dell'ambiente della shared cache

`DYLD_SHARED_CACHE_DIR` indica una directory della cache, mentre `DYLD_SHARED_REGION` seleziona una modalità di shared region. La precedente forma `DYLD_DHARED_REGION` era errata e `avoid` non è un valore valido per `DYLD_SHARED_CACHE_DIR`. L'attuale dyld limita la modalità `private` in base al permesso AMFI di usare shared cache personalizzate; quindi, impostare solo le variabili d'ambiente non dimostra che un processo possa caricare una cache sostitutiva. <sup>[[10]](#references)</sup>

## Permessi speciali dei file

### Permessi delle cartelle

Per una directory, **read** consente di elencare le voci, **write** consente di crearle o rimuoverle e **execute** consente di attraversarla. Di conseguenza, un utente che può leggere un file ma non può attraversare una directory genitore non può accedere a quel file tramite il percorso. <sup>[[4]](#references)</sup>

### Modificatori dei flag

I file possono avere flag che ne modificano il comportamento. Esamina i flag in una directory con `ls -lO /path/directory`.

- **`uchg`**: noto come flag **uchange**, **impedisce qualsiasi azione** che modifichi o elimini il **file**. Per impostarlo, esegui: `chflags uchg file.txt`
  - Il proprietario del file o root può rimuovere questo flag **utente** con `chflags nouchg file.txt`; non è una protezione contro nessuno dei due. Il flag immutabile **di sistema** separato (`schg`) è riservato a root. <sup>[[11]](#references)</sup>
- **`restricted`**: questo flag protegge il file con **SIP** (non puoi aggiungere questo flag a un file).
- **`Sticky bit`**: in una directory con sticky bit impostato, solo il proprietario del file, il proprietario della directory o root può rinominare o eliminare una voce. È in genere abilitato su `/tmp` per impedire agli utenti di eliminare o spostare i file di altri utenti.

Tutti i flag sono definiti nel file `sys/stat.h` (trovalo usando `mdfind stat.h | grep stat.h`) e sono:

- `UF_SETTABLE` 0x0000ffff: maschera dei flag modificabili dal proprietario.
- `UF_NODUMP` 0x00000001: non eseguire il dump del file.
- `UF_IMMUTABLE` 0x00000002: il file non può essere modificato.
- `UF_APPEND` 0x00000004: è possibile aggiungere contenuti al file, ma non sovrascriverli.
- `UF_OPAQUE` 0x00000008: la directory è opaca rispetto a union.
- `UF_COMPRESSED` 0x00000020: il file è compresso (alcuni file system).
- `UF_TRACKED` 0x00000040: nessuna notifica per eliminazioni/rinomine dei file a cui è applicato.
- `UF_DATAVAULT` 0x00000080: è richiesta un'entitlement per la lettura e la scrittura.
- `UF_HIDDEN` 0x00008000: suggerimento che questo elemento non debba essere visualizzato in una GUI.
- `SF_SUPPORTED` 0x009f0000: maschera dei flag supportati dal superutente.
- `SF_SETTABLE` 0x3fff0000: maschera dei flag modificabili dal superutente.
- `SF_SYNTHETIC` 0xc0000000: maschera dei flag sintetici di sistema in sola lettura.
- `SF_ARCHIVED` 0x00010000: il file è archiviato.
- `SF_IMMUTABLE` 0x00020000: il file non può essere modificato.
- `SF_APPEND` 0x00040000: è possibile aggiungere contenuti al file, ma non sovrascriverli.
- `SF_RESTRICTED` 0x00080000: è richiesta un'entitlement per la scrittura.
- `SF_NOUNLINK` 0x00100000: l'elemento non può essere rimosso, rinominato o usato come punto di mount.
- `SF_FIRMLINK` 0x00800000: il file è un firmlink.
- `SF_DATALESS` 0x40000000: il file è un oggetto senza dati.

### **ACL dei file**

Le **ACL** dei file contengono **ACE** (Access Control Entries), che consentono di assegnare **permessi più granulari** a utenti diversi.

È possibile concedere a una **directory** questi permessi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Per un **file**: `read`, `write`, `append` ed `execute`.

Quando il file contiene ACL, vedrai un **"+" accanto ai permessi, come in**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

Puoi **leggere gli ACL** del file con:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

Puoi trovare **tutti i file con ACL** con il seguente comando (è molto lento):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Attributi estesi

Gli attributi estesi sono valori di metadati denominati, memorizzati separatamente dagli attributi ordinari di un file. Elencali con `ls -l@` e ispezionali o modificali con `xattr`. <sup>[[5]](#references)</sup> Alcuni attributi estesi comuni sono:

- `com.apple.resourceFork`: Compatibilità con il resource fork. Visibile anche come `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadati di quarantena di macOS Gatekeeper
- `metadata:*`: Metadati di macOS, come `_backup_excludeItem` o `kMD*`
- `com.apple.lastuseddate` (#PS): Data dell'ultimo utilizzo del file
- `com.apple.FinderInfo`: Informazioni di macOS Finder, come i tag colore
- `com.apple.TextEncoding`: Specifica la codifica del testo dei file di testo ASCII
- `com.apple.logd.metadata`: Usato da logd sui file in `/var/db/diagnostics`
- `com.apple.genstore.*`: Archiviazione generazionale (`/.DocumentRevisions-V100` nella root del filesystem)
- `com.apple.rootless`: Metadati di macOS associati a System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Contrassegni di logd delle epoche di avvio con UUID univoci
- `com.apple.decmpfs`: Metadati di macOS per la compressione trasparente dei file
- `com.apple.cprotect`: \*OS: Dati di crittografia per file (III/11)
- `com.apple.installd.*`: \*OS: Metadati usati da installd, ad esempio `installType`, `uniqueInstallID`

### Fork delle risorse | macOS ADS

I fork delle risorse forniscono uno stream di dati alternativo su macOS. I contenuti possono essere archiviati nell'attributo esteso `com.apple.ResourceFork` e consultati tramite `file/..namedfork/rsrc`.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Puoi **trovare tutti i file che contengono questo attributo esteso** con:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

L’attributo esteso `com.apple.decmpfs` memorizza metadati per la compressione trasparente; non indica la presenza di crittografia. A seconda del formato di compressione, i dati compressi possono essere memorizzati nell’attributo o in un resource fork e vengono decompressi in modo trasparente durante la lettura.

Il flag `UF_COMPRESSED` appare come `compressed` in `ls -lO`. Non cancellarlo manualmente: il sistema potrebbe interpretare in modo errato la rappresentazione compressa.

Il comando che cancella il flag è mostrato qui perché è utile durante l’analisi forense, ma eseguirlo su un file compresso può far apparire il file vuoto o renderlo inaccessibile finché i metadati non vengono riparati:

```bash
chflags nocompressed /path/to/file
```

L'utility integrata `/usr/bin/afscexpand` può forzare l'espansione dei file compressi in modo trasparente. Anche l'utility di terze parti separata `afsctool` può ispezionare o decomprimere la compressione del file system Apple, ma non va confusa con il comando integrato. <sup>[[8]](#references)</sup>


### Percorsi di configurazione interessanti (macOS)

| Percorso / Posizione | Scopo / Cosa configura | Sicurezza / Potenziale di attacco |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Contiene i file plist dei feature flag di Apple, che controllano comportamenti opzionali o sperimentali nei daemon / framework di sistema | Se un attacker riesce ad aggirare SIP o a ottenere privilegi, la manomissione di questi file potrebbe abilitare percorsi di codice nascosti o disattivare le protezioni |
| `/System/Library/CoreServices/systemVersion.plist` | Contiene i metadati della versione di macOS (ProductVersion, BuildVersion) usati da app / installer per determinare il comportamento | La modifica può indurre app o installer ad accettare versioni del sistema operativo non supportate o a sbloccare funzionalità |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferenze delle app / di sistema | Se scrivibili, gli attacker possono inserire impostazioni per influenzare il comportamento delle app, disattivare protezioni o causare configurazioni errate |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definizioni plist per daemon e agent in background | L'inserimento o la modifica di plist (se i permessi lo consentono) permette la persistence o privilege escalation |
| `/etc/hosts` | Associazioni hostname ↔ IP usate dal resolver DNS di sistema | Reindirizzamento dei nomi di dominio, intercettazione del traffico, spoofing di servizi sotto controllo locale |
| `/etc/sudoers` | Definisce chi può eseguire comandi con `sudo` e a quali condizioni | Un file sudoers manomesso può concedere root o privilegi impropri agli account degli attacker |
| `/private/var/db/dslocal/nodes/Default/users/` | File plist che definiscono gli account utente locali | La manomissione permette di creare o modificare account utente, hash delle password o metadati utente |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Estensioni del kernel / driver | Installare o modificare kext può portare al controllo a livello kernel; sono fortemente protetti da SIP / dalle policy di firma |
| `/private/var/db/SystemPolicyConfiguration/` | Contiene la configurazione per l'applicazione delle policy di sistema (ad es. Gatekeeper, notarizzazione) | La manomissione potrebbe consentire di aggirare i controlli delle policy o le regole di attendibilità |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binari helper e file di configurazione SSH | Una configurazione errata può comportare una sicurezza SSH debole, accessi non autorizzati o algoritmi non sicuri |
| `/System/Library/Sandbox/Profiles` | Profili sandbox di sistema (SBPL) usati per limitare le azioni dei processi | Sostituire o modificare i profili può aprire vettori di sandbox escape o indebolire il contenimento |

> **Nota**: Molti di questi percorsi si trovano in directory protette da SIP (ad es. `/System`) e sono protetti dalla scrittura, a meno che SIP non venga disabilitato o aggirato.  


## Binari universali e formato Mach-O

Mach-O è il formato eseguibile nativo di macOS. Un binario universale, o fat, racchiude più slice Mach-O specifiche per architettura in un unico file; la pagina dedicata illustra entrambi i formati:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Rischio dei file e metadati dei gestori

LaunchServices, la quarantena dei file e Gatekeeper influenzano insieme il modo in cui macOS gestisce i file scaricati e seleziona le applicazioni per le estensioni e gli schemi URL. I relativi database e file di risorse interni cambiano tra le diverse release; consulta le pagine dedicate invece di considerare un percorso privato di CoreTypes come un'interfaccia stabile per le policy:

Nelle release che espongono i metadati di rischio legacy di CoreTypes in `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, le categorie comunemente riscontrate sono:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: contenuto considerato sufficientemente sicuro per l'apertura automatica in base alla policy applicabile dell'applicazione.
- **`LSRiskCategoryNeutral`**: contenuto che normalmente non attiva un avviso e non viene aperto automaticamente.
- **`LSRiskCategoryUnsafeExecutable`**: contenuto eseguibile per il quale l'utente dovrebbe ricevere un avviso dell'applicazione.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: contenitori, come gli archivi, che potrebbero contenere contenuti eseguibili e richiedono ulteriori verifiche.

Questi sono dettagli di implementazione, non un'API pubblica stabile per le policy; verifica i metadati effettivi e il comportamento di Safari/Gatekeeper sulla versione di macOS in esame.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## File di log

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene informazioni sui file scaricati, come l'URL da cui sono stati scaricati.
- **Unified log**: Nelle versioni attuali di macOS, consulta gli eventi di sistema e delle applicazioni con `log show` e `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** e **`/private/var/log/asl/*.asl`**: Artefatti di logging legacy che possono ancora essere rilevanti nei sistemi meno recenti. In quelle release, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configura `syslogd`; `launchctl list | grep com.apple.syslogd` può aiutare a determinare se il servizio è caricato.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Memorizza i file e le applicazioni a cui si è acceduto di recente tramite "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Percorso legacy delle preferenze associato agli elementi di login; le versioni moderne di macOS usano meccanismi aggiuntivi.
- **`$HOME/Library/Logs/DiskUtility.log`**: File di log legacy di Disk Utility che può contenere informazioni sulle unità, inclusi i dispositivi USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dati sui punti di accesso wireless.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Dati legacy delle sostituzioni di launchd.



## References

- [1] [Apple - Guida alla programmazione del file system](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Guida alla programmazione dei bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Panoramica della shared cache di dyld](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Guida alla programmazione del file system: sicurezza del file system di macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - Pagina man di macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - Pagina man di macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - Pagina man di macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Apple Developer Forums - Estrazione degli archivi Apple](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Sicurezza degli script shell: flag speciali dei permessi dei file](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Attività di firma del codice: pacchetti installer](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
