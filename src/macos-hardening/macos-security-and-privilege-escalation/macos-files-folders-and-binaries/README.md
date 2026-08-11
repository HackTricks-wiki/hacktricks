# File, cartelle, binari e memoria di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Struttura gerarchica dei file

Apple documenta il filesystem di macOS come una gerarchia di domini di sistema, locali, di rete e utente. I contenuti esatti variano a seconda della release del sistema operativo e le posizioni di sistema sono sempre più protette o sintetizzate. <sup>[[1]](#references)</sup>

- **/Applications**: Le app installate dovrebbero trovarsi qui. Tutti gli utenti potranno accedervi.
- **/bin**: Binari da riga di comando
- **/cores**: Se esiste, viene usata per archiviare i core dump
- **/dev**: Tutto viene trattato come un file, quindi qui si possono trovare i dispositivi hardware.
- **/etc**: File di configurazione
- **/Library**: Qui si trovano molte sottodirectory e file relativi a preferenze, cache e log. Esiste una cartella Library nella root e nella directory di ogni utente.
- **/private**: Non documentata, ma molte delle cartelle menzionate sono collegamenti simbolici alla directory private.
- **/sbin**: Binari di sistema essenziali (relativi all'amministrazione)
- **/System**: File richiesti da macOS; questo albero contiene principalmente componenti forniti da Apple.
- **/tmp**: File temporanei (un collegamento simbolico a `/private/tmp`). Le installazioni storiche pulivano comunemente i vecchi file temporanei secondo una pianificazione periodica, talvolta descritta come di tre giorni, ma l'intervallo di pulizia attuale dipende dal sistema e dai criteri adottati; non fare affidamento sulla persistenza dei dati in questa posizione.
- **/Users**: Directory home degli utenti.
- **/usr**: Configurazioni e binari di sistema
- **/var**: File di log
- **/Volumes**: I volumi montati vengono visualizzati qui.
- **/.vol**: Eseguendo `stat a.txt` si ottiene qualcosa come `16777223 7545753 -rw-r--r-- 1 username wheel ...`, dove il primo numero è l'ID del volume in cui esiste il file e il secondo è il numero dell'inode. È possibile accedere al contenuto di questo file tramite /.vol/ con queste informazioni, eseguendo `cat /.vol/16777223/7545753`

### Cartelle Applications

- Le **applicazioni di sistema** si trovano in `/System/Applications`
- Le applicazioni **installate** vengono generalmente installate in `/Applications` o in `~/Applications`
- I dati delle applicazioni possono essere trovati in `/Library/Application Support` per le applicazioni eseguite come root e in `~/Library/Application Support` per le applicazioni eseguite dall'utente.
- I **daemons** di applicazioni di terze parti che **devono essere eseguiti come root** si trovano generalmente in `/Library/PrivilegedHelperTools/`.
- Le app **Sandboxed** sono mappate nella cartella `~/Library/Containers`. Ogni app ha una cartella denominata in base al bundle ID dell'applicazione (`com.apple.Safari`).
- Il **kernel** si trova in `/System/Library/Kernels/kernel`
- Le estensioni del **kernel di Apple** si trovano in `/System/Library/Extensions`
- Le estensioni del **kernel di terze parti** sono memorizzate in `/Library/Extensions`

### File con informazioni sensibili

macOS archivia informazioni sensibili, comprese le credenziali, in diverse posizioni:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Installer pkg vulnerabili


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Estensioni specifiche di OS X

- **`.dmg`**: I file Apple Disk Image sono molto frequenti per gli installer.
- **`.kext`**: Deve seguire una struttura specifica ed è la versione di OS X di un driver. (è un bundle)
- **`.plist`**: Un property list archivia informazioni strutturate in formato XML o binario.
- Può essere XML o binario. Quelli binari possono essere letti con:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plist`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Un application bundle che segue la struttura standard delle directory di macOS.
- **`.dylib`**: Librerie dinamiche (come i file DLL di Windows)
- **`.pkg`**: Sono equivalenti a xar (formato eXtensible Archive). Il comando installer può essere usato per installare il contenuto di questi file.
- **`.DS_Store`**: Questo file si trova in ogni directory e salva gli attributi e le personalizzazioni della directory.
- **`.Spotlight-V100`**: Questa cartella appare nella directory root di ogni volume del sistema.
- **`.metadata_never_index`**: Se questo file si trova nella root di un volume, Spotlight non indicizzerà quel volume.
- **`.noindex`**: I file e le cartelle con questa estensione non verranno indicizzati da Spotlight.
- **`.sdef`**: Un file di definizione di scripting che descrive come AppleScript può interagire con un'applicazione.

### Bundle macOS

Un bundle è una directory con una gerarchia standardizzata che Finder può presentare come un singolo oggetto; i bundle delle applicazioni usano l'estensione `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Su macOS e iOS, le librerie e i framework di sistema usati comunemente sono precollegati nella **dyld shared cache**, migliorando le prestazioni di avvio delle applicazioni. Sebbene venga trattata come un'unica cache logica, le release attuali possono memorizzarla come una cache principale più diversi file di subcache, anziché in un unico file letterale. Il suo formato e la sua posizione sono dettagli di implementazione che cambiano tra le release del sistema operativo. <sup>[[3]](#references)</sup>

Su macOS si trova in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` e nelle versioni precedenti potrebbe essere possibile trovare la **shared cache** in **`/System/Library/dyld/`**.\
In iOS è possibile trovarle in **`/System/Library/Caches/com.apple.dyld/`**.

Analogamente alla dyld shared cache, anche il kernel e le estensioni del kernel vengono compilati in una kernel cache, caricata al momento dell'avvio.

Le release precedenti potevano essere estratte con [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Quella build potrebbe non supportare i formati di cache attuali; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) è un'altra opzione:
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Nota che, anche se lo strumento `dyld_shared_cache_util` non funziona, puoi passare il **shared dyld binary a Hopper** e Hopper sarà in grado di identificare tutte le librerie e permetterti di **selezionare quale** vuoi analizzare:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Alcuni extractors non funzioneranno, poiché le dylib sono prelinked con indirizzi hard coded e quindi potrebbero saltare a indirizzi sconosciuti.

> [!TIP]
> È anche possibile scaricare la Shared Library Cache di altri dispositivi \*OS su macos utilizzando un emulatore in Xcode. Verranno scaricate all'interno di: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, come:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** utilizza la syscall **`shared_region_check_np`** per sapere se lo SLC è stato mappato (restituisce l'indirizzo) e **`shared_region_map_and_slide_np`** per mappare lo SLC.

Nota che, anche se lo SLC viene sottoposto a slide al primo utilizzo, tutti i **processi** utilizzano la **stessa copia**, il che **eliminava la protezione ASLR** se l'attaccante riusciva a eseguire processi nel sistema. Questo è stato effettivamente sfruttato in passato e risolto con shared region pager.

Branch pools sono piccole dylib Mach-O che creano piccoli spazi tra i mapping delle immagini, rendendo impossibile interporre le funzioni.

### Override SLCs

Utilizzando le variabili d'ambiente:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Questo consente di caricare una nuova shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** e sostituendo manualmente le librerie con symlink alla shared cache contenente quelle reali (dovrai estrarle)

## Permessi speciali dei file

### Permessi delle cartelle

Per una directory, **read** consente di elencare le entry, **write** consente di creare o rimuovere entry ed **execute** consente il traversal. Di conseguenza, un utente che può leggere un file ma non può attraversare una directory padre non può accedere a quel file tramite il suo path. <sup>[[4]](#references)</sup>

### Modificatori dei flag

I file possono avere flag che ne modificano il comportamento. Ispeziona i flag in una directory con `ls -lO /path/directory`.

- **`uchg`**: Noto come flag **uchange**, **impedisce qualsiasi azione** che modifichi o elimini il **file**. Per impostarlo esegui: `chflags uchg file.txt`
- L'utente root può **rimuovere il flag** e modificare il file
- **`restricted`**: Questo flag fa sì che il file sia **protetto da SIP** (non puoi aggiungere questo flag a un file).
- **`Sticky bit`**: In una directory con lo sticky bit impostato, solo il proprietario del file, il proprietario della directory o root possono rinominare o eliminare un'entry. Solitamente è abilitato su `/tmp` per impedire agli utenti di eliminare o spostare i file degli altri utenti.

Tutti i flag sono disponibili nel file `sys/stat.h` (trovalo usando `mdfind stat.h | grep stat.h`) e sono:

- `UF_SETTABLE` 0x0000ffff: Mask dei flag modificabili dal proprietario.
- `UF_NODUMP` 0x00000001: Non eseguire il dump del file.
- `UF_IMMUTABLE` 0x00000002: Il file non può essere modificato.
- `UF_APPEND` 0x00000004: Le scritture sul file possono solo aggiungere dati.
- `UF_OPAQUE` 0x00000008: La directory è opaque rispetto a union.
- `UF_COMPRESSED` 0x00000020: Il file è compresso (alcuni file system).
- `UF_TRACKED` 0x00000040: Nessuna notifica per eliminazioni/rinomine dei file con questo flag impostato.
- `UF_DATAVAULT` 0x00000080: È richiesto un entitlement per la lettura e la scrittura.
- `UF_HIDDEN` 0x00008000: Indica che questo elemento non dovrebbe essere visualizzato in una GUI.
- `SF_SUPPORTED` 0x009f0000: Mask dei flag supportati dal superuser.
- `SF_SETTABLE` 0x3fff0000: Mask dei flag modificabili dal superuser.
- `SF_SYNTHETIC` 0xc0000000: Mask dei flag sintetici di sistema in sola lettura.
- `SF_ARCHIVED` 0x00010000: Il file è archiviato.
- `SF_IMMUTABLE` 0x00020000: Il file non può essere modificato.
- `SF_APPEND` 0x00040000: Le scritture sul file possono solo aggiungere dati.
- `SF_RESTRICTED` 0x00080000: È richiesto un entitlement per la scrittura.
- `SF_NOUNLINK` 0x00100000: L'elemento non può essere rimosso, rinominato o montato.
- `SF_FIRMLINK` 0x00800000: Il file è un firmlink.
- `SF_DATALESS` 0x40000000: Il file è un oggetto dataless.

### **ACL dei file**

Le **ACL** dei file contengono **ACE** (Access Control Entries), tramite le quali è possibile assegnare **permessi più granulari** a utenti diversi.

È possibile concedere a una **directory** questi permessi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Per un **file**: `read`, `write`, `append` ed `execute`.

Quando il file contiene ACL, **troverai un "+" elencando i permessi, come in**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Puoi **leggere le ACL** del file con:
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

Gli attributi estesi sono valori di metadati denominati archiviati separatamente dagli attributi ordinari di un file. Elencali con `ls -l@` e ispezionali o modificali con `xattr`. <sup>[[5]](#references)</sup> Alcuni attributi estesi comuni sono:

- `com.apple.resourceFork`: Compatibilità con il resource fork. Visibile anche come `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadati della quarantena di macOS Gatekeeper
- `metadata:*`: Metadati di macOS, come `_backup_excludeItem` o `kMD*`
- `com.apple.lastuseddate` (#PS): Data dell'ultimo utilizzo del file
- `com.apple.FinderInfo`: Informazioni di macOS Finder, come i tag colorati
- `com.apple.TextEncoding`: Specifica la codifica del testo dei file di testo ASCII
- `com.apple.logd.metadata`: Utilizzato da logd sui file in `/var/db/diagnostics`
- `com.apple.genstore.*`: Archiviazione generazionale (`/.DocumentRevisions-V100` nella radice del filesystem)
- `com.apple.rootless`: Metadati di macOS associati a System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Contrassegni di logd delle epoche di avvio con UUID univoco
- `com.apple.decmpfs`: Metadati della compressione trasparente dei file di macOS
- `com.apple.cprotect`: \*OS: Dati di cifratura per file (III/11)
- `com.apple.installd.*`: \*OS: Metadati utilizzati da installd, ad esempio `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

I resource fork forniscono un alternate data stream su macOS. Il contenuto può essere archiviato nell'attributo esteso `com.apple.ResourceFork` e vi si può accedere tramite `file/..namedfork/rsrc`.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Puoi **trovare tutti i file contenenti questo attributo esteso** con:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

L'attributo esteso `com.apple.decmpfs` memorizza i metadati per la compressione trasparente; non indica la crittografia. A seconda del formato di compressione, i dati compressi possono essere memorizzati nell'attributo o in un resource fork e vengono decompressi in modo trasparente durante la lettura.

Il flag `UF_COMPRESSED` appare come `compressed` in `ls -lO`. Non cancellarlo manualmente: farlo può indurre il sistema a interpretare in modo errato la rappresentazione compressa.

Il comando che cancella il flag è mostrato qui perché è utile durante l'analisi forense, ma eseguirlo su un file compresso può far apparire il file vuoto o renderlo inaccessibile finché i suoi metadati non vengono riparati:
```bash
chflags nocompressed /path/to/file
```
L'utilità integrata `/usr/bin/afscexpand` può forzare l'espansione dei file compressi in modo trasparente. L'utilità separata di terze parti `afsctool` può anche ispezionare o decomprimere la compressione del filesystem Apple, ma non deve essere confusa con il comando integrato. <sup>[[8]](#references)</sup>


### Posizioni di configurazione interessanti (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Archivia i file plist dei feature flag di Apple che controllano comportamenti opzionali o sperimentali nei daemon / framework di sistema | Se un attacker può bypassare SIP o ottenere privilegi, la loro modifica potrebbe abilitare percorsi di codice nascosti o disabilitare le protezioni |
| `/System/Library/CoreServices/systemVersion.plist` | Contiene i metadati della versione di macOS (ProductVersion, BuildVersion) utilizzati da app / installer per determinare il comportamento | La modifica può indurre app o installer ad accettare versioni del sistema operativo non supportate o a sbloccare funzionalità |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferenze dell'applicazione / a livello di sistema | Se scrivibili, gli attacker possono iniettare impostazioni per indirizzare il comportamento delle app, disabilitare le protezioni o causare una configurazione errata |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definizioni plist per daemon e agent in background | L'inserimento o la manipolazione di plist dannosi (se i permessi lo consentono) permette la persistenza o l'escalation dei privilegi |
| `/etc/hosts` | Mappature hostname ↔ IP utilizzate dal resolver DNS del sistema | Reindirizzamento dei nomi di dominio, intercettazione del traffico, spoofing dei servizi sotto il controllo locale |
| `/etc/sudoers` | Definisce chi può eseguire comandi con `sudo` e a quali condizioni | Un file sudoers corrotto può concedere privilegi root o privilegi inappropriati agli account degli attacker |
| `/private/var/db/dslocal/nodes/Default/users/` | File plist di definizione degli account utente locali | La manipolazione consente la creazione o la modifica di account utente, hash delle password o metadati degli utenti |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Estensioni del kernel / driver | L'installazione o la modifica di kext può portare al controllo a livello kernel; queste operazioni sono fortemente protette da SIP / policy sulle firme |
| `/private/var/db/SystemPolicyConfiguration/` | Archivia la configurazione per l'applicazione delle policy di sistema (ad es. Gatekeeper, notarizzazione) | La manipolazione può consentire l'elusione dei controlli delle policy o delle regole di attendibilità |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binari helper SSH e file di configurazione | Una configurazione errata porta a una sicurezza SSH debole, accessi non autorizzati o algoritmi non sicuri |
| `/System/Library/Sandbox/Profiles` | Profili sandbox di sistema (SBPL) utilizzati per limitare le azioni dei processi | La sostituzione o modifica dei profili può aprire vettori di sandbox escape o indebolire il contenimento |

> **Nota**: Molti di questi percorsi si trovano in directory protette da SIP (ad es. `/System`) e sono protetti dalla scrittura, a meno che SIP non sia disabilitato o bypassato.


## Universal Binaries e formato Mach-O

Mach-O è il formato eseguibile nativo di macOS. Un universal binary, o fat binary, racchiude più slice Mach-O specifiche per l'architettura in un singolo file; la pagina dedicata spiega entrambi i formati:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Dump della memoria di macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Rischio dei file e metadati degli handler

LaunchServices, la quarantena dei file e Gatekeeper influenzano collettivamente il modo in cui macOS gestisce i file scaricati e seleziona le applicazioni per le estensioni e gli schemi URL. I relativi database e file di risorse interni cambiano tra le release; usa le pagine dedicate invece di considerare un percorso privato di CoreTypes come un'interfaccia stabile per le policy:

Nelle release che espongono i metadati legacy del rischio di CoreTypes in `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, le categorie comunemente incontrate sono:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: contenuto considerato sufficientemente sicuro per l'apertura automatica secondo la policy applicabile dell'applicazione.
- **`LSRiskCategoryNeutral`**: contenuto che normalmente non attiva un avviso e non viene aperto automaticamente.
- **`LSRiskCategoryUnsafeExecutable`**: contenuto eseguibile per il quale l'utente dovrebbe ricevere un avviso dell'applicazione.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: contenitori come gli archivi che possono contenere contenuto eseguibile e richiedono un'ulteriore ispezione.

Questi sono dettagli di implementazione, non una API pubblica stabile per le policy; verifica i metadati effettivi e il comportamento di Safari/Gatekeeper sulla versione di macOS sottoposta a test.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## File di log

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene informazioni sui file scaricati, come l'URL da cui sono stati scaricati.
- **Unified log**: Nelle versioni attuali di macOS, interroga gli eventi di sistema e delle applicazioni con `log show` e `log stream`. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** e **`/private/var/log/asl/*.asl`**: Artefatti di logging legacy che possono essere ancora rilevanti sui sistemi meno recenti. In tali release, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` configura `syslogd`; `launchctl list | grep com.apple.syslogd` può aiutare a determinare se il servizio è caricato.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Archivia i file e le applicazioni a cui si è avuto accesso di recente tramite "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Percorso delle preferenze legacy associato agli elementi di login; le versioni moderne di macOS utilizzano meccanismi aggiuntivi.
- **`$HOME/Library/Logs/DiskUtility.log`**: Log legacy di Disk Utility che può contenere informazioni sulle unità, inclusi i dispositivi USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dati sui punti di accesso wireless.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Dati legacy degli override di launchd.

## References

- [1] [Apple - Guida alla programmazione del file system](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Guida alla programmazione dei bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Apple Developer Forums - Panoramica della dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Guida alla programmazione del file system: sicurezza del file system di macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - pagina del manuale di macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - pagina del manuale di macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - pagina del manuale di macOS](https://manp.gs/mac/1/afscexpand)
{{#include ../../../banners/hacktricks-training.md}}
