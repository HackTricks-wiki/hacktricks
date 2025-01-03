# macOS File, Cartelle, Binaries & Memoria

{{#include ../../../banners/hacktricks-training.md}}

## Layout gerarchico dei file

- **/Applications**: Le app installate dovrebbero trovarsi qui. Tutti gli utenti potranno accedervi.
- **/bin**: Binaries da linea di comando
- **/cores**: Se esiste, viene utilizzato per memorizzare i core dump
- **/dev**: Tutto è trattato come un file, quindi potresti vedere i dispositivi hardware memorizzati qui.
- **/etc**: File di configurazione
- **/Library**: Qui si possono trovare molte sottodirectory e file relativi a preferenze, cache e log. Una cartella Library esiste nella root e in ogni directory utente.
- **/private**: Non documentato, ma molte delle cartelle menzionate sono collegamenti simbolici alla directory privata.
- **/sbin**: Binaries di sistema essenziali (relativi all'amministrazione)
- **/System**: File per far funzionare OS X. Qui dovresti trovare principalmente solo file specifici di Apple (non di terze parti).
- **/tmp**: I file vengono eliminati dopo 3 giorni (è un collegamento simbolico a /private/tmp)
- **/Users**: Directory home per gli utenti.
- **/usr**: Config e binaries di sistema
- **/var**: File di log
- **/Volumes**: Le unità montate appariranno qui.
- **/.vol**: Eseguendo `stat a.txt` ottieni qualcosa come `16777223 7545753 -rw-r--r-- 1 username wheel ...` dove il primo numero è l'id del volume in cui esiste il file e il secondo è il numero inode. Puoi accedere al contenuto di questo file tramite /.vol/ con quelle informazioni eseguendo `cat /.vol/16777223/7545753`

### Cartelle delle Applicazioni

- **Le applicazioni di sistema** si trovano sotto `/System/Applications`
- **Le applicazioni installate** sono solitamente installate in `/Applications` o in `~/Applications`
- **I dati delle applicazioni** possono essere trovati in `/Library/Application Support` per le applicazioni in esecuzione come root e `~/Library/Application Support` per le applicazioni in esecuzione come utente.
- Le **daemon** delle applicazioni di terze parti che **devono essere eseguite come root** si trovano solitamente in `/Library/PrivilegedHelperTools/`
- Le app **sandboxed** sono mappate nella cartella `~/Library/Containers`. Ogni app ha una cartella denominata secondo l'ID del bundle dell'applicazione (`com.apple.Safari`).
- Il **kernel** si trova in `/System/Library/Kernels/kernel`
- **Le estensioni del kernel di Apple** si trovano in `/System/Library/Extensions`
- **Le estensioni del kernel di terze parti** sono memorizzate in `/Library/Extensions`

### File con Informazioni Sensibili

MacOS memorizza informazioni come le password in diversi luoghi:

{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Installer pkg Vulnerabili

{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Estensioni Specifiche di OS X

- **`.dmg`**: I file Apple Disk Image sono molto frequenti per gli installer.
- **`.kext`**: Deve seguire una struttura specifica ed è la versione OS X di un driver. (è un bundle)
- **`.plist`**: Conosciuto anche come property list, memorizza informazioni in formato XML o binario.
- Può essere XML o binario. Quelli binari possono essere letti con:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Applicazioni Apple che seguono la struttura delle directory (è un bundle).
- **`.dylib`**: Librerie dinamiche (come i file DLL di Windows)
- **`.pkg`**: Sono gli stessi di xar (eXtensible Archive format). Il comando installer può essere utilizzato per installare i contenuti di questi file.
- **`.DS_Store`**: Questo file si trova in ogni directory, salva gli attributi e le personalizzazioni della directory.
- **`.Spotlight-V100`**: Questa cartella appare nella directory root di ogni volume del sistema.
- **`.metadata_never_index`**: Se questo file si trova nella root di un volume, Spotlight non indicizzerà quel volume.
- **`.noindex`**: File e cartelle con questa estensione non verranno indicizzati da Spotlight.
- **`.sdef`**: File all'interno dei bundle che specificano come è possibile interagire con l'applicazione da un AppleScript.

### Bundle di macOS

Un bundle è una **directory** che **sembra un oggetto in Finder** (un esempio di Bundle sono i file `*.app`).

{{#ref}}
macos-bundles.md
{{#endref}}

## Cache della Libreria Condivisa Dyld (SLC)

Su macOS (e iOS) tutte le librerie condivise di sistema, come framework e dylibs, sono **combinati in un unico file**, chiamato **cache condivisa dyld**. Questo migliora le prestazioni, poiché il codice può essere caricato più rapidamente.

Questo si trova in macOS in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` e nelle versioni più vecchie potresti trovare la **cache condivisa** in **`/System/Library/dyld/`**.\
In iOS puoi trovarli in **`/System/Library/Caches/com.apple.dyld/`**.

Simile alla cache condivisa dyld, il kernel e le estensioni del kernel sono anche compilati in una cache del kernel, che viene caricata all'avvio.

Per estrarre le librerie dal file unico della cache condivisa dylib, era possibile utilizzare il binario [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip) che potrebbe non funzionare al giorno d'oggi, ma puoi anche usare [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Nota che anche se lo strumento `dyld_shared_cache_util` non funziona, puoi passare il **binary dyld condiviso a Hopper** e Hopper sarà in grado di identificare tutte le librerie e permetterti di **selezionare quale** vuoi investigare:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Alcuni estrattori non funzioneranno poiché le dylibs sono precollegate con indirizzi hardcoded e quindi potrebbero saltare a indirizzi sconosciuti.

> [!TIP]
> È anche possibile scaricare la Cache delle Librerie Condivise di altri dispositivi \*OS in macos utilizzando un emulatore in Xcode. Saranno scaricati all'interno di: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, come: `$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** utilizza la syscall **`shared_region_check_np`** per sapere se l'SLC è stato mappato (che restituisce l'indirizzo) e **`shared_region_map_and_slide_np`** per mappare l'SLC.

Nota che anche se l'SLC è scivolato al primo utilizzo, tutti i **processi** utilizzano la **stessa copia**, il che **elimina la protezione ASLR** se l'attaccante è in grado di eseguire processi nel sistema. Questo è stato effettivamente sfruttato in passato ed è stato corretto con il pager della regione condivisa.

I branch pool sono piccole dylibs Mach-O che creano piccoli spazi tra le mappature delle immagini rendendo impossibile l'interposizione delle funzioni.

### Override SLCs

Utilizzando le variabili di ambiente:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Questo permetterà di caricare una nuova cache di librerie condivise.
- **`DYLD_SHARED_CACHE_DIR=avoid`** e sostituire manualmente le librerie con symlink alla cache condivisa con quelle reali (dovrai estrarle).

## Permessi Speciali dei File

### Permessi delle Cartelle

In una **cartella**, il **permesso di lettura** consente di **elencarla**, il **permesso di scrittura** consente di **eliminare** e **scrivere** file al suo interno, e il **permesso di esecuzione** consente di **attraversare** la directory. Quindi, ad esempio, un utente con **permesso di lettura su un file** all'interno di una directory in cui non ha **permesso di esecuzione** **non sarà in grado di leggere** il file.

### Modificatori di Flag

Ci sono alcuni flag che possono essere impostati nei file che faranno comportare il file in modo diverso. Puoi **controllare i flag** dei file all'interno di una directory con `ls -lO /path/directory`

- **`uchg`**: Conosciuto come flag **uchange** impedirà **qualsiasi azione** di modifica o eliminazione del **file**. Per impostarlo fare: `chflags uchg file.txt`
- L'utente root potrebbe **rimuovere il flag** e modificare il file.
- **`restricted`**: Questo flag rende il file **protetto da SIP** (non puoi aggiungere questo flag a un file).
- **`Sticky bit`**: Se una directory ha il bit sticky, **solo** il **proprietario della directory o root può rinominare o eliminare** file. Tipicamente questo è impostato sulla directory /tmp per impedire agli utenti normali di eliminare o spostare i file di altri utenti.

Tutti i flag possono essere trovati nel file `sys/stat.h` (trovalo usando `mdfind stat.h | grep stat.h`) e sono:

- `UF_SETTABLE` 0x0000ffff: Maschera dei flag modificabili dal proprietario.
- `UF_NODUMP` 0x00000001: Non eseguire il dump del file.
- `UF_IMMUTABLE` 0x00000002: Il file non può essere modificato.
- `UF_APPEND` 0x00000004: Le scritture nel file possono solo aggiungere.
- `UF_OPAQUE` 0x00000008: La directory è opaca rispetto all'unione.
- `UF_COMPRESSED` 0x00000020: Il file è compresso (alcuni file system).
- `UF_TRACKED` 0x00000040: Nessuna notifica per eliminazioni/rinominazioni per file con questo impostato.
- `UF_DATAVAULT` 0x00000080: È richiesta un'autorizzazione per la lettura e la scrittura.
- `UF_HIDDEN` 0x00008000: Suggerimento che questo elemento non dovrebbe essere visualizzato in un'interfaccia grafica.
- `SF_SUPPORTED` 0x009f0000: Maschera dei flag supportati dall'utente super.
- `SF_SETTABLE` 0x3fff0000: Maschera dei flag modificabili dall'utente super.
- `SF_SYNTHETIC` 0xc0000000: Maschera dei flag sintetici di sola lettura di sistema.
- `SF_ARCHIVED` 0x00010000: Il file è archiviato.
- `SF_IMMUTABLE` 0x00020000: Il file non può essere modificato.
- `SF_APPEND` 0x00040000: Le scritture nel file possono solo aggiungere.
- `SF_RESTRICTED` 0x00080000: È richiesta un'autorizzazione per la scrittura.
- `SF_NOUNLINK` 0x00100000: L'elemento non può essere rimosso, rinominato o montato.
- `SF_FIRMLINK` 0x00800000: Il file è un firmlink.
- `SF_DATALESS` 0x40000000: Il file è un oggetto senza dati.

### **File ACLs**

Le **ACLs** dei file contengono **ACE** (Access Control Entries) dove possono essere assegnati permessi **più granulari** a diversi utenti.

È possibile concedere a una **directory** questi permessi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
E a un **file**: `read`, `write`, `append`, `execute`.

Quando il file contiene ACLs troverai **un "+" quando elenchi i permessi come in**:
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
Puoi trovare **tutti i file con ACL** con (questo è molto lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Attributi Estesi

Gli attributi estesi hanno un nome e un valore desiderato, e possono essere visualizzati usando `ls -@` e manipolati usando il comando `xattr`. Alcuni attributi estesi comuni sono:

- `com.apple.resourceFork`: Compatibilità con il fork delle risorse. Visibile anche come `filename/..namedfork/rsrc`
- `com.apple.quarantine`: MacOS: meccanismo di quarantena di Gatekeeper (III/6)
- `metadata:*`: MacOS: vari metadati, come `_backup_excludeItem`, o `kMD*`
- `com.apple.lastuseddate` (#PS): Ultima data di utilizzo del file
- `com.apple.FinderInfo`: MacOS: informazioni del Finder (ad es., Tag di colore)
- `com.apple.TextEncoding`: Specifica la codifica del testo dei file di testo ASCII
- `com.apple.logd.metadata`: Utilizzato da logd su file in `/var/db/diagnostics`
- `com.apple.genstore.*`: Archiviazione generazionale (`/.DocumentRevisions-V100` nella radice del filesystem)
- `com.apple.rootless`: MacOS: Utilizzato da System Integrity Protection per etichettare il file (III/10)
- `com.apple.uuidb.boot-uuid`: marcature logd delle epoche di avvio con UUID unici
- `com.apple.decmpfs`: MacOS: compressione trasparente dei file (II/7)
- `com.apple.cprotect`: \*OS: Dati di crittografia per file singoli (III/11)
- `com.apple.installd.*`: \*OS: Metadati utilizzati da installd, ad es., `installType`, `uniqueInstallID`

### Fork delle Risorse | macOS ADS

Questo è un modo per ottenere **Stream di Dati Alternativi in MacOS**. Puoi salvare contenuti all'interno di un attributo esteso chiamato **com.apple.ResourceFork** all'interno di un file salvandolo in **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Puoi **trovare tutti i file che contengono questo attributo esteso** con:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

L'attributo esteso `com.apple.decmpfs` indica che il file è memorizzato in modo crittografato, `ls -l` riporterà una **dimensione di 0** e i dati compressi si trovano all'interno di questo attributo. Ogni volta che il file viene accesso, verrà decrittografato in memoria.

Questo attributo può essere visualizzato con `ls -lO` indicato come compresso perché i file compressi sono anche contrassegnati con il flag `UF_COMPRESSED`. Se un file compresso viene rimosso con questo flag usando `chflags nocompressed </path/to/file>`, il sistema non saprà che il file era compresso e quindi non sarà in grado di decomprimere e accedere ai dati (penserà che sia effettivamente vuoto).

Lo strumento afscexpand può essere utilizzato per forzare la decompressione di un file.

## **Universal binaries &** Mach-o Format

I binari Mac OS di solito sono compilati come **universal binaries**. Un **universal binary** può **supportare più architetture nello stesso file**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}

## macOS Process Memory

## macOS memory dumping

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Risk Category Files Mac OS

La directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` è dove sono memorizzate le informazioni sul **rischio associato a diverse estensioni di file**. Questa directory categorizza i file in vari livelli di rischio, influenzando il modo in cui Safari gestisce questi file al momento del download. Le categorie sono le seguenti:

- **LSRiskCategorySafe**: I file in questa categoria sono considerati **completamente sicuri**. Safari aprirà automaticamente questi file dopo che sono stati scaricati.
- **LSRiskCategoryNeutral**: Questi file non presentano avvisi e **non vengono aperti automaticamente** da Safari.
- **LSRiskCategoryUnsafeExecutable**: I file sotto questa categoria **attivano un avviso** che indica che il file è un'applicazione. Questo serve come misura di sicurezza per avvisare l'utente.
- **LSRiskCategoryMayContainUnsafeExecutable**: Questa categoria è per file, come archivi, che potrebbero contenere un eseguibile. Safari **attiverà un avviso** a meno che non possa verificare che tutti i contenuti siano sicuri o neutrali.

## Log files

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene informazioni sui file scaricati, come l'URL da cui sono stati scaricati.
- **`/var/log/system.log`**: Log principale dei sistemi OSX. com.apple.syslogd.plist è responsabile dell'esecuzione del syslogging (puoi controllare se è disabilitato cercando "com.apple.syslogd" in `launchctl list`).
- **`/private/var/log/asl/*.asl`**: Questi sono i log di sistema Apple che possono contenere informazioni interessanti.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Memorizza i file e le applicazioni recentemente accessibili tramite "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Memorizza gli elementi da avviare all'avvio del sistema.
- **`$HOME/Library/Logs/DiskUtility.log`**: File di log per l'app DiskUtility (info sui dischi, inclusi gli USB).
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dati sui punti di accesso wireless.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Elenco dei demoni disattivati.

{{#include ../../../banners/hacktricks-training.md}}
