# File, cartelle, binari e memoria di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Struttura gerarchica dei file

- **/Applications**: Le app installate dovrebbero trovarsi qui. Tutti gli utenti potranno accedervi.
- **/bin**: Binari da riga di comando
- **/cores**: Se esiste, viene usata per memorizzare i core dump
- **/dev**: Tutto viene trattato come un file, quindi qui si possono trovare i dispositivi hardware.
- **/etc**: File di configurazione
- **/Library**: Qui si trovano molte sottodirectory e file relativi a preferenze, cache e log. Esiste una cartella Library nella root e nella directory di ogni utente.
- **/private**: Non documentata, ma molte delle cartelle menzionate sono collegamenti simbolici alla directory private.
- **/sbin**: Binari di sistema essenziali (relativi all'amministrazione)
- **/System**: File necessari per eseguire OS X. Qui dovrebbero trovarsi principalmente file specifici di Apple (non di terze parti).
- **/tmp**: I file vengono eliminati dopo 3 giorni (è un soft link a /private/tmp)
- **/Users**: Directory home degli utenti.
- **/usr**: Configurazioni e binari di sistema
- **/var**: File di log
- **/Volumes**: Le unità montate appariranno qui.
- **/.vol**: Eseguendo `stat a.txt` si ottiene qualcosa come `16777223 7545753 -rw-r--r-- 1 username wheel ...`, dove il primo numero è l'ID del volume in cui esiste il file e il secondo è il numero dell'inode. È possibile accedere al contenuto di questo file tramite /.vol/ con queste informazioni, eseguendo `cat /.vol/16777223/7545753`

### Cartelle delle applicazioni

- Le **applicazioni di sistema** si trovano in `/System/Applications`
- Le applicazioni **installate** vengono solitamente installate in `/Applications` o in `~/Applications`
- I dati delle applicazioni si trovano in `/Library/Application Support` per le applicazioni eseguite come root e in `~/Library/Application Support` per le applicazioni eseguite come utente.
- I **daemon** di applicazioni di terze parti che **devono essere eseguiti come root** si trovano solitamente in `/Library/PrivilegedHelperTools/`
- Le app **sandboxed** sono mappate nella cartella `~/Library/Containers`. Ogni app ha una cartella denominata in base al bundle ID dell'applicazione (`com.apple.Safari`).
- Il **kernel** si trova in `/System/Library/Kernels/kernel`
- Le estensioni del **kernel** di **Apple** si trovano in `/System/Library/Extensions`
- Le estensioni del **kernel** di **terze parti** sono memorizzate in `/Library/Extensions`

### File con informazioni sensibili

MacOS memorizza informazioni come le password in diverse posizioni:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Installer pkg vulnerabili


{{#ref}}
macos-installers-abuse.md
{{#endref}}

## Estensioni specifiche di OS X

- **`.dmg`**: I file Apple Disk Image sono molto comuni per gli installer.
- **`.kext`**: Deve seguire una struttura specifica ed è la versione di OS X di un driver. (è un bundle)
- **`.plist`**: Conosciuto anche come property list, memorizza informazioni in formato XML o binario.
- Può essere XML o binario. Quelli binari possono essere letti con:
- `defaults read config.plist`
- `/usr/libexec/PlistBuddy -c print config.plsit`
- `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
- `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
- `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Applicazioni Apple che seguono una struttura a directory (è un bundle).
- **`.dylib`**: Librerie dinamiche (come i file DLL di Windows)
- **`.pkg`**: Sono uguali a xar (formato eXtensible Archive). Il comando installer può essere utilizzato per installare il contenuto di questi file.
- **`.DS_Store`**: Questo file si trova in ogni directory e salva gli attributi e le personalizzazioni della directory.
- **`.Spotlight-V100`**: Questa cartella appare nella directory root di ogni volume del sistema.
- **`.metadata_never_index`**: Se questo file si trova nella root di un volume, Spotlight non indicizzerà quel volume.
- **`.noindex`**: I file e le cartelle con questa estensione non verranno indicizzati da Spotlight.
- **`.sdef`**: File all'interno dei bundle che specificano come è possibile interagire con l'applicazione da un AppleScript.

### Bundle di macOS

Un bundle è una **directory** che **sembra un oggetto nel Finder** (un esempio di Bundle sono i file `*.app`).


{{#ref}}
macos-bundles.md
{{#endref}}

## Cache delle librerie condivise Dyld (SLC)

Su macOS (e iOS), tutte le librerie condivise di sistema, come framework e dylib, sono **combinate in un singolo file**, chiamato **dyld shared cache**. Questo ha migliorato le prestazioni, poiché il codice può essere caricato più velocemente.

Su macOS si trova in `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` e nelle versioni precedenti potrebbe essere possibile trovare la **shared cache** in **`/System/Library/dyld/`**.\
Su iOS è possibile trovarla in **`/System/Library/Caches/com.apple.dyld/`**.

Analogamente alla dyld shared cache, anche il kernel e le estensioni del kernel vengono compilati in una kernel cache, che viene caricata all'avvio.

Per estrarre le librerie dalla singola shared cache di dylib era possibile utilizzare il binario [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip), che potrebbe non funzionare al giorno d'oggi, ma è anche possibile usare [**dyldextractor**](https://github.com/arandomdev/dyldextractor):
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
> [!TIP]
> Nota che anche se lo strumento `dyld_shared_cache_util` non funziona, puoi passare il **binario dyld condiviso a Hopper** e Hopper sarà in grado di identificare tutte le librerie e permetterti di **selezionare quale** vuoi analizzare:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Alcuni estrattori non funzioneranno, poiché le dylib sono precollegate con indirizzi hard-coded e quindi potrebbero saltare a indirizzi sconosciuti

> [!TIP]
> È anche possibile scaricare la Shared Library Cache di altri dispositivi \*OS in macos utilizzando un emulator in Xcode. Verranno scaricate all'interno di: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, come:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** utilizza la syscall **`shared_region_check_np`** per sapere se la SLC è stata mappata (restituisce l'indirizzo) e **`shared_region_map_and_slide_np`** per mappare la SLC.

Nota che, anche se la SLC viene sottoposta a slide al primo utilizzo, tutti i **processi** utilizzano la **stessa copia**, il che **eliminava la protezione ASLR** se l'attacker riusciva a eseguire processi nel sistema. Questo è stato effettivamente sfruttato in passato e risolto con shared region pager.

I branch pool sono piccole dylib Mach-O che creano piccoli spazi tra le mappature delle immagini, rendendo impossibile fare interpose sulle funzioni.

### Override SLCs

Utilizzando le variabili d'ambiente:

- **`DYLD_DHARED_REGION=private DYLD_SHARED_CACHE_DIR=</path/dir> DYLD_SHARED_CACHE_DONT_VALIDATE=1`** -> Questo consentirà di caricare una nuova shared library cache
- **`DYLD_SHARED_CACHE_DIR=avoid`** e sostituendo manualmente le librerie con symlink alla shared cache contenente quelle reali (dovrai estrarle)

## Permessi speciali dei file

### Permessi delle cartelle

In una **cartella**, **read** consente di **elencarne il contenuto**, **write** consente di **eliminare** e **scrivere** file al suo interno, mentre **execute** consente di **attraversare** la directory. Quindi, ad esempio, un utente con **permesso di lettura su un file** all'interno di una directory sulla quale **non dispone del permesso execute** **non potrà leggere** il file.

### Modificatori dei flag

Esistono alcuni flag che possono essere impostati sui file e che ne modificano il comportamento. Puoi **controllare i flag** dei file all'interno di una directory con `ls -lO /path/directory`

- **`uchg`**: Noto come flag **uchange**, **impedisce qualsiasi azione** che modifichi o elimini il **file**. Per impostarlo, esegui: `chflags uchg file.txt`
- L'utente root può **rimuovere il flag** e modificare il file
- **`restricted`**: Questo flag fa sì che il file sia **protetto da SIP** (non puoi aggiungere questo flag a un file).
- **`Sticky bit`**: Se una directory ha lo sticky bit, **solo il proprietario della directory o root può rinominare o eliminare** i file. In genere viene impostato sulla directory /tmp per impedire agli utenti comuni di eliminare o spostare i file degli altri utenti.

Tutti i flag sono disponibili nel file `sys/stat.h` (trovalo utilizzando `mdfind stat.h | grep stat.h`) e sono:

- `UF_SETTABLE` 0x0000ffff: Maschera dei flag modificabili dal proprietario.
- `UF_NODUMP` 0x00000001: Non eseguire il dump del file.
- `UF_IMMUTABLE` 0x00000002: Il file non può essere modificato.
- `UF_APPEND` 0x00000004: È possibile solo aggiungere dati al file.
- `UF_OPAQUE` 0x00000008: La directory è opaca rispetto all'union.
- `UF_COMPRESSED` 0x00000020: Il file è compresso (alcuni file system).
- `UF_TRACKED` 0x00000040: Nessuna notifica per eliminazioni/ridenominazioni dei file per i quali questo flag è impostato.
- `UF_DATAVAULT` 0x00000080: È richiesto un entitlement per la lettura e la scrittura.
- `UF_HIDDEN` 0x00008000: Indicazione che questo elemento non dovrebbe essere visualizzato in una GUI.
- `SF_SUPPORTED` 0x009f0000: Maschera dei flag supportati dal superuser.
- `SF_SETTABLE` 0x3fff0000: Maschera dei flag modificabili dal superuser.
- `SF_SYNTHETIC` 0xc0000000: Maschera dei flag sintetici in sola lettura del sistema.
- `SF_ARCHIVED` 0x00010000: Il file è archiviato.
- `SF_IMMUTABLE` 0x00020000: Il file non può essere modificato.
- `SF_APPEND` 0x00040000: È possibile solo aggiungere dati al file.
- `SF_RESTRICTED` 0x00080000: È richiesto un entitlement per la scrittura.
- `SF_NOUNLINK` 0x00100000: L'elemento non può essere rimosso, rinominato o utilizzato come punto di mount.
- `SF_FIRMLINK` 0x00800000: Il file è un firmlink.
- `SF_DATALESS` 0x40000000: Il file è un oggetto dataless.

### **ACL dei file**

Le **ACL** dei file contengono le **ACE** (Access Control Entries), tramite le quali è possibile assegnare **permessi più granulari** a utenti diversi.

È possibile assegnare a una **directory** questi permessi: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
E a un **file**: `read`, `write`, `append`, `execute`.

Quando il file contiene ACL, vedrai un **"+" quando elenchi i permessi, come in**:
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
Puoi trovare **tutti i file con ACL** con (è mooolto lento):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Attributi estesi

Gli attributi estesi hanno un nome e qualsiasi valore desiderato e possono essere visualizzati usando `ls -@` e manipolati usando il comando `xattr`. Alcuni attributi estesi comuni sono:

- `com.apple.resourceFork`: Compatibilità con Resource fork. Visibile anche come `filename/..namedfork/rsrc`
- `com.apple.quarantine`: macOS: meccanismo di quarantena di Gatekeeper (III/6)
- `metadata:*`: macOS: vari metadati, come `_backup_excludeItem` o `kMD*`
- `com.apple.lastuseddate` (#PS): Data dell'ultimo utilizzo del file
- `com.apple.FinderInfo`: macOS: informazioni di Finder (ad esempio, i Tag colorati)
- `com.apple.TextEncoding`: Specifica la codifica del testo dei file di testo ASCII
- `com.apple.logd.metadata`: Utilizzato da logd sui file in `/var/db/diagnostics`
- `com.apple.genstore.*`: Archiviazione generazionale (`/.DocumentRevisions-V100` nella radice del filesystem)
- `com.apple.rootless`: macOS: utilizzato da System Integrity Protection per etichettare i file (III/10)
- `com.apple.uuidb.boot-uuid`: Marcature di logd delle epoche di avvio con UUID univoci
- `com.apple.decmpfs`: macOS: compressione trasparente dei file (II/7)
- `com.apple.cprotect`: \*OS: dati di cifratura per file (III/11)
- `com.apple.installd.*`: \*OS: metadati utilizzati da installd, ad esempio `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Questo è un modo per ottenere **Alternate Data Streams sulle macchine macOS**. È possibile salvare contenuti all'interno di un attributo esteso chiamato **com.apple.ResourceFork** dentro un file, salvandoli in **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Puoi **trovare tutti i file contenenti questo attributo esteso** con:
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
### decmpfs

L'attributo esteso `com.apple.decmpfs` indica che il file è archiviato in forma compressa, `ls -l` riporterà una **dimensione pari a 0** e i dati compressi si trovano all'interno di questo attributo. Ogni volta che si accede al file, questo verrà decompresso in memoria.

Questo attr può essere visualizzato con `ls -lO`, dove viene indicato come compresso, poiché i file compressi sono contrassegnati anche con il flag `UF_COMPRESSED`. Se a un file compresso viene rimosso questo flag con `chflags nocompressed </path/to/file>`, il sistema non saprà che il file era compresso e quindi non sarà in grado di decomprimerlo e accedere ai dati (penserà che sia effettivamente vuoto).

Lo strumento afscexpand può essere utilizzato per forzare la decompressione di un file.


### Posizioni di configurazione interessanti (macOS)

| Percorso / Posizione | Scopo / Cosa configura | Sicurezza / Potenziale di attacco |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Contiene i file plist dei feature flag di Apple che controllano comportamenti opzionali o sperimentali nei daemon / framework di sistema | Se un attacker riesce a bypassare SIP o a ottenere privilegi, la loro manomissione potrebbe abilitare percorsi di codice nascosti o disabilitare le protezioni |
| `/System/Library/CoreServices/systemVersion.plist` | Contiene i metadati della versione di macOS (ProductVersion, BuildVersion) utilizzati da app / installer per determinare il comportamento | La modifica potrebbe indurre app o installer ad accettare versioni del sistema operativo non supportate o a sbloccare funzionalità |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Preferenze dell'applicazione / a livello di sistema | Se scrivibili, gli attacker possono iniettare impostazioni per indirizzare il comportamento delle app, disabilitare le protezioni o causare una configurazione errata |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Definizioni plist per daemon e agent in background | L'inserimento o la manipolazione di plist malevoli (se i permessi lo consentono) permette la persistenza o l'escalation dei privilegi |
| `/etc/hosts` | Mappature hostname ↔ IP utilizzate dal resolver DNS del sistema | Reindirizzamento dei nomi di dominio, intercettazione del traffico, spoofing dei servizi sotto controllo locale |
| `/etc/sudoers` | Definisce chi può eseguire comandi con `sudo` e a quali condizioni | Un file sudoers corrotto può concedere root o privilegi inappropriati agli account degli attacker |
| `/private/var/db/dslocal/nodes/Default/users/` | File plist di definizione degli account utente locali | La manomissione permette la creazione o la modifica di account utente, hash delle password o metadati degli utenti |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Estensioni del kernel / driver | L'installazione o la modifica dei kext può portare al controllo a livello kernel; sono fortemente protetti da SIP / policy sulle firme |
| `/private/var/db/SystemPolicyConfiguration/` | Contiene la configurazione per l'applicazione delle policy di sistema (ad es. Gatekeeper, notarizzazione) | La manomissione può consentire di aggirare i controlli delle policy o le regole di trust |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Binaries helper e file di configurazione SSH | Una configurazione errata può causare una sicurezza SSH debole, accessi non autorizzati o algoritmi non sicuri |
| `/System/Library/Sandbox/Profiles` | Profili sandbox di sistema (SBPL) utilizzati per limitare le azioni dei processi | La sostituzione o la modifica dei profili può creare vettori di sandbox escape o indebolire il contenimento |

> **Nota**: Molti di questi percorsi si trovano in directory protette da SIP (ad es. `/System`) e sono protetti dalla scrittura, a meno che SIP non sia disabilitato o bypassato.


## Binaries universali & formato Mach-o

I binaries di Mac OS sono generalmente compilati come **binaries universali**. Un **universal binary** può **supportare più architetture nello stesso file**.

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Dump della memoria di macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## File delle categorie di rischio di Mac OS

La directory `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` è il percorso in cui vengono memorizzate le informazioni sul **rischio associato alle diverse estensioni di file**. Questa directory classifica i file in vari livelli di rischio, influenzando il modo in cui Safari gestisce questi file dopo il download. Le categorie sono le seguenti:

- **LSRiskCategorySafe**: I file di questa categoria sono considerati **completamente sicuri**. Safari aprirà automaticamente questi file dopo il download.
- **LSRiskCategoryNeutral**: Questi file non mostrano avvisi e **non vengono aperti automaticamente** da Safari.
- **LSRiskCategoryUnsafeExecutable**: I file di questa categoria **generano un avviso** che indica che il file è un'applicazione. Questo funge da misura di sicurezza per avvisare l'utente.
- **LSRiskCategoryMayContainUnsafeExecutable**: Questa categoria è destinata ai file, come gli archivi, che potrebbero contenere un eseguibile. Safari **genererà un avviso** a meno che non possa verificare che tutti i contenuti siano sicuri o neutrali.

## File di log

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Contiene informazioni sui file scaricati, come l'URL da cui sono stati scaricati.
- **`/var/log/system.log`**: Log principale dei sistemi OSX. com.apple.syslogd.plist è responsabile dell'esecuzione del syslogging (è possibile verificare se è disabilitato cercando "com.apple.syslogd" in `launchctl list`.
- **`/private/var/log/asl/*.asl`**: Questi sono gli Apple System Logs e possono contenere informazioni interessanti.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Memorizza i file e le applicazioni a cui si è avuto recentemente accesso tramite "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Memorizza gli elementi da avviare all'avvio del sistema
- **`$HOME/Library/Logs/DiskUtility.log`**: File di log dell'app DiskUtility (informazioni sulle unità, incluse le USB)
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dati sui punti di accesso wireless.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Elenco dei daemon disattivati.

{{#include ../../../banners/hacktricks-training.md}}
