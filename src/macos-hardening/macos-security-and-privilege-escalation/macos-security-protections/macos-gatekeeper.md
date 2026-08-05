# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** è una funzionalità di sicurezza sviluppata per i sistemi operativi Mac, progettata per garantire che gli utenti **eseguano solo software affidabile** sui propri sistemi. Funziona **convalidando il software** che un utente scarica e tenta di aprire da **fonti esterne all'App Store**, come un'app, un plug-in o un pacchetto di installazione.

Il meccanismo principale di Gatekeeper consiste nel processo di **verifica**. Controlla se il software è **firmato da uno sviluppatore riconosciuto**, garantendone l'autenticità. Inoltre, verifica che il software sia stato **notarizzato da Apple**, confermando che sia privo di contenuti dannosi noti e che non sia stato manomesso dopo la notarizzazione.

Inoltre, Gatekeeper rafforza il controllo e la sicurezza dell'utente **chiedendo agli utenti di approvare l'apertura** del software scaricato al primo utilizzo. Questa protezione aiuta a impedire agli utenti di eseguire inavvertitamente codice eseguibile potenzialmente dannoso che potrebbero aver scambiato per un file di dati innocuo.

### Firme delle applicazioni

Le firme delle applicazioni, note anche come firme del codice, sono una componente essenziale dell'infrastruttura di sicurezza di Apple. Vengono utilizzate per **verificare l'identità dell'autore del software** (lo sviluppatore) e per garantire che il codice non sia stato manomesso dall'ultima volta in cui è stato firmato.

Ecco come funziona:

1. **Firma dell'applicazione:** quando uno sviluppatore è pronto a distribuire la propria applicazione, **firma l'applicazione utilizzando una chiave privata**. Questa chiave privata è associata a un **certificato che Apple rilascia allo sviluppatore** quando si iscrive all'Apple Developer Program. Il processo di firma consiste nella creazione di un hash crittografico di tutte le parti dell'app e nella crittografia di questo hash con la chiave privata dello sviluppatore.
2. **Distribuzione dell'applicazione:** l'applicazione firmata viene quindi distribuita agli utenti insieme al certificato dello sviluppatore, che contiene la chiave pubblica corrispondente.
3. **Verifica dell'applicazione:** quando un utente scarica e tenta di eseguire l'applicazione, il sistema operativo del Mac utilizza la chiave pubblica contenuta nel certificato dello sviluppatore per decrittografare l'hash. Ricalcola quindi l'hash in base allo stato attuale dell'applicazione e lo confronta con l'hash decrittografato. Se corrispondono, significa che **l'applicazione non è stata modificata** da quando lo sviluppatore l'ha firmata e il sistema ne consente l'esecuzione.

Le firme delle applicazioni sono una parte essenziale della tecnologia Gatekeeper di Apple. Quando un utente tenta di **aprire un'applicazione scaricata da Internet**, Gatekeeper verifica la firma dell'applicazione. Se è firmata con un certificato rilasciato da Apple a uno sviluppatore noto e il codice non è stato manomesso, Gatekeeper consente l'esecuzione dell'applicazione. In caso contrario, blocca l'applicazione e avvisa l'utente.

A partire da macOS Catalina, **Gatekeeper verifica anche se l'applicazione è stata notarizzata** da Apple, aggiungendo un ulteriore livello di sicurezza. Il processo di notarizzazione verifica la presenza di problemi di sicurezza noti e codice dannoso nell'applicazione e, se questi controlli vengono superati, Apple aggiunge un ticket all'applicazione che Gatekeeper può verificare.

#### Controllo delle firme

Quando controlli un **malware sample**, dovresti sempre **controllare la firma** del binario, poiché lo **sviluppatore** che l'ha firmato potrebbe essere già **correlato** a un **malware**.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarizzazione

Il processo di notarizzazione di Apple funge da ulteriore protezione per salvaguardare gli utenti da software potenzialmente dannoso. Prevede che lo **sviluppatore invii la propria applicazione per l'esame** da parte dell'**Apple's Notary Service**, che non deve essere confuso con l'App Review. Questo servizio è un **sistema automatizzato** che analizza il software inviato per verificare la presenza di **contenuti dannosi** e di eventuali problemi relativi alla firma del codice.

Se il software **supera** questa verifica senza rilevare problemi, il Notary Service genera un ticket di notarizzazione. Lo sviluppatore deve quindi **allegare questo ticket al software**, tramite un processo chiamato "stapling". Inoltre, il ticket di notarizzazione viene pubblicato online, dove Gatekeeper, la tecnologia di sicurezza di Apple, può accedervi.

Durante la prima installazione o esecuzione del software da parte dell'utente, l'esistenza del ticket di notarizzazione, sia esso allegato all'eseguibile o trovato online, **informa Gatekeeper che il software è stato sottoposto a notarizzazione da parte di Apple**. Di conseguenza, Gatekeeper visualizza un messaggio descrittivo nella finestra di dialogo del primo avvio, indicando che Apple ha verificato la presenza di contenuti dannosi nel software. Questo processo aumenta quindi la fiducia degli utenti nella sicurezza del software che installano o eseguono sui propri sistemi.

### spctl & syspolicyd

> [!CAUTION]
> Nota che a partire dalla versione Sequoia, **`spctl`** non consente più di modificare la configurazione di Gatekeeper.

**`spctl`** è lo strumento CLI per enumerare e interagire con Gatekeeper (tramite il daemon `syspolicyd` mediante messaggi XPC). Ad esempio, è possibile visualizzare lo **stato** di GateKeeper con:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Nota che i controlli della signature di GateKeeper vengono eseguiti solo sui **file con l'attributo Quarantine**, non su ogni file.

GateKeeper verificherà se, in base alle **preferenze e alla signature**, un binary può essere eseguito:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** è il daemon principale responsabile dell'applicazione di Gatekeeper. Mantiene un database situato in `/var/db/SystemPolicy` ed è possibile trovare il codice che supporta il [database qui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) e il [template SQL qui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Nota che il database non è soggetto alle restrizioni di SIP ed è scrivibile da root, mentre il database `/var/db/.SystemPolicy-default` viene utilizzato come backup originale nel caso in cui l'altro venga corrotto.

Inoltre, i bundle **`/var/db/gke.bundle`** e **`/var/db/gkopaque.bundle`** contengono file con regole che vengono inserite nel database. Puoi controllare questo database come root con:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** espone inoltre un server XPC con diverse operazioni come `assess`, `update`, `record` e `cancel`, raggiungibili anche tramite le API **`SecAssessment*`** di **`Security.framework`**; inoltre, **`spctl`** comunica effettivamente con **`syspolicyd`** tramite XPC.

Si noti come la prima regola termini con "**App Store**" e la seconda con "**Developer ID**", e che nell'immagine precedente fosse **abilitata l'esecuzione delle app provenienti dall'App Store e degli sviluppatori identificati**.\
Se **modificate** tale impostazione in App Store, le regole "**Notarized Developer ID" scompariranno**.

Esistono inoltre migliaia di regole di **tipo GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Questi sono gli hash provenienti da:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

In alternativa, puoi elencare le informazioni precedenti con:
```bash
sudo spctl --list
```
Le opzioni **`--master-disable`** e **`--global-disable`** di **`spctl`** **disabiliteranno completamente** questi controlli delle firme:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Quando completamente abilitata, apparirà una nuova opzione:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

È possibile **verificare se un'app sarà autorizzata da GateKeeper** con:
```bash
spctl --assess -v /Applications/App.app
```
È possibile aggiungere nuove regole in GateKeeper per consentire l'esecuzione di determinate app con:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
Per quanto riguarda le **estensioni del kernel**, la cartella `/var/db/SystemPolicyConfiguration` contiene file con gli elenchi dei kext autorizzati a essere caricati. Inoltre, `spctl` dispone dell'entitlement `com.apple.private.iokit.nvram-csr` perché è in grado di aggiungere nuove estensioni del kernel pre-approvate, che devono essere salvate anche nella NVRAM in una chiave `kext-allowed-teams`.

#### Gestire Gatekeeper su macOS 15 (Sequoia) e versioni successive

- Il bypass di lunga data del Finder **Ctrl+Apertura / clic destro → Apri** è stato rimosso; dopo la prima finestra di blocco, gli utenti devono consentire esplicitamente l'app bloccata da **Impostazioni di Sistema → Privacy e sicurezza → Apri comunque**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` non sono più accettati; `spctl` è effettivamente di sola lettura per la valutazione e la gestione delle etichette, mentre l'applicazione dei criteri viene configurata tramite l'interfaccia utente o MDM.

A partire da macOS 15 Sequoia, gli utenti finali non possono più modificare i criteri di Gatekeeper da `spctl`. La gestione viene eseguita tramite Impostazioni di Sistema oppure distribuendo un profilo di configurazione MDM con il payload `com.apple.systempolicy.control`. Esempio di sezione di profilo per consentire App Store e sviluppatori identificati, ma non "Ovunque":

<details>
<summary>Profilo MDM per consentire App Store e sviluppatori identificati</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### File in quarantena

Quando **scaricano** un'applicazione o un file, alcune **applicazioni** macOS specifiche, come i browser web o i client di posta elettronica, **associano un attributo esteso del file**, comunemente noto come "**quarantine flag**", al file scaricato. Questo attributo funge da misura di sicurezza per **contrassegnare il file** come proveniente da una fonte non attendibile (Internet) e potenzialmente rischiosa. Tuttavia, non tutte le applicazioni associano questo attributo; ad esempio, i comuni client software BitTorrent solitamente ignorano questo processo.

**La presenza di un quarantine flag segnala la funzionalità di sicurezza Gatekeeper di macOS quando un utente tenta di eseguire il file**.

Nel caso in cui il **quarantine flag non sia presente** (come nel caso dei file scaricati tramite alcuni client BitTorrent), i **controlli di Gatekeeper potrebbero non essere eseguiti**. Pertanto, gli utenti dovrebbero prestare attenzione quando aprono file scaricati da fonti meno sicure o sconosciute.

> [!NOTE] > **Verificare** la **validità** delle firme del codice è un processo **dispendioso in termini di risorse**, che include la generazione di **hash** crittografici del codice e di tutte le risorse incluse. Inoltre, la verifica della validità del certificato comporta un **controllo online** sui server Apple per verificare se il certificato sia stato revocato dopo il rilascio. Per questi motivi, eseguire un controllo completo della firma del codice e della notarizzazione **ogni volta che un'app viene avviata non è pratico**.
>
> Pertanto, questi controlli vengono eseguiti **solo quando si eseguono app con l'attributo quarantine**.

> [!WARNING]
> Questo attributo deve essere **impostato dall'applicazione che crea/scarica** il file.
>
> Tuttavia, i file sottoposti a sandbox avranno questo attributo impostato su ogni file che creano. Inoltre, le app non sottoposte a sandbox possono impostarlo autonomamente oppure specificare la chiave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) nell'**Info.plist**, facendo sì che il sistema imposti l'attributo esteso `com.apple.quarantine` sui file creati,

Inoltre, tutti i file creati da un processo che chiama **`qtn_proc_apply_to_self`** vengono messi in quarantena. In alternativa, l'API **`qtn_file_apply_to_path`** aggiunge l'attributo quarantine a un percorso di file specificato.

È possibile **verificarne lo stato e abilitarlo/disabilitarlo** (sono necessari i privilegi root) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Puoi anche **verificare se un file dispone dell'attributo esteso di quarantena** con:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Controlla il **valore** degli **attributi** **extended** e scopri l'app che ha scritto l'attributo quarantine con:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
In realtà, un processo "potrebbe impostare i quarantine flags sui file che crea" (ho già provato ad applicare il flag USER_APPROVED a un file creato, ma non viene applicato):

<details>

<summary>Codice sorgente per applicare i quarantine flags</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

E **rimuovi** quell'attributo con:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
E trova tutti i file in quarantena con:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Le informazioni di Quarantine sono archiviate anche in un database centrale gestito da LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, che consente alla GUI di ottenere dati sull'origine dei file. Inoltre, questo database può essere sovrascritto dalle applicazioni interessate a nascondere la propria origine. Ciò può essere fatto anche tramite le API di LaunchServices.

#### **libquarantine.dylib**

Questa libreria esporta diverse funzioni che consentono di manipolare i campi degli extended attribute.

Le API `qtn_file_*` gestiscono le policy di Quarantine dei file, mentre le API `qtn_proc_*` vengono applicate ai processi (file creati dal processo). Le funzioni non esportate `__qtn_syscall_quarantine*` sono quelle che applicano le policy chiamando `mac_syscall` con `"Quarantine"` come primo argomento, inviando così le richieste a `Quarantine.kext`.

#### **Quarantine.kext**

La kernel extension è disponibile solo tramite la **kernel cache del sistema**; tuttavia, è possibile _scaricare il **Kernel Debug Kit da** [**https://developer.apple.com/**](https://developer.apple.com/), che conterrà una versione symbolicated dell'estensione.

Questa Kext utilizza MACF per intercettare diverse chiamate e tracciare tutti gli eventi del ciclo di vita dei file: creazione, apertura, ridenominazione, hard-linking... persino `setxattr`, per impedirgli di impostare l'extended attribute `com.apple.quarantine`.

Utilizza inoltre un paio di MIB:

- `security.mac.qtn.sandbox_enforce`: applica Quarantine insieme a Sandbox
- `security.mac.qtn.user_approved_exec`: i processi in Quarantine possono eseguire solo file approvati

#### Provenance xattr (Ventura e versioni successive)

macOS 13 Ventura ha introdotto un meccanismo di provenance separato, che viene popolato la prima volta che un'app in Quarantine può essere eseguita.<sup>[[2]](#references)</sup> Vengono creati due artefatti:

- L'xattr `com.apple.provenance` nella directory del bundle `.app` (un valore binario di dimensione fissa contenente una chiave primaria e dei flag).
- Una riga nella tabella `provenance_tracking` all'interno del database ExecPolicy in `/var/db/SystemPolicyConfiguration/ExecPolicy/`, che memorizza il cdhash e i metadati dell'app.

Utilizzo pratico:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect è una funzionalità **anti-malware** integrata in macOS. XProtect **controlla ogni applicazione al primo avvio o dopo una modifica, confrontandola con il proprio database** di malware noti e tipi di file non sicuri. Quando scarichi un file tramite determinate app, come Safari, Mail o Messaggi, XProtect esegue automaticamente la scansione del file. Se corrisponde a un malware noto presente nel database, XProtect **impedirà l'esecuzione del file** e ti avviserà della minaccia.

Il database di XProtect viene **aggiornato regolarmente** da Apple con nuove definizioni di malware, e questi aggiornamenti vengono scaricati e installati automaticamente sul Mac. In questo modo XProtect è sempre aggiornato sulle minacce note più recenti.

Tuttavia, è importante notare che **XProtect non è una soluzione antivirus completa**. Controlla solo un elenco specifico di minacce note e non esegue scansioni on-access come la maggior parte dei software antivirus.

Puoi ottenere informazioni sull'ultimo aggiornamento di XProtect eseguendo:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect si trova nella posizione protetta da SIP **/Library/Apple/System/Library/CoreServices/XProtect.bundle** e all'interno del bundle è possibile trovare le informazioni utilizzate da XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Consente al codice con quei cdhash di utilizzare i legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Elenco di plugin ed estensioni il cui caricamento è vietato tramite BundleID e TeamID, oppure che indica una versione minima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regole Yara per rilevare malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Database SQLite3 contenente gli hash delle applicazioni bloccate e dei TeamID.

Si noti che esiste un'altra App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** correlata a XProtect, ma che non è coinvolta nel processo di Gatekeeper.

> XProtect Remediator: Nelle versioni moderne di macOS, Apple distribuisce scanner on-demand (XProtect Remediator) che vengono eseguiti periodicamente tramite launchd per rilevare e rimediare a famiglie di malware. È possibile osservare queste scansioni nei unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Non Gatekeeper

> [!CAUTION]
> Si noti che Gatekeeper **non viene eseguito ogni volta** che si esegue un'applicazione; semplicemente _**AppleMobileFileIntegrity**_ verificherà le **firme del codice eseguibile** quando si esegue un'app già eseguita e verificata da Gatekeeper.

In precedenza, quindi, era possibile eseguire un'app per memorizzarla nella cache di Gatekeeper, quindi **modificare i file non eseguibili dell'applicazione** (come i file asar o NIB di Electron) e, se non erano presenti altre protezioni, l'applicazione veniva **eseguita** con le aggiunte **malevole**.

Tuttavia, ora ciò non è più possibile perché macOS **impedisce di modificare i file** all'interno dei bundle delle applicazioni. Quindi, se si tenta l'attacco [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), si scopre che non è più possibile abusarne perché, dopo aver eseguito l'app per memorizzarla nella cache di Gatekeeper, non sarà possibile modificare il bundle. Inoltre, se si modifica, ad esempio, il nome della directory Contents in NotCon (come indicato nell'exploit) e poi si esegue il binario principale dell'app per memorizzarlo nella cache di Gatekeeper, verrà generato un errore e l'app non verrà eseguita.

## Bypass di Gatekeeper

Qualsiasi modo per bypassare Gatekeeper (riuscire a fare in modo che l'utente scarichi ed esegua qualcosa quando Gatekeeper dovrebbe impedirlo) è considerato una vulnerabilità in macOS. Questi sono alcuni CVE assegnati a tecniche che in passato hanno consentito di bypassare Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

È stato osservato che, se **Archive Utility** viene utilizzato per l'estrazione, i file con **percorsi superiori a 886 caratteri** non ricevono l'attributo esteso com.apple.quarantine. Questa situazione consente inavvertitamente a tali file di **eludere i** controlli di sicurezza di **Gatekeeper**.<sup>[[5]](#references)</sup>

Consultare il [**report originale**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) per ulteriori informazioni.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando un'applicazione viene creata con **Automator**, le informazioni su ciò che deve eseguire si trovano in `application.app/Contents/document.wflow`, non nell'eseguibile. L'eseguibile è semplicemente un binario Automator generico chiamato **Automator Application Stub**.

Pertanto, si poteva fare in modo che `application.app/Contents/MacOS/Automator\ Application\ Stub` **puntasse tramite un symbolic link a un altro Automator Application Stub presente nel sistema**; in questo modo avrebbe eseguito ciò che si trova in `document.wflow` (lo script) **senza attivare Gatekeeper**, perché l'eseguibile effettivo non disponeva dell'xattr quarantine.<sup>[[6]](#references)</sup>

Esempio di percorso previsto: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consultare il [**report originale**](https://ronmasas.com/posts/bypass-macos-gatekeeper) per ulteriori informazioni.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In questo bypass, veniva creato un file zip iniziando a comprimere l'applicazione da `application.app/Contents` invece che da `application.app`. Pertanto, l'attributo **quarantine** veniva applicato a tutti i **file di `application.app/Contents`**, ma **non a `application.app`**, che era l'elemento controllato da Gatekeeper. Gatekeeper veniva quindi bypassato perché, quando `application.app` veniva attivata, **non disponeva dell'attributo quarantine.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Consulta il [**report originale**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) per ulteriori informazioni.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Anche se i componenti sono diversi, lo sfruttamento di questa vulnerabilità è molto simile a quello precedente. In questo caso genereremo un Apple Archive da **`application.app/Contents`**, in modo che **`application.app` non riceva l'attributo quarantine** quando viene decompresso da **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulta il [**report originale**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) per ulteriori informazioni.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

L'ACL **`writeextattr`** può essere utilizzata per impedire a chiunque di scrivere un attributo in un file:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Inoltre, il formato di file **AppleDouble** copia un file includendo i relativi ACE.<sup>[[9]](#references)</sup>

Nel [**codice sorgente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale dell'ACL memorizzata nell'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompresso. Quindi, se si comprime un'applicazione in un file zip con il formato **AppleDouble** e con un ACL che impedisce la scrittura di altri xattr... l'xattr di quarantena non veniva impostato sull'applicazione:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulta il [**report originale**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) per ulteriori informazioni.

Nota che questo potrebbe essere sfruttato anche con AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

È stato scoperto che **Google Chrome non impostava l'attributo di quarantena** sui file scaricati a causa di alcuni problemi interni di macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

I formati di file AppleDouble memorizzano gli attributi di un file in un file separato che inizia con `._`; questo aiuta a copiare gli attributi dei file **tra macOS machines**. Tuttavia, è stato notato che, dopo la decompressione di un file AppleDouble, al file che iniziava con `._` **non veniva assegnato l'attributo di quarantena**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Poter creare un file che non avesse impostato l'attributo di quarantena **rendeva possibile bypassare Gatekeeper.** Il trucco consisteva nel **creare un'applicazione in un file DMG** usando la convenzione per i nomi AppleDouble (iniziando con `._`) e nel creare un **file visibile come symlink a questo file nascosto** senza l'attributo di quarantena.\
Quando il **file DMG viene eseguito**, poiché non ha un attributo di quarantena, **bypassa Gatekeeper**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

Un Gatekeeper bypass corretto in macOS Sonoma 14.0 consentiva l'esecuzione di app appositamente create senza mostrare alcuna richiesta. I dettagli sono stati divulgati pubblicamente dopo il rilascio della patch e il problema era stato sfruttato attivamente in the wild prima della correzione. Assicurarsi che sia installato Sonoma 14.0 o versioni successive.

### [CVE-2024-27853]

Un Gatekeeper bypass in macOS 14.4 (rilasciato a marzo 2024), derivante dalla gestione di ZIP malevoli da parte di `libarchive`, consentiva alle app di eludere la valutazione. Aggiornare alla versione 14.4 o successive, nella quale Apple ha corretto il problema.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un workflow **Automator Quick Action** incorporato in un'app scaricata poteva essere attivato senza la valutazione di Gatekeeper, perché i workflow venivano trattati come dati ed eseguiti dall'helper di Automator al di fuori del normale percorso della richiesta di notarizzazione. Un `.app` appositamente creato che includesse una Quick Action in grado di eseguire uno shell script (ad esempio, all'interno di `Contents/PlugIns/*.workflow/Contents/document.wflow`) poteva quindi eseguirsi immediatamente all'avvio. Apple ha aggiunto un'ulteriore finestra di consenso e corretto il percorso di valutazione in Ventura **13.7**, Sonoma **14.7** e Sequoia **15**.<sup>[[3]](#references)</sup>

### Unarchiver di terze parti che propagano erroneamente la quarantena (2023–2024)

Diverse vulnerabilità presenti in strumenti di estrazione diffusi (ad esempio The Unarchiver) facevano sì che i file estratti dagli archivi non ricevessero l'xattr `com.apple.quarantine`, creando opportunità per un Gatekeeper bypass. Durante i test, affidarsi sempre a macOS Archive Utility o a strumenti aggiornati e verificare gli xattr dopo l'estrazione.

### uchg (da questo [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Creare una directory contenente un'app.
- Aggiungere uchg all'app.
- Comprimere l'app in un file tar.gz.
- Inviare il file tar.gz a una vittima.
- La vittima apre il file tar.gz ed esegue l'app.
- Gatekeeper non controlla l'app.<sup>[[12]](#references)</sup>

### Prevenire l'xattr di quarantena

Se in un bundle ".app" l'xattr di quarantena non viene aggiunto, quando viene eseguito **Gatekeeper non verrà attivato**.


## Riferimenti

- [1] [Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: How macOS now tracks the provenance of apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: The Discovery of CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifies Safari vulnerability allowing for Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifies macOS Archive Utility vulnerability allowing for Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper's Achilles heel: Unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Discovery of a Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Finding and reporting a Gatekeeper bypass exploit with help from Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
