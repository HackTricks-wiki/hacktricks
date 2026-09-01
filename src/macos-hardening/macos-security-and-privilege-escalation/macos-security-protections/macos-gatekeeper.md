# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** è una funzionalità di sicurezza sviluppata per i sistemi operativi Mac, progettata per garantire che gli utenti **eseguano solo software affidabile** sui propri sistemi. Funziona **convalidando il software** che un utente scarica e tenta di aprire da **fonti esterne all'App Store**, come un'app, un plug-in o un pacchetto di installazione.

Il meccanismo principale di Gatekeeper consiste nel processo di **verifica**. Controlla se il software è **firmato da uno sviluppatore riconosciuto**, garantendone l'autenticità. Inoltre, verifica che il software **sia stato sottoposto a notarizzazione da Apple**, confermando che sia privo di contenuti dannosi noti e che non sia stato manomesso dopo la notarizzazione.

In aggiunta, Gatekeeper rafforza il controllo e la sicurezza dell'utente **chiedendo di approvare l'apertura** del software scaricato al primo avvio. Questa protezione aiuta a impedire che gli utenti eseguano inavvertitamente codice eseguibile potenzialmente dannoso, scambiandolo per un file di dati innocuo.

### Firme delle applicazioni

Le firme delle applicazioni, note anche come firme del codice, sono una componente essenziale dell'infrastruttura di sicurezza di Apple. Vengono utilizzate per **verificare l'identità dell'autore del software** (lo sviluppatore) e per garantire che il codice non sia stato manomesso dall'ultima volta che è stato firmato.

Ecco come funziona:

1. **Firma dell'applicazione:** quando uno sviluppatore è pronto a distribuire la propria applicazione, **firma l'applicazione utilizzando una chiave privata**. Questa chiave privata è associata a un **certificato che Apple rilascia allo sviluppatore** quando si iscrive all'Apple Developer Program. Il processo di firma consiste nella creazione di un hash crittografico di tutte le parti dell'app e nella cifratura di questo hash con la chiave privata dello sviluppatore.
2. **Distribuzione dell'applicazione:** l'applicazione firmata viene quindi distribuita agli utenti insieme al certificato dello sviluppatore, che contiene la chiave pubblica corrispondente.
3. **Verifica dell'applicazione:** quando un utente scarica e tenta di eseguire l'applicazione, il sistema operativo Mac utilizza la chiave pubblica contenuta nel certificato dello sviluppatore per decifrare l'hash. Ricalcola quindi l'hash in base allo stato attuale dell'applicazione e lo confronta con l'hash decifrato. Se corrispondono, significa che **l'applicazione non è stata modificata** da quando lo sviluppatore l'ha firmata e il sistema ne consente l'esecuzione.

Le firme delle applicazioni sono una parte essenziale della tecnologia Gatekeeper di Apple. Quando un utente tenta di **aprire un'applicazione scaricata da Internet**, Gatekeeper verifica la firma dell'applicazione. Se è firmata con un certificato rilasciato da Apple a uno sviluppatore noto e il codice non è stato manomesso, Gatekeeper consente l'esecuzione dell'applicazione. In caso contrario, blocca l'applicazione e avvisa l'utente.

A partire da macOS Catalina, **Gatekeeper verifica anche se l'applicazione è stata sottoposta a notarizzazione** da Apple, aggiungendo un ulteriore livello di sicurezza. Il processo di notarizzazione controlla l'applicazione alla ricerca di problemi di sicurezza noti e codice dannoso e, se questi controlli vengono superati, Apple aggiunge all'applicazione un ticket che Gatekeeper può verificare.

#### Controllare le firme

Quando si analizza un **malware sample**, è sempre necessario **controllare la firma** del binario, poiché lo **sviluppatore** che lo ha firmato potrebbe essere già **associato** a **malware.**
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

Il processo di notarizzazione di Apple funge da ulteriore misura di sicurezza per proteggere gli utenti da software potenzialmente dannoso. Prevede che lo **sviluppatore invii la propria applicazione per l'esame** da parte dell'**Apple's Notary Service**, che non deve essere confuso con App Review. Questo servizio è un **sistema automatizzato** che analizza il software inviato per verificare la presenza di **contenuti dannosi** e di eventuali problemi con la code-signing.

Se il software **supera** questa ispezione senza sollevare dubbi, il Notary Service genera un ticket di notarizzazione. Lo sviluppatore deve quindi **associare questo ticket al proprio software**, un processo noto come 'stapling.' Inoltre, il ticket di notarizzazione viene pubblicato online, dove Gatekeeper, la tecnologia di sicurezza di Apple, può accedervi.

Alla prima installazione o esecuzione del software da parte dell'utente, l'esistenza del ticket di notarizzazione - associato all'eseguibile tramite stapling o individuato online - **informa Gatekeeper che il software è stato sottoposto a notarizzazione da parte di Apple**. Di conseguenza, Gatekeeper mostra un messaggio descrittivo nella finestra di dialogo del primo avvio, indicando che il software è stato sottoposto da Apple a controlli per individuare contenuti dannosi. Questo processo aumenta quindi la fiducia degli utenti nella sicurezza del software che installano o eseguono sui propri sistemi.

### spctl & syspolicyd

> [!CAUTION]
> Nota che, a partire dalla versione Sequoia, **`spctl`** non consente più di modificare la configurazione di Gatekeeper.

**`spctl`** è lo strumento CLI per elencare e interagire con Gatekeeper (con il demone `syspolicyd` tramite messaggi XPC). Ad esempio, è possibile visualizzare lo **stato** di GateKeeper con:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Nota che i controlli della firma di GateKeeper vengono eseguiti solo sui **file con l'attributo Quarantine**, non su ogni file.

GateKeeper verificherà se, in base alle **preferenze e alla firma**, un binary può essere eseguito:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** è il daemon principale responsabile dell'applicazione di Gatekeeper. Mantiene un database situato in `/var/db/SystemPolicy` ed è possibile trovare il codice che supporta il [database qui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) e il [template SQL qui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Nota che il database non è limitato da SIP ed è scrivibile da root; il database `/var/db/.SystemPolicy-default` viene utilizzato come backup originale nel caso in cui l'altro venga danneggiato.

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
**`syspolicyd`** espone anche un server XPC con diverse operazioni come `assess`, `update`, `record` e `cancel`, anch'esse accessibili utilizzando le API **`Security.framework`'s `SecAssessment*`** e **`spctl`** comunica effettivamente con **`syspolicyd`** tramite XPC.

Si noti come la prima regola terminasse con "**App Store**" e la seconda con "**Developer ID**", e che nella precedente immagine fosse **abilitata l'esecuzione di app dall'App Store e di sviluppatori identificati**.\
Se **modifichi** questa impostazione in App Store, le regole "**Notarized Developer ID" scompariranno**.

Esistono anche migliaia di regole di **tipo GKE** :
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
Quando è completamente abilitata, apparirà una nuova opzione:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

È possibile **verificare se un'app sarà consentita da GateKeeper** con:
```bash
spctl --assess -v /Applications/App.app
```
Su macOS 14 e versioni successive, **`syspolicy_check`** è un utile controllo di livello superiore da eseguire prima della distribuzione di un application bundle. Produce diagnosi sull'esecuzione attendibile più utili rispetto a un semplice risultato di `spctl`, anche se Apple raccomanda comunque di testare il percorso reale di download/estrazione/primo avvio, perché questo verifica anche la propagazione della quarantena.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
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
Per quanto riguarda le **kernel extensions**, la cartella `/var/db/SystemPolicyConfiguration` contiene file con elenchi di kext autorizzate al caricamento. Inoltre, `spctl` dispone dell’entitlement `com.apple.private.iokit.nvram-csr` perché è in grado di aggiungere nuove kernel extensions pre-autorizzate, che devono essere salvate anche nella NVRAM in una chiave `kext-allowed-teams`.

#### Gestione di Gatekeeper su macOS 15 (Sequoia) e versioni successive

- Il bypass di lunga data del Finder **Ctrl+Open / clic destro → Open** è stato rimosso; dopo la prima finestra di blocco, gli utenti devono autorizzare esplicitamente un’app bloccata da **Impostazioni di Sistema → Privacy e sicurezza → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` non sono più accettati come modifiche alle policy non interattive. Le operazioni che modificano il database delle regole o lo stato globale di assessment sono deprecate; usa quindi `spctl` per l’assessment e configura l’enforcement tramite l’interfaccia utente o MDM.

A partire da macOS 15 Sequoia, gli utenti finali non possono più modificare la policy di Gatekeeper da `spctl`. La gestione viene eseguita tramite Impostazioni di Sistema oppure distribuendo un configuration profile MDM con il payload `com.apple.systempolicy.control`. Esempio di snippet del profilo per consentire App Store e sviluppatori identificati, ma non “Anywhere”:

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

Quando si **scarica** un'applicazione o un file, specifiche **applicazioni** macOS, come i browser web o i client di posta elettronica, **associano un attributo esteso del file**, comunemente noto come "**quarantine flag**", al file scaricato. Questo attributo funge da misura di sicurezza per **contrassegnare il file** come proveniente da una fonte non attendibile (Internet) e potenzialmente rischiosa. Tuttavia, non tutte le applicazioni associano questo attributo; ad esempio, i comuni client software BitTorrent solitamente ignorano questo processo.

**La presenza di un quarantine flag segnala la funzionalità di sicurezza Gatekeeper di macOS quando un utente tenta di eseguire il file**.

Nel caso in cui il **quarantine flag non sia presente** (come nel caso dei file scaricati tramite alcuni client BitTorrent), i **controlli di Gatekeeper potrebbero non essere eseguiti**. Pertanto, gli utenti dovrebbero prestare attenzione quando aprono file scaricati da fonti meno sicure o sconosciute.

> [!NOTE] > **Verificare** la **validità** delle firme del codice è un processo che richiede molte risorse e include la generazione di **hash crittografici** del codice e di tutte le risorse incluse. Inoltre, la verifica della validità del certificato implica un **controllo online** sui server Apple per verificare se il certificato è stato revocato dopo il rilascio. Per questi motivi, eseguire un controllo completo della firma del codice e della notarizzazione **ogni volta che viene avviata un'app non è pratico**.
>
> Pertanto, questi controlli vengono eseguiti **solo quando si eseguono app con l'attributo quarantined**.

> [!WARNING]
> Questo attributo deve essere **impostato dall'applicazione che crea o scarica** il file.
>
> Tuttavia, i file creati in sandbox avranno questo attributo impostato per ogni file che creano. Le app non sandboxed possono impostarlo autonomamente oppure specificare la chiave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) nell'**Info.plist**, facendo sì che il sistema imposti l'attributo esteso `com.apple.quarantine` sui file creati,

Inoltre, tutti i file creati da un processo che chiama **`qtn_proc_apply_to_self`** vengono messi in quarantena. In alternativa, l'API **`qtn_file_apply_to_path`** aggiunge l'attributo di quarantena a un percorso file specificato.

È possibile **verificarne lo stato e abilitarlo/disabilitarlo** (root richiesto) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Puoi anche **verificare se un file ha l'attributo esteso di quarantena** con:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Controlla il **valore** degli **attributi** **estesi** e individua l'app che ha scritto l'attributo di quarantena con:
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
In realtà un processo "potrebbe impostare i quarantine flags sui file che crea" (ho già provato ad applicare il flag USER_APPROVED a un file creato, ma non viene applicato):

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
Le informazioni sulla Quarantine sono memorizzate anche in un database centrale gestito da LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, che consente alla GUI di ottenere dati sull’origine del file. Inoltre, questo può essere sovrascritto dalle applicazioni interessate a nasconderne l’origine. Ciò può essere fatto anche tramite le API di LaunchServices.

#### **libquarantine.dylib**

Questa libreria esporta diverse funzioni che consentono di manipolare i campi degli attributi estesi.

Le API `qtn_file_*` gestiscono le policy di Quarantine dei file, mentre le API `qtn_proc_*` vengono applicate ai processi (file creati dal processo). Le funzioni non esportate `__qtn_syscall_quarantine*` sono quelle che applicano le policy e chiamano `mac_syscall` con "Quarantine" come primo argomento, inviando le richieste a `Quarantine.kext`.

#### **Quarantine.kext**

L’estensione del kernel è disponibile solo tramite la **kernel cache del sistema**; tuttavia, è possibile _scaricare il **Kernel Debug Kit da** [**https://developer.apple.com/**](https://developer.apple.com/), che conterrà una versione dell’estensione con i simboli risolti.

Questo Kext utilizza MACF per intercettare diverse chiamate, in modo da rilevare tutti gli eventi del ciclo di vita dei file: creazione, apertura, rinomina, hard-linking... persino `setxattr`, per impedire che imposti l’attributo esteso `com.apple.quarantine`.

Utilizza inoltre un paio di MIB:

- `security.mac.qtn.sandbox_enforce`: applica la Quarantine insieme a Sandbox
- `security.mac.qtn.user_approved_exec`: i processi in Quarantine possono eseguire solo file approvati

#### Provenance xattr (Ventura e versioni successive)

macOS 13 Ventura ha introdotto un meccanismo di provenance separato, popolato la prima volta che un’app in Quarantine può essere eseguita.<sup>[[2]](#references)</sup> Vengono creati due artefatti:

- L’attributo xattr `com.apple.provenance` sulla directory del bundle `.app` (un valore binario di dimensione fissa contenente una primary key e dei flag).
- Una riga nella tabella `provenance_tracking` all’interno del database ExecPolicy in `/var/db/SystemPolicyConfiguration/ExecPolicy/`, che memorizza il cdhash e i metadati dell’app.

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

XProtect è una funzionalità **anti-malware** integrata in macOS. XProtect **verifica ogni applicazione al primo avvio o dopo una modifica, confrontandola con il proprio database** di malware conosciuti e tipi di file non sicuri. Quando scarichi un file tramite determinate app, come Safari, Mail o Messaggi, XProtect esegue automaticamente una scansione del file. Se corrisponde a un malware conosciuto presente nel database, XProtect **impedisce l'esecuzione del file** e ti avvisa della minaccia.

Il database di XProtect viene **aggiornato regolarmente** da Apple con nuove definizioni di malware, e questi aggiornamenti vengono scaricati e installati automaticamente sul Mac. In questo modo, XProtect è sempre aggiornato sulle minacce conosciute più recenti.

Tuttavia, è importante notare che **XProtect non è una soluzione antivirus completa**. Verifica solo un elenco specifico di minacce conosciute e non esegue scansioni on-access come la maggior parte dei software antivirus.

Puoi ottenere informazioni sull'ultimo aggiornamento di XProtect eseguendo:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect si trova nella posizione protetta da SIP **/Library/Apple/System/Library/CoreServices/XProtect.bundle** e all'interno del bundle è possibile trovare le informazioni utilizzate da XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Consente al codice con quei cdhash di utilizzare i legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Elenco di plugin ed estensioni il cui caricamento è vietato tramite BundleID e TeamID oppure per i quali viene indicata una versione minima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regole Yara per rilevare malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Database SQLite3 contenente gli hash delle applicazioni bloccate e i TeamID.

Nota che esiste un'altra App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** correlata a XProtect, che non è coinvolta nel processo di Gatekeeper.

> XProtect Remediator: nelle versioni moderne di macOS, Apple distribuisce scanner on-demand (XProtect Remediator) che vengono eseguiti periodicamente tramite launchd per rilevare e rimediare alle famiglie di malware. È possibile osservare queste scansioni nei unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Non Gatekeeper

> [!CAUTION]
> Nota che Gatekeeper **non viene eseguito ogni volta** che esegui un'applicazione: solo _**AppleMobileFileIntegrity**_ **verificherà le firme del codice eseguibile** quando esegui un'app già eseguita e verificata da Gatekeeper.

In precedenza, quindi, era possibile eseguire un'app per metterla nella cache di Gatekeeper, quindi **modificare i file non eseguibili dell'applicazione** (come i file asar o NIB di Electron) e, se non erano presenti altre protezioni, l'applicazione veniva **eseguita** con le aggiunte **malicious**.

Tuttavia, ora ciò non è possibile perché macOS **impedisce di modificare i file** all'interno dei bundle delle applicazioni. Pertanto, se provi l'attacco [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), scoprirai che non è più possibile sfruttarlo perché, dopo aver eseguito l'app per metterla nella cache di Gatekeeper, non potrai modificare il bundle. Inoltre, se cambi, ad esempio, il nome della directory Contents in NotCon (come indicato nell'exploit) e poi esegui il binario principale dell'app per metterlo nella cache di Gatekeeper, verrà generato un errore e l'app non verrà eseguita.

## Gatekeeper Bypasses

Qualsiasi metodo per bypassare Gatekeeper (riuscire a fare in modo che l'utente scarichi ed esegua qualcosa quando Gatekeeper dovrebbe impedirlo) è considerato una vulnerabilità in macOS. Questi sono alcuni CVE assegnati a tecniche che in passato hanno permesso di bypassare Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

È stato osservato che, se per l'estrazione viene utilizzato **Archive Utility**, i file con **percorsi che superano 886 caratteri** non ricevono l'attributo esteso com.apple.quarantine. Questa situazione consente involontariamente a tali file di **eludere i controlli di sicurezza di Gatekeeper**.<sup>[[5]](#references)</sup>

Consulta il [**report originale**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) per ulteriori informazioni.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando un'applicazione viene creata con **Automator**, le informazioni su ciò che deve eseguire si trovano all'interno di `application.app/Contents/document.wflow`, non nell'eseguibile. L'eseguibile è semplicemente un binario Automator generico chiamato **Automator Application Stub**.

Pertanto, era possibile fare in modo che `application.app/Contents/MacOS/Automator\ Application\ Stub` **puntasse tramite un symbolic link a un altro Automator Application Stub presente nel sistema**, che avrebbe eseguito ciò che si trova in `document.wflow` (il tuo script) **senza attivare Gatekeeper**, perché l'eseguibile effettivo non disponeva dell'xattr quarantine.<sup>[[6]](#references)</sup>

Esempio di posizione prevista: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta il [**report originale**](https://ronmasas.com/posts/bypass-macos-gatekeeper) per ulteriori informazioni.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In questo bypass veniva creato un file zip iniziando a comprimere da `application.app/Contents` invece che da `application.app`. Pertanto, l'attributo **quarantine** veniva applicato a tutti i **file contenuti in `application.app/Contents`**, ma **non a `application.app`**, che era ciò che Gatekeeper controllava. Gatekeeper veniva quindi bypassato perché, quando `application.app` veniva attivato, **non disponeva dell'attributo quarantine.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Consulta il [**report originale**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) per ulteriori informazioni.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Anche se i componenti sono diversi, lo sfruttamento di questa vulnerabilità è molto simile al precedente. In questo caso genereremo un Apple Archive da **`application.app/Contents`**, quindi **`application.app` non riceverà l'attributo quarantine** quando verrà decompresso da **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulta il [**report originale**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) per maggiori informazioni.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

L'ACL **`writeextattr`** può essere utilizzata per impedire a chiunque di scrivere un attributo in un file:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Inoltre, il formato di file **AppleDouble** copia un file includendo i relativi ACE.<sup>[[9]](#references)</sup>

Nel [**codice sorgente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale dell'ACL memorizzata all'interno dell'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompresso. Quindi, se si comprimeva un'applicazione in un file zip con il formato **AppleDouble** e con un ACL che impedisce la scrittura di altri xattr al suo interno... l'xattr di quarantena non veniva impostato nell'applicazione:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obtener más información.<sup>[[9]](#references)</sup>

Ten en cuenta que esto también podría explotarse con AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

È stato scoperto che **Google Chrome non impostava l'attributo quarantine** sui file scaricati a causa di alcuni problemi interni di macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble memorizza gli attributi di un file in un file separato il cui nome inizia con `._`; ciò aiuta a copiare gli attributi dei file **tra macOS machines**. Tuttavia, dopo la decompressione di un file AppleDouble, al file che iniziava con `._` **non veniva assegnato l'attributo quarantine**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Potendo creare un file a cui non veniva impostato l'attributo di quarantena, era **possibile bypassare Gatekeeper.** Il trucco consisteva nel **creare un'applicazione in un file DMG** utilizzando la convenzione dei nomi AppleDouble (iniziando con `._`) e nel creare un **file visibile come symlink a questo** file nascosto privo dell'attributo di quarantena.\
Quando il **file DMG viene eseguito**, non avendo un attributo di quarantena, **bypassa Gatekeeper**.
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

Apple ha corretto un errore logico di LaunchServices in macOS Sonoma 14.0 tramite controlli migliorati. L'advisory pubblico dichiara solo che un'app poteva bypassare Gatekeeper, quindi non bisogna dedurre un formato specifico del carrier o una catena di exploitation dalla sola voce CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Un bypass di Gatekeeper in macOS 14.4 (rilasciato a marzo 2024), derivante dalla gestione di ZIP malevoli da parte di `libarchive`, consentiva alle app di eludere la valutazione. Aggiornare alla versione 14.4 o successive, in cui Apple ha risolto il problema.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **workflow Automator Quick Action** incorporato in un'app scaricata poteva essere attivato senza la valutazione di Gatekeeper, perché i workflow venivano trattati come dati ed eseguiti dall'helper Automator al di fuori del normale percorso del prompt di notarizzazione. Un `.app` appositamente creato che includeva una Quick Action per eseguire uno shell script (ad esempio, all'interno di `Contents/PlugIns/*.workflow/Contents/document.wflow`) poteva quindi essere eseguito immediatamente all'avvio. Apple ha aggiunto una finestra di consenso aggiuntiva e corretto il percorso di valutazione in Ventura **13.7**, Sonoma **14.7** e Sequoia **15**.<sup>[[3]](#references)</sup>

### Errori nella propagazione della quarantine durante l'estrazione e la copia

Uno studio del 2024 ha rilevato lacune nella propagazione nelle versioni testate di iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) e 7z Utility (DMG/ZIP/7Z); ha inoltre osservato che l'attributo veniva perso durante le copie host-to-guest di VMware Tools. Diversi vendor hanno successivamente annunciato delle correzioni, quindi considera questi nomi come spunti per un **nuovo test specifico per versione**, non come un elenco permanente di software vulnerabili. Lo stesso problema relativo al trust boundary si applica ai workflow Unix nativi: `curl`/`scp` non aggiungono la quarantine e `tar`/`unzip` da riga di comando non la ereditano automaticamente da un carrier archive.<sup>[[15]](#references)</sup>

Per i test offensivi, confronta il carrier e l'app finale dopo **ogni** passaggio tramite browser, mail client, archivio, disk image, cloud-sync, shared folder e copia su VM. Un rifiuto esplicito da parte di `spctl` non ripristina un xattr mancante: senza quarantine, il normale percorso di Gatekeeper alla prima apertura potrebbe non richiedere mai tale valutazione.<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Crea una directory contenente un'app.
- Aggiungi uchg all'app.
- Comprimi l'app in un file tar.gz.
- Invia il file tar.gz a una vittima.
- La vittima apre il file tar.gz ed esegue l'app.
- Gatekeeper non controlla l'app.<sup>[[12]](#references)</sup>

### Previeni il quarantine xattr

In un bundle ".app", se il quarantine xattr non viene aggiunto, quando viene eseguito **Gatekeeper non verrà attivato**.

Consulta [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) per le primitive basate su filesystem, flag, ACL e AppleDouble che possono impedire o eliminare gli extended attributes.



## References

- [1] [Apple Platform Security: Informazioni sul contenuto di sicurezza di macOS Sonoma 14.4 (include CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Come macOS tiene ora traccia della provenienza delle app](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Informazioni sul contenuto di sicurezza di macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia rimuove il bypass di Gatekeeper tramite “Apri” con clic tenendo premuto Control](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: La scoperta di CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypass di macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifica una vulnerabilità di Safari che consente il bypass di Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifica una vulnerabilità di macOS Archive Utility che consente il bypass di Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Il tallone d'Achille di Gatekeeper: alla scoperta di una vulnerabilità di macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Scoperta di un bypass di Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Individuazione e segnalazione di un exploit per il bypass di Gatekeeper con l'aiuto di Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypass dei meccanismi di sicurezza e privacy di macOS — Da Gatekeeper a System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Informazioni sul contenuto di sicurezza di macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Test di un prodotto notarizzato](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Bypass di Gatekeeper — Alla scoperta delle debolezze di un meccanismo di sicurezza di macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
