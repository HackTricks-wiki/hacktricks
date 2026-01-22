# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** è una funzionalità di sicurezza sviluppata per i sistemi operativi Mac, progettata per garantire che gli utenti **eseguano solo software attendibile** sui loro sistemi. Funziona **validando il software** che un utente scarica e tenta di aprire da **fonti esterne all'App Store**, come un'app, un plug-in o un pacchetto di installazione.

Il meccanismo chiave di Gatekeeper risiede nel suo processo di **verifica**. Controlla se il software scaricato è **firmato da uno sviluppatore riconosciuto**, assicurando l'autenticità del software. Inoltre, verifica se il software è **notarizzato da Apple**, confermando che è privo di contenuti maligni conosciuti e che non è stato manomesso dopo la notarizzazione.

In aggiunta, Gatekeeper rafforza il controllo e la sicurezza dell'utente **richiedendo all'utente di approvare l'apertura** del software scaricato la prima volta. Questa protezione aiuta a prevenire che gli utenti eseguano involontariamente codice eseguibile potenzialmente dannoso che potrebbero aver scambiato per un innocuo file di dati.

### Application Signatures

Le firme delle applicazioni, note anche come code signatures, sono una componente critica dell'infrastruttura di sicurezza di Apple. Vengono utilizzate per **verificare l'identità dell'autore del software** (lo sviluppatore) e per assicurare che il codice non sia stato manomesso da quando è stato firmato.

Ecco come funziona:

1. **Signing the Application:** Quando uno sviluppatore è pronto a distribuire la propria applicazione, **firma l'applicazione usando una chiave privata**. Questa chiave privata è associata a un **certificato che Apple rilascia allo sviluppatore** quando si iscrive all'Apple Developer Program. Il processo di firma comporta la creazione di un hash crittografico di tutte le parti dell'app e la cifratura di questo hash con la chiave privata dello sviluppatore.
2. **Distributing the Application:** L'applicazione firmata viene quindi distribuita agli utenti insieme al certificato dello sviluppatore, che contiene la corrispondente chiave pubblica.
3. **Verifying the Application:** Quando un utente scarica e tenta di eseguire l'applicazione, il sistema operativo del Mac utilizza la chiave pubblica del certificato dello sviluppatore per decifrare l'hash. Poi ricalcola l'hash in base allo stato attuale dell'applicazione e lo confronta con l'hash decifrato. Se coincidono, significa che **l'applicazione non è stata modificata** da quando lo sviluppatore l'ha firmata, e il sistema permette l'esecuzione dell'applicazione.

Le firme delle applicazioni sono una parte essenziale della tecnologia Gatekeeper di Apple. Quando un utente tenta di **aprire un'applicazione scaricata da Internet**, Gatekeeper verifica la firma dell'applicazione. Se è firmata con un certificato rilasciato da Apple a uno sviluppatore noto e il codice non è stato manomesso, Gatekeeper permette l'esecuzione dell'applicazione. Altrimenti, blocca l'applicazione e avvisa l'utente.

A partire da macOS Catalina, **Gatekeeper verifica anche se l'applicazione è stata notarizzata** da Apple, aggiungendo un ulteriore livello di sicurezza. Il processo di notarizzazione controlla l'applicazione alla ricerca di problemi di sicurezza noti e codice maligno, e se questi controlli vengono superati, Apple aggiunge un ticket all'applicazione che Gatekeeper può verificare.

#### Check Signatures

Quando si controlla un sample di malware dovresti sempre **verificare la firma** del binario poiché lo sviluppatore che l'ha firmato potrebbe essere già correlato al malware.
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

Il processo di notarizzazione di Apple funge da ulteriore protezione per tutelare gli utenti da software potenzialmente dannoso. Coinvolge lo **sviluppatore che invia la propria applicazione per l'esame** da parte del **Notary Service di Apple**, da non confondere con App Review. Questo servizio è un **sistema automatizzato** che analizza il software inviato alla ricerca di **contenuti malevoli** e di eventuali problemi con la code-signing.

Se il software **supera** questa ispezione senza sollevare problemi, il Notary Service genera un ticket di notarizzazione. Lo sviluppatore deve quindi **allegare questo ticket al loro software**, un processo noto come 'stapling'. Inoltre, il ticket di notarizzazione viene anche pubblicato online dove Gatekeeper, la tecnologia di sicurezza di Apple, può accedervi.

Al primo installazione o esecuzione del software da parte dell'utente, l'esistenza del ticket di notarizzazione — sia se allegato all'eseguibile sia se reperibile online — **informa Gatekeeper che il software è stato notarizzato da Apple**. Di conseguenza, Gatekeeper mostra un messaggio descrittivo nella finestra di avvio iniziale, indicando che il software è stato sottoposto a controlli per contenuti malevoli da parte di Apple. Questo processo aumenta quindi la fiducia dell'utente nella sicurezza del software che installa o esegue sui propri sistemi.

### spctl & syspolicyd

> [!CAUTION]
> Nota che dalla versione Sequoia, **`spctl`** non permette più di modificare la configurazione di Gatekeeper.

**`spctl`** è lo strumento da CLI per enumerare e interagire con Gatekeeper (con il daemon `syspolicyd` tramite messaggi XPC). Ad esempio, è possibile vedere lo **status** di GateKeeper con:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Nota che i controlli di firma di GateKeeper vengono eseguiti solo sui **file con l'attributo Quarantine**, non su tutti i file.

GateKeeper verificherà se, secondo le **preferenze & la firma**, un eseguibile può essere avviato:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** è il daemon principale responsabile dell'applicazione di GateKeeper. Mantiene un database situato in `/var/db/SystemPolicy` ed è possibile trovare il codice a supporto del [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) e il [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Nota che il database non è soggetto a restrizioni da SIP ed è scrivibile da root e il database `/var/db/.SystemPolicy-default` viene usato come backup originale nel caso in cui l'altro si corrompa.

Moreover, the bundles **`/var/db/gke.bundle`** and **`/var/db/gkopaque.bundle`** contains files with rules that are inserted in the database. You can check this database as root with:
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
**`syspolicyd`** espone anche un server XPC con diverse operazioni come `assess`, `update`, `record` e `cancel` che sono raggiungibili anche tramite le API **`Security.framework`'s `SecAssessment*`** e **`spctl`** in realtà comunica con **`syspolicyd`** via XPC.

Nota come la prima regola terminava in "**App Store**" e la seconda in "**Developer ID**" e che nell'immagine precedente era **abilitato a eseguire app dall'App Store e da sviluppatori identificati**.\
Se **modifichi** quell'impostazione su App Store, le regole **"Notarized Developer ID"** scompariranno.

Ci sono anche migliaia di regole di **type GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Questi sono gli hashes provenienti da:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Oppure puoi elencare le informazioni precedenti con:
```bash
sudo spctl --list
```
Le opzioni **`--master-disable`** e **`--global-disable`** di **`spctl`** **disabiliteranno** completamente questi controlli di firma:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Quando è completamente abilitata, comparirà una nuova opzione:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

È possibile **verificare se un'App sarà consentita da GateKeeper** con:
```bash
spctl --assess -v /Applications/App.app
```
È possibile aggiungere nuove regole in GateKeeper per consentire l'esecuzione di alcune app con:
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
Per quanto riguarda le **estensioni del kernel**, la cartella `/var/db/SystemPolicyConfiguration` contiene file con liste di kexts autorizzati a essere caricati. Inoltre, `spctl` possiede l'entitlement `com.apple.private.iokit.nvram-csr` perché è in grado di aggiungere nuove kernel extensions pre-approvate che devono essere salvate anche nella NVRAM in una chiave `kext-allowed-teams`.

#### Gestione di Gatekeeper su macOS 15 (Sequoia) e versioni successive

- Il bypass storico del Finder **Ctrl+Open / Right‑click → Open** è stato rimosso; gli utenti devono esplicitamente autorizzare un'app bloccata da **System Settings → Privacy & Security → Open Anyway** dopo la prima finestra di blocco.
- `spctl --master-disable/--global-disable` non sono più accettati; `spctl` è effettivamente di sola lettura per la valutazione e la gestione delle label, mentre l'applicazione delle policy viene configurata tramite UI o MDM.

A partire da macOS 15 Sequoia, gli utenti finali non possono più modificare la policy di Gatekeeper tramite `spctl`. La gestione avviene tramite System Settings o distribuendo un profilo di configurazione MDM con il payload `com.apple.systempolicy.control`. Esempio di snippet di profilo per consentire App Store e sviluppatori identificati (ma non "Anywhere"):

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

Al momento del **download** di un'applicazione o di un file, alcune **app** macOS come i browser web o i client di posta **aggiungono un attributo esteso al file**, comunemente noto come "**quarantine flag**", al file scaricato. Questo attributo funge da misura di sicurezza per **segnare il file** come proveniente da una fonte non attendibile (internet) e potenzialmente rischiosa. Tuttavia, non tutte le applicazioni aggiungono questo attributo; per esempio, alcuni client BitTorrent comuni di solito aggirano questo processo.

**La presenza di un quarantine flag segnala a Gatekeeper di macOS quando un utente tenta di eseguire il file.**

Nel caso in cui il **quarantine flag non sia presente** (come con i file scaricati tramite alcuni client BitTorrent), i controlli di Gatekeeper **potrebbero non essere eseguiti**. Pertanto, gli utenti dovrebbero prestare attenzione quando aprono file scaricati da fonti meno sicure o sconosciute.

> [!NOTE] > **Verificare** la **validità** delle code signature è un processo **intensivo in termini di risorse** che include la generazione di **hash** crittografici del codice e di tutte le risorse incluse nel bundle. Inoltre, controllare la validità del certificato comporta un **controllo online** verso i server Apple per verificare se è stato revocato dopo l'emissione. Per questi motivi, un controllo completo della code signature e della notarizzazione è **impraticabile da eseguire ogni volta che un'app viene avviata**.
>
> Pertanto, questi controlli vengono **eseguiti solo quando si lanciano app con l'attributo in quarantena.**

> [!WARNING]
> Questo attributo deve essere **impostato dall'applicazione che crea/scarica** il file.
>
> Tuttavia, i file creati da processi sandboxati avranno questo attributo impostato su ogni file che creano. E le app non sandboxate possono impostarlo da sole, oppure specificare la chiave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) nell'**Info.plist**, che farà sì che il sistema imposti l'attributo esteso `com.apple.quarantine` sui file creati,

Inoltre, tutti i file creati da un processo che chiama **`qtn_proc_apply_to_self`** sono messi in quarantena. Oppure l'API **`qtn_file_apply_to_path`** aggiunge l'attributo di quarantena a un percorso di file specificato.

È possibile **verificarne lo stato e abilitare/disabilitare** (richiede root) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Puoi anche **verificare se un file ha l'attributo esteso quarantine** con:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Controlla il **valore** degli **attributi** **estesi** e scopri l'app che ha scritto l'attributo quarantine con:
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
In realtà un processo "potrebbe impostare flag di quarantena sui file che crea" (ho già provato ad applicare il flag USER_APPROVED a un file creato ma non viene applicato):

<details>

<summary>Codice sorgente per applicare i flag di quarantena</summary>
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
Le informazioni di quarantine sono anche memorizzate in un database centrale gestito da LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, che permette alla GUI di ottenere dati sull'origine dei file. Inoltre queste informazioni possono essere sovrascritte da applicazioni interessate a nascondere la loro origine. Inoltre, questo può essere fatto dalle LaunchServices APIS.

#### **libquarantine.dylib**

Questa libreria esporta diverse funzioni che consentono di manipolare i campi degli extended attribute.

Le API `qtn_file_*` gestiscono le policy di quarantine dei file, le API `qtn_proc_*` sono applicate ai processi (i file creati dal processo). Le funzioni non esportate `__qtn_syscall_quarantine*` sono quelle che applicano le policy e che chiamano `mac_syscall` con "Quarantine" come primo argomento, il quale invia le richieste a `Quarantine.kext`.

#### **Quarantine.kext**

L'estensione kernel è disponibile solo tramite la **kernel cache on the system**; tuttavia, puoi _scaricare_ il **Kernel Debug Kit from** [**https://developer.apple.com/**](https://developer.apple.com/), che conterrà una versione simbolicata dell'estensione.

Questo Kext aggancerà, tramite MACF, diverse chiamate per intercettare tutti gli eventi del ciclo di vita dei file: creazione, apertura, rinomina, hard link... persino `setxattr` per impedirne l'impostazione dell'extended attribute `com.apple.quarantine`.

Usa inoltre un paio di MIB:

- `security.mac.qtn.sandbox_enforce`: Applica la quarantine anche nella Sandbox
- `security.mac.qtn.user_approved_exec`: I processi in quarantine possono eseguire solo file approvati

#### Provenance xattr (Ventura e successivi)

macOS 13 Ventura ha introdotto un meccanismo di provenance separato che viene popolato la prima volta che a un'app in quarantena viene permesso di avviarsi. Vengono creati due artefatti:

- L'xattr `com.apple.provenance` sulla directory del bundle `.app` (valore binario a dimensione fissa contenente una chiave primaria e flag).
- Una riga nella tabella `provenance_tracking` all'interno del database ExecPolicy in `/var/db/SystemPolicyConfiguration/ExecPolicy/` che memorizza il cdhash dell'app e i metadati.

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

XProtect è una funzione **anti-malware** integrata in macOS. XProtect **controlla ogni applicazione al primo avvio o quando viene modificata rispetto al suo database** di malware noti e tipi di file non sicuri. Quando scarichi un file tramite alcune app, come Safari, Mail o Messages, XProtect scansiona automaticamente il file. Se corrisponde a un malware noto nel suo database, XProtect **impedisce l'esecuzione del file** e ti avverte della minaccia.

Il database di XProtect viene **aggiornato regolarmente** da Apple con nuove definizioni di malware, e questi aggiornamenti vengono scaricati e installati automaticamente sul tuo Mac. Ciò garantisce che XProtect sia sempre aggiornato rispetto alle minacce note più recenti.

Tuttavia, vale la pena notare che **XProtect non è una soluzione antivirus completa**. Controlla soltanto una lista specifica di minacce conosciute e non esegue scansioni in tempo reale come fanno la maggior parte dei software antivirus.

Puoi ottenere informazioni sull'ultimo aggiornamento di XProtect eseguendo:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect si trova in una posizione protetta da SIP in **/Library/Apple/System/Library/CoreServices/XProtect.bundle** e all'interno del bundle puoi trovare le informazioni che XProtect usa:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permette al codice con quei cdhash di usare entitlements legacy.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Elenco di plugin e estensioni il cui caricamento è vietato tramite BundleID e TeamID oppure che indicano una versione minima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regole Yara per rilevare malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Database SQLite3 con hash di applicazioni bloccate e TeamID.

Nota che esiste un'altra App in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relativa a XProtect che non è coinvolta nel processo di Gatekeeper.

> XProtect Remediator: Su macOS moderni, Apple include scanner on-demand (XProtect Remediator) che vengono eseguiti periodicamente tramite launchd per rilevare e rimediare a famiglie di malware. Puoi osservare queste scansioni nei unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Non Gatekeeper

> [!CAUTION]
> Nota che Gatekeeper **non viene eseguito ogni volta** che esegui un'applicazione; solo _**AppleMobileFileIntegrity**_ (AMFI) verificherà **le firme del codice eseguibile** quando esegui un'app che è già stata eseguita e verificata da Gatekeeper.

Quindi, in passato era possibile eseguire un'app per metterla in cache con Gatekeeper, poi **modificare file non eseguibili dell'applicazione** (come Electron asar o file NIB) e se non erano presenti altre protezioni, l'applicazione veniva **eseguita** con le aggiunte **maligne**.

Tuttavia, ora questo non è possibile perché macOS **impedisce la modifica dei file** all'interno dei bundle delle applicazioni. Quindi, se provi l'attacco [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), scoprirai che non è più possibile abusarne perché dopo aver eseguito l'app per metterla in cache con Gatekeeper, non potrai modificare il bundle. E se cambi, ad esempio, il nome della directory Contents in NotCon (come indicato nell'exploit), e poi esegui il main binary dell'app per metterla in cache con Gatekeeper, verrà generato un errore e non verrà eseguita.

## Bypass di Gatekeeper

Qualsiasi metodo per bypassare Gatekeeper (riuscire a far scaricare qualcosa all'utente ed eseguirlo quando Gatekeeper dovrebbe impedirlo) è considerato una vulnerabilità in macOS. Di seguito alcuni CVE assegnati a tecniche che in passato permettevano di bypassare Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

È stato osservato che se per l'estrazione viene usata Archive Utility, i file con percorsi che superano i 886 caratteri non ricevono l'attributo esteso com.apple.quarantine. Questa situazione permette involontariamente a quei file di **circumventare i controlli di sicurezza di Gatekeeper**.

Consulta il [**report originale**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) per maggiori informazioni.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando un'applicazione viene creata con Automator, le informazioni su cosa deve eseguire sono all'interno di `application.app/Contents/document.wflow` e non nell'eseguibile. L'eseguibile è solo un binario Automator generico chiamato **Automator Application Stub**.

Perciò, era possibile far puntare `application.app/Contents/MacOS/Automator\ Application\ Stub` con un collegamento simbolico a un altro Automator Application Stub presente nel sistema ed eseguirà ciò che c'è dentro `document.wflow` (il tuo script) **senza attivare Gatekeeper** perché l'eseguibile reale non ha lo xattr di quarantine.

Esempio di percorso previsto: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta il [**report originale**](https://ronmasas.com/posts/bypass-macos-gatekeeper) per maggiori informazioni.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In questo bypass è stato creato un file zip con un'applicazione iniziando la compressione da `application.app/Contents` invece che da `application.app`. Di conseguenza, l'**attributo quarantine** è stato applicato a tutti i **file in `application.app/Contents`** ma **non a `application.app`**, che è ciò che Gatekeeper controllava, quindi Gatekeeper veniva bypassato perché quando `application.app` veniva avviata **non aveva l'attributo di quarantine.**
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) per maggiori informazioni.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Anche se i componenti sono diversi, lo sfruttamento di questa vulnerabilità è molto simile a quello precedente. In questo caso verrà generato un Apple Archive da **`application.app/Contents`**, quindi **`application.app` non riceverà l'attributo quarantine** quando viene decompresso da **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulta il [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) per maggiori informazioni.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

L'ACL **`writeextattr`** può essere usata per impedire a chiunque di scrivere un attributo in un file:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Inoltre, il formato di file **AppleDouble** copia un file includendo i suoi ACEs.

Nel [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) è possibile vedere che la rappresentazione testuale della ACL memorizzata dentro l'xattr chiamato **`com.apple.acl.text`** verrà impostata come ACL nel file decompressato. Quindi, se hai compresso un'applicazione in un file zip con il formato di file **AppleDouble** con una ACL che impedisce che altri xattr vengano scritti su di essa... la quarantine xattr non è stata impostata nell'applicazione:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulta il [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) per maggiori informazioni.

Nota che questo può anche essere sfruttato con AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Si è scoperto che **Google Chrome non impostava il quarantine attribute** sui file scaricati a causa di alcuni problemi interni di macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

I formati AppleDouble memorizzano gli attributi di un file in un file separato che inizia con `._`, questo aiuta a copiare gli attributi dei file **tra macchine macOS**. Tuttavia, è stato osservato che dopo la decompressione di un file AppleDouble, il file che inizia con `._` **non riceveva il quarantine attribute**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Essendo possibile creare un file a cui non viene impostato l'attributo quarantine, era **possible to bypass Gatekeeper.** Il trucco era **create a DMG file application** usando la convenzione di nome AppleDouble (iniziarlo con `._`) e creare un **visible file as a sym link to this hidden** file senza l'attributo quarantine.\
Quando il **dmg file is executed**, poiché non ha l'attributo quarantine, esso **bypass Gatekeeper**.
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

Un bypass di Gatekeeper risolto in macOS Sonoma 14.0 permetteva ad app appositamente create di essere eseguite senza richiesta. I dettagli sono stati divulgati pubblicamente dopo la patch e il problema è stato sfruttato attivamente nel mondo reale prima della correzione. Assicurarsi che sia installato Sonoma 14.0 o successivo.

### [CVE-2024-27853]

Un bypass di Gatekeeper in macOS 14.4 (rilasciato marzo 2024) dovuto alla gestione da parte di `libarchive` di ZIP maligni permetteva alle app di eludere la valutazione. Aggiornare a 14.4 o successivo, dove Apple ha risolto il problema.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **Automator Quick Action workflow** incorporato in un'app scaricata poteva attivarsi senza la valutazione di Gatekeeper, perché i workflow venivano trattati come dati ed eseguiti dall'helper di Automator al di fuori del normale percorso del prompt di notarizzazione. Una `.app` appositamente creata che include una Quick Action che esegue uno shell script (es., dentro `Contents/PlugIns/*.workflow/Contents/document.wflow`) poteva quindi eseguirsi immediatamente al lancio. Apple ha aggiunto un dialogo di consenso aggiuntivo e ha corretto il percorso di valutazione in Ventura **13.7**, Sonoma **14.7** e Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Diverse vulnerabilità in popolari tool di estrazione (es., The Unarchiver) facevano sì che i file estratti dagli archivi non ricevessero l'xattr `com.apple.quarantine`, permettendo opportunità di bypass di Gatekeeper. Affidarsi sempre a macOS Archive Utility o a tool patchati durante i test e verificare gli xattr dopo l'estrazione.

### uchg (da questo [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Crea una directory contenente un'app.
- Aggiungi uchg all'app.
- Comprimi l'app in un file tar.gz.
- Invia il file tar.gz a una vittima.
- La vittima apre il file tar.gz ed esegue l'app.
- Gatekeeper non controlla l'app.

### Prevent Quarantine xattr

In un bundle ".app", se l'xattr di quarantine non viene aggiunto, all'esecuzione **Gatekeeper non verrà attivato**.


## Riferimenti

- Apple Platform Security: Informazioni sul contenuto di sicurezza di macOS Sonoma 14.4 (includes CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: Come macOS ora traccia la provenienza delle app – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: Informazioni sul contenuto di sicurezza di macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia rimuove il bypass Gatekeeper “Control‑click ‘Open’” – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
