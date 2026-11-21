# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** è una funzionalità di sicurezza sviluppata per i sistemi operativi Mac, progettata per garantire che gli utenti **eseguano solo software attendibile** sui propri sistemi. Funziona **convalidando il software** che un utente scarica e tenta di aprire da **fonti esterne all'App Store**, come un'app, un plug-in o un pacchetto di installazione.

Il meccanismo chiave di Gatekeeper è il processo di **verifica**. Controlla se il software scaricato è **firmato da uno sviluppatore riconosciuto**, garantendone l'autenticità. Inoltre, verifica che il software sia **stato notarizzato da Apple**, confermando che è privo di contenuti dannosi noti e che non è stato manomesso dopo la notarizzazione.

Inoltre, Gatekeeper rafforza il controllo e la sicurezza degli utenti **chiedendo loro di approvare l'apertura** del software scaricato al primo avvio. Questa misura di protezione aiuta a impedire agli utenti di eseguire inavvertitamente codice eseguibile potenzialmente dannoso, scambiandolo per un file di dati innocuo.

### Firme delle applicazioni

Le firme delle applicazioni, note anche come firme del codice, sono una componente fondamentale dell'infrastruttura di sicurezza di Apple. Servono a **verificare l'identità dell'autore del software** (lo sviluppatore) e a garantire che il codice non sia stato manomesso dall'ultima firma.

Ecco come funziona:

1. **Firma dell'applicazione:** quando uno sviluppatore è pronto a distribuire la propria applicazione, la **firma usando una chiave privata**. Questa chiave privata è associata a un **certificato che Apple rilascia allo sviluppatore** quando si iscrive all'Apple Developer Program. Il processo di firma consiste nel creare un hash crittografico di tutte le parti dell'app e nel cifrare questo hash con la chiave privata dello sviluppatore.
2. **Distribuzione dell'applicazione:** l'applicazione firmata viene quindi distribuita agli utenti insieme al certificato dello sviluppatore, che contiene la chiave pubblica corrispondente.
3. **Verifica dell'applicazione:** quando un utente scarica e tenta di eseguire l'applicazione, il sistema operativo del Mac usa la chiave pubblica contenuta nel certificato dello sviluppatore per decifrare l'hash. Ricalcola quindi l'hash in base allo stato corrente dell'applicazione e lo confronta con quello decifrato. Se i due hash corrispondono, significa che **l'applicazione non è stata modificata** da quando lo sviluppatore l'ha firmata e il sistema ne consente l'esecuzione.

Le firme delle applicazioni sono una parte essenziale della tecnologia Gatekeeper di Apple. Quando un utente tenta di **aprire un'applicazione scaricata da internet**, Gatekeeper ne verifica la firma. Se l'applicazione è firmata con un certificato rilasciato da Apple a uno sviluppatore conosciuto e il codice non è stato manomesso, Gatekeeper ne consente l'esecuzione. In caso contrario, blocca l'applicazione e avvisa l'utente.

A partire da macOS Catalina, **Gatekeeper controlla anche se l'applicazione è stata notarizzata** da Apple, aggiungendo un ulteriore livello di sicurezza. Il processo di notarizzazione verifica la presenza di problemi di sicurezza noti e codice dannoso nell'applicazione; se i controlli vengono superati, Apple aggiunge un ticket all'applicazione, che Gatekeeper può verificare.

#### Verifica delle firme

Quando esamini un **campione di malware**, dovresti sempre **verificare la firma** del binario, poiché lo **sviluppatore** che lo ha firmato potrebbe essere già **associato** a **malware**.

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

Il processo di notarizzazione di Apple offre un'ulteriore protezione per gli utenti da software potenzialmente dannoso. Prevede che **lo sviluppatore invii la propria applicazione per l'esame** da parte del **Notary Service di Apple**, da non confondere con App Review. Questo servizio è un **sistema automatizzato** che analizza il software inviato per rilevare la presenza di **contenuti dannosi** e possibili problemi di code-signing.

Se il software **supera** l'ispezione senza destare preoccupazioni, il Notary Service genera un ticket di notarizzazione. Lo sviluppatore deve quindi **allegare questo ticket al software**: un processo noto come 'stapling'. Inoltre, il ticket di notarizzazione viene pubblicato online, dove Gatekeeper, la tecnologia di sicurezza di Apple, può accedervi.

Al primo avvio o alla prima installazione del software da parte dell'utente, la presenza del ticket di notarizzazione — allegato all'eseguibile o reperibile online — **indica a Gatekeeper che il software è stato notarizzato da Apple**. Di conseguenza, Gatekeeper mostra un messaggio descrittivo nella finestra di dialogo del primo avvio, indicando che Apple ha verificato il software per rilevare eventuali contenuti dannosi. Questo processo aumenta la fiducia degli utenti nella sicurezza del software che installano o eseguono sui propri sistemi.

### spctl & syspolicyd

> [!CAUTION]
> Nota che, a partire dalla versione Sequoia, **`spctl`** non consente più di modificare la configurazione di Gatekeeper.

**`spctl`** è lo strumento CLI per enumerare e interagire con Gatekeeper (tramite messaggi XPC con il daemon `syspolicyd`). Ad esempio, è possibile verificare lo **stato** di GateKeeper con:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Nota che i controlli della firma di GateKeeper vengono eseguiti solo sui **file con l'attributo Quarantine**, non su tutti i file.

GateKeeper verificherà se, in base alle **preferenze e alla firma**, è possibile eseguire un binario:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** è il daemon principale responsabile dell'applicazione di Gatekeeper. Mantiene un database che si trova in `/var/db/SystemPolicy`; è possibile trovare il codice che supporta il [database qui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) e il [template SQL qui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Tieni presente che il database non è soggetto a SIP ed è scrivibile da root; il database `/var/db/.SystemPolicy-default` viene usato come backup originale nel caso in cui l'altro si corrompa.

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

**`syspolicyd`** espone anche un server XPC con diverse operazioni, come `assess`, `update`, `record` e `cancel`, accessibili anche tramite le API **`SecAssessment*` di `Security.framework`**. Anche **`spctl`** comunica effettivamente con **`syspolicyd`** tramite XPC.

Nota che la prima regola terminava con "**App Store**" e la seconda con "**Developer ID**" e che nell'immagine precedente era **abilitata l'esecuzione delle app dell'App Store e degli sviluppatori identificati**.\
Se **modifichi** questa impostazione selezionando App Store, le regole "**Notarized Developer ID" scompariranno**.

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

Oppure puoi elencare le informazioni precedenti con:

```bash
sudo spctl --list
```

Le opzioni **`--master-disable`** e **`--global-disable`** di **`spctl`** **disattivano** completamente questi controlli delle firme:

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

È possibile **verificare se un'app sarà consentita da Gatekeeper** con:

```bash
spctl --assess -v /Applications/App.app
```

Su macOS 14 e versioni successive, **`syspolicy_check`** è un utile controllo di livello superiore da eseguire prima della distribuzione di un bundle applicativo. Fornisce diagnosi più concrete sull’esecuzione attendibile rispetto al semplice risultato di `spctl`, anche se Apple consiglia comunque di testare il percorso reale di download/estrazione/primo avvio, perché verifica anche la propagazione della quarantine.<sup>[[14]](#references)</sup>

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

Per quanto riguarda le **kernel extensions**, la cartella `/var/db/SystemPolicyConfiguration` contiene file con elenchi di kext autorizzate al caricamento. Inoltre, `spctl` dispone dell’entitlement `com.apple.private.iokit.nvram-csr`, poiché può aggiungere nuove kernel extensions pre-approvate, che devono essere salvate anche in NVRAM nella chiave `kext-allowed-teams`.

#### Gestire Gatekeeper su macOS 15 (Sequoia) e versioni successive

- La scorciatoia di Finder **Ctrl+Apri / clic destro → Apri**, usata da tempo per aggirare il blocco, è stata rimossa; dopo la prima finestra di dialogo di blocco, gli utenti devono autorizzare esplicitamente l’app bloccata da **Impostazioni di Sistema → Privacy e Sicurezza → Apri comunque**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` non sono più accettati per modifiche ai criteri non interattive. Le operazioni che modificano il database delle regole o lo stato globale di valutazione sono deprecate: usa `spctl` per la valutazione e configura l’applicazione dei criteri tramite l’interfaccia utente o MDM.

A partire da macOS 15 Sequoia, gli utenti finali non possono più modificare i criteri di Gatekeeper tramite `spctl`. La gestione avviene tramite Impostazioni di Sistema o distribuendo un profilo di configurazione MDM con il payload `com.apple.systempolicy.control`. Esempio di frammento di profilo per consentire App Store e sviluppatori identificati (ma non “Ovunque”):

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

Quando si **scarica** un'applicazione o un file, alcune **applicazioni** macOS, come i browser web o i client di posta elettronica, **associano un attributo esteso del file**, comunemente noto come "**quarantine flag**", al file scaricato. Questo attributo funge da misura di sicurezza per **contrassegnare il file** come proveniente da una fonte non attendibile (Internet) e potenzialmente rischiosa. Tuttavia, non tutte le applicazioni associano questo attributo; ad esempio, i comuni client BitTorrent in genere aggirano questo processo.

**La presenza di un quarantine flag segnala la funzionalità di sicurezza Gatekeeper di macOS quando un utente tenta di eseguire il file**.

Se il **quarantine flag è assente** (come nel caso dei file scaricati tramite alcuni client BitTorrent), i **controlli** di Gatekeeper **potrebbero non essere eseguiti**. Pertanto, gli utenti dovrebbero prestare attenzione quando aprono file scaricati da fonti meno sicure o sconosciute.

> [!NOTE] > **Verificare** la **validità** delle firme del codice è un processo che richiede molte **risorse** e include la generazione di **hash** crittografici del codice e di tutte le risorse incluse nel pacchetto. Inoltre, per verificare la validità del certificato è necessario eseguire un **controllo online** sui server Apple per verificare se è stato revocato dopo l'emissione. Per questi motivi, eseguire ogni volta un controllo completo della firma del codice e della notarizzazione **non è pratico**.
>
> Pertanto, questi controlli vengono eseguiti **solo quando si eseguono app con l'attributo di quarantena**.

> [!WARNING]
> Questo attributo deve essere **impostato dall'applicazione che crea/scarica** il file.
>
> Tuttavia, i file creati in sandbox avranno questo attributo impostato su ogni file che creano. Le app non sandboxed possono impostarlo autonomamente oppure specificare la chiave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) in **Info.plist**, facendo sì che il sistema imposti l'attributo esteso `com.apple.quarantine` sui file creati,

Inoltre, tutti i file creati da un processo che chiama **`qtn_proc_apply_to_self`** vengono messi in quarantena. L'API **`qtn_file_apply_to_path`** aggiunge invece l'attributo di quarantena al percorso di un file specificato.

È possibile **controllarne lo stato e abilitarlo/disabilitarlo** (è necessario root) con:

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

Controlla il **valore** degli **attributi** **estesi** e scopri quale app ha scritto l'attributo di quarantena con:

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

In realtà, un processo «potrebbe impostare i quarantine flag sui file che crea» (ho già provato ad applicare il flag USER_APPROVED a un file creato, ma non è stato possibile):

<details>

<summary>Codice sorgente per applicare i quarantine flag</summary>

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

Le informazioni di quarantine sono memorizzate anche in un database centrale gestito da LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, che consente alla GUI di ottenere dati sull’origine dei file. Inoltre, le applicazioni interessate a nascondere la propria origine possono sovrascrivere queste informazioni. È possibile farlo anche tramite le API di LaunchServices.

#### **libquarantine.dylib**

Questa libreria esporta diverse funzioni che consentono di manipolare i campi degli attributi estesi.

Le API `qtn_file_*` gestiscono le policy di quarantine dei file; le API `qtn_proc_*` si applicano ai processi (ai file creati dal processo). Le funzioni non esportate `__qtn_syscall_quarantine*` applicano le policy chiamando `mac_syscall` con "Quarantine" come primo argomento, che invia le richieste a `Quarantine.kext`.

#### **Quarantine.kext**

Questa estensione del kernel è disponibile solo tramite la **kernel cache del sistema**; tuttavia, è possibile scaricare il **Kernel Debug Kit da** [**https://developer.apple.com/**](https://developer.apple.com/), che contiene una versione dell’estensione con simboli.

Questa Kext usa MACF per intercettare diverse chiamate e rilevare tutti gli eventi del ciclo di vita dei file: creazione, apertura, rinomina, creazione di hard link... persino `setxattr`, per impedirgli di impostare l’attributo esteso `com.apple.quarantine`.

Usa anche un paio di MIB:

- `security.mac.qtn.sandbox_enforce`: applica la quarantine insieme a Sandbox
- `security.mac.qtn.user_approved_exec`: i processi in quarantine possono eseguire solo file approvati

#### Attributo xattr di provenienza (Ventura e versioni successive)

macOS 13 Ventura ha introdotto un meccanismo di provenienza separato, popolato la prima volta che viene consentito l’avvio di un’app in quarantine.<sup>[[2]](#references)</sup> Vengono creati due artefatti:

- L’attributo xattr `com.apple.provenance` sulla directory del bundle `.app` (un valore binario di dimensione fissa contenente una chiave primaria e dei flag).
- Una riga nella tabella `provenance_tracking` del database ExecPolicy in `/var/db/SystemPolicyConfiguration/ExecPolicy/`, che memorizza il cdhash e i metadati dell’app.

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

XProtect è una funzionalità **anti-malware** integrata in macOS. XProtect **controlla ogni applicazione al primo avvio o dopo una modifica confrontandola con il proprio database** di malware noti e tipi di file non sicuri. Quando scarichi un file tramite alcune app, come Safari, Mail o Messaggi, XProtect lo analizza automaticamente. Se corrisponde a un malware noto presente nel database, XProtect **impedirà l'esecuzione del file** e ti avviserà della minaccia.

Apple **aggiorna regolarmente** il database di XProtect con nuove definizioni di malware; questi aggiornamenti vengono scaricati e installati automaticamente sul Mac. In questo modo, XProtect è sempre aggiornato sulle minacce note più recenti.

Tuttavia, è bene ricordare che **XProtect non è una soluzione antivirus completa**. Controlla solo un elenco specifico di minacce note e non esegue scansioni all'accesso come la maggior parte dei software antivirus.

Puoi ottenere informazioni sull'ultimo aggiornamento di XProtect eseguendo:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect si trova in una posizione protetta da SIP, **/Library/Apple/System/Library/CoreServices/XProtect.bundle**; all'interno del bundle puoi trovare le informazioni usate da XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: consente al codice con quegli cdhashes di usare legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: elenco di plugin ed estensioni di cui è vietato il caricamento tramite BundleID e TeamID, oppure che indica una versione minima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: regole Yara per rilevare malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: database SQLite3 con gli hash delle applicazioni bloccate e dei TeamID.

Nota che esiste un'altra app in **`/Library/Apple/System/Library/CoreServices/XProtect.app`** correlata a XProtect, ma non coinvolta nel processo Gatekeeper.

> XProtect Remediator: nelle versioni moderne di macOS, Apple include scanner on-demand (XProtect Remediator) che vengono eseguiti periodicamente tramite launchd per rilevare e rimuovere famiglie di malware. Puoi osservare queste scansioni nei unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Non Gatekeeper

> [!CAUTION]
> Nota che Gatekeeper **non viene eseguito ogni volta** che avvii un'applicazione: solo _**AppleMobileFileIntegrity**_ (AMFI) **verifica le firme del codice eseguibile** quando avvii un'app già avviata e verificata da Gatekeeper.

In passato, quindi, era possibile avviare un'app per farla mettere in cache da Gatekeeper, poi **modificare i file non eseguibili dell'applicazione** (come i file asar o NIB di Electron) e, in assenza di altre protezioni, l'applicazione veniva **eseguita** con le aggiunte **malevole**.

Ora, tuttavia, questo non è possibile perché macOS **impedisce di modificare i file** all'interno dei bundle delle applicazioni. Quindi, se provi l'attacco [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), vedrai che non è più possibile sfruttarlo: dopo aver avviato l'app per farla mettere in cache da Gatekeeper, non potrai modificare il bundle. Inoltre, se, ad esempio, rinomini la directory Contents in NotCon (come indicato nell'exploit) e poi avvii il binario principale dell'app per farlo mettere in cache da Gatekeeper, verrà generato un errore e l'app non verrà avviata.

## Gatekeeper Bypasses

Qualsiasi metodo per aggirare Gatekeeper (riuscire a far scaricare all'utente qualcosa e a farlo eseguire quando Gatekeeper dovrebbe impedirlo) è considerato una vulnerabilità in macOS. Ecco alcuni CVE assegnati a tecniche che in passato consentivano di aggirare Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

È stato osservato che, se per l'estrazione viene usata **Archive Utility**, ai file con **percorsi più lunghi di 886 caratteri** non viene applicato l'attributo esteso com.apple.quarantine. Questa situazione consente involontariamente a tali file di **eludere** i controlli di sicurezza di Gatekeeper.<sup>[[5]](#references)</sup>

Consulta il [**report originale**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) per maggiori informazioni.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando un'applicazione viene creata con **Automator**, le informazioni su ciò che deve eseguire si trovano in `application.app/Contents/document.wflow`, non nell'eseguibile. L'eseguibile è solo un binario generico di Automator chiamato **Automator Application Stub**.

Pertanto, si poteva fare in modo che `application.app/Contents/MacOS/Automator\ Application\ Stub` **puntasse tramite un link simbolico a un altro Automator Application Stub nel sistema**; così avrebbe eseguito il contenuto di `document.wflow` (lo script) **senza attivare Gatekeeper**, perché l'eseguibile effettivo non ha l'attributo esteso quarantine.<sup>[[6]](#references)</sup>

Esempio di percorso previsto: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta il [**report originale**](https://ronmasas.com/posts/bypass-macos-gatekeeper) per maggiori informazioni.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

In questo bypass veniva creato un file zip comprimendo un'applicazione a partire da `application.app/Contents` anziché da `application.app`. Pertanto, l'**attributo quarantine** veniva applicato a tutti i **file in `application.app/Contents`**, ma **non a `application.app`**, che era l'elemento controllato da Gatekeeper. Il bypass era quindi possibile perché, quando veniva avviato `application.app`, **non aveva l'attributo quarantine.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Consulta il [**report originale**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) per maggiori informazioni.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Anche se i componenti sono diversi, l'exploitation di questa vulnerabilità è molto simile a quella precedente. In questo caso genereremo un Apple Archive da **`application.app/Contents`**, così **`application.app` non riceverà l'attributo quarantine** quando verrà decompresso da **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Consulta il [**report originale**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) per maggiori informazioni.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

L’ACL **`writeextattr`** può essere usato per impedire a chiunque di scrivere un attributo in un file:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Per il meccanismo `com.apple.acl.text`/AppleDouble e la riproduzione completa dei sidecar, vedi [Riproduzione del bypass di AppleDouble ACL quarantine](macos-fs-tricks/macos-appledouble-acl-quarantine-bypass.md). La variante ZIP dell’applicazione Gatekeeper usa la seguente sequenza:

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

È stato scoperto che **Google Chrome non impostava l'attributo di quarantena** sui file scaricati a causa di alcuni problemi interni di macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble memorizza gli attributi di un file in un file separato il cui nome inizia con `._`; ciò consente di copiare gli attributi **tra macchine macOS**. Tuttavia, dopo la decompressione di un file AppleDouble, al file che iniziava con `._` **non veniva assegnato l'attributo di quarantena**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Essendo possibile creare un file senza attributo quarantine, era **possibile aggirare Gatekeeper.** Il trucco consisteva nel **creare un file DMG dell’applicazione** usando la convenzione di denominazione AppleDouble (facendolo iniziare con `._`) e creare un **file visibile come link simbolico a questo file nascosto** privo dell’attributo quarantine.\
Quando il **file DMG viene eseguito**, poiché non ha un attributo quarantine, **aggira Gatekeeper**.

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

Apple ha corretto un errore logico di LaunchServices in macOS Sonoma 14.0 tramite controlli migliorati. L'avviso pubblico afferma solo che un'app poteva bypassare Gatekeeper, quindi non dedurre uno specifico formato del contenitore o una catena di exploit basandoti solo sulla voce CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Un bypass di Gatekeeper in macOS 14.4 (rilasciato a marzo 2024), dovuto alla gestione da parte di `libarchive` di ZIP malevoli, permetteva alle app di eludere la valutazione. Aggiorna alla versione 14.4 o successiva, in cui Apple ha corretto il problema.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Un **workflow di Quick Action di Automator** incorporato in un'app scaricata poteva attivarsi senza la valutazione di Gatekeeper, perché i workflow erano trattati come dati ed eseguiti dall'helper di Automator al di fuori del normale percorso della richiesta di notarizzazione. Un `.app` appositamente creato, che include una Quick Action per eseguire uno script shell (ad esempio, in `Contents/PlugIns/*.workflow/Contents/document.wflow`), poteva quindi essere eseguito immediatamente all'avvio. Apple ha aggiunto una finestra di dialogo di consenso aggiuntiva e corretto il percorso di valutazione in Ventura **13.7**, Sonoma **14.7** e Sequoia **15**.<sup>[[3]](#references)</sup>

### Errori nella propagazione della quarantena durante l'estrazione e la copia

Uno studio del 2024 ha rilevato lacune nella propagazione nelle versioni testate di iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) e 7z Utility (DMG/ZIP/7Z); ha inoltre osservato la perdita dell'attributo durante le copie da host a guest con VMware Tools. Diversi fornitori hanno poi annunciato correzioni: considera quindi questi nomi come spunti per **nuovi test specifici per versione**, non come un elenco permanente di software vulnerabili. Lo stesso problema relativo ai confini di fiducia si applica ai workflow Unix nativi: `curl`/`scp` non aggiungono la quarantena e `tar`/`unzip` da riga di comando non la ereditano automaticamente da un archivio contenitore.<sup>[[15]](#references)</sup>

Per i test offensivi, confronta il contenitore e l'app finale dopo **ogni** passaggio attraverso browser, client di posta, archivi, immagini disco, sincronizzazione cloud, cartelle condivise e copie tra VM. Un rifiuto esplicito di `spctl` non corregge un xattr mancante: senza quarantena, il normale percorso di Gatekeeper alla prima apertura potrebbe non richiedere mai tale valutazione.<sup>[[15]](#references)</sup>

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

### uchg (da questo [intervento](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Crea una directory contenente un'app.
- Aggiungi uchg all'app.
- Comprimi l'app in un file tar.gz.
- Invia il file tar.gz a una vittima.
- La vittima apre il file tar.gz ed esegue l'app.
- Gatekeeper non controlla l'app.<sup>[[12]](#references)</sup>

### Impedire l'xattr Quarantine

In un bundle ".app", se non viene aggiunto l'xattr quarantine, quando lo si esegue **Gatekeeper non verrà attivato**.

Vedi [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) per primitive basate su filesystem, flag, ACL e AppleDouble che possono impedire o eliminare gli attributi estesi.





## References

- [1] [Apple Platform Security: Informazioni sul contenuto di sicurezza di macOS Sonoma 14.4 (include CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Come macOS tiene ora traccia della provenienza delle app](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Informazioni sul contenuto di sicurezza di macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia rimuove l'elusione di Gatekeeper tramite clic con Control e selezione di “Apri”](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: La scoperta di CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, elusione di macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs individua una vulnerabilità di Safari che consente di eludere Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs individua una vulnerabilità di macOS Archive Utility che consente di eludere Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Il tallone d'Achille di Gatekeeper: individuazione di una vulnerabilità di macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Scoperta di un'elusione di Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Individuazione e segnalazione di un exploit per eludere Gatekeeper con l'aiuto di Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Elusione dei meccanismi di sicurezza e privacy di macOS — Da Gatekeeper alla System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Informazioni sul contenuto di sicurezza di macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Testare un prodotto autenticato tramite notarizzazione](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Elusione di Gatekeeper — Individuazione delle debolezze in un meccanismo di sicurezza di macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
